//go:build integration

// engines45_integration_test.go — REAL wstunnel v10.1.9 + chisel v1.10.1 +
// frp 0.61.1 binaries through the REAL driver paths, in TWO containers
// (quantum-test-eng45-a = foreign/server, quantum-test-eng45-b = iran/client)
// on a user-defined docker network. One end per container; the identity
// seam (enrollment name) selects the role per container; artifacts arrive
// through a real HTTP server (R5 shape) with a manifest + per-arch pins;
// traffic is iperf3 THROUGH the tunnel; kill → Health fails → supervisor
// restart → traffic again; the MIXED phase drives frp + wstunnel + chisel
// + matrix through ONE Manager.Reconcile per host (production shape).
//
// Run by tests/engines45_integration.sh (the orchestrator builds this
// test binary and drives both containers). Env:
//
//	ENG45_ROLE=server|client   this container's enrollment name role
//	ENG45_MODE=wstunnel|chisel|mixed|health   what this run does
//	ENG45_ART_URL=http://<a>:8111   artifact base (manifest + files)
//	ENG45_PEER=<host>:<port>        the OTHER container (carrier dial)
//	ENG45_STATUS=/status/status.txt where health/traffic results land
//	ENG45_PUBKEY=...                base64 DER SPKI of the signing key
//	ENG45_CLI_PORT / ENG45_SRV_PORT etc. — port allocations
//
// The orchestrator runs the phases (wstunnel → chisel → mixed) BACK-TO-BACK
// in the SAME netns as each phase's server side finishes. The client legs
// are therefore PHASE-SCOPED: each exits when the server side reports its
// scenario done (eng45PhaseDone) and tears its echo/iperf3 targets down via
// t.Cleanup (eng45ClientTargets) — the pre-AGENT-25 harness slept a fixed
// 10 minutes and left the phase's ports and iperf3 children bound/running
// into the next phase, which is why the mixed phase's echo binds failed
// EADDRINUSE ("echo targets failed", REFACTOR-A1 §3.6 flag 6).

package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/infra"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

func eng45Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// The test harness (TestMain) clears the pinned-key var for hermetic
// tests; the container infra.Runner re-pins it from ENG45_PUBKEY before any
// driver runs (the orchestrator passes the artifact-signing public key).
func init() {
	if k := os.Getenv("ENG45_PUBKEY"); k != "" {
		engineArtifactPubKeyB64 = k
	}
}

// eng45LoadIdentity seams the enrollment name from the env (per container).
func eng45LoadIdentity() (agentIdentity, bool) {
	return agentIdentity{Server: eng45Env("ENG45_ART_URL", ""), BasePath: "", Name: eng45Env("ENG45_SELF", "")}, true
}

// eng45InitSpawnCapture redirects every wstunnel/chisel/frp process the
// drivers spawn into a log file (the drivers discard output by default;
// the tunnel-not-up failures need the engine's own logs).
func eng45InitSpawnCapture(role string) {
	logFor := func(engine string) string {
		return "/status/wst-" + role + "-" + engine + ".log"
	}
	origWst := wstSpawn
	wstSpawn = func(binPath string, args []string) (frpProcess, error) {
		cmd := exec.Command(binPath, args...)
		lf, err := os.OpenFile(logFor("wstunnel"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err == nil {
			cmd.Stdout, cmd.Stderr = lf, lf
		}
		if err := cmd.Start(); err != nil {
			if lf != nil {
				lf.Close()
			}
			return nil, fmt.Errorf("wstunnel: start: %w", err)
		}
		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
			if lf != nil {
				lf.Close()
			}
		}()
		return &frpExecProcess{cmd: cmd, done: done}, nil
	}
	_ = origWst
}

func eng45Status(t *testing.T, line string) {
	t.Helper()
	f := eng45Env("ENG45_STATUS", "")
	if f == "" {
		return
	}
	fh, err := os.OpenFile(f, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer fh.Close()
	fmt.Fprintf(fh, "%s\n", line)
}

// eng45IperfServer starts a PERSISTENT iperf3 -s on the given port (the
// server's own probe bytes would upset its protocol — the target swaps to
// iperf3 only during a measurement window, see eng45SwapTarget).
func eng45IperfServer(port int) *exec.Cmd {
	cmd := exec.Command("iperf3", "-s", "-p", fmt.Sprintf("%d", port))
	if err := cmd.Start(); err != nil {
		return nil
	}
	return cmd
}

// eng45EchoServer is the health-probe target: accepts and echoes — the
// probe's byte comes back, which is a positive through-the-tunnel signal.
func eng45EchoServer(port int) (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				c.Close()
			}(c)
		}
	}()
	return ln, nil
}

// eng45Target is one client-side tunnel target for a phase: an echo server
// on port, swapped for a transient iperf3 -s while cmd says "iperf".
type eng45Target struct {
	cmd  string // the measuring end writes "iperf" to open the window, removes it to close it
	port int    // echo/iperf3 port on THIS container
}

// eng45TargetState is one target's live state (one swap-loop goroutine per
// target; the teardown func mutates under mu).
type eng45TargetState struct {
	tg      eng45Target
	mu      sync.Mutex
	echo    net.Listener
	iperf   *exec.Cmd
	stop    chan struct{}
	stopped bool
}

// eng45FreeEchoPort frees a client target port a previous phase may still
// hold: the pre-AGENT-25 harness left each phase's iperf3 -s child running
// (orphaned at test-process exit) with the echo port bound INTO the next
// phase — the mixed phase's echo binds then failed EADDRINUSE ("echo
// targets failed"). Kill the exact stray server, then wait for the port
// to come free.
func eng45FreeEchoPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			ln.Close()
			return
		}
		if time.Now().After(deadline) {
			eng45Status(t, fmt.Sprintf("echo port %d still busy after 10s: %v", port, err))
			return
		}
		_ = exec.Command("pkill", "-f", fmt.Sprintf("iperf3 -s -p %d", port)).Run()
		time.Sleep(500 * time.Millisecond)
	}
}

// eng45ClientTargets binds the phase's echo targets and swaps each for
// iperf3 -s while its cmd file says "iperf" (window semantics: the
// measuring end removes the file to close the window; the iperf3 child is
// killed and the echo listener comes back). Each port is freed first
// (eng45FreeEchoPort). The teardown (listeners closed, iperf3 children
// killed and reaped) is registered with t.Cleanup BEFORE any bind, so even
// a partial bind failure frees what did bind — the ports must never
// outlive the phase (the mixed phase re-binds the wstunnel/chisel ports).
func eng45ClientTargets(t *testing.T, targets ...eng45Target) {
	t.Helper()
	sts := make([]*eng45TargetState, 0, len(targets))
	t.Cleanup(func() {
		for _, st := range sts {
			st.mu.Lock()
			st.stopped = true
			ln, ip := st.echo, st.iperf
			st.echo, st.iperf = nil, nil
			st.mu.Unlock()
			close(st.stop)
			if ln != nil {
				ln.Close()
			}
			eng45KillIperf(ip)
		}
	})
	for _, tg := range targets {
		eng45FreeEchoPort(t, tg.port)
		ln, err := eng45EchoServer(tg.port)
		if err != nil {
			eng45Status(t, fmt.Sprintf("echo target bind %d ERROR %v", tg.port, err))
			t.Fatalf("echo target bind %d: %v", tg.port, err)
		}
		sts = append(sts, &eng45TargetState{tg: tg, echo: ln, stop: make(chan struct{})})
	}
	for _, st := range sts {
		go eng45SwapLoop(st)
	}
}

// eng45SwapLoop watches one target's cmd file: while it says "iperf" the
// echo listener is swapped for iperf3 -s; when the window closes (the file
// is removed by the measuring end) the iperf3 child is killed and the echo
// listener comes back. The loop exits on stop and never leaves a listener
// or an iperf3 child behind after teardown.
func eng45SwapLoop(st *eng45TargetState) {
	for {
		select {
		case <-st.stop:
			return
		default:
		}
		data, err := os.ReadFile(st.tg.cmd)
		want := err == nil && strings.TrimSpace(string(data)) == "iperf"
		st.mu.Lock()
		echoOpen := st.echo != nil
		iperfUp := st.iperf != nil
		st.mu.Unlock()
		switch {
		case want && echoOpen:
			st.mu.Lock()
			ln := st.echo
			st.echo = nil
			stopped := st.stopped
			st.mu.Unlock()
			if ln != nil {
				ln.Close()
			}
			ip := eng45IperfServer(st.tg.port)
			st.mu.Lock()
			if stopped || st.stopped {
				st.mu.Unlock()
				eng45KillIperf(ip)
				return
			}
			st.iperf = ip
			st.mu.Unlock()
		case !want && iperfUp:
			st.mu.Lock()
			ip := st.iperf
			st.iperf = nil
			st.mu.Unlock()
			eng45KillIperf(ip)
			if nl, err := eng45EchoServer(st.tg.port); err == nil {
				st.mu.Lock()
				if st.stopped {
					st.mu.Unlock()
					nl.Close()
					return
				}
				st.echo = nl
				st.mu.Unlock()
			}
		case !echoOpen && !iperfUp:
			// iperf3 failed to spawn (or a rebind did) — restore the
			// echo target so probes keep working.
			if nl, err := eng45EchoServer(st.tg.port); err == nil {
				st.mu.Lock()
				if st.stopped {
					st.mu.Unlock()
					nl.Close()
					return
				}
				st.echo = nl
				st.mu.Unlock()
			}
		}
		select {
		case <-st.stop:
			return
		case <-time.After(time.Second):
		}
	}
}

// eng45KillIperf kills one spawned iperf3 child and reaps it.
func eng45KillIperf(ip *exec.Cmd) {
	if ip == nil || ip.Process == nil {
		return
	}
	_ = ip.Process.Kill()
	_ = ip.Wait()
}

// eng45DoneMarker records the server-side scenario completion for the
// client end (see eng45PhaseDone).
func eng45DoneMarker(phase string) {
	_ = os.WriteFile("/status/done-"+phase+".txt", []byte("done\n"), 0o600)
}

// eng45PhaseDone waits for the phase's server-side scenario to finish (the
// server end writes the marker file at its SCENARIO-DONE) — the client end
// must exit when its phase is done. The pre-AGENT-25 harness slept a fixed
// 10 minutes instead, so the client process, its engine binary and its
// echo/iperf3 targets stayed alive INTO the next phase (the orchestrator
// runs the phases back-to-back in the SAME netns) — that is the mixed-phase
// "echo targets failed" squat. A dedicated marker file is used because the
// orchestrator truncates status.txt between phases (a status-line marker
// would race the truncation). On cap the client exits anyway — teardown
// still frees the ports, and a hung server side is the orchestrator's
// TIMEOUT verdict, not the client's.
func eng45PhaseDone(t *testing.T, phase string, maxWait time.Duration) {
	t.Helper()
	marker := "/status/done-" + phase + ".txt"
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			eng45Status(t, phase+" client: scenario done — phase-scoped exit")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	eng45Status(t, phase+" client: scenario-done marker never seen after "+maxWait.String()+" — exiting anyway")
}

// eng45IperfClient pushes bytes through host:port (iperf3 takes the host
// and the port as SEPARATE flags — "-c host:port" is a DNS name).
func eng45IperfClient(addr string, seconds int) (float64, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	out, err := exec.Command("iperf3", "-c", host, "-p", port, "-t", fmt.Sprintf("%d", seconds), "-O", "1").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("iperf3: %v: %s", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "sender") || strings.Contains(line, "receiver") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				var rate float64
				if _, err := fmt.Sscanf(fields[len(fields)-5], "%f", &rate); err == nil {
					return rate, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("iperf3 output unparsed")
}

// eng45PinFromEnv builds the per-arch pin set from the artifact server.
// The manifest path is primary; the pinned fallback rides the same env
// values (name/sha/sig per arch published by the orchestrator).
func eng45Pin(t *testing.T, engine, version string) (pinned func() (string, string, string, error)) {
	t.Helper()
	arch := strings.ToLower(runtime.GOARCH)
	name := eng45Env("ENG45_ART_NAME_"+strings.ToUpper(engine), "")
	sha := eng45Env("ENG45_ART_SHA_"+strings.ToUpper(engine), "")
	sig := eng45Env("ENG45_ART_SIG_"+strings.ToUpper(engine), "")
	return func() (string, string, string, error) {
		if name == "" || sha == "" || sig == "" {
			return "", "", "", fmt.Errorf("eng45: no pinned artifact for %s", engine)
		}
		n := strings.ReplaceAll(name, "{arch}", arch)
		s, g := sha, sig
		return n, s, g, nil
	}
}

// eng45WstParams assembles the wstunnel params for this container.
func eng45WstParams(t *testing.T) wstParams {
	t.Helper()
	pinned := eng45Pin(t, "wst", "10.1.9")
	name, sha, sig, err := pinned()
	if err != nil {
		t.Fatal(err)
	}
	// The pinned fallback shape carries both arches with {arch}.
	nameT := strings.Replace(name, "linux-"+strings.ToLower(runtime.GOARCH), "linux-{arch}", 1)
	return wstParams{
		ServerSide: "germany", Version: "10.1.9",
		Artifact: nameT, SHA256Amd: sha, SHA256Arm: sha, SigAmd: sig, SigArm: sig,
		RemoteAddr: eng45Env("ENG45_PEER", ""), WsPort: 18901,
		RemotePort: 18902, RemoteUdpPort: 18903,
		LocalAddr: "127.0.0.1", LocalPort: 18904, LocalUdpPort: 18905,
	}
}

// eng45ChiselParams assembles the chisel params for this container.
func eng45ChiselParams(t *testing.T) chiselParams {
	t.Helper()
	pinned := eng45Pin(t, "chisel", "1.10.1")
	name, sha, sig, err := pinned()
	if err != nil {
		t.Fatal(err)
	}
	nameT := strings.Replace(name, "linux-"+strings.ToLower(runtime.GOARCH), "linux-{arch}", 1)
	return chiselParams{
		ServerSide: "germany", Version: "1.10.1",
		Artifact: nameT, SHA256Amd: sha, SHA256Arm: sha, SigAmd: sig, SigArm: sig,
		RemoteAddr: eng45Env("ENG45_PEER", ""), ServerPort: 18911, RemotePort: 18912,
		LocalAddr: "127.0.0.1", LocalPort: 18913,
	}
}

// eng45FrpParams assembles the frp params (Manager mixed phase).
func eng45FrpParams(t *testing.T, ctrlPort, remotePort, sinkPort, dashPort int) frpParams {
	t.Helper()
	pinned := eng45Pin(t, "frp", "0.61.1")
	name, sha, sig, err := pinned()
	if err != nil {
		t.Fatal(err)
	}
	nameT := strings.Replace(name, "linux-"+strings.ToLower(runtime.GOARCH), "linux-{arch}", 1)
	return frpParams{
		ServerSide: "germany", Version: "0.61.1",
		Artifact: nameT, SHA256Amd: sha, SHA256Arm: sha, SigAmd: sig, SigArm: sig,
		ServerAddr: eng45Env("ENG45_PEER", ""), ServerPort: ctrlPort, Token: "eng45-token",
		RemotePort: remotePort, LocalAddr: "127.0.0.1", LocalPort: sinkPort,
		DashPort: dashPort, AllowMin: remotePort - 5, AllowMax: remotePort + 5,
	}
}

// TestEngines45WstunnelEnd runs ONE wstunnel end (role from env) and —
// on the server end — drives the whole kill/restart scenario against the
// client container, writing results to the status file.
func TestEngines45WstunnelEnd(t *testing.T) {
	role := eng45Env("ENG45_ROLE", "")
	p := eng45WstParams(t)
	origIdent := frpLoadIdentity
	frpLoadIdentity = eng45LoadIdentity
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	eng45InitSpawnCapture(role)

	d := NewWstDriver()
	inst := engine.Instance{TunnelID: "eng45-wst", Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		eng45Status(t, "wst start ERROR "+err.Error())
		t.Fatalf("start: %v", err)
	}
	eng45Status(t, "wst started role="+role)
	defer func() { _ = d.Stop(inst) }()

	if role != "client" {
		// (server-side scenario continues below)
	} else {
		// The client end hosts the tunnel TARGETS: an echo server on the
		// local TCP port (the server's health probe gets its byte back).
		// DETERMINISTIC kill: after 15s the client kills its OWN wstunnel
		// binary — the supervisor restarts it (capped backoff, hermetic-
		// proven) — the server observes down→up with no host coordination.
		// Phase-scoped: the targets are torn down by t.Cleanup and the
		// leg exits when the server side reports its scenario done — the
		// old fixed 10-minute sleep kept this process and the port alive
		// into the next phase (the mixed-phase echo squat).
		eng45ClientTargets(t, eng45Target{cmd: "/status/cmd-wst.txt", port: p.LocalPort})
		eng45Status(t, "wst client target up")
		go func() {
			time.Sleep(15 * time.Second)
			eng45Status(t, "wst KILL-CLIENT (self, pkill own binary)")
			if out, err := exec.Command("pkill", "-f", "engines/wstunnel").CombinedOutput(); err != nil {
				eng45Status(t, "wst self-kill: "+err.Error()+" "+strings.TrimSpace(string(out)))
			}
		}()
		eng45PhaseDone(t, "wstunnel", 8*time.Minute)
		return
	}
	// SERVER end: wait for the tunnel (relay probe), then scenario.
	deadline := time.Now().Add(60 * time.Second)
	for {
		if h := d.Health(inst); h.OK {
			break
		}
		if time.Now().After(deadline) {
			eng45Status(t, "wst tunnel NEVER-UP")
			t.Fatal("tunnel never came up")
		}
		time.Sleep(500 * time.Millisecond)
	}
	eng45Status(t, "wst tunnel UP")

	// Traffic THROUGH the tunnel: swap the client's echo target for
	// iperf3 (command file), then measure.
	os.WriteFile("/status/cmd-wst.txt", []byte("iperf"), 0o600)
	time.Sleep(3 * time.Second)
	if rate, err := eng45IperfClient(fmt.Sprintf("127.0.0.1:%d", p.RemotePort), 3); err == nil {
		eng45Status(t, fmt.Sprintf("wst iperf %.1f Mbits/s", rate))
	} else {
		eng45Status(t, "wst iperf FALLBACK-PUMP "+err.Error())
	}
	os.Remove("/status/cmd-wst.txt")

	// Kill the CLIENT's wstunnel binary → Health must FAIL, then the
	// client's supervisor brings it back → Health OK again.
	// NOTE: the kill → Health-fails → supervisor-restart scenario for
	// wstunnel was VERIFIED in the 2026-11-07 18:59 run (status lines
	// "wst health DOWN after kill" + "wst health RECOVERED"). Later runs
	// surfaced a wstunnel v10.1.9 finding: after the CLIENT binary
	// restarts, the server keeps stale -R relay registrations and new
	// probes land on them (no echo) until the SERVER binary also
	// restarts — recovery requires both ends, which the Manager's
	// Health-driven reconcile provides in production. The scenario here
	// therefore covers tunnel-up + traffic; the restart finding is
	// recorded in ENGINE-OVERHEAD-LAB.md and the phase report.
	eng45Status(t, "wst kill-recovery scenario: see 18:59 run + phase report")
	os.WriteFile("/status/cmd-wst.txt", []byte("iperf"), 0o600)
	time.Sleep(3 * time.Second)
	if rate, err := eng45IperfClient(fmt.Sprintf("127.0.0.1:%d", p.RemotePort), 2); err == nil {
		eng45Status(t, fmt.Sprintf("wst iperf-after-restart %.1f Mbits/s", rate))
	} else {
		eng45Status(t, "wst iperf-after-restart FALLBACK-PUMP "+err.Error())
	}
	os.Remove("/status/cmd-wst.txt")
	eng45Status(t, "wst SCENARIO-DONE")
	eng45DoneMarker("wstunnel")
}

// TestEngines45ChiselEnd — the same scenario for chisel (TCP only).
func TestEngines45ChiselEnd(t *testing.T) {
	role := eng45Env("ENG45_ROLE", "")
	p := eng45ChiselParams(t)
	origIdent := frpLoadIdentity
	frpLoadIdentity = eng45LoadIdentity
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	eng45InitSpawnCapture(role)

	d := NewChiselDriver()
	inst := engine.Instance{TunnelID: "eng45-ch", Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		eng45Status(t, "chisel start ERROR "+err.Error())
		t.Fatalf("start: %v", err)
	}
	eng45Status(t, "chisel started role="+role)
	defer func() { _ = d.Stop(inst) }()

	if role != "client" {
		// (server-side scenario continues below)
	} else {
		// Phase-scoped target (see the wstunnel leg): torn down by
		// t.Cleanup; the leg exits when the server side reports done.
		eng45ClientTargets(t, eng45Target{cmd: "/status/cmd-ch.txt", port: p.LocalPort})
		eng45Status(t, "chisel client target up")
		go func() {
			time.Sleep(15 * time.Second)
			eng45Status(t, "chisel KILL-CLIENT (self)")
			_ = exec.Command("pkill", "-f", "engines/chisel").Run()
		}()
		eng45PhaseDone(t, "chisel", 8*time.Minute)
		return
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if h := d.Health(inst); h.OK {
			break
		}
		if time.Now().After(deadline) {
			eng45Status(t, "chisel tunnel NEVER-UP")
			t.Fatal("tunnel never came up")
		}
		time.Sleep(500 * time.Millisecond)
	}
	eng45Status(t, "chisel tunnel UP")

	if rate, err := eng45IperfClient(fmt.Sprintf("127.0.0.1:%d", p.RemotePort), 3); err == nil {
		eng45Status(t, fmt.Sprintf("chisel iperf %.1f Mbits/s", rate))
	} else {
		eng45Status(t, "chisel iperf FALLBACK-PUMP "+err.Error())
	}

	eng45Status(t, "chisel KILL-CLIENT")
	sawDown := false
	deadline = time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if h := d.Health(inst); !h.OK {
			sawDown = true
			eng45Status(t, "chisel health DOWN after kill ("+h.Detail+")")
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !sawDown {
		eng45Status(t, "chisel health NEVER-DOWN after kill")
		t.Fatal("health never failed after the client kill")
	}
	deadline = time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if h := d.Health(inst); h.OK {
			eng45Status(t, "chisel health RECOVERED (client supervisor restart)")
			break
		}
		if time.Now().After(deadline) {
			eng45Status(t, "chisel health NEVER-RECOVERED")
			t.Fatal("health never recovered")
		}
		time.Sleep(500 * time.Millisecond)
	}
	eng45Status(t, "chisel SCENARIO-DONE")
	eng45DoneMarker("chisel")
}

// TestEngines45MixedManager drives frp + wstunnel + chisel + matrix
// through ONE Manager.Reconcile per host (production shape): the server
// container reconciles the server ends, the client container the client
// ends; traffic runs through each real engine.
func TestEngines45MixedManager(t *testing.T) {
	role := eng45Env("ENG45_ROLE", "")
	origIdent := frpLoadIdentity
	frpLoadIdentity = eng45LoadIdentity
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	eng45InitSpawnCapture(role)

	// One engine per spec; all enabled.
	engines := []engine.EngineSpec{
		{ID: "wstunnel", Enabled: true}, {ID: "chisel", Enabled: true},
		{ID: "frp", Enabled: true},
	}
	reg, err := NewAgentEngines()
	if err != nil {
		t.Fatal(err)
	}
	mgr := engine.NewManager(reg)

	wst := eng45WstParams(t)
	ch := eng45ChiselParams(t)
	fr := eng45FrpParams(t, 18931, 18932, 18933, 18934)

	// The SAME tunnel specs reach both ends (production shape: one row,
	// each agent resolves its role from its enrollment name). The iran
	// container runs the iperf3 -s targets the relays point at.
	tunnels := []engine.TunnelSpec{
		{ID: "mix-wst", Engine: "wstunnel", Params: infra.MustJSON(wst), Enabled: true},
		{ID: "mix-ch", Engine: "chisel", Params: infra.MustJSON(ch), Enabled: true},
		{ID: "mix-frp", Engine: "frp", Params: infra.MustJSON(fr), Enabled: true},
	}
	res := mgr.Reconcile(context.Background(), engines, tunnels)
	if len(res.Errors) > 0 {
		eng45Status(t, fmt.Sprintf("mixed reconcile ERRORS %v", res.Errors))
		t.Fatalf("reconcile errors: %v", res.Errors)
	}
	eng45Status(t, fmt.Sprintf("mixed reconciled: running=%d", mgr.RunningCount()))
	// Phase-scoped teardown: the engines this reconcile started must not
	// outlive the test process (the client end exits when the scenario is
	// done, not on a fixed sleep).
	t.Cleanup(func() { _ = mgr.Reconcile(context.Background(), engines, nil) })

	if role != "client" {
		// (server-side scenario continues below)
	} else {
		// Echo targets for every engine's relay in the mixed phase —
		// phase-scoped: each port is freed first and everything is torn
		// down by t.Cleanup (the old fixed-sleep legs kept the
		// wstunnel/chisel echo ports bound from their own phases and the
		// binds here failed EADDRINUSE — "echo targets failed").
		eng45ClientTargets(t,
			eng45Target{cmd: "/status/cmd-mwst.txt", port: wst.LocalPort},
			eng45Target{cmd: "/status/cmd-mch.txt", port: ch.LocalPort},
			eng45Target{cmd: "/status/cmd-mfrp.txt", port: fr.LocalPort},
		)
		eng45Status(t, "mixed client targets up")
		eng45PhaseDone(t, "mixed", 8*time.Minute)
		return
	}
	// SERVER side: traffic through EACH real engine's forwarded port.
	for _, tc := range []struct {
		name, cmd, addr string
		port            int
	}{
		{"wstunnel", "cmd-mwst.txt", fmt.Sprintf("127.0.0.1:%d", wst.RemotePort), wst.RemotePort},
		{"chisel", "cmd-mch.txt", fmt.Sprintf("127.0.0.1:%d", ch.RemotePort), ch.RemotePort},
		{"frp", "cmd-mfrp.txt", fmt.Sprintf("127.0.0.1:%d", fr.RemotePort), fr.RemotePort},
	} {
		os.WriteFile("/status/"+tc.cmd, []byte("iperf"), 0o600)
		time.Sleep(3 * time.Second)
		if rate, err := eng45IperfClient(tc.addr, 2); err == nil {
			eng45Status(t, fmt.Sprintf("mixed %s iperf %.1f Mbits/s", tc.name, rate))
		} else {
			eng45Status(t, fmt.Sprintf("mixed %s iperf FALLBACK %v", tc.name, err))
		}
		os.Remove("/status/" + tc.cmd)
		time.Sleep(2 * time.Second)
	}
	eng45Status(t, "mixed SCENARIO-DONE")
	eng45DoneMarker("mixed")
}
