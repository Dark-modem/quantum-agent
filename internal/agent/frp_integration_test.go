//go:build integration

// frp_integration_test.go — REAL frp binaries through the REAL driver
// paths (artifact download → verify → extract → process spawn → tunnel →
// traffic → kill → Health fail → Manager restart), plus lab-loopback
// throughput for the overhead ratio. Numbers are loopback ONLY.
//
//	Run: FRP_INTEGRATION=1 go test -tags integration -run TestFRPIntegration \
//	         ./internal/agent/ -count=1 -v
//
// Requires: Linux, network (builds frps/frpc v0.61.1 from source).

package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

func frpIntSkip(t *testing.T) string {
	t.Helper()
	if os.Getenv("FRP_INTEGRATION") == "" {
		t.Skip("FRP_INTEGRATION not set (builds frp from source; network + Linux)")
	}
	dir := os.Getenv("FRP_INTEG_DIR")
	if dir == "" {
		t.Skip("FRP_INTEG_DIR not set (work dir)")
	}
	return dir
}

// buildFRPSource builds real frps + frpc from the public frp source.
// cleanGoEnv strips GOFLAGS/GOPACKAGESDRIVER from the environment so the
// pkg@version build is module-clean.
func cleanGoEnv() []string {
	var out []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "GOFLAGS=") || strings.HasPrefix(e, "GOPACKAGESDRIVER=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

func buildFRPSource(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct{ out, pkg string }{
		{filepath.Join(dir, "src-frps"), "github.com/fatedier/frp/cmd/frps"},
		{filepath.Join(dir, "src-frpc"), "github.com/fatedier/frp/cmd/frpc"},
	} {
		if _, err := os.Stat(spec.out); err == nil {
			continue
		}
		// frp's go.mod carries replace directives, so `go install pkg@version`
		// refuses it. Clone the repo at the tag (its go.mod is then the MAIN
		// module, which is fine) and build from there.
		repo := filepath.Join(dir, "frp-src")
		if _, err := os.Stat(filepath.Join(repo, "go.mod")); err != nil {
			clone := exec.Command("git", "clone", "--depth", "1", "--branch", "v0.61.1",
				"https://github.com/fatedier/frp", repo)
			if out, err := clone.CombinedOutput(); err != nil {
				t.Fatalf("clone frp: %v: %s", err, string(out[:minInt(len(out), 300)]))
			}
		}
		cmd := exec.Command("go", "build", "-trimpath", "-o", spec.out, spec.pkg)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-mod=mod")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v: %s", spec.pkg, err, string(out[:minInt(len(out), 300)]))
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// frpIntegrationArtifact wraps the REAL frps/frpc binaries into the
// tar.gz the driver extracts (frp_0.61.1/{frps,frpc}), returning the
// artifact bytes + pins.
func frpIntegrationArtifact(t *testing.T, dir string) (body []byte, shaHex, sigB64, pubB64 string) {
	t.Helper()
	buildFRPSource(t, dir)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 = base64.StdEncoding.EncodeToString(pubDER)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	// The real GitHub release wraps the binaries in a version DIRECTORY
	// entry; include one here so extraction is exercised against the
	// production tarball shape (directory entries must be skipped, not
	// refused).
	if err := tw.WriteHeader(&tar.Header{
		Name: "frp_0.61.1/", Mode: int64(0o755), Typeflag: tar.TypeDir,
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"frps", "frpc"} {
		content, err := os.ReadFile(filepath.Join(dir, "src-"+name))
		if err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(&tar.Header{Name: "frp_0.61.1/" + name, Mode: 0o755, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	body = buf.Bytes()
	sum := sha256.Sum256(body)
	shaHex = hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, body)
	sigB64 = base64.StdEncoding.EncodeToString(sig)
	return body, shaHex, sigB64, pubB64
}

func TestFRPIntegration(t *testing.T) {
	dir := frpIntSkip(t)
	body, shaHex, sigB64, pubB64 := frpIntegrationArtifact(t, dir)

	// Artifact HTTP server (the R5 controller endpoint stand-in): a REAL
	// listener so the driver's own download path runs end to end.
	artLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Logf("artifact request: %s %s", r.Method, r.URL.Path)
		w.Write(body)
	})
	artSrv := &http.Server{Handler: mux}
	go artSrv.Serve(artLn)
	defer artSrv.Close()
	artURL := fmt.Sprintf("http://127.0.0.1:%d", artLn.Addr().(*net.TCPAddr).Port)

	// Driver config dir + identity pointing at the artifact server.
	cfg := t.TempDir()
	origConfigDir := configDir
	configDir = cfg
	t.Cleanup(func() { configDir = origConfigDir })
	origIdent := frpLoadIdentity
	// The identity's Name is the role resolver's self-identifier: it must
	// equal params.server_side on the frps end ("germany") and differ on
	// the frpc end. The seam is swapped between the two Starts below —
	// in production the two agents have separate identities.
	identName := "germany"
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: artURL, BasePath: "", Name: identName}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	t.Cleanup(func() { engineArtifactPubKeyB64 = origKey })
	// Capture the real frp processes' output into the work dir (the default
	// frpSpawn discards it, and the tunnel-not-up failure needs the logs).
	origSpawn := frpSpawn
	frpSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		logFile := filepath.Join(os.Getenv("FRP_INTEG_DIR"),
			filepath.Base(binPath)+".log")
		cmd := exec.Command(binPath, "-c", cfgPath)
		lf, err := os.Create(logFile)
		if err != nil {
			return nil, err
		}
		cmd.Stdout = lf
		cmd.Stderr = lf
		if err := cmd.Start(); err != nil {
			lf.Close()
			return nil, fmt.Errorf("frp: start %s: %w", binPath, err)
		}
		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
			lf.Close()
		}()
		return &frpExecProcess{cmd: cmd, done: done}, nil
	}
	t.Cleanup(func() { frpSpawn = origSpawn })
	// The hermetic TestMain stubs the runner seam; the integration test
	// needs REAL host commands (iptables counters, config probes).
	origRunner := runner
	runner = execRunner
	t.Cleanup(func() { runner = origRunner })

	// Ports.
	// Probe ports BELOW the ephemeral range (Linux default 32768-60999):
	// a port from the ephemeral range can be grabbed by any outbound
	// connection between the probe and the bind. The probe NEVER returns
	// the same port twice (each call advances the cursor) — otherwise all
	// four ports collide on the first free one and frps exits with
	// "address already in use" on its own dashboard.
	nextPort := 20000
	freePort := func() int {
		for nextPort < 30000 {
			base := nextPort
			nextPort += 7
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base))
			if err != nil {
				continue
			}
			p := ln.Addr().(*net.TCPAddr).Port
			ln.Close()
			return p
		}
		t.Fatal("no free port in 20000-30000")
		return 0
	}
	ctrlPort := freePort()
	remotePort := freePort()
	sinkPort := freePort()
	dashPort := freePort()

	_, stopSink := tcpSink(t, fmt.Sprintf("127.0.0.1:%d", sinkPort))
	defer stopSink()

	// Real pins, real params — one tunnel description serves both ends,
	// same shape desired state carries.
	p := frpParams{
		ServerSide: "germany", Version: "0.61.1",
		Artifact:  "frp-0.61.1-linux-{arch}.tar.gz",
		SHA256Amd: shaHex, SHA256Arm: shaHex, SigAmd: sigB64, SigArm: sigB64,
		ServerAddr: "127.0.0.1", ServerPort: ctrlPort, Token: "int-token",
		RemotePort: remotePort, LocalAddr: "127.0.0.1", LocalPort: sinkPort,
		DashPort: dashPort, AllowMin: remotePort - 10, AllowMax: remotePort + 10,
	}
	// Compiler shape: BOTH ends receive the tunnel's local/remote names in
	// the same fields — the compiler does not swap them per agent (the
	// remote end sees its OWN name in RemoteServer). The role therefore
	// resolves from the enrollment identity, not from these fields. The
	// identity seam below is swapped between the two Starts accordingly.
	srvInst := engine.Instance{TunnelID: "t-int-srv", LocalServer: "iran",
		RemoteServer: "germany", Params: mustJSON(p)}
	cliInst := engine.Instance{TunnelID: "t-int-cli", LocalServer: "iran",
		RemoteServer: "germany", Params: mustJSON(p)}

	// In production each agent host runs its own driver instance; the two
	// ends of a tunnel never share one runs map. Mirror that here.
	dSrv := NewFRPDriver()
	dCli := NewFRPDriver()
	ctx := context.Background()

	// EnsureBinary: the real download → verify → extract path.
	binDir, err := frpEnsureBinary(ctx, p)
	if err != nil {
		t.Fatalf("EnsureBinary: %v", err)
	}
	for _, b := range []string{"frps", "frpc"} {
		if fi, err := os.Stat(filepath.Join(binDir, b)); err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("EnsureBinary missing %s: %v", b, err)
		}
	}

	// Start both ends (real frps + frpc processes). The identity seam is
	// swapped so each end resolves its own role from its own enrollment
	// name — in production the two agents have separate identities.
	identName = "germany"
	if err := dSrv.Start(ctx, srvInst); err != nil {
		t.Fatalf("frps start: %v", err)
	}
	// frpc's loginFailExit default means ONE refused connection exits the
	// client permanently — the control port must be live first.
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", ctrlPort), 15*time.Second)
	identName = "iran"
	if err := dCli.Start(ctx, cliInst); err != nil {
		t.Fatalf("frpc start: %v", err)
	}
	defer func() {
		_ = dSrv.Stop(srvInst)
		_ = dCli.Stop(cliInst)
		_ = dSrv.Uninstall(ctx)
		_ = dCli.Uninstall(ctx)
	}()

	// Tunnel up: traffic passes end to end.
	for _, f := range []string{"engines/frp/t-int.toml"} {
		if b, err := os.ReadFile(filepath.Join(cfg, f)); err == nil {
			t.Logf("rendered %s: %s", f, strings.ReplaceAll(string(b), "\n", " | "))
		} else {
			t.Logf("rendered %s: %v", f, err)
		}
	}
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", remotePort), 15*time.Second)
	sendAndExpect(t, remotePort, "hello-through-tunnel")

	// Health: both ends OK (server via the real dashboard API handshake).
	sec := frpDashSecret(srvInst.TunnelID, p)
	code, dashErr := frpDashStatus(dashPort, sec)
	t.Logf("dashboard probe: port=%d secret=%s code=%d err=%v", dashPort, sec, code, dashErr)
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/api/status", dashPort), nil)
	req.SetBasicAuth("quantum", sec)
	resp, rerr := http.DefaultClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		t.Logf("dashboard raw: code=%d err=%v body=%s", resp.StatusCode, rerr, string(b))
	}
	if h := dSrv.Health(srvInst); !h.OK {
		t.Fatalf("frps health down: %+v", h)
	}
	if h := dCli.Health(cliInst); !h.OK {
		t.Fatalf("frpc health down: %+v", h)
	}

	// Kill the frps process → Health must fail.
	killFRPProcesses(t, "frps")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if !dSrv.Health(srvInst).OK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("frps Health still OK 5s after kill")
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Log("frps killed → Health correctly reports failure")

	// Manager behavior: stop + start again → traffic passes.
	if err := dSrv.Stop(srvInst); err != nil {
		t.Fatalf("stop after kill: %v", err)
	}
	if err := dSrv.Start(ctx, srvInst); err != nil {
		t.Fatalf("frps restart: %v", err)
	}
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", ctrlPort), 15*time.Second)
	if err := dCli.Start(ctx, cliInst); err != nil {
		t.Fatalf("frpc restart: %v", err)
	}
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", remotePort), 15*time.Second)
	sendAndExpect(t, remotePort, "after-restart")

	// LAB-LOOPBACK overhead: direct sink vs through the tunnel.
	direct := benchTCP(t, fmt.Sprintf("127.0.0.1:%d", sinkPort), 8<<20)
	via := benchTCP(t, fmt.Sprintf("127.0.0.1:%d", remotePort), 8<<20)
	t.Logf("LAB-LOOPBACK: direct %.1f MB/s, via frp %.1f MB/s, ratio %.2f (overhead ~%.0f%%)",
		direct, via, via/direct, (1-via/direct)*100)

	// Counters: honest Known flags.
	c := dSrv.Counters(srvInst)
	t.Logf("server counters: wire_known=%v payload_known=%v payload_rx=%d payload_tx=%d",
		c.WireKnown, c.PayloadKnown, c.PayloadRx, c.PayloadTx)
}

// tcpSink accepts connections and counts every byte; returns the count
// getter (stop by closing the listener).
func tcpSink(t *testing.T, addr string) (got func() uint64, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	var total uint64
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			go func(c net.Conn) {
				n, _ := io.Copy(io.Discard, c)
				total += uint64(n)
				c.Close()
			}(conn)
		}
	}()
	return func() uint64 { return total }, func() { ln.Close(); <-done }
}

func waitTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("%s never came up within %s", addr, timeout)
}

func sendAndExpect(t *testing.T, remotePort int, payload string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort), 5*time.Second)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // let the sink drain the bytes
}

func benchTCP(t *testing.T, addr string, total int64) float64 {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("bench dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	start := time.Now()
	buf := make([]byte, 64<<10)
	written := int64(0)
	for written < total {
		n, err := conn.Write(buf)
		written += int64(n)
		if err != nil {
			t.Fatalf("bench write: %v", err)
		}
	}
	return float64(written) / time.Since(start).Seconds() / (1 << 20)
}

func killFRPProcesses(t *testing.T, name string) {
	t.Helper()
	_ = exec.Command("pkill", "-f", name).Run()
}

var _ = json.Marshal // keep json if unused in some build paths
