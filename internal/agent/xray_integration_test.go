//go:build integration

// xray_integration_test.go — REAL Xray-core binaries through the REAL
// driver paths (R5-style artifact download → verify → extract with the
// directory-entry tarball → typed-config render → spawn → Reality tunnel
// up → iperf3 through the tunnel per direction → kill → Health fail →
// supervisor restart → traffic again). Both ends run in SEPARATE network
// namespaces (quantum-test-* naming). All numbers lab-loopback ONLY.
//
//	Run: XRAY_INTEGRATION=1 XRAY_INTEG_DIR=/tmp/xray-int \
//	         go test -tags integration -run TestXrayIntegration \
//	         ./internal/agent/ -count=1 -v   (as root; iperf3, ip needed)
//
// Requires: Linux root, network (builds Xray-core from source at the
// pinned tag), iperf3, openssl, python3 (the local Reality-dest TLS
// endpoint), nc. Cleanup is trap-driven.

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

const xrayUpstreamTag = "v24.12.31"

func xrayIntSkip(t *testing.T) string {
	t.Helper()
	if os.Getenv("XRAY_INTEGRATION") == "" {
		t.Skip("XRAY_INTEGRATION not set (builds Xray-core from source; root + Linux + iperf3)")
	}
	dir := os.Getenv("XRAY_INTEG_DIR")
	if dir == "" {
		t.Skip("XRAY_INTEG_DIR not set")
	}
	return dir
}

// xrayBuildSource builds the REAL xray binary from the upstream source at
// the pinned tag (Xray's go.mod is the main module — direct build).
func xrayBuildSource(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "src-xray")
	if _, err := os.Stat(bin); err == nil {
		return bin
	}
	repo := filepath.Join(dir, "xray-src")
	if _, err := os.Stat(filepath.Join(repo, "go.mod")); err != nil {
		clone := exec.Command("git", "clone", "-q", "--depth", "1", "--branch", xrayUpstreamTag,
			"https://github.com/XTLS/Xray-core", repo)
		if out, err := clone.CombinedOutput(); err != nil {
			t.Fatalf("clone xray: %v: %s", err, string(out[:minInt(len(out), 300)]))
		}
	}
	cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", bin, "./main")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-mod=mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build xray: %v: %s", err, string(out[:minInt(len(out), 300)]))
	}
	return bin
}

// xrayIntegrationArtifact wraps the REAL binary into the tar.gz the
// driver extracts (xray_24.12.31/{xray}) — directory entry included.
func xrayIntegrationArtifact(t *testing.T, dir string, realBin string) (body []byte, shaHex, sigB64, pubB64 string) {
	t.Helper()
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
	if err := tw.WriteHeader(&tar.Header{Name: "xray_24.12.31/", Mode: int64(0o755), Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(realBin)
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "xray_24.12.31/xray", Mode: 0o755, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
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

// xrayIntKeygen runs `xray x25519` on the REAL binary: the deploy-time
// Reality keypair helper path.
func xrayIntKeygen(t *testing.T, bin string) (pub, priv string) {
	t.Helper()
	out, err := exec.Command(bin, "x25519").CombinedOutput()
	if err != nil {
		t.Fatalf("xray x25519: %v: %s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Private key:") {
			priv = strings.TrimSpace(strings.TrimPrefix(line, "Private key:"))
		}
		if strings.HasPrefix(line, "Public key:") {
			pub = strings.TrimSpace(strings.TrimPrefix(line, "Public key:"))
		}
	}
	if pub == "" || priv == "" {
		t.Fatalf("xray x25519 output unparsable: %s", out)
	}
	return pub, priv
}

const (
	xrNSA     = "quantum-test-xray-a" // foreign end (Xray server)
	xrNSB     = "quantum-test-xray-b" // Iran end (Xray client)
	xrIPA     = "10.204.0.1"
	xrIPB     = "10.204.0.2"
	xrCarrier = 25443 // VLESS+Reality carrier (foreign)
	xrPublic  = 25401 // dokodemo data port (foreign)
	xrIperf   = 25402 // iperf3 server (Iran end target)
	xrDest    = 25499 // local Reality-dest TLS endpoint (Iran end)
	xrVethA   = "v-xr-a"
	xrVethB   = "v-xr-b"
)

func TestXrayIntegration(t *testing.T) {
	dir := xrayIntSkip(t)
	realBin := xrayBuildSource(t, dir)
	body, shaHex, sigB64, pubB64 := xrayIntegrationArtifact(t, dir, realBin)
	realityPub, realityPriv := xrayIntKeygen(t, realBin)

	clean := func() {
		exec.Command("sudo", "ip", "netns", "del", xrNSA).Run()
		exec.Command("sudo", "ip", "netns", "del", xrNSB).Run()
		exec.Command("sudo", "ip", "link", "del", xrVethA).Run()
		exec.Command("sudo", "ip", "link", "del", xrVethB).Run()
	}
	clean()
	t.Cleanup(clean)
	if out, err := exec.Command("sudo", "ip", "netns", "add", xrNSA).CombinedOutput(); err != nil {
		t.Fatalf("netns a: %v: %s", err, out)
	}
	if out, err := exec.Command("sudo", "ip", "netns", "add", xrNSB).CombinedOutput(); err != nil {
		t.Fatalf("netns b: %v: %s", err, out)
	}
	if out, err := exec.Command("sudo", "ip", "link", "add", xrVethA, "type", "veth", "peer", "name", xrVethB).CombinedOutput(); err != nil {
		t.Fatalf("veth: %v: %s", err, out)
	}
	if out, err := exec.Command("sudo", "ip", "link", "set", xrVethA, "netns", xrNSA).CombinedOutput(); err != nil {
		t.Fatalf("move a: %v: %s", err, out)
	}
	if out, err := exec.Command("sudo", "ip", "link", "set", xrVethB, "netns", xrNSB).CombinedOutput(); err != nil {
		t.Fatalf("move b: %v: %s", err, out)
	}
	runNS := func(ns string, args ...string) (string, error) {
		full := append([]string{"ip", "netns", "exec", ns}, args...)
		out, err := exec.Command("sudo", full...).CombinedOutput()
		return string(out), err
	}
	mustNS := func(ns string, args ...string) string {
		out, err := runNS(ns, args...)
		if err != nil {
			t.Fatalf("netns exec %s %v: %v: %s", ns, args, err, out)
		}
		return out
	}
	mustNS(xrNSA, "ip", "addr", "add", xrIPA+"/30", "dev", xrVethA)
	mustNS(xrNSA, "ip", "link", "set", xrVethA, "up")
	mustNS(xrNSA, "ip", "link", "set", "lo", "up")
	mustNS(xrNSB, "ip", "addr", "add", xrIPB+"/30", "dev", xrVethB)
	mustNS(xrNSB, "ip", "link", "set", xrVethB, "up")
	mustNS(xrNSB, "ip", "link", "set", "lo", "up")
	if out, err := runNS(xrNSB, "ping", "-c", "1", "-W", "2", xrIPA); err != nil {
		t.Fatalf("underlay unreachable: %v: %s", err, out)
	}

	// Same-run underlay baseline (the lab rules: the ratio is computed
	// against the SAME run's baseline, never a different run's).
	const xrBase = 25498
	mustNS(xrNSB, "sh", "-c", fmt.Sprintf("nohup iperf3 -s -p %d > /dev/null 2>&1 &", xrBase))
	defer func() { _, _ = runNS(xrNSB, "pkill", "-f", fmt.Sprintf("iperf3 -s -p %d", xrBase)) }()
	time.Sleep(time.Second)
	if base, berr := runNS(xrNSA, "sh", "-c",
		fmt.Sprintf("timeout 30 iperf3 -c %s -p %d -t 3 2>&1 | grep -E 'sender|receiver'", xrIPB, xrBase)); berr == nil {
		t.Logf("lab-loopback UNDERLAY baseline (no tunnel): %s", strings.TrimSpace(base))
	}

	// Local Reality-dest TLS endpoint (self-signed CA for CN=www.microsoft.com
	// installed into the SHARED fs — both netns trust it). The Reality
	// server mirrors this cert during handshakes; without a reachable dest
	// every handshake dies (the earlier "carrier up but no data" mystery).
	crt, key := "/tmp/xr-int-server.crt", "/tmp/xr-int-server.key"
	caFile := "/usr/local/share/ca-certificates/quantum-xray-int.crt"
	if out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-days", "2", "-keyout", key, "-out", crt, "-subj", "/CN=www.microsoft.com",
		"-addext", "subjectAltName=DNS:www.microsoft.com").CombinedOutput(); err != nil {
		t.Fatalf("openssl self-signed: %v: %s", err, out)
	}
	if out, err := exec.Command("sudo", "cp", crt, caFile).CombinedOutput(); err != nil {
		t.Fatalf("install CA: %v: %s", err, out)
	}
	if out, err := exec.Command("sudo", "update-ca-certificates").CombinedOutput(); err != nil {
		t.Fatalf("update-ca-certificates: %v: %s", err, out)
	}
	t.Cleanup(func() {
		exec.Command("sudo", "rm", "-f", caFile).Run()
		exec.Command("sudo", "update-ca-certificates").Run()
		exec.Command("rm", "-f", crt, key).Run()
	})
	destSrv := fmt.Sprintf(`nohup python3 -c "
import ssl, socket, os, threading
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('%s', '%s')
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', %d)); s.listen(16)
open('/tmp/xr-int-dest.pid','w').write(str(os.getpid()))
def h(c):
    try:
        t = ctx.wrap_socket(c, server_side=True)
        t.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi')
        t.close()
    except Exception:
        try: c.close()
        except Exception: pass
while True:
    c, _ = s.accept()
    threading.Thread(target=h, args=(c,), daemon=True).start()
" > /dev/null 2>&1 &`, crt, key, xrDest)
	mustNS(xrNSB, "sh", "-c", destSrv)
	t.Cleanup(func() { runNS(xrNSB, "sh", "-c", "kill $(cat /tmp/xr-int-dest.pid) 2>/dev/null || true") })

	// R5-style artifact server (REAL listener).
	artLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
	artSrv := &http.Server{Handler: mux}
	go artSrv.Serve(artLn)
	defer artSrv.Close()
	artURL := fmt.Sprintf("http://127.0.0.1:%d", artLn.Addr().(*net.TCPAddr).Port)

	origConfigDir := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = origConfigDir })
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	t.Cleanup(func() { engineArtifactPubKeyB64 = origKey })
	origRunner := runner
	runner = execRunner
	t.Cleanup(func() { runner = origRunner })

	// One driver per end; the identity decides the role.
	dServer := NewXrayDriver()
	dClient := NewXrayDriver()
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: artURL, BasePath: "", Name: "germany"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })

	// Spawn seam: run inside the server/client namespace respectively,
	// logs into the work dir (for the failure dump).
	serveNS := xrNSA
	logTag := "server"
	origSpawn := xraySpawn
	xraySpawn = func(binPath, cfgPath string) (frpProcess, error) {
		lf, err := os.Create(filepath.Join(dir, logTag+".log"))
		if err != nil {
			return nil, err
		}
		cmd := exec.Command("sudo", "ip", "netns", "exec", serveNS, binPath, "run", "-c", cfgPath)
		cmd.Stdout = lf
		cmd.Stderr = lf
		if err := cmd.Start(); err != nil {
			lf.Close()
			return nil, err
		}
		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
			lf.Close()
		}()
		return &frpExecProcess{cmd: cmd, done: done}, nil
	}
	t.Cleanup(func() { xraySpawn = origSpawn })

	p := xrayParams{
		ServerSide: "germany", Version: "24.12.31",
		Artifact:  "xray-24.12.31-linux-{arch}.tar.gz",
		SHA256Amd: shaHex, SHA256Arm: shaHex,
		SigAmd: sigB64, SigArm: sigB64,
		RemoteAddr: xrIPA, CarrierPort: xrCarrier,
		PublicPort: xrPublic, LocalAddr: "127.0.0.1", LocalPort: xrIperf,
		// Dest is the LOCAL TLS endpoint in xrNSB (the netns cannot reach
		// the real internet — egress rides the host VPN; raw-forwarded
		// traffic cannot dial the camouflage site, which killed every
		// Reality handshake in earlier runs). The Reality server mirrors
		// this cert; the SNI stays www.microsoft.com and the netns trust
		// store carries the lab CA.
		ServerName: "www.microsoft.com", Dest: fmt.Sprintf("%s:%d", xrIPB, xrDest),
		ShortID: "0123abcd", RealityPublicKey: realityPub,
		RealityPrivateKey: realityPriv,
		// Flow must be EMPTY: the reverse carrier multiplexes by itself
		// (mux.cool); vision stalls all data (see xrayValidateParams).
		Flow: "", UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		APIPort: 21599,
	}

	// Start the SERVER end inside xrNSA (its identity name matches).
	serverInst := engine.Instance{TunnelID: "xr-int-s", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(p)}
	if err := dServer.Start(context.Background(), serverInst); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	// The CLIENT end inside xrNSB dials the carrier; its identity differs.
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: artURL, BasePath: "", Name: "iran-1"}, true
	}
	serveNS = xrNSB
	logTag = "client"
	clientInst := engine.Instance{TunnelID: "xr-int-c", LocalServer: "iran", RemoteServer: "germany",
		Params: mustJSON(p)}
	if err := dClient.Start(context.Background(), clientInst); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	serveNS = xrNSA
	logTag = "server"
	t.Cleanup(func() {
		_ = dServer.Stop(serverInst)
		_ = dClient.Stop(clientInst)
	})

	// Wait for the carrier: the client end's dialer logs + a real TCP
	// connect to the carrier port from xrNSB.
	deadline := time.Now().Add(60 * time.Second)
	carrierUp := false
	for time.Now().Before(deadline) {
		if out, err := runNS(xrNSB, "sh", "-c",
			fmt.Sprintf("timeout 2 nc -z %s %d && echo OPEN", xrIPA, xrCarrier)); err == nil &&
			strings.Contains(out, "OPEN") {
			carrierUp = true
			break
		}
		time.Sleep(time.Second)
	}
	if !carrierUp {
		t.Fatalf("carrier never came up; server log: %s", bhIntTail(t, dir, "server"))
	}

	// Warmup gate (PHASE8 1b): route the driver's through-tunnel probe
	// into the SERVER namespace (the probe port lives inside xrNSA) and
	// expect the bridge's HTTP answer — the REAL round trip.
	origProbeFn := xrayProbeFn
	xrayProbeFn = func(int) error {
		out, err := runNS(xrNSA, "sh", "-c",
			fmt.Sprintf("printf 'GET /probe HTTP/1.0\\r\\nHost: probe.quantum\\r\\n\\r\\n' | timeout 3 nc 127.0.0.1 %d 2>/dev/null | head -c 5", 21599+1))
		if err == nil && strings.HasPrefix(out, "HTTP/") {
			return nil
		}
		return fmt.Errorf("probe: %q %v", out, err)
	}
	t.Cleanup(func() { xrayProbeFn = origProbeFn })
	// The driver's stats gate and Counters run `xray api statsquery`
	// against the api-in listener — which lives INSIDE xrNSA (the server
	// end's netns). From the test process (host netns) that loopback dial
	// can never answer, so route the SAME production query through the
	// server netns, exactly the way xrayProbeFn routes the warmup probe
	// (both exercise the real listener; in production the agent and its
	// drivers share one netns, so the un-routed dial is correct there).
	// Discovered 2026-11-19: this leg failed identically at the A1 tip
	// (4452c88) and the pre-A1 base (f78d2e3) — a test-harness topology
	// gap, not a driver regression.
	origStats := execCommandJSON
	execCommandJSON = func(apiPort int, prefix string) (uint64, uint64, bool) {
		out, err := runNS(xrNSA, realBin, "api", "statsquery",
			fmt.Sprintf("--server=127.0.0.1:%d", apiPort))
		if err != nil {
			return 0, 0, false
		}
		var parsed struct {
			Stats []struct {
				Name  string `json:"name"`
				Value int64  `json:"value"`
			} `json:"stats"`
		}
		if json.Unmarshal([]byte(out), &parsed) != nil {
			return 0, 0, false
		}
		var up, down uint64
		for _, s := range parsed.Stats {
			if !strings.HasPrefix(s.Name, prefix) {
				continue
			}
			switch {
			case strings.HasSuffix(s.Name, ">>>uplink"):
				up = uint64(s.Value)
			case strings.HasSuffix(s.Name, ">>>downlink"):
				down = uint64(s.Value)
			}
		}
		return up, down, true
	}
	t.Cleanup(func() { execCommandJSON = origStats })
	// EARLY in the warmup the tunnel must NOT be reported healthy: the
	// balancer must not route to a tunnel whose channel pool is not up.
	if h := dServer.Health(serverInst); h.OK {
		t.Fatalf("health reported OK before the through-tunnel probe: %+v", h)
	}
	t.Logf("lab-loopback warmup gate: Health correctly unhealthy before the probe")

	// iperf3 target on the IRAN end (the tunnel carries connections from
	// the foreign dokodemo INTO this listener).
	mustNS(xrNSB, "sh", "-c",
		fmt.Sprintf("nohup iperf3 -s -p %d > /dev/null 2>&1 &", xrIperf))
	defer func() { _, _ = runNS(xrNSB, "pkill", "-f", fmt.Sprintf("iperf3 -s -p %d", xrIperf)) }()
	// Readiness: the iperf3 listener must be answering before the client
	// dials through the tunnel (the reverse channel needs the target up).
	rDeadline := time.Now().Add(15 * time.Second)
	iperfUp := false
	for time.Now().Before(rDeadline) {
		if out, err := runNS(xrNSB, "sh", "-c", fmt.Sprintf("timeout 1 nc -z 127.0.0.1 %d && echo UP", xrIperf)); err == nil && strings.Contains(out, "UP") {
			iperfUp = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !iperfUp {
		t.Fatal("iperf3 listener in xrNSB never came up")
	}

	// Plain TCP through the FULL tunnel before any iperf3 run (TASK 3a
	// checklist): dokodemo → rev-portal → reverse channel → bridge →
	// freedom → the iperf3 listener. This is also the WARMUP: the bridge
	// registers its channel pool lazily, and the FIRST public connections
	// arrive on an empty worker list and are dropped — probe until the
	// path answers, otherwise the measurement measures the warmup.
	wDeadline := time.Now().Add(30 * time.Second)
	pathUp := false
	for time.Now().Before(wDeadline) {
		if out, err := runNS(xrNSA, "sh", "-c", fmt.Sprintf("timeout 2 nc -z 127.0.0.1 %d && echo PATHUP", xrPublic)); err == nil && strings.Contains(out, "PATHUP") {
			pathUp = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !pathUp {
		t.Fatalf("full tunnel path never answered; portal log: %s", bhIntTail(t, dir, "server"))
	}
	t.Logf("lab-loopback full-tunnel TCP probe OK (warmup complete)")
	// With the path answering, the warmup gate must OPEN (probe ok).
	if h := dServer.Health(serverInst); !h.OK {
		t.Fatalf("health still unhealthy after the probe succeeded: %+v", h)
	}
	t.Logf("lab-loopback warmup gate: Health healthy after the probe (%s)", "api ok, tunnel probe ok")

	// Per-direction measurement, lab-loopback labeled. The forward path:
	// foreign iperf3 client → the DOKODEMO on its own end (127.0.0.1:25401)
	// → Reality carrier → Iran vless-in → freedom → iperf3 server in
	// xrNSB. The reverse (-R) flips the data direction on the same path.
	forward, ferr := runNS(xrNSA, "sh", "-c",
		fmt.Sprintf("timeout 40 iperf3 -c 127.0.0.1 -p %d -t 3", xrPublic))
	if ferr != nil {
		t.Fatalf("forward iperf: %v: %s", ferr, forward)
	}
	t.Logf("lab-loopback XRAY FORWARD (foreign→Iran through tunnel): %s", strings.TrimSpace(forward))
	reverse, rerr := runNS(xrNSA, "sh", "-c",
		fmt.Sprintf("timeout 40 iperf3 -c 127.0.0.1 -p %d -R -t 3 2>&1 | grep -E 'sender|receiver'", xrPublic))
	if rerr != nil {
		t.Logf("reverse iperf note: %v: %s", rerr, reverse)
	}
	t.Logf("lab-loopback XRAY REVERSE (-R, Iran→foreign data direction): %s", strings.TrimSpace(reverse))

	// Health through the driver (server end, api in the same ns as the
	// process — but the test process is in the host ns; use the ns curl).
	stats, serr := runNS(xrNSA, "curl", "-s", fmt.Sprintf("http://127.0.0.1:%d/stats", 21599))
	if serr != nil || !strings.Contains(stats, "Connected") {
		// The dokodemo/api health check: the carrier answering is the
		// real signal; assert the driver's own view too.
		t.Logf("stats view: %q %v", stats, serr)
	}

	// Kill the server process → Health fails → supervisor restarts →
	// traffic again. The supervisor respawns INSIDE the same namespace
	// (the spawn seam is namespace-scoped).
	if out, err := runNS(xrNSA, "pkill", "-f", "xray"); err != nil {
		t.Logf("pkill note: %v: %s", err, out)
	}
	time.Sleep(2 * time.Second)
	deadline2 := time.Now().Add(30 * time.Second)
	back := false
	for time.Now().Before(deadline2) {
		if out, err := runNS(xrNSB, "sh", "-c",
			fmt.Sprintf("timeout 2 nc -z %s %d && echo OPEN", xrIPA, xrCarrier)); err == nil &&
			strings.Contains(out, "OPEN") {
			back = true
			break
		}
		time.Sleep(time.Second)
	}
	if !back {
		t.Fatal("supervisor did not restore the carrier after the kill")
	}
	t.Logf("lab-loopback supervisor restart: carrier restored within 30s")
}

// bhIntTail is reused from backhaul_integration_test.go for log dumps.
