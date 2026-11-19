//go:build integration

// rathole_integration_test.go — REAL rathole v0.5.0 binaries through the
// REAL driver paths (R5-style artifact → verify → extract → typed-config
// render → spawn → noise reverse tunnel up → per-direction iperf3 with a
// same-run baseline → kill → Health fail → supervisor restart → traffic).
// Both ends run in SEPARATE network namespaces (quantum-test-* naming).
// All numbers lab-loopback ONLY.
//
//	Run: RATHOLE_INTEGRATION=1 RATHOLE_INTEG_DIR=/tmp/rathole-int \
//	         go test -tags integration -run TestRatholeIntegration \
//	         ./internal/agent/ -count=1 -v   (as root; iperf3, ip, curl)
//
// Requires: Linux root, network (downloads the upstream release zip once),
// iperf3. Cleanup is trap-driven.

package agent

import (
	"archive/tar"
	"archive/zip"
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

const ratholeUpstreamURL = "https://github.com/rapiz1/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-gnu.zip"

const (
	rhNSA     = "quantum-test-rh-a" // foreign end (rathole server)
	rhNSB     = "quantum-test-rh-b" // Iran end (rathole client)
	rhIPA     = "10.207.0.1"
	rhIPB     = "10.207.0.2"
	rhCarrier = 23343 // carrier (server bind / client dial)
	rhService = 25202 // PUBLIC data port (server side)
	rhTarget  = 25402 // iperf3 server (Iran end target)
	rhBase    = 25409 // same-run underlay baseline
	rhVethA   = "v-rh-a"
	rhVethB   = "v-rh-b"
)

func ratholeIntSkip(t *testing.T) string {
	t.Helper()
	if os.Getenv("RATHOLE_INTEGRATION") == "" {
		t.Skip("RATHOLE_INTEGRATION not set (downloads the upstream release zip; root + Linux + iperf3)")
	}
	dir := os.Getenv("RATHOLE_INTEG_DIR")
	if dir == "" {
		t.Skip("RATHOLE_INTEG_DIR not set")
	}
	return dir
}

// ratholeFetchBinary downloads (once, cached) the upstream release zip and
// returns the raw rathole binary.
func ratholeFetchBinary(t *testing.T, dir string) []byte {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "rathole-bin")
	if b, err := os.ReadFile(cache); err == nil {
		return b
	}
	resp, err := http.Get(ratholeUpstreamURL)
	if err != nil {
		t.Fatalf("download rathole release: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("download rathole release: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	bin, err := zipEntryBytes(body, "rathole")
	if err != nil {
		t.Fatalf("extract from upstream zip: %v", err)
	}
	if err := os.WriteFile(cache, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// ratholeIntegrationArtifact wraps the REAL binary into the tar.gz the
// driver extracts (rathole_0.5.0/ directory entry + the binary + a
// LICENSE placeholder the packer replaces with the real one).
func ratholeIntegrationArtifact(t *testing.T, dir string, realBin []byte) (body []byte, shaHex, sigB64, pubB64 string) {
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
	if err := tw.WriteHeader(&tar.Header{Name: "rathole_0.5.0/", Mode: int64(0o755), Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "rathole_0.5.0/rathole", Mode: 0o755, Size: int64(len(realBin))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(realBin); err != nil {
		t.Fatal(err)
	}
	lic := []byte("Apache License 2.0 — see https://www.apache.org/licenses/LICENSE-2.0 (upstream rapiz1/rathole)")
	if err := tw.WriteHeader(&tar.Header{Name: "rathole_0.5.0/LICENSE", Mode: 0o644, Size: int64(len(lic))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(lic); err != nil {
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

func TestRatholeIntegration(t *testing.T) {
	dir := ratholeIntSkip(t)
	realBin := ratholeFetchBinary(t, dir)
	body, shaHex, sigB64, pubB64 := ratholeIntegrationArtifact(t, dir, realBin)

	clean := func() {
		exec.Command("sudo", "ip", "netns", "del", rhNSA).Run()
		exec.Command("sudo", "ip", "netns", "del", rhNSB).Run()
		exec.Command("sudo", "ip", "link", "del", rhVethA).Run()
		exec.Command("sudo", "ip", "link", "del", rhVethB).Run()
	}
	clean()
	t.Cleanup(clean)
	for _, c := range [][]string{
		{"ip", "netns", "add", rhNSA}, {"ip", "netns", "add", rhNSB},
		{"ip", "link", "add", rhVethA, "type", "veth", "peer", "name", rhVethB},
		{"ip", "link", "set", rhVethA, "netns", rhNSA},
		{"ip", "link", "set", rhVethB, "netns", rhNSB},
	} {
		if out, err := exec.Command("sudo", c...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", c, err, out)
		}
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
	mustNS(rhNSA, "ip", "addr", "add", rhIPA+"/30", "dev", rhVethA)
	mustNS(rhNSA, "ip", "link", "set", rhVethA, "up")
	mustNS(rhNSA, "ip", "link", "set", "lo", "up")
	mustNS(rhNSB, "ip", "addr", "add", rhIPB+"/30", "dev", rhVethB)
	mustNS(rhNSB, "ip", "link", "set", rhVethB, "up")
	mustNS(rhNSB, "ip", "link", "set", "lo", "up")
	if out, err := runNS(rhNSB, "ping", "-c", "1", "-W", "2", rhIPA); err != nil {
		t.Fatalf("underlay unreachable: %v: %s", err, out)
	}

	// Same-run underlay baseline (lab rules).
	mustNS(rhNSA, "sh", "-c", fmt.Sprintf("nohup iperf3 -s -p %d > /dev/null 2>&1 &", rhBase))
	defer runNS(rhNSA, "pkill", "-f", fmt.Sprintf("iperf3 -s -p %d", rhBase))
	time.Sleep(time.Second)
	if base, berr := runNS(rhNSB, "sh", "-c",
		fmt.Sprintf("timeout 30 iperf3 -c %s -p %d -t 3 2>&1 | grep -E 'sender|receiver'", rhIPA, rhBase)); berr == nil {
		t.Logf("lab-loopback UNDERLAY baseline (no tunnel): %s", strings.TrimSpace(base))
	}

	// R5-style artifact server.
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

	// Two AGENTS' worth of state: each end has its OWN configDir (in
	// production the agents live on different hosts — sharing one dir
	// would make the client's Start overwrite the server's config file:
	// both processes auto-detect their role from the SAME path).
	dirA, dirB := filepath.Join(dir, "agent-a"), filepath.Join(dir, "agent-b")
	origConfigDir := configDir
	configDir = dirA
	t.Cleanup(func() { configDir = origConfigDir })
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	t.Cleanup(func() { engineArtifactPubKeyB64 = origKey })
	origRunner := runner
	runner = execRunner
	t.Cleanup(func() { runner = origRunner })

	// Spawn seam: each instance respawns in ITS OWN namespace forever —
	// keyed by config path (a closure over a mutable serveNS would put a
	// respawned CLIENT inside the SERVER's namespace when the supervisors
	// fire at arbitrary times).
	nsByCfg := map[string]string{
		filepath.Join(dirA, "engines", "rathole", "instances", "rh-int.toml"): rhNSA,
		filepath.Join(dirB, "engines", "rathole", "instances", "rh-int.toml"): rhNSB,
	}
	logByCfg := map[string]string{
		filepath.Join(dirA, "engines", "rathole", "instances", "rh-int.toml"): "server",
		filepath.Join(dirB, "engines", "rathole", "instances", "rh-int.toml"): "client",
	}
	serveNS := rhNSA // still used by the iptables seam (server end only)
	origSpawn := ratholeSpawn
	ratholeSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		ns := nsByCfg[cfgPath]
		tag := logByCfg[cfgPath]
		lf, err := os.Create(filepath.Join(dir, tag+".log"))
		if err != nil {
			return nil, err
		}
		if ns == "" {
			lf.Close()
			return nil, fmt.Errorf("rathole spawn: no namespace registered for %q", cfgPath)
		}
		cmd := exec.Command("sudo", "ip", "netns", "exec", ns, binPath, cfgPath)
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
	t.Cleanup(func() { ratholeSpawn = origSpawn })
	// The wire-accounting seam also lands in the SERVER namespace.
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) {
		full := append([]string{"ip", "netns", "exec", serveNS}, args...)
		out, err := exec.Command("sudo", full...).CombinedOutput()
		return out, err
	}
	t.Cleanup(func() { acctIptables = origIpt })
	// The health gate's service-port dial happens INSIDE the server ns.
	origDial := ratholeHealthDial
	ratholeHealthDial = func(port int) error {
		out, err := runNS(rhNSA, "sh", "-c", fmt.Sprintf("timeout 2 nc -z 127.0.0.1 %d && echo OPEN", port))
		if err == nil && strings.Contains(out, "OPEN") {
			return nil
		}
		return fmt.Errorf("service port not answering in ns")
	}
	t.Cleanup(func() { ratholeHealthDial = origDial })

	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		name := "germany"
		if serveNS == rhNSB {
			name = "iran-1"
		}
		return agentIdentity{Server: artURL, BasePath: "", Name: name}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })

	p := ratholeParams{
		ServerSide: "germany", Version: "0.5.0",
		Artifact:  "rathole-0.5.0-linux-{arch}.tar.gz",
		SHA256Amd: shaHex, SHA256Arm: shaHex, SigAmd: sigB64, SigArm: sigB64,
		ServerAddr:  fmt.Sprintf("%s:%d", rhIPA, rhCarrier),
		ServiceAddr: fmt.Sprintf("0.0.0.0:%d", rhService),
		LocalAddr:   fmt.Sprintf("127.0.0.1:%d", rhTarget),
		Token:       "rathole-int-token-01",
	}

	dServer := NewRatholeDriver()
	dClient := NewRatholeDriver()
	serverInst := engine.Instance{TunnelID: "rh-int", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(p)}
	if err := dServer.Start(context.Background(), serverInst); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	// The SERVER's noise public key: read from the persisted key state —
	// in production it rides the ack detail to the panel.
	ksRaw, err := os.ReadFile(filepath.Join(configDir, "wg", "rathole-rh-int.noise"))
	if err != nil {
		t.Fatalf("noise key state: %v", err)
	}
	var ks wgKeyState
	if err := json.Unmarshal(ksRaw, &ks); err != nil || ks.PublicKey == "" {
		t.Fatalf("noise public key missing from the state: %v", err)
	}

	// The client CANNOT start without the server's acked noise key (fail
	// closed) — the panel pushes it in the desired revision and the client
	// starts once with the complete params, in ITS OWN state dir.
	serveNS = rhNSB
	configDir = dirB
	revP := p
	revP.NoiseServerPublic = ks.PublicKey
	clientInst := engine.Instance{TunnelID: "rh-int", LocalServer: "iran", RemoteServer: "germany",
		Params: mustJSON(revP)}
	if err := dClient.Start(context.Background(), clientInst); err != nil {
		t.Fatalf("client Start with the noise key: %v", err)
	}
	serveNS = rhNSA
	t.Cleanup(func() {
		_ = dServer.Stop(serverInst)
		_ = dClient.Stop(clientInst)
	})

	// The health gate: the service port answers only once the client
	// registered (tunnel usable end to end).
	gateOK := false
	for i := 0; i < 30; i++ {
		if h := dServer.Health(serverInst); h.OK {
			gateOK = true
			break
		}
		time.Sleep(time.Second)
	}
	if !gateOK {
		t.Fatalf("health gate never opened; server log: %s", bhIntTail(t, dir, "server"))
	}
	t.Logf("lab-loopback rathole tunnel registered (service port answering)")

	// iperf3 target on the IRAN end.
	mustNS(rhNSB, "sh", "-c", fmt.Sprintf("nohup iperf3 -s -p %d > /dev/null 2>&1 &", rhTarget))
	defer runNS(rhNSB, "pkill", "-f", fmt.Sprintf("iperf3 -s -p %d", rhTarget))
	time.Sleep(time.Second)
	fwd, ferr := runNS(rhNSA, "sh", "-c",
		fmt.Sprintf("timeout 40 iperf3 -c 127.0.0.1 -p %d -t 3 2>&1 | grep -E 'sender|receiver'", rhService))
	if ferr != nil {
		t.Fatalf("forward iperf: %v: %s", ferr, fwd)
	}
	t.Logf("lab-loopback RATHOLE FORWARD (foreign→Iran through tunnel): %s", strings.TrimSpace(fwd))
	rev, rerr := runNS(rhNSA, "sh", "-c",
		fmt.Sprintf("timeout 40 iperf3 -c 127.0.0.1 -p %d -R -t 3 2>&1 | grep -E 'sender|receiver'", rhService))
	if rerr != nil {
		t.Fatalf("reverse iperf: %v: %s", rerr, rev)
	}
	t.Logf("lab-loopback RATHOLE REVERSE (-R, Iran→foreign data direction): %s", strings.TrimSpace(rev))

	// Kill the server process → Health fails → supervisor restarts.
	if out, err := runNS(rhNSA, "pkill", "-f", "engines/rathole/bin"); err != nil {
		t.Logf("pkill note: %v: %s", err, out)
	}
	deadline := time.Now().Add(10 * time.Second)
	healthDown := false
	for time.Now().Before(deadline) {
		if !dServer.Health(serverInst).OK {
			healthDown = true
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !healthDown {
		t.Fatal("Health still OK after the server process was killed")
	}
	t.Logf("lab-loopback rathole kill → Health fails (supervisor restart path)")
	// The supervisor restarts the process inside the SAME namespace; the
	// client reconnects and the gate reopens.
	gateOK = false
	for i := 0; i < 45; i++ {
		if h := dServer.Health(serverInst); h.OK {
			gateOK = true
			break
		}
		time.Sleep(time.Second)
	}
	if !gateOK {
		t.Fatalf("supervisor did not restore the tunnel; server log: %s", bhIntTail(t, dir, "server"))
	}
	// The client's data channel reconnects on its own backoff after the
	// server's restart — the gate (service port bound) can open before the
	// channel is usable; retry the measurement a few times.
	var fwd2 string
	var ferr2 error
	for i := 0; i < 5; i++ {
		time.Sleep(3 * time.Second)
		fwd2, ferr2 = runNS(rhNSA, "sh", "-c",
			fmt.Sprintf("timeout 40 iperf3 -c 127.0.0.1 -p %d -t 3 2>&1 | grep receiver", rhService))
		if ferr2 == nil {
			break
		}
	}
	if ferr2 != nil {
		t.Fatalf("post-restart iperf: %v: %s", ferr2, fwd2)
	}
	t.Logf("lab-loopback rathole supervisor restart → traffic again: %s", strings.TrimSpace(fwd2))
}

// zipEntryBytes extracts a single named file from a zip archive (the
// upstream release shape — this test repackages it into the tar.gz
// artifact with a directory entry). A1: moved here from rathole_driver.go
// — it is test-only tooling.
func zipEntryBytes(body []byte, want string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("zip: %w", err)
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) != want || f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, 256<<20))
	}
	return nil, fmt.Errorf("zip: entry %q not found", want)
}
