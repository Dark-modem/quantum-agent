//go:build integration

// gost_integration_test.go — REAL gost v3 binaries through the REAL
// driver paths (R5-style artifact → verify → extract → typed-args spawn
// → relay+ws reverse tunnel up → per-direction iperf3 with a same-run
// baseline → kill → Health fail → supervisor restart → traffic). Both
// ends in SEPARATE network namespaces (quantum-test-* naming). All
// numbers lab-loopback ONLY.
//
//	Run: GOST_INTEGRATION=1 GOST_INTEG_DIR=/tmp/gost-int \
//	         go test -tags integration -run TestGostIntegration \
//	         ./internal/agent/ -count=1 -v   (as root; iperf3, ip)
//
// Requires: Linux root, network (downloads the upstream release once),
// iperf3. Cleanup is trap-driven.

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

	"github.com/Dark-modem/quantum-agent/internal/infra"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const gostUpstreamURL = "https://github.com/go-gost/gost/releases/download/v3.3.3/gost_3.3.3_linux_amd64.tar.gz"

const (
	gstNSA     = "quantum-test-gst-a" // foreign end (the relay + the public port)
	gstNSB     = "quantum-test-gst-b" // Iran end (dials OUT)
	gstIPA     = "10.209.0.1"
	gstIPB     = "10.209.0.2"
	gstCarrier = 23344 // relay+ws carrier port
	gstPublic  = 25203 // PUBLIC data port (opened on the foreign host by rtcp)
	gstTarget  = 25402 // iperf3 server (Iran end target)
	gstBase    = 25409 // same-run underlay baseline
	gstVethA   = "v-gst-a"
	gstVethB   = "v-gst-b"
)

func gostIntSkip(t *testing.T) string {
	t.Helper()
	if os.Getenv("GOST_INTEGRATION") == "" {
		t.Skip("GOST_INTEGRATION not set (downloads the upstream release; root + Linux + iperf3)")
	}
	dir := os.Getenv("GOST_INTEG_DIR")
	if dir == "" {
		t.Skip("GOST_INTEG_DIR not set")
	}
	return dir
}

// gostFetchBinary downloads (once, cached) the upstream release tarball
// and returns the raw gost binary.
func gostFetchBinary(t *testing.T, dir string) []byte {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "gost-bin")
	if b, err := os.ReadFile(cache); err == nil {
		return b
	}
	resp, err := http.Get(gostUpstreamURL)
	if err != nil {
		t.Fatalf("download gost release: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("download gost release: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("release gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			t.Fatal("release: gost binary not found")
		}
		if err != nil {
			t.Fatalf("release tar: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != "gost" {
			continue
		}
		bin, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cache, bin, 0o755); err != nil {
			t.Fatal(err)
		}
		return bin
	}
}

// gostIntegrationArtifact wraps the REAL binary into the tar.gz the
// driver extracts (gost_3.3.3/ directory entry + binary + LICENSE).
func gostIntegrationArtifact(t *testing.T, dir string, realBin []byte) (body []byte, shaHex, sigB64, pubB64 string) {
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
	if err := tw.WriteHeader(&tar.Header{Name: "gost_3.3.3/", Mode: int64(0o755), Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "gost_3.3.3/gost", Mode: 0o755, Size: int64(len(realBin))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(realBin); err != nil {
		t.Fatal(err)
	}
	lic := []byte("MIT License — see the upstream go-gost/gost repository")
	if err := tw.WriteHeader(&tar.Header{Name: "gost_3.3.3/LICENSE", Mode: 0o644, Size: int64(len(lic))}); err != nil {
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
	sigB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, body))
	return body, shaHex, sigB64, pubB64
}

func TestGostIntegration(t *testing.T) {
	dir := gostIntSkip(t)
	realBin := gostFetchBinary(t, dir)
	body, shaHex, sigB64, pubB64 := gostIntegrationArtifact(t, dir, realBin)

	clean := func() {
		exec.Command("sudo", "ip", "netns", "del", gstNSA).Run()
		exec.Command("sudo", "ip", "netns", "del", gstNSB).Run()
		exec.Command("sudo", "ip", "link", "del", gstVethA).Run()
		exec.Command("sudo", "ip", "link", "del", gstVethB).Run()
	}
	clean()
	t.Cleanup(clean)
	for _, c := range [][]string{
		{"ip", "netns", "add", gstNSA}, {"ip", "netns", "add", gstNSB},
		{"ip", "link", "add", gstVethA, "type", "veth", "peer", "name", gstVethB},
		{"ip", "link", "set", gstVethA, "netns", gstNSA},
		{"ip", "link", "set", gstVethB, "netns", gstNSB},
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
	mustNS(gstNSA, "ip", "addr", "add", gstIPA+"/30", "dev", gstVethA)
	mustNS(gstNSA, "ip", "link", "set", gstVethA, "up")
	mustNS(gstNSA, "ip", "link", "set", "lo", "up")
	mustNS(gstNSB, "ip", "addr", "add", gstIPB+"/30", "dev", gstVethB)
	mustNS(gstNSB, "ip", "link", "set", gstVethB, "up")
	mustNS(gstNSB, "ip", "link", "set", "lo", "up")
	if out, err := runNS(gstNSB, "ping", "-c", "1", "-W", "2", gstIPA); err != nil {
		t.Fatalf("underlay unreachable: %v: %s", err, out)
	}

	// Same-run underlay baseline (lab rules).
	mustNS(gstNSA, "sh", "-c", fmt.Sprintf("nohup iperf3 -s -p %d > /dev/null 2>&1 &", gstBase))
	defer runNS(gstNSA, "pkill", "-f", fmt.Sprintf("iperf3 -s -p %d", gstBase))
	time.Sleep(time.Second)
	if base, berr := runNS(gstNSB, "sh", "-c",
		fmt.Sprintf("timeout 30 iperf3 -c %s -p %d -t 3 2>&1 | grep -E 'sender|receiver'", gstIPA, gstBase)); berr == nil {
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

	origConfigDir := infra.ConfigDir
	infra.ConfigDir = t.TempDir()
	t.Cleanup(func() { infra.ConfigDir = origConfigDir })
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	t.Cleanup(func() { engineArtifactPubKeyB64 = origKey })
	origRunner := infra.Runner
	infra.Runner = execRunner
	t.Cleanup(func() { infra.Runner = origRunner })

	// Spawn seam: per-instance namespace keyed by the ARGS (the client's
	// -L rtcp:// vs the server's -L relay+ws://) so supervisor respawns
	// always land in the right namespace.
	origSpawn := gostSpawn
	gostSpawn = func(binPath string, args []string) (frpProcess, error) {
		joined := strings.Join(args, " ")
		ns := gstNSA
		tag := "server"
		if strings.Contains(joined, "rtcp://") {
			ns = gstNSB
			tag = "client"
		}
		lf, err := os.Create(filepath.Join(dir, tag+".log"))
		if err != nil {
			return nil, err
		}
		cmd := exec.Command("sudo", "ip", "netns", "exec", ns, binPath)
		cmd.Args = append(cmd.Args, args...)
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
	t.Cleanup(func() { gostSpawn = origSpawn })
	// Wire accounting lands in the SERVER namespace.
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) {
		full := append([]string{"ip", "netns", "exec", gstNSA, "iptables"}, args...)
		out, err := exec.Command("sudo", full...).CombinedOutput()
		return out, err
	}
	t.Cleanup(func() { acctIptables = origIpt })
	// The health gate's public-port dial happens INSIDE the server ns.
	origDial := gostHealthDial
	gostHealthDial = func(port int) error {
		out, err := runNS(gstNSA, "sh", "-c", fmt.Sprintf("timeout 2 nc -z 127.0.0.1 %d && echo OPEN", port))
		if err == nil && strings.Contains(out, "OPEN") {
			return nil
		}
		return fmt.Errorf("public port not answering in ns")
	}
	t.Cleanup(func() { gostHealthDial = origDial })

	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		name := "germany"
		if serveNSGost == gstNSB {
			name = "iran-1"
		}
		return agentIdentity{Server: artURL, BasePath: "", Name: name}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })

	p := gostParams{
		ServerSide: "germany", Version: "3.3.3",
		Artifact:  "gost-3.3.3-linux-{arch}.tar.gz",
		SHA256Amd: shaHex, SHA256Arm: shaHex, SigAmd: sigB64, SigArm: sigB64,
		CarrierAddr: fmt.Sprintf("%s:%d", gstIPA, gstCarrier),
		PublicPort:  gstPublic,
		LocalAddr:   fmt.Sprintf("127.0.0.1:%d", gstTarget),
		Transport:   "ws",
	}

	dServer := NewGostDriver()
	dClient := NewGostDriver()
	serverInst := engine.Instance{TunnelID: "gst-int", LocalServer: "germany", RemoteServer: "iran",
		Params: infra.MustJSON(p)}
	if err := dServer.Start(context.Background(), serverInst); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	serveNSGost = gstNSB
	clientInst := engine.Instance{TunnelID: "gst-int", LocalServer: "iran", RemoteServer: "germany",
		Params: infra.MustJSON(p)}
	if err := dClient.Start(context.Background(), clientInst); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	serveNSGost = gstNSA
	t.Cleanup(func() {
		_ = dServer.Stop(serverInst)
		_ = dClient.Stop(clientInst)
	})

	// The health gate: the public port answers only once the client's
	// relay registration opened the rtcp listener on the foreign host.
	gateOK := false
	for i := 0; i < 30; i++ {
		if h := dServer.Health(serverInst); h.OK {
			gateOK = true
			break
		}
		time.Sleep(time.Second)
	}
	if !gateOK {
		t.Fatalf("health gate never opened; server log: %s", gostLogTail(t, dir, "server"))
	}
	t.Logf("lab-loopback gost tunnel registered (public port answering)")

	mustNS(gstNSB, "sh", "-c", fmt.Sprintf("nohup iperf3 -s -p %d > /dev/null 2>&1 &", gstTarget))
	defer runNS(gstNSB, "pkill", "-f", fmt.Sprintf("iperf3 -s -p %d", gstTarget))
	time.Sleep(time.Second)
	fwd, ferr := runNS(gstNSA, "sh", "-c",
		fmt.Sprintf("timeout 40 iperf3 -c 127.0.0.1 -p %d -t 3 2>&1 | grep -E 'sender|receiver'", gstPublic))
	if ferr != nil {
		t.Fatalf("forward iperf: %v: %s", ferr, fwd)
	}
	t.Logf("lab-loopback GOST FORWARD (foreign→Iran through tunnel): %s", strings.TrimSpace(fwd))
	rev, rerr := runNS(gstNSA, "sh", "-c",
		fmt.Sprintf("timeout 40 iperf3 -c 127.0.0.1 -p %d -R -t 3 2>&1 | grep -E 'sender|receiver'", gstPublic))
	if rerr != nil {
		t.Fatalf("reverse iperf: %v: %s", rerr, rev)
	}
	t.Logf("lab-loopback GOST REVERSE (-R, Iran→foreign data direction): %s", strings.TrimSpace(rev))

	// Kill the server process → Health fails → supervisor restarts.
	if out, err := runNS(gstNSA, "pkill", "-f", "engines/gost/bin"); err != nil {
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
	t.Logf("lab-loopback gost kill → Health fails (supervisor restart path)")
	gateOK = false
	for i := 0; i < 45; i++ {
		if h := dServer.Health(serverInst); h.OK {
			gateOK = true
			break
		}
		time.Sleep(time.Second)
	}
	if !gateOK {
		t.Fatalf("supervisor did not restore the tunnel; server log: %s", gostLogTail(t, dir, "server"))
	}
	var fwd2 string
	var ferr2 error
	for i := 0; i < 5; i++ {
		time.Sleep(2 * time.Second)
		fwd2, ferr2 = runNS(gstNSA, "sh", "-c",
			fmt.Sprintf("timeout 40 iperf3 -c 127.0.0.1 -p %d -t 3 2>&1 | grep receiver", gstPublic))
		if ferr2 == nil {
			break
		}
	}
	if ferr2 != nil {
		t.Fatalf("post-restart iperf: %v: %s", ferr2, fwd2)
	}
	t.Logf("lab-loopback gost supervisor restart → traffic again: %s", strings.TrimSpace(fwd2))
}

// serveNSGost is the integration-only role switch (mirrors the rathole
// test's serveNS pattern).
var serveNSGost string

func gostLogTail(t *testing.T, dir, tag string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, tag+".log"))
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\x00", ""), "\n")
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	return strings.Join(lines, " | ")
}
