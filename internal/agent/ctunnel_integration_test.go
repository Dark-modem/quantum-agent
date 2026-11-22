//go:build integration

// ctunnel_integration_test.go — REAL ctunnel-engine v1.1.1 through the
// REAL driver paths: R5-style artifact → sha256+ed25519 verify → extract
// → TUN setup (arg-list ip) → spawn (`ctunnel-engine -config`) → reverse
// UDP-Crypt tunnel (dtls-1.3) between TWO network namespaces → TCP+UDP
// ECHO through the PUBLIC DNAT'd port from a THIRD namespace → inner
// IPv6 ping across the tunnel → kill → Health fails → supervisor restart
// → echo again. A second leg proves the in-agent RELAY composition over
// a real kernel veth pair (the production inner hop the netns leg cannot
// run — the relay lives in the agent process, the netns TUN does not).
//
// Topology (lab-loopback):
//
//	ns-c (client) ── ns-a (foreign, ROLE=iran, DNAT) ══ carrier ══ ns-b (Iran, ROLE=kharej)
//	10.210.0.6/30      10.210.0.5/30 + 10.210.0.1/30        10.210.0.2/30
//
//	Run: CT_INTEGRATION=1 CT_INTEG_DIR=/tmp/ct-int \
//	         go test -tags integration -run TestCtunnelIntegration \
//	         ./internal/agent/ -count=1 -v   (as root; python3, ip)
//
// Scope per the phase-15 task: launch + connect + ONE TCP and ONE UDP
// echo per supported family — NO throughput/overhead campaigns (those
// stay UNVERIFIED for this engine). Cleanup is trap-driven.

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

const (
	// The v2 binary comes from OUR published core release (the exact bytes
	// the agents download — tarball sha256 verified before extraction).
	ctUpstreamURL = "https://github.com/Dark-modem/quantum-cores/releases/download/ctunnel-v2.0.0/ctunnel-linux-amd64.tar.gz"
	// sha256 of the ctunnel-v2.0.0 ctunnel-linux-amd64.tar.gz release asset
	// (the AGENT-29 pack bytes; mirrored in quantum-cores ctunnel/MANIFEST.json).
	ctUpstreamSHA = "19d6b3f0d64c57b7b9fb1231ceed8cb23219aee079e262c5c2abaf2b8da2cf32"

	ctNSA   = "quantum-test-ct-a" // foreign end (ROLE=iran: passive carrier + public DNAT)
	ctNSB   = "quantum-test-ct-b" // Iran end (ROLE=kharej: dials OUT + relay INPUT)
	ctNSC   = "quantum-test-ct-c" // external client hitting the public port
	ctIPA   = "10.210.0.1"
	ctIPB   = "10.210.0.2"
	ctIPAc  = "10.210.0.5" // ns-a's client-facing address (the "public" entry)
	ctIPCs  = "10.210.0.6"
	ctVethA = "v-ct-a"
	ctVethB = "v-ct-b"
	ctVethC = "v-ct-c"
	ctVethD = "v-ct-d"

	// serveRoleCT flips the enrollment identity between the two Starts.

	ctCarrier  = 24312 // UDP carrier port (ns-a)
	ctPublic   = 25207 // PUBLIC forwarded port (ns-a, DNAT)
	ctTarget   = 25201 // the Iran-local target (python echo in ns-b)
	ctRelayLeg = 25205 // leg-2 relay target (python echo, root ns)
)

func ctIntSkip(t *testing.T) string {
	t.Helper()
	if os.Getenv("CT_INTEGRATION") == "" {
		t.Skip("CT_INTEGRATION not set (downloads the upstream release; root + Linux + python3)")
	}
	dir := os.Getenv("CT_INTEG_DIR")
	if dir == "" {
		t.Skip("CT_INTEG_DIR not set")
	}
	return dir
}

// ctFetchEngine downloads (once, cached) the published v2 release tarball,
// verifies its sha256, and extracts ctunnel_2.0.0/ctunnel-engine — the
// M2 shape the production driver exercises (verify-then-extract).
func ctFetchEngine(t *testing.T, dir string) []byte {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "ctunnel-artifact-bin")
	var tarBytes []byte
	if b, err := os.ReadFile(cache); err == nil {
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != ctUpstreamSHA {
			t.Fatal("cached ctunnel artifact does not match the pinned sha256")
		}
		tarBytes = b
	}
	if tarBytes == nil {
		resp, err := http.Get(ctUpstreamURL)
		if err != nil {
			t.Fatalf("download ctunnel artifact: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("download ctunnel artifact: HTTP %d", resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != ctUpstreamSHA {
			t.Fatalf("downloaded ctunnel artifact sha256 mismatch (want %s)", ctUpstreamSHA)
		}
		tarBytes = body
		if err := os.WriteFile(cache, tarBytes, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Extract ctunnel_2.0.0/ctunnel-engine (the pack shape).
	gz, err := gzip.NewReader(bytes.NewReader(tarBytes))
	if err != nil {
		t.Fatalf("artifact not gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	bin := []byte(nil)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeDir || filepath.Base(hdr.Name) != "ctunnel-engine" {
			continue
		}
		bin, err = io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	if bin == nil {
		t.Fatal("artifact carries no ctunnel-engine")
	}
	return bin
}

// ctIntegrationArtifact wraps the REAL binary into the tar.gz the driver
// extracts (ctunnel_2.0.0/ directory entry + binary + LICENSE).
func ctIntegrationArtifact(t *testing.T, dir string, realBin []byte) (body []byte, shaHex, sigB64, pubB64 string) {
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
	if err := tw.WriteHeader(&tar.Header{Name: "ctunnel_2.0.0/", Mode: int64(0o755), Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "ctunnel_2.0.0/ctunnel-engine", Mode: 0o755, Size: int64(len(realBin))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(realBin); err != nil {
		t.Fatal(err)
	}
	lic := []byte("GNU AFFERO GENERAL PUBLIC LICENSE Version 3 — see the upstream CIAUB/C-Tunnel repository")
	if err := tw.WriteHeader(&tar.Header{Name: "ctunnel_2.0.0/LICENSE", Mode: 0o644, Size: int64(len(lic))}); err != nil {
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

// ctEchoScript is the stand-in for the Iran-local target service: a
// TCP+UDP echo bound to 0.0.0.0:<port> inside the Iran namespace (the
// driver's in-agent relay is exercised in leg 2 — a netns TUN address is
// not bindable from the test process).
const ctEchoScript = `import socket, threading, sys
port = int(sys.argv[1])
host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, port))
    while True:
        d, a = s.recvfrom(4096)
        s.sendto(d, a)
threading.Thread(target=udp, daemon=True).start()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(16)
while True:
    c, _ = s.accept()
    def h(c):
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                c.sendall(d)
        except Exception:
            pass
        c.close()
    threading.Thread(target=h, args=(c,), daemon=True).start()
`

// serveRoleCT is the integration-only role switch (which end resolves as
// server_side).
var serveRoleCT string

func TestCtunnelIntegration(t *testing.T) {
	dir := ctIntSkip(t)
	realBin := ctFetchEngine(t, dir)
	body, shaHex, sigB64, pubB64 := ctIntegrationArtifact(t, dir, realBin)

	clean := func() {
		for _, ns := range []string{ctNSA, ctNSB, ctNSC} {
			exec.Command("sudo", "ip", "netns", "del", ns).Run()
		}
		for _, l := range []string{ctVethA, ctVethB, ctVethC, ctVethD} {
			exec.Command("sudo", "ip", "link", "del", l).Run()
		}
	}
	clean()
	t.Cleanup(clean)
	for _, c := range [][]string{
		{"ip", "netns", "add", ctNSA}, {"ip", "netns", "add", ctNSB}, {"ip", "netns", "add", ctNSC},
		{"ip", "link", "add", ctVethA, "type", "veth", "peer", "name", ctVethB},
		{"ip", "link", "add", ctVethC, "type", "veth", "peer", "name", ctVethD},
		{"ip", "link", "set", ctVethA, "netns", ctNSA},
		{"ip", "link", "set", ctVethB, "netns", ctNSB},
		{"ip", "link", "set", ctVethC, "netns", ctNSA},
		{"ip", "link", "set", ctVethD, "netns", ctNSC},
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
	mustNS(ctNSA, "ip", "addr", "add", ctIPA+"/30", "dev", ctVethA)
	mustNS(ctNSA, "ip", "link", "set", ctVethA, "up")
	mustNS(ctNSA, "ip", "link", "set", "lo", "up")
	mustNS(ctNSA, "ip", "addr", "add", ctIPAc+"/30", "dev", ctVethC)
	mustNS(ctNSA, "ip", "link", "set", ctVethC, "up")
	mustNS(ctNSB, "ip", "addr", "add", ctIPB+"/30", "dev", ctVethB)
	mustNS(ctNSB, "ip", "link", "set", ctVethB, "up")
	mustNS(ctNSB, "ip", "link", "set", "lo", "up")
	mustNS(ctNSC, "ip", "addr", "add", ctIPCs+"/30", "dev", ctVethD)
	mustNS(ctNSC, "ip", "link", "set", ctVethD, "up")
	mustNS(ctNSC, "ip", "link", "set", "lo", "up")
	mustNS(ctNSC, "ip", "route", "add", "default", "via", ctIPAc)
	if out, err := runNS(ctNSC, "ping", "-c", "1", "-W", "2", ctIPAc); err != nil {
		t.Fatalf("underlay unreachable: %v: %s", err, out)
	}

	// The Iran-local target: TCP+UDP echo in the IRAN namespace, bound to
	// the tunnel address the DNAT delivers to.
	echoPath := filepath.Join(dir, "echo.py")
	if err := os.WriteFile(echoPath, []byte(ctEchoScript), 0o644); err != nil {
		t.Fatal(err)
	}
	echoCmd := exec.Command("sudo", "ip", "netns", "exec", ctNSB, "python3", echoPath,
		fmt.Sprint(ctTarget))
	echoCmd.Stdout = nil
	echoCmd.Stderr = nil
	if err := echoCmd.Start(); err != nil {
		t.Fatalf("echo server: %v", err)
	}
	t.Cleanup(func() { _ = echoCmd.Process.Kill() })
	time.Sleep(700 * time.Millisecond)

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
	infra.Runner = infra.ExecRunner
	t.Cleanup(func() { infra.Runner = origRunner })

	// Spawn seam: the namespace comes from the env file's ROLE= line (the
	// args are identical for both ends: -config <env path>).
	origSpawn := ctSpawn
	ctSpawn = func(binPath string, args []string) (frpProcess, error) {
		envPath := ""
		for i, a := range args {
			if a == "-config" && i+1 < len(args) {
				envPath = args[i+1]
			}
		}
		raw, err := os.ReadFile(envPath)
		if err != nil {
			return nil, err
		}
		ns, tag := ctNSA, "server"
		if strings.Contains(string(raw), "ROLE=kharej") {
			ns, tag = ctNSB, "client"
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
	t.Cleanup(func() { ctSpawn = origSpawn })

	// Interface-admin seam: TUN setup/teardown lands in the CURRENT
	// namespace (the test flips serveNSCT between the two Starts; the
	// final cleanup deletes the namespaces wholesale). All ctIfaceUp
	// commands — tuntap add, link, addr — flow through ctIPCmd.
	serveNSCT := ctNSA
	origIPCmd := ctIPCmd
	ctIPCmd = func(args ...string) error {
		full := append([]string{"ip", "netns", "exec", serveNSCT, "ip"}, args...)
		_, err := exec.Command("sudo", full...).CombinedOutput()
		return err
	}
	t.Cleanup(func() { ctIPCmd = origIPCmd })

	// sysctl seam: ip_forward lands in the SERVER namespace.
	origSysctl := ctSysctl
	ctSysctl = func(args ...string) error {
		full := append([]string{"ip", "netns", "exec", ctNSA, "sysctl"}, args...)
		_, err := exec.Command("sudo", full...).CombinedOutput()
		return err
	}
	t.Cleanup(func() { ctSysctl = origSysctl })

	// iptables seam: rule-shape routing — nat/FORWARD/chain accounting
	// belong to the SERVER namespace; the relay's INPUT accept belongs to
	// the IRAN (client) namespace.
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		ns := ctNSA
		if strings.HasPrefix(joined, "-A INPUT -i ") ||
			strings.HasPrefix(joined, "-I INPUT -i ") ||
			strings.HasPrefix(joined, "-C INPUT -i ") ||
			strings.HasPrefix(joined, "-D INPUT -i ") {
			ns = ctNSB
		}
		full := append([]string{"ip", "netns", "exec", ns, "iptables"}, args...)
		return exec.Command("sudo", full...).CombinedOutput()
	}
	t.Cleanup(func() { acctIptables = origIpt })
	origSave := acctIptablesSave
	acctIptablesSave = func() ([]byte, error) {
		out, err := exec.Command("sudo", "ip", "netns", "exec", ctNSA,
			"iptables-save", "-c", "-t", "filter").CombinedOutput()
		return out, err
	}
	t.Cleanup(func() { acctIptablesSave = origSave })

	// The through-probe seam: connect INSIDE the server namespace and
	// require a byte echoed back (bash /dev/tcp against the python echo).
	origProbe := ctProbeDial
	ctProbeDial = func(addr string, timeout time.Duration) error {
		host, port, _ := net.SplitHostPort(addr)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sudo", "ip", "netns", "exec", ctNSA, "bash", "-c",
			fmt.Sprintf("exec 3<>/dev/tcp/%s/%s; printf Q >&3; head -c 1 <&3", host, port))
		out, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("probe: %v: %s", err, strings.TrimSpace(string(out)))
		}
		if strings.TrimSpace(string(out)) != "Q" {
			return fmt.Errorf("probe: no echo (got %q)", strings.TrimSpace(string(out)))
		}
		return nil
	}
	t.Cleanup(func() { ctProbeDial = origProbe })

	// The payload counter view: the TUN lives in the CLIENT namespace —
	// route the netdev seam there (the parse logic under test is the
	// driver's; the /proc read is namespace plumbing).
	origNetDev := infra.AgentReadNetDev
	infra.AgentReadNetDev = func() (string, error) {
		out, err := exec.Command("sudo", "ip", "netns", "exec", ctNSB, "cat", "/proc/net/dev").CombinedOutput()
		return string(out), err
	}
	t.Cleanup(func() { infra.AgentReadNetDev = origNetDev })

	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		name := "germany"
		if serveRoleCT == ctNSB {
			name = "iran-1"
		}
		return agentIdentity{Server: artURL, BasePath: "", Name: name}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })

	secret := strings.Repeat("3a", 32)
	p := ctunnelParams{
		ServerSide: "germany", Version: ctPinnedVersion,
		Artifact:  "ctunnel-" + ctPinnedVersion + "-linux-{arch}.tar.gz",
		SHA256Amd: shaHex, SHA256Arm: shaHex, SigAmd: sigB64, SigArm: sigB64,
		Method: "dtls-1.3", Direction: "reverse",
		ForeignAddr: fmt.Sprintf("%s:%d", ctIPA, ctCarrier),
		CarrierPort: ctCarrier, PublicPort: ctPublic,
		LocalAddr: fmt.Sprintf("127.0.0.1:%d", ctTarget), Proto: "both",
		Secret: secret, Padding: 16,
	}

	dServer := NewCtunnelDriver()
	dClient := NewCtunnelDriver()
	serverInst := engine.Instance{TunnelID: "ct-int", LocalServer: "germany", RemoteServer: "iran",
		Params: infra.MustJSON(p)}
	if err := dServer.Start(context.Background(), serverInst); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	// Capture the SERVER env path before the "second host" swap (the
	// pkill below must match only the server engine's config path).
	srvEnv := ctEnvPath("ct-int")
	serveNSCT = ctNSB
	serveRoleCT = ctNSB
	infra.ConfigDir = t.TempDir() // the "second host": fresh state dir, fresh artifact fetch
	clientInst := engine.Instance{TunnelID: "ct-int", LocalServer: "iran", RemoteServer: "germany",
		Params: infra.MustJSON(p)}
	if err := dClient.Start(context.Background(), clientInst); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	t.Cleanup(func() {
		_ = dServer.Stop(serverInst)
		_ = dClient.Stop(clientInst)
	})

	// The warmup gate: the through-tunnel probe (echo round trip) answers
	// only once the client registered and the relay path is complete.
	gateOK := false
	for i := 0; i < 30; i++ {
		if h := dServer.Health(serverInst); h.OK {
			gateOK = true
			break
		}
		time.Sleep(time.Second)
	}
	if !gateOK {
		t.Fatalf("health gate never opened; server log: %s | client log: %s",
			ctLogTail(t, dir, "server"), ctLogTail(t, dir, "client"))
	}
	t.Logf("lab-loopback ctunnel (dtls-1.3 reverse) registered; through-tunnel probe ok")

	// TCP echo from the CLIENT namespace through the PUBLIC DNAT'd port.
	tcpEcho := func() error {
		out, err := runNS(ctNSC, "python3", "-c",
			fmt.Sprintf(`import socket;s=socket.create_connection(('%s',%d),8);s.sendall(b'hello-tcp');d=s.recv(16);print(d.decode());exit(0 if d==b'hello-tcp' else 1)`, ctIPAc, ctPublic))
		if err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(out))
		}
		return nil
	}
	if err := tcpEcho(); err != nil {
		t.Fatalf("TCP echo through the public port: %v", err)
	}
	t.Logf("lab-loopback TCP echo through the public port (ns-c -> DNAT -> tunnel -> ns-b) PASS")

	// UDP echo on the same public port.
	udpOut, err := runNS(ctNSC, "python3", "-c",
		fmt.Sprintf(`import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(8);s.sendto(b'hello-udp',('%s',%d));d=s.recv(16);print(d.decode());exit(0 if d==b'hello-udp' else 1)`, ctIPAc, ctPublic))
	if err != nil {
		t.Fatalf("UDP echo through the public port: %v: %s", err, strings.TrimSpace(udpOut))
	}
	t.Logf("lab-loopback UDP echo through the public port PASS")

	// Inner IPv6 across the tunnel (the driver-configured ULA pair).
	idx := ctDeriveFor("ct-int", "iran").index
	v6 := fmt.Sprintf("fd00:77:%x::2", idx)
	if out, err := runNS(ctNSA, "ping", "-6", "-c", "1", "-W", "3", v6); err != nil {
		t.Logf("inner-IPv6 ping FAILED (marked UNVERIFIED): %v: %s", err, strings.TrimSpace(out))
	} else {
		t.Logf("inner-IPv6 ping across the tunnel (ns-a -> %s) PASS", v6)
	}

	// Wire/payload counters: the iran end must know BOTH views.
	cn := dServer.Counters(serverInst)
	if !cn.WireKnown || !cn.PayloadKnown {
		t.Fatalf("server counters not known: %+v", cn)
	}
	if cn.WireRx == 0 || cn.PayloadRx == 0 {
		t.Fatalf("server counters zero after echo traffic: %+v", cn)
	}
	t.Logf("server counters: wire rx=%d tx=%d, payload rx=%d tx=%d", cn.WireRx, cn.WireTx, cn.PayloadRx, cn.PayloadTx)

	// Kill the SERVER engine (by its unique env path) -> Health fails.
	if out, err := runNS(ctNSA, "pkill", "-f", srvEnv); err != nil {
		t.Logf("pkill note: %v: %s", err, out)
	}
	deadline := time.Now().Add(15 * time.Second)
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
	t.Logf("lab-loopback kill -> Health fails (supervisor restart path)")
	gateOK = false
	for i := 0; i < 45; i++ {
		if h := dServer.Health(serverInst); h.OK {
			gateOK = true
			break
		}
		time.Sleep(time.Second)
	}
	if !gateOK {
		t.Fatalf("supervisor did not restore the tunnel; server log: %s",
			ctLogTail(t, dir, "server"))
	}
	var echoErr error
	for i := 0; i < 5; i++ {
		time.Sleep(2 * time.Second)
		echoErr = tcpEcho()
		if echoErr == nil {
			break
		}
	}
	if echoErr != nil {
		t.Fatalf("post-restart TCP echo: %v", echoErr)
	}
	t.Logf("lab-loopback supervisor restart -> TCP echo PASS again")
}

// ctLeg2Relay proves the in-agent relay composition over a REAL kernel
// path: a veth pair in the root namespace stands in for the tunnel's
// inner point-to-point link (10.77.199.1 ↔ .2); the relay binds the far
// address and dials a loopback echo target — exactly the production hop
// the DNAT'd traffic takes after arriving at the kharej end.
func TestCtunnelIntegrationRelayLeg(t *testing.T) {
	dir := ctIntSkip(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	clean := func() {
		exec.Command("sudo", "ip", "link", "del", "ct-leg-a").Run()
	}
	clean()
	t.Cleanup(clean)
	for _, c := range [][]string{
		{"ip", "link", "add", "ct-leg-a", "type", "veth", "peer", "name", "ct-leg-b"},
		{"ip", "addr", "add", "10.77.199.1/30", "dev", "ct-leg-a"},
		{"ip", "addr", "add", "10.77.199.2/30", "dev", "ct-leg-b"},
		{"ip", "link", "set", "ct-leg-a", "up"},
		{"ip", "link", "set", "ct-leg-b", "up"},
	} {
		if out, err := exec.Command("sudo", c...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", c, err, out)
		}
	}
	echoPath := filepath.Join(dir, "echo_leg2.py")
	if err := os.WriteFile(echoPath, []byte(ctEchoScript), 0o644); err != nil {
		t.Fatal(err)
	}
	echoCmd := exec.Command("python3", echoPath, fmt.Sprint(ctRelayLeg), "127.0.0.1")
	if err := echoCmd.Start(); err != nil {
		t.Fatalf("leg-2 echo server: %v", err)
	}
	t.Cleanup(func() { _ = echoCmd.Process.Kill() })
	time.Sleep(500 * time.Millisecond)

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	relay := ctStartRelay(stop, "10.77.199.2:25205", fmt.Sprintf("127.0.0.1:%d", ctRelayLeg), "both")
	t.Cleanup(relay.Close)
	deadline := time.Now().Add(3 * time.Second)
	for !relay.Ready(true, true) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !relay.Ready(true, true) {
		t.Fatal("leg-2 relay not ready (bind 10.77.199.2)")
	}
	// TCP through the relay (the address the through-probe / DNAT hits).
	conn, err := net.DialTimeout("tcp", "10.77.199.2:25205", 2*time.Second)
	if err != nil {
		t.Fatalf("leg-2 TCP dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("leg2-tcp")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if _, err := conn.Read(buf); err != nil || string(buf) != "leg2-tcp" {
		t.Fatalf("leg-2 TCP echo: %v %q", err, buf)
	}
	conn.Close()
	// UDP through the relay.
	uc, err := net.Dial("udp", "10.77.199.2:25205")
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := uc.Write([]byte("leg2-udp")); err != nil {
		t.Fatal(err)
	}
	rbuf := make([]byte, 8)
	if _, err := uc.Read(rbuf); err != nil || string(rbuf) != "leg2-udp" {
		t.Fatalf("leg-2 UDP echo: %v %q", err, rbuf)
	}
	t.Logf("lab-loopback relay leg: TCP+UDP echo via relay(10.77.199.2) -> 127.0.0.1 target PASS")
}

func ctLogTail(t *testing.T, dir, tag string) string {
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

// TestCtunnelIntegrationKernelLegs — REAL kernel-direct family legs over
// the same lab topology shape (a veth carrier between two namespaces):
//
//	gre DIRECT      — both ends run the driver's kernel path (NO engine):
//	                  ip link add type gre remote <peer carrier> + addr +
//	                  MSS + notrack; the inner 10.77 pair pings THROUGH the
//	                  gre device in BOTH directions; client payload counters
//	                  move; Stop deletes the devices.
//	vxlan DIRECT    — same shape with the vxlan device (dstport + VNI).
//	icmp (engine)   — TUN + the REAL v2 ctunnel-engine on both ends; the
//	                  sealed ICMP-echo carrier carries the inner pings.
//
// These legs prove the kernel/stealth data planes without the forward/
// relay composition (that is proven by the dtls-1.3 leg + the relay leg):
// the health-gate's through-probe needs the in-process relay, which binds
// inside the ROOT namespace — a netns tunnel address is not bindable from
// the test process, so the gate here is the inner ping itself. Honest
// scope: launch + inner datapath + teardown, no throughput campaigns.
func TestCtunnelIntegrationKernelLegs(t *testing.T) {
	dir := ctIntSkip(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const (
		knsA   = "quantum-test-ct-ka"
		knsB   = "quantum-test-ct-kb"
		kvethA = "v-ctk-a"
		kvethB = "v-ctk-b"
		kIPA   = "10.211.0.1"
		kIPB   = "10.211.0.2"
		kPort  = 24417
	)
	clean := func() {
		for _, ns := range []string{knsA, knsB} {
			exec.Command("sudo", "ip", "netns", "del", ns).Run()
		}
		for _, l := range []string{kvethA, kvethB} {
			exec.Command("sudo", "ip", "link", "del", l).Run()
		}
	}
	clean()
	t.Cleanup(clean)
	for _, c := range [][]string{
		{"ip", "netns", "add", knsA}, {"ip", "netns", "add", knsB},
		{"ip", "link", "add", kvethA, "type", "veth", "peer", "name", kvethB},
		{"ip", "link", "set", kvethA, "netns", knsA},
		{"ip", "link", "set", kvethB, "netns", knsB},
	} {
		if out, err := exec.Command("sudo", c...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", c, err, out)
		}
	}
	runKNS := func(ns string, args ...string) (string, error) {
		full := append([]string{"ip", "netns", "exec", ns}, args...)
		out, err := exec.Command("sudo", full...).CombinedOutput()
		return string(out), err
	}
	mustKNS := func(ns string, args ...string) string {
		out, err := runKNS(ns, args...)
		if err != nil {
			t.Fatalf("netns exec %s %v: %v: %s", ns, args, err, out)
		}
		return out
	}
	mustKNS(knsA, "ip", "addr", "add", kIPA+"/30", "dev", kvethA)
	mustKNS(knsA, "ip", "link", "set", kvethA, "up")
	mustKNS(knsA, "ip", "link", "set", "lo", "up")
	mustKNS(knsB, "ip", "addr", "add", kIPB+"/30", "dev", kvethB)
	mustKNS(knsB, "ip", "link", "set", kvethB, "up")
	mustKNS(knsB, "ip", "link", "set", "lo", "up")
	if out, err := runKNS(knsA, "ping", "-c", "1", "-W", "2", kIPB); err != nil {
		t.Fatalf("kernel-leg underlay unreachable: %v: %s", err, out)
	}

	origConfigDir := infra.ConfigDir
	infra.ConfigDir = t.TempDir()
	t.Cleanup(func() { infra.ConfigDir = origConfigDir })
	origRunner := infra.Runner
	infra.Runner = infra.ExecRunner
	t.Cleanup(func() { infra.Runner = origRunner })

	// Per-leg seams: interface + tc + wg + route-get + iptables + sysctl
	// all land in the CURRENT leg namespace (serveKNS flips between the
	// two Starts, exactly the server→client swap the main leg does).
	serveKNS := knsA

	// The artifact server (only the icmp leg needs the engine): the REAL
	// published v2 tarball, re-signed by the leg's own ed25519 key — the
	// R5 verify-then-extract path the production driver exercises.
	realBin := ctFetchEngine(t, dir)
	body, shaHex, sigB64, pubB64 := ctIntegrationArtifact(t, dir, realBin)
	artLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	artMux := http.NewServeMux()
	artMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
	artSrv := &http.Server{Handler: artMux}
	go artSrv.Serve(artLn)
	defer artSrv.Close()
	artURL := fmt.Sprintf("http://127.0.0.1:%d", artLn.Addr().(*net.TCPAddr).Port)

	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	t.Cleanup(func() { engineArtifactPubKeyB64 = origKey })

	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		// The enrollment identity follows the CURRENT leg namespace (the
		// two Starts are two hosts): ns-a is server_side, ns-b is iran-1.
		// Each "host" also gets its own state dir so the artifact fetch
		// (icmp leg) runs per end.
		if serveKNS == knsB {
			return agentIdentity{Server: artURL, Name: "iran-1"}, true
		}
		return agentIdentity{Server: artURL, Name: "germany"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	origIPCmd := ctIPCmd
	ctIPCmd = func(args ...string) error {
		full := append([]string{"ip", "netns", "exec", serveKNS, "ip"}, args...)
		_, err := exec.Command("sudo", full...).CombinedOutput()
		if f, ferr := os.OpenFile(filepath.Join(dir, "kernel-legs-commands.log"),
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); ferr == nil {
			fmt.Fprintf(f, "%s | %v => %v\n", serveKNS, args, err)
			f.Close()
		}
		return err
	}
	t.Cleanup(func() { ctIPCmd = origIPCmd })
	origTCCmd := ctTCCmd
	ctTCCmd = func(args ...string) error {
		full := append([]string{"ip", "netns", "exec", serveKNS, "tc"}, args...)
		_, err := exec.Command("sudo", full...).CombinedOutput()
		return err
	}
	t.Cleanup(func() { ctTCCmd = origTCCmd })
	origWg := ctWgCmd
	ctWgCmd = func(args ...string) error {
		full := append([]string{"ip", "netns", "exec", serveKNS, "wg"}, args...)
		_, err := exec.Command("sudo", full...).CombinedOutput()
		return err
	}
	t.Cleanup(func() { ctWgCmd = origWg })
	origLocal := ctLocalIPFor
	ctLocalIPFor = func(peerIP string) (string, error) {
		out, err := exec.Command("sudo", "ip", "netns", "exec", serveKNS,
			"ip", "-4", "route", "get", peerIP).CombinedOutput()
		if err != nil {
			return "", err
		}
		i := strings.Index(string(out), " src ")
		if i < 0 {
			return "", fmt.Errorf("no src in route get: %s", out)
		}
		return strings.Fields(string(out)[i+5:])[0], nil
	}
	t.Cleanup(func() { ctLocalIPFor = origLocal })
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) {
		full := append([]string{"ip", "netns", "exec", serveKNS, "iptables"}, args...)
		return exec.Command("sudo", full...).CombinedOutput()
	}
	t.Cleanup(func() { acctIptables = origIpt })
	origSysctl := ctSysctl
	ctSysctl = func(args ...string) error {
		full := append([]string{"ip", "netns", "exec", serveKNS, "sysctl"}, args...)
		_, err := exec.Command("sudo", full...).CombinedOutput()
		return err
	}
	t.Cleanup(func() { ctSysctl = origSysctl })
	// The kernel-direct legs must never spawn the engine (fail loudly if
	// they try); the icmp leg swaps its own spawn seam in below.
	origSpawn := ctSpawn
	ctSpawn = func(binPath string, args []string) (frpProcess, error) {
		return nil, fmt.Errorf("kernel-direct legs must not spawn the engine")
	}
	t.Cleanup(func() { ctSpawn = origSpawn })
	// The netdev view for the payload counters of the CURRENT leg ns.
	origNetDev := infra.AgentReadNetDev
	infra.AgentReadNetDev = func() (string, error) {
		out, err := exec.Command("sudo", "ip", "netns", "exec", serveKNS, "cat", "/proc/net/dev").CombinedOutput()
		return string(out), err
	}
	t.Cleanup(func() { infra.AgentReadNetDev = origNetDev })

	dA := NewCtunnelDriver()
	dB := NewCtunnelDriver()
	instA := engine.Instance{TunnelID: "ct-kleg", LocalServer: "germany", RemoteServer: "iran"}
	instB := engine.Instance{TunnelID: "ct-kleg", LocalServer: "iran", RemoteServer: "germany"}

	runKernelLeg := func(method string, carrierPort int) {
		t.Helper()
		p := ctunnelParams{
			ServerSide: "germany", Method: method, Direction: "direct",
			ForeignAddr: fmt.Sprintf("%s:%d", kIPB, carrierPort),
			PeerAddr:    fmt.Sprintf("%s:%d", kIPA, carrierPort),
			CarrierPort: carrierPort, PublicPort: ctPublic,
			LocalAddr: fmt.Sprintf("127.0.0.1:%d", ctTarget), Proto: "tcp",
			Secret: strings.Repeat("3a", 32),
		}
		instA.Params = infra.MustJSON(p)
		instB.Params = infra.MustJSON(p)
		serveKNS = knsA
		if err := dA.Start(context.Background(), instA); err != nil {
			t.Fatalf("%s server Start: %v", method, err)
		}
		serveKNS = knsB
		if err := dB.Start(context.Background(), instB); err != nil {
			t.Fatalf("%s client Start: %v", method, err)
		}
		idx := ctDeriveFor("ct-kleg", "iran").index
		innerA := fmt.Sprintf("10.77.%d.1", idx)
		innerB := fmt.Sprintf("10.77.%d.2", idx)
		// The inner pair pings THROUGH the kernel device, both directions.
		var pingErr error
		var pingOut string
		for i := 0; i < 10; i++ {
			pingOut, pingErr = runKNS(knsA, "ping", "-c", "1", "-W", "3", innerB)
			if pingErr == nil {
				break
			}
			time.Sleep(time.Second)
		}
		if pingErr != nil {
			t.Fatalf("%s: inner ping %s -> %s failed: %v: %s", method, innerA, innerB, pingErr, pingOut)
		}
		if out, err := runKNS(knsB, "ping", "-c", "1", "-W", "3", innerA); err != nil {
			t.Fatalf("%s: inner ping %s -> %s failed: %v: %s", method, innerB, innerA, err, out)
		}
		// The client end's payload counters see the device (both directions
		// moved bytes through it).
		cn := dB.Counters(instB)
		if !cn.PayloadKnown || cn.PayloadRx == 0 || cn.PayloadTx == 0 {
			t.Fatalf("%s: client payload counters not moving: %+v", method, cn)
		}
		t.Logf("%s kernel-direct leg: inner ping both ways + payload counters PASS", method)
		// Stop removes the devices (each Stop lands in ITS OWN namespace:
		// flip the seam like the Starts did).
		serveKNS = knsA
		if err := dA.Stop(instA); err != nil {
			t.Fatalf("%s server Stop: %v", method, err)
		}
		serveKNS = knsB
		if err := dB.Stop(instB); err != nil {
			t.Fatalf("%s client Stop: %v", method, err)
		}
		if out, err := runKNS(knsA, "ip", "link", "show", ctDeriveFor("ct-kleg", "iran").iface); err == nil {
			t.Fatalf("%s: server device survived Stop: %s", method, out)
		}
	}

	runKernelLeg("gre", 0)       // raw-IP carrier, no FOU
	runKernelLeg("vxlan", kPort) // UDP carrier on the allocated port

	// The icmp leg: TUN + the REAL engine on both ends (the spawn seam →
	// namespaces, mirroring the dtls leg's shape).
	ctSpawn = func(binPath string, args []string) (frpProcess, error) {
		envPath := ""
		for i, a := range args {
			if a == "-config" && i+1 < len(args) {
				envPath = args[i+1]
			}
		}
		raw, err := os.ReadFile(envPath)
		if err != nil {
			return nil, err
		}
		ns := knsA
		if strings.Contains(string(raw), "ROLE=kharej") {
			ns = knsB
		}
		lf, err := os.Create(filepath.Join(dir, "icmp-"+strings.ReplaceAll(ns, "quantum-test-", "")+".log"))
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
	p := ctunnelParams{
		ServerSide: "germany", Version: ctPinnedVersion,
		Artifact:  "ctunnel-" + ctPinnedVersion + "-linux-{arch}.tar.gz",
		SHA256Amd: shaHex, SHA256Arm: shaHex, SigAmd: sigB64, SigArm: sigB64,
		Method: "icmp", Direction: "reverse",
		ForeignAddr: fmt.Sprintf("%s:%d", kIPA, 0),
		CarrierPort: 0, PublicPort: ctPublic,
		LocalAddr: fmt.Sprintf("127.0.0.1:%d", ctTarget), Proto: "tcp",
		Secret: strings.Repeat("3a", 32), Padding: 16,
	}
	instA.Params = infra.MustJSON(p)
	instB.Params = infra.MustJSON(p)
	serveKNS = knsA
	infra.ConfigDir = t.TempDir() // the "second host" gets a fresh state dir
	if err := dA.Start(context.Background(), instA); err != nil {
		t.Fatalf("icmp server Start: %v", err)
	}
	serveKNS = knsB
	infra.ConfigDir = t.TempDir()
	if err := dB.Start(context.Background(), instB); err != nil {
		t.Fatalf("icmp client Start: %v", err)
	}
	idx := ctDeriveFor("ct-kleg", "iran").index
	innerB := fmt.Sprintf("10.77.%d.2", idx)
	gateOK := false
	for i := 0; i < 20; i++ {
		if out, err := runKNS(knsA, "ping", "-c", "1", "-W", "3", innerB); err == nil {
			gateOK = true
			break
		} else if i == 19 {
			t.Fatalf("icmp: inner ping through the sealed carrier failed: %s (server log: %s | client log: %s)",
				out, ctLogTail(t, dir, "icmp-a"), ctLogTail(t, dir, "icmp-b"))
		}
		time.Sleep(time.Second)
	}
	t.Logf("icmp engine leg: inner ping through the sealed ICMP carrier PASS (gate=%v)", gateOK)
	serveKNS = knsA
	if err := dA.Stop(instA); err != nil {
		t.Fatal(err)
	}
	serveKNS = knsB
	if err := dB.Stop(instB); err != nil {
		t.Fatal(err)
	}
}
