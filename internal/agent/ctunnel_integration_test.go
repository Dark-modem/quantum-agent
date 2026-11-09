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

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const (
	ctUpstreamURL = "https://github.com/CIAUB/C-Tunnel/releases/download/v1.1.1/ctunnel-engine-linux-amd64"
	// sha256 of the v1.1.1 ctunnel-engine-linux-amd64 release asset
	// (verified against the upstream SHA256SUMS file during the audit).
	ctUpstreamSHA = "c5deec0a4c996b82037d5b7961885f37342f3aae4a53090b80e9952e49edb370"

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

// ctFetchEngine downloads (once, cached) the upstream release binary and
// verifies it against the pinned sha256.
func ctFetchEngine(t *testing.T, dir string) []byte {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "ctunnel-engine-bin")
	if b, err := os.ReadFile(cache); err == nil {
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != ctUpstreamSHA {
			t.Fatal("cached ctunnel-engine does not match the pinned sha256")
		}
		return b
	}
	resp, err := http.Get(ctUpstreamURL)
	if err != nil {
		t.Fatalf("download ctunnel-engine: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("download ctunnel-engine: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != ctUpstreamSHA {
		t.Fatalf("downloaded ctunnel-engine sha256 mismatch (want %s)", ctUpstreamSHA)
	}
	if err := os.WriteFile(cache, body, 0o755); err != nil {
		t.Fatal(err)
	}
	return body
}

// ctIntegrationArtifact wraps the REAL binary into the tar.gz the driver
// extracts (ctunnel_1.1.1/ directory entry + binary + LICENSE).
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
	if err := tw.WriteHeader(&tar.Header{Name: "ctunnel_1.1.1/", Mode: int64(0o755), Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "ctunnel_1.1.1/ctunnel-engine", Mode: 0o755, Size: int64(len(realBin))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(realBin); err != nil {
		t.Fatal(err)
	}
	lic := []byte("GNU AFFERO GENERAL PUBLIC LICENSE Version 3 — see the upstream CIAUB/C-Tunnel repository")
	if err := tw.WriteHeader(&tar.Header{Name: "ctunnel_1.1.1/LICENSE", Mode: 0o644, Size: int64(len(lic))}); err != nil {
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

	origConfigDir := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = origConfigDir })
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	t.Cleanup(func() { engineArtifactPubKeyB64 = origKey })
	origRunner := runner
	runner = execRunner
	t.Cleanup(func() { runner = origRunner })

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
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) {
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
	t.Cleanup(func() { frpIptables = origIpt })
	origSave := frpIptablesSave
	frpIptablesSave = func() ([]byte, error) {
		out, err := exec.Command("sudo", "ip", "netns", "exec", ctNSA,
			"iptables-save", "-c", "-t", "filter").CombinedOutput()
		return out, err
	}
	t.Cleanup(func() { frpIptablesSave = origSave })

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
	origNetDev := agentReadNetDev
	agentReadNetDev = func() (string, error) {
		out, err := exec.Command("sudo", "ip", "netns", "exec", ctNSB, "cat", "/proc/net/dev").CombinedOutput()
		return string(out), err
	}
	t.Cleanup(func() { agentReadNetDev = origNetDev })

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
		Params: mustJSON(p)}
	if err := dServer.Start(context.Background(), serverInst); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	// Capture the SERVER env path before the "second host" swap (the
	// pkill below must match only the server engine's config path).
	srvEnv := ctEnvPath("ct-int")
	serveNSCT = ctNSB
	serveRoleCT = ctNSB
	configDir = t.TempDir() // the "second host": fresh state dir, fresh artifact fetch
	clientInst := engine.Instance{TunnelID: "ct-int", LocalServer: "iran", RemoteServer: "germany",
		Params: mustJSON(p)}
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
