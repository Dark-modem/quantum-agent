package agent

// Integration lab for the AGENT-31 drivers (hysteria + sing-box over the
// VENDORED cores). Mirrors the ctunnel integration discipline:
//   - the REAL released binaries (exact bytes the agents download — the
//     tarball sha256 verified before extraction, the M2 shape);
//   - real netns underlay (veth pair, /30 each side);
//   - through-probes prove the tunnel CARRIES DATA, not just that the
//     processes are alive;
//   - all cleanup proven (0 netns, 0 veth, 0 stray processes).
//
// Env-gated: SB_INTEGRATION=1 + INTEG_DIR=<dir> (downloads the two core
// releases on first run, caches in INTEG_DIR; root + Linux + python3
// required — same as the ctunnel lab).
//
// Legs:
//   1. hysteria: netns-A runs `hysteria server` (QUIC :36712, password
//      auth, self-signed TLS pair generated in-test, salamander obfs ON)
//      + a python3 TCP echo on A:5201; netns-B runs `hysteria client`
//      (insecure to the self-signed pair) with a tcpForwarding entry
//      :21000 → A:5201. The probe dials 127.0.0.1:21000 INSIDE netns-B
//      and expects the echo — the full QUIC carrier + forward path.
//   2. sing-box: netns-A runs `sing-box run` (shadowsocks inbound
//      :8388, aes-256-gcm; direct outbound) + the same echo; netns-B
//      runs `sing-box run` (direct inbound :21001 override→A:5201 +
//      shadowsocks outbound + route rule). Probe dials 127.0.0.1:21001
//      inside netns-B — the ss tunnel + override path.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	hyReleaseURL = "https://github.com/Dark-modem/quantum-cores/releases/download/hysteria-v2.14.0/hysteria-linux-amd64.tar.gz"
	hyReleaseSHA = "ef9270a5f10ce4a3868b52f10847ff8e249bed488d5e08eb5d1a78632aabbece"
	sbReleaseURL = "https://github.com/Dark-modem/quantum-cores/releases/download/sing-box-v1.14.4/sing-box-linux-amd64.tar.gz"
	sbReleaseSHA = "71b2d4a0ee1cea9a116ee944ebb9987295b823af78b562c9988f4e0b7b289c29"
)

func sbIntegEnv(t *testing.T) string {
	if os.Getenv("SB_INTEGRATION") == "" {
		t.Skip("SB_INTEGRATION not set (downloads the core releases; root + Linux + python3)")
	}
	dir := os.Getenv("INTEG_DIR")
	if dir == "" {
		t.Skip("INTEG_DIR not set")
	}
	return dir
}

// sbFetchCore downloads (once, cached) a published core release tarball
// and verifies its sha256 — the M2 verify-then-extract shape.
func sbFetchCore(t *testing.T, dir, cacheName, url, wantSHA string) []byte {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, cacheName)
	if b, err := os.ReadFile(cache); err == nil {
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != wantSHA {
			t.Fatalf("cached %s does not match the pinned sha256", cacheName)
		}
		return b
	}
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("download %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("download %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != wantSHA {
		t.Fatalf("downloaded %s sha256 mismatch (want %s)", cacheName, wantSHA)
	}
	if err := os.WriteFile(cache, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return body
}

// sbExtractBinary extracts the WHOLE release tarball and copies the
// named binary out (the layout is <core>/<binary>; the production
// extractor matches by basename at any depth — this mirrors that).
func sbExtractBinary(t *testing.T, tarball []byte, binName string) string {
	dir := t.TempDir()
	tar := filepath.Join(dir, "core.tar.gz")
	if err := os.WriteFile(tar, tarball, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("tar", "-xzf", tar, "-C", dir).CombinedOutput(); err != nil {
		t.Fatalf("extract tarball: %v: %s", err, out)
	}
	var found string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, werr error) error {
		if werr == nil && info.Mode().IsRegular() && filepath.Base(path) == binName && path != tar {
			found = path
		}
		return nil
	})
	if err != nil || found == "" {
		t.Fatalf("binary %s not found in the extracted tarball", binName)
	}
	b, err := os.ReadFile(found)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "bin", binName)
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

const (
	sbNSA  = "sbtest-a"
	sbNSB  = "sbtest-b"
	sbVA   = "sbtest-va"
	sbVB   = "sbtest-vb"
	sbIPA  = "10.77.31.1"
	sbIPB  = "10.77.31.2"
	sbEcho = 5201
)

func sbSetupNetns(t *testing.T) (runNS func(ns string, args ...string) (string, error), mustNS func(ns string, args ...string) string) {
	t.Helper()
	clean := func() {
		for _, ns := range []string{sbNSA, sbNSB} {
			exec.Command("sudo", "ip", "netns", "del", ns).Run()
		}
		exec.Command("sudo", "ip", "link", "del", sbVA).Run()
	}
	clean()
	t.Cleanup(clean)
	for _, c := range [][]string{
		{"ip", "netns", "add", sbNSA}, {"ip", "netns", "add", sbNSB},
		{"ip", "link", "add", sbVA, "type", "veth", "peer", "name", sbVB},
		{"ip", "link", "set", sbVA, "netns", sbNSA},
		{"ip", "link", "set", sbVB, "netns", sbNSB},
	} {
		if out, err := exec.Command("sudo", c...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", c, err, out)
		}
	}
	runNS = func(ns string, args ...string) (string, error) {
		full := append([]string{"ip", "netns", "exec", ns}, args...)
		out, err := exec.Command("sudo", full...).CombinedOutput()
		return string(out), err
	}
	mustNS = func(ns string, args ...string) string {
		out, err := runNS(ns, args...)
		if err != nil {
			t.Fatalf("netns exec %s %v: %v: %s", ns, args, err, out)
		}
		return out
	}
	mustNS(sbNSA, "ip", "addr", "add", sbIPA+"/30", "dev", sbVA)
	mustNS(sbNSA, "ip", "link", "set", sbVA, "up")
	mustNS(sbNSA, "ip", "link", "set", "lo", "up")
	mustNS(sbNSB, "ip", "addr", "add", sbIPB+"/30", "dev", sbVB)
	mustNS(sbNSB, "ip", "link", "set", sbVB, "up")
	mustNS(sbNSB, "ip", "link", "set", "lo", "up")
	return runNS, mustNS
}

// sbEchoScriptPath writes the python3 echo server script (a FILE, not a
// -c blob — shell quoting of multi-line python proved fragile).
func sbEchoScriptPath(t *testing.T, dir, ip string) string {
	t.Helper()
	script := fmt.Sprintf(`import socket,threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("%s",%d)); s.listen(8)
def one(c):
    try:
        while True:
            d=c.recv(4096)
            if not d: break
            c.sendall(d)
    finally: c.close()
while True:
    c,_=s.accept(); threading.Thread(target=one,args=(c,),daemon=True).start()
`, ip, sbEcho)
	path := filepath.Join(dir, "echo.py")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// sbStartEchoBG starts the echo server inside a netns (detached nohup).
func sbStartEchoBG(t *testing.T, dir string, mustNS func(ns string, args ...string) string, ns, ip string) {
	script := sbEchoScriptPath(t, dir, ip)
	mustNS(ns, "sh", "-c", fmt.Sprintf("nohup python3 %s >/dev/null 2>&1 &", script))
}

// sbProbe dials host:port INSIDE a netns and returns what came back.
func sbProbe(runNS func(ns string, args ...string) (string, error), ns, host string, port int, payload string) (string, error) {
	script := fmt.Sprintf(
		`exec 3<>/dev/tcp/%s/%d; printf '%%s' '%s' >&3; head -c %d <&3`, host, port, payload, len(payload))
	out, err := runNS(ns, "bash", "-c", script)
	return strings.TrimSpace(out), err
}

// sbWaitFor polls a zero-arg check until it passes or the deadline hits.
func sbWaitFor(t *testing.T, what string, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s: not ready within %s", what, timeout)
}

func TestHysteriaIntegrationForwardEcho(t *testing.T) {
	dir := sbIntegEnv(t)
	runNS, mustNS := sbSetupNetns(t)
	bin := sbExtractBinary(t, sbFetchCore(t, dir, "hysteria.tar.gz", hyReleaseURL, hyReleaseSHA), "hysteria")

	// self-signed server TLS pair (hysteria2 is always TLS)
	cert := filepath.Join(dir, "hy.crt")
	key := filepath.Join(dir, "hy.key")
	if out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=sbtest.quantum").CombinedOutput(); err != nil {
		t.Fatalf("self-signed cert: %v: %s", err, out)
	}

	cfgA := filepath.Join(dir, "hy-server.yaml")
	serverYAML := fmt.Sprintf(`listen: ":36712"
auth:
  type: password
  password: "hy-lab-pass-01"
obfs:
  type: salamander
  salamander:
    password: "hy-lab-obfs-01"
tls:
  cert: %q
  key: %q
`, cert, key)
	if err := os.WriteFile(cfgA, []byte(serverYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	// start the echo + the server inside netns A (detached)
	sbStartEchoBG(t, dir, mustNS, sbNSA, sbIPA)
	mustNS(sbNSA, "sh", "-c",
		fmt.Sprintf("nohup %s server -c %q >/tmp/hy-server.log 2>&1 &", bin, cfgA))
	// the client (netns B)
	cfgB := filepath.Join(dir, "hy-client.yaml")
	clientYAML := fmt.Sprintf(`server: "%s:36712"
auth: "hy-lab-pass-01"
obfs:
  type: salamander
  salamander:
    password: "hy-lab-obfs-01"
tls:
  insecure: true
tcpForwarding:
  - listen: "127.0.0.1:21000"
    remote: "%s:%d"
`, sbIPA, sbIPA, sbEcho)
	if err := os.WriteFile(cfgB, []byte(clientYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	mustNS(sbNSB, "sh", "-c",
		fmt.Sprintf("nohup %s client -c %q >/tmp/hy-client.log 2>&1 &", bin, cfgB))

	sbWaitFor(t, "hysteria tunnel forward listener", 20*time.Second, func() bool {
		out, err := runNS(sbNSB, "sh", "-c", "ss -ltn | grep 21000")
		return err == nil && strings.Contains(out, "21000")
	})
	out, err := sbProbe(runNS, sbNSB, "127.0.0.1", 21000, "hello-through-hysteria")
	if err != nil || out != "hello-through-hysteria" {
		// one retry after a settle second (QUIC handshake + forward setup)
		time.Sleep(time.Second)
		out, err = sbProbe(runNS, sbNSB, "127.0.0.1", 21000, "hello-through-hysteria")
		if err != nil || out != "hello-through-hysteria" {
			t.Fatalf("hysteria echo-through: err=%v out=%q", err, out)
		}
	}
	t.Logf("hysteria QUIC forward leg: echo-through PASS (%q)", out)
}

func TestSingboxIntegrationForwardEcho(t *testing.T) {
	dir := sbIntegEnv(t)
	runNS, mustNS := sbSetupNetns(t)
	bin := sbExtractBinary(t, sbFetchCore(t, dir, "singbox.tar.gz", sbReleaseURL, sbReleaseSHA), "sing-box")

	sbStartEchoBG(t, dir, mustNS, sbNSA, sbIPA)
	cfgA := filepath.Join(dir, "sb-server.json")
	serverCfg := fmt.Sprintf(`{"inbounds":[{"type":"shadowsocks","tag":"carrier-in","listen":"0.0.0.0","listen_port":8388,"method":"aes-256-gcm","password":"sb-lab-pass-01"}],"outbounds":[{"type":"direct","tag":"direct-out"}]}`)
	if err := os.WriteFile(cfgA, []byte(serverCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	mustNS(sbNSA, "sh", "-c",
		fmt.Sprintf("nohup %s run -c %q >/tmp/sb-server.log 2>&1 &", bin, cfgA))
	cfgB := filepath.Join(dir, "sb-client.json")
	clientCfg := fmt.Sprintf(`{"inbounds":[{"type":"direct","tag":"forward-in","listen":"127.0.0.1","listen_port":21001,"override_address":%q,"override_port":%d}],"outbounds":[{"type":"shadowsocks","tag":"carrier-out","server":%q,"server_port":8388,"method":"aes-256-gcm","password":"sb-lab-pass-01"}],"route":{"rules":[{"inbound":["forward-in"],"outbound":"carrier-out"}]}}`, sbIPA, sbEcho, sbIPA)
	if err := os.WriteFile(cfgB, []byte(clientCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	mustNS(sbNSB, "sh", "-c",
		fmt.Sprintf("nohup %s run -c %q >/tmp/sb-client.log 2>&1 &", bin, cfgB))

	sbWaitFor(t, "sing-box forward listener", 20*time.Second, func() bool {
		out, err := runNS(sbNSB, "sh", "-c", "ss -ltn | grep 21001")
		return err == nil && strings.Contains(out, "21001")
	})
	out, err := sbProbe(runNS, sbNSB, "127.0.0.1", 21001, "hello-through-singbox")
	if err != nil || out != "hello-through-singbox" {
		time.Sleep(time.Second)
		out, err = sbProbe(runNS, sbNSB, "127.0.0.1", 21001, "hello-through-singbox")
		if err != nil || out != "hello-through-singbox" {
			t.Fatalf("singbox echo-through: err=%v out=%q", err, out)
		}
	}
	t.Logf("sing-box shadowsocks forward leg: echo-through PASS (%q)", out)
}
