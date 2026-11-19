//go:build integration

// wg_integration_test.go — REAL WireGuard through the REAL driver paths:
// kernel interface per end (qwg*), keys generated on the agent, peer keys
// applied through the same wgApplyPeer command shape the panel's second
// desired revision triggers, handshake, ping + iperf3 across the tunnel
// per direction, wg transfer counters. Two network namespaces on one
// kernel (point-to-point veth; WireGuard needs no internet). All numbers
// lab-loopback ONLY.
//
//	Run: WG_INTEGRATION=1 go test -tags integration -run TestWgIntegration \
//	         ./internal/agent/ -count=1 -v   (as root; ip, wg, iperf3, ping)
//
// Requires: Linux root, the wireguard kernel module + iproute2 + wg tools
// + iperf3. Cleanup is trap-driven; never touches the real host.

package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/infra"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const (
	wgNSA     = "quantum-test-wg-a" // foreign end (listens on UDP)
	wgNSB     = "quantum-test-wg-b" // Iran end (dials out)
	wgIPA     = "10.206.0.1"
	wgIPB     = "10.206.0.2"
	wgCarrier = 51820 // UDP underlay port
	wgTunnel  = 25410 // iperf3 over the tunnel (10.189.0.x)
	wgBase    = 25409 // same-run underlay baseline
	wgVethA   = "v-wg-a"
	wgVethB   = "v-wg-b"
)

func wgIntSkip(t *testing.T) {
	t.Helper()
	if os.Getenv("WG_INTEGRATION") == "" {
		t.Skip("WG_INTEGRATION not set (kernel wireguard + ip + wg + iperf3; root + Linux)")
	}
}

func TestWgIntegration(t *testing.T) {
	wgIntSkip(t)

	// Persisted key state must survive the restart phase within this run.
	origCfg := infra.ConfigDir
	infra.ConfigDir = t.TempDir()
	t.Cleanup(func() { infra.ConfigDir = origCfg })

	// kernel capability probe: the wireguard module must be loadable.
	if out, err := exec.Command("sudo", "ip", "link", "add", "wg-probe0", "type", "wireguard").CombinedOutput(); err != nil {
		t.Skipf("wireguard kernel module unavailable: %v: %s", err, out)
	}
	exec.Command("sudo", "ip", "link", "del", "wg-probe0").Run()

	clean := func() {
		exec.Command("sudo", "ip", "netns", "del", wgNSA).Run()
		exec.Command("sudo", "ip", "netns", "del", wgNSB).Run()
		exec.Command("sudo", "ip", "link", "del", wgVethA).Run()
		exec.Command("sudo", "ip", "link", "del", wgVethB).Run()
	}
	clean()
	t.Cleanup(clean)
	for _, c := range [][]string{
		{"ip", "netns", "add", wgNSA}, {"ip", "netns", "add", wgNSB},
		{"ip", "link", "add", wgVethA, "type", "veth", "peer", "name", wgVethB},
		{"ip", "link", "set", wgVethA, "netns", wgNSA},
		{"ip", "link", "set", wgVethB, "netns", wgNSB},
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
	mustNS(wgNSA, "ip", "addr", "add", wgIPA+"/30", "dev", wgVethA)
	mustNS(wgNSA, "ip", "link", "set", wgVethA, "up")
	mustNS(wgNSA, "ip", "link", "set", "lo", "up")
	mustNS(wgNSB, "ip", "addr", "add", wgIPB+"/30", "dev", wgVethB)
	mustNS(wgNSB, "ip", "link", "set", wgVethB, "up")
	mustNS(wgNSB, "ip", "link", "set", "lo", "up")
	if out, err := runNS(wgNSB, "ping", "-c", "1", "-W", "2", wgIPA); err != nil {
		t.Fatalf("underlay unreachable: %v: %s", err, out)
	}

	// Same-run underlay baseline (lab rules: ratios use the same run).
	mustNS(wgNSA, "sh", "-c", fmt.Sprintf("nohup iperf3 -s -p %d > /dev/null 2>&1 &", wgBase))
	defer runNS(wgNSA, "pkill", "-f", fmt.Sprintf("iperf3 -s -p %d", wgBase))
	time.Sleep(time.Second)
	if base, berr := runNS(wgNSB, "sh", "-c",
		fmt.Sprintf("timeout 30 iperf3 -c %s -p %d -t 3 2>&1 | grep -E 'sender|receiver'", wgIPA, wgBase)); berr == nil {
		t.Logf("lab-loopback UNDERLAY baseline (no tunnel): %s", strings.TrimSpace(base))
	}

	// Route the driver's kernel work into the RIGHT namespace: the seam
	// runs every ip/wg command under `ip netns exec <serveNS>`; the test
	// switches serveNS between the two ends (mirrors the real agent, one
	// process per host).
	serveNS := wgNSA
	origTool := wgToolExec
	wgToolExec = func(args ...string) (string, error) {
		// Mirror the production wgToolExec mapping (wg_driver.go): callers
		// pass either the binary ("ip …", "wg …") or a bare wg subcommand.
		rest := args
		if len(args) > 0 && args[0] == "wg" {
			rest = args[1:]
		}
		full := []string{"ip", "netns", "exec", serveNS}
		if len(rest) > 0 && rest[0] != "ip" {
			full = append(full, "wg")
		}
		full = append(full, rest...)
		out, err := exec.Command("sudo", full...).CombinedOutput()
		return string(out), err
	}
	t.Cleanup(func() { wgToolExec = origTool })

	// The kernel path needs the REAL identity per end.
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		name := "germany"
		if serveNS == wgNSB {
			name = "iran-1"
		}
		return agentIdentity{Server: "http://panel.test", Name: name}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })

	d := NewWgDriver()
	p := wgParams{ServerSide: "germany", CarrierIP: wgIPA, CarrierPort: wgCarrier, MTU: 0}
	instA := engine.Instance{TunnelID: "twga", LocalServer: "germany", RemoteServer: "iran",
		Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), instA); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	ifaceA := mustIfaceName(t, d, "twga")
	// DEBUG: state pubkey vs kernel pubkey right after Start
	if out, err := runNS(wgNSA, "wg", "show", ifaceA, "public-key"); err == nil {
		d.mu.Lock()
		st := d.runs["twga"]
		priv := st.privB64
		statePub := st.pubB64
		d.mu.Unlock()
		derived, derr := exec.Command("sh", "-c", fmt.Sprintf("printf '%%s\\n' '%s' | wg pubkey", priv)).Output()
		t.Logf("DEBUG server: state_pub=%s kernel=%s derive(state_priv)=%s (err=%v) priv=%s",
			statePub, strings.TrimSpace(out), strings.TrimSpace(string(derived)), derr, priv)
	}

	serveNS = wgNSB
	instB := engine.Instance{TunnelID: "twgb", LocalServer: "iran", RemoteServer: "germany",
		Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), instB); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	ifaceB := mustIfaceName(t, d, "twgb")

	// The key exchange (ENGINE-WG-DESIGN.md), driven through the REAL
	// reconcile path: both ends ack their own public key; the panel pushes
	// peer_public back; Reload applies it LIVE via `wg set` — no
	// interface recreation, no re-key.
	d.mu.Lock()
	pubA := d.runs["twga"].pubB64
	pubB := d.runs["twgb"].pubB64
	d.mu.Unlock()
	if pubA == "" || pubB == "" {
		t.Fatal("agent-generated public keys missing")
	}
	revA := p
	revA.PeerPublic = pubB
	revB := p
	revB.PeerPublic = pubA
	serveNS = wgNSA
	if err := d.Reload(engine.Instance{TunnelID: "twga", Params: infra.MustJSON(revA)}); err != nil {
		t.Fatalf("server peer_public revision must apply live: %v", err)
	}
	serveNS = wgNSB
	if err := d.Reload(engine.Instance{TunnelID: "twgb", Params: infra.MustJSON(revB)}); err != nil {
		t.Fatalf("client peer_public revision must apply live: %v", err)
	}

	// Handshake + reachability: ping across the tunnel (forces the
	// handshake through the client's keepalive/traffic).
	pingOK := false
	for i := 0; i < 30; i++ {
		if out, err := runNS(wgNSB, "ping", "-c", "1", "-W", "1", "10.189.0.1"); err == nil &&
			strings.Contains(out, " 0% packet loss") {
			pingOK = true
			break
		}
		time.Sleep(time.Second)
	}
	if !pingOK {
		hs, _ := runNS(wgNSB, "wg", "show", ifaceB)
		hsA, _ := runNS(wgNSA, "wg", "show", ifaceA)
		ports, _ := runNS(wgNSA, "ss", "-uln")
		t.Fatalf("tunnel never carried a ping;\nclient wg show: %s\nserver wg show: %s\nserver UDP listeners: %s", hs, hsA, ports)
	}
	t.Logf("lab-loopback WG handshake + ping across the tunnel OK")

	// iperf3 server on the FOREIGN end's tunnel address; the client dials
	// through the tunnel per direction.
	mustNS(wgNSA, "sh", "-c", fmt.Sprintf("nohup iperf3 -s -p %d > /dev/null 2>&1 &", wgTunnel))
	defer runNS(wgNSA, "pkill", "-f", fmt.Sprintf("iperf3 -s -p %d", wgTunnel))
	time.Sleep(time.Second)
	fwd, ferr := runNS(wgNSB, "sh", "-c",
		fmt.Sprintf("timeout 40 iperf3 -c 10.189.0.1 -p %d -t 3 2>&1 | grep -E 'sender|receiver'", wgTunnel))
	if ferr != nil {
		t.Fatalf("forward iperf: %v: %s", ferr, fwd)
	}
	t.Logf("lab-loopback WG FORWARD (Iran→foreign through tunnel): %s", strings.TrimSpace(fwd))
	rev, rerr := runNS(wgNSB, "sh", "-c",
		fmt.Sprintf("timeout 40 iperf3 -c 10.189.0.1 -p %d -R -t 3 2>&1 | grep -E 'sender|receiver'", wgTunnel))
	if rerr != nil {
		t.Fatalf("reverse iperf: %v: %s", rerr, rev)
	}
	t.Logf("lab-loopback WG REVERSE (-R, foreign→Iran data direction): %s", strings.TrimSpace(rev))

	// The driver's own view: wire transfer counters must be nonzero.
	serveNS = wgNSB
	c := d.Counters(instB)
	if !c.WireKnown || c.WireRx == 0 || c.WireTx == 0 {
		t.Fatalf("wire counters after transfer = %+v", c)
	}
	t.Logf("lab-loopback WG counters (client view): wire rx=%d tx=%d", c.WireRx, c.WireTx)

	// AGENT RESTART (phase-8 key persistence): the client process dies and
	// a NEW driver starts from the SAME persisted state — the keypair must
	// be identical (the panel's ack'd key stays valid), the peer applies
	// from the revised desired state at Start, and the handshake survives.
	serveNS = wgNSB
	if err := d.Stop(instB); err != nil {
		t.Fatalf("client Stop (restart phase): %v", err)
	}
	d2 := NewWgDriver()
	origIdent2 := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "iran-1"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent2 })
	if err := d2.Start(context.Background(), engine.Instance{TunnelID: "twgb",
		LocalServer: "iran", RemoteServer: "germany", Params: infra.MustJSON(revB)}); err != nil {
		t.Fatalf("client restart Start: %v", err)
	}
	d2.mu.Lock()
	pubB2 := d2.runs["twgb"].pubB64
	ifaceB2 := d2.runs["twgb"].iface
	d2.mu.Unlock()
	if pubB2 != pubB {
		t.Fatalf("restart re-keyed the tunnel: %s != %s", pubB2, pubB)
	}
	pingOK2 := false
	for i := 0; i < 30; i++ {
		if out, err := runNS(wgNSB, "ping", "-c", "1", "-W", "1", "10.189.0.1"); err == nil &&
			strings.Contains(out, " 0% packet loss") {
			pingOK2 = true
			break
		}
		time.Sleep(time.Second)
	}
	if !pingOK2 {
		hs, _ := runNS(wgNSB, "wg", "show", ifaceB2)
		t.Fatalf("handshake did not survive the agent restart; wg show: %s", hs)
	}
	t.Logf("lab-loopback WG agent restart: same keypair (%s…), handshake survived", pubB2[:12])

	// Stop both ends; the interfaces must disappear.
	serveNS = wgNSA
	if err := d.Stop(instA); err != nil {
		t.Fatalf("server Stop: %v", err)
	}
	serveNS = wgNSB
	if err := d2.Stop(engine.Instance{TunnelID: "twgb", Params: infra.MustJSON(revB)}); err != nil {
		t.Fatalf("client Stop: %v", err)
	}
	for _, x := range []struct{ ns, iface string }{{wgNSA, ifaceA}, {wgNSB, ifaceB2}} {
		if out, err := runNS(x.ns, "ip", "link", "show", x.iface); err == nil {
			t.Fatalf("interface %s still present in %s: %s", x.iface, x.ns, out)
		}
	}
	t.Logf("lab-loopback WG Stop: both interfaces deleted")
}

func mustIfaceName(t *testing.T, d *WgDriver, id string) string {
	t.Helper()
	d.mu.Lock()
	st := d.runs[id]
	d.mu.Unlock()
	if st == nil {
		t.Fatalf("instance %q not registered", id)
	}
	return st.iface
}
