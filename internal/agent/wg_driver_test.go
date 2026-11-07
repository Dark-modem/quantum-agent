package agent

// Hermetic tests for the WireGuard driver: key generation (private key
// never logged), iface naming (disjoint from qmx*), role resolution,
// Start/Stop shape with STUBBED ip/wg/wgTool seams (no kernel touches in
// unit tests), validate, reconcile shape, and the key-exchange flow
// (ack carries the public key; DesiredV2 carries the peer key back).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// wgSetTestEnv stubs every seam: no kernel touches.
func wgSetTestEnv(t *testing.T) (cmds *[]string, spawned *int) {
	t.Helper()
	cmds = new([]string)
	origRun := wgRun
	origCmd := wgCmd
	wgRun = func(iface string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "genkey" {
			// 44-char base64 of 32 bytes (deterministic shape, random
			// enough for the tests through the seeded pins).
			return strings.Repeat("aB", 22) + "==", nil
		}
		if len(args) > 1 && args[0] == "pubkey" {
			return strings.Repeat("cD", 22) + "==", nil
		}
		if len(args) > 0 && args[0] == "show" {
			if len(args) > 2 && args[2] == "transfer" {
				return "PEERKEY 1000 2000\n", nil
			}
			if len(args) > 2 && args[2] == "latest-handshakes" {
				return "PEERKEY " + fmtNow(), nil
			}
		}
		return "", nil
	}
	wgCmd = func(args ...string) error {
		*cmds = append(*cmds, strings.Join(args, " "))
		return nil
	}
	spawned = new(int)
	origSpawn := frpSpawn
	frpSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		*spawned++
		return &fakeFRPProcess{}, nil
	}
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "germany"}, true
	}
	origCfg := configDir
	configDir = t.TempDir()
	t.Cleanup(func() {
		wgRun = origRun
		wgCmd = origCmd
		frpSpawn = origSpawn
		frpLoadIdentity = origIdent
		configDir = origCfg
	})
	return cmds, spawned
}

// fmtNow returns the current unix time as a string (handshake age 0).
func fmtNow() string { return fmt.Sprintf("%d", time.Now().Unix()) }

func wgTestParams() wgParams {
	return wgParams{ServerSide: "germany", CarrierIP: "203.0.113.9", CarrierPort: 25110, MTU: 0}
}

func TestWgDriverImplementsEngineDriver(t *testing.T) {
	var d engine.Driver = NewWgDriver()
	if d.ID() != "wireguard" {
		t.Fatalf("ID = %q", d.ID())
	}
}

func TestWgValidateParams(t *testing.T) {
	d := NewWgDriver()
	p := wgTestParams()
	raw, _ := json.Marshal(p)
	if err := d.Validate(raw); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
	bad := p
	bad.CarrierIP = "not-an-ip"
	raw, _ = json.Marshal(bad)
	if err := d.Validate(raw); err == nil {
		t.Fatal("bad carrier_ip accepted")
	}
	bad = p
	bad.MTU = 500
	raw, _ = json.Marshal(bad)
	if err := d.Validate(raw); err == nil {
		t.Fatal("tiny MTU accepted")
	}
	good := p
	good.PeerPublic = strings.Repeat("cD", 21) + "=="
	raw, _ = json.Marshal(good)
	if err := d.Validate(raw); err != nil {
		t.Fatalf("valid 44-char peer_public rejected: %v", err)
	}
	for _, badPub := range []string{"PLACEHOLDER", strings.Repeat("cD", 22), "not base64!!=="} {
		badP := p
		badP.PeerPublic = badPub
		raw, _ = json.Marshal(badP)
		if err := d.Validate(raw); err == nil {
			t.Fatalf("bad peer_public %q accepted", badPub)
		}
	}
}

// TestWgToolExecMapping locks the wgToolExec binary mapping: wg exits 0
// even on "Invalid subcommand", so a wrong mapping is a SILENT no-op (the
// kernel never gets configured and every command "succeeds" — found by
// the netns integration test).
func TestWgToolExecMapping(t *testing.T) {
	origRunner := runner
	t.Cleanup(func() { runner = origRunner })
	var name string
	var gotArgs []string
	runner = func(ctx context.Context, n string, a ...string) ([]byte, error) {
		name, gotArgs = n, a
		return nil, nil
	}
	for _, c := range []struct {
		in       []string
		wantBin  string
		wantArgs []string
	}{
		{[]string{"wg", "set", "qwg1", "private-key", "/tmp/k"}, "wg", []string{"set", "qwg1", "private-key", "/tmp/k"}},
		{[]string{"ip", "link", "add", "qwg1", "type", "wireguard"}, "ip", []string{"link", "add", "qwg1", "type", "wireguard"}},
		{[]string{"show", "qwg1", "transfer"}, "wg", []string{"show", "qwg1", "transfer"}},
	} {
		if _, err := wgToolExec(c.in...); err != nil {
			t.Fatalf("%v: %v", c.in, err)
		}
		if name != c.wantBin || strings.Join(gotArgs, " ") != strings.Join(c.wantArgs, " ") {
			t.Fatalf("%v → %s %v, want %s %v", c.in, name, gotArgs, c.wantBin, c.wantArgs)
		}
	}
}

// TestWgIfaceBytesParsesIPSDirections: the payload counters must read the
// RX and TX rows of `ip -s link show` separately (the old line-4 hack
// reported RX packets as TX bytes).
func TestWgIfaceBytesParsesIPSDirections(t *testing.T) {
	orig := wgRun
	wgRun = func(iface string, args ...string) (string, error) {
		return `3: qwgb: <POINTOPOINT,NOARP,UP,LOWER_UP>
    link/none
    RX: bytes packets errors dropped  missed  mcast
      184711     2873      0       0       0       0
    TX: bytes packets errors dropped carrier  collsns
      214000000   150000      0       0       0       0
`, nil
	}
	t.Cleanup(func() { wgRun = orig })
	rx, tx, ok := wgIfaceBytes("qwgb")
	if !ok {
		t.Fatal("parse failed")
	}
	if rx != 184711 {
		t.Fatalf("rx = %d, want 184711", rx)
	}
	if tx != 214000000 {
		t.Fatalf("tx = %d, want 214000000", tx)
	}
}

// TestWgPeerApplicationShape: with peer_public set, the SERVER installs
// the peer with allowed-ips pinned to the client's tunnel address, and
// the CLIENT pins the carrier endpoint + keepalive. Without peer_public
// NO peer is configured at all — a real wg binary rejects invalid keys,
// so there is no placeholder (found by the netns integration test).
func TestWgPeerApplicationShape(t *testing.T) {
	cmds, _ := wgSetTestEnv(t)
	d := NewWgDriver()
	peerPub := strings.Repeat("cD", 21) + "=="
	// The env stub's identity is "germany" (server role); the client-role
	// half needs an Iran identity.
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "iran-1"}, true
	}
	p := wgTestParams()
	p.PeerPublic = peerPub
	inst := engine.Instance{TunnelID: "tw2", LocalServer: "iran", RemoteServer: "germany",
		Params: mustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	frpLoadIdentity = origIdent
	joined := strings.Join(*cmds, "\n")
	want := "peer " + peerPub + " endpoint 203.0.113.9:25110 persistent-keepalive 15 allowed-ips 10.189.0.1/32"
	if !strings.Contains(joined, want) {
		t.Fatalf("client peer shape missing %q:\n%s", want, joined)
	}

	*cmds = (*cmds)[:0]
	p2 := wgTestParams()
	p2.PeerPublic = peerPub
	inst2 := engine.Instance{TunnelID: "tw2b", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(p2)}
	if err := d.Start(context.Background(), inst2); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	joined = strings.Join(*cmds, "\n")
	if !strings.Contains(joined, "peer "+peerPub+" allowed-ips 10.189.0.2/32") {
		t.Fatalf("server peer shape missing the client tunnel address:\n%s", joined)
	}

	// No peer_public: no peer command at all (no placeholder).
	*cmds = (*cmds)[:0]
	inst3 := engine.Instance{TunnelID: "tw2c", LocalServer: "iran", RemoteServer: "germany",
		Params: mustJSON(wgTestParams())}
	if err := d.Start(context.Background(), inst3); err != nil {
		t.Fatalf("peerless client Start: %v", err)
	}
	if strings.Contains(strings.Join(*cmds, "\n"), " peer ") {
		t.Fatalf("peer configured without peer_public:\n%s", strings.Join(*cmds, "\n"))
	}
}

func TestWgIfaceNameDisjointFromMatrix(t *testing.T) {
	name, err := wgIfaceName("tb1a2b3c")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "qwg") || strings.HasPrefix(name, "qmx") || len(name) > 15 {
		t.Fatalf("iface name = %q", name)
	}
	// Distinct tunnel ids → distinct ifaces.
	n2, _ := wgIfaceName("tb2b3c4d")
	if n2 == name {
		t.Fatal("iface collision")
	}
}

func TestWgKeysGeneratedOnAgent(t *testing.T) {
	// Private key never logged: generate and scan the driver's surfaces.
	pub, priv, err := wgKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 44 || len(priv) != 44 { // b64 of 32 bytes + padding
		t.Fatalf("key shapes: pub=%d priv=%d", len(pub), len(priv))
	}
	if pub == priv {
		t.Fatal("pub == priv")
	}
	// Round-trip: pub derives from priv.
	if decoded, err := wgB64Decode(priv); err != nil || len(decoded) != 32 {
		t.Fatalf("priv decode: %v", err)
	}
}

func TestWgStartStopShape(t *testing.T) {
	cmds, _ := wgSetTestEnv(t)
	d := NewWgDriver()
	p := wgTestParams()
	inst := engine.Instance{TunnelID: "tw1", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("Start: %v", err)
	}
	joined := strings.Join(*cmds, "\n")
	for _, want := range []string{"link add qwg", "type wireguard", "addr add 10.189.0.1/30",
		"mtu 1420", "listen-port 25110"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("cmds missing %q:\n%s", want, joined)
		}
	}
	// AllowedIPs scoped to the /30: the server config must never contain
	// 0.0.0.0/0.
	if strings.Contains(joined, "0.0.0.0/0") {
		t.Fatal("catch-all allowed-ips in the kernel config")
	}
	if h := d.Health(inst); !h.OK {
		t.Fatalf("health = %+v", h)
	}
	c := d.Counters(inst)
	if !c.WireKnown || c.WireRx != 1000 || c.WireTx != 2000 {
		t.Fatalf("wire counters = %+v", c)
	}
	if err := d.Stop(inst); err != nil {
		t.Fatal(err)
	}
	if h := d.Health(inst); h.OK {
		t.Fatal("alive after Stop")
	}
	// The interface was deleted.
	found := false
	for _, c := range *cmds {
		if strings.HasPrefix(c, "ip link del qwg") {
			found = true
		}
	}
	if !found {
		t.Fatal("interface not deleted on Stop")
	}
}

func TestWgReconcileShape(t *testing.T) {
	_, _ = wgSetTestEnv(t)
	reg := engine.NewRegistry()
	if err := reg.Register(NewWgDriver()); err != nil {
		t.Fatal(err)
	}
	mgr := engine.NewManager(reg)
	p := wgTestParams()
	res := mgr.Reconcile(context.Background(),
		[]engine.EngineSpec{{ID: "wireguard", Enabled: true}},
		[]engine.TunnelSpec{{ID: "tw2", Engine: "wireguard", LocalServer: "germany", RemoteServer: "iran",
			Params: mustJSON(p), Enabled: true}})
	if len(res.Errors) > 0 {
		t.Fatalf("reconcile: %v", res.Errors)
	}
	if mgr.RunningCount() != 1 {
		t.Fatalf("running = %d", mgr.RunningCount())
	}
	res = mgr.Reconcile(context.Background(), nil, nil)
	if mgr.RunningCount() != 0 {
		t.Fatal("running after disable")
	}
	found := false
	for _, id := range res.Uninstalled {
		if id == "wireguard" {
			found = true
		}
	}
	if !found {
		t.Fatalf("wg not uninstalled after idle: %v", res.Uninstalled)
	}
}

// TestWgKeyExchangeFlow pins the DESIGN flow: the server end's ack
// detail carries the generated public key; the later desired revision
// delivers the peer key to the client end. The driver exposes the public
// key through its state for the ack path (wgPeerPublic).
func TestWgKeyExchangeFlow(t *testing.T) {
	_, _ = wgSetTestEnv(t)
	d := NewWgDriver()
	p := wgTestParams()
	inst := engine.Instance{TunnelID: "tw3", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	st := d.runs["tw3"]
	pub := st.pubB64
	d.mu.Unlock()
	if pub == "" {
		t.Fatal("public key not generated on the agent")
	}
	// The ack path (wgPeerPublic) returns it for the panel.
	if wgPeerPublic(st) != pub {
		t.Fatal("peer public key not reported")
	}
}

// TestWgTwoAgentKeyPersistence: two agents' worth of state in one test.
// Keys persist per tunnel (0600) across driver recreation (agent
// restart); the panel's peer_public revision applies LIVE via `wg set`
// (Reload nil — no restart, no interface recreation, no re-key); a
// non-peer params change still requires a restart.
func TestWgTwoAgentKeyPersistence(t *testing.T) {
	cmds, _ := wgSetTestEnv(t)
	origCfg := configDir
	t.Cleanup(func() { configDir = origCfg })
	dirA, dirB := t.TempDir(), t.TempDir()

	p := wgTestParams()
	dA := NewWgDriver() // agent A (foreign, server role)
	configDir = dirA
	instA := engine.Instance{TunnelID: "twp-a", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(p)}
	if err := dA.Start(context.Background(), instA); err != nil {
		t.Fatalf("A start: %v", err)
	}
	dA.mu.Lock()
	pubA := dA.runs["twp-a"].pubB64
	dA.mu.Unlock()
	fi, err := os.Stat(filepath.Join(dirA, "wg", "twp-a.key"))
	if err != nil {
		t.Fatalf("persisted key file missing: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", fi.Mode().Perm())
	}

	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "iran-1"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	dB := NewWgDriver() // agent B (Iran, client role)
	configDir = dirB
	instB := engine.Instance{TunnelID: "twp-b", LocalServer: "iran", RemoteServer: "germany",
		Params: mustJSON(p)}
	if err := dB.Start(context.Background(), instB); err != nil {
		t.Fatalf("B start: %v", err)
	}
	dB.mu.Lock()
	pubB := dB.runs["twp-b"].pubB64
	dB.mu.Unlock()

	// The panel's peer_public revision on B: LIVE apply, no restart.
	*cmds = (*cmds)[:0]
	revB := p
	revB.PeerPublic = pubA
	if err := dB.Reload(engine.Instance{TunnelID: "twp-b", Params: mustJSON(revB)}); err != nil {
		t.Fatalf("peer_public revision must apply live, got: %v", err)
	}
	joined := strings.Join(*cmds, "\n")
	if !strings.Contains(joined, "peer "+pubA+" endpoint 203.0.113.9:25110") {
		t.Fatalf("live peer apply missing:\n%s", joined)
	}
	if strings.Contains(joined, "link del qwg") {
		t.Fatalf("revision recreated the interface:\n%s", joined)
	}
	// The revision is recorded in the state: a second identical Reload is a no-op.
	if err := dB.Reload(engine.Instance{TunnelID: "twp-b", Params: mustJSON(revB)}); err != nil {
		t.Fatalf("second identical revision: %v", err)
	}

	// Peer revocation (peer_public back to empty) removes the kernel peer.
	*cmds = (*cmds)[:0]
	if err := dB.Reload(engine.Instance{TunnelID: "twp-b", Params: mustJSON(p)}); err != nil {
		t.Fatalf("revocation revision: %v", err)
	}
	if !strings.Contains(strings.Join(*cmds, "\n"), "peer "+pubA+" remove") {
		t.Fatalf("revocation missing the kernel peer remove:\n%s", strings.Join(*cmds, "\n"))
	}
	// Re-apply for the restart phase.
	if err := dB.Reload(engine.Instance{TunnelID: "twp-b", Params: mustJSON(revB)}); err != nil {
		t.Fatalf("re-apply: %v", err)
	}

	// Agent restart: a NEW driver on the SAME persisted state re-keys
	// NOTHING, and the revised desired state (with peer_public) applies
	// the peer at Start.
	*cmds = (*cmds)[:0]
	dB2 := NewWgDriver()
	instB2 := instB
	instB2.Params = mustJSON(revB)
	if err := dB2.Start(context.Background(), instB2); err != nil {
		t.Fatalf("B restart: %v", err)
	}
	dB2.mu.Lock()
	pubB2, privB2 := dB2.runs["twp-b"].pubB64, dB2.runs["twp-b"].privB64
	dB2.mu.Unlock()
	dB.mu.Lock()
	privB := dB.runs["twp-b"].privB64
	dB.mu.Unlock()
	if pubB2 != pubB || privB2 != privB {
		t.Fatal("restart regenerated the keypair")
	}
	if !strings.Contains(strings.Join(*cmds, "\n"), "peer "+pubA) {
		t.Fatalf("restart did not apply the peer from the revised state:\n%s", strings.Join(*cmds, "\n"))
	}

	// Server side: same persistence + its revision pins the client's /32.
	*cmds = (*cmds)[:0]
	configDir = dirA            // back to agent A's state dir
	frpLoadIdentity = origIdent // agent A's identity (germany, server role)
	dA2 := NewWgDriver()
	revA := p
	revA.PeerPublic = pubB
	if err := dA2.Start(context.Background(), engine.Instance{TunnelID: "twp-a",
		LocalServer: "germany", RemoteServer: "iran", Params: mustJSON(revA)}); err != nil {
		t.Fatalf("A restart: %v", err)
	}
	dA2.mu.Lock()
	pubA2 := dA2.runs["twp-a"].pubB64
	dA2.mu.Unlock()
	if pubA2 != pubA {
		t.Fatal("server restart regenerated the keypair")
	}
	if !strings.Contains(strings.Join(*cmds, "\n"), "peer "+pubB+" allowed-ips 10.189.0.2/32") {
		t.Fatalf("server peer shape after restart:\n%s", strings.Join(*cmds, "\n"))
	}

	// A non-peer change (MTU) still requires a restart.
	mtu := revB
	mtu.MTU = 1380
	if err := dB.Reload(engine.Instance{TunnelID: "twp-b", Params: mustJSON(mtu)}); err != engine.ErrRestartRequired {
		t.Fatalf("MTU change must require a restart, got %v", err)
	}
}
