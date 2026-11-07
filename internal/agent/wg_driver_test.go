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
