package agent

// Hermetic tests for the WireGuard carrier companion (udp2raw): param
// validation, the peer-endpoint override, the kernel RST rule lifecycle
// (Add on Start, Del on Stop, comment-tagged with the tunnel id), the
// supervised respawn seam, and the companion binary delivery cache path.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

func wgCompanionTest() *wgCompanion {
	return &wgCompanion{
		Kind: "udp2raw", ServerAddr: "203.0.113.9:51930", ListenAddr: "0.0.0.0:51930",
		Password: "udp2raw-pass-01", AutoIptables: true,
		Version: "20230206.0", Artifact: "udp2raw-20230206.0-linux-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("aa", 32), SHA256Arm: strings.Repeat("bb", 32),
		SigAmd: strings.Repeat("QQ==", 22)[:88], SigArm: strings.Repeat("QQ==", 22)[:88],
	}
}

// warmUDP2RawCache pre-populates the companion binary cache so Start
// exercises the cache-hit path without any fetch.
func warmUDP2RawCache(t *testing.T) {
	t.Helper()
	dir := filepath.Join(configDir, "engines", "udp2raw", "bin", "20230206.0")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "udp2raw"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "artifact.sha256"), []byte(strings.Repeat("aa", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWgCompanionValidate(t *testing.T) {
	c := wgCompanionTest()
	if err := c.validate(); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
	for name, mutate := range map[string]func(*wgCompanion){
		"kind":        func(c *wgCompanion) { c.Kind = "gre" },
		"server_addr": func(c *wgCompanion) { c.ServerAddr = "no-port" },
		"listen_addr": func(c *wgCompanion) { c.ListenAddr = `0.0.0.0:"1"` },
		"password":    func(c *wgCompanion) { c.Password = "short" },
		"pins":        func(c *wgCompanion) { c.SHA256Amd = "short" },
	} {
		bad := wgCompanionTest()
		mutate(bad)
		if err := bad.validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// Nil companion is valid (plain UDP).
	var nilc *wgCompanion
	if err := nilc.validate(); err != nil {
		t.Fatalf("nil companion rejected: %v", err)
	}
	// AGENT-20: udp2raw is amd64-only upstream — the arm64 pins are
	// OPTIONAL (both or neither); an amd64-only pin set validates.
	amd64Only := wgCompanionTest()
	amd64Only.SHA256Arm, amd64Only.SigArm = "", ""
	if err := amd64Only.validate(); err != nil {
		t.Fatalf("amd64-only pins rejected: %v", err)
	}
	halfArm := wgCompanionTest()
	halfArm.SigArm = ""
	if err := halfArm.validate(); err == nil {
		t.Fatal("arm64 sha without signature accepted (pins must be a pair or absent)")
	}
	shortArm := wgCompanionTest()
	shortArm.SHA256Arm = "short"
	if err := shortArm.validate(); err == nil {
		t.Fatal("malformed arm64 pin accepted")
	}
}

// TestWgCompanionArchPin: the ensure-time fail-closed resolution — amd64
// always resolves; arm64 resolves ONLY with pins (udp2raw is amd64-only
// upstream) and the error names the situation clearly, BEFORE any fetch.
func TestWgCompanionArchPin(t *testing.T) {
	c := wgCompanionTest()
	name, sha, sig, err := wgCompanionArchPin("amd64", c)
	if err != nil || !strings.Contains(name, "amd64") || sha != c.SHA256Amd || sig != c.SigAmd {
		t.Fatalf("amd64 pin: %v %q", err, name)
	}
	name, sha, sig, err = wgCompanionArchPin("arm64", c)
	if err != nil || !strings.Contains(name, "arm64") || sha != c.SHA256Arm {
		t.Fatalf("arm64 pin (pinned): %v %q", err, name)
	}
	noArm := wgCompanionTest()
	noArm.SHA256Arm, noArm.SigArm = "", ""
	_, _, _, err = wgCompanionArchPin("arm64", noArm)
	if err == nil || !strings.Contains(err.Error(), "amd64-only") {
		t.Fatalf("arm64 without pins must fail closed with the amd64-only message, got: %v", err)
	}
	if _, _, _, err := wgCompanionArchPin("riscv64", c); err == nil {
		t.Fatal("unsupported arch accepted")
	}
}

func TestWgPeerEndpointCompanion(t *testing.T) {
	p := wgTestParams()
	if got := wgPeerEndpoint(p, engineSideClient); got != "203.0.0.9:25110" && got != "203.0.113.9:25110" {
		t.Fatalf("plain endpoint = %q", got)
	}
	p.Companion = wgCompanionTest()
	if got := wgPeerEndpoint(p, engineSideClient); got != "127.0.0.1:51930" {
		t.Fatalf("companion endpoint = %q, want 127.0.0.1:51930", got)
	}
	if got := wgPeerEndpoint(p, engineSideServer); got != "" {
		t.Fatalf("server endpoint = %q, want empty", got)
	}
}

func TestWgCompanionStartStopShape(t *testing.T) {
	_, _ = wgSetTestEnv(t)
	origIpt := acctIptables
	iptCalls := new([]string)
	acctIptables = func(args ...string) ([]byte, error) {
		*iptCalls = append(*iptCalls, strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() { acctIptables = origIpt })
	origCap := osGeteuid
	osGeteuid = func() int { return 0 } // the hermetic env is "root"
	t.Cleanup(func() { osGeteuid = origCap })
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = "test-pinned-key"
	t.Cleanup(func() { engineArtifactPubKeyB64 = origKey })
	warmUDP2RawCache(t)

	var spawnArgs []string
	origCSpawn := wgCompanionSpawn
	wgCompanionSpawn = func(binPath string, args []string) (frpProcess, error) {
		spawnArgs = append([]string{binPath}, args...)
		return &fakeFRPProcess{}, nil
	}
	t.Cleanup(func() { wgCompanionSpawn = origCSpawn })

	d := NewWgDriver()
	p := wgTestParams()
	p.Companion = wgCompanionTest()
	inst := engine.Instance{TunnelID: "twc1", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("server Start with companion: %v", err)
	}
	// The udp2raw spawn: server mode, listen 0.0.0.0:51930, forward to the
	// WG carrier on loopback.
	joined := strings.Join(spawnArgs, " ")
	for _, want := range []string{"udp2raw", "-s", "-l 0.0.0.0:51930", "-r 127.0.0.1:25110", "--raw-mode faketcp"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("udp2raw args missing %q: %s", want, joined)
		}
	}
	// The kernel RST rule: added with the tunnel comment.
	ipt := strings.Join(*iptCalls, "\n")
	if !strings.Contains(ipt, "-I INPUT -p tcp --dport 51930") ||
		!strings.Contains(ipt, "--comment quantum-wg-twc1") {
		t.Fatalf("kernel RST rule missing:\n%s", ipt)
	}
	// Stop: the rule is removed with the SAME comment, nothing else.
	*iptCalls = (*iptCalls)[:0]
	if err := d.Stop(inst); err != nil {
		t.Fatal(err)
	}
	ipt = strings.Join(*iptCalls, "\n")
	if !strings.Contains(ipt, "-D INPUT -p tcp --dport 51930") {
		t.Fatalf("RST rule not removed on Stop:\n%s", ipt)
	}
	if strings.Count(ipt, "-D INPUT") != 1 {
		t.Fatalf("Stop removed %d rules, want exactly 1", strings.Count(ipt, "-D INPUT"))
	}
}

func TestWgCompanionClientEndpointAtStart(t *testing.T) {
	cmds, _ := wgSetTestEnv(t)
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "iran-1"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	origCap := osGeteuid
	osGeteuid = func() int { return 0 }
	t.Cleanup(func() { osGeteuid = origCap })
	warmUDP2RawCache(t)
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = "test-pinned-key"
	t.Cleanup(func() { engineArtifactPubKeyB64 = origKey })
	origCSpawn := wgCompanionSpawn
	wgCompanionSpawn = func(binPath string, args []string) (frpProcess, error) {
		return &fakeFRPProcess{}, nil
	}
	t.Cleanup(func() { wgCompanionSpawn = origCSpawn })

	d := NewWgDriver()
	p := wgTestParams()
	p.Companion = wgCompanionTest()
	p.PeerPublic = strings.Repeat("cD", 21) + "=="
	if err := d.Start(context.Background(), engine.Instance{TunnelID: "twc2",
		LocalServer: "iran", RemoteServer: "germany", Params: mustJSON(p)}); err != nil {
		t.Fatal(err)
	}
	// The client's peer endpoint goes into the LOCAL udp2raw listener.
	joined := strings.Join(*cmds, "\n")
	if !strings.Contains(joined, "endpoint 127.0.0.1:51930") {
		t.Fatalf("client peer endpoint not routed through the companion:\n%s", joined)
	}
	if strings.Contains(joined, "endpoint 203.0.113.9") {
		t.Fatalf("client peer endpoint dials the raw UDP carrier despite the companion:\n%s", joined)
	}

}

func TestRegistryCompanionSuffix(t *testing.T) {
	reg := engine.NewRegistry()
	if err := reg.Register(NewWgDriver()); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Driver("wireguard"); !ok {
		t.Fatal("plain id not found")
	}
	if _, ok := reg.Driver("wireguard@udp2raw"); !ok {
		t.Fatal("companion suffix did not resolve to the base driver")
	}
	if _, ok := reg.Driver("nosuch@udp2raw"); ok {
		t.Fatal("unknown base resolved")
	}
	if engine.BaseEngineID("wireguard@udp2raw") != "wireguard" ||
		engine.BaseEngineID("wireguard") != "wireguard" {
		t.Fatal("BaseEngineID broken")
	}
	_ = json.Marshal
}
