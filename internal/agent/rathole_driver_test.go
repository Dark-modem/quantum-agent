package agent

// Hermetic tests for the rathole driver: validate shapes (TOML injection
// guarded), config rendering (noise keys, service name shared by both
// ends, secrets never in unexpected places), role resolution via the
// enrollment name, Start/Stop shape with stubbed seams, the server's
// service-port health gate, and Uninstall cleanliness.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

func ratholeTestParams() ratholeParams {
	return ratholeParams{
		ServerSide: "germany", Version: "0.5.0",
		Artifact:  "rathole-0.5.0-linux-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("aa", 32), SHA256Arm: strings.Repeat("bb", 32),
		SigAmd: strings.Repeat("QQ==", 22)[:88], SigArm: strings.Repeat("QQ==", 22)[:88],
		ServerAddr: "0.0.0.0:23331", ServiceAddr: "0.0.0.0:25202",
		LocalAddr: "127.0.0.1:25201", Token: "rathole-test-token-01",
	}
}

// ratholeSetTestEnv stubs every seam: no kernel touches, no processes.
func ratholeSetTestEnv(t *testing.T) (cmds *[]string, spawned *int) {
	t.Helper()
	cmds = new([]string)
	origCmd := wgCmd
	wgCmd = func(args ...string) error {
		*cmds = append(*cmds, strings.Join(args, " "))
		return nil
	}
	spawned = new(int)
	origSpawn := ratholeSpawn
	ratholeSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		*spawned++
		return &fakeFRPProcess{}, nil
	}
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "germany"}, true
	}
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) {
		*cmds = append(*cmds, strings.Join(args, " "))
		return nil, nil
	}
	// A pinned key + a warm binary cache so Start exercises the idempotent
	// cache-hit path without any fetch (the fetch/verify path has its own
	// coverage in the integration test).
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = "test-pinned-key"
	origCfg := configDir
	configDir = t.TempDir()
	binDir := ratholeBinDir("0.5.0")
	_ = os.MkdirAll(binDir, 0o700)
	_ = os.WriteFile(filepath.Join(binDir, "rathole"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	_ = os.WriteFile(filepath.Join(binDir, "artifact.sha256"), []byte(strings.Repeat("aa", 32)), 0o600)
	t.Cleanup(func() {
		wgCmd = origCmd
		ratholeSpawn = origSpawn
		frpLoadIdentity = origIdent
		frpIptables = origIpt
		engineArtifactPubKeyB64 = origKey
		configDir = origCfg
	})
	return cmds, spawned
}

func TestRatholeValidateParams(t *testing.T) {
	d := NewRatholeDriver()
	raw, _ := json.Marshal(ratholeTestParams())
	if err := d.Validate(raw); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
	for name, mutate := range map[string]func(*ratholeParams){
		"quote in token":    func(p *ratholeParams) { p.Token = `to"ken1234` },
		"newline in token":  func(p *ratholeParams) { p.Token = "to\nken1234" },
		"short token":       func(p *ratholeParams) { p.Token = "short" },
		"bad server_addr":   func(p *ratholeParams) { p.ServerAddr = "no-port-here" },
		"bad service_addr":  func(p *ratholeParams) { p.ServiceAddr = `x"y:1` },
		"bad local_addr":    func(p *ratholeParams) { p.LocalAddr = "127.0.0.1" },
		"bad sha pin":       func(p *ratholeParams) { p.SHA256Amd = "short" },
		"bad sig pin":       func(p *ratholeParams) { p.SigArm = "short" },
		"no arch template":  func(p *ratholeParams) { p.Artifact = "rathole.tar.gz" },
		"bad noise key len": func(p *ratholeParams) { p.NoiseServerPublic = "short" },
		"noise key quotes":  func(p *ratholeParams) { p.NoiseServerPublic = strings.Repeat("a", 43) + "'=" },
		"empty server_side": func(p *ratholeParams) { p.ServerSide = " " },
	} {
		p := ratholeTestParams()
		mutate(&p)
		raw, _ := json.Marshal(p)
		if err := d.Validate(raw); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestRatholeRenderConfig(t *testing.T) {
	p := ratholeTestParams()
	p.NoiseServerPublic = strings.Repeat("cD", 21) + "=="
	srv := ratholeRenderConfig("server", "qtw1", p, "SERVER_PRIV_KEY_B64")
	for _, want := range []string{
		`[server]`, `bind_addr = "0.0.0.0:23331"`, `heartbeat_interval = 30`,
		`type = "noise"`, `local_private_key = "SERVER_PRIV_KEY_B64"`,
		`[server.services.qtw1]`, `token = "rathole-test-token-01"`,
		`bind_addr = "0.0.0.0:25202"`,
	} {
		if !strings.Contains(srv, want) {
			t.Fatalf("server config missing %q:\n%s", want, srv)
		}
	}
	if strings.Contains(srv, "SERVER_PRIV_KEY_B64\n[client") || strings.Contains(srv, "remote_public_key") {
		t.Fatal("server config leaks the noise key shape or carries the client block")
	}
	cli := ratholeRenderConfig("client", "qtw1", p, "")
	for _, want := range []string{
		`[client]`, `remote_addr = "0.0.0.0:23331"`, `heartbeat_timeout = 40`,
		`remote_public_key = "` + p.NoiseServerPublic + `"`,
		`[client.services.qtw1]`, `local_addr = "127.0.0.1:25201"`,
	} {
		if !strings.Contains(cli, want) {
			t.Fatalf("client config missing %q:\n%s", want, cli)
		}
	}
	if strings.Contains(cli, "local_private_key") {
		t.Fatal("client config carries a private key")
	}
}

func TestRatholeStartStopShape(t *testing.T) {
	cmds, spawned := ratholeSetTestEnv(t)
	d := NewRatholeDriver()
	p := ratholeTestParams()
	inst := engine.Instance{TunnelID: "trh1", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	if *spawned != 1 {
		t.Fatalf("spawned = %d, want 1", *spawned)
	}
	// The server end installs wire accounting on the carrier port.
	if !strings.Contains(strings.Join(*cmds, "\n"), "23331") {
		t.Fatalf("wire accounting for the carrier port missing:\n%s", strings.Join(*cmds, "\n"))
	}
	// Idempotent second Start.
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("idempotent Start: %v", err)
	}
	if *spawned != 1 {
		t.Fatalf("second Start spawned again: %d", *spawned)
	}
	// Health: the service-port gate is ON for the server role — with no
	// listener the dial fails fast in the test env (no retries hang).
	if h := d.Health(inst); h.OK {
		t.Fatalf("health without a registered client: %+v", h)
	}
	if err := d.Stop(inst); err != nil {
		t.Fatal(err)
	}
	if h := d.Health(inst); h.OK {
		t.Fatal("alive after Stop")
	}
	// Uninstall removes the engine dir entirely.
	if err := d.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fileExists(ratholeEngineDir()) {
		t.Fatal("engine dir left behind after Uninstall")
	}
}

func TestRatholeClientNeedsNoiseKey(t *testing.T) {
	cmds, _ := ratholeSetTestEnv(t)
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "iran-1"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	d := NewRatholeDriver()
	// Without noise_server_public: fail closed.
	p := ratholeTestParams()
	if err := d.Start(context.Background(), engine.Instance{TunnelID: "trh2",
		LocalServer: "iran", RemoteServer: "germany", Params: mustJSON(p)}); err == nil {
		t.Fatal("client Start without the server's noise key accepted")
	}
	// With it: starts, and the rendered config carries the key.
	p.NoiseServerPublic = strings.Repeat("cD", 21) + "=="
	if err := d.Start(context.Background(), engine.Instance{TunnelID: "trh2",
		LocalServer: "iran", RemoteServer: "germany", Params: mustJSON(p)}); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	b, err := os.ReadFile(ratholeConfigPath("trh2"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "remote_public_key") {
		t.Fatalf("client config missing the remote noise key:\n%s", b)
	}
	_ = cmds
}

func TestRatholeHealthClientRole(t *testing.T) {
	ratholeSetTestEnv(t)
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "iran-1"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	d := NewRatholeDriver()
	p := ratholeTestParams()
	p.NoiseServerPublic = strings.Repeat("cD", 21) + "=="
	inst := engine.Instance{TunnelID: "trh3", LocalServer: "iran", RemoteServer: "germany",
		Params: mustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatal(err)
	}
	// The CLIENT role has no service-port gate (the process check only).
	if h := d.Health(inst); !h.OK {
		t.Fatalf("client health: %+v", h)
	}
}
