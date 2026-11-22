package agent

// Hermetic tests for the gost driver: validate shapes, the strictly-typed
// CLI rendering for both ends, role resolution, Start/Stop shape with
// stubbed seams, and the server-end health gate.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/infra"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

func gostTestParams() gostParams {
	return gostParams{
		ServerSide: "germany", Version: "3.3.3",
		Artifact:  "gost-3.3.3-linux-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("aa", 32), SHA256Arm: strings.Repeat("bb", 32),
		SigAmd: strings.Repeat("QQ==", 22)[:88], SigArm: strings.Repeat("QQ==", 22)[:88],
		CarrierAddr: "0.0.0.0:23344", PublicPort: 25203,
		LocalAddr: "127.0.0.1:25201", Transport: "ws",
	}
}

func gostSetTestEnv(t *testing.T) (cmds *[]string, spawned *int) {
	t.Helper()
	cmds = new([]string)
	spawned = new(int)
	origSpawn := gostSpawn
	gostSpawn = func(binPath string, args []string) (frpProcess, error) {
		*spawned++
		*cmds = append(*cmds, strings.Join(args, " "))
		return &fakeFRPProcess{}, nil
	}
	t.Cleanup(func() { gostSpawn = origSpawn })
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) {
		*cmds = append(*cmds, strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() { acctIptables = origIpt })
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "germany"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = "test-pinned-key"
	origCfg := infra.ConfigDir
	infra.ConfigDir = t.TempDir()
	binDir := gostBinDir("3.3.3")
	_ = os.MkdirAll(binDir, 0o700)
	_ = os.WriteFile(filepath.Join(binDir, "gost"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	_ = os.WriteFile(filepath.Join(binDir, "artifact.sha256"), []byte(strings.Repeat("aa", 32)), 0o600)
	t.Cleanup(func() {
		frpLoadIdentity = origIdent
		engineArtifactPubKeyB64 = origKey
		infra.ConfigDir = origCfg
	})
	return cmds, spawned
}

func TestGostValidateParams(t *testing.T) {
	d := NewGostDriver()
	raw, _ := json.Marshal(gostTestParams())
	if err := d.Validate(raw); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
	for name, mutate := range map[string]func(*gostParams){
		"wss transport":  func(p *gostParams) { p.Transport = "wss" },
		"tls transport":  func(p *gostParams) { p.Transport = "tls" },
		"bad carrier":    func(p *gostParams) { p.CarrierAddr = "no-port" },
		"carrier quotes": func(p *gostParams) { p.CarrierAddr = `0.0.0.0:"1"` },
		"public port 0":  func(p *gostParams) { p.PublicPort = 0 },
		"bad local_addr": func(p *gostParams) { p.LocalAddr = "127.0.0.1" },
		"local quotes":   func(p *gostParams) { p.LocalAddr = `12"1:1` },
		"bad sha":        func(p *gostParams) { p.SHA256Arm = "short" },
		"no arch templ":  func(p *gostParams) { p.Artifact = "gost.tar.gz" },
		"empty server":   func(p *gostParams) { p.ServerSide = " " },
	} {
		p := gostTestParams()
		mutate(&p)
		raw, _ := json.Marshal(p)
		if err := d.Validate(raw); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestGostArgsShape(t *testing.T) {
	cmds, spawned := gostSetTestEnv(t)
	d := NewGostDriver()
	p := gostTestParams()
	inst := engine.Instance{TunnelID: "tg1", LocalServer: "germany", RemoteServer: "iran",
		Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	if *spawned != 1 {
		t.Fatalf("spawned = %d", *spawned)
	}
	// The server's strictly-typed relay+ws with bind.
	if !strings.Contains(strings.Join(*cmds, "\n"), `-L relay+ws://:23344?bind=true`) {
		t.Fatalf("server args missing the relay+ws bind form:\n%s", strings.Join(*cmds, "\n"))
	}
	// Idempotent.
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatal(err)
	}
	if *spawned != 1 {
		t.Fatalf("idempotent Start spawned again: %d", *spawned)
	}

	// The client: rtcp remote forward + the relay+ws chain.
	*cmds = (*cmds)[:0]
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "iran-1"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	if err := d.Start(context.Background(), engine.Instance{TunnelID: "tg2",
		LocalServer: "iran", RemoteServer: "germany", Params: infra.MustJSON(p)}); err != nil {
		t.Fatal(err)
	}
	clientArgs := strings.Join(*cmds, "\n")
	if !strings.Contains(clientArgs, `-L rtcp://:25203/127.0.0.1:25201`) ||
		!strings.Contains(clientArgs, `-F relay+ws://0.0.0.0:23344`) {
		t.Fatalf("client args wrong:\n%s", clientArgs)
	}
	// Health: the server-end gate dial fails (no listener in the hermetic
	// env) — bounded retries, then unhealthy.
	if h := d.Health(engine.Instance{TunnelID: "tg1"}); h.OK {
		t.Fatalf("health without a registered client: %+v", h)
	}
	if err := d.Stop(engine.Instance{TunnelID: "tg1"}); err != nil {
		t.Fatal(err)
	}
	if h := d.Health(engine.Instance{TunnelID: "tg1"}); h.OK {
		t.Fatal("alive after Stop")
	}
	if err := d.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if infra.FileExists(gostEngineDir()) {
		t.Fatal("engine dir left after Uninstall")
	}
}
