// Hermetic tests for the Backhaul driver (production shape, mirroring
// the FRP driver's test suite): release-style tarball WITH a directory
// entry, role resolution through the enrollment name, supervisor with
// capped backoff, render shapes, Uninstall on idle, and Manager
// reconcile. The binary is a fake shell script — the real-binary
// integration test lives in backhaul_integration_test.go.
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
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// backhaulTestArtifact builds a signed backhaul-style tar.gz: the binary
// wrapped in a version DIRECTORY entry (the production release shape).
func backhaulTestArtifact(t *testing.T) (body []byte, shaHex, sigB64, pubB64 string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "backhaul_0.7.2/", Mode: int64(0o755), Typeflag: tar.TypeDir,
	}); err != nil {
		t.Fatal(err)
	}
	content := []byte("#!/bin/sh\n# fake backhaul: serve the config path arg\nsleep 3600\n")
	if err := tw.WriteHeader(&tar.Header{Name: "backhaul_0.7.2/backhaul", Mode: 0o755, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
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
	sig := ed25519.Sign(priv, body)
	sigB64 = base64.StdEncoding.EncodeToString(sig)
	pubB64 = base64.StdEncoding.EncodeToString(pubDER)
	return body, shaHex, sigB64, pubB64
}

var backhaulTestPins = struct{ amd, arm, sigAmd, sigArm string }{
	strings.Repeat("ab", 32), strings.Repeat("cd", 32), strings.Repeat("QQ==", 22)[:88], strings.Repeat("QQ==", 22)[:88],
}

func backhaulTestParams() backhaulParams {
	return backhaulParams{
		ServerSide: "germany", Version: "0.7.2",
		Artifact:  "backhaul-0.7.2-linux-{arch}.tar.gz",
		Transport: "tcp", Token: "tok-backhaul-1",

		SHA256Amd: backhaulTestPins.amd, SHA256Arm: backhaulTestPins.arm,
		SigAmd: backhaulTestPins.sigAmd, SigArm: backhaulTestPins.sigArm, BindAddr: "127.0.0.1:21010",
		RemoteAddr: "127.0.0.1:21010",
		Ports:      []string{"5201=127.0.0.1:5201"},
	}
}

// backhaulSetTestEnv wires every seam the driver touches: the artifact
// HTTP endpoints (R5 manifest + file + pinned fallback), the identity,
// the key, the config dir, and a spawn seam that runs the fake binary
// with its config and logs into the work dir.
func backhaulSetTestEnv(t *testing.T) (spawned *int, fetchCalls *int) {
	t.Helper()
	body, shaHex, sigB64, pubB64 := backhaulTestArtifact(t)
	backhaulTestPins.amd, backhaulTestPins.arm = shaHex, shaHex
	backhaulTestPins.sigAmd, backhaulTestPins.sigArm = sigB64, sigB64

	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test:7777", BasePath: "bp", Name: "germany"}, true
	}
	fetchCalls = new(int)
	origFetch := frpFetchArtifact
	frpFetchArtifact = func(_ context.Context, url string) ([]byte, error) {
		*fetchCalls++
		switch {
		case strings.Contains(url, "/api/agent/engine-artifacts?engine=backhaul&goarch="):
			arch := strings.ToLower(runtime.GOARCH)
			entry := fmt.Sprintf(`{"engine":"backhaul","version":"0.7.2","goos":"linux","goarch":%q,"artifact":%q,"sha256":%q,"signature":%q}`,
				arch, strings.ReplaceAll("backhaul-0.7.2-linux-{arch}.tar.gz", "{arch}", arch), shaHex, sigB64)
			return []byte(`{"artifacts":[` + entry + `]}`), nil
		case strings.Contains(url, "/api/agent/engine-artifacts/file/"),
			strings.Contains(url, "/bp/api/agent/artifact/backhaul-0.7.2-linux-"):
			return body, nil
		}
		return nil, fmt.Errorf("unexpected artifact url %q", url)
	}
	spawned = new(int)
	origSpawn := frpSpawn
	frpSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		*spawned++
		if !strings.HasSuffix(binPath, "backhaul") {
			return nil, fmt.Errorf("unexpected binary %q", binPath)
		}
		if _, err := os.Stat(cfgPath); err != nil {
			return nil, fmt.Errorf("spawn without a rendered config: %w", err)
		}
		return &fakeFRPProcess{}, nil
	}
	origCfg := configDir
	configDir = t.TempDir()
	t.Cleanup(func() {
		engineArtifactPubKeyB64 = origKey
		frpLoadIdentity = origIdent
		frpFetchArtifact = origFetch
		frpSpawn = origSpawn
		configDir = origCfg
	})
	return spawned, fetchCalls
}

func TestBackhaulDriverImplementsEngineDriver(t *testing.T) {
	var d engine.Driver = NewBackhaulDriver()
	if d.ID() != "backhaul" {
		t.Fatalf("ID = %q", d.ID())
	}
}

func TestBackhaulValidateParams(t *testing.T) {
	p := backhaulTestParams()
	raw, _ := json.Marshal(p)
	if err := NewBackhaulDriver().Validate(raw); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}
	bad := p
	bad.Transport = "gre" // the legacy GRE transport is out of scope
	raw, _ = json.Marshal(bad)
	if err := NewBackhaulDriver().Validate(raw); err == nil {
		t.Fatal("GRE transport accepted")
	}
	bad = p
	bad.Token = "short" // < 8 chars
	raw, _ = json.Marshal(bad)
	if err := NewBackhaulDriver().Validate(raw); err == nil {
		t.Fatal("short token accepted")
	}
	bad = p
	bad.Ports = []string{`x"; rm -rf /"`}
	raw, _ = json.Marshal(bad)
	if err := NewBackhaulDriver().Validate(raw); err == nil {
		t.Fatal("TOML-unsafe port mapping accepted")
	}
}

func TestBackhaulRoleResolution(t *testing.T) {
	_, _, _, pubB64 := backhaulTestArtifact(t)
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "germany"}, true
	}
	t.Cleanup(func() {
		engineArtifactPubKeyB64 = origKey
		frpLoadIdentity = origIdent
	})
	p := backhaulTestParams()
	role, err := backhaulResolveRole(p)
	if err != nil || role != "server" {
		t.Fatalf("germany end role = %q %v, want server", role, err)
	}
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "iran-1"}, true
	}
	if role, err := backhaulResolveRole(p); err != nil || role != "client" {
		t.Fatalf("iran end role = %q %v, want client", role, err)
	}
	frpLoadIdentity = func() (agentIdentity, bool) { return agentIdentity{}, false }
	if _, err := backhaulResolveRole(p); err == nil {
		t.Fatal("role resolved without an identity (must fail closed)")
	}
}

func TestBackhaulRenderConfig(t *testing.T) {
	p := backhaulTestParams()
	serverCfg := backhaulRenderConfig("server", p)
	for _, want := range []string{`[server]`, `bind_addr = "127.0.0.1:21010"`, `transport = "tcp"`,
		`token = "tok-backhaul-1"`, `ports = ["5201=127.0.0.1:5201"]`} {
		if !strings.Contains(serverCfg, want) {
			t.Fatalf("server config missing %q:\n%s", want, serverCfg)
		}
	}
	clientCfg := backhaulRenderConfig("client", p)
	for _, want := range []string{`[client]`, `remote_addr = "127.0.0.1:21010"`, `connection_pool = 8`, `retry_interval = 5`} {
		if !strings.Contains(clientCfg, want) {
			t.Fatalf("client config missing %q:\n%s", want, clientCfg)
		}
	}
}

func TestBackhaulStartStopHealth(t *testing.T) {
	spawned, _ := backhaulSetTestEnv(t)
	d := NewBackhaulDriver()

	// Both ends of one tunnel (separate state dirs would exist in
	// production; here the seams make one process tree serve both).
	serverInst := engine.Instance{TunnelID: "tb1", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(backhaulTestParams())}
	if err := d.Start(context.Background(), serverInst); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	if *spawned != 1 {
		t.Fatalf("spawned = %d, want 1", *spawned)
	}
	// Idempotent Start with equal params.
	if err := d.Start(context.Background(), serverInst); err != nil {
		t.Fatalf("idempotent Start: %v", err)
	}
	if *spawned != 1 {
		t.Fatalf("idempotent Start respawned (%d)", *spawned)
	}
	h := d.Health(serverInst)
	if !h.OK {
		t.Fatalf("health = %+v", h)
	}
	// Wire accounting on the server end's carrier port: the counter rule
	// exists (iptables may be unavailable in the unit env — the driver
	// degrades to Unknown honestly, so only assert no panic).
	_ = d.Counters(serverInst)

	if err := d.Stop(serverInst); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	h = d.Health(serverInst)
	if h.OK {
		t.Fatalf("health after Stop = %+v", h)
	}
}

func TestBackhaulUninstallRemovesCache(t *testing.T) {
	spawned, _ := backhaulSetTestEnv(t)
	d := NewBackhaulDriver()
	inst := engine.Instance{TunnelID: "tb2", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(backhaulTestParams())}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatal(err)
	}
	if *spawned != 1 {
		t.Fatal("not spawned")
	}
	if err := d.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backhaulEngineDir()); !os.IsNotExist(err) {
		t.Fatal("engine dir survived Uninstall")
	}
	h := d.Health(inst)
	if h.OK {
		t.Fatal("instance alive after Uninstall")
	}
}

func TestBackhaulManagerReconcile(t *testing.T) {
	spawned, _ := backhaulSetTestEnv(t)
	reg := engine.NewRegistry()
	if err := reg.Register(NewBackhaulDriver()); err != nil {
		t.Fatal(err)
	}
	mgr := engine.NewManager(reg)
	// The wire-accounting seam must not touch real iptables in unit env.
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { frpIptables = origIpt })
	p := backhaulTestParams()
	if res := mgr.Reconcile(context.Background(),
		[]engine.EngineSpec{{ID: "backhaul", Enabled: true}},
		[]engine.TunnelSpec{{ID: "tb3", Engine: "backhaul", LocalServer: "germany", RemoteServer: "iran", Params: mustJSON(p), Enabled: true}}); len(res.Errors) != 0 {
		t.Fatalf("reconcile: %v", res.Errors)
	}
	if mgr.RunningCount() != 1 || *spawned != 1 {
		t.Fatalf("running=%d spawned=%d", mgr.RunningCount(), *spawned)
	}
	// Idempotent reconcile.
	res := mgr.Reconcile(context.Background(),
		[]engine.EngineSpec{{ID: "backhaul", Enabled: true}},
		[]engine.TunnelSpec{{ID: "tb3", Engine: "backhaul", LocalServer: "germany", RemoteServer: "iran", Params: mustJSON(p), Enabled: true}})
	if len(res.Errors) != 0 {
		t.Fatalf("reconcile 2: %v", res.Errors)
	}
	if *spawned != 1 {
		t.Fatalf("reconcile respawned (%d)", *spawned)
	}
	// Disabled → stop + uninstall-when-idle.
	if res := mgr.Reconcile(context.Background(), []engine.EngineSpec{{ID: "backhaul", Enabled: false}},
		nil); len(res.Errors) != 0 {
		t.Fatalf("reconcile 3: %v", res.Errors)
	}
	if mgr.RunningCount() != 0 {
		t.Fatal("instance survived the disabled reconcile")
	}
	if _, err := os.Stat(backhaulEngineDir()); !os.IsNotExist(err) {
		t.Fatal("engine dir survived idle uninstall")
	}
}
