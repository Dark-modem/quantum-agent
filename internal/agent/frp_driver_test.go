package agent

// Hermetic tests for the FRP engine driver: no network beyond loopback
// (the dashboard fake), no root, no real processes — process spawn,
// iptables and artifact fetch are seams.

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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

var frpTestPins = struct{ amd, arm, sigAmd, sigArm string }{
	strings.Repeat("ab", 32), strings.Repeat("cd", 32), "AAAA", "BBBB",
}

func frpTestParams() frpParams {
	return frpParams{
		ServerSide: "germany", Version: "0.61.1",
		Artifact:  "frp-0.61.1-linux-{arch}.tar.gz",
		SHA256Amd: frpTestPins.amd, SHA256Arm: frpTestPins.arm,
		SigAmd: frpTestPins.sigAmd, SigArm: frpTestPins.sigArm,
		ServerAddr: "198.51.100.9", ServerPort: 7000, Token: "tok123",
		RemotePort: 34001, LocalAddr: "127.0.0.1", LocalPort: 5201,
		DashPort: 17500, AllowMin: 34000, AllowMax: 34010,
	}
}

// frpTestInstances builds the two ends of one tunnel: the compiler sets
// LocalServer to the receiving agent's own server name.
func frpTestInstances(p frpParams) (serverInst, clientInst engine.Instance) {
	return engine.Instance{TunnelID: "t1", LocalServer: "germany", RemoteServer: "iran", Params: mustJSON(p)},
		engine.Instance{TunnelID: "t1", LocalServer: "iran", RemoteServer: "germany", Params: mustJSON(p)}
}

func TestFRPDriverImplementsEngineDriver(t *testing.T) {
	var d engine.Driver = NewFRPDriver()
	if d.ID() != "frp" {
		t.Fatalf("ID = %q", d.ID())
	}
}

func TestFRPValidateParams(t *testing.T) {
	d := NewFRPDriver()
	if err := d.Validate(nil); err == nil {
		t.Fatal("empty params accepted")
	}
	if err := d.Validate(json.RawMessage(`not json`)); err == nil {
		t.Fatal("non-JSON params accepted")
	}
	good, _ := json.Marshal(frpTestParams())
	if err := d.Validate(good); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}

	bad := frpTestParams()
	bad.ServerSide = ""
	if err := d.Validate(mustJSON(bad)); err == nil {
		t.Fatal("params without server_side accepted")
	}
	bad = frpTestParams()
	bad.SHA256Amd = "short"
	if err := d.Validate(mustJSON(bad)); err == nil {
		t.Fatal("bad amd64 sha256 accepted")
	}
	bad = frpTestParams()
	bad.SHA256Arm = "short"
	if err := d.Validate(mustJSON(bad)); err == nil {
		t.Fatal("bad arm64 sha256 accepted")
	}
	bad = frpTestParams()
	bad.Token = `has "quote"`
	if err := d.Validate(mustJSON(bad)); err == nil {
		t.Fatal("token with quote accepted")
	}
	bad = frpTestParams()
	bad.AllowMin = 10
	bad.AllowMax = 5
	if err := d.Validate(mustJSON(bad)); err == nil {
		t.Fatal("inverted port range accepted")
	}
	badC := frpTestParams()
	badC.RemotePort = 0
	if err := d.Validate(mustJSON(badC)); err == nil {
		t.Fatal("params without remote_port accepted")
	}
}

func TestFRPRenderConfig(t *testing.T) {
	p := frpTestParams()
	srvInst, _ := frpTestInstances(p)
	srv := frpRenderConfig(srvInst.TunnelID, "server", p)
	for _, want := range []string{
		`bindPort = 7000`, `auth.token = "tok123"`,
		`webServer.port = 17500`, `allowPorts = [{ start = 34000, end = 34010 }]`,
	} {
		if !strings.Contains(srv, want) {
			t.Fatalf("server config missing %q:\n%s", want, srv)
		}
	}
	cli := frpRenderConfig("t2", "client", p)
	for _, want := range []string{
		`serverAddr = "198.51.100.9"`, `serverPort = 7000`,
		`name = "t2"`, `localPort = 5201`, `remotePort = 34001`,
	} {
		if !strings.Contains(cli, want) {
			t.Fatalf("client config missing %q:\n%s", want, cli)
		}
	}
}

// frpTestArtifact builds a signed frp-like tar.gz artifact.
func frpTestArtifact(t *testing.T) (body []byte, shaHex, sigB64 string, pubB64 string) {
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
	for _, name := range []string{"frps", "frpc"} {
		content := []byte("#!/bin/sh\nfake-" + name + "\n")
		if err := tw.WriteHeader(&tar.Header{Name: "frp_0.61.1/" + name, Mode: 0o755, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
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

func frpSetTestEnv(t *testing.T) (fetchCalls *int, shaHex, sigB64 string) {
	t.Helper()
	body, shaHex, sigB64, pubB64 := frpTestArtifact(t)
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test:7777", BasePath: "bp", Name: "germany"}, true
	}
	fetchCalls = new(int)
	origFetch := frpFetchArtifact
	frpFetchArtifact = func(ctx context.Context, url string) ([]byte, error) {
		*fetchCalls++
		// The R5 manifest endpoint (Phase 5): the client asks for its own
		// arch and gets the pin triple; the bytes ride the /file/ URL.
		switch {
		case strings.Contains(url, "/api/agent/engine-artifacts?engine=frp&goarch="):
			arch := strings.ToLower(runtime.GOARCH)
			entry := fmt.Sprintf(`{"engine":"frp","version":"0.61.1","goos":"linux","goarch":%q,"artifact":%q,"sha256":%q,"signature":%q}`,
				arch, strings.ReplaceAll("frp-0.61.1-linux-{arch}.tar.gz", "{arch}", arch), shaHex, sigB64)
			return []byte(`{"artifacts":[` + entry + `]}`), nil
		case strings.Contains(url, "/api/agent/engine-artifacts/file/"):
			return body, nil
		case strings.Contains(url, "/bp/api/agent/artifact/frp-0.61.1-linux-"):
			return body, nil
		}
		return nil, fmt.Errorf("unexpected artifact url %q", url)
	}
	// the fake artifact must satisfy whatever pins frpTestParams carries
	frpTestPins.amd = shaHex
	frpTestPins.arm = shaHex
	frpTestPins.sigAmd = sigB64
	frpTestPins.sigArm = sigB64
	origCfg := configDir
	configDir = t.TempDir()
	t.Cleanup(func() {
		engineArtifactPubKeyB64 = origKey
		frpLoadIdentity = origIdent
		frpFetchArtifact = origFetch
		configDir = origCfg
	})
	return fetchCalls, shaHex, sigB64
}

func TestFRPEnsureBinary(t *testing.T) {
	fetchCalls, _, _ := frpSetTestEnv(t)
	p := frpTestParams()

	dir, err := frpEnsureBinary(context.Background(), p)
	if err != nil {
		t.Fatalf("EnsureBinary: %v", err)
	}
	if !fileExists(filepath.Join(dir, "frps")) || !fileExists(filepath.Join(dir, "frpc")) {
		t.Fatal("binaries not installed")
	}
	// Phase 5: the manifest flow costs TWO calls on a miss (manifest GET
	// + file GET); the cached fast path costs none.
	if *fetchCalls != 2 {
		t.Fatalf("fetch calls = %d, want 2 (manifest + file)", *fetchCalls)
	}
	// cache hit: same pins → no second fetch (the pinned fast path)
	if _, err := frpEnsureBinary(context.Background(), p); err != nil {
		t.Fatalf("cache hit: %v", err)
	}
	if *fetchCalls != 2 {
		t.Fatalf("cache hit refetched (%d calls)", *fetchCalls)
	}
	// A stale engine_params pin no longer fails: the manifest is the
	// source of truth once it resolves, and it points at the verified
	// cached artifact (fail-closed behavior lives in the tamper tests).
	p2 := p
	p2.SHA256Amd = strings.Repeat("ef", 32)
	if _, err := frpEnsureBinary(context.Background(), p2); err != nil {
		t.Fatalf("manifest-resolved cache hit with a stale pin: %v", err)
	}
	// fail closed without a pinned key
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = ""
	if _, err := frpEnsureBinary(context.Background(), p); err == nil {
		t.Fatal("artifact accepted without pinned key")
	}
	engineArtifactPubKeyB64 = origKey
}

func TestFRPStartStopHealthCounters(t *testing.T) {
	fetchCalls, _, _ := frpSetTestEnv(t)
	p := frpTestParams()

	// fake process seam
	spawned := 0
	killed := 0
	origSpawn := frpSpawn
	frpSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		spawned++
		if !strings.HasSuffix(binPath, "/frps") {
			return nil, fmt.Errorf("unexpected binary %q", binPath)
		}
		return &fakeFRPProcess{onKill: func() { killed++ }}, nil
	}
	t.Cleanup(func() { frpSpawn = origSpawn })

	// iptables seams
	deleted := 0
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-D" {
			deleted++
		}
		return nil, nil
	}
	origSave := acctIptablesSave
	acctIptablesSave = func() ([]byte, error) {
		return []byte(fmt.Sprintf(`-A FRPDRV_ACCT_IN -p tcp -m tcp --dport 34000:34010 -m comment --comment frpdrv-t1 [ 11:2222 ]
-A FRPDRV_ACCT_OUT -p tcp -m tcp --sport 34000:34010 -m comment --comment frpdrv-t1 [ 33:4444 ]`)), nil
	}
	t.Cleanup(func() { acctIptables = origIpt; acctIptablesSave = origSave })

	// dashboard seam
	origDash := frpDashHTTP
	frpDashHTTP = func(ctx context.Context, url, user, pass string) (int, []byte, error) {
		if strings.Contains(url, "/api/serverinfo") {
			return 200, []byte(`{"version":"0.61.1"}`), nil
		}
		if strings.Contains(url, "/api/proxy/tcp") {
			return 200, []byte(`{"proxies":[{"name":"t1","today_traffic_in":1234,"today_traffic_out":5678}]}`), nil
		}
		return 404, nil, nil
	}
	t.Cleanup(func() { frpDashHTTP = origDash })

	d := NewFRPDriver()
	inst, _ := frpTestInstances(p)
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if spawned != 1 || fetchCalls != nil && *fetchCalls != 2 {
		// Phase 5: a cache miss now costs TWO calls (manifest GET + file
		// GET) when the manifest resolves; the pinned fast path costs 0.
		t.Fatalf("spawned=%d fetch=%v", spawned, *fetchCalls)
	}
	cfgPath := frpConfigPath("t1")
	if !fileExists(cfgPath) {
		t.Fatal("config file missing while running")
	}

	h := d.Health(inst)
	if !h.OK || h.LatencyMs < 0 {
		t.Fatalf("health = %+v", h)
	}
	c := d.Counters(inst)
	if !c.WireKnown || c.WireRx != 2222 || c.WireTx != 4444 {
		t.Fatalf("wire counters = %+v", c)
	}
	if !c.PayloadKnown || c.PayloadRx != 1234 || c.PayloadTx != 5678 {
		t.Fatalf("payload counters = %+v", c)
	}

	// idempotent start with same params: no second process
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("idempotent Start: %v", err)
	}
	if spawned != 1 {
		t.Fatalf("spawned = %d, want 1", spawned)
	}
	// changed params → restart
	p2 := p
	p2.DashPort = 17501
	inst2, _ := frpTestInstances(p2)
	if err := d.Start(context.Background(), inst2); err != nil {
		t.Fatalf("restart Start: %v", err)
	}
	if spawned != 2 {
		t.Fatalf("spawned after change = %d, want 2", spawned)
	}
	// reload with equal params → nil; with changed params → ErrRestartRequired
	if err := d.Reload(engine.Instance{TunnelID: "t1", Params: mustJSON(p2)}); err != nil {
		t.Fatalf("reload equal: %v", err)
	}
	if err := d.Reload(engine.Instance{TunnelID: "t1", Params: mustJSON(p)}); err != engine.ErrRestartRequired {
		t.Fatalf("reload changed = %v", err)
	}

	if err := d.Stop(inst); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// one auto-stop from the params-change restart plus the explicit Stop:
	// 2 signals, 4 rule deletions (2 rules per stop)
	if killed != 2 || deleted != 4 {
		t.Fatalf("killed=%d deleted=%d", killed, deleted)
	}
	if fileExists(cfgPath) {
		t.Fatal("config file left behind after Stop")
	}
	if h := d.Health(inst); h.OK {
		t.Fatal("health OK after stop")
	}
}

func TestFRPUninstallRemovesCache(t *testing.T) {
	fetchCalls, _, _ := frpSetTestEnv(t)
	p := frpTestParams()
	origSpawn := frpSpawn
	frpSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		return &fakeFRPProcess{}, nil
	}
	t.Cleanup(func() { frpSpawn = origSpawn })
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { acctIptables = origIpt })

	d := NewFRPDriver()
	inst, _ := frpTestInstances(p)
	inst.TunnelID = "t9"
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("Start: %v", err)
	}
	dir, err := frpEnsureBinary(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Uninstall(context.Background()); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("binary cache survived Uninstall")
	}
	if h := d.Health(inst); h.OK {
		t.Fatal("instance alive after Uninstall")
	}
	_ = fetchCalls
}

func TestFRPManagerReconcile(t *testing.T) {
	fetchCalls, _, _ := frpSetTestEnv(t)
	p := frpTestParams()
	origSpawn := frpSpawn
	frpSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		return &fakeFRPProcess{}, nil
	}
	t.Cleanup(func() { frpSpawn = origSpawn })
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { acctIptables = origIpt })

	reg := engine.NewRegistry()
	if err := reg.Register(NewFRPDriver()); err != nil {
		t.Fatal(err)
	}
	mgr := engine.NewManager(reg)
	res := mgr.Reconcile(context.Background(),
		[]engine.EngineSpec{{ID: "frp", Enabled: true}},
		[]engine.TunnelSpec{{ID: "mt1", Engine: "frp", LocalServer: "germany", RemoteServer: "iran", Params: mustJSON(p), Enabled: true}})
	if len(res.Errors) > 0 {
		t.Fatalf("reconcile errors: %v", res.Errors)
	}
	if mgr.RunningCount() != 1 {
		t.Fatalf("running = %d", mgr.RunningCount())
	}
	res = mgr.Reconcile(context.Background(), nil, nil)
	if mgr.RunningCount() != 0 {
		t.Fatalf("running after disable = %d", mgr.RunningCount())
	}
	found := false
	for _, id := range res.Uninstalled {
		if id == "frp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("frp not uninstalled after last tunnel stopped: %v", res.Uninstalled)
	}
	_ = fetchCalls
}

// fakeFRPProcess runs until signaled, like a real frp process.
type fakeFRPProcess struct {
	onKill func()
	once   sync.Once
	done   chan error
}

func (f *fakeFRPProcess) Pid() int { return 4242 }

func (f *fakeFRPProcess) Signal(sig os.Signal) error {
	if f.onKill != nil {
		f.onKill()
	}
	f.doneInit()
	f.once.Do(func() { close(f.done) })
	return nil
}

func (f *fakeFRPProcess) Done() <-chan error {
	f.doneInit()
	return f.done
}

func (f *fakeFRPProcess) doneInit() {
	if f.done == nil {
		f.done = make(chan error, 1)
	}
}

var _ = httptest.NewServer // keep import if unused paths change
var _ = http.StatusOK

// dyingFRPProcess exits on its own shortly after construction.
type dyingFRPProcess struct{ done chan error }

func newDyingFRPProcess() *dyingFRPProcess {
	d := &dyingFRPProcess{done: make(chan error, 1)}
	go func() {
		time.Sleep(80 * time.Millisecond)
		d.done <- nil
	}()
	return d
}

func (f *dyingFRPProcess) Pid() int                   { return 1 }
func (f *dyingFRPProcess) Signal(sig os.Signal) error { return nil }
func (f *dyingFRPProcess) Done() <-chan error         { return f.done }

func TestFRPSupervisorRespawns(t *testing.T) {
	fetchCalls, _, _ := frpSetTestEnv(t)
	p := frpTestParams()
	origSpawn := frpSpawn
	spawns := 0
	frpSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		spawns++
		return newDyingFRPProcess(), nil
	}
	t.Cleanup(func() { frpSpawn = origSpawn })
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { acctIptables = origIpt })

	d := NewFRPDriver()
	inst, _ := frpTestInstances(p)
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for spawns < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if spawns < 2 {
		t.Fatalf("supervisor did not respawn (spawns=%d)", spawns)
	}
	if err := d.Stop(inst); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	afterStop := spawns
	time.Sleep(300 * time.Millisecond)
	if spawns != afterStop {
		t.Fatalf("supervisor respawned after Stop (%d -> %d)", afterStop, spawns)
	}
	_ = fetchCalls
}

// TestFRPRoleResolutionBothEnds: the SAME tunnel description resolved by
// the two ends' enrollment names must give server on the frps end and
// client on the frpc end.
func TestFRPRoleResolutionBothEnds(t *testing.T) {
	p := frpTestParams() // ServerSide: "germany"
	origIdent := frpLoadIdentity
	t.Cleanup(func() { frpLoadIdentity = origIdent })

	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Name: "germany"}, true
	}
	if role, err := frpResolveRole(p, ""); err != nil || role != "server" {
		t.Fatalf("germany end: role=%q err=%v, want server", role, err)
	}

	// same description, other end
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Name: "iran"}, true
	}
	if role, err := frpResolveRole(p, ""); err != nil || role != "client" {
		t.Fatalf("iran end: role=%q err=%v, want client", role, err)
	}

	// an unrelated enrollment name still serves the frpc end (only the
	// server_side host runs frps)
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Name: "third-node"}, true
	}
	if role, err := frpResolveRole(p, ""); err != nil || role != "client" {
		t.Fatalf("third-node end: role=%q err=%v, want client", role, err)
	}

	// no identity: fail closed
	frpLoadIdentity = func() (agentIdentity, bool) { return agentIdentity{}, false }
	if _, err := frpResolveRole(p, ""); err == nil {
		t.Fatal("missing identity accepted")
	}
}

func TestFRPForwardAddress(t *testing.T) {
	fetchCalls, _, _ := frpSetTestEnv(t)
	p := frpTestParams()
	origSpawn := frpSpawn
	frpSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		return &fakeFRPProcess{}, nil
	}
	t.Cleanup(func() { frpSpawn = origSpawn })
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { acctIptables = origIpt })

	d := NewFRPDriver()
	srvInst, _ := frpTestInstances(p)
	if err := d.Start(context.Background(), srvInst); err != nil {
		t.Fatal(err)
	}
	host, port, ok := d.ForwardAddress(srvInst)
	if !ok || host != "127.0.0.1" || port != 34001 {
		t.Fatalf("server end ForwardAddress = %s:%d ok=%v", host, port, ok)
	}
	if err := d.Stop(srvInst); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := d.ForwardAddress(srvInst); ok {
		t.Fatal("ForwardAddress ok after Stop")
	}
	_ = fetchCalls
}

// TestFRPRoleResolutionSelfName (R6, phase 17): the panel-stamped
// Self.Name is authoritative — it resolves the role even when the
// enrollment name differs from the mesh server name, and an empty
// SelfName (pre-R6 panel) keeps the enrollment-name behavior.
func TestFRPRoleResolutionSelfName(t *testing.T) {
	p := frpTestParams() // ServerSide: "germany"
	origIdent := frpLoadIdentity
	t.Cleanup(func() { frpLoadIdentity = origIdent })

	// R6: the enrollment name ("legacy-node") does NOT match the mesh
	// server name, yet the panel-stamped Self.Name resolves the frps end.
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Name: "legacy-node"}, true
	}
	if role, err := frpResolveRole(p, "germany"); err != nil || role != "server" {
		t.Fatalf("self germany: role=%q err=%v, want server", role, err)
	}
	if role, err := frpResolveRole(p, "iran-server"); err != nil || role != "client" {
		t.Fatalf("self iran-server: role=%q err=%v, want client", role, err)
	}
	// blank Self.Name falls back to the enrollment identity (pre-R6)
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Name: "germany"}, true
	}
	if role, err := frpResolveRole(p, "  "); err != nil || role != "server" {
		t.Fatalf("blank self fallback: role=%q err=%v, want server", role, err)
	}
	// no identity AND no SelfName: fail closed
	frpLoadIdentity = func() (agentIdentity, bool) { return agentIdentity{}, false }
	if _, err := frpResolveRole(p, ""); err == nil {
		t.Fatal("missing identity and missing SelfName accepted")
	}
}
