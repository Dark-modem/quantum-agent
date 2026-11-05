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
		if !strings.Contains(url, "/bp/api/agent/artifact/frp-0.61.1-linux-") {
			return nil, fmt.Errorf("unexpected artifact url %q", url)
		}
		return body, nil
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
	if *fetchCalls != 1 {
		t.Fatalf("fetch calls = %d, want 1", *fetchCalls)
	}
	// cache hit: same pins → no second fetch
	if _, err := frpEnsureBinary(context.Background(), p); err != nil {
		t.Fatalf("cache hit: %v", err)
	}
	if *fetchCalls != 1 {
		t.Fatalf("cache hit refetched (%d calls)", *fetchCalls)
	}
	// different pins (different artifact) → verification fails
	p2 := p
	p2.SHA256Amd = strings.Repeat("ef", 32)
	if _, err := frpEnsureBinary(context.Background(), p2); err == nil {
		t.Fatal("wrong-sha artifact accepted")
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
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-D" {
			deleted++
		}
		return nil, nil
	}
	origSave := frpIptablesSave
	frpIptablesSave = func() ([]byte, error) {
		return []byte(fmt.Sprintf(`-A FRPDRV_ACCT_IN -p tcp -m tcp --dport 34000:34010 -m comment --comment frpdrv-t1 [ 11:2222 ]
-A FRPDRV_ACCT_OUT -p tcp -m tcp --sport 34000:34010 -m comment --comment frpdrv-t1 [ 33:4444 ]`)), nil
	}
	t.Cleanup(func() { frpIptables = origIpt; frpIptablesSave = origSave })

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
	if spawned != 1 || fetchCalls != nil && *fetchCalls != 1 {
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
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { frpIptables = origIpt })

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
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { frpIptables = origIpt })

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
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { frpIptables = origIpt })

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
