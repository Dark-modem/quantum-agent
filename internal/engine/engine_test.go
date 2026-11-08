package engine

// Hermetic tests: only the FakeEngine runs here; nothing touches the
// host, the network or the filesystem.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRegistryRejectsNilEmptyAndDuplicates(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(nil); err == nil {
		t.Fatal("nil driver accepted")
	}
	if err := reg.Register(NewFakeEngine("")); err == nil {
		t.Fatal("empty-ID driver accepted")
	}
	if err := reg.Register(NewFakeEngine("fake")); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := reg.Register(NewFakeEngine("fake")); err == nil {
		t.Fatal("duplicate ID accepted — injection vector")
	}
	if _, ok := reg.Driver("nope"); ok {
		t.Fatal("unknown engine found")
	}
	if ids := reg.IDs(); len(ids) != 1 || ids[0] != "fake" {
		t.Fatalf("IDs = %v", ids)
	}
}

func TestManagerStartsEnabledAndStopsRemoved(t *testing.T) {
	reg := NewRegistry()
	fake := NewFakeEngine("fake")
	if err := reg.Register(fake); err != nil {
		t.Fatal(err)
	}
	m := NewManager(reg)
	ctx := context.Background()

	res := m.Reconcile(ctx,
		[]EngineSpec{{ID: "fake", Enabled: true}},
		[]TunnelSpec{
			{ID: "t1", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Engine: "fake", Params: mustJSON(t, map[string]string{"k": "v"}), Enabled: true},
			{ID: "t2", Engine: "fake", Enabled: false},
		})
	if len(res.Started) != 1 || res.Started[0] != "t1" {
		t.Fatalf("started = %v (t2 is disabled and must not start)", res.Started)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	if running := fake.Running(); len(running) != 1 || running[0] != "t1" {
		t.Fatalf("fake running = %v", running)
	}

	// Idempotent: same desired state again changes nothing.
	res = m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: true}},
		[]TunnelSpec{{ID: "t1", Engine: "fake", Params: mustJSON(t, map[string]string{"k": "v"}), Enabled: true}})
	if len(res.Started)+len(res.Stopped)+len(res.Reloaded)+len(res.Restarted) != 0 {
		t.Fatalf("second reconcile did work: %+v", res)
	}

	// Tunnel removed -> stopped. Phase 11: the engine is still
	// DESIRED-ENABLED, so it STAYS installed (install on first enable;
	// the binary is ready for the next tunnel).
	res = m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: true}}, nil)
	if len(res.Stopped) != 1 || res.Stopped[0] != "t1" {
		t.Fatalf("stopped = %v", res.Stopped)
	}
	_, uninstall, _, _, _ := fake.Calls()
	if uninstall != 0 {
		t.Fatalf("uninstall=%d — a desired-enabled engine must stay installed when idle", uninstall)
	}
	if !m.EngineInstalled("fake") {
		t.Fatal("desired-enabled idle engine must report installed")
	}
	if m.RunningCount() != 0 {
		t.Fatalf("running count = %d", m.RunningCount())
	}

	// Disabling the engine (or dropping it from desired) uninstalls the
	// now-idle engine.
	res = m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: false}}, nil)
	if len(res.Uninstalled) != 1 || res.Uninstalled[0] != "fake" {
		t.Fatalf("uninstalled = %v — a disabled idle engine must uninstall", res.Uninstalled)
	}
	if m.EngineInstalled("fake") {
		t.Fatal("disabled engine must not report installed")
	}
}

func TestManagerDisableEngineStopsItsTunnels(t *testing.T) {
	reg := NewRegistry()
	fake := NewFakeEngine("fake")
	_ = reg.Register(fake)
	m := NewManager(reg)
	ctx := context.Background()

	spec := []TunnelSpec{{ID: "t1", Engine: "fake", Enabled: true}}
	m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: true}}, spec)
	if m.RunningCount() != 1 {
		t.Fatal("tunnel not started")
	}
	// Engine disabled while the tunnel spec is still enabled: must stop.
	res := m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: false}}, spec)
	if len(res.Stopped) != 1 || len(res.Errors) != 0 {
		t.Fatalf("res = %+v", res)
	}
	if m.RunningCount() != 0 {
		t.Fatal("tunnel still running after engine disabled")
	}
}

func TestManagerUnknownEngineSurfacesAsError(t *testing.T) {
	reg := NewRegistry()
	m := NewManager(reg)
	res := m.Reconcile(context.Background(),
		[]EngineSpec{{ID: "ghost", Enabled: true}},
		[]TunnelSpec{{ID: "t1", Engine: "ghost", Enabled: true}})
	if len(res.Started) != 0 || m.RunningCount() != 0 {
		t.Fatal("unknown engine must not start anything")
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "unknown engine") ||
		!strings.Contains(res.Errors[0], "t1") {
		t.Fatalf("errors = %v", res.Errors)
	}
}

func TestManagerReloadAndRestartOnParamChange(t *testing.T) {
	reg := NewRegistry()
	fake := NewFakeEngine("fake")
	_ = reg.Register(fake)
	m := NewManager(reg)
	ctx := context.Background()

	p1 := mustJSON(t, map[string]string{"port": "1"})
	p2 := mustJSON(t, map[string]string{"port": "2"})
	spec := func(p json.RawMessage) []TunnelSpec {
		return []TunnelSpec{{ID: "t1", Engine: "fake", Params: p, Enabled: true}}
	}
	m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: true}}, spec(p1))

	// Live reload when the driver can apply it.
	res := m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: true}}, spec(p2))
	if len(res.Reloaded) != 1 || len(res.Restarted) != 0 {
		t.Fatalf("reload res = %+v", res)
	}

	// Driver refuses live reload -> manager restarts (stop+start).
	fake.FailReload("t1", ErrRestartRequired)
	p3 := mustJSON(t, map[string]string{"port": "3"})
	res = m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: true}}, spec(p3))
	if len(res.Restarted) != 1 || res.Restarted[0] != "t1" {
		t.Fatalf("restart res = %+v", res)
	}
	_, _, started, stopped, _ := fake.Calls()
	if len(started) != 2 || len(stopped) != 1 {
		t.Fatalf("calls after restart: started=%v stopped=%v", started, stopped)
	}

	// Reload failure that is NOT ErrRestartRequired surfaces as an error
	// and leaves the instance running with the OLD params.
	fake.FailReload("t1", errors.New("boom"))
	p4 := mustJSON(t, map[string]string{"port": "4"})
	res = m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: true}}, spec(p4))
	if len(res.Errors) != 1 || m.RunningCount() != 1 {
		t.Fatalf("res = %+v running=%d", res, m.RunningCount())
	}
	// The failed reload must leave the instance running with the OLD
	// params (the manager surfaced the error and changed nothing).
	st := m.Status()
	if len(st) != 1 || !st[0].Running || st[0].Engine != "fake" {
		t.Fatalf("status after failed reload = %+v", st)
	}
}

func TestManagerEngineSwapRestartsOnNewDriver(t *testing.T) {
	reg := NewRegistry()
	a := NewFakeEngine("engine-a")
	b := NewFakeEngine("engine-b")
	_ = reg.Register(a)
	_ = reg.Register(b)
	m := NewManager(reg)
	ctx := context.Background()

	m.Reconcile(ctx, []EngineSpec{{ID: "engine-a", Enabled: true}},
		[]TunnelSpec{{ID: "t1", Engine: "engine-a", Enabled: true}})
	res := m.Reconcile(ctx,
		[]EngineSpec{{ID: "engine-a", Enabled: false}, {ID: "engine-b", Enabled: true}},
		[]TunnelSpec{{ID: "t1", Engine: "engine-b", Enabled: true}})
	if len(res.Stopped) != 1 || len(res.Started) != 1 || len(res.Uninstalled) != 1 || res.Uninstalled[0] != "engine-a" {
		t.Fatalf("swap res = %+v", res)
	}
	if running := b.Running(); len(running) != 1 || running[0] != "t1" {
		t.Fatalf("engine-b running = %v", running)
	}
}

func TestManagerStartFailureKeepsStateClean(t *testing.T) {
	reg := NewRegistry()
	fake := NewFakeEngine("fake")
	_ = reg.Register(fake)
	fake.FailStart("t1", errors.New("port taken"))
	m := NewManager(reg)

	res := m.Reconcile(context.Background(),
		[]EngineSpec{{ID: "fake", Enabled: true}},
		[]TunnelSpec{{ID: "t1", Engine: "fake", Enabled: true}})
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "port taken") {
		t.Fatalf("res = %+v", res)
	}
	if m.RunningCount() != 0 {
		t.Fatal("failed start left a running slot")
	}
	// A later reconcile may retry and succeed.
	fake.FailStart("t1", nil)
	res = m.Reconcile(context.Background(),
		[]EngineSpec{{ID: "fake", Enabled: true}},
		[]TunnelSpec{{ID: "t1", Engine: "fake", Enabled: true}})
	if len(res.Started) != 1 {
		t.Fatalf("retry res = %+v", res)
	}
}

func TestManagerStopFailureRetriesNextReconcile(t *testing.T) {
	reg := NewRegistry()
	fake := NewFakeEngine("fake")
	_ = reg.Register(fake)
	m := NewManager(reg)
	ctx := context.Background()
	spec := []TunnelSpec{{ID: "t1", Engine: "fake", Enabled: true}}
	m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: true}}, spec)

	fake.FailStop("t1", errors.New("unit stuck"))
	res := m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: true}}, nil)
	if len(res.Errors) != 1 || m.RunningCount() != 1 {
		t.Fatalf("res = %+v", res)
	}
	// The failed stop must not uninstall the engine (it is still in use).
	_, uninstall, _, _, _ := fake.Calls()
	if uninstall != 0 {
		t.Fatal("uninstalled an engine whose stop failed")
	}
	fake.FailStop("t1", nil) // the transient stop failure clears
	res = m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: true}}, nil)
	if len(res.Stopped) != 1 || len(res.Errors) != 0 {
		t.Fatalf("retry res = %+v", res)
	}
}

func TestManagerStatusCarriesHealthAndCounters(t *testing.T) {
	reg := NewRegistry()
	fake := NewFakeEngine("matrix-fake")
	_ = reg.Register(fake)
	m := NewManager(reg)
	fake.SetCounters("t1", Counters{WireRx: 105, WireTx: 21, WireKnown: true, PayloadRx: 100, PayloadTx: 20, PayloadKnown: true})
	fake.SetHealth("t1", Health{OK: true, LatencyMs: 12.5})

	m.Reconcile(context.Background(),
		[]EngineSpec{{ID: "matrix-fake", Enabled: true}},
		[]TunnelSpec{{ID: "t1", Engine: "matrix-fake", Enabled: true}})
	st := m.Status()
	if len(st) != 1 {
		t.Fatalf("status = %+v", st)
	}
	if !st[0].Health.OK || st[0].Counters.WireRx != 105 || !st[0].Counters.PayloadKnown {
		t.Fatalf("status[0] = %+v", st[0])
	}
}

func TestVerifyArtifact(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	artifact := []byte("engine binary bytes")
	sum := sha256.Sum256(artifact)
	sumHex := hex.EncodeToString(sum[:])
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, artifact))

	if err := VerifyArtifact(artifact, sumHex, sig, pemKey); err != nil {
		t.Fatalf("valid artifact rejected: %v", err)
	}
	if err := VerifyArtifact([]byte("tampered"), sumHex, sig, pemKey); err == nil ||
		!strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("tampered: %v", err)
	}
	if err := VerifyArtifact(artifact, sumHex, sig, ""); err == nil ||
		!strings.Contains(err.Error(), "no engine artifact signing key pinned") {
		t.Fatalf("no key must fail closed: %v", err)
	}
	wrong := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte("other")))
	if err := VerifyArtifact(artifact, sumHex, wrong, pemKey); err == nil ||
		!strings.Contains(err.Error(), "FAILED") {
		t.Fatalf("wrong signature: %v", err)
	}
	// Base64-DER key form (ldflags -X cannot carry newlines).
	if err := VerifyArtifact(artifact, sumHex, sig, base64.StdEncoding.EncodeToString(der)); err != nil {
		t.Fatalf("base64-DER key rejected: %v", err)
	}
}

func TestFakeEngineValidateScripting(t *testing.T) {
	f := NewFakeEngine("fake")
	if err := f.Validate(mustJSON(t, map[string]string{"a": "1"})); err != nil {
		t.Fatal(err)
	}
	f.FailValidate("bad", errors.New("invalid params"))
	if err := f.Validate(mustJSON(t, map[string]string{"x": "BAD thing"})); err == nil {
		t.Fatal("scripted validation error not raised")
	}
	if err := f.Validate(mustJSON(t, map[string]string{"x": "ok"})); err != nil {
		t.Fatalf("unrelated params must validate: %v", err)
	}
}
