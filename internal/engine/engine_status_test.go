package engine

// engine_status_test.go — Phase 11: install-on-enable semantics, the
// per-engine last-error capture, and ProcessPIDs discovery.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// mustJSONRaw is engine_test's mustJSON; reuse it via the same name.

func TestManagerInstallOnEnableStaysInstalledWhileIdle(t *testing.T) {
	reg := NewRegistry()
	fake := NewFakeEngine("fake")
	if err := reg.Register(fake); err != nil {
		t.Fatal(err)
	}
	m := NewManager(reg)
	ctx := context.Background()

	// Enable with NO tunnels: EnsureBinary must run now (install on
	// first enable), the engine reports installed + desired.
	res := m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: true}}, nil)
	ensureCalls, _, _, _, _ := fake.Calls()
	if len(res.Errors) != 0 || ensureCalls != 1 {
		t.Fatalf("enable reconcile: %+v ensure=%d", res, ensureCalls)
	}
	if !m.EngineInstalled("fake") || !m.EngineDesired("fake") {
		t.Fatalf("installed=%v desired=%v (want true/true)", m.EngineInstalled("fake"), m.EngineDesired("fake"))
	}
	sts := m.EnginesStatus()
	if len(sts) != 1 || !sts[0].Installed || sts[0].Instances != 0 || sts[0].LastError != "" {
		t.Fatalf("engines status: %+v", sts)
	}

	// Enable failure (binary download breaks) is captured per engine.
	reg2 := NewRegistry()
	bad := NewFakeEngine("bad")
	bad.SetEnsureError(errors.New("artifact missing for arch arm64"))
	if err := reg2.Register(bad); err != nil {
		t.Fatal(err)
	}
	m2 := NewManager(reg2)
	res = m2.Reconcile(ctx, []EngineSpec{{ID: "bad", Enabled: true}}, nil)
	if len(res.Errors) != 0 { // engine-level install failure is NOT a tunnel error
		t.Fatalf("enable failure must not surface as tunnel errors: %+v", res.Errors)
	}
	if m2.EngineInstalled("bad") {
		t.Fatal("failed install must not mark installed")
	}
	sts = m2.EnginesStatus()
	if len(sts) != 1 || sts[0].Installed || sts[0].LastError == "" {
		t.Fatalf("status after failed install: %+v", sts)
	}
}

func TestManagerProcessPIDsAndStartErrorCapture(t *testing.T) {
	reg := NewRegistry()
	fake := NewFakeEngine("fake")
	if err := reg.Register(fake); err != nil {
		t.Fatal(err)
	}
	// The fake has no processes; the manager must return no entry.
	m := NewManager(reg)
	ctx := context.Background()
	_ = m.Reconcile(ctx, []EngineSpec{{ID: "fake", Enabled: true}},
		[]TunnelSpec{{ID: "t1", Engine: "fake", Enabled: true, Params: mustJSON(t, map[string]string{})}})
	if pids := m.ProcessPIDs(); len(pids) != 0 {
		t.Fatalf("fake engine must have no PIDs: %+v", pids)
	}

	// A start failure lands in the engine's LastError...
	failing := NewFakeEngine("flaky")
	failing.SetStartError("t1", errors.New("bind: address already in use"))
	reg3 := NewRegistry()
	if err := reg3.Register(failing); err != nil {
		t.Fatal(err)
	}
	m3 := NewManager(reg3)
	res := m3.Reconcile(ctx, []EngineSpec{{ID: "flaky", Enabled: true}},
		[]TunnelSpec{{ID: "t1", Engine: "flaky", Enabled: true, Params: mustJSON(t, map[string]string{})}})
	if len(res.Errors) != 1 {
		t.Fatalf("start failure must surface: %+v", res)
	}
	sts := m3.EnginesStatus()
	if len(sts) != 1 || sts[0].LastError == "" || !sts[0].Installed || sts[0].Healthy+sts[0].Down != 0 {
		t.Fatalf("status after failed start: %+v", sts)
	}

	// ...and is cleared by the next successful start.
	failing.SetStartError("t1", nil)
	if res := m3.Reconcile(ctx, []EngineSpec{{ID: "flaky", Enabled: true}},
		[]TunnelSpec{{ID: "t1", Engine: "flaky", Enabled: true,
			Params: mustJSON(t, map[string]string{})}}); len(res.Started) != 1 {
		t.Fatalf("retry start: %+v", res)
	}
	sts = m3.EnginesStatus()
	if sts[0].LastError != "" || sts[0].Instances != 1 {
		t.Fatalf("status after successful start: %+v", sts)
	}
}

// SetEnsureError / SetStartError shims (FakeEngine gained these fields
// for Phase 11; kept next to the test that needs them).
func mustJSON2(t *testing.T, v any) json.RawMessage { return mustJSON(t, v) }
