package engine_test

// AGENT-24 layer 2 (defense-in-depth): the reconcile/preflight no-op
// decisions must compare CANONICALIZED engine_params (JSON whitespace
// normalized), not raw bytes. A legacy agent's journal (pre-AGENT-24
// MarshalIndent state files) replays INDENTED params against instances
// running the compact wire bytes; those are the SAME params and must not
// produce a phantom "params changed" reload/restart. The restart path
// itself is untouched — only the comparison input changes.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-agent/internal/engine/faketest"
)

func TestParamsEqualCanonicalizesJSON(t *testing.T) {
	compact := json.RawMessage(`{"lab_addr":"10.200.0.21","lab_port":8443}`)
	indented := json.RawMessage("{\n  \"lab_addr\": \"10.200.0.21\",\n  \"lab_port\": 8443\n}")
	if !engine.ParamsEqual(compact, indented) {
		t.Fatalf("same params in different whitespace must compare equal")
	}
	if !engine.ParamsEqual(indented, compact) {
		t.Fatalf("ParamsEqual must be symmetric")
	}
	if engine.ParamsEqual(compact, json.RawMessage(`{"lab_addr":"10.200.0.21","lab_port":8445}`)) {
		t.Fatalf("genuinely different params must not compare equal")
	}
	// Invalid JSON on either side falls back to trimmed bytes.
	if !engine.ParamsEqual(json.RawMessage("not json"), json.RawMessage("not json")) {
		t.Fatalf("byte-identical invalid params must compare equal via the fallback")
	}
	if engine.ParamsEqual(json.RawMessage("not json"), json.RawMessage("other junk")) {
		t.Fatalf("differing invalid params must not compare equal")
	}
	// Empty vs empty-object: the fallback compares trimmed bytes ("" vs
	// "{}" differ) — the pre-AGENT-24 behavior, preserved on purpose.
	if engine.ParamsEqual(nil, json.RawMessage(`{}`)) {
		t.Fatalf("nil params vs {} must keep the legacy byte semantics")
	}
}

func TestManagerReconcileNoRestartOnCanonicalEqualParams(t *testing.T) {
	reg := engine.NewRegistry()
	fake := faketest.NewFakeEngine("fake")
	if err := reg.Register(fake); err != nil {
		t.Fatal(err)
	}
	m := engine.NewManager(reg)
	ctx := context.Background()
	spec := []engine.EngineSpec{{ID: "fake", Enabled: true}}

	compact := json.RawMessage(`{"lab_addr":"10.200.0.21","lab_port":8443}`)
	res := m.Reconcile(ctx, spec, []engine.TunnelSpec{
		{ID: "t1", Engine: "fake", Params: compact, Enabled: true}})
	if len(res.Started) != 1 {
		t.Fatalf("start res = %+v", res)
	}

	// A legacy agent's journal replays the SAME params INDENTED (the
	// pre-AGENT-24 state files re-indented nested RawMessage). This is a
	// no-op — no reload, no restart, no stop; the running instance keeps
	// its engine state (counters included).
	indented := json.RawMessage("{\n  \"lab_addr\": \"10.200.0.21\",\n  \"lab_port\": 8443\n}")
	res = m.Reconcile(ctx, spec, []engine.TunnelSpec{
		{ID: "t1", Engine: "fake", Params: indented, Enabled: true}})
	if len(res.Started) != 0 || len(res.Stopped) != 0 || len(res.Restarted) != 0 || len(res.Reloaded) != 0 {
		t.Fatalf("canonical-equal replay must be a no-op, got %+v", res)
	}
	_, _, started, stopped, reloaded := fake.Calls()
	if len(started) != 1 || len(stopped) != 0 || len(reloaded) != 0 {
		t.Fatalf("driver calls after canonical-equal replay: started=%v stopped=%v reloaded=%v",
			started, stopped, reloaded)
	}

	// Genuinely different params still change the instance (here a live
	// reload — the restart path itself is untouched by AGENT-24).
	res = m.Reconcile(ctx, spec, []engine.TunnelSpec{
		{ID: "t1", Engine: "fake", Params: json.RawMessage(`{"lab_addr":"10.200.0.21","lab_port":8445}`), Enabled: true}})
	if len(res.Reloaded) != 1 {
		t.Fatalf("real param change must still reload, got %+v", res)
	}
}
