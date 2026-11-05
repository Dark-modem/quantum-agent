package agent

// Hermetic tests for the Matrix engine driver adapter: shape validation
// and registry composition only — the underlying matrix functions keep
// their own tests (matrix_instances_test.go & co. are unchanged).

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

func TestMatrixDriverImplementsEngineDriver(t *testing.T) {
	var d engine.Driver = NewMatrixDriver()
	if d.ID() != "matrix" {
		t.Fatalf("ID = %q", d.ID())
	}
}

func TestMatrixDriverValidate(t *testing.T) {
	d := NewMatrixDriver()
	if err := d.Validate(nil); err == nil {
		t.Fatal("empty params accepted")
	}
	if err := d.Validate(json.RawMessage(`{"instance":"not-matrix!"}`)); err == nil {
		t.Fatal("invalid instance accepted")
	}
	if err := d.Validate(json.RawMessage(`{"instance":"matrix"}`)); err != nil {
		t.Fatalf("legacy instance rejected: %v", err)
	}
	if err := d.Validate(json.RawMessage(`{"instance":"matrix2"}`)); err != nil {
		t.Fatalf("numbered instance rejected: %v", err)
	}
	if err := d.Validate(json.RawMessage(`not json`)); err == nil {
		t.Fatal("non-JSON params accepted")
	}
}

func TestAgentEnginesRegistry(t *testing.T) {
	reg, err := AgentEngines()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Driver("matrix"); !ok {
		t.Fatal("matrix driver not registered")
	}
	if err := reg.Register(NewMatrixDriver()); err == nil {
		t.Fatal("duplicate matrix registration accepted")
	}
}

// TestMatrixDriverHealthMeshWindow covers the Phase-4 rule: an active unit
// with a dead mesh must not report OK. The driver combines the unit state
// with the latest rolling probe window (agent_health.go).
func TestMatrixDriverHealthMeshWindow(t *testing.T) {
	// Decision table (pure).
	if h := agentHealthWithWindow("unit active", agentTunnelHealth{}, false); !h.OK {
		t.Fatalf("no window yet: health = %+v, want OK (unit state alone)", h)
	}
	down := agentTunnelHealth{Quality: "down", LossPct: 100}
	if h := agentHealthWithWindow("unit active", down, true); h.OK {
		t.Fatalf("quality down: health = %+v, want not OK", h)
	}
	dead := agentTunnelHealth{Quality: "poor", LossPct: 100, Reachable: false}
	if h := agentHealthWithWindow("unit active", dead, true); h.OK {
		t.Fatalf("unreachable mesh: health = %+v, want not OK", h)
	}
	if h := agentHealthWithWindow("unit active", dead, true); !strings.Contains(h.Detail, "loss 100%") {
		t.Fatalf("dead-mesh detail must carry quality+loss, got %q", h.Detail)
	}
	good := agentTunnelHealth{Quality: "good", LossPct: 0, Reachable: true, LatencyMs: 12}
	if h := agentHealthWithWindow("unit active", good, true); !h.OK || h.LatencyMs != 12 {
		t.Fatalf("reachable mesh: health = %+v, want OK with latency 12", h)
	}

	// Wiring: a live probe window flips the driver's verdict.
	agentLab(t)
	oldPing, oldLink := agentPingExec, agentIPLinkShow
	t.Cleanup(func() {
		agentPingExec, agentIPLinkShow = oldPing, oldLink
		agentHealthMu.Lock()
		delete(agentHealthLatest, "matrix")
		agentHealthMu.Unlock()
	})
	agentPingExec = func(string, string) (string, error) {
		return "time=10 ms\ntime=11 ms\ntime=12 ms\n0% packet loss\n", nil
	}
	agentIPLinkShow = func(string) (string, error) { return `[{"ifname":"qmx0","operstate":"UP"}]`, nil }

	legacy := matrixLegacyInstance()
	st := matrixState{Enabled: true, Network: matrixNetname, Role: "node", Family: "ipv4", Port: 21010, Addr: "185.226.119.75", Name: "nodeabc", IP: matrixFirstPeer}
	if err := saveMatrixInstance(legacy, st); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(matrixStatePathOf(legacy)) })

	d := NewMatrixDriver()
	inst := engine.Instance{Params: json.RawMessage(`{"instance":"matrix"}`)}
	agentProbeInstance(legacy) // store a healthy window
	h := d.Health(inst)
	if !h.OK || h.LatencyMs != 11 || !strings.Contains(h.Detail, "mesh good") {
		t.Fatalf("healthy mesh: health = %+v", h)
	}

	// The mesh dies: 100% loss in the newest window → not OK.
	agentPingExec = func(string, string) (string, error) {
		return "3 packets transmitted, 0 received, 100% packet loss\n", nil
	}
	agentProbeInstance(legacy)
	h = d.Health(inst)
	if h.OK {
		t.Fatalf("dead mesh behind an active unit must not report OK: %+v", h)
	}
	if !strings.Contains(h.Detail, "mesh unreachable") {
		t.Fatalf("dead-mesh detail = %q", h.Detail)
	}
}
