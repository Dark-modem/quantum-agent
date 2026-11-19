package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	protocol "github.com/Dark-modem/quantum-protocol"
)

// BalHarness is the test fixture for the balancer: a fake engine, a Manager,
// a ForwardBalancer, and scripted host calls. It is duplicated from the
// agent's v2_test.go because the two live in different packages (§6.A4:
// internal/balancer never imports internal/agent).
type BalHarness struct {
	fake *engine.FakeEngine
	bal  *ForwardBalancer
	mgr  *engine.Manager
	reg  *engine.Registry

	mu       sync.Mutex
	scripts  []string
	failNft  int
	now      time.Time
	healthOK map[string]bool
}

func newBalHarness(t *testing.T) *BalHarness {
	t.Helper()
	fake := engine.NewFakeEngine("fake")
	h := &BalHarness{reg: engine.NewRegistry()}
	if err := h.reg.Register(fake); err != nil {
		t.Fatal(err)
	}
	h.fake = fake
	mgr := engine.NewManager(h.reg)
	h.mgr = mgr
	h.now = time.Unix(1796470000, 0)
	h.healthOK = map[string]bool{"t1": true, "t2": true}
	h.bal = New(mgr, h.reg)
	h.bal.NowFn = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.now }
	realApply := ApplyNFTScript
	ApplyNFTScript = func(script string) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.failNft > 0 {
			h.failNft--
			return errors.New("nft failed (scripted)")
		}
		h.scripts = append(h.scripts, script)
		return nil
	}
	t.Cleanup(func() { ApplyNFTScript = realApply; h.bal.Stop() })
	return h
}

// testCtx is context.Background (the balancer tests are synchronous).
func testCtx() context.Context { return context.Background() }

func (h *BalHarness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func (h *BalHarness) scriptCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.scripts)
}

func (h *BalHarness) lastScript() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.scripts) == 0 {
		return ""
	}
	return h.scripts[len(h.scripts)-1]
}

func regWith(t *testing.T, d engine.Driver) *engine.Registry {
	t.Helper()
	r := engine.NewRegistry()
	if err := r.Register(d); err != nil {
		t.Fatal(err)
	}
	return r
}

func toEngineSpecs(engines []protocol.EngineSpec, tunnels []protocol.TunnelSpec) ([]engine.EngineSpec, []engine.TunnelSpec) {
	engs := make([]engine.EngineSpec, 0, len(engines))
	for _, e := range engines {
		engs = append(engs, engine.EngineSpec{ID: e.ID, Enabled: e.Enabled})
	}
	tuns := make([]engine.TunnelSpec, 0, len(tunnels))
	for _, t := range tunnels {
		tuns = append(tuns, engine.TunnelSpec{
			ID: t.ID, TopologyID: t.TopologyID, LocalServer: t.LocalServer,
			RemoteServer: t.RemoteServer, Engine: t.Engine, Params: t.EngineParams, Enabled: t.Enabled,
		})
	}
	return engs, tuns
}

func testDesiredV2() protocol.DesiredV2 {
	return protocol.DesiredV2{
		Revision: "1796470000000000100",
		Engines: []protocol.EngineSpec{
			{ID: "matrix", Enabled: true},
			{ID: "fake", Enabled: true},
		},
		Tunnels: []protocol.TunnelSpec{
			{ID: "t1", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Engine: "fake", Enabled: true},
			{ID: "t2", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Engine: "ghost", Enabled: true},
		},
	}
}

func testForwardDesired(t *testing.T) protocol.DesiredV2 {
	t.Helper()
	d := testDesiredV2()
	d.Tunnels = []protocol.TunnelSpec{
		{ID: "t1", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Engine: "fake", Enabled: true},
		{ID: "t2", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2", Engine: "fake", Enabled: true},
	}
	d.Balancing = &protocol.BalancingPolicy{
		Weights: []protocol.WeightRule{
			{TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Weight: 70},
			{TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2", Weight: 30},
		},
		HealthCheck: protocol.HealthCheckParams{IntervalS: 1, TimeoutMS: 200, Probe: "engine", ConsecutiveDown: 2, ConsecutiveUp: 1},
		Failover:    protocol.FailoverRules{PreferOrder: []string{"hz-fra-1", "hz-fra-2"}, SwitchBackS: 0},
	}
	d.TargetGroups = []protocol.TargetGroup{{ID: "grp-pool", TopologyID: "topo-drak-hetzner"}}
	d.Forwards = []protocol.ForwardRule{{ID: "fw-web", ListenPort: 8443, Proto: "both", TargetGroup: "grp-pool", TargetPort: 8443}}
	return d
}
