package agent

// Phase 2A tests: v2 session adoption (negotiation, desired application,
// boot replay) and the local forward balancer's failure semantics. All
// hermetic — the nft apply and the clock are seams.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-protocol"
)

func testCtx() context.Context { return context.Background() }

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

// ---- negotiation ----

func TestAgentNegotiateOrV1(t *testing.T) {
	if got := agentNegotiateOrV1(0); got != 1 {
		t.Fatalf("v1 controller (absent version) -> %d, want 1", got)
	}
	if got := agentNegotiateOrV1(1); got != 1 {
		t.Fatalf("v1 -> %d", got)
	}
	if got := agentNegotiateOrV1(2); got != 2 {
		t.Fatalf("v2 -> %d", got)
	}
	if got := agentNegotiateOrV1(99); got != 2 {
		t.Fatalf("future controller clamps down -> %d, want 2", got)
	}
}

func TestEngineCatalogIncludesMatrix(t *testing.T) {
	cat := agentEngineCatalog()
	found := false
	for _, id := range cat {
		if id == "matrix" {
			found = true
		}
	}
	if !found {
		t.Fatalf("catalog %v lacks matrix", cat)
	}
}

func TestAgentCapsIncludeHardening(t *testing.T) {
	found := false
	for _, c := range agentCaps() {
		if c == agentCapHardening {
			found = true
		}
	}
	if !found {
		t.Fatal("CapHardening missing from hello caps")
	}
}

// ---- desired v2 application through the manager ----

func TestApplyDesiredV2StartsTunnelsAndAcks(t *testing.T) {
	withTempConfig(t)
	registerV2TestDriver(t)
	d := testDesiredV2()
	ack := agentApplyDesiredV2(&d)
	if !ack.OK || ack.Kind != "desired-v2" || ack.Revision != d.Revision {
		t.Fatalf("ack = %+v", ack)
	}
	mgr, _, err := agentV2RuntimeRef()
	if err != nil {
		t.Fatal(err)
	}
	if mgr.RunningCount() != 1 {
		t.Fatalf("running = %d, want 1 (t1 enabled; the unknown-engine tunnel must not start)", mgr.RunningCount())
	}
}

func TestApplyDesiredV2RevisionFencing(t *testing.T) {
	withTempConfig(t)
	registerV2TestDriver(t)
	d := testDesiredV2()
	if ack := agentApplyDesiredV2(&d); !ack.OK {
		t.Fatalf("first apply: %+v", ack)
	}
	// A stale revision (older than applied) is refused.
	old := d
	old.Revision = "1"
	if ack := agentApplyDesiredV2(&old); ack.OK {
		t.Fatal("stale revision accepted")
	}
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

// resetV2Runtime tears the package-level v2 runtime down between tests.
func resetV2Runtime() {
	agentV2.mu.Lock()
	if agentV2.balancer != nil {
		agentV2.balancer.Stop()
	}
	agentV2.manager = nil
	agentV2.balancer = nil
	agentV2AppliedRevision = ""
	agentV2.mu.Unlock()
	agentV2TestDriver = nil
	// The builtin registry is built once per process; tests that swap
	// the test driver in must be able to rebuild it.
	matrixDriverRegOnce = sync.Once{}
}

func registerV2TestDriver(t *testing.T) *engine.FakeEngine {
	agentV2.mu.Lock()
	agentV2AppliedRevision = ""
	agentV2.mu.Unlock()
	t.Helper()
	fake := engine.NewFakeEngine("fake")
	agentV2TestDriver = fake
	// Force the next AgentEngines() to rebuild with the test driver even
	// if an earlier test already consumed the sync.Once.
	matrixDriverRegOnce = sync.Once{}
	t.Cleanup(resetV2Runtime)
	return fake
}

// ---- hardening dispatch (STEP 5) ----

func TestHardeningOpRouting(t *testing.T) {
	// detect is read-only and hermetic: the dispatcher answers with a
	// structured Result in Data.
	res := agentRunCommand(agentCommand{ID: "c1", Op: agentCmdHardeningDetect})
	if !res.OK {
		t.Fatalf("hardening.detect: %s", res.Error)
	}
	if len(res.Data) == 0 || !strings.Contains(string(res.Data), "state") {
		t.Fatalf("structured result missing: %s", res.Data)
	}
	// apply without confirm is refused by the v1 mutating gate.
	res = agentRunCommand(agentCommand{ID: "c2", Op: agentCmdHardeningApply, Params: map[string]string{"profile": "{}"}})
	if res.OK || !strings.Contains(res.Error, "confirm=yes") {
		t.Fatalf("apply without confirm must be refused: %+v", res)
	}
}

// ---- balancer (STEP 4) ----

type balHarness struct {
	fake *engine.FakeEngine
	bal  *forwardBalancer
	mgr  *engine.Manager
	reg  *engine.Registry

	mu       sync.Mutex
	scripts  []string
	failNft  int
	now      time.Time
	healthOK map[string]bool
}

func newBalHarness(t *testing.T) *balHarness {
	t.Helper()
	fake := engine.NewFakeEngine("fake")
	h := &balHarness{reg: engine.NewRegistry()}
	if err := h.reg.Register(fake); err != nil {
		t.Fatal(err)
	}
	h.fake = fake
	mgr := engine.NewManager(h.reg)
	h.mgr = mgr
	h.now = time.Unix(1796470000, 0)
	h.healthOK = map[string]bool{"t1": true, "t2": true}
	h.bal = newForwardBalancer(mgr, h.reg)
	h.bal.nowFn = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.now }
	realApply := nftApplyScript
	nftApplyScript = func(script string) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.failNft > 0 {
			h.failNft--
			return errors.New("nft failed (scripted)")
		}
		h.scripts = append(h.scripts, script)
		return nil
	}
	t.Cleanup(func() { nftApplyScript = realApply; h.bal.Stop(); resetV2Runtime() })
	return h
}

func regWith(t *testing.T, d engine.Driver) *engine.Registry {
	t.Helper()
	r := engine.NewRegistry()
	if err := r.Register(d); err != nil {
		t.Fatal(err)
	}
	return r
}

func (h *balHarness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func (h *balHarness) scriptCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.scripts)
}

func (h *balHarness) lastScript() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.scripts) == 0 {
		return ""
	}
	return h.scripts[len(h.scripts)-1]
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

func TestBalDebug(t *testing.T) {
	h := newBalHarness(t)
	d := testForwardDesired(t)
	d.Tunnels = []protocol.TunnelSpec{
		{ID: "t1", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Engine: "fake", Enabled: true},
		{ID: "t2", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2", Engine: "fake", Enabled: true},
	}
	engs, tuns := toEngineSpecs(d.Engines, d.Tunnels)
	if res := h.mgr.Reconcile(testCtx(), engs, tuns); len(res.Errors) != 0 {
		t.Fatalf("mgr: %v", res.Errors)
	}
	h.fake.SetForwardAddress("t1", "10.189.0.2", 8443)
	h.fake.SetForwardAddress("t2", "10.189.0.3", 8443)
	rep := h.bal.tick()
	t.Logf("rep: %+v", rep)
	t.Logf("lastScript: %q", h.lastScript())
	t.Logf("running: %d", h.mgr.RunningCount())
}

func TestBalancerFailoverAndFailback(t *testing.T) {
	h := newBalHarness(t)
	d := testForwardDesired(t)
	// Give both tunnels forward addresses + healthy engine views.
	d.Tunnels = []protocol.TunnelSpec{
		{ID: "t1", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Engine: "fake", EngineParams: json.RawMessage(`{"fw_addr":"10.189.0.2"}`), Enabled: true},
		{ID: "t2", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2", Engine: "fake", EngineParams: json.RawMessage(`{"fw_addr":"10.189.0.3"}`), Enabled: true},
	}
	// The manager reconciles the tunnels so the balancer sees them running.
	engs, tuns := toEngineSpecs(d.Engines, d.Tunnels)
	if res := h.mgr.Reconcile(testCtx(), engs, tuns); len(res.Errors) != 0 {
		t.Fatalf("manager reconcile: %v", res.Errors)
	}
	h.fake.SetForwardAddress("t1", "10.189.0.2", 8443)
	h.fake.SetForwardAddress("t2", "10.189.0.3", 8443)

	// Start the balancer with a 1s interval (test cadence).
	go func() { h.bal.Reconcile(&d) }()
	time.Sleep(50 * time.Millisecond)

	// The first apply must carry both tunnels, weights 70/30.
	script := h.lastScript()
	if !strings.Contains(script, "0-69 : 10.189.0.2") || !strings.Contains(script, "70-99 : 10.189.0.3") {
		t.Fatalf("initial map wrong:\n%s", script)
	}
	if !strings.Contains(script, ": 8443") {
		t.Fatalf("target port missing:\n%s", script)
	}

	// Scripted failure: t1 goes down. Detection = 2 consecutive misses at
	// a 1s interval. Measure the wall time from the failure to the map
	// update (the brief requires reporting the measured time).
	failureAt := time.Now()
	h.fake.SetHealth("t1", engine.Health{OK: false})
	deadline := failureAt.Add(3500 * time.Millisecond)
	for {
		script = h.lastScript()
		if !strings.Contains(script, "10.189.0.2") && strings.Contains(script, "10.189.0.3") {
			detected := time.Since(failureAt)
			t.Logf("measured failover detection time: %v (interval 1s x 2 misses)", detected.Round(time.Millisecond))
			if detected > 3500*time.Millisecond {
				t.Fatalf("detection took %v, want <= 3.5s", detected)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("t1 never left the rotation; last script:\n%s", script)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Failback: t1 healthy again -> re-added (switch_back 0).
	h.fake.SetHealth("t1", engine.Health{OK: true})
	deadline = time.Now().Add(3500 * time.Millisecond)
	for {
		script = h.lastScript()
		if strings.Contains(script, "10.189.0.2") && strings.Contains(script, "10.189.0.3") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("t1 never returned; last script:\n%s", script)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestBalancerWholeServerDownAndWeightChange(t *testing.T) {
	h := newBalHarness(t)
	d := testForwardDesired(t)
	d.Tunnels = []protocol.TunnelSpec{
		{ID: "t1", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Engine: "fake", Enabled: true},
		{ID: "t2", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2", Engine: "fake", Enabled: true},
	}
	engs, tuns := toEngineSpecs(d.Engines, d.Tunnels)
	_ = h.mgr.Reconcile(testCtx(), engs, tuns)
	h.fake.SetForwardAddress("t1", "10.189.0.2", 8443)
	h.fake.SetForwardAddress("t2", "10.189.0.3", 8443)
	go func() { h.bal.Reconcile(&d) }()
	time.Sleep(50 * time.Millisecond)

	// Whole foreign server down: t2 dies (hz-fra-2). t1 (hz-fra-1) takes
	// ALL the traffic: t2 leaves the rotation and t1's weight covers the
	// shrunken modulus (functionally 100% of new connections).
	h.fake.SetHealth("t2", engine.Health{OK: false})
	deadline := time.Now().Add(6 * time.Second)
	for {
		script := h.lastScript()
		if script != "" && !strings.Contains(script, "10.189.0.3") && strings.Contains(script, "10.189.0.2") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server failover did not consolidate traffic:\n%s", script)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Weight change: the panel rebalances 50/50 -> the map re-renders.
	d.Balancing.Weights = []protocol.WeightRule{
		{TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Weight: 50},
		{TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2", Weight: 50},
	}
	h.bal.Reconcile(&d)
	script := h.lastScript()
	if !strings.Contains(script, "0-49 : 10.189.0.2") {
		t.Fatalf("weight change not applied:\n%s", script)
	}
}

func TestBalancerAllDownAndFlapping(t *testing.T) {
	h := newBalHarness(t)
	d := testForwardDesired(t)
	d.Tunnels = []protocol.TunnelSpec{
		{ID: "t1", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Engine: "fake", Enabled: true},
		{ID: "t2", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2", Engine: "fake", Enabled: true},
	}
	engs, tuns := toEngineSpecs(d.Engines, d.Tunnels)
	_ = h.mgr.Reconcile(testCtx(), engs, tuns)
	h.fake.SetForwardAddress("t1", "10.189.0.2", 8443)
	h.fake.SetForwardAddress("t2", "10.189.0.3", 8443)
	go func() { h.bal.Reconcile(&d) }()
	time.Sleep(50 * time.Millisecond)

	// All down: the chain renders with NO dnat (fail fast, no blackhole).
	h.fake.SetHealth("t1", engine.Health{OK: false})
	h.fake.SetHealth("t2", engine.Health{OK: false})
	deadline := time.Now().Add(6 * time.Second)
	for {
		script := h.lastScript()
		if strings.Contains(script, "counter return") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("all-down must render a pass-through chain:\n%s", script)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Flapping: t1 flaps fast; each flip is honored (detection windows
	// apply, no crash, the rotation always reflects the last state).
	for i := 0; i < 3; i++ {
		h.fake.SetHealth("t1", engine.Health{OK: true})
		time.Sleep(1200 * time.Millisecond)
		h.fake.SetHealth("t1", engine.Health{OK: false})
		time.Sleep(1200 * time.Millisecond)
	}
	if n := h.scriptCount(); n < 3 {
		t.Fatalf("flapping produced %d applies, want >= 3", n)
	}
}

func TestRenderForwardNFTValidationShape(t *testing.T) {
	script := renderForwardNFT([]forwardRender{
		{ID: "fw-web", ListenPort: 8443, TargetPort: 8443, Proto: "both", Targets: []balTarget{
			{TunnelID: "a", IP: "10.189.0.2", Weight: 70},
			{TunnelID: "b", IP: "10.189.0.3", Weight: 30},
		}},
	})
	for _, want := range []string{
		"table ip quantum-fwd",
		"delete table ip quantum-fwd",
		"tcp dport 8443 dnat to numgen inc mod 100 map { 0-69 : 10.189.0.2, 70-99 : 10.189.0.3 } : 8443",
		"udp dport 8443 dnat to jhash ip saddr mod 100 map { 0-69 : 10.189.0.2, 70-99 : 10.189.0.3 } : 8443",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
}
