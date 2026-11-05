package agent

// Phase-5 weighted-balancing tests. The e2e measured 100/0 against a
// desired 70/30; the root causes were (a) forwardAddressOf fabricating a
// params-less Instance so params-based drivers (lab) never resolved an
// address, and (b) the lab engine binding its sink on every instance —
// the near end squatted the forward listen port and only one lab tunnel
// per host could start. These tests pin the fixed behavior:
//
//   - the rendered nft map carries BOTH targets with the configured
//     weights, and the numgen distribution over 10,000 NEW connections
//     matches the weights within ±2 percentage points;
//   - weight changes re-render (70/30 -> 30/70 -> 100/0);
//   - health transitions exclude/re-admit targets and re-apply exactly
//     once per change;
//   - repeated reconciliation with no changes does not touch nftables.

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-protocol"
)

// numgenDistribution parses the rendered TCP dnat map and simulates
// 10,000 sequential NEW connections (numgen inc: 0,1,2,... mod total)
// returning the per-target connection counts keyed by target address.
func numgenDistribution(t *testing.T, script string) map[string]int {
	t.Helper()
	chainRe := regexp.MustCompile(`tcp dport \d+ dnat to numgen inc mod (\d+) map \{ ([^}]*) \}`)
	m := chainRe.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("no tcp numgen map in script:\n%s", script)
	}
	total, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	type rng struct {
		lo, hi int
		target string
	}
	var ranges []rng
	for _, elem := range strings.Split(m[2], ", ") {
		parts := strings.SplitN(strings.TrimSpace(elem), " : ", 2)
		if len(parts) != 2 {
			t.Fatalf("bad map element %q", elem)
		}
		bounds := strings.SplitN(parts[0], "-", 2)
		lo, err := strconv.Atoi(bounds[0])
		if err != nil {
			t.Fatal(err)
		}
		hi := lo
		if len(bounds) == 2 {
			if hi, err = strconv.Atoi(bounds[1]); err != nil {
				t.Fatal(err)
			}
		}
		ranges = append(ranges, rng{lo: lo, hi: hi, target: parts[1]})
	}
	out := map[string]int{}
	const conns = 10000
	for i := 0; i < conns; i++ {
		v := i % total
		for _, r := range ranges {
			if v >= r.lo && v <= r.hi {
				out[r.target]++
				break
			}
		}
	}
	return out
}

func withinPct(t *testing.T, got, want, total int, label string) {
	t.Helper()
	pct := float64(got) / float64(total) * 100
	if diff := pct - float64(want); diff > 2 || diff < -2 {
		t.Fatalf("%s: %d/%d = %.2f%%, want %d%% (±2pp tolerance)", label, got, total, pct, want)
	}
}

// newWeightTestDesired is the desired state the phase-4 e2e intended:
// two fake tunnels from ir-drak-1 to the two foreign servers, balanced
// over the topology pool with weights 70/30.
func newWeightTestDesired(t *testing.T) protocol.DesiredV2 {
	t.Helper()
	return protocol.DesiredV2{
		Revision: "phase5-weights-1",
		Engines:  []protocol.EngineSpec{{ID: "fake", Enabled: true}},
		Tunnels: []protocol.TunnelSpec{
			{ID: "t1", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Engine: "fake", Enabled: true},
			{ID: "t2", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2", Engine: "fake", Enabled: true},
		},
		Balancing: &protocol.BalancingPolicy{
			Weights: []protocol.WeightRule{
				{TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Weight: 70},
				{TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2", Weight: 30},
			},
			HealthCheck: protocol.HealthCheckParams{IntervalS: 1, TimeoutMS: 200, Probe: "engine", ConsecutiveDown: 2, ConsecutiveUp: 1},
		},
		TargetGroups: []protocol.TargetGroup{{ID: "grp-pool", TopologyID: "topo-drak-hetzner"}},
		Forwards:     []protocol.ForwardRule{{ID: "fw-web", ListenPort: 8443, Proto: "tcp", TargetGroup: "grp-pool", TargetPort: 8443}},
	}
}

// reconcileWeightDesired reconciles the desired's tunnels into the
// manager and scripts both forward addresses.
func reconcileWeightDesired(t *testing.T, h *balHarness, d *protocol.DesiredV2) {
	t.Helper()
	engs, tuns := toEngineSpecs(d.Engines, d.Tunnels)
	if res := h.mgr.Reconcile(testCtx(), engs, tuns); len(res.Errors) != 0 {
		t.Fatalf("manager reconcile: %v", res.Errors)
	}
	h.fake.SetForwardAddress("t1", "10.189.0.2", 8443)
	h.fake.SetForwardAddress("t2", "10.189.0.3", 8443)
}

func TestBalancerWeightedDistribution7030(t *testing.T) {
	h := newBalHarness(t)
	d := newWeightTestDesired(t)
	reconcileWeightDesired(t, h, &d)
	h.bal.Reconcile(&d)

	script := h.lastScript()
	dist := numgenDistribution(t, script)
	if len(dist) != 2 {
		t.Fatalf("want both targets in the map, got %v:\n%s", dist, script)
	}
	// numgen is a per-connection round robin: over 10k NEW connections
	// the kernel-side distribution is exactly the weight split; the ±2pp
	// tolerance is the documented acceptance band.
	withinPct(t, dist["10.189.0.2"], 70, 10000, "hz-fra-1")
	withinPct(t, dist["10.189.0.3"], 30, 10000, "hz-fra-2")
	if dist["10.189.0.2"] < 6800 || dist["10.189.0.2"] > 7200 {
		t.Fatalf("70%% target got %d/10000", dist["10.189.0.2"])
	}

	// Structured diagnostics must select both targets with their weights.
	sel := map[string]balTargetDiag{}
	for _, td := range h.bal.tick().Targets {
		if td.Reason == "selected" {
			sel[td.Tunnel] = td
		}
	}
	if sel["t1"].Weight != 70 || sel["t2"].Weight != 30 {
		t.Fatalf("selected diagnostics: %+v %+v", sel["t1"], sel["t2"])
	}
	if sel["t1"].Addr != "10.189.0.2:8443" || sel["t2"].Addr != "10.189.0.3:8443" {
		t.Fatalf("selected addresses: %+v %+v", sel["t1"], sel["t2"])
	}
}

func TestBalancerWeightChange3070(t *testing.T) {
	h := newBalHarness(t)
	d := newWeightTestDesired(t)
	reconcileWeightDesired(t, h, &d)
	h.bal.Reconcile(&d)

	// Flip the weights 70/30 -> 30/70: a NEW revision, the same way the
	// panel recompiles after a weight edit.
	d.Revision = "phase5-weights-2"
	d.Balancing.Weights = []protocol.WeightRule{
		{TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Weight: 30},
		{TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2", Weight: 70},
	}
	h.bal.Reconcile(&d)

	dist := numgenDistribution(t, h.lastScript())
	withinPct(t, dist["10.189.0.2"], 30, 10000, "hz-fra-1 after change")
	withinPct(t, dist["10.189.0.3"], 70, 10000, "hz-fra-2 after change")
}

func TestBalancerIntentional100To0(t *testing.T) {
	h := newBalHarness(t)
	d := newWeightTestDesired(t)
	reconcileWeightDesired(t, h, &d)
	// Operator intent: send everything to hz-fra-1 (weight 0 excludes).
	d.Balancing.Weights = []protocol.WeightRule{
		{TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Weight: 100},
		{TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2", Weight: 0},
	}
	h.bal.Reconcile(&d)

	script := h.lastScript()
	if !strings.Contains(script, "0-99 : 10.189.0.2") {
		t.Fatalf("100%% target missing from the map:\n%s", script)
	}
	if strings.Contains(script, "10.189.0.3") {
		t.Fatalf("weight-0 target must be excluded:\n%s", script)
	}
	dist := numgenDistribution(t, script)
	if dist["10.189.0.2"] != 10000 {
		t.Fatalf("100/0 config: hz-fra-1 got %d/10000", dist["10.189.0.2"])
	}
}

func TestBalancerUnhealthyTargetExcludedAndRecovers(t *testing.T) {
	h := newBalHarness(t)
	d := newWeightTestDesired(t)
	reconcileWeightDesired(t, h, &d)
	h.bal.Reconcile(&d)

	// t1 (hz-fra-1) dies: detection = ConsecutiveDown=2 ticks.
	h.fake.SetHealth("t1", engine.Health{OK: false})
	h.bal.tick()
	rep := h.bal.tick()
	if len(rep.DetectedDown) != 1 || rep.DetectedDown[0] != "t1" {
		t.Fatalf("detection: %+v", rep.DetectedDown)
	}
	dist := numgenDistribution(t, h.lastScript())
	if len(dist) != 1 || dist["10.189.0.3"] != 10000 {
		t.Fatalf("unhealthy exclusion: %v", dist)
	}

	// Recovery: ConsecutiveUp=1 tick re-admits t1 (failback, sticky-away
	// is disabled).
	h.fake.SetHealth("t1", engine.Health{OK: true})
	rep = h.bal.tick()
	if len(rep.DetectedUp) != 1 || rep.DetectedUp[0] != "t1" {
		t.Fatalf("recovery: %+v", rep.DetectedUp)
	}
	dist = numgenDistribution(t, h.lastScript())
	if len(dist) != 2 || dist["10.189.0.2"] < 6800 || dist["10.189.0.2"] > 7200 {
		t.Fatalf("failback distribution: %v", dist)
	}
}

func TestBalancerWholeServerDownAndAllDown(t *testing.T) {
	h := newBalHarness(t)
	d := newWeightTestDesired(t)
	// hz-fra-1 carries TWO tunnels (as in the generated topology): both
	// must vanish together when the server dies.
	d.Tunnels = append(d.Tunnels, protocol.TunnelSpec{
		ID: "t3", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Engine: "fake", Enabled: true,
	})
	reconcileWeightDesired(t, h, &d)
	h.fake.SetForwardAddress("t3", "10.189.0.4", 8443)
	h.bal.Reconcile(&d)
	if dist := numgenDistribution(t, h.lastScript()); len(dist) != 3 {
		t.Fatalf("three-target map expected: %v", dist)
	}

	// Whole foreign server hz-fra-1 dies: t1 AND t3 down together.
	h.fake.SetHealth("t1", engine.Health{OK: false})
	h.fake.SetHealth("t3", engine.Health{OK: false})
	h.bal.tick()
	h.bal.tick()
	dist := numgenDistribution(t, h.lastScript())
	if len(dist) != 1 || dist["10.189.0.3"] != 10000 {
		t.Fatalf("whole-server failover: %v", dist)
	}

	// Every target unavailable: pass-through chain, no dnat statement.
	h.fake.SetHealth("t2", engine.Health{OK: false})
	h.bal.tick()
	h.bal.tick()
	script := h.lastScript()
	if !strings.Contains(script, "counter return") || strings.Contains(script, "dnat") {
		t.Fatalf("all-down must render the fail-fast pass-through chain:\n%s", script)
	}
}

func TestBalancerNoNftChurnOnRepeatedReconcile(t *testing.T) {
	h := newBalHarness(t)
	d := newWeightTestDesired(t)
	reconcileWeightDesired(t, h, &d)
	h.bal.Reconcile(&d)
	if got := len(h.scripts); got != 1 {
		t.Fatalf("initial apply count = %d, want 1", got)
	}
	// Repeated reconciliation with the SAME desired and stable health:
	// the ruleset must not be re-applied.
	for i := 0; i < 5; i++ {
		h.bal.Reconcile(&d)
		h.bal.tick()
	}
	if got := len(h.scripts); got != 1 {
		t.Fatalf("no-op reconciles re-applied nft %d times", got)
	}
	// A real change (weight edit) applies exactly once more.
	d.Balancing.Weights = []protocol.WeightRule{
		{TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1", Weight: 50},
		{TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2", Weight: 50},
	}
	h.bal.Reconcile(&d)
	if got := len(h.scripts); got != 2 {
		t.Fatalf("weight change applied %d times, want exactly one more", got-1)
	}
}

// paramsForwardDriver is a minimal driver whose forward address comes
// ONLY from engine_params (like the lab driver) — the exact shape that
// the old params-less forwardAddressOf fabrication broke.
type paramsForwardDriver struct{ *engine.FakeEngine }

func (p *paramsForwardDriver) ForwardAddress(inst engine.Instance) (string, int, bool) {
	var v struct {
		Addr string `json:"fw_addr"`
		Port int    `json:"fw_port"`
	}
	if json.Unmarshal(inst.Params, &v) != nil || v.Addr == "" {
		return "", 0, false
	}
	return v.Addr, v.Port, true
}

// TestBalancerForwardAddressFromManagerInstance is the regression test
// for the Phase-5 root cause: the balancer must resolve forward
// addresses through the manager's ACTUAL instance (with engine_params).
// With the old params-less fabrication the params-based driver resolved
// nothing and the forward rendered zero targets (the e2e 100/0
// artifact).
func TestBalancerForwardAddressFromManagerInstance(t *testing.T) {
	h := newBalHarness(t)
	if err := h.reg.Register(&paramsForwardDriver{FakeEngine: engine.NewFakeEngine("paramdrv")}); err != nil {
		t.Fatal(err)
	}
	d := newWeightTestDesired(t)
	d.Engines = append(d.Engines, protocol.EngineSpec{ID: "paramdrv", Enabled: true})
	d.Tunnels = []protocol.TunnelSpec{
		{ID: "l1", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-1",
			Engine: "paramdrv", EngineParams: json.RawMessage(`{"fw_addr":"10.200.0.21","fw_port":8443}`), Enabled: true},
		{ID: "l2", TopologyID: "topo-drak-hetzner", LocalServer: "ir-drak-1", RemoteServer: "hz-fra-2",
			Engine: "paramdrv", EngineParams: json.RawMessage(`{"fw_addr":"10.200.0.22","fw_port":8444}`), Enabled: true},
	}
	d.Forwards = []protocol.ForwardRule{{ID: "fw-web", ListenPort: 8443, Proto: "tcp", TargetGroup: "grp-pool", TargetPort: 8443}}
	engs, tuns := toEngineSpecs(d.Engines, d.Tunnels)
	if res := h.mgr.Reconcile(testCtx(), engs, tuns); len(res.Errors) != 0 {
		t.Fatalf("manager reconcile: %v", res.Errors)
	}
	h.bal.Reconcile(&d)

	script := h.lastScript()
	if !strings.Contains(script, "10.200.0.21") || !strings.Contains(script, "10.200.0.22") {
		t.Fatalf("params-based forward addresses missing — the Phase-5 regression:\n%s", script)
	}
	// Distinct target ports must render the per-target form.
	if !strings.Contains(script, "10.200.0.21 . 8443") || !strings.Contains(script, "10.200.0.22 . 8444") {
		t.Fatalf("per-target-port map missing:\n%s", script)
	}
	if strings.Contains(script, "} : 8443") {
		t.Fatalf("mixed ports must not use the single-port suffix:\n%s", script)
	}
}

// TestLabFakeSideAwareSink pins the lab driver's side contract: only the
// FAR end (lab_addr owned by this host) binds the sink; the NEAR end
// binds nothing and its health is a real probe of the far end. Two far
// ends on one host coexist on distinct ports (the e2e gives each tunnel
// its own lab port).
func TestLabFakeSideAwareSink(t *testing.T) {
	oldOwns, oldProbe := labOwnsAddr, labProbeTCP
	t.Cleanup(func() { labOwnsAddr, labProbeTCP = oldOwns, oldProbe })
	labOwnsAddr = func(addr string) bool { return addr == "10.200.0.21" }
	probes := 0
	probeUp := true
	labProbeTCP = func(string, int, time.Duration) bool { probes++; return probeUp }

	lab := NewLabFakeDriver()
	ctx := testCtx()

	far1 := engine.Instance{TunnelID: "far1", TopologyID: "topo", LocalServer: "ir-drak-1", RemoteServer: "hz",
		Params: json.RawMessage(`{"lab_addr":"10.200.0.21","lab_port":8443}`)}
	far2 := engine.Instance{TunnelID: "far2", TopologyID: "topo", LocalServer: "ir-drak-2", RemoteServer: "hz",
		Params: json.RawMessage(`{"lab_addr":"10.200.0.21","lab_port":8444}`)}
	near := engine.Instance{TunnelID: "near", TopologyID: "topo", LocalServer: "ir", RemoteServer: "hz-fra-9",
		Params: json.RawMessage(`{"lab_addr":"10.200.0.99","lab_port":8443}`)}

	// Both far ends bind (distinct ports); the near end binds nothing.
	if err := lab.Start(ctx, far1); err != nil {
		t.Fatalf("far1 start: %v", err)
	}
	if err := lab.Start(ctx, far2); err != nil {
		t.Fatalf("far2 start: %v", err)
	}
	if err := lab.Start(ctx, near); err != nil {
		t.Fatalf("near start: %v", err)
	}
	lab.mu.Lock()
	_, l1 := lab.sinks["far1"]
	_, l2 := lab.sinks["far2"]
	_, l3 := lab.sinks["near"]
	lab.mu.Unlock()
	if !l1 || !l2 || l3 {
		t.Fatalf("side-aware binding wrong: far1=%v far2=%v near=%v", l1, l2, l3)
	}
	if h := lab.Health(near); !h.OK || probes != 1 {
		t.Fatalf("near health = %+v probes=%d", h, probes)
	}
	if h := lab.Health(far1); !h.OK || probes != 1 {
		t.Fatalf("far health = %+v probes=%d (must not probe itself)", h, probes)
	}
	// The far end dying flips the near end's health (end-to-end signal).
	probeUp = false
	if h := lab.Health(near); h.OK || probes != 2 {
		t.Fatalf("near health after far death = %+v probes=%d", h, probes)
	}
	// ForwardAddress resolves from params on BOTH ends (balancer input).
	if host, port, ok := lab.ForwardAddress(near); !ok || host != "10.200.0.99" || port != 8443 {
		t.Fatalf("near ForwardAddress = %s:%d %v", host, port, ok)
	}
	if host, port, ok := lab.ForwardAddress(far1); !ok || host != "10.200.0.21" || port != 8443 {
		t.Fatalf("far ForwardAddress = %s:%d %v", host, port, ok)
	}
}
