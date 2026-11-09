package agent

// forwardBalancer enforces the DesiredV2 service-forward contract on an
// Iran agent, locally: for every ForwardRule, new connections are
// distributed across the HEALTHY tunnels of its target group with the
// configured weights (resolution order tunnel > server pair >
// topology, mirroring the panel store), with active health checks,
// automatic failover when a tunnel or a whole foreign server dies, and
// failback. Everything it needs was in the last desired state, so it
// keeps working when the panel is dead.
//
// Kernel path (nftables, validated against nft 1.0.9 — see nft.go): the
// agent re-renders one atomic transaction whenever the healthy set or
// the weights change. Existing connections on a tunnel that dies break
// (accepted per the architecture brief); NEW connections move within
// the configured detection time (interval × consecutive_down, measured
// in the tests). Zero forwards = zero goroutines (light-agent rule).

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-protocol"
)

// applyNFTScript feeds one rendered transaction to nft -f through a
// throwaway 0600 file (the command runner seam has no stdin).
func applyNFTScript(script string) error {
	f, err := os.CreateTemp("", "quantum-fwd-*.nft")
	if err != nil {
		return err
	}
	name := f.Name()
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		os.Remove(name)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_ = os.Chmod(name, 0600)
	_, err = runCmdTimeout(15*time.Second, "nft", "-f", name)
	os.Remove(name)
	return err
}

// Seams (tests swap these; nothing else touches the host or the clock).
var (
	// nftApplyScript is the apply seam (tests capture the script).
	nftApplyScript = applyNFTScript
	// balancerProbeTCP is the tcp health probe.
	balancerProbeTCP = func(host string, port int, timeout time.Duration) bool {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), timeout)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
	// balancerNow is the clock seam.
	balancerNow = time.Now
)

// balHealthState is one tunnel's health accounting for the balancer.
type balHealthState struct {
	healthy    bool
	downStreak int
	upStreak   int
	wentDownAt time.Time
	lastProbe  time.Time
}

// balTargetDiag is one candidate target's evaluation outcome for one
// forward rule (structured diagnostics: the report and the debug log).
type balTargetDiag struct {
	Forward string `json:"forward"`
	Tunnel  string `json:"tunnel"`
	Reason  string `json:"reason"` // selected | unhealthy | weight-0 | no-forward-address
	Health  string `json:"health,omitempty"`
	Weight  int    `json:"weight,omitempty"`
	Addr    string `json:"addr,omitempty"`
	// NftRange is the target's slice of the numgen/jhash modulus, e.g.
	// "70-99" — the operator-visible answer to "what share did this
	// tunnel actually get" (phase 9: the mod-60 diagnostic).
	NftRange string `json:"nft_range,omitempty"`
	// Total is the rendered modulus (the sum of the SELECTED targets'
	// weights) for this pass.
	Total int `json:"total,omitempty"`
}

// balancerStatusPath is where the balancer persists its last pass for
// `quantum-agent balancer status` (0600; best-effort — never fatal).
func balancerStatusPath() string {
	return filepath.Join(configDir, "balancer-status.json")
}

// balTickReport is one health+apply pass, for tests and the report.
type balTickReport struct {
	Evaluated    int
	Healthy      int
	Changed      bool
	DetectedDown []string
	DetectedUp   []string
	Errors       []string
	Targets      []balTargetDiag
	Tunnels      []map[string]any
	// RouteLocalnet mirrors the balancer-owned dynamic knob (RUNBOOK
	// ITEM 35): true while the enforced ruleset DNATs to loopback and
	// the agent holds a captured net.ipv4.conf.all.route_localnet value.
	RouteLocalnet bool `json:"route_localnet,omitempty"`
}

type forwardBalancer struct {
	mgr *engine.Manager
	reg *engine.Registry

	mu           sync.Mutex
	desired      protocol.DesiredV2
	health       map[string]*balHealthState
	lastRule     string // last applied script (skip no-op applies)
	lastDiagKey  string // last logged target evaluation (change-keyed log)
	lastForwards []protocol.ForwardRuntime
	stop         chan struct{}
	running      bool
	nowFn        func() time.Time
	// Balancer-owned route_localnet state (RUNBOOK ITEM 35, see
	// routelocalnet.go): rlActive while the enforced ruleset DNATs to
	// loopback; rlSaved is the CAPTURED previous value (never a guess)
	// restored when no loopback target remains. Guarded by mu.
	rlActive     bool
	rlSaved      string
	rlIface      string
	rlSavedIface string
}

func newForwardBalancer(mgr *engine.Manager, reg *engine.Registry) *forwardBalancer {
	return &forwardBalancer{
		mgr: mgr, reg: reg,
		health: map[string]*balHealthState{},
		nowFn:  balancerNow,
	}
}

// Reconcile adopts a v2 desired state's forwarding section. It (re)starts
// the health loop only when at least one forward rule exists.
func (b *forwardBalancer) Reconcile(d *protocol.DesiredV2) {
	b.mu.Lock()
	b.desired = *d
	start := len(d.Forwards) > 0 && !b.running
	if start {
		b.stop = make(chan struct{})
		b.running = true
	}
	stop := b.stop
	b.mu.Unlock()
	if start {
		go b.loop(stop)
	}
	// Immediate pass so a new desired state takes effect at once.
	b.tick()
}

// Stop halts the loop and removes the applied ruleset.
func (b *forwardBalancer) Stop() {
	b.mu.Lock()
	if !b.running {
		b.mu.Unlock()
		return
	}
	close(b.stop)
	b.running = false
	// Ruleset cleanup under the same lock that guards the route_localnet
	// state: with no forward rules left, a captured knob value is no
	// longer ours to hold (applyScriptRL restores it).
	err := b.applyScriptRL(renderForwardNFT(nil))
	b.mu.Unlock()
	if err != nil {
		log.Printf("[balancer] ruleset cleanup failed: %v", err)
	}
}

func (b *forwardBalancer) loop(stop chan struct{}) {
	for {
		b.mu.Lock()
		interval := 1
		if b.desired.Balancing != nil && b.desired.Balancing.HealthCheck.IntervalS > 0 {
			interval = b.desired.Balancing.HealthCheck.IntervalS
		}
		b.mu.Unlock()
		if interval < 1 {
			interval = 1
		}
		select {
		case <-stop:
			return
		case <-time.After(time.Duration(interval) * time.Second):
			b.tick()
		}
	}
}

// tick runs one health pass and applies the ruleset if it changed.
func (b *forwardBalancer) tick() balTickReport {
	b.mu.Lock()
	defer b.mu.Unlock()
	rep := balTickReport{}
	d := b.desired
	now := b.nowFn()
	hc := protocol.HealthCheckParams{IntervalS: 1, TimeoutMS: 1000, Probe: "engine", ConsecutiveDown: 1, ConsecutiveUp: 1}
	if d.Balancing != nil {
		hc = d.Balancing.HealthCheck
	}
	if hc.ConsecutiveDown < 1 {
		hc.ConsecutiveDown = 1
	}
	if hc.ConsecutiveUp < 1 {
		hc.ConsecutiveUp = 1
	}

	// Resolve group -> healthy tunnel targets.
	groups := map[string]protocol.TargetGroup{}
	for _, g := range d.TargetGroups {
		groups[g.ID] = g
	}
	// diag records one candidate's evaluation for the structured report
	// (and the change-keyed debug log at the end of the pass).
	diag := func(forward, tid, reason string, h *balHealthState, fa *forwardAddr, weight int) {
		entry := balTargetDiag{Forward: forward, Tunnel: tid, Reason: reason, Weight: weight}
		if h != nil {
			if h.healthy {
				entry.Health = "up"
			} else {
				entry.Health = "down"
			}
		}
		if fa != nil {
			entry.Addr = net.JoinHostPort(fa.host, fmt.Sprint(fa.port))
		}
		rep.Targets = append(rep.Targets, entry)
	}
	status := b.mgr.Status()
	byID := map[string]engine.TunnelStatus{}
	for _, st := range status {
		byID[st.TunnelID] = st
	}
	// Stable tunnel order across the whole pass.
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, tid := range ids {
		st := byID[tid]
		var drv engine.Driver
		if dd, ok := b.reg.Driver(st.Engine); ok {
			drv = dd
		}
		h := b.health[tid]
		if h == nil {
			h = &balHealthState{healthy: true}
			b.health[tid] = h
		}
		if st.Engine == "" {
			continue
		}
		rep.Evaluated++
		ok := false
		switch {
		case drv == nil:
			ok = false
		case hc.Probe == "tcp" && st.RemoteServer != "":
			// TCP probe hits the forward target through the tunnel
			// endpoint; the endpoint host doubles as the probe target.
			if fa, hasAddr := forwardAddressOf(b.mgr, b.reg, st); hasAddr {
				ok = balancerProbeTCP(fa.host, orDefault(fa.port, 22), time.Duration(hc.TimeoutMS)*time.Millisecond)
			}
		default: // "engine" | "icmp": the driver's own health view
			ok = st.Health.OK
		}
		if !st.Running {
			ok = false
		}
		if ok {
			h.downStreak = 0
			h.upStreak++
			if !h.healthy && h.upStreak >= hc.ConsecutiveUp {
				// Failback: honor switch_back_s (sticky away time).
				if d.Balancing.Failover.SwitchBackS > 0 &&
					now.Sub(h.wentDownAt) < time.Duration(d.Balancing.Failover.SwitchBackS)*time.Second {
					// still sticky-away; stay down for now
				} else {
					h.healthy = true
					rep.DetectedUp = append(rep.DetectedUp, tid)
				}
			}
		} else {
			h.upStreak = 0
			h.downStreak++
			if h.healthy && h.downStreak >= hc.ConsecutiveDown {
				h.healthy = false
				h.wentDownAt = now
				rep.DetectedDown = append(rep.DetectedDown, tid)
			}
		}
		if h.healthy {
			rep.Healthy++
		}
	}

	// Render + apply when something changed.
	rules := make([]forwardRender, 0, len(d.Forwards))
	forwards := make([]protocol.ForwardRuntime, 0, len(d.Forwards))
	for _, fr := range d.Forwards {
		if !fr.IsEnabled() {
			continue // explicitly disabled rule: not rendered (PROTOCOL-REQUESTS R1)
		}
		runtime := protocol.ForwardRuntime{
			ID: fr.ID, ListenPort: fr.ListenPort, Proto: fr.Proto, TargetGroup: fr.TargetGroup,
		}
		if fr.TargetGroup == "" && strings.TrimSpace(fr.Target) != "" {
			// Static per-server rule (panel ForwardSpec form, no
			// balancing group): rendered unconditionally — availability
			// is the panel's responsibility here.
			host, port, perr := splitForwardTarget(fr.Target, fr.TargetPort)
			if perr != nil {
				rep.Errors = append(rep.Errors, fmt.Sprintf("forward %s: %v", fr.ID, perr))
				continue
			}
			rules = append(rules, forwardRender{ID: fr.ID, ListenPort: fr.ListenPort, TargetPort: fr.TargetPort, Proto: fr.Proto,
				Targets: []balTarget{{TunnelID: "static:" + fr.ID, IP: host, Port: port, Weight: 1}}})
			runtime.Targets = append(runtime.Targets, "static:"+fr.ID)
			runtime.Weights = append(runtime.Weights, 1)
			forwards = append(forwards, runtime)
			continue
		}
		g, ok := groups[fr.TargetGroup]
		if !ok {
			rep.Errors = append(rep.Errors, fmt.Sprintf("forward %s: unknown target group %q", fr.ID, fr.TargetGroup))
			continue
		}
		targets := []balTarget{}
		for _, tid := range ids {
			st := byID[tid]
			if st.TopologyID != g.TopologyID {
				continue
			}
			if g.RemoteServer != "" && st.RemoteServer != g.RemoteServer {
				continue
			}
			h := b.health[tid]
			if h == nil || !h.healthy || !st.Running {
				diag(fr.ID, tid, "unhealthy", b.health[tid], nil, 0)
				continue
			}
			w, okW := resolveWeight(d.Balancing.Weights, st.TopologyID, st.LocalServer, st.RemoteServer, tid)
			if !okW || w <= 0 {
				diag(fr.ID, tid, "weight-0", h, nil, w)
				continue // weight 0 = excluded from balancing
			}
			fa, hasAddr := forwardAddressOf(b.mgr, b.reg, st)
			if !hasAddr || fa.host == "" {
				diag(fr.ID, tid, "no-forward-address", h, nil, w)
				continue
			}
			diag(fr.ID, tid, "selected", h, &fa, w)
			targets = append(targets, balTarget{TunnelID: tid, IP: fa.host, Port: fa.port, Weight: w})
		}
		// RUNBOOK ITEM 36 mirror: the nft renderer drops port-less targets
		// that cannot join a per-target-port map (`addr . 0` — the kernel
		// no-ops the element). The runtime view and the nft ranges below
		// must describe the rotation AS RENDERED, so the same split
		// applies before reporting; a dropped target's "selected" diag
		// entry becomes "portless-target".
		keptTargets, portless := forwardUsableTargets(forwardRender{ID: fr.ID, ListenPort: fr.ListenPort, TargetPort: fr.TargetPort, Proto: fr.Proto, Targets: targets})
		for _, t := range portless {
			for i := range rep.Targets {
				if rep.Targets[i].Forward == fr.ID && rep.Targets[i].Tunnel == t.TunnelID && rep.Targets[i].Reason == "selected" {
					rep.Targets[i].Reason = "portless-target"
				}
			}
		}
		targets = keptTargets
		for _, t := range targets {
			runtime.Targets = append(runtime.Targets, t.TunnelID)
			runtime.Weights = append(runtime.Weights, t.Weight)
		}
		rules = append(rules, forwardRender{ID: fr.ID, ListenPort: fr.ListenPort, TargetPort: fr.TargetPort, Proto: fr.Proto, Targets: targets})
		// Per-target nft range (phase-9 diagnostic): the same deterministic
		// order + range math the nft renderer uses, surfaced so the
		// operator sees "tunnel X got 0-29 of mod 60" without parsing nft.
		sorted := append([]balTarget(nil), targets...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].TunnelID < sorted[j].TunnelID })
		total := 0
		for _, t := range sorted {
			total += t.Weight
		}
		lo := 0
		for _, t := range sorted {
			hi := lo + t.Weight - 1
			if hi >= total {
				hi = total - 1
			}
			for i := range rep.Targets {
				if rep.Targets[i].Forward == fr.ID && rep.Targets[i].Tunnel == t.TunnelID &&
					rep.Targets[i].Reason == "selected" {
					rep.Targets[i].NftRange = fmt.Sprintf("%d-%d", lo, hi)
					rep.Targets[i].Total = total
				}
			}
			lo += t.Weight
			if lo >= total {
				break
			}
		}
		forwards = append(forwards, runtime)
	}

	script := renderForwardNFT(rules)
	if script != b.lastRule {
		listenPorts := make([]int, 0, len(rules))
		for _, r := range rules {
			listenPorts = append(listenPorts, r.ListenPort)
		}
		if err := b.applyScriptRL(script, listenPorts...); err != nil {
			rep.Errors = append(rep.Errors, "nft apply: "+err.Error())
			log.Printf("[balancer] nft apply failed: %v", err)
		} else {
			b.lastRule = script
			rep.Changed = true
		}
	}
	b.lastForwards = forwards
	rep.RouteLocalnet = b.rlActive
	// Structured diagnostics, logged when the evaluation changes
	// (reconcile, health flip, weight change) — never every tick.
	diagKey := ""
	for _, t := range rep.Targets {
		diagKey += fmt.Sprintf("%s|%s|%s|%s|%d;", t.Forward, t.Tunnel, t.Reason, t.Health, t.Weight)
	}
	if diagKey != b.lastDiagKey {
		if out, err := json.Marshal(rep.Targets); err == nil {
			log.Printf("[balancer] targets: %s", out)
		}
		b.lastDiagKey = diagKey
	}
	// Persist the last pass for `quantum-agent balancer status` (0600,
	// best-effort — the diag must never break balancing).
	if out, err := json.MarshalIndent(rep, "", "  "); err == nil {
		_ = os.WriteFile(balancerStatusPath(), out, 0o600)
	}
	return rep
}

// ForwardRuntimeSnapshot returns the last enforced forwarding state for
// the v2 heartbeat.
func (b *forwardBalancer) ForwardRuntimeSnapshot() []protocol.ForwardRuntime {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]protocol.ForwardRuntime(nil), b.lastForwards...)
}

// Hardening-free helper: resolves the effective weight for one tunnel.
// Mirrors the panel store's resolution: tunnel rule > (local, remote)
// pair rule > topology rule; ties break toward the smaller weight;
// no rule = 1. Returns ok=false for weight 0 (excluded).
func resolveWeight(rules []protocol.WeightRule, topologyID, localServer, remoteServer, tunnelID string) (int, bool) {
	found := false
	bestRank, bestW := 0, 0
	for _, r := range rules {
		if r.TopologyID != "" && r.TopologyID != topologyID {
			continue
		}
		if r.LocalServer != "" && r.LocalServer != localServer {
			continue
		}
		if r.RemoteServer != "" && r.RemoteServer != remoteServer {
			continue
		}
		rank := 1
		if r.TunnelID != "" {
			if r.TunnelID != tunnelID {
				continue
			}
			rank = 3
		} else if r.LocalServer != "" && r.RemoteServer != "" {
			rank = 2
		}
		if !found || rank > bestRank || (rank == bestRank && r.Weight < bestW) {
			found, bestRank, bestW = true, rank, r.Weight
		}
	}
	if !found {
		return 1, true // no rule: default weight 1
	}
	if bestW <= 0 {
		return 0, false
	}
	return bestW, true
}

type forwardAddr struct {
	host string
	port int
}

// forwardAddressOf resolves a tunnel's forward address via the driver's
// ForwardAddresser against the MANAGER'S actual instance. Phase-5 bug
// fix: this used to fabricate a params-less Instance — drivers read the
// address from engine_params, so every target resolved to "no address"
// and the balancer rendered zero DNAT targets (the 100/0 e2e artifact).
func forwardAddressOf(mgr *engine.Manager, reg *engine.Registry, st engine.TunnelStatus) (forwardAddr, bool) {
	drv, ok := reg.Driver(st.Engine)
	if !ok {
		return forwardAddr{}, false
	}
	fa, canAddr := drv.(engine.ForwardAddresser)
	if !canAddr {
		return forwardAddr{}, false
	}
	inst, okInst := mgr.Instance(st.TunnelID)
	if !okInst {
		return forwardAddr{}, false
	}
	host, port, ok := fa.ForwardAddress(inst)
	if !ok || host == "" {
		return forwardAddr{}, false
	}
	return forwardAddr{host: host, port: port}, true
}

// splitForwardTarget parses "addr" or "addr:port" (port defaulting to
// the rule's target_port).
func splitForwardTarget(target string, defaultPort int) (string, int, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		if strings.Contains(target, ":") && !strings.HasPrefix(target, "[") {
			return "", 0, fmt.Errorf("forward target %q: %v", target, err)
		}
		return strings.Trim(strings.TrimSpace(target), "[]"), defaultPort, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("forward target %q: bad port", target)
	}
	return strings.Trim(host, "[]"), port, nil
}

func orDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// writeTempFile is a small helper (0600, agent temp dir).
func writeTempFile(pattern, content string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	os.Chmod(f.Name(), 0600)
	return f.Name(), nil
}
