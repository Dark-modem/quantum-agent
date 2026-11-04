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
	"fmt"
	"log"
	"net"
	"os"
	"sort"
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

// balTickReport is one health+apply pass, for tests and the report.
type balTickReport struct {
	Evaluated    int
	Healthy      int
	Changed      bool
	DetectedDown []string
	DetectedUp   []string
	Errors       []string
}

type forwardBalancer struct {
	mgr *engine.Manager
	reg *engine.Registry

	mu           sync.Mutex
	desired      protocol.DesiredV2
	health       map[string]*balHealthState
	lastRule     string // last applied script (skip no-op applies)
	lastForwards []protocol.ForwardRuntime
	stop         chan struct{}
	running      bool
	nowFn        func() time.Time
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
	b.mu.Unlock()
	if err := nftApplyScript(renderForwardNFT(nil)); err != nil {
		log.Printf("[balancer] ruleset cleanup failed: %v", err)
	}
}

func (b *forwardBalancer) loop(stop chan struct{}) {
	for {
		b.mu.Lock()
		interval := b.desired.Balancing.HealthCheck.IntervalS
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
			if fa, hasAddr := forwardAddressOf(b.reg, st); hasAddr {
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
		g, ok := groups[fr.TargetGroup]
		if !ok {
			rep.Errors = append(rep.Errors, fmt.Sprintf("forward %s: unknown target group %q", fr.ID, fr.TargetGroup))
			continue
		}
		targets := []balTarget{}
		runtime := protocol.ForwardRuntime{
			ID: fr.ID, ListenPort: fr.ListenPort, Proto: fr.Proto, TargetGroup: fr.TargetGroup,
		}
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
				continue
			}
			w, okW := resolveWeight(d.Balancing.Weights, st.TopologyID, st.LocalServer, st.RemoteServer, tid)
			if !okW || w <= 0 {
				continue // weight 0 = excluded from balancing
			}
			fa, hasAddr := forwardAddressOf(b.reg, st)
			if !hasAddr || fa.host == "" {
				continue
			}
			targets = append(targets, balTarget{TunnelID: tid, IP: fa.host, Port: fa.port, Weight: w})
			runtime.Targets = append(runtime.Targets, tid)
			runtime.Weights = append(runtime.Weights, w)
		}
		rules = append(rules, forwardRender{ID: fr.ID, ListenPort: fr.ListenPort, TargetPort: fr.TargetPort, Proto: fr.Proto, Targets: targets})
		forwards = append(forwards, runtime)
	}

	script := renderForwardNFT(rules)
	if script != b.lastRule {
		if err := nftApplyScript(script); err != nil {
			rep.Errors = append(rep.Errors, "nft apply: "+err.Error())
			log.Printf("[balancer] nft apply failed: %v", err)
		} else {
			b.lastRule = script
			rep.Changed = true
		}
	}
	b.lastForwards = forwards
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

func forwardAddressOf(reg *engine.Registry, st engine.TunnelStatus) (forwardAddr, bool) {
	drv, ok := reg.Driver(st.Engine)
	if !ok {
		return forwardAddr{}, false
	}
	fa, canAddr := drv.(engine.ForwardAddresser)
	if !canAddr {
		return forwardAddr{}, false
	}
	inst := engine.Instance{ // the manager keeps params; status carries ids
		TunnelID:     st.TunnelID,
		TopologyID:   st.TopologyID,
		LocalServer:  st.LocalServer,
		RemoteServer: st.RemoteServer,
	}
	host, port, ok := fa.ForwardAddress(inst)
	if !ok || host == "" {
		return forwardAddr{}, false
	}
	return forwardAddr{host: host, port: port}, true
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
