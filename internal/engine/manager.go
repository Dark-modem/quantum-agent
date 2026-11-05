package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// Manager reconciles desired state into running tunnel instances.
//
// Convergence contract:
//   - an enabled tunnel whose engine is enabled and registered is
//     ensured running with EXACTLY the desired params (changed params
//     are reloaded; if the driver reports ErrRestartRequired the
//     instance is restarted);
//   - tunnels that disappear from desired state, or become disabled, or
//     whose engine becomes disabled, are stopped;
//   - an engine whose last instance stopped is uninstalled (binary and
//     on-disk state removed) so idle engines consume zero resources;
//   - an enabled tunnel naming an unknown or disabled engine never runs
//     and surfaces as an Error entry — the rest of the desired state
//     still applies.
type Manager struct {
	reg *Registry

	mu        sync.Mutex
	running   map[string]runSlot // tunnelID -> running instance
	installed map[string]bool    // engineID -> EnsureBinary done, not yet uninstalled
}

type runSlot struct {
	inst Instance
	drv  Driver
}

// ReconcileResult reports what one Reconcile pass did.
type ReconcileResult struct {
	Started     []string
	Stopped     []string
	Reloaded    []string
	Restarted   []string
	Uninstalled []string
	// Errors carries per-tunnel failures as "tunnel <id>: <cause>".
	// A tunnel that failed to start is NOT counted as running.
	Errors []string
}

// NewManager returns a Manager over reg.
func NewManager(reg *Registry) *Manager {
	return &Manager{
		reg:       reg,
		running:   map[string]runSlot{},
		installed: map[string]bool{},
	}
}

// TunnelStatus is the Manager's view of one desired tunnel.
type TunnelStatus struct {
	TunnelID     string
	TopologyID   string
	LocalServer  string
	RemoteServer string
	Engine       string
	Enabled      bool
	Running      bool
	Health       Health
	Counters     Counters
	Error        string
}

// Status reports every tunnel from the last reconciled desired state.
func (m *Manager) Status() []TunnelStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TunnelStatus, 0, len(m.running))
	for id, slot := range m.running {
		st := TunnelStatus{
			TunnelID:     id,
			TopologyID:   slot.inst.TopologyID,
			LocalServer:  slot.inst.LocalServer,
			RemoteServer: slot.inst.RemoteServer,
			Engine:       slot.drv.ID(),
			Running:      true,
		}
		st.Health = slot.drv.Health(slot.inst)
		st.Counters = slot.drv.Counters(slot.inst)
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TunnelID < out[j].TunnelID })
	return out
}

// RunningCount returns how many instances are currently running.
func (m *Manager) RunningCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.running)
}

// Instance returns a copy of one running instance (with its engine
// params). The balancer needs the params the Status view deliberately
// omits — drivers implement ForwardAddresser against the full instance.
func (m *Manager) Instance(id string) (Instance, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	slot, ok := m.running[id]
	if !ok {
		return Instance{}, false
	}
	return slot.inst, true
}

// Reconcile converges to (engines, tunnels). It is safe to call
// repeatedly with the same desired state (idempotent).
func (m *Manager) Reconcile(ctx context.Context, engines []EngineSpec, tunnels []TunnelSpec) ReconcileResult {
	res := ReconcileResult{}
	enabledEngines := map[string]bool{}
	for _, e := range engines {
		enabledEngines[e.ID] = e.Enabled
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	want := map[string]TunnelSpec{}
	for _, t := range tunnels {
		want[t.ID] = t
	}

	// 1. Stop tunnels that are gone, disabled, or whose engine is
	// disabled/unregistered; uninstall engines that became idle.
	for id, slot := range m.running {
		t, ok := want[id]
		mustStop := !ok || !t.Enabled || !enabledEngines[t.Engine]
		if !mustStop {
			continue
		}
		if err := slot.drv.Stop(slot.inst); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("tunnel %s: stop: %v", id, err))
			continue // keep the slot; a later reconcile retries the stop
		}
		delete(m.running, id)
		res.Stopped = append(res.Stopped, id)
		m.maybeUninstall(ctx, slot.drv, &res)
	}

	// 2. Ensure every enabled tunnel with an enabled, registered engine.
	for _, t := range want {
		if !t.Enabled || !enabledEngines[t.Engine] {
			continue
		}
		if t.ID == "" {
			res.Errors = append(res.Errors, "tunnel <empty id>: desired state must give every tunnel an id")
			continue
		}
		drv, ok := m.reg.Driver(t.Engine)
		if !ok {
			res.Errors = append(res.Errors, fmt.Sprintf("tunnel %s: %s: %q", t.ID, ErrUnknownEngine, t.Engine))
			continue
		}
		inst := Instance{
			TunnelID:     t.ID,
			TopologyID:   t.TopologyID,
			LocalServer:  t.LocalServer,
			RemoteServer: t.RemoteServer,
			Params:       t.Params,
		}
		slot, running := m.running[t.ID]
		if running && slot.drv.ID() != drv.ID() {
			// Engine changed for an existing tunnel: restart on the new driver.
			if err := slot.drv.Stop(slot.inst); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("tunnel %s: stop old engine: %v", t.ID, err))
				continue
			}
			delete(m.running, t.ID)
			res.Stopped = append(res.Stopped, t.ID)
			m.maybeUninstall(ctx, slot.drv, &res)
			running = false
		}
		if !running {
			if !m.installed[drv.ID()] {
				if _, err := drv.EnsureBinary(ctx); err != nil {
					res.Errors = append(res.Errors, fmt.Sprintf("tunnel %s: install engine %s: %v", t.ID, drv.ID(), err))
					continue
				}
				m.installed[drv.ID()] = true
			}
			if err := drv.Start(ctx, inst); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("tunnel %s: start: %v", t.ID, err))
				continue
			}
			m.running[t.ID] = runSlot{inst: inst, drv: drv}
			res.Started = append(res.Started, t.ID)
			continue
		}
		if bytes.Equal(bytes.TrimSpace(slot.inst.Params), bytes.TrimSpace(t.Params)) {
			continue // already running with exactly these params
		}
		next := slot.inst
		next.Params = t.Params
		if err := drv.Reload(next); err != nil {
			if err != ErrRestartRequired {
				res.Errors = append(res.Errors, fmt.Sprintf("tunnel %s: reload: %v", t.ID, err))
				continue
			}
			// Restart path: params cannot be applied live.
			if err := drv.Stop(slot.inst); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("tunnel %s: restart-stop: %v", t.ID, err))
				continue
			}
			delete(m.running, t.ID)
			if err := drv.Start(ctx, next); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("tunnel %s: restart-start: %v", t.ID, err))
				continue
			}
			m.running[t.ID] = runSlot{inst: next, drv: drv}
			res.Restarted = append(res.Restarted, t.ID)
			continue
		}
		m.running[t.ID] = runSlot{inst: next, drv: drv}
		res.Reloaded = append(res.Reloaded, t.ID)
	}

	sort.Strings(res.Started)
	sort.Strings(res.Stopped)
	sort.Strings(res.Reloaded)
	sort.Strings(res.Restarted)
	sort.Strings(res.Uninstalled)
	sort.Strings(res.Errors)
	return res
}

// maybeUninstall uninstalls the engine when no instance of it runs
// anymore. Caller holds m.mu.
func (m *Manager) maybeUninstall(ctx context.Context, drv Driver, res *ReconcileResult) {
	if !m.installed[drv.ID()] {
		return
	}
	for _, slot := range m.running {
		if slot.drv.ID() == drv.ID() {
			return // still in use
		}
	}
	if err := drv.Uninstall(ctx); err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("engine %s: uninstall: %v", drv.ID(), err))
		return
	}
	delete(m.installed, drv.ID())
	res.Uninstalled = append(res.Uninstalled, drv.ID())
}

// paramsEqual reports whether two opaque param documents are identical.
func paramsEqual(a, b json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b))
}
