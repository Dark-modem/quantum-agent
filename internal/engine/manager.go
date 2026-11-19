package engine

import (
	"bytes"
	"context"
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
	// desiredEnabled mirrors the latest Reconcile's EngineSpec flags
	// (Phase 11): a DESIRED-ENABLED engine stays installed even with no
	// instances (install on enable); a desired-disabled engine uninstalls
	// as soon as it is idle.
	desiredEnabled map[string]bool
	// lastEngineError remembers the last install/start failure per
	// engine (cleared on the next success) for the engine-status report.
	lastEngineError map[string]string
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
		reg:             reg,
		running:         map[string]runSlot{},
		installed:       map[string]bool{},
		desiredEnabled:  map[string]bool{},
		lastEngineError: map[string]string{},
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

	m.desiredEnabled = map[string]bool{}
	for _, e := range engines {
		m.desiredEnabled[BaseEngineID(e.ID)] = e.Enabled
	}

	// 0. Install every DESIRED-ENABLED engine now (Phase 11: install on
	// first enable, even before any tunnel uses it) and uninstall
	// desired-disabled engines that no longer run anything.
	for _, id := range sortedDesired(m.desiredEnabled) {
		if !m.desiredEnabled[id] {
			continue
		}
		if m.installed[id] {
			continue
		}
		drv, ok := m.reg.Driver(id)
		if !ok {
			m.noteEngineError(id, fmt.Sprintf("%s: %q", ErrUnknownEngine, id))
			continue
		}
		if _, err := drv.EnsureBinary(ctx); err != nil {
			m.noteEngineError(id, fmt.Sprintf("install: %v", err))
			continue
		}
		m.installed[id] = true
		m.clearEngineError(id)
	}
	for _, id := range m.idleInstalledLocked() {
		if m.desiredEnabled[id] {
			continue
		}
		drv, ok := m.reg.Driver(id)
		if !ok {
			delete(m.installed, id)
			continue
		}
		if err := drv.Uninstall(ctx); err != nil {
			m.noteEngineError(id, fmt.Sprintf("uninstall: %v", err))
			continue
		}
		delete(m.installed, id)
		res.Uninstalled = append(res.Uninstalled, id)
	}

	want := map[string]TunnelSpec{}
	for _, t := range tunnels {
		want[t.ID] = t
	}

	// 1. Stop tunnels that are gone, disabled, or whose engine is
	// disabled/unregistered; uninstall engines that became idle.
	for id, slot := range m.running {
		t, ok := want[id]
		mustStop := !ok || !t.Enabled || !enabledEngines[BaseEngineID(t.Engine)]
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
		if !t.Enabled || !enabledEngines[BaseEngineID(t.Engine)] {
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
			SelfName:     t.SelfName,
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
					m.noteEngineError(BaseEngineID(drv.ID()), fmt.Sprintf("install: %v", err))
					res.Errors = append(res.Errors, fmt.Sprintf("tunnel %s: install engine %s: %v", t.ID, drv.ID(), err))
					continue
				}
				m.installed[drv.ID()] = true
			}
			if err := drv.Start(ctx, inst); err != nil {
				m.noteEngineError(BaseEngineID(drv.ID()), fmt.Sprintf("start tunnel %s: %v", t.ID, err))
				res.Errors = append(res.Errors, fmt.Sprintf("tunnel %s: start: %v", t.ID, err))
				continue
			}
			m.clearEngineError(BaseEngineID(drv.ID()))
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

// ValidateAll runs each enabled spec's driver Validate — the apply-path
// preflight (Manager.Reconcile never calls Validate itself: desired state
// must be validated BEFORE anything starts or reloads). The result is
// aligned with specs: index i carries the error for specs[i]; nil for
// disabled specs, for specs naming an unknown engine (Reconcile owns
// that error) and for specs that validate cleanly.
func (m *Manager) ValidateAll(specs []TunnelSpec) []error {
	out := make([]error, len(specs))
	for i, t := range specs {
		if !t.Enabled {
			continue
		}
		drv, ok := m.reg.Driver(t.Engine)
		if !ok {
			continue
		}
		if err := drv.Validate(t.Params); err != nil {
			out[i] = err
		}
	}
	return out
}

// EngineRegistered reports whether the engine id resolves to a driver in
// the Manager's registry (base@companion ids map to the base driver).
// The apply-path preflight uses it to skip tunnels the Manager itself
// would refuse as unknown-engine.
func (m *Manager) EngineRegistered(id string) bool {
	_, ok := m.reg.Driver(id)
	return ok
}

// maybeUninstall uninstalls the engine when no instance of it runs
// anymore — unless the engine is DESIRED-ENABLED (Phase 11: install on
// enable keeps the binary ready). Caller holds m.mu.
func (m *Manager) maybeUninstall(ctx context.Context, drv Driver, res *ReconcileResult) {
	if !m.installed[drv.ID()] {
		return
	}
	if m.desiredEnabled[BaseEngineID(drv.ID())] {
		return // desired-enabled: stay installed for the next tunnel
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

// sortedDesired is a deterministic iteration order for the desired map.
func sortedDesired(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// idleInstalledLocked lists installed engine ids with no running
// instance. Caller holds m.mu.
func (m *Manager) idleInstalledLocked() []string {
	busy := map[string]bool{}
	for _, slot := range m.running {
		busy[BaseEngineID(slot.drv.ID())] = true
	}
	var out []string
	for id := range m.installed {
		if !busy[id] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// noteEngineError / clearEngineError maintain the per-engine last error
// shown in the engine-status report. Caller holds m.mu.
func (m *Manager) noteEngineError(engineID, text string) {
	m.lastEngineError[engineID] = text
}

func (m *Manager) clearEngineError(engineID string) {
	delete(m.lastEngineError, engineID)
}

// EngineStatus is one engine's aggregated view for the v2 report.
type EngineStatus struct {
	Engine    string // the registry id the manager knows it by
	Installed bool
	Instances int
	Healthy   int
	Down      int // running but Health.OK == false
	LastError string
}

// EnginesStatus aggregates the running slots per engine and the
// installed/last-error bookkeeping. The order is by engine id.
func (m *Manager) EnginesStatus() []EngineStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	byID := map[string]*EngineStatus{}
	get := func(id string) *EngineStatus {
		e := byID[id]
		if e == nil {
			e = &EngineStatus{Engine: id}
			byID[id] = e
		}
		return e
	}
	for id := range m.installed {
		get(id).Installed = true
	}
	for id, text := range m.lastEngineError {
		get(id).LastError = text
	}
	for _, slot := range m.running {
		e := get(BaseEngineID(slot.drv.ID()))
		e.Instances++
		if slot.drv.Health(slot.inst).OK {
			e.Healthy++
		} else {
			e.Down++
		}
	}
	out := make([]EngineStatus, 0, len(byID))
	for _, e := range byID {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Engine < out[j].Engine })
	return out
}

// ProcessPIDs asks every running driver that implements ProcessInfoer
// for its instance's process PIDs: tunnelID -> PIDs. Tunnels whose
// engine has no processes (kernel-only, or between restarts) are absent.
func (m *Manager) ProcessPIDs() map[string][]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string][]int{}
	for id, slot := range m.running {
		pi, ok := slot.drv.(ProcessInfoer)
		if !ok {
			continue
		}
		pids := pi.ProcessPIDs(slot.inst)
		if len(pids) > 0 {
			out[id] = pids
		}
	}
	return out
}

// EngineInstalled reports whether the engine currently has its binary
// installed (EnsureBinary done, not yet uninstalled).
func (m *Manager) EngineInstalled(engineID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.installed[engineID]
}

// EngineDesired reports the latest desired enabled-flag for an engine
// (false before the first Reconcile).
func (m *Manager) EngineDesired(engineID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.desiredEnabled[engineID]
}
