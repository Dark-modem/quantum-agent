package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// FakeEngine is a scripted in-memory Driver for tests and the lab. It
// records every call, keeps no processes, and lets tests decide
// validation outcomes, health and counters. It never touches the host.
type FakeEngine struct {
	mu           sync.Mutex
	id           string
	validateErr  map[string]error // params-key -> error (empty key: default)
	startErr     map[string]error // tunnel -> error
	reloadErr    map[string]error // tunnel -> error (ErrRestartRequired triggers manager restart)
	stopErr      map[string]error // tunnel -> error
	uninstallErr error
	ensureErr    error // EnsureBinary failure (Phase 11 status tests)

	ensureCalls    int
	startCalls     map[string]int
	stopCalls      map[string]int
	reloadCalls    map[string]int
	uninstallCalls int
	running        map[string]Instance
	binaryPath     string

	health   map[string]Health
	counters map[string]Counters

	forwardAddr map[string]string
	forwardPort map[string]int

	describeVersion string
	describeSchema  json.RawMessage
}

// NewFakeEngine returns a healthy, empty FakeEngine with the given ID.
func NewFakeEngine(id string) *FakeEngine {
	return &FakeEngine{
		id:          id,
		validateErr: map[string]error{},
		startErr:    map[string]error{},
		reloadErr:   map[string]error{},
		stopErr:     map[string]error{},
		startCalls:  map[string]int{},
		stopCalls:   map[string]int{},
		reloadCalls: map[string]int{},
		running:     map[string]Instance{},
		health:      map[string]Health{},
		counters:    map[string]Counters{},
		forwardAddr: map[string]string{},
		forwardPort: map[string]int{},
		binaryPath:  "/nonexistent/" + id,
	}
}

// ID implements Driver.
func (f *FakeEngine) ID() string { return f.id }

// FailValidate scripts Validate to fail for params containing substr
// (or always, with substr "").
func (f *FakeEngine) FailValidate(substr string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validateErr[substr] = err
}

// FailStart scripts Start to fail for one tunnel.
func (f *FakeEngine) FailStart(tunnelID string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startErr[tunnelID] = err
}

// FailReload scripts Reload to fail for one tunnel (use
// ErrRestartRequired to exercise the manager's restart path).
func (f *FakeEngine) FailReload(tunnelID string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloadErr[tunnelID] = err
}

// FailStop scripts Stop to fail for one tunnel.
func (f *FakeEngine) FailStop(tunnelID string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopErr[tunnelID] = err
}

// FailUninstall scripts Uninstall to fail once scripted.
func (f *FakeEngine) FailUninstall(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uninstallErr = err
}

// SetHealth scripts Health for one tunnel.
func (f *FakeEngine) SetHealth(tunnelID string, h Health) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.health[tunnelID] = h
}

// SetCounters scripts Counters for one tunnel.
func (f *FakeEngine) SetCounters(tunnelID string, c Counters) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counters[tunnelID] = c
}

// Calls reports the recorded call counts.
func (f *FakeEngine) Calls() (ensure, uninstall int, started, stopped, reloaded []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, n := range f.startCalls {
		for i := 0; i < n; i++ {
			started = append(started, id)
		}
	}
	for id, n := range f.stopCalls {
		for i := 0; i < n; i++ {
			stopped = append(stopped, id)
		}
	}
	for id, n := range f.reloadCalls {
		for i := 0; i < n; i++ {
			reloaded = append(reloaded, id)
		}
	}
	sort.Strings(started)
	sort.Strings(stopped)
	sort.Strings(reloaded)
	return f.ensureCalls, f.uninstallCalls, started, stopped, reloaded
}

// Running lists currently running tunnel IDs, sorted.
func (f *FakeEngine) Running() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.running))
	for id := range f.running {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// --- Driver interface ---

// Validate implements Driver: it fails when a scripted error matches.
func (f *FakeEngine) Validate(params json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for substr, err := range f.validateErr {
		if substr == "" || strings.Contains(strings.ToLower(string(params)), strings.ToLower(substr)) {
			return err
		}
	}
	return nil
}

// EnsureBinary implements Driver: it counts calls and succeeds.
func (f *FakeEngine) EnsureBinary(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureCalls++
	if f.ensureErr != nil {
		return "", f.ensureErr
	}
	return f.binaryPath, nil
}

// SetEnsureError scripts the EnsureBinary result (nil restores success).
func (f *FakeEngine) SetEnsureError(err error) {
	f.mu.Lock()
	f.ensureErr = err
	f.mu.Unlock()
}

// SetStartError scripts one tunnel's Start result (nil restores success).
func (f *FakeEngine) SetStartError(tunnelID string, err error) {
	f.mu.Lock()
	if err == nil {
		delete(f.startErr, tunnelID)
	} else {
		f.startErr[tunnelID] = err
	}
	f.mu.Unlock()
}

// Start implements Driver.
func (f *FakeEngine) Start(ctx context.Context, inst Instance) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalls[inst.TunnelID]++
	if err := f.startErr[inst.TunnelID]; err != nil {
		return err
	}
	f.running[inst.TunnelID] = inst
	return nil
}

// Stop implements Driver.
func (f *FakeEngine) Stop(inst Instance) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls[inst.TunnelID]++
	if err := f.stopErr[inst.TunnelID]; err != nil {
		return err
	}
	delete(f.running, inst.TunnelID)
	return nil
}

// Reload implements Driver: success updates the stored params.
func (f *FakeEngine) Reload(inst Instance) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloadCalls[inst.TunnelID]++
	if err := f.reloadErr[inst.TunnelID]; err != nil {
		return err
	}
	if _, ok := f.running[inst.TunnelID]; ok {
		f.running[inst.TunnelID] = inst
	}
	return nil
}

// Health implements Driver.
func (f *FakeEngine) Health(inst Instance) Health {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h, ok := f.health[inst.TunnelID]; ok {
		return h
	}
	_, running := f.running[inst.TunnelID]
	return Health{OK: running, Detail: fmt.Sprintf("fake engine %s", f.id), LatencyMs: -1}
}

// Counters implements Driver.
func (f *FakeEngine) Counters(inst Instance) Counters {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counters[inst.TunnelID]
}

// Uninstall implements Driver.
func (f *FakeEngine) Uninstall(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uninstallCalls++
	if f.uninstallErr != nil {
		err := f.uninstallErr
		f.uninstallErr = nil // one-shot, so tests do not loop on it
		return err
	}
	f.running = map[string]Instance{}
	return nil
}

// Compile-time check that FakeEngine really is a Driver.
var _ Driver = (*FakeEngine)(nil)

// SetForwardAddress scripts the ForwardAddresser capability for one
// tunnel (empty host removes it).
func (f *FakeEngine) SetForwardAddress(tunnelID, host string, port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if host == "" {
		delete(f.forwardAddr, tunnelID)
		delete(f.forwardPort, tunnelID)
		return
	}
	f.forwardAddr[tunnelID] = host
	f.forwardPort[tunnelID] = port
}

// ForwardAddress implements the optional ForwardAddresser capability.
func (f *FakeEngine) ForwardAddress(inst Instance) (string, int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.forwardAddr[inst.TunnelID]
	if !ok {
		return "", 0, false
	}
	return h, f.forwardPort[inst.TunnelID], true
}

// SetDescribe scripts the Describer capability.
func (f *FakeEngine) SetDescribe(version string, schema json.RawMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.describeVersion = version
	f.describeSchema = schema
}

// Describe implements the optional Describer capability.
func (f *FakeEngine) Describe() EngineInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return EngineInfo{ID: f.id, Version: f.describeVersion, ParamsSchema: f.describeSchema}
}
