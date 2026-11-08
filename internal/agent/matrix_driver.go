package agent

// MatrixDriver wraps the existing Matrix/tinc code (matrix.go,
// agent_matrix_local.go) as an engine.Driver — the first real engine
// behind the Phase-1A interface. It is a thin adapter: provisioning
// (matrixSetup, bundles, host files) stays with the v1 desired-state
// path, and this driver owns only the per-tunnel lifecycle the engine
// framework needs (start/stop/reload a Matrix instance, health, wire
// counters).
//
// Counters: wire bytes come from the instance's qmx interface counters
// (/proc/net/dev). Matrix/tinc does not expose payload bytes separately
// yet, so PayloadKnown is false until the engine grows its own payload
// accounting — the panel never invents a number from a missing one.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// MatrixDriver implements engine.Driver over the Matrix instances.
type MatrixDriver struct{}

// NewMatrixDriver returns the Matrix engine driver.
func NewMatrixDriver() *MatrixDriver { return &MatrixDriver{} }

// matrixDriverParams is the engine_params shape the Matrix driver
// accepts. It is deliberately the same "instance" selector the v1
// matrix.* commands use.
type matrixDriverParams struct {
	Instance string `json:"instance"`
}

// ID implements engine.Driver.
func (d *MatrixDriver) ID() string { return "matrix" }

// Validate implements engine.Driver: shape check only, no side effects.
// The instance does not have to exist yet — provisioning happens through
// the desired-state path before an instance can start.
func (d *MatrixDriver) Validate(params json.RawMessage) error {
	var p matrixDriverParams
	if len(params) == 0 {
		return errors.New("matrix: engine_params required (instance)")
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("matrix: engine_params: %w", err)
	}
	in := matrixInstance{ID: strings.TrimSpace(p.Instance)}
	if !in.valid() {
		return fmt.Errorf("matrix: invalid instance %q", p.Instance)
	}
	return nil
}

// EnsureBinary implements engine.Driver: the Matrix binaries (tinc) are
// provisioned by the matrixSetup desired-state path, so there is nothing
// to download here.
func (d *MatrixDriver) EnsureBinary(ctx context.Context) (string, error) {
	return "", nil
}

// Start implements engine.Driver: same semantics as the matrix.start
// command (the unit stays enabled; reconciliation brings it back).
func (d *MatrixDriver) Start(ctx context.Context, inst engine.Instance) error {
	return d.power(agentCmdMatrixStart, inst)
}

// Stop implements engine.Driver: stop only — the unit stays enabled so
// the state survives agent restarts (matching the v1 command semantics).
func (d *MatrixDriver) Stop(inst engine.Instance) error {
	return d.power(agentCmdMatrixStop, inst)
}

// Reload implements engine.Driver: a Matrix instance applies its config
// by restarting, so reload == restart.
func (d *MatrixDriver) Reload(inst engine.Instance) error {
	return d.power(agentCmdMatrixRestart, inst)
}

func (d *MatrixDriver) power(op string, inst engine.Instance) error {
	var p matrixDriverParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("matrix: engine_params: %w", err)
	}
	res := agentRunMatrixPower(op, map[string]string{"instance": strings.TrimSpace(p.Instance)}, agentCommandResult{})
	if !res.OK {
		if res.Error == "" {
			res.Error = "matrix power op failed"
		}
		return errors.New(res.Error)
	}
	return nil
}

// Health implements engine.Driver: the systemd unit state AND the latest
// rolling mesh probe (agent_health.go). A dead mesh behind an active unit
// must not report OK — the balancer's "engine" probe and StateReportV2
// both consume this view (Phase-4: a black-holed tunnel was reported
// healthy because only the unit state was checked). Without a probe
// window yet (fresh boot, loop not started) the unit state alone decides,
// so this never reports worse than before.
func (d *MatrixDriver) Health(inst engine.Instance) engine.Health {
	var p matrixDriverParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return engine.Health{OK: false, Detail: "matrix: engine_params unreadable", LatencyMs: -1}
	}
	in := matrixInstance{ID: strings.TrimSpace(p.Instance)}
	if !in.valid() {
		return engine.Health{OK: false, Detail: fmt.Sprintf("matrix: invalid instance %q", p.Instance), LatencyMs: -1}
	}
	st := loadMatrixInstance(in)
	if !st.Enabled || st.Network != in.network() {
		return engine.Health{OK: false, Detail: "no owned Matrix network on instance " + in.ID, LatencyMs: -1}
	}
	if !matrixServiceActive(in) {
		return engine.Health{OK: false, Detail: "unit not active", LatencyMs: -1}
	}
	// Unit active — consult the latest probe window when one exists.
	agentHealthMu.Lock()
	w, has := agentHealthLatest[in.ID]
	agentHealthMu.Unlock()
	return agentHealthWithWindow("unit active", w, has)
}

// agentHealthWithWindow combines the "unit active" verdict with the latest
// rolling probe window. Pure so the decision table stays hermetically
// testable; MatrixDriver.Health is the only caller.
func agentHealthWithWindow(detail string, w agentTunnelHealth, has bool) engine.Health {
	if !has {
		// No window yet (fresh boot, probe loop not started): the unit
		// state alone decides — never worse than the pre-Phase-4 view.
		return engine.Health{OK: true, Detail: detail, LatencyMs: -1}
	}
	if !w.Reachable || w.Quality == "down" {
		return engine.Health{OK: false, Detail: fmt.Sprintf("%s; mesh unreachable (%s, loss %.0f%%)", detail, w.Quality, w.LossPct), LatencyMs: -1}
	}
	return engine.Health{OK: true, Detail: detail + "; mesh " + w.Quality, LatencyMs: w.LatencyMs}
}

// Counters implements engine.Driver: wire bytes from the instance's
// qmx interface; payload bytes are not engine-accounted yet.
func (d *MatrixDriver) Counters(inst engine.Instance) engine.Counters {
	var p matrixDriverParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return engine.Counters{}
	}
	in := matrixInstance{ID: strings.TrimSpace(p.Instance)}
	if !in.valid() {
		return engine.Counters{}
	}
	data, err := agentReadNetDev()
	if err != nil {
		return engine.Counters{}
	}
	c, ok := agentParseNetDev(data)[in.iface()]
	if !ok {
		return engine.Counters{}
	}
	// Wire counters are known; payload accounting is engine-side future
	// work (tinc does not separate it).
	return engine.Counters{WireRx: c.Rx, WireTx: c.Tx, WireKnown: true}
}

// Uninstall implements engine.Driver: a no-op — Matrix state is
// controller-driven (desired apply/remove), and removing tinc would
// break provisioning for re-enabled instances.
func (d *MatrixDriver) Uninstall(ctx context.Context) error { return nil }

// Compile-time check.
var _ engine.Driver = (*MatrixDriver)(nil)

// agentV2TestDriver, when set (tests only), is registered alongside the
// builtin drivers so hermetic tests can drive the Manager without host
// access. Never set in production builds.
var agentV2TestDriver engine.Driver

// NewAgentEngines returns the agent's engine registry with every builtin
// driver registered. Callers (the run loop, the lab) add their own
// drivers on top.
func NewAgentEngines() (*engine.Registry, error) {
	reg := engine.NewRegistry()
	if err := reg.Register(NewMatrixDriver()); err != nil {
		return nil, err
	}
	if err := reg.Register(NewFRPDriver()); err != nil {
		return nil, err
	}
	if err := reg.Register(NewBackhaulDriver()); err != nil {
		return nil, err
	}
	if err := reg.Register(NewXrayDriver()); err != nil {
		return nil, err
	}
	if err := reg.Register(NewWgDriver()); err != nil {
		return nil, err
	}
	if err := reg.Register(NewWstDriver()); err != nil {
		return nil, err
	}
	if err := reg.Register(NewChiselDriver()); err != nil {
		return nil, err
	}
	if err := reg.Register(NewGostDriver()); err != nil {
		return nil, err
	}
	if err := RegisterLabEngines(reg); err != nil {
		return nil, err
	}
	if agentV2TestDriver != nil {
		if err := reg.Register(agentV2TestDriver); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

// matrixDriverOnce guards the package-level registry used by tests.
var (
	matrixDriverRegOnce sync.Once
	matrixDriverReg     *engine.Registry
)

// AgentEngines returns the shared builtin engine registry.
func AgentEngines() (*engine.Registry, error) {
	matrixDriverRegOnce.Do(func() {
		matrixDriverReg, _ = NewAgentEngines()
	})
	return matrixDriverReg, nil
}

// ForwardAddress implements the optional engine.ForwardAddresser
// capability: new connections balanced onto a Matrix tunnel are
// delivered to the instance's mesh address on the foreign side (the hub
// IP for a node, the own mesh IP is NOT useful — a hub forwards to its
// nodes, so the address is the hub's mesh IP when we are a node, or the
// first registered node's mesh IP when we are the hub). The instance
// state carries what pairing established; unknown → ok=false.
func (d *MatrixDriver) ForwardAddress(inst engine.Instance) (string, int, bool) {
	var p matrixDriverParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return "", 0, false
	}
	in := matrixInstance{ID: strings.TrimSpace(p.Instance)}
	if !in.valid() {
		return "", 0, false
	}
	st := loadMatrixInstance(in)
	if !st.Enabled || st.Network != in.network() {
		return "", 0, false
	}
	if st.Role == "node" {
		if st.Addr == "" {
			return "", 0, false
		}
		return st.Addr, 0, true
	}
	// Hub: forward to the first reachable registered node's mesh IP.
	for _, peer := range st.Peers {
		if peer.IP != "" {
			return peer.IP, 0, true
		}
	}
	return "", 0, false
}

// Describe implements the optional engine.Describer capability
// (PROTOCOL-REQUESTS R3): the catalog entry the panel stores per agent.
// The params_schema is a hint document (the engine owns its params).
func (d *MatrixDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{
		ID:           "matrix",
		Version:      panelVersion,
		ParamsSchema: json.RawMessage(`{"instance":"matrix|matrix2|… (required)"}`),
	}
}
