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

// Health implements engine.Driver.
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
	ok := matrixServiceActive(in)
	detail := "unit active"
	if !ok {
		detail = "unit not active"
	}
	return engine.Health{OK: ok, Detail: detail, LatencyMs: -1}
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

// NewAgentEngines returns the agent's engine registry with every builtin
// driver registered. Callers (the run loop, the lab) add their own
// drivers on top.
func NewAgentEngines() (*engine.Registry, error) {
	reg := engine.NewRegistry()
	if err := reg.Register(NewMatrixDriver()); err != nil {
		return nil, err
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
