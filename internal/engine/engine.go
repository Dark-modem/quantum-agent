// Package engine is the Quantum agent's tunnel-engine framework: the
// Driver contract every tunnel engine implements, the Registry that maps
// engine IDs to drivers, and the Manager that reconciles desired state
// into running instances.
//
// The guiding rule is that agents stay light: an engine with zero
// running instances consumes zero resources — no processes, no
// goroutines, no binary on disk (EnsureBinary downloads on first
// enable; Uninstall removes on last disable).
//
// Implementations live outside this package (the Matrix driver in
// package agent wraps the existing Matrix/tinc code); this package
// knows only the interface. See 00-ADMIN/ENGINE-GUIDE.md before writing
// a new driver.

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Instance is one tunnel instance an engine runs. Params is the opaque
// engine_params JSON from desired state: only the named engine validates
// and interprets it.
type Instance struct {
	TunnelID     string
	TopologyID   string
	LocalServer  string
	RemoteServer string
	Params       json.RawMessage
}

// Health is a driver's instantaneous view of one instance.
type Health struct {
	OK        bool
	Detail    string // short diagnostic text only, never secrets
	LatencyMs float64
	Since     time.Time // when the current state began; zero = unknown
}

// Counters carries BOTH byte views for one instance. Quantum statistics
// are always real bytes — no coefficient is ever applied here. Wire
// bytes come from the carrier interface counters; payload bytes from the
// engine's own accounting. The two Known flags are independent: an
// engine may know one and not the other.
type Counters struct {
	WireRx       uint64
	WireTx       uint64
	WireKnown    bool
	PayloadRx    uint64
	PayloadTx    uint64
	PayloadKnown bool
}

// Driver is one tunnel engine. Implementations must be safe for
// concurrent use.
type Driver interface {
	// ID is the engine name used in desired state ("matrix", …).
	ID() string

	// Validate checks engine_params without side effects. It must
	// reject anything the engine cannot honor — desired state is
	// validated before anything runs.
	Validate(params json.RawMessage) error

	// EnsureBinary makes the engine binary available and returns its
	// path. The Manager calls it only when the first instance of the
	// engine is about to start (Install on demand). Implementations
	// must be idempotent and must verify what they download:
	// sha256 always, and an ed25519 signature when the engine pins a
	// signing key (see VerifyArtifact). Failing closed is correct.
	EnsureBinary(ctx context.Context) (string, error)

	// Start starts one tunnel instance. It must be idempotent per
	// TunnelID (starting a running instance is a no-op or a reload).
	Start(ctx context.Context, inst Instance) error

	// Stop stops one tunnel instance and cleans up its runtime state.
	// Stopping a non-running instance is a no-op.
	Stop(inst Instance) error

	// Reload applies changed Params to a running instance. Returning
	// ErrRestartRequired makes the Manager stop+start instead. Reload
	// must not leave the instance running with the OLD params.
	Reload(inst Instance) error

	// Health reports the instance's current health.
	Health(inst Instance) Health

	// Counters reports the instance's wire and payload bytes.
	Counters(inst Instance) Counters

	// Uninstall removes the engine's binary and on-disk state. The
	// Manager calls it only after the engine's last instance stopped.
	Uninstall(ctx context.Context) error
}

// Sentinel errors drivers and the Manager return.
var (
	// ErrRestartRequired tells the Manager the parameter change cannot
	// be applied live and the instance must be stopped and started.
	ErrRestartRequired = errors.New("engine: restart required")

	// ErrUnknownEngine is returned when desired state names an engine
	// no driver is registered for.
	ErrUnknownEngine = errors.New("engine: unknown engine")
)

// TunnelSpec is one desired tunnel instance. It mirrors the protocol's
// v2 TunnelSpec (the agent adapts one into the other) so this package
// stays dependency-free.
type TunnelSpec struct {
	ID           string
	TopologyID   string
	LocalServer  string
	RemoteServer string
	Engine       string
	Params       json.RawMessage
	Enabled      bool
}

// EngineSpec enables or disables a whole engine.
type EngineSpec struct {
	ID      string
	Enabled bool
}

// ForwardAddresser is an optional capability: engines whose tunnels can
// carry forwarded service traffic report where new connections should be
// delivered (e.g. the remote mesh address for L3 tunnels). The local
// balancer type-asserts for it; engines without it are excluded from
// balancing groups.
type ForwardAddresser interface {
	// ForwardAddress returns the delivery target for a tunnel instance.
	// ok=false when the address is not currently known.
	ForwardAddress(inst Instance) (host string, port int, ok bool)
}
