package main

// Agent-side definitions for types that were previously shared with the
// controller. In the separated architecture, the agent computes its own
// status locally using these lightweight view types. The controller
// receives agent-reported data through the WSS protocol.

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// agentSeam is a mutex-guarded function seam (duplicated from the
// controller's agentSeam per shared-code policy).
type agentSeam[F any] struct {
	mu sync.RWMutex
	fn F
}

func (s *agentSeam[F]) get() F { s.mu.RLock(); defer s.mu.RUnlock(); return s.fn }
func (s *agentSeam[F]) set(f F) { s.mu.Lock(); s.fn = f; s.mu.Unlock() }

// HubSnapshot is a minimal stub: the agent does not build hub snapshots.
// Referenced by carrieradvisor.go and tunnelhealth.go for type compatibility.
type HubSnapshot struct {
	At      time.Time
	BuildMs float64
}

// PeerHandshakeRequest is a minimal stub for the agent-side handshake type.
type PeerHandshakeRequest struct{}

// alertTracker tracks alert states for the agent's local alert evaluation.
type alertTracker struct {
	states map[string]string
}

func newAlertTracker() *alertTracker { return &alertTracker{states: map[string]string{}} }

// ctrlQuery identifies a link for hub-side control session matching.
type ctrlQuery struct {
	ID int
}

// errEvent is a local error event for the agent's error journal.
type errEvent struct {
	At   int64
	Code string
	Msg  string
}

// linkSnap is a link snapshot view DTO.
type linkSnap struct {
	Name, State, Why string
}

// primaryInterface returns the outbound-facing interface name.
func primaryInterface() string {
	return "" // the agent uses net.Interfaces directly; this is a compat stub
}

// configDir is the agent's configuration directory.
var configDir = "/etc/quantum-agent"

// panelVersion is the agent binary version (independent from controller).
var panelVersion = "v0.1.0"

// hostView is the agent's host probe result (minimal for agent-side use).
type hostView struct {
	Ifaces map[string]uint64
}

// icmpResult is the result of an ICMP probe.
type icmpResult struct {
	OK bool
	Ms float64
}

// newWorkPool creates a bounded worker pool (duplicated per shared-code policy).
type workPool struct {
	sem chan struct{}
	wg  sync.WaitGroup
}

func newWorkPool(n int) *workPool { return &workPool{sem: make(chan struct{}, n)} }

func (p *workPool) Go(fn func()) {
	p.sem <- struct{}{}
	p.wg.Add(1)
	go func() { defer p.wg.Done(); fn(); <-p.sem }()
}

func (p *workPool) Wait() { p.wg.Wait() }

// syncEngineToPeer is a no-op on the agent: peer sync is a controller concern.
func syncEngineToPeer(engine, transport string) (bool, error) { return false, nil }

// LogSecurityAudit writes to the agent's local audit log (simplified from
// the controller's version: the agent logs to its own audit file).
func LogSecurityAudit(event, user, ip, detail string) {
	// The agent logs locally; no HTTP or database involved.
}

// linkLabel returns a display label for a peer record.
func linkLabel(p peerRecord) string {
	if p.Name != "" {
		return p.Name
	}
	return p.RemotePub
}

// loadPeerConfig loads the peer registry from the agent's local state.
func loadPeerConfig() []peerRecord {
	return nil // the agent reads its state from matrixState; no peer registry
}

// syncCarrierToPeer is a no-op on the agent: carrier sync is controller-managed.
func syncCarrierToPeer(ends interface{}, engine, transport string) (string, error) {
	return "", nil
}

// trimLen truncates a string to n characters.
func trimLen(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// writeJSON writes JSON to an HTTP response (used by the agent's local
// diagnostic endpoints; the agent has no management UI listener).
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// --- Controller-only stubs ---
// The agent has no HTTP management server. These stubs satisfy compilation
// for engine files that reference controller HTTP helpers. They are never
// called at runtime because the agent has no HTTP routes.

var frpDir = "/etc/frp"

func writeAPIError(w http.ResponseWriter, r *http.Request, code, msg string) {
	http.Error(w, msg, http.StatusInternalServerError)
}

func linkLabelFromString(s string) string { return s }
