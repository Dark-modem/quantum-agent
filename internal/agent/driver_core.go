package agent

// driver_core.go — the shared driver-framework core (REFACTOR-PLAN-AGENT
// §6.A1). Every process driver used to hand-write the same boilerplate:
// a mutex + runs map, the per-instance stop channel / process handle /
// config-path state, and token-identical Stop / Reload / Uninstall
// bodies plus per-driver copies of params-equal and host:port parsing.
// This file is the ONE copy of those shapes, generic over the concrete
// instance-state type.
//
// PURE REFACTOR (stage A1 rules): every helper reproduces the pre-existing
// per-driver behavior exactly — the stop-then-kill order, the
// "reload on stopped instance" error shape, the idempotent-Uninstall loop
// and the canonical-JSON params comparison are unchanged. Registry IDs,
// counters semantics, nft/iptables chain names and rendered configs are
// NOT part of this file; they stay byte-identical inside the drivers.
//
// One deliberate non-goal: the Start idempotency block stays inline in
// each driver — it reads driver params/roles and differs in real ways
// (wg returns early instead of restarting; frp checks its raw proc field
// before the accessor existed).

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// ---- the generic per-tunnel instance table -------------------------------

// instTable is the per-driver runs map with its mutex, generic over the
// concrete instance-state type. The methods mirror the exact lock
// discipline the drivers used inline: peek (lookup without delete) for
// Health/Counters/Reload/ProcessPIDs, take (lookup+delete) for Stop.
type instTable[T any] struct {
	mu   sync.Mutex
	runs map[string]*T
}

func newInstTable[T any]() *instTable[T] {
	return &instTable[T]{runs: map[string]*T{}}
}

func (t *instTable[T]) peek(tunnelID string) *T {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.runs[tunnelID]
}

func (t *instTable[T]) take(tunnelID string) *T {
	t.mu.Lock()
	st := t.runs[tunnelID]
	delete(t.runs, tunnelID)
	t.mu.Unlock()
	return st
}

func (t *instTable[T]) put(tunnelID string, st *T) {
	t.mu.Lock()
	t.runs[tunnelID] = st
	t.mu.Unlock()
}

// len reports the number of RUNNING instances (tests assert on it).
func (t *instTable[T]) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.runs)
}

// ids snapshots the running tunnel ids (the Uninstall stop-each loop —
// map order was and stays unspecified).
func (t *instTable[T]) ids() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.runs))
	for id := range t.runs {
		out = append(out, id)
	}
	return out
}

// ---- the embedded per-instance base state -------------------------------

// engineInst is the per-instance base state every process driver embeds
// by value: the supervisor's stop channel, the process handle
// (mutex-guarded — engineSupervise's setProc races Stop's read), the
// rendered config/args file path (removed on Stop; "" for args-form
// drivers like gost that never write one) and the binary path (the
// supervisor's respawn target). It satisfies engineProcState.
type engineInst struct {
	mu      sync.Mutex
	proc    frpProcess
	stop    chan struct{}
	cfg     string
	binPath string
}

func (e *engineInst) setProc(p frpProcess) { e.mu.Lock(); e.proc = p; e.mu.Unlock() }

func (e *engineInst) current() frpProcess {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.proc
}

// ---- the shared Stop / Uninstall shapes ---------------------------------

// engineStopInst tears one instance down in the exact shared order every
// driver used: the stop channel closes FIRST (the supervisor must never
// resurrect a deliberately stopped process), then the process is
// SIGINT/killed with the capped grace periods, then the rendered config
// file is removed (args-form drivers keep cfg empty — nothing to
// remove), then the driver-specific teardown hook runs (wire-accounting
// rules, the ctunnel relay/interface, wg's companion). st == nil (Stop
// of a non-running instance) is a no-op.
func engineStopInst(st *engineInst, teardown func()) {
	if st == nil {
		return
	}
	close(st.stop)
	frpProcStop(st.current())
	if st.cfg != "" {
		_ = os.Remove(st.cfg)
	}
	if teardown != nil {
		teardown()
	}
}

// engineUninstallAll is the shared Uninstall shape: snapshot the running
// ids, Stop each, then remove the engine's whole state dir. Stop results
// and the RemoveAll result are ignored exactly as before — Uninstall
// never fails (the Manager calls it only after the last instance
// stopped).
func engineUninstallAll[T any](t *instTable[T], stop func(tunnelID string), dir string) {
	for _, id := range t.ids() {
		stop(id)
	}
	_ = os.RemoveAll(dir)
}

// ---- the shared Reload / params-equal shapes ----------------------------

// engineReloadParams parses engine_params for Reload with the shared
// error shape ("<engine>: engine_params: <err>").
func engineReloadParams[TParams any](engineID string, raw json.RawMessage) (TParams, error) {
	var p TParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("%s: engine_params: %w", engineID, err)
	}
	return p, nil
}

// engineReloadMissing is the shared Reload error for a non-running
// instance ("<engine>: reload on stopped instance \"<id>\"").
func engineReloadMissing(engineID, tunnelID string) error {
	return fmt.Errorf("%s: reload on stopped instance %q", engineID, tunnelID)
}

// engineReload is the shared Reload shape of the restart-only drivers:
// parse the incoming params, fail on a non-running instance, no-op when
// the params are equal, engine.ErrRestartRequired otherwise. Drivers
// with live-apply semantics (wg's peer_public) do NOT use it.
func engineReload[TInst any, TParams any](t *instTable[TInst], engineID, tunnelID string,
	raw json.RawMessage, params func(*TInst) TParams, equal func(TParams, TParams) bool) error {
	p, err := engineReloadParams[TParams](engineID, raw)
	if err != nil {
		return err
	}
	st := t.peek(tunnelID)
	if st == nil {
		return engineReloadMissing(engineID, tunnelID)
	}
	if equal(params(st), p) {
		return nil
	}
	return engine.ErrRestartRequired
}

// engineParamsEqual is the shared Reload/Start no-op comparison: params
// compare through their canonical JSON (key-order independent,
// constant-time). Every engine param struct marshals without error
// (typed fields only), and the bodies this replaces (mustJSON string
// compare, json.Marshal + ConstantTimeCompare) return the same boolean
// for every value these types can carry. wg is the one exception — its
// comparison case-folds and stays local.
func engineParamsEqual[TParams any](a, b TParams) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

// ---- the shared host:port parser ----------------------------------------

// enginePortOf extracts the port from a "host:port" address (0 when
// absent or not a decimal port in range). Byte-identical to the
// backhaulPortOf / gostPortOf / ratholePortOf bodies it replaces.
func enginePortOf(addr string) int {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return 0
	}
	n := 0
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return 0
		}
		n = n*10 + int(port[i]-'0')
		if n > 65535 {
			return 0
		}
	}
	return n
}
