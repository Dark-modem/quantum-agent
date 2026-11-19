package agent

// preflight.go — the apply-path preflight for v2 desired state (phase14
// ports). DesiredV2 previously went straight into Manager.Reconcile: a
// tunnel whose engine_params named a port something else already held
// failed inside the driver's Start (a bind error after the fact), and
// engine_params were never run through the driver's Validate at all (the
// Manager contract does not call it). Both checks now run here, BEFORE
// anything starts:
//
//   - every enabled tunnel spec whose engine is registered and
//     desired-enabled runs drv.Validate(params) (via Manager.ValidateAll)
//     and a port scan of its engine_params: integer fields whose name
//     contains "port" (case-insensitive; one top level + one nested map
//     level) are checked with portAvailabilityCheck on BOTH transports
//     (engine_params do not name a transport; a listener on either is a
//     bind hazard);
//   - every enabled forward rule's listen port gets the same check (the
//     nft DNAT would silently steal inbound traffic from whatever local
//     service already listens there);
//   - a refused tunnel is withheld from Reconcile: a not-yet-running
//     tunnel never starts; a RUNNING tunnel keeps its CURRENT params (the
//     change is refused, the tunnel is not torn down) — matching
//     Manager.Reconcile's error style, the failures ride the ack as
//     per-entry errors and the rest of the desired state still applies.
//
// Self-held ports are not conflicts: a re-apply of an identical document
// skips the port scan entirely (the Manager no-ops it anyway), and a
// changed-params re-apply of a running tunnel allows ports held by the
// tunnel's own current process PIDs or its own registry reservation —
// the driver's reload/restart rebinds them deliberately.
//
// Known limitation (accepted, fail-closed): params fields that name
// ports the tunnel only CONNECTS to (e.g. a chisel remote/local target
// port) are checked like listen ports, so a param change can be refused
// because an unrelated service occupies that port. The error entry names
// the holder, so the operator can judge and adjust.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	protocol "github.com/Dark-modem/quantum-protocol"
)

// preflightScanDepth: the params object itself plus ONE nested map level
// (deeper structures are skipped — a port inside a third-level document
// is not something the preflight spec covers).
const preflightScanDepth = 1

// preflightSuggestScanCap bounds the suggestion scan below a conflicting
// port (ports inside the kernel ephemeral range are skipped outright, so
// the cap applies to genuinely evaluated candidates).
const preflightSuggestScanCap = 512

// agentPreflightV2 validates and port-checks a DesiredV2's tunnels and
// forwards. It returns the tunnel specs that may proceed to
// Manager.Reconcile (refused NEW tunnels dropped, refused running
// tunnels reverted to their current params) and the forward list the
// balancer may enforce, plus one error line per refusal in
// Manager.Reconcile error style.
func agentPreflightV2(mgr *engine.Manager, engs []engine.EngineSpec, specs []engine.TunnelSpec, forwards []protocol.ForwardRule) ([]engine.TunnelSpec, []protocol.ForwardRule, []string) {
	engineEnabled := map[string]bool{}
	for _, e := range engs {
		engineEnabled[engine.BaseEngineID(e.ID)] = e.Enabled
	}
	verrs := mgr.ValidateAll(specs)
	ownPIDs := mgr.ProcessPIDs() // tunnel id -> this tunnel's own process pids
	snap := preflightSnapshotNow()

	var errs []string
	out := make([]engine.TunnelSpec, 0, len(specs))
	for i, t := range specs {
		if !t.Enabled || !engineEnabled[engine.BaseEngineID(t.Engine)] {
			// Disabled tunnels (or tunnels on desired-disabled engines)
			// are not prefelighted: the Manager stops/ignores them.
			out = append(out, t)
			continue
		}
		if !mgr.EngineRegistered(t.Engine) {
			// Unknown engine: Reconcile carries its own error entry.
			out = append(out, t)
			continue
		}
		if preflightRunningSame(mgr, t) {
			// Idempotent re-apply (panel push of the same document, boot
			// replay): nothing changes, and the tunnel's own listeners
			// would otherwise fail its own ports. No checks.
			out = append(out, t)
			continue
		}

		ok := true
		if verrs[i] != nil {
			ok = false
			errs = append(errs, fmt.Sprintf("tunnel %s: validate: %v", t.ID, verrs[i]))
		}
		if ok {
			for _, p := range preflightParamPorts(t.Params) {
				if iss, taken := preflightPortConflict(p, ownPIDs[t.ID], t.ID); taken {
					ok = false
					errs = append(errs, preflightIssueText("tunnel "+t.ID, iss, snap))
					break // one precise refusal per tunnel is enough
				}
			}
		}
		if ok {
			out = append(out, t)
			continue
		}
		// Refused: a running tunnel keeps its CURRENT params (the change
		// is refused; the tunnel is not torn down), a new tunnel is
		// withheld from Reconcile entirely.
		if inst, running := mgr.Instance(t.ID); running {
			old := t
			old.Params = inst.Params
			out = append(out, old)
		}
	}

	keptForwards := make([]protocol.ForwardRule, 0, len(forwards))
	for _, f := range forwards {
		if !f.IsEnabled() {
			keptForwards = append(keptForwards, f) // not rendered anyway
			continue
		}
		protos := []string{portProtoTCP}
		switch f.Proto {
		case "udp":
			protos = []string{portProtoUDP}
		case "both":
			protos = []string{portProtoTCP, portProtoUDP}
		}
		ok := true
		for _, proto := range protos {
			if iss, taken := preflightPortConflictProto(f.ListenPort, proto, nil, ""); taken {
				ok = false
				errs = append(errs, preflightIssueText("forward "+f.ID, iss, snap))
				break
			}
		}
		if ok {
			keptForwards = append(keptForwards, f)
		}
	}
	return out, keptForwards, errs
}

// preflightRunningSame reports whether the Manager already runs this
// tunnel with EXACTLY these params (the same equality Manager.Reconcile
// uses for its no-op path).
func preflightRunningSame(mgr *engine.Manager, t engine.TunnelSpec) bool {
	inst, running := mgr.Instance(t.ID)
	return running && bytes.Equal(bytes.TrimSpace(inst.Params), bytes.TrimSpace(t.Params))
}

// preflightParamPorts scans engine_params for integer port fields: keys
// whose name contains "port" (case-insensitive), one top level deep plus
// one nested map level. Non-integral, string and out-of-range values are
// ignored (the owning driver validates them).
func preflightParamPorts(params json.RawMessage) []int {
	if len(params) == 0 {
		return nil
	}
	var top map[string]any
	if json.Unmarshal(params, &top) != nil {
		return nil
	}
	var out []int
	preflightScanPorts(top, 0, &out)
	sort.Ints(out)
	return out
}

func preflightScanPorts(m map[string]any, depth int, out *[]int) {
	if depth > preflightScanDepth {
		return
	}
	for k, v := range m {
		if strings.Contains(strings.ToLower(k), "port") {
			if n, ok := preflightJSONInt(v); ok {
				*out = append(*out, n)
			}
		}
		if sub, isMap := v.(map[string]any); isMap {
			preflightScanPorts(sub, depth+1, out)
		}
	}
}

// preflightJSONInt accepts integral JSON numbers in 1..65535.
func preflightJSONInt(v any) (int, bool) {
	n, ok := v.(float64)
	if !ok || n != math.Trunc(n) {
		return 0, false
	}
	i := int(n)
	if i < 1 || i > 65535 {
		return 0, false
	}
	return i, true
}

// preflightPortConflict checks one port on BOTH transports via
// portAvailabilityCheck (TCP first). A holder that is the tunnel's own
// current process (self-rebind of an unchanged port) or the tunnel's own
// registry reservation is not a conflict.
func preflightPortConflict(port int, ownPIDs []int, tunnelID string) (preflightPortIssue, bool) {
	for _, proto := range []string{portProtoTCP, portProtoUDP} {
		if iss, taken := preflightPortConflictProto(port, proto, ownPIDs, tunnelID); taken {
			return iss, true
		}
	}
	return preflightPortIssue{}, false
}

// preflightPortIssue is one refused port.
type preflightPortIssue struct {
	Port      int
	Proto     string
	Holder    string // process name / registry owner ("" = structural reason)
	Ephemeral bool   // port sits in the kernel ephemeral range
	Reason    string // the availability check's own reason text
}

func preflightPortConflictProto(port int, proto string, ownPIDs []int, tunnelID string) (preflightPortIssue, bool) {
	a := portAvailabilityCheck(port, proto)
	if a.Available {
		return preflightPortIssue{}, false
	}
	// Self-held allowances (changed-params re-apply of a running tunnel).
	if a.Listener != nil && a.Listener.PID > 0 && intInList(a.Listener.PID, ownPIDs) {
		return preflightPortIssue{}, false
	}
	if tunnelID != "" && a.ReservedBy == portOwnerTunnel+":"+tunnelID {
		return preflightPortIssue{}, false
	}
	iss := preflightPortIssue{Port: port, Proto: proto, Reason: a.Reason}
	if strings.Contains(a.Reason, "ephemeral range") {
		iss.Ephemeral = true
		return iss, true
	}
	if a.Listener != nil {
		if a.Listener.Process != "" {
			iss.Holder = a.Listener.Process
		} else {
			iss.Holder = "an unidentified listener on " + a.Listener.Address
		}
	} else if a.ReservedBy != "" {
		iss.Holder = a.ReservedBy
	} else {
		iss.Holder = a.Reason
	}
	return iss, true
}

// preflightIssueText renders one refusal in the Manager.Reconcile error
// style ("tunnel <id>: port <p>: in use by ...") with the next free
// ports above the conflict as suggestions.
func preflightIssueText(scope string, iss preflightPortIssue, snap preflightSnapshot) string {
	if iss.Ephemeral {
		return fmt.Sprintf("%s: port %d: %s (choose a port outside the ephemeral range)", scope, iss.Port, iss.Reason)
	}
	sugg := snap.suggestFree(iss.Port, 3, iss.Proto)
	if len(sugg) == 0 {
		return fmt.Sprintf("%s: port %d: in use by %q (no free port found above it; free the conflicting listener)", scope, iss.Port, iss.Holder)
	}
	parts := make([]string, 0, len(sugg))
	for _, p := range sugg {
		parts = append(parts, strconv.Itoa(p))
	}
	return fmt.Sprintf("%s: port %d: in use by %q (choose a free port; suggested free: %s)", scope, iss.Port, iss.Holder, strings.Join(parts, ", "))
}

func intInList(v int, list []int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ---- batched availability snapshot ----

// preflightSnapshot is ONE consistent host view (a single ss listing, a
// single registry read, a single ephemeral-range read) for the
// suggestion scan: evaluating many candidate ports must not shell out to
// ss per candidate. check() mirrors portAvailabilityCheck rule by rule —
// preflightSnapshotAgreesWithAvailabilityCheck pins the two together.
type preflightSnapshot struct {
	listeners []portListener
	registry  []portEntry
	ephLo     int
	ephHi     int
}

func preflightSnapshotNow() preflightSnapshot {
	s := preflightSnapshot{}
	if ls, err := portListeners(); err == nil {
		s.listeners = ls
	}
	portRegMu.Lock()
	s.registry = append([]portEntry(nil), portRegistryLoad().Entries...)
	portRegMu.Unlock()
	s.ephLo, s.ephHi = portEphemeralRange()
	return s
}

// check evaluates one port/transport against the snapshot with the exact
// portAvailabilityCheck rules.
func (s preflightSnapshot) check(port int, proto string) portAvailability {
	a := portAvailability{Port: port, Proto: proto}
	if port < 1 || port > 65535 || (proto != portProtoTCP && proto != portProtoUDP) {
		a.Reason = "invalid port or proto"
		return a
	}
	if port >= s.ephLo && port <= s.ephHi {
		a.Reason = fmt.Sprintf("inside the kernel ephemeral range %d-%d", s.ephLo, s.ephHi)
		return a
	}
	for _, e := range s.registry {
		if e.Port == port && e.Proto == proto {
			a.ReservedBy = e.owner()
			a.Reason = "reserved by " + e.owner()
			return a
		}
	}
	for _, l := range s.listeners {
		if l.Port != port {
			continue
		}
		if l.Proto == proto {
			l := l
			a.Listener = &l
			a.Reason = fmt.Sprintf("%s listener present (%s, pid %d)", proto, l.Process, l.PID)
			return a
		}
		a.OtherTransport = fmt.Sprintf("%s listener present (%s, pid %d)", l.Proto, l.Process, l.PID)
	}
	a.Available = true
	return a
}

// suggestFree returns up to n free ports strictly above from, evaluated
// with the same availability rules. Ports inside the ephemeral range are
// skipped without evaluation (they can never be handed out).
func (s preflightSnapshot) suggestFree(from, n int, proto string) []int {
	var out []int
	evaluated := 0
	for p := from + 1; p <= 65535 && len(out) < n && evaluated < preflightSuggestScanCap; p++ {
		if p >= s.ephLo && p <= s.ephHi {
			continue
		}
		evaluated++
		if s.check(p, proto).Available {
			out = append(out, p)
		}
	}
	return out
}
