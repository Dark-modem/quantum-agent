package agent

// Phase 2A: v2 protocol adoption. A negotiated-v2 session applies
// DesiredV2 through the engine Manager, the forward balancer and the
// hardening module; persists the last desired state and replays it at
// boot without the panel (the v1 mechanism); and reports StateReportV2
// with per-tunnel wire+payload bytes every heartbeat. v1 sessions (v1
// panels) keep the whole v1 path untouched.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/balancer"
	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-agent/internal/hardening"
	protocol "github.com/Dark-modem/quantum-protocol"
)

// agentNegotiateOrV1 clamps the controller-declared session version.
func agentNegotiateOrV1(controllerVersion int) int {
	return protocol.NegotiateOrV1(controllerVersion)
}

// agentEngineCatalog lists the engine IDs this agent can drive.
func agentEngineCatalog() []string {
	reg, err := AgentEngines()
	if err != nil {
		return nil
	}
	return reg.IDs()
}

// agentEngineInfos returns the rich catalog (PROTOCOL-REQUESTS R3).
func agentEngineInfos() []protocol.EngineInfo {
	reg, err := AgentEngines()
	if err != nil {
		return nil
	}
	infos := engine.CatalogOf(reg)
	out := make([]protocol.EngineInfo, 0, len(infos))
	for _, i := range infos {
		out = append(out, protocol.EngineInfo{ID: i.ID, Version: i.Version, ParamsSchema: i.ParamsSchema})
	}
	return out
}

// agentV2 is the process-wide v2 runtime: the engine manager over the
// builtin registry plus the forward balancer. Constructed lazily; the
// Manager has no background activity until a v2 desired state arrives,
// and the balancer's loop runs only while forward rules exist.
type agentV2Runtime struct {
	mu       sync.Mutex
	manager  *engine.Manager
	balancer *balancer.ForwardBalancer
}

var agentV2 agentV2Runtime

// agentV2AppliedRevision is the in-memory fencing floor for v2 desired
// state. The process's authority (disk is only the boot backup): tests
// run without a writable infra.ConfigDir, and fencing must not depend on it.
var agentV2AppliedRevision string

// agentV2FenceAccepts reports whether revision is strictly newer than
// everything applied so far (disk state included).
func agentV2FenceAccepts(revision string) bool {
	agentV2.mu.Lock()
	floor := agentV2AppliedRevision
	agentV2.mu.Unlock()
	if st := agentLoadState(); st.AppliedRevision > floor {
		floor = st.AppliedRevision
	}
	return protocol.RevisionNewer(revision, floor)
}

// agentV2RecordApplied moves the fencing floor forward (memory first,
// disk best-effort).
func agentV2RecordApplied(revision string) {
	agentV2.mu.Lock()
	if protocol.RevisionNewer(revision, agentV2AppliedRevision) {
		agentV2AppliedRevision = revision
	}
	agentV2.mu.Unlock()
}

// agentV2RuntimeRef returns (and lazily builds) the v2 runtime.
func agentV2RuntimeRef() (*engine.Manager, *balancer.ForwardBalancer, error) {
	agentV2.mu.Lock()
	defer agentV2.mu.Unlock()
	if agentV2.manager == nil {
		reg, err := AgentEngines()
		if err != nil {
			return nil, nil, err
		}
		agentV2.manager = engine.NewManager(reg)
		agentV2.balancer = balancer.New(agentV2.manager, reg)
	}
	return agentV2.manager, agentV2.balancer, nil
}

// decodeInbound decodes one inbound message with the session's
// negotiated version: v1 sessions keep the strict v1 decode; v2
// sessions accept v1-and-v2 envelopes and surface the envelope version
// so desired-state routing can pick the payload shape.
func (s *agentSession) decodeInbound(raw []byte) (typ string, envVersion int, data json.RawMessage, err error) {
	if s.version >= agentProtoVersionV2 {
		v, t, d, derr := protocol.DecodeAny(raw)
		return t, v, d, derr
	}
	typ, data, err = agentDecode(raw)
	return typ, protocol.ProtoVersionV1, data, err
}

// handleDesiredV2 journals the v2 desired as pending (crash-safe boot
// replay without the panel), applies it, acks with the hardening journal
// reference and pushes a fresh heartbeat.
func (s *agentSession) handleDesiredV2(data []byte) {
	var d protocol.DesiredV2
	if uerr := json.Unmarshal(data, &d); uerr != nil {
		log.Printf("[agent] malformed v2 desired: %v", uerr)
		s.fail(uerr)
		return
	}
	raw := append([]byte(nil), data...)
	if err := agentMutateState(func(st *agentPersistedState) {
		st.DesiredV2Raw = raw
		st.DesiredStatus = "pending"
	}); err != nil {
		log.Printf("[agent] cannot persist v2 desired: %v", err)
	}
	agentMu.Lock()
	ack := agentApplyDesiredV2(&d)
	agentMu.Unlock()
	if err := s.send(agentMsgAck, ack); err != nil {
		log.Printf("[agent] v2 ack send failed: %v", err)
		s.fail(err)
		return // state stays pending; the next boot replays it
	}
	agentRecordAck(d.Revision, ack)
	s.sendHeartbeat()
}

// agentApplyDesiredV2 converges the host to a DesiredV2 document. Used
// online (with a panel to ack) and at boot without the panel. Revision
// fencing matches v1: strictly newer revisions only, applied
// idempotently; stale/equal revisions are refused.
func agentApplyDesiredV2(d *protocol.DesiredV2) agentAck {
	return agentApplyDesiredV2Fenced(d, true)
}

// agentApplyDesiredV2Fenced is the apply with an explicit fencing switch:
// boot replay of the agent's own journaled document re-applies the exact
// revision it already ran (idempotent by contract), so it must bypass the
// newer-revision fence or every agent restart would drop its tunnels
// until the panel pushes again.
func agentApplyDesiredV2Fenced(d *protocol.DesiredV2, fence bool) agentAck {
	ack := agentAck{Revision: d.Revision, OK: true, Kind: "desired-v2"}
	if fence && !agentV2FenceAccepts(d.Revision) {
		ack.OK = false
		ack.Error = fmt.Sprintf("stale or duplicate revision %s", d.Revision)
		return ack
	}
	mgr, bal, err := agentV2RuntimeRef()
	if err != nil {
		ack.OK = false
		ack.Error = "v2 runtime: " + err.Error()
		return ack
	}

	// 1. Hardening section (HARDENING.md §5a): apply through the module;
	// the ack carries the journal reference for the confirm banner.
	if len(d.Hardening) > 0 {
		res := hardening.Dispatch(context.Background(), hardening.Request{
			Op:                 "apply",
			Profile:            string(d.Hardening),
			SafeApply:          boolPtr(true),
			RollbackTimeoutSec: d.HardeningTimeoutSec,
		})
		ack.Kind = "hardening"
		if res == nil || !res.Ok {
			ack.OK = false
			if res != nil {
				ack.Error = res.Error
			}
			return ack
		}
		if res.Journal != nil {
			ack.JournalID = res.Journal.ID
			ack.Armed = res.Armed
			ack.TimerUnit = res.TimerUnit
			ack.Plan = mustJSONRaw(res.Plan)
		}
	}

	// 2. Tunnels + engines: reconcile through the engine Manager.
	// selfName (R6, phase 17): the panel stamps DesiredV2.Self with the
	// receiving agent's mesh server name — the authoritative self for
	// engines that resolve their side by name (FRP frps/frpc). Empty
	// (pre-R6 panel) keeps the drivers' legacy resolution untouched.
	selfName := ""
	if d.Self != nil {
		selfName = strings.TrimSpace(d.Self.Name)
	}
	specs := make([]engine.TunnelSpec, 0, len(d.Tunnels))
	engs := make([]engine.EngineSpec, 0, len(d.Engines))
	for _, e := range d.Engines {
		engs = append(engs, engine.EngineSpec{ID: e.ID, Enabled: e.Enabled})
	}
	for _, t := range d.Tunnels {
		if err := validateTunnelSpec(t); err != nil {
			ack.OK = false
			ack.Error = err.Error()
			return ack
		}
		specs = append(specs, engine.TunnelSpec{
			ID:           t.ID,
			TopologyID:   t.TopologyID,
			LocalServer:  t.LocalServer,
			RemoteServer: t.RemoteServer,
			Engine:       t.Engine,
			Params:       t.EngineParams,
			Enabled:      t.Enabled,
			SelfName:     selfName,
		})
	}
	// Defensive alignment check (R6): with Self stamped, every delivered
	// tunnel names its two ends; if NONE of them is Self.Name the panel
	// linked this agent to a different server than the doc's tunnels
	// reference. Non-fatal (a doc may legitimately carry engines/forwards
	// without tunnels) — it rides the ack detail so the UI can surface it.
	if selfName != "" && len(specs) > 0 {
		aligned := false
		for _, t := range specs {
			if t.LocalServer == selfName || t.RemoteServer == selfName {
				aligned = true
				break
			}
		}
		if !aligned {
			if ack.Detail == nil {
				ack.Detail = map[string]string{}
			}
			ack.Detail["self_alignment_warning"] = fmt.Sprintf(
				"self %q matches no tunnel end in revision %s", selfName, d.Revision)
			log.Printf("[agent] v2 self alignment: self %q matches no tunnel end (revision %s)",
				selfName, d.Revision)
		}
	}
	// 2a. PREFLIGHT (phase14 ports): driver Validate + port availability
	// for every enabled tunnel, and the listen port for every enabled
	// forward — BEFORE anything starts (Manager.Reconcile never calls
	// Validate, and a bind conflict would otherwise fail inside the
	// driver's Start). Refused NEW tunnels are withheld from Reconcile,
	// refused running tunnels keep their current params, refused forwards
	// are withheld from the balancer; the failures ride the ack like the
	// reconcile errors below while the rest of the desired state applies.
	specs, forwards, pfErrs := agentPreflightV2(mgr, engs, specs, d.Forwards)
	for i, e := range pfErrs {
		log.Printf("[agent] v2 preflight error: %s", e)
		if ack.Detail == nil {
			ack.Detail = map[string]string{}
		}
		ack.Detail[fmt.Sprintf("preflight_error_%d", i)] = e
	}
	if res := mgr.Reconcile(context.Background(), engs, specs); len(res.Errors) > 0 {
		// Partial failures do not fail the whole ack: the applied part
		// stands and the errors ride the next heartbeat's Errors.
		log.Printf("[agent] v2 reconcile reported %d error(s): %v", len(res.Errors), res.Errors)
		if ack.Detail == nil {
			ack.Detail = map[string]string{}
		}
		for i, e := range res.Errors {
			log.Printf("[agent] v2 reconcile error: %s", e)
			ack.Detail[fmt.Sprintf("reconcile_error_%d", i)] = e
		}
	}

	// 3. Forwards + balancing: enforce locally (works without the panel).
	// The preflighted forward list (refused listen ports dropped) is what
	// gets enforced; everything else is the untouched desired document.
	balDoc := *d
	balDoc.Forwards = forwards
	bal.Reconcile(&balDoc)

	// 4. Record the applied revision (boot replay + fencing depend on
	// it; agentRecordAck does the same for the online path).
	agentV2RecordApplied(d.Revision)
	if err := agentMutateState(func(st *agentPersistedState) {
		st.AppliedRevision = d.Revision
		st.DesiredStatus = "applied"
	}); err != nil {
		log.Printf("[agent] cannot persist v2 applied revision: %v", err)
	}
	return ack
}

func validateTunnelSpec(t protocol.TunnelSpec) error {
	if strings.TrimSpace(t.ID) == "" {
		return fmt.Errorf("tunnel: empty id")
	}
	if strings.TrimSpace(t.Engine) == "" {
		return fmt.Errorf("tunnel %s: empty engine", t.ID)
	}
	if len(t.EngineParams) > 0 && !json.Valid(t.EngineParams) {
		return fmt.Errorf("tunnel %s: engine_params is not valid JSON", t.ID)
	}
	return nil
}

func mustJSONRaw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// agentReportClock is the report-builder's clock seam (tests inject a
// fixed clock — no sleeps). R7 (PROTOCOL-REQUESTS.md): every v2 state
// report carries the AGENT's own wall clock, read ONCE per report, as
// late as possible in the build — the value is "when this report was
// assembled", never a boot time and never a fabricated 0 (the panel
// treats 0 as legacy and skips the clock_drift rule).
var agentReportClock = time.Now

// agentBuildStateReportV2 builds the v2 heartbeat state: everything the
// v1 report carries plus per-tunnel runtime (wire AND payload bytes),
// per-engine overhead samples and the balancer's enforced forwards.
func agentBuildStateReportV2() *agentStateReportV2 {
	v1 := agentBuildStateReport()
	out := &agentStateReportV2{
		AppliedRevision: v1.AppliedRevision,
		Matrix:          v1.Matrix,
		Resources:       v1.Resources,
		UpdateProgress:  v1.UpdateProgress,
		NodeDetect:      v1.NodeDetect,
		Errors:          v1.Errors,
	}
	mgr, bal, err := agentV2RuntimeRef()
	if err != nil {
		out.Errors = append(out.Errors, "v2 runtime: "+err.Error())
		out.ReportedAt = agentReportClock().Unix()
		return out
	}
	// Per-tunnel runtime with both byte views; per-engine overhead
	// samples derived from real counter pairs only.
	engines := map[string]*protocol.EngineOverheadSample{}
	// Loss is only known for probed matrix instances: instance -> health.
	matrixLoss := map[string]float64{}
	for _, h := range agentHealthSnapshot() {
		if h.Samples > 0 {
			matrixLoss[h.Instance] = h.LossPct
		}
	}
	for _, st := range mgr.Status() {
		tr := protocol.TunnelRuntime{
			TunnelID: st.TunnelID, Engine: st.Engine, Up: st.Health.OK,
			LatencyMs: st.Health.LatencyMs,
			WireRx:    st.Counters.WireRx, WireTx: st.Counters.WireTx,
			PayloadRx: st.Counters.PayloadRx, PayloadTx: st.Counters.PayloadTx,
			CountersKnown: st.Counters.WireKnown, // legacy field: wire-known
			WireKnown:     st.Counters.WireKnown,
			PayloadKnown:  st.Counters.PayloadKnown,
		}
		// Phase-11 per-tunnel extras: last error, uptime, measured loss.
		if !st.Health.OK && st.Health.Detail != "" {
			tr.LastError = truncateReportDetail(st.Health.Detail)
		}
		if st.Health.OK && !st.Health.Since.IsZero() {
			if up := int64(time.Since(st.Health.Since).Seconds()); up > 0 {
				tr.UptimeS = up
			}
		}
		if st.Engine == "matrix" {
			if inst, ok := mgr.Instance(st.TunnelID); ok {
				var mp struct {
					Instance string `json:"instance"`
				}
				if json.Unmarshal(inst.Params, &mp) == nil && mp.Instance != "" {
					if loss, known := matrixLoss[mp.Instance]; known {
						tr.LossPct = loss
					}
				}
			}
		}
		// Per-direction overhead from real counter pairs only (Phase-4);
		// each engine's sample accumulates both directions independently.
		if st.Counters.WireKnown && st.Counters.PayloadKnown && st.Counters.PayloadRx > 0 {
			tr.OverheadRatio = float64(st.Counters.WireRx) / float64(st.Counters.PayloadRx)
		}
		if st.Counters.WireKnown && st.Counters.PayloadKnown && st.Counters.PayloadTx > 0 {
			tr.OverheadRatioTx = float64(st.Counters.WireTx) / float64(st.Counters.PayloadTx)
		}
		if st.Counters.WireKnown || st.Counters.PayloadKnown {
			es := engines[st.Engine]
			if es == nil {
				es = &protocol.EngineOverheadSample{Engine: st.Engine, Tunnels: 0}
				engines[st.Engine] = es
			}
			es.Tunnels++
			es.WireRx += st.Counters.WireRx
			es.PayloadRx += st.Counters.PayloadRx
			es.WireTx += st.Counters.WireTx
			es.PayloadTx += st.Counters.PayloadTx
			if es.PayloadRx > 0 {
				es.Ratio = float64(es.WireRx) / float64(es.PayloadRx)
			}
			if es.PayloadTx > 0 {
				es.RatioTx = float64(es.WireTx) / float64(es.PayloadTx)
			}
		}
		out.Tunnels = append(out.Tunnels, tr)
	}
	for _, e := range engines {
		out.Engines = append(out.Engines, *e)
	}
	sort.Slice(out.Engines, func(i, j int) bool { return out.Engines[i].Engine < out.Engines[j].Engine })
	out.Forwards = bal.ForwardRuntimeSnapshot()
	// Phase-11 UI data: per-tunnel process metrics (no process tunnels →
	// nil + zero /proc reads) and per-engine installation state.
	out.Proc = agentSampleTunnelProc(mgr)
	out.EngineStatus = agentEngineStatusReportV2(mgr)
	out.Hardening = agentHardeningRuntime()
	out.ReportedAt = agentReportClock().Unix()
	return out
}

// agentHardeningRuntime surfaces the safe-apply pending state in the
// heartbeat: while a journal is armed, the panel shows the confirm
// banner with the deadline (Phase 2A STEP 5).
func agentHardeningRuntime() *protocol.HardeningRuntime {
	j, jerr := hardening.LoadLatestJournal()
	if jerr != nil || j == nil || j.Confirmed || j.RolledBack || j.FinishedAt != 0 {
		return nil
	}
	hr := &protocol.HardeningRuntime{
		JournalID: j.ID,
		Name:      j.ProfileName,
		Armed:     j.SafeApply && !j.Confirmed,
		TimerUnit: j.TimerUnit,
	}
	if j.SafeApply && j.TimeoutSec > 0 {
		hr.DeadlineS = j.StartedAt + int64(j.TimeoutSec)
	}
	return hr
}

// agentRunHardeningOp adapts the v2 hardening commands to the module's
// Dispatch (agentRunTypedOp routes hardening.* here). Structured
// results ride CommandResult.Data (HARDENING.md §5b).
//
// Param-key compatibility (Phase-7 release blocker): the panel's
// profile/apply endpoint sends the profile JSON under "payload" and the
// timer under "rollback_timer_s" (protocol.ParamRollbackTimerS), while
// this agent historically read "profile" and "rollback_timeout_sec".
// BOTH spellings are accepted — "profile"/"rollback_timeout_sec" first
// (the documented v2 contract), "payload"/"rollback_timer_s" as the
// panel's spelling (the real-server acceptance hit this mismatch).
func agentRunHardeningOp(op string, params map[string]string) (any, error) {
	req := hardeningRequestFromParams(op, params)
	res := hardening.Dispatch(context.Background(), req)
	if res == nil {
		return nil, fmt.Errorf("hardening: no result")
	}
	return res, nil
}

// hardeningRequestFromParams resolves the command params into the
// module's Request. Both spellings are accepted — "profile" and
// "rollback_timeout_sec" first (the documented v2 contract),
// "payload" and "rollback_timer_s" as the panel's profile/apply endpoint
// spells them (protocol.ParamRollbackTimerS; the real-server acceptance
// hit this mismatch). "profile" wins when both are present.
func hardeningRequestFromParams(op string, params map[string]string) hardening.Request {
	req := hardening.Request{Op: strings.TrimPrefix(op, "hardening.")}
	if prof := params["profile"]; prof != "" {
		req.Profile = prof
	} else if payload := params["payload"]; payload != "" {
		req.Profile = payload
	}
	timer := params["rollback_timeout_sec"]
	if timer == "" {
		timer = params["rollback_timer_s"]
	}
	if timer != "" {
		if n, err := strconv.Atoi(timer); err == nil {
			req.RollbackTimeoutSec = n
		}
	}
	if v := params["journal_id"]; v != "" {
		req.JournalID = v
	}
	if params["safe_apply"] == "false" {
		req.SafeApply = boolPtr(false)
	}
	return req
}
