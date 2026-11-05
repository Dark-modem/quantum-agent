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

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-agent/internal/hardening"
	"github.com/Dark-modem/quantum-protocol"
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
	balancer *forwardBalancer
}

var agentV2 agentV2Runtime

// agentV2AppliedRevision is the in-memory fencing floor for v2 desired
// state. The process's authority (disk is only the boot backup): tests
// run without a writable configDir, and fencing must not depend on it.
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
func agentV2RuntimeRef() (*engine.Manager, *forwardBalancer, error) {
	agentV2.mu.Lock()
	defer agentV2.mu.Unlock()
	if agentV2.manager == nil {
		reg, err := AgentEngines()
		if err != nil {
			return nil, nil, err
		}
		agentV2.manager = engine.NewManager(reg)
		agentV2.balancer = newForwardBalancer(agentV2.manager, reg)
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
	ack := agentAck{Revision: d.Revision, OK: true, Kind: "desired-v2"}
	if !agentV2FenceAccepts(d.Revision) {
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
		})
	}
	if res := mgr.Reconcile(context.Background(), engs, specs); len(res.Errors) > 0 {
		// Partial failures do not fail the whole ack: the applied part
		// stands and the errors ride the next heartbeat's Errors.
		log.Printf("[agent] v2 reconcile reported %d error(s)", len(res.Errors))
		ack.Detail = map[string]string{}
		for i, e := range res.Errors {
			ack.Detail[fmt.Sprintf("reconcile_error_%d", i)] = e
		}
	}

	// 3. Forwards + balancing: enforce locally (works without the panel).
	bal.Reconcile(d)

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
		return out
	}
	// Per-tunnel runtime with both byte views; per-engine overhead
	// samples derived from real counter pairs only.
	engines := map[string]*protocol.EngineOverheadSample{}
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
	out.Hardening = agentHardeningRuntime()
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
func agentRunHardeningOp(op string, params map[string]string) (any, error) {
	req := hardening.Request{Op: strings.TrimPrefix(op, "hardening.")}
	if prof := params["profile"]; prof != "" {
		req.Profile = prof
	}
	if v := params["rollback_timeout_sec"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			req.RollbackTimeoutSec = n
		}
	}
	if v := params["journal_id"]; v != "" {
		req.JournalID = v
	}
	if params["safe_apply"] == "false" {
		req.SafeApply = boolPtr(false)
	}
	res := hardening.Dispatch(context.Background(), req)
	if res == nil {
		return nil, fmt.Errorf("hardening: no result")
	}
	return res, nil
}
