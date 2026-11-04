// api.go — the entry point the contract session wires into the protocol.
// One typed request, one function, stable JSON-serializable results (the
// same dispatcher discipline as netopt's NetopDispatch). Proposed protocol
// command names: hardening.detect / plan / apply / status / confirm /
// rollback — see docs/HARDENING.md for the message shapes.

package hardening

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Request is one hardening operation.
type Request struct {
	Op string `json:"op"` // detect|plan|apply|status|confirm|rollback

	// Profile is the JSON profile document (plan/apply).
	Profile string `json:"profile,omitempty"`
	// SafeApply defaults to true; only an explicit false (plus a
	// non-risky plan) skips the rollback timer.
	SafeApply *bool `json:"safe_apply,omitempty"`
	// RollbackTimeoutSec overrides the armed timer (min 120).
	RollbackTimeoutSec int `json:"rollback_timeout_sec,omitempty"`
	// JournalID targets one journal (confirm/rollback; "" = latest).
	JournalID string `json:"journal_id,omitempty"`
}

// Result is the JSON-serializable outcome. Exactly one of Plan/Journal/
// State is set depending on the op; Error carries the failure text.
type Result struct {
	Ok        bool           `json:"ok"`
	Error     string         `json:"error,omitempty"`
	State     *DetectedState `json:"state,omitempty"`
	Plan      *Plan          `json:"plan,omitempty"`
	Journal   *Journal       `json:"journal,omitempty"`
	Armed     bool           `json:"armed,omitempty"`
	TimerUnit string         `json:"timer_unit,omitempty"`
	Verify    []VerifyResult `json:"verify,omitempty"`
	// Leftovers lists safe-apply pre-open rules still present after a
	// confirm (informational; never auto-removed).
	Leftovers []string `json:"leftovers,omitempty"`
}

var validOps = map[string]bool{
	"detect": true, "plan": true, "apply": true,
	"status": true, "confirm": true, "rollback": true,
}

// Dispatch routes one typed request. Mutating ops (apply/confirm/rollback)
// expect the protocol layer to have enforced payload.confirm == "yes"; this
// layer enforces the safe-apply discipline itself.
func Dispatch(ctx context.Context, req Request) *Result {
	if !validOps[req.Op] {
		return &Result{Error: fmt.Sprintf("hardening: unknown op %q (valid: detect, plan, apply, status, confirm, rollback)", req.Op)}
	}
	switch req.Op {
	case "detect":
		return &Result{Ok: true, State: Detect(ctx)}
	case "plan":
		p, err := parseProfile(req.Profile)
		if err != nil {
			return &Result{Error: err.Error()}
		}
		plan, err := PlanProfile(p, Detect(ctx))
		if err != nil {
			return &Result{Error: err.Error()}
		}
		return &Result{Ok: true, Plan: plan}
	case "apply":
		p, err := parseProfile(req.Profile)
		if err != nil {
			return &Result{Error: err.Error()}
		}
		opts := ApplyOpts{SafeApply: true, RollbackTimeoutSec: req.RollbackTimeoutSec}
		if req.SafeApply != nil {
			opts.SafeApply = *req.SafeApply
		}
		res, err := ApplyProfile(ctx, p, opts)
		if res != nil {
			r := &Result{Ok: err == nil, Error: errString(err), Plan: res.Plan,
				Journal: res.Journal, Armed: res.Armed, TimerUnit: res.TimerUnit, Verify: res.Verify}
			return r
		}
		return &Result{Error: errString(err)}
	case "status":
		return statusResult(ctx)
	case "confirm":
		j, err := Confirm(ctx, req.JournalID)
		if err != nil {
			return &Result{Error: err.Error()}
		}
		return &Result{Ok: true, Journal: j, Leftovers: leftoverRules(ctx)}
	case "rollback":
		j, err := Rollback(ctx, req.JournalID)
		if err != nil {
			return &Result{Journal: j, Error: err.Error()}
		}
		return &Result{Ok: true, Journal: j}
	}
	return &Result{Error: fmt.Sprintf("hardening: unreachable op %q", req.Op)} // guarded by validOps
}

// statusResult is the panel's view: latest journal + fresh detection +
// whether a rollback timer is still armed.
func statusResult(ctx context.Context) *Result {
	res := &Result{Ok: true, State: Detect(ctx)}
	if j, err := LoadLatestJournal(); err == nil && j != nil {
		res.Journal = j
		if j.TimerUnit != "" && !j.Confirmed && !j.RolledBack {
			res.Armed = timerActive(ctx, j.TimerUnit)
			res.TimerUnit = j.TimerUnit
			if res.Armed {
				res.Leftovers = leftoverRules(ctx)
			}
		}
	}
	return res
}

// leftoverRules lists ufw rules still tagged quantum:hardening:safe-apply.
func leftoverRules(ctx context.Context) []string {
	raw := ufwNumbered(ctx)
	return ufwOurRulesTagged(raw, preOpenOwner)
}

// ufwOurRulesTagged filters our-rules by owner substring.
func ufwOurRulesTagged(raw, owner string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, hardeningCommentTag+owner) {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}

func parseProfile(raw string) (Profile, error) {
	var p Profile
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, fmt.Errorf("invalid profile JSON: %v", err)
	}
	return p, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
