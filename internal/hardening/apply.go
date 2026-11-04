// apply.go — the Apply/Verify stage. ApplyProfile walks a plan in a fixed
// order chosen for lockout-safety:
//
//	1. non-risky items (sysctl merge, fail2ban, timesync, journald)
//	2. risky items under SAFE-APPLY (safeapply.go):
//	     a. pre-open BOTH the current and the new SSH port (additive allows)
//	     b. verify the current SSH path answers
//	     c. arm the automatic rollback timer (systemd-run)
//	     d. write + validate (sshd -t) the drop-in, reload, probe banners
//	     e. apply firewall rule adds, then policies, then removals
//	     f. re-probe the SSH banner (the policy flip must not cut it)
//
// Every executed step carries its undo (inverse argvs and/or previous file
// bytes); the first failure rolls everything applied so far back and marks
// the journal rolled back. Verification failures are failures.

package hardening

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ApplyOpts tunes one apply.
type ApplyOpts struct {
	// SafeApply arms the automatic rollback timer. Refused (hard error)
	// when the plan is risky and this is false. Default true.
	SafeApply bool
	// RollbackTimeoutSec is the systemd-run delay; default 120, minimum 120
	// (a human has to be able to react, and the panel polls at ~30 s).
	RollbackTimeoutSec int
}

// ApplyResult is what apply reports back (JSON-serializable end to end).
type ApplyResult struct {
	Journal   *Journal       `json:"journal"`
	Plan      *Plan          `json:"plan"`
	Armed     bool           `json:"armed"`
	TimerUnit string         `json:"timer_unit,omitempty"`
	Verify    []VerifyResult `json:"verify,omitempty"`
}

// VerifyResult is one post-apply check.
type VerifyResult struct {
	ItemID string `json:"item_id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// errUnsafeApply is returned when a risky plan arrives with SafeApply off.
var errUnsafeApply = errors.New("refusing to apply a profile that can cut remote access without safe-apply (SafeApply must be true)")

// ApplyProfile detects, plans and applies one profile end to end.
func ApplyProfile(ctx context.Context, profile Profile, opts ApplyOpts) (*ApplyResult, error) {
	if opts.RollbackTimeoutSec == 0 {
		opts.RollbackTimeoutSec = defaultRollbackTimeoutSec
	}
	if opts.RollbackTimeoutSec < minRollbackTimeoutSec {
		opts.RollbackTimeoutSec = minRollbackTimeoutSec
	}
	state := Detect(ctx)
	plan, err := PlanProfile(profile, state)
	if err != nil {
		return nil, err
	}
	res := &ApplyResult{Plan: plan}
	if plan.Noop {
		res.Journal = &Journal{ID: plan.ID, ProfileName: profile.Name, StartedAt: nowUnix(),
			FinishedAt: nowUnix(), Confirmed: true}
		_ = saveJournal(res.Journal)
		return res, nil
	}
	if plan.Risky && !opts.SafeApply {
		return res, errUnsafeApply
	}

	j := &Journal{ID: plan.ID, ProfileName: profile.Name, StartedAt: nowUnix(),
		SafeApply: opts.SafeApply, TimeoutSec: opts.RollbackTimeoutSec, Before: state}
	res.Journal = j
	finish := func(err error) (*ApplyResult, error) {
		j.FinishedAt = nowUnix()
		if err != nil {
			j.Error = err.Error()
		}
		// A rolled-back journal was already persisted and marked terminal by
		// rollbackJournal; re-saving here would resurrect the renamed files.
		if !j.RolledBack {
			_ = saveJournal(j)
		}
		return res, err
	}

	// ---- phase 1: non-risky items ----
	if err := applyNonRisky(ctx, plan, state, j, res); err != nil {
		rollbackJournal(ctx, j, err.Error())
		j.RolledBack = true
		return finish(err)
	}

	// ---- phase 2: risky items under safe-apply ----
	risky := riskyItems(plan)
	if len(risky) > 0 {
		r, err := applyRisky(ctx, profile, state, j, risky, opts)
		res.Armed = r.armed
		res.TimerUnit = r.timerUnit
		res.Verify = append(res.Verify, r.verify...)
		if err != nil {
			rollbackJournal(ctx, j, "risky apply failed: "+err.Error())
			j.RolledBack = true
			return finish(err)
		}
	}

	// ---- final verification of every applied item ----
	for _, it := range plan.Items {
		if it.Blocked || it.Risky {
			continue // risky items verified inside the safe-apply path
		}
		if vr := verifyItem(ctx, it); vr != nil {
			res.Verify = append(res.Verify, *vr)
			if !vr.OK {
				err := fmt.Errorf("item %s failed final verification: %s", it.ID, vr.Detail)
				rollbackJournal(ctx, j, err.Error())
				j.RolledBack = true
				return finish(err)
			}
		}
	}
	return finish(nil)
}

// applyNonRisky applies sysctl (as one merged drop-in), fail2ban, timesync
// and journald items, appending steps + verify results to the journal.
func applyNonRisky(ctx context.Context, plan *Plan, state *DetectedState, j *Journal, res *ApplyResult) error {
	// sysctl items merge into one drop-in write.
	var sys []PlanItem
	for _, it := range plan.Items {
		if it.Kind == KindSysctl && !it.Blocked {
			sys = append(sys, it)
		}
	}
	if len(sys) > 0 {
		step, err := applySysctlSet(ctx, sys, state)
		j.Steps = append(j.Steps, step)
		if err != nil {
			return fmt.Errorf("sysctl: %v", err)
		}
		for _, it := range sys {
			res.Verify = append(res.Verify, VerifyResult{ItemID: it.ID, OK: true})
		}
	}

	for _, it := range plan.Items {
		if it.Blocked || it.Risky {
			continue
		}
		switch it.Kind {
		case KindSysctl:
			continue // handled above as one set
		case KindFail2Ban, KindTimeSync, KindJournald:
			step, err := applyMiscItem(ctx, it)
			j.Steps = append(j.Steps, step)
			if err != nil {
				return fmt.Errorf("%s: %v", it.ID, err)
			}
			if vr := verifyItem(ctx, it); vr != nil {
				res.Verify = append(res.Verify, *vr)
				if !vr.OK {
					return fmt.Errorf("%s did not verify: %s", it.ID, vr.Detail)
				}
			}
		}
	}
	return nil
}

// riskyItems returns the plan's risky, non-blocked items in apply order:
// rule adds (pre-open), ssh config, policies, rule removals.
func riskyItems(plan *Plan) []PlanItem {
	var adds, ssh, policies, dels []PlanItem
	for _, it := range plan.Items {
		if it.Blocked || !it.Risky {
			continue
		}
		switch it.Kind {
		case KindFwRuleAdd:
			adds = append(adds, it)
		case KindSSHConfig:
			ssh = append(ssh, it)
		case KindFwPolicyIn, KindFwPolicyOut:
			policies = append(policies, it)
		case KindFwRuleDel:
			dels = append(dels, it)
		}
	}
	out := append(append(adds, ssh...), policies...)
	return append(out, dels...)
}

// applyMiscItem executes one fail2ban/timesync/journald item.
func applyMiscItem(ctx context.Context, it PlanItem) (Step, error) {
	step := Step{Item: it}
	switch it.Kind {
	case KindFail2Ban:
		switch {
		case strings.HasSuffix(it.ID, ":remove"):
			prev := it.Before
			if err := os.Remove(fail2banJailPath); err != nil && !os.IsNotExist(err) {
				return step, fmt.Errorf("remove jail: %v", err)
			}
			step.Files = []FileUndo{{Path: fail2banJailPath, Before: prev, Mode: 0o644}}
		default:
			prev, had := "", false
			if b, err := readFile(fail2banJailPath); err == nil {
				prev, had = string(b), true
			}
			if err := writeFileAtomic(fail2banJailPath, it.After, 0o644); err != nil {
				return step, fmt.Errorf("write jail: %v", err)
			}
			step.Files = []FileUndo{{Path: fail2banJailPath, Before: prev, Absent: !had, Mode: 0o644}}
		}
		for _, cmd := range it.Cmds {
			if _, err := run(ctx, cmd[0], cmd[1:]...); err != nil {
				return step, fmt.Errorf("%v: %v", cmd, err)
			}
			step.Cmds = append(step.Cmds, cmd)
		}
		return step, nil
	case KindTimeSync:
		for _, cmd := range it.Cmds {
			if _, err := run(ctx, cmd[0], cmd[1:]...); err != nil {
				return step, fmt.Errorf("%v: %v", cmd, err)
			}
			step.Cmds = append(step.Cmds, cmd)
		}
		step.Undo = [][]string{{"systemctl", "disable", "--now", "systemd-timesyncd"}}
		return step, nil
	case KindJournald:
		if err := os.MkdirAll(journaldLogDir, 0o755); err != nil {
			return step, fmt.Errorf("create %s: %v", journaldLogDir, err)
		}
		prev, had := "", false
		if b, err := readFile(journaldDropInPath); err == nil {
			prev, had = string(b), true
		}
		content := journaldDropInContent()
		if err := writeFileAtomic(journaldDropInPath, content, 0o644); err != nil {
			return step, fmt.Errorf("write journald drop-in: %v", err)
		}
		for _, cmd := range it.Cmds {
			_, _ = run(ctx, cmd[0], cmd[1:]...) // try-restart failure is non-fatal; the directory alone enables persistence
			step.Cmds = append(step.Cmds, cmd)
		}
		step.Files = []FileUndo{{Path: journaldDropInPath, Before: prev, Absent: !had, Mode: 0o644}}
		return step, nil
	}
	return step, fmt.Errorf("applyMiscItem: unhandled kind %q", it.Kind)
}

func journaldDropInContent() string {
	return "# managed by quantum-agent hardening — do not edit\n[Journal]\nStorage=persistent\n"
}
