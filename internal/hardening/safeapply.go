// safeapply.go — SAFE-APPLY, the mandatory path for anything that can cut
// remote access. Order of operations:
//
//	1. pre-open BOTH the current and the new SSH port (additive ufw allows
//	   tagged quantum:hardening:safe-apply; never rate-limited)
//	2. verify the current SSH path really answers (banner probe)
//	3. write the rollback script for EVERY intended risky mutation and arm
//	   the automatic timer: systemd-run --on-active=<t>s /bin/sh <script>
//	   (default 120 s). If arming fails, nothing risky has happened yet.
//	4. apply risky items in order (ssh drop-in + sshd -t + reload +
//	   banner re-probe; then firewall rules; then policies with an
//	   immediate re-probe after every default-deny flip)
//	5. hand back to the caller: the panel must Confirm (disarm) or the
//	   timer fires and the generated script restores the previous state
//	   even if the agent binary is dead.
//
// The rollback script is generated, self-contained POSIX sh: it re-runs the
// recorded inverse argvs and restores owned files from embedded previous
// bytes. No state lives in the script beyond what the journal already has.

package hardening

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRollbackTimeoutSec = 120
	minRollbackTimeoutSec     = 120
	// preOpenOwner tags the temporary additive allows. Convergence never
	// removes them; Confirm/Rollback do.
	preOpenOwner = "safe-apply"
	// listenerSettle is how long apply waits for sshd to re-listen after a
	// reload before probing banners.
	listenerSettle = 2 * time.Second
)

type riskyOutcome struct {
	armed     bool
	timerUnit string
	verify    []VerifyResult
}

// currentSSHPorts returns the ports SSH answers on right now, defaulting
// to 22 when detection found nothing (conservative pre-open).
func currentSSHPorts(s *DetectedState) []int {
	ports := append([]int{}, s.SSH.ListeningPorts...)
	if len(ports) == 0 {
		ports = []int{22}
	}
	return ports
}

// sshPortChanged reports whether the plan introduces a NEW ssh listener port.
func sshPortChanged(p Profile, s *DetectedState) (int, bool) {
	if p.SSH == nil || p.SSH.Port == 0 {
		return 0, false
	}
	want := p.SSH.Port
	for _, cur := range s.SSH.ListeningPorts {
		if cur == want {
			return want, false
		}
	}
	return want, true
}

// applyRisky executes the risky items of an already-planned profile under
// the safe-apply discipline. j collects steps as they happen.
func applyRisky(ctx context.Context, profile Profile, state *DetectedState, j *Journal, risky []PlanItem, opts ApplyOpts) (riskyOutcome, error) {
	var out riskyOutcome

	curPorts := currentSSHPorts(state)
	newPort, portChanged := sshPortChanged(profile, state)
	wantPorts := append([]int{}, curPorts...)
	if portChanged {
		wantPorts = append(wantPorts, newPort)
	}
	sshSvc := sshServiceName(ctx)

	// ---- 1. pre-open current + new SSH ports ----
	pre := Step{Item: PlanItem{
		Kind: KindFwRuleAdd, ID: "safe-apply:pre-open",
		Summary: "pre-open SSH paths before any risky change (additive allows)",
	}}
	portsToOpen := append([]int{}, curPorts...)
	if portChanged {
		portsToOpen = append(portsToOpen, newPort)
	}
	fwManageable := state.Firewall.Backend == "ufw" && state.Firewall.UfwActive
	if fwManageable {
		for _, p := range dedupePorts(portsToOpen) {
			add := []string{"ufw", "allow", strconv.Itoa(p) + "/tcp", "comment", hardeningCommentTag + preOpenOwner}
			del := []string{"ufw", "delete", "allow", strconv.Itoa(p) + "/tcp"}
			if _, err := run(ctx, add[0], add[1:]...); err != nil {
				// An additive allow failing is not fatal by itself (the rule
				// may already exist); the banner probe in step 2 decides.
				pre.Note += fmt.Sprintf("allow %d: %v; ", p, err)
				continue
			}
			pre.Cmds = append(pre.Cmds, add)
			pre.Undo = append(pre.Undo, del)
		}
		j.Steps = append(j.Steps, pre)
	}

	// ---- 2. verify the CURRENT SSH path before touching anything ----
	if vr := verifySSHPath(curPorts); vr != nil {
		out.verify = append(out.verify, *vr)
		if !vr.OK {
			return out, fmt.Errorf("SSH path was already broken before any change: %s (aborted, nothing modified)", vr.Detail)
		}
	}

	// ---- 3. write the rollback script and arm the timer ----
	undoPlan := plannedRiskyUndos(state, risky, sshSvc)
	if err := writeRollbackScript(j.ID, undoPlan); err != nil {
		return out, fmt.Errorf("cannot write rollback script: %v (nothing risky changed)", err)
	}
	unit, err := armRollbackTimer(ctx, j.ID, opts.RollbackTimeoutSec)
	if err != nil {
		out.verify = append(out.verify, VerifyResult{ItemID: "safe-apply.timer", OK: false, Detail: err.Error()})
		return out, fmt.Errorf("cannot arm the rollback timer: %v (aborted before any risky change)", err)
	}
	out.armed, out.timerUnit = true, unit
	j.TimerUnit, j.TimeoutSec = unit, opts.RollbackTimeoutSec
	j.Steps = append(j.Steps, Step{
		Item: PlanItem{Kind: "safe-apply.timer", ID: "timer:" + unit, Summary: "armed automatic rollback (" + strconv.Itoa(opts.RollbackTimeoutSec) + " s)"},
		Cmds: [][]string{{"systemd-run", "--on-active=" + strconv.Itoa(opts.RollbackTimeoutSec) + "s", "--unit=" + unit, "--collect", "/bin/sh", rollbackScriptPath(j.ID)}},
	})
	out.verify = append(out.verify, VerifyResult{ItemID: "safe-apply.timer", OK: true, Detail: unit + ".timer"})

	// ---- 4. execute risky items in order ----
	for _, it := range risky {
		step, err := applyRiskyItem(ctx, it, state, sshSvc)
		j.Steps = append(j.Steps, step)
		if err != nil {
			return out, fmt.Errorf("%s: %v", it.ID, err)
		}
		switch it.Kind {
		case KindSSHConfig:
			if err := sshdValidate(ctx); err != nil {
				return out, fmt.Errorf("%s: %v (the invalid config was NOT loaded; rolling back)", it.ID, err)
			}
			if err := sshdReload(ctx); err != nil {
				return out, fmt.Errorf("%s: %v", it.ID, err)
			}
			time.Sleep(listenerSettle)
			vr := waitSSHPath(wantPorts)
			out.verify = append(out.verify, *vr)
			if !vr.OK {
				return out, fmt.Errorf("%s: SSH did not answer after the change: %s", it.ID, vr.Detail)
			}
		case KindFwPolicyIn, KindFwPolicyOut:
			// A default-policy flip is the exact moment a lockout happens:
			// re-probe immediately.
			vr := waitSSHPath(wantPorts)
			out.verify = append(out.verify, *vr)
			if !vr.OK {
				return out, fmt.Errorf("%s: firewall policy cut the SSH path: %s", it.ID, vr.Detail)
			}
		}
	}
	return out, nil
}

// applyRiskyItem executes one risky plan item and records its undo.
func applyRiskyItem(ctx context.Context, it PlanItem, state *DetectedState, sshSvc string) (Step, error) {
	step := Step{Item: it}
	switch it.Kind {
	case KindFwRuleAdd, KindFwRuleDel:
		for _, cmd := range it.Cmds {
			if _, err := run(ctx, cmd[0], cmd[1:]...); err != nil {
				// ufw add of an existing rule says "Skipping adding existing
				// rule" with exit 0; a delete of a missing rule errors —
				// tolerate that specific idempotent case.
				if it.Kind == KindFwRuleDel && ufwNotFoundOutput(err) {
					step.Skipped = true
					continue
				}
				return step, fmt.Errorf("%v: %v", cmd, err)
			}
			step.Cmds = append(step.Cmds, cmd)
			if mirror := mirrorUfw(cmd); mirror != nil {
				step.Undo = append(step.Undo, mirror)
			}
		}
		return step, nil
	case KindFwPolicyIn, KindFwPolicyOut:
		for _, cmd := range it.Cmds {
			if _, err := run(ctx, cmd[0], cmd[1:]...); err != nil {
				return step, fmt.Errorf("%v: %v", cmd, err)
			}
			step.Cmds = append(step.Cmds, cmd)
		}
		prev := state.Firewall.DefaultIncoming
		if it.Kind == KindFwPolicyOut {
			prev = state.Firewall.DefaultOutgoing
		}
		if prev == "" {
			prev = "allow" // ufw factory default; safest restore target
		}
		family := "incoming"
		if it.Kind == KindFwPolicyOut {
			family = "outgoing"
		}
		step.Undo = [][]string{{"ufw", "default", prev, family}}
		return step, nil
	case KindSSHConfig:
		prev, had := "", false
		if b, err := readFile(sshDropInPath); err == nil {
			prev, had = string(b), true
		}
		if err := writeFileAtomic(sshDropInPath, it.After, 0o600); err != nil {
			return step, fmt.Errorf("write drop-in: %v", err)
		}
		step.Files = []FileUndo{{Path: sshDropInPath, Before: prev, Absent: !had, Mode: 0o600}}
		step.Undo = [][]string{{"systemctl", "reload", sshSvc}}
		return step, nil
	}
	return step, fmt.Errorf("applyRiskyItem: unhandled kind %q", it.Kind)
}

// ufwNotFoundOutput reports the "could not delete non-existent rule" case.
func ufwNotFoundOutput(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "could not delete") || strings.Contains(s, "non-existent") || strings.Contains(s, "not found")
}

// mirrorUfw builds the inverse of one ufw argv (allow<->delete). Comments
// are metadata: deletes drop them.
func mirrorUfw(argv []string) []string {
	if len(argv) < 2 || argv[0] != "ufw" {
		return nil
	}
	switch argv[1] {
	case "allow", "limit":
		out := []string{"ufw", "delete"}
		for _, a := range argv[1:] {
			out = append(out, a)
		}
		return stripComment(out)
	case "delete":
		out := []string{"ufw"}
		for _, a := range argv[2:] {
			out = append(out, a)
		}
		return stripComment(out)
	}
	return nil
}

// stripComment removes a trailing ["comment", tag] pair.
func stripComment(argv []string) []string {
	for i, a := range argv {
		if a == "comment" && i+1 < len(argv) {
			return append(argv[:i:i], argv[i+2:]...)
		}
	}
	return argv
}

// ---- undo planning (for the pre-armed rollback script) ----

// undoEntry is one planned inverse mutation.
type undoEntry struct {
	Files []FileUndo
	Cmds  [][]string
}

// plannedRiskyUndos computes, BEFORE any risky mutation, the inverse of
// every intended change (in reverse execution order). Because every entry
// is idempotent, the script restores correctly even if the apply died
// halfway through.
func plannedRiskyUndos(state *DetectedState, risky []PlanItem, sshSvc string) []undoEntry {
	var out []undoEntry
	for i := len(risky) - 1; i >= 0; i-- {
		it := risky[i]
		switch it.Kind {
		case KindFwRuleAdd, KindFwRuleDel:
			e := undoEntry{}
			for _, cmd := range it.Cmds {
				if m := mirrorUfw(cmd); m != nil {
					e.Cmds = append(e.Cmds, m)
				}
			}
			out = append(out, e)
		case KindFwPolicyIn, KindFwPolicyOut:
			prev := state.Firewall.DefaultIncoming
			family := "incoming"
			if it.Kind == KindFwPolicyOut {
				prev = state.Firewall.DefaultOutgoing
				family = "outgoing"
			}
			if prev == "" {
				prev = "allow"
			}
			out = append(out, undoEntry{Cmds: [][]string{{"ufw", "default", prev, family}}})
		case KindSSHConfig:
			out = append(out, undoEntry{
				Files: []FileUndo{{Path: sshDropInPath, Before: state.SSH.DropInContent, Absent: !state.SSH.DropInPresent, Mode: 0o600}},
				Cmds:  [][]string{{"systemctl", "reload", sshSvc}},
			})
		}
	}
	return out
}

// ---- timer ----

// armRollbackTimer arms `systemd-run --on-active` for the rollback script
// and verifies the timer is actually running before returning.
func armRollbackTimer(ctx context.Context, journalID string, timeoutSec int) (string, error) {
	unit := "quantum-harden-" + journalID
	argv := []string{
		"systemd-run", "--on-active=" + strconv.Itoa(timeoutSec) + "s",
		"--unit=" + unit, "--collect", "--quiet",
		"/bin/sh", rollbackScriptPath(journalID),
	}
	if out, err := run(ctx, argv[0], argv[1:]...); err != nil {
		return "", fmt.Errorf("systemd-run: %v: %s", err, strings.TrimSpace(string(out)))
	}
	out, err := run(ctx, "systemctl", "is-active", unit+".timer")
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		// Clean up the half-created unit pair before reporting.
		_, _ = run(ctx, "systemctl", "stop", unit+".timer")
		_, _ = run(ctx, "systemctl", "reset-failed", unit+".service")
		return "", fmt.Errorf("timer %s did not reach active state", unit)
	}
	return unit, nil
}

// disarmRollbackTimer stops the timer and any pending service run.
func disarmRollbackTimer(ctx context.Context, unit string) {
	if unit == "" {
		return
	}
	_, _ = run(ctx, "systemctl", "stop", unit+".timer")
	_, _ = run(ctx, "systemctl", "stop", unit+".service")
	_, _ = run(ctx, "systemctl", "reset-failed", unit+".service")
}

// timerActive reports whether a rollback timer is still armed.
func timerActive(ctx context.Context, unit string) bool {
	if unit == "" {
		return false
	}
	out, err := run(ctx, "systemctl", "is-active", unit+".timer")
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// ---- confirm / rollback entry points ----

// Confirm marks a journal as panel-confirmed: the timer is disarmed, the
// temporary pre-open allows are removed where safe (port moved away, or the
// profile now declares the port itself), and the journal is finalized.
func Confirm(ctx context.Context, id string) (*Journal, error) {
	j, err := loadJournalOrLatest(id)
	if err != nil {
		return nil, err
	}
	disarmRollbackTimer(ctx, j.TimerUnit)

	// Which ports does the profile itself declare? (j keeps no profile copy;
	// the pre-open step's undo plus a fresh detect decides what to remove.)
	state := Detect(ctx)
	listening := map[int]bool{}
	for _, p := range state.SSH.ListeningPorts {
		listening[p] = true
	}
	for i := len(j.Steps) - 1; i >= 0; i-- {
		step := j.Steps[i]
		if step.Item.ID != "safe-apply:pre-open" {
			continue
		}
		for k := len(step.Cmds) - 1; k >= 0; k-- {
			cmd := step.Cmds[k]
			port := preOpenPortOf(cmd)
			if port == 0 {
				continue
			}
			// Keep the allow while the port is still an SSH listener the
			// profile does not itself declare — removing it could cut access.
			if listening[port] && !portDeclaredByProfile(j, port) {
				continue
			}
			if mirror := mirrorUfw(cmd); mirror != nil {
				_, _ = run(ctx, mirror[0], mirror[1:]...) // best effort; convergence reports leftovers
			}
		}
	}
	j.Confirmed = true
	j.FinishedAt = nowUnix()
	_ = saveJournal(j)
	markJournalTerminal(j, ".confirmed")
	_ = os.Remove(rollbackScriptPath(j.ID))
	_ = os.Remove(rollbackLogPath(j.ID))
	return j, nil
}

// preOpenPortOf extracts the port from a pre-open ufw allow argv.
func preOpenPortOf(argv []string) int {
	for i, a := range argv {
		if i > 0 && strings.HasSuffix(a, "/tcp") {
			if p, err := strconv.Atoi(strings.TrimSuffix(a, "/tcp")); err == nil {
				return p
			}
		}
	}
	return 0
}

// portDeclaredByProfile reports whether the journal names the profile
// declaring this port. Journals carry no profile copy, so the conservative
// rule is: keep the allow unless detection shows the port no longer
// listening (the port-moved case). When the profile declares the same port
// its own rule already allows it, so a leftover duplicate is harmless and
// surfaces in status leftovers.
func portDeclaredByProfile(j *Journal, port int) bool {
	_ = j // journals do not store the profile; see comment above
	return false
}

// Rollback undoes the last (or named) journal: the inverse of everything it
// applied, timer disarmed, journal marked rolled back.
func Rollback(ctx context.Context, id string) (*Journal, error) {
	j, err := loadJournalOrLatest(id)
	if err != nil {
		return nil, err
	}
	if errs := rollbackJournal(ctx, j, "manual rollback"); len(errs) > 0 {
		return j, fmt.Errorf("rollback incomplete: %v", errs)
	}
	return j, nil
}

func loadJournalOrLatest(id string) (*Journal, error) {
	if strings.TrimSpace(id) == "" {
		return LoadLatestJournal()
	}
	return LoadJournal(id)
}

// dedupePorts preserves order, removes duplicates.
func dedupePorts(ports []int) []int {
	seen := map[int]bool{}
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// waitSSHPath probes with a few retries (sshd re-listen latency).
func waitSSHPath(ports []int) *VerifyResult {
	deadline := time.Now().Add(8 * time.Second)
	var last *VerifyResult
	for {
		last = verifySSHPath(ports)
		if last.OK {
			return last
		}
		if time.Now().After(deadline) {
			return last
		}
		time.Sleep(500 * time.Millisecond)
	}
}
