// sysctlapply.go — sysctl application as ONE owned drop-in. Keys already
// owned by the netopt engine's drop-in are never touched (plan blocks them
// before we get here). The drop-in is merged: repeated applies update only
// the keys they declare, leaving earlier hardening keys intact. A foreign
// (non-Quantum) file at the owned path is never overwritten.

package hardening

import (
	"context"
	"fmt"
	"strings"
)

// applySysctlSet merges all planned sysctl items into the owned drop-in,
// applies it with `sysctl -p`, and read-verifies every key. One Step covers
// the set (single file write, per-key undo values).
func applySysctlSet(ctx context.Context, items []PlanItem, before *DetectedState) (Step, error) {
	step := Step{Item: PlanItem{
		Kind: KindSysctl, ID: fmt.Sprintf("sysctl:%d keys", len(items)),
		Summary: "apply " + sysctlDropInPath,
	}}

	prev, had := "", false
	if b, err := readFile(sysctlDropInPath); err == nil {
		prev = string(b)
		had = true
		if !strings.Contains(prev, ownedMarker) {
			return step, fmt.Errorf("%s exists but is not Quantum-owned; refusing to overwrite", sysctlDropInPath)
		}
	}

	// Merge: existing owned keys, overlaid by this plan's items.
	values := map[string]string{}
	var order []string
	for _, line := range strings.Split(prev, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.Index(line, "=")
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		if _, seen := values[k]; !seen {
			order = append(order, k)
		}
		values[k] = strings.TrimSpace(line[i+1:])
	}
	for _, it := range items {
		key := strings.TrimPrefix(it.ID, "sysctl:")
		if _, seen := values[key]; !seen {
			order = append(order, key)
		}
		values[key] = it.After
	}

	var b strings.Builder
	b.WriteString(ownedMarker + "\n")
	b.WriteString("# quantum-agent hardening sysctl — safe-hygiene keys; performance tuning\n")
	b.WriteString("# (bbr, buffers, conntrack sizing) lives in the netopt engine's drop-in.\n")
	for _, k := range order {
		b.WriteString(k + " = " + values[k] + "\n")
	}
	if err := writeFileAtomic(sysctlDropInPath, b.String(), 0o644); err != nil {
		return step, fmt.Errorf("write drop-in: %v", err)
	}
	step.Files = []FileUndo{{Path: sysctlDropInPath, Before: prev, Absent: !had, Mode: 0o644}}

	if out, err := run(ctx, "sysctl", "-p", sysctlDropInPath); err != nil {
		return step, fmt.Errorf("sysctl -p: %v: %s", err, strings.TrimSpace(string(out)))
	}
	step.Cmds = append(step.Cmds, []string{"sysctl", "-p", sysctlDropInPath})

	// Read-back verification for every key this set touched (the setup.sh
	// discipline: nothing is silent).
	for _, it := range items {
		key := strings.TrimPrefix(it.ID, "sysctl:")
		got := readSysctl(key)
		if !sysctlEq(got, it.After) {
			return step, fmt.Errorf("verify %s: kernel reports %q, want %q", key, got, it.After)
		}
		// Per-key undo: restore the captured before value when there was one.
		if it.Before != "" {
			argv := []string{"sysctl", "-w", key + "=" + it.Before}
			step.Undo = append(step.Undo, argv)
		}
	}
	return step, nil
}

// ownedMarker identifies the owned sysctl drop-in (also used by the merge).
const ownedMarker = "# managed by quantum-agent hardening — do not edit; revert with hardening.rollback"
