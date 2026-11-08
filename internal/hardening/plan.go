// plan.go — the Plan stage: diff DetectedState against a Profile into an
// ordered, displayable, JSON-serializable list of items. A plan never
// touches the host. Blocked items (safety guards fired) stay in the plan so
// the operator sees WHY nothing happened; apply skips them.

package hardening

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// Item kinds.
const (
	KindFwPolicyIn  = "firewall.policy.incoming"
	KindFwPolicyOut = "firewall.policy.outgoing"
	KindFwRuleAdd   = "firewall.rule.add"
	KindFwRuleDel   = "firewall.rule.remove"
	KindSSHConfig   = "ssh.config"
	KindSysctl      = "sysctl"
	KindFail2Ban    = "fail2ban"
	KindTimeSync    = "timesync"
	KindJournald    = "journald"
)

// PlanItem is one diff entry. Cmds is what apply would execute (display
// only in plans; the journal records the actually-executed forms).
type PlanItem struct {
	Kind          string     `json:"kind"`
	ID            string     `json:"id"`
	Summary       string     `json:"summary"`
	Before        string     `json:"before,omitempty"`
	After         string     `json:"after,omitempty"`
	Risky         bool       `json:"risky,omitempty"`   // can cut remote access → safe-apply mandatory
	Blocked       bool       `json:"blocked,omitempty"` // safety guard fired; apply must skip
	BlockedReason string     `json:"blocked_reason,omitempty"`
	Cmds          [][]string `json:"cmds,omitempty"`
}

// Plan is the ordered diff for one profile.
type Plan struct {
	ID          string     `json:"id"`
	ProfileName string     `json:"profile_name"`
	Items       []PlanItem `json:"items"`
	Risky       bool       `json:"risky"` // any non-blocked risky item
	Noop        bool       `json:"noop"`  // zero actionable items
}

// PlanProfile diffs state against profile. currentDropIn is the current
// owned sshd drop-in content ("" = absent); it is passed in (rather than
// re-read) so callers can plan against a detect they already hold.
func PlanProfile(profile Profile, state *DetectedState) (*Plan, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	plan := &Plan{ID: planID("hp"), ProfileName: profile.Name}
	planItems(profile, state, plan)
	sshItems(profile, state, plan)
	sysctlItems(profile, state, plan)
	miscItems(profile, state, plan)
	for _, it := range plan.Items {
		if it.Risky && !it.Blocked {
			plan.Risky = true
		}
	}
	// Noop means: nothing desired at all (zero items). A plan whose items
	// are all BLOCKED is not a noop — it is a plan that would do nothing on
	// purpose; apply reports it as success-with-nothing-applied.
	plan.Noop = len(plan.Items) == 0
	return plan, nil
}

// ---- firewall planning ----

func planItems(p Profile, s *DetectedState, plan *Plan) {
	fw := p.Firewall
	if fw == nil {
		return
	}
	blocked := firewallBlockedReason(s)

	if fw.DefaultDenyIncoming != nil && (blocked != "" || s.Firewall.DefaultIncoming != policyName(*fw.DefaultDenyIncoming)) {
		it := PlanItem{
			Kind: KindFwPolicyIn, ID: "policy:incoming", Risky: true,
			Summary: "ufw default policy incoming = " + policyName(*fw.DefaultDenyIncoming),
			Before:  s.Firewall.DefaultIncoming, After: policyName(*fw.DefaultDenyIncoming),
			Cmds: [][]string{{"ufw", "default", policyName(*fw.DefaultDenyIncoming), "incoming"}},
		}
		if blocked != "" {
			blockItem(&it, blocked)
		}
		plan.Items = append(plan.Items, it)
	}
	if fw.AllowOutgoing != nil && (blocked != "" || s.Firewall.DefaultOutgoing != policyName(*fw.AllowOutgoing)) {
		it := PlanItem{
			Kind: KindFwPolicyOut, ID: "policy:outgoing",
			Summary: "ufw default policy outgoing = " + policyName(*fw.AllowOutgoing),
			Before:  s.Firewall.DefaultOutgoing, After: policyName(*fw.AllowOutgoing),
			Cmds: [][]string{{"ufw", "default", policyName(*fw.AllowOutgoing), "outgoing"}},
		}
		if blocked != "" {
			blockItem(&it, blocked)
		}
		plan.Items = append(plan.Items, it)
	}

	for _, r := range fw.Allows {
		it := fwRuleItem(r, false, s)
		plan.Items = append(plan.Items, it)
	}
	for _, r := range fw.Limits {
		it := fwRuleItem(r, true, s)
		plan.Items = append(plan.Items, it)
	}

	// Convergence: our tagged rules that the profile no longer declares are
	// removed. safe-apply pre-open rules (owner "safe-apply") are exempt —
	// they are removed by Confirm/Rollback, never by convergence, because
	// removing them mid-window is exactly the lockout this module exists to
	// prevent.
	desired := map[string]bool{}
	for _, r := range append(append([]PortRule{}, fw.Allows...), fw.Limits...) {
		desired[ruleKey(r, isLimitOwner(r, fw))] = true
	}
	for _, raw := range s.Firewall.Ours {
		owner, r, limit := parseOurRule(raw)
		if owner == "" || owner == "safe-apply" {
			continue
		}
		if desired[ruleKey(r, limit)] {
			continue
		}
		it := PlanItem{
			Kind: KindFwRuleDel, ID: "remove:" + ruleKey(r, limit), Risky: true,
			Summary: "remove Quantum-owned rule no longer in profile: " + ruleKey(r, limit),
			Before:  raw,
			Cmds:    ufwDeleteCmds(r, limit),
		}
		if blocked != "" {
			blockItem(&it, blocked)
		}
		plan.Items = append(plan.Items, it)
	}
}

// isLimitOwner reports whether the rule sits in the profile's Limits list.
func isLimitOwner(r PortRule, fw *FirewallSpec) bool {
	for _, l := range fw.Limits {
		if l.Port == r.Port && l.Proto == r.Proto && l.From == r.From && l.Owner == r.Owner {
			return true
		}
	}
	return false
}

// firewallBlockedReason returns "" when ufw is active and manageable.
func firewallBlockedReason(s *DetectedState) string {
	if s.Firewall.Backend != "ufw" {
		return s.Firewall.ReasonNotManaged
	}
	if !s.Firewall.UfwActive {
		return "ufw is installed but inactive; hardening never enables a firewall (the installer enables it after pre-opening SSH). Enable ufw first, then re-apply"
	}
	return ""
}

func blockItem(it *PlanItem, reason string) {
	it.Blocked = true
	it.BlockedReason = reason
}

// policyName maps bool → ufw policy word.
func policyName(v bool) string {
	if v {
		return "deny"
	}
	return "allow"
}

func fwRuleItem(r PortRule, limit bool, s *DetectedState) PlanItem {
	key := ruleKey(r, limit)
	it := PlanItem{
		Kind:    KindFwRuleAdd,
		ID:      key,
		Summary: "ufw " + ruleVerb(limit) + " " + key + " (owner " + r.Owner + ")",
		Cmds:    ufwAddCmds(r, limit),
	}
	if firewallBlockedReason(s) != "" {
		blockItem(&it, firewallBlockedReason(s))
		return it
	}
	if ufwRulePresent(s.Firewall.RawRules, r, limit) {
		it.Before = "present"
		it.After = "present"
		it.Cmds = nil
		it.Summary = it.Summary + " — already present, no-op"
	}
	return it
}

func ruleVerb(limit bool) string {
	if limit {
		return "limit"
	}
	return "allow"
}

// ruleKey is the stable identity of a rule.
func ruleKey(r PortRule, limit bool) string {
	src := "any"
	if r.From != "" {
		src = r.From
	}
	return fmt.Sprintf("%s %s/%s from %s [%s]", ruleVerb(limit), strconv.Itoa(r.Port), r.Proto, src, r.Owner)
}

// ufwAddCmds builds the additive ufw command (+ its exact inverse).
func ufwAddCmds(r PortRule, limit bool) [][]string {
	verb := ruleVerb(limit)
	tag := hardeningCommentTag + r.Owner
	if r.From != "" {
		return [][]string{{"ufw", verb, "from", r.From, "to", "any", "port", strconv.Itoa(r.Port), "proto", r.Proto, "comment", tag}}
	}
	return [][]string{{"ufw", verb, strconv.Itoa(r.Port) + "/" + r.Proto, "comment", tag}}
}

func ufwDeleteCmds(r PortRule, limit bool) [][]string {
	verb := ruleVerb(limit)
	tag := hardeningCommentTag + r.Owner
	if r.From != "" {
		return [][]string{{"ufw", "delete", verb, "from", r.From, "to", "any", "port", strconv.Itoa(r.Port), "proto", r.Proto, "comment", tag}}
	}
	return [][]string{{"ufw", "delete", verb, strconv.Itoa(r.Port) + "/" + r.Proto, "comment", tag}}
}

// ufwRulePresent matches the rule in `ufw status numbered` output: the
// spec token, the ALLOW/LIMIT verb, the source column (when given) and the
// owner tag. v6 twins count as present (one command adds both families).
func ufwRulePresent(raw string, r PortRule, limit bool) bool {
	spec := strconv.Itoa(r.Port) + "/" + r.Proto
	verb := strings.ToUpper(ruleVerb(limit))
	for _, line := range strings.Split(raw, "\n") {
		if !strings.Contains(line, hardeningCommentTag+r.Owner) {
			continue
		}
		if !strings.Contains(line, spec) || !strings.Contains(line, verb) {
			continue
		}
		if r.From != "" && !strings.Contains(line, r.From) {
			continue
		}
		return true
	}
	return false
}

// parseOurRule parses one tagged status line back into its rule. Best
// effort: unparseable lines return owner="" and are ignored by convergence.
func parseOurRule(line string) (owner string, r PortRule, limit bool) {
	i := strings.Index(line, hardeningCommentTag)
	if i < 0 {
		return "", PortRule{}, false
	}
	owner = strings.TrimSpace(line[i+len(hardeningCommentTag):])
	if j := strings.IndexAny(owner, " \t()"); j >= 0 {
		owner = owner[:j]
	}
	upper := strings.ToUpper(line)
	limit = strings.Contains(upper, "LIMIT")
	fields := strings.Fields(line)
	for _, f := range fields {
		if k := strings.Index(f, "/"); k > 0 && portRe.MatchString(f[:k]) {
			p, err := strconv.Atoi(f[:k])
			if err != nil {
				continue
			}
			r.Port = p
			r.Proto = strings.ToLower(f[k+1:])
			break
		}
	}
	for _, f := range fields {
		if netParseOK(f) {
			r.From = f
			break
		}
	}
	r.Owner = owner
	if r.Port == 0 || (r.Proto != "tcp" && r.Proto != "udp") || owner == "" {
		return "", PortRule{}, false
	}
	return owner, r, limit
}

// netParseOK accepts plain IPs and CIDRs (v4/v6) for the From column.
func netParseOK(s string) bool {
	if strings.Contains(s, "/") {
		return cidrRe.MatchString(s)
	}
	return cidrRe.MatchString(s) && strings.ContainsAny(s, ".:")
}

// ---- ssh planning ----

// sshItems plans at most one item for the owned sshd drop-in.
func sshItems(p Profile, s *DetectedState, plan *Plan) {
	spec := p.SSH
	if spec == nil {
		return
	}
	want := RenderSSHDropIn(spec)
	have := s.SSH.DropInContent
	// Earlier-sorting vendor drop-ins that set the same directives LOSE to
	// ours only when they sort after: sshd takes the FIRST value and Include
	// processes files lexicographically. Our 00- prefix sorts first (beats
	// vendor files like 01-arvan-*), but the operator must still SEE any
	// drop-in that sorts before ours and sets the same keys
	// (RUNBOOK-FIXES item 10).
	conflicts := sshdDropInConflicts(sshDropInDir, sshDropInPath, renderSSHDropInKeywords(spec))
	conflictNote := ""
	if len(conflicts) > 0 {
		conflictNote = "; WARNING: conflicting earlier drop-ins set the same keys and will be overridden: " + strings.Join(conflicts, ", ")
	}
	appendSSH := func(it PlanItem) {
		it.Summary += conflictNote
		plan.Items = append(plan.Items, it)
	}
	if spec.KeyOnly != nil && *spec.KeyOnly {
		if !s.Keys.AnyKeyPresent {
			it := PlanItem{
				Kind: KindSSHConfig, ID: "ssh.config", Risky: true,
				Summary: "enforce SSH key-only authentication",
				After:   want,
			}
			blockItem(&it, "no authorized public key found for any user; refusing to enforce key-only (install a key first — the panel must verify `ssh.keyscan` or the operator must add one)")
			appendSSH(it)
			return
		}
		// Root-login removal while root is the only key holder = lockout.
		if spec.PermitRoot == "no" && keysOnlyForRoot(s.Keys) {
			it := PlanItem{
				Kind: KindSSHConfig, ID: "ssh.config", Risky: true,
				Summary: "enforce key-only SSH and disable root login",
				After:   want,
			}
			blockItem(&it, "root is the only user with an authorized key; PermitRootLogin no would remove the last access path. Add a key for an admin user first")
			appendSSH(it)
			return
		}
	}
	if have == want {
		return
	}
	it := PlanItem{
		Kind: KindSSHConfig, ID: "ssh.config", Risky: true,
		Summary: "update the owned sshd drop-in " + sshDropInPath,
		Before:  have, After: want,
	}
	appendSSH(it)
}

// sshdDropInConflicts lists other drop-ins in dir that sort BEFORE ours
// (lexicographically) and set any of the given keywords. dirList is a
// seam (tests point it at the fake host root).
func sshdDropInConflicts(dir, ourPath string, keywords []string) []string {
	entries, err := dirList(dir)
	if err != nil {
		return nil
	}
	ours := filepath.Base(ourPath)
	var conflicts []string
	for _, e := range entries {
		name := e.Name()
		if name == ours || !strings.HasSuffix(name, ".conf") || strings.HasPrefix(name, ".") {
			continue
		}
		if !(name < ours) {
			continue // sorts after ours: WE win anyway
		}
		data, rerr := readFile(filepath.Join(dir, name))
		if rerr != nil {
			continue
		}
		for _, kw := range keywords {
			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(kw)) {
					conflicts = append(conflicts, name+" ("+kw+")")
					break
				}
			}
		}
	}
	return conflicts
}

// renderSSHDropInKeywords returns the directives RenderSSHDropIn may emit
// for the spec (the conflict scan matches on these).
func renderSSHDropInKeywords(spec *SSHSpec) []string {
	kw := []string{}
	if spec.Port != 0 {
		kw = append(kw, "Port")
	}
	if spec.KeyOnly != nil && *spec.KeyOnly {
		kw = append(kw, "PasswordAuthentication", "KbdInteractiveAuthentication", "PermitEmptyPasswords")
	}
	if spec.PermitRoot != "" {
		kw = append(kw, "PermitRootLogin")
	}
	if spec.MaxAuthTries != 0 {
		kw = append(kw, "MaxAuthTries")
	}
	return kw
}

func keysOnlyForRoot(k SSHKeysState) bool {
	return k.AnyKeyPresent && len(k.Users) == 1 && k.Users[0] == "root"
}

// RenderSSHDropIn renders the exact drop-in content for a spec. Only the
// directives the spec sets appear; deterministic order so plans diff clean.
func RenderSSHDropIn(spec *SSHSpec) string {
	var b strings.Builder
	b.WriteString("# managed by quantum-agent hardening — do not edit\n")
	b.WriteString("# the first obtained value wins in sshd_config; this file is included\n")
	b.WriteString("# from the TOP of sshd_config (Ubuntu/Debian), so it overrides the base file.\n")
	if spec.Port != 0 {
		b.WriteString("Port " + strconv.Itoa(spec.Port) + "\n")
	}
	if spec.KeyOnly != nil && *spec.KeyOnly {
		b.WriteString("PasswordAuthentication no\n")
		b.WriteString("KbdInteractiveAuthentication no\n")
		b.WriteString("PermitEmptyPasswords no\n")
	}
	if spec.PermitRoot != "" {
		b.WriteString("PermitRootLogin " + spec.PermitRoot + "\n")
	}
	if spec.MaxAuthTries != 0 {
		b.WriteString("MaxAuthTries " + strconv.Itoa(spec.MaxAuthTries) + "\n")
	}
	return b.String()
}

// ---- sysctl planning ----

func sysctlItems(p Profile, s *DetectedState, plan *Plan) {
	if len(p.Sysctl) == 0 {
		return
	}
	owned := map[string]bool{}
	for _, k := range s.Sysctl.NetoptOwned {
		owned[k] = true
	}
	// Stable order: iterate as given, but merge into one drop-in item set.
	for _, rule := range p.Sysctl {
		if owned[rule.Key] {
			it := PlanItem{
				Kind: KindSysctl, ID: "sysctl:" + rule.Key,
				Summary: "sysctl " + rule.Key + " = " + rule.Value,
				After:   rule.Value,
			}
			blockItem(&it, "key owned by the netopt engine's drop-in (99-quantum-netopt.conf); change it in the netopt profile, not hardening")
			plan.Items = append(plan.Items, it)
			continue
		}
		cur := readSysctl(rule.Key)
		if sysctlEq(cur, rule.Value) {
			continue
		}
		plan.Items = append(plan.Items, PlanItem{
			Kind: KindSysctl, ID: "sysctl:" + rule.Key,
			Summary: "sysctl " + rule.Key + ": " + displayVal(cur) + " -> " + rule.Value,
			Before:  cur, After: rule.Value,
			Cmds: [][]string{{"sysctl", "-w", rule.Key + "=" + rule.Value}},
		})
	}
}

// sysctlEq compares token-normalized (vector values print with tabs).
func sysctlEq(a, b string) bool {
	return strings.Join(strings.Fields(a), " ") == strings.Join(strings.Fields(b), " ")
}

func displayVal(v string) string {
	if v == "" {
		return "(unset)"
	}
	return v
}

// ---- fail2ban / timesync / journald planning ----

func miscItems(p Profile, s *DetectedState, plan *Plan) {
	if p.SSH != nil && p.SSH.Fail2Ban != nil {
		fb := p.SSH.Fail2Ban
		if fb.Enabled {
			want := RenderFail2BanJail(fb, p.SSH.Port)
			if !s.Fail2Ban.Installed {
				it := PlanItem{
					Kind: KindFail2Ban, ID: "fail2ban",
					Summary: "enable fail2ban sshd jail",
					After:   want,
				}
				blockItem(&it, "fail2ban is not installed on this host (the installer installs it); profile continues without it")
				plan.Items = append(plan.Items, it)
			} else if !s.Fail2Ban.OurJailPath || jailDiffers(s, want) {
				plan.Items = append(plan.Items, PlanItem{
					Kind: KindFail2Ban, ID: "fail2ban",
					Summary: "write fail2ban sshd jail drop-in " + fail2banJailPath,
					Before:  jailContent(s), After: want,
					Cmds: [][]string{
						{"systemctl", "enable", "--now", "fail2ban"},
						{"systemctl", "restart", "fail2ban"},
					},
				})
			} else if !s.Fail2Ban.Active {
				plan.Items = append(plan.Items, PlanItem{
					Kind: KindFail2Ban, ID: "fail2ban",
					Summary: "start fail2ban (jail already configured)",
					Cmds:    [][]string{{"systemctl", "restart", "fail2ban"}},
				})
			}
		} else if s.Fail2Ban.OurJailPath {
			plan.Items = append(plan.Items, PlanItem{
				Kind: KindFail2Ban, ID: "fail2ban:remove",
				Summary: "remove the owned fail2ban jail drop-in",
				Before:  jailContent(s),
				Cmds:    [][]string{{"systemctl", "reload-or-restart", "fail2ban"}},
			})
		}
	}

	if p.TimeSync != nil && p.TimeSync.EnsureActive && !s.TimeSync.NTPActive {
		it := PlanItem{
			Kind: KindTimeSync, ID: "timesync",
			Summary: "enable systemd-timesyncd (NTP was " + orDash(s.TimeSync.Detail) + ")",
			Cmds:    [][]string{{"systemctl", "enable", "--now", "systemd-timesyncd"}},
		}
		if s.TimeSync.Detail == "timedatectl unavailable" {
			blockItem(&it, "timedatectl is not available; cannot manage time sync here")
		}
		plan.Items = append(plan.Items, it)
	}

	if p.Logging != nil && p.Logging.PersistentJournal && (!s.Logging.PersistentJournal || !s.Logging.DropInPresent) {
		plan.Items = append(plan.Items, PlanItem{
			Kind: KindJournald, ID: "journald",
			Summary: "enable a persistent systemd journal (" + journaldLogDir + " + drop-in)",
			Cmds: [][]string{
				{"systemctl", "try-restart", "systemd-journald"},
			},
		})
	}
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func jailDiffers(s *DetectedState, want string) bool {
	return jailContent(s) != want
}

func jailContent(s *DetectedState) string {
	if !s.Fail2Ban.OurJailPath {
		return ""
	}
	b, err := readFile(fail2banJailPath)
	if err != nil {
		return ""
	}
	return string(b)
}
