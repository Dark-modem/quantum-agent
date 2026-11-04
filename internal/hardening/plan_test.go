// plan_test.go — Plan generation: diffs, blocks, delegation, convergence.

package hardening

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hasItem(t *testing.T, plan *Plan, kind, idSubstr string) PlanItem {
	t.Helper()
	for _, it := range plan.Items {
		if it.Kind == kind && strings.Contains(it.ID, idSubstr) {
			return it
		}
	}
	t.Fatalf("plan has no %s item matching %q; items: %+v", kind, idSubstr, plan.Items)
	return PlanItem{}
}

func TestPlanConservativeFreshServer(t *testing.T) {
	h := newFakeHost(t)
	_ = h
	setProcValue(t, "net/ipv4/tcp_syncookies", "1") // already satisfied
	withKeys(t)                                     // no keys

	p := Conservative(22, []PortRule{{Port: 443, Proto: "tcp", Owner: "service:decoy"}})
	plan, err := PlanProfile(p, Detect(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Risky {
		t.Fatalf("conservative on a fresh ufw-active server must not be risky (no policy change needed: default is already deny; ssh rule re-added = noop), items: %+v", plan.Items)
	}

	// 443/tcp allow planned; 22 limit is a no-op (present in fake status).
	hasItem(t, plan, KindFwRuleAdd, "443/tcp")
	// All conservative sysctls planned except the satisfied one.
	sys := 0
	for _, it := range plan.Items {
		if it.Kind == KindSysctl {
			sys++
			if it.ID == "sysctl:net.ipv4.tcp_syncookies" {
				t.Fatalf("satisfied sysctl must not be planned")
			}
		}
	}
	if sys == 0 {
		t.Fatalf("expected unsatisfied conservative sysctls in the plan")
	}
	hasItem(t, plan, KindTimeSync, "timesync")
	hasItem(t, plan, KindJournald, "journald")
}

func TestPlanIncomingPolicyChangeIsRisky(t *testing.T) {
	h := newFakeHost(t)
	// Detection reports default policy ALLOW incoming.
	h.responses["ufw status verbose"] = "Status: active\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n"

	deny := true
	p := Profile{Version: ProfileVersion, Name: "t", Firewall: &FirewallSpec{DefaultDenyIncoming: &deny}}
	plan, err := PlanProfile(p, Detect(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	it := hasItem(t, plan, KindFwPolicyIn, "policy:incoming")
	if !it.Risky || it.Blocked {
		t.Fatalf("deny-incoming flip must be a risky, unblocked item: %+v", it)
	}
	if !plan.Risky {
		t.Fatalf("plan must be flagged risky")
	}
}

func TestPlanFirewallBlockedWhenUfwInactive(t *testing.T) {
	h := newFakeHost(t)
	h.responses["ufw status verbose"] = "Status: inactive\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n"
	h.responses["ufw status numbered"] = ""
	h.responses["ufw status"] = "Status: inactive"

	limit := PortRule{Port: 22, Proto: "tcp", Owner: "service:ssh"}
	p := Profile{Version: ProfileVersion, Name: "t",
		Firewall: &FirewallSpec{Limits: []PortRule{limit}}}
	plan, err := PlanProfile(p, Detect(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	it := hasItem(t, plan, KindFwRuleAdd, "22/tcp")
	if !it.Blocked {
		t.Fatalf("rule item must be blocked while ufw is inactive: %+v", it)
	}
	if plan.Risky {
		t.Fatalf("a fully blocked plan is not risky")
	}
	if plan.Noop {
		t.Fatalf("a plan with blocked items is not a noop")
	}
}

func TestPlanKeyOnlyBlockedWithoutKeys(t *testing.T) {
	_ = newFakeHost(t)
	no := true
	p := Profile{Version: ProfileVersion, Name: "t", SSH: &SSHSpec{KeyOnly: &no}}
	plan, err := PlanProfile(p, Detect(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	it := hasItem(t, plan, KindSSHConfig, "ssh.config")
	if !it.Blocked {
		t.Fatalf("key-only must be blocked when no authorized key exists: %+v", it)
	}
	if !strings.Contains(it.BlockedReason, "no authorized public key") {
		t.Fatalf("blocked reason must explain the guard, got: %s", it.BlockedReason)
	}
}

func TestPlanKeyOnlyAllowedWithKey(t *testing.T) {
	_ = newFakeHost(t)
	withKeys(t, "root")
	no := true
	p := Profile{Version: ProfileVersion, Name: "t", SSH: &SSHSpec{KeyOnly: &no}}
	plan, err := PlanProfile(p, Detect(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	it := hasItem(t, plan, KindSSHConfig, "ssh.config")
	if it.Blocked {
		t.Fatalf("key-only with a root key present must be plannable: %+v", it)
	}
	if !strings.Contains(it.After, "PasswordAuthentication no") {
		t.Fatalf("drop-in must enforce password off, got: %s", it.After)
	}
}

func TestPlanRootLoginNoBlockedWhenRootOnlyKeyHolder(t *testing.T) {
	_ = newFakeHost(t)
	withKeys(t, "root")
	no, rootNo := true, "no"
	p := Profile{Version: ProfileVersion, Name: "t", SSH: &SSHSpec{KeyOnly: &no, PermitRoot: rootNo}}
	plan, err := PlanProfile(p, Detect(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	it := hasItem(t, plan, KindSSHConfig, "ssh.config")
	if !it.Blocked || !strings.Contains(it.BlockedReason, "only user with an authorized key") {
		t.Fatalf("PermitRootLogin no with root as sole key holder must be blocked: %+v", it)
	}
}

func TestPlanSysctlDelegatedToNetopt(t *testing.T) {
	_ = newFakeHost(t)
	if err := os.MkdirAll(filepath.Dir(netoptSysctlPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(netoptSysctlPath, []byte("# managed by netopt\nnet.core.somaxconn = 8192\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := Profile{Version: ProfileVersion, Name: "t", Sysctl: []SysctlRule{
		{Key: "net.core.somaxconn", Value: "4096"},
		{Key: "net.ipv4.tcp_syncookies", Value: "1"},
	}}
	plan, err := PlanProfile(p, Detect(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	dep := hasItem(t, plan, KindSysctl, "sysctl:net.core.somaxconn")
	if !dep.Blocked || !strings.Contains(dep.BlockedReason, "netopt") {
		t.Fatalf("netopt-owned key must be delegated (blocked), got: %+v", dep)
	}
	// The non-owned key is planned normally.
	it := hasItem(t, plan, KindSysctl, "sysctl:net.ipv4.tcp_syncookies")
	if it.Blocked {
		t.Fatalf("non-netopt key must not be blocked: %+v", it)
	}
}

func TestPlanConvergenceRemovesStaleOwnedRule(t *testing.T) {
	h := newFakeHost(t)
	// An old quantum-owned rule for a port the profile no longer declares.
	h.responses["ufw status numbered"] = "[ 1] 2200/tcp                     ALLOW IN    Anywhere (quantum:hardening:profile:old)\n" +
		"[ 2] 22/tcp                     LIMIT IN    Anywhere (quantum:hardening:safe-apply)\n"
	p := Profile{Version: ProfileVersion, Name: "t", Firewall: &FirewallSpec{
		Limits: []PortRule{{Port: 22, Proto: "tcp", Owner: "service:ssh"}},
	}}
	plan, err := PlanProfile(p, Detect(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	it := hasItem(t, plan, KindFwRuleDel, "remove:")
	if !strings.Contains(it.ID, "2200/tcp") {
		t.Fatalf("stale rule must be planned for removal, got %s", it.ID)
	}
	// The safe-apply pre-open rule is exempt from convergence.
	for _, x := range plan.Items {
		if strings.Contains(x.ID, "safe-apply") {
			t.Fatalf("safe-apply rules must never be convergence-removed: %+v", x)
		}
	}
}

func TestPlanSSHNoopWhenDropInMatches(t *testing.T) {
	_ = newFakeHost(t)
	spec := &SSHSpec{Port: 2222}
	if err := os.MkdirAll(filepath.Dir(sshDropInPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sshDropInPath, []byte(RenderSSHDropIn(spec)), 0o600); err != nil {
		t.Fatal(err)
	}
	p := Profile{Version: ProfileVersion, Name: "t", SSH: spec}
	plan, err := PlanProfile(p, Detect(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range plan.Items {
		if it.Kind == KindSSHConfig {
			t.Fatalf("identical drop-in must not be planned: %+v", it)
		}
	}
}

func TestPlanSSHPortMovedDetectsNoChange(t *testing.T) {
	h := newFakeHost(t)
	// sshd already listens on 2222 per ss output.
	h.responses["ss -tlnp"] = "LISTEN 0 4096 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\"))\n" +
		"LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\"))\n"
	p := Profile{Version: ProfileVersion, Name: "t", SSH: &SSHSpec{Port: 2222}}
	plan, err := PlanProfile(p, Detect(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	// Plan should still contain the drop-in (not present yet), but the port
	// must NOT be treated as a new pre-open port (it already listens).
	// Verified behaviorally in safeapply_test (no pre-open for 2222 there);
	// here we assert the ssh item exists and is risky.
	it := hasItem(t, plan, KindSSHConfig, "ssh.config")
	if !it.Risky {
		t.Fatalf("ssh config item must be risky")
	}
}

func TestValidateProfile(t *testing.T) {
	bad := []Profile{
		{Version: 99, Name: "x"},
		{Version: ProfileVersion, Name: "bad name!"},
		{Version: ProfileVersion, Name: "t", Firewall: &FirewallSpec{Allows: []PortRule{{Port: 0, Proto: "tcp", Owner: "o"}}}},
		{Version: ProfileVersion, Name: "t", Firewall: &FirewallSpec{Limits: []PortRule{{Port: 22, Proto: "sctp", Owner: "o"}}}},
		{Version: ProfileVersion, Name: "t", Firewall: &FirewallSpec{Allows: []PortRule{{Port: 22, Proto: "tcp", Owner: "has space"}}}},
		{Version: ProfileVersion, Name: "t", SSH: &SSHSpec{Port: 70000}},
		{Version: ProfileVersion, Name: "t", SSH: &SSHSpec{PermitRoot: "sometimes"}},
		{Version: ProfileVersion, Name: "t", Sysctl: []SysctlRule{{Key: "Bad Key", Value: "1"}}},
	}
	for i, p := range bad {
		if err := p.Validate(); err == nil {
			t.Fatalf("profile %d must fail validation: %+v", i, p)
		}
	}
	good := Conservative(22, nil)
	if err := good.Validate(); err != nil {
		t.Fatalf("conservative profile must validate: %v", err)
	}
}

func TestParseOurRule(t *testing.T) {
	owner, r, limit := parseOurRule("[ 1] 52587/tcp                     LIMIT IN    Anywhere (quantum:hardening:service:ssh)")
	if owner != "service:ssh" || !limit || r.Port != 52587 || r.Proto != "tcp" {
		t.Fatalf("parse failed: owner=%q limit=%v rule=%+v", owner, limit, r)
	}
	owner, r, limit = parseOurRule("[ 2] 443/tcp from 10.0.0.0/24   ALLOW IN    10.0.0.0/24 (quantum:hardening:service:decoy)")
	if owner != "service:decoy" || limit || r.Port != 443 || r.From != "10.0.0.0/24" {
		t.Fatalf("parse with source failed: owner=%q limit=%v rule=%+v", owner, limit, r)
	}
	if owner, _, _ := parseOurRule("garbage line"); owner != "" {
		t.Fatalf("garbage must not parse, got owner %q", owner)
	}
}
