// safeapply_test.go — the SAFE-APPLY contract, exercised with a simulated
// failure: command ordering, timer arming, automatic rollback, confirm.

package hardening

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// moveSSHProfile is the canonical risky change: move SSH to port 2222.
func moveSSHProfile() Profile {
	return Profile{Version: ProfileVersion, Name: "move-ssh", SSH: &SSHSpec{Port: 2222}}
}

// denyIncomingProfile flips the incoming policy to deny (risky).
func denyIncomingProfile() Profile {
	deny := true
	return Profile{Version: ProfileVersion, Name: "deny-in", Firewall: &FirewallSpec{DefaultDenyIncoming: &deny}}
}

func TestSafeApplyOrder(t *testing.T) {
	h := newFakeHost(t)
	fakeBanner(t, map[int]bool{22: true, 2222: true})
	withKeys(t, "root")

	res, err := ApplyProfile(context.Background(), moveSSHProfile(), ApplyOpts{SafeApply: true, RollbackTimeoutSec: 120})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if !res.Armed || !strings.HasPrefix(res.TimerUnit, "quantum-harden-") {
		t.Fatalf("rollback timer must be armed, got armed=%v unit=%q", res.Armed, res.TimerUnit)
	}

	// THE critical order: pre-open new port -> arm timer -> validate ->
	// reload sshd -> (policy changes would come after).
	pre := h.callsIndex(t, "ufw allow 2222/tcp")
	arm := h.callsIndex(t, "systemd-run --on-active=120s")
	val := h.callsIndex(t, "sshd -t")
	rel := h.callsIndex(t, "systemctl reload ssh")
	if !(pre < arm && arm < val && val < rel) {
		t.Fatalf("safe-apply order violated: pre-open=%d arm=%d validate=%d reload=%d\ncalls:\n%s",
			pre, arm, val, rel, strings.Join(h.responses2calls(), "\n"))
	}

	// Pre-open of the CURRENT port happens too, before the reload.
	pre22 := h.callsIndex(t, "ufw allow 22/tcp")
	if pre22 > rel {
		t.Fatalf("current SSH port must be pre-opened before any reload")
	}

	// The systemd-run line carries the generated script.
	armLine := h.calls[arm]
	if !strings.Contains(armLine, "/bin/sh") || !strings.Contains(armLine, "rollback-") {
		t.Fatalf("systemd-run must execute the generated rollback script: %s", armLine)
	}

	// Journal persisted and unconfirmed; drop-in written.
	if res.Journal.Confirmed || res.Journal.RolledBack {
		t.Fatalf("journal must be open (awaiting confirmation): %+v", res.Journal)
	}
	b, err := os.ReadFile(sshDropInPath)
	if err != nil || !strings.Contains(string(b), "Port 2222") {
		t.Fatalf("sshd drop-in with Port 2222 must exist after apply: %v %s", err, string(b))
	}
}

// responses2calls is a tiny test helper re-exposing the call log.
func (h *fakeHost) responses2calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

func TestSafeApplySimulatedFailureRollsBack(t *testing.T) {
	h := newFakeHost(t)
	// Simulate: sshd reloads with the new config but never opens 2222
	// (the exact lockout scenario safe-apply exists for).
	fakeBanner(t, map[int]bool{22: true /* 2222 refused */})
	withKeys(t, "root")

	res, err := ApplyProfile(context.Background(), moveSSHProfile(), ApplyOpts{SafeApply: true})
	if err == nil {
		t.Fatalf("apply must fail when the new SSH port does not answer")
	}
	if !strings.Contains(err.Error(), "did not answer") && !strings.Contains(err.Error(), "port 2222") {
		t.Fatalf("error must name the failed verification, got: %v", err)
	}

	j := res.Journal
	if j == nil || !j.RolledBack {
		t.Fatalf("journal must record the rollback: %+v", j)
	}

	// Rollback ran: drop-in removed (it was absent before), timer stopped,
	// pre-open rule for 2222 deleted, sshd reloaded back.
	b, err := os.ReadFile(sshDropInPath)
	if err == nil {
		t.Fatalf("sshd drop-in must be removed by the rollback, found: %s", string(b))
	}
	if !os.IsNotExist(err) {
		t.Fatalf("unexpected read error: %v", err)
	}
	h.called(t, "systemctl stop "+j.TimerUnit+".timer")
	h.called(t, "ufw delete allow 2222/tcp")
	h.called(t, "systemctl reload ssh")

	// Journal is terminal: renamed .rolledback, latest pointer gone.
	if _, err := os.Stat(filepath.Join(StateDir, "journal-"+j.ID+".json.rolledback")); err != nil {
		t.Fatalf("journal must be renamed .rolledback: %v", err)
	}
	if _, err := os.Stat(filepath.Join(StateDir, "journal.json")); !os.IsNotExist(err) {
		t.Fatalf("latest pointer must be removed after a terminal rollback: %v", err)
	}
	// The rollback script is cleaned up.
	if _, err := os.Stat(filepath.Join(StateDir, "rollback-"+j.ID+".sh")); !os.IsNotExist(err) {
		t.Fatalf("rollback script must be removed after execution: %v", err)
	}
}

func TestSafeApplyRefusesUnsafeMode(t *testing.T) {
	h := newFakeHost(t)
	fakeBanner(t, map[int]bool{22: true})
	withKeys(t, "root")

	_, err := ApplyProfile(context.Background(), moveSSHProfile(), ApplyOpts{SafeApply: false})
	if err == nil || !errors.Is(err, errUnsafeApply) {
		t.Fatalf("risky plan without safe-apply must be refused, got: %v", err)
	}
	h.notCalled(t, "systemctl reload ssh")
}

func TestSafeApplyAbortsWhenTimerCannotArm(t *testing.T) {
	h := newFakeHost(t)
	fakeBanner(t, map[int]bool{22: true, 2222: true})
	withKeys(t, "root")
	// systemd-run fails: no rollback safety net -> nothing risky may happen.
	// (The unit name embeds the journal id, so fail by command name.)
	h.failByCommand["systemd-run"] = true

	res, err := ApplyProfile(context.Background(), moveSSHProfile(), ApplyOpts{SafeApply: true})
	if err == nil || !strings.Contains(err.Error(), "cannot arm the rollback timer") {
		t.Fatalf("arming failure must abort the apply, got: %v", err)
	}
	h.notCalled(t, "systemctl reload ssh")
	if _, statErr := os.Stat(sshDropInPath); statErr == nil {
		t.Fatalf("no ssh drop-in may be written when arming fails")
	}
	// The pre-open allows from step 1 are rolled back (no residue), and the
	// journal records it.
	h.called(t, "ufw delete allow 2222/tcp")
	if res.Journal == nil || !res.Journal.RolledBack {
		t.Fatalf("journal must record the pre-open rollback: %+v", res.Journal)
	}
}

func TestConfirmDisarmsAndFinalizes(t *testing.T) {
	h := newFakeHost(t)
	fakeBanner(t, map[int]bool{22: true, 2222: true})
	withKeys(t, "root")

	res, err := ApplyProfile(context.Background(), moveSSHProfile(), ApplyOpts{SafeApply: true})
	if err != nil {
		t.Fatal(err)
	}
	j, err := Confirm(context.Background(), res.Journal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !j.Confirmed {
		t.Fatalf("journal must be confirmed")
	}
	h.called(t, "systemctl stop "+res.TimerUnit+".timer")
	// Conservative confirm: ports still listening keep their pre-open allow;
	// both are reported as leftovers for the panel.
	if _, err := os.Stat(filepath.Join(StateDir, "journal-"+j.ID+".json.confirmed")); err != nil {
		t.Fatalf("journal must be renamed .confirmed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(StateDir, "rollback-"+j.ID+".sh")); !os.IsNotExist(err) {
		t.Fatalf("confirmed journals must not keep a rollback script")
	}
}

func TestRollbackRestoresFiles(t *testing.T) {
	h := newFakeHost(t)
	fakeBanner(t, map[int]bool{22: true, 2222: true})
	withKeys(t, "root")

	// First apply WITH a previous drop-in in place (so restore must rewrite
	// bytes, not just delete).
	prevContent := "# managed by quantum-agent hardening — do not edit\nPort 2200\n"
	if err := os.MkdirAll(filepath.Dir(sshDropInPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sshDropInPath, []byte(prevContent), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ApplyProfile(context.Background(), moveSSHProfile(), ApplyOpts{SafeApply: true})
	if err != nil {
		t.Fatal(err)
	}
	j, err := Rollback(context.Background(), res.Journal.ID)
	if err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if !j.RolledBack {
		t.Fatalf("journal must record the rollback")
	}
	b, err := os.ReadFile(sshDropInPath)
	if err != nil || string(b) != prevContent {
		t.Fatalf("rollback must restore the previous drop-in byte-for-byte, got %q (%v)", string(b), err)
	}
	h.called(t, "systemctl reload ssh") // restore reloads sshd
}

func TestApplyNonRiskyProfileSkipsTimer(t *testing.T) {
	h := newFakeHost(t)
	fakeBanner(t, map[int]bool{22: true})
	setProcValue(t, "net/ipv4/tcp_syncookies", "0")
	// remove other sysctls from profile: only one key
	p := Profile{Version: ProfileVersion, Name: "sysctl-only",
		Sysctl: []SysctlRule{{Key: "net.ipv4.tcp_syncookies", Value: "1"}}}
	res, err := ApplyProfile(context.Background(), p, ApplyOpts{SafeApply: false})
	if err != nil {
		t.Fatalf("non-risky apply must succeed without safe-apply: %v", err)
	}
	if res.Armed {
		t.Fatalf("sysctl-only profile must not arm a rollback timer")
	}
	h.called(t, "sysctl -p "+sysctlDropInPath)
	b, err := os.ReadFile(sysctlDropInPath)
	if err != nil || !strings.Contains(string(b), "net.ipv4.tcp_syncookies = 1") {
		t.Fatalf("sysctl drop-in missing/invalid: %v %s", err, string(b))
	}
}

func TestApplySysctlForeignFileRefused(t *testing.T) {
	_ = newFakeHost(t)
	setProcValue(t, "net/ipv4/tcp_syncookies", "0")
	if err := os.MkdirAll(filepath.Dir(sysctlDropInPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sysctlDropInPath, []byte("# some other tool's file\nnet.ipv4.tcp_syncookies = 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := Profile{Version: ProfileVersion, Name: "sysctl-only",
		Sysctl: []SysctlRule{{Key: "net.ipv4.tcp_syncookies", Value: "1"}}}
	_, err := ApplyProfile(context.Background(), p, ApplyOpts{SafeApply: false})
	if err == nil || !strings.Contains(err.Error(), "not Quantum-owned") {
		t.Fatalf("foreign drop-in must be refused, got: %v", err)
	}
	// The foreign file is untouched.
	b, _ := os.ReadFile(sysctlDropInPath)
	if strings.Contains(string(b), "managed by quantum-agent") {
		t.Fatalf("foreign file must not be overwritten")
	}
}
