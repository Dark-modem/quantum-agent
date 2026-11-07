package hardening

// Regression tests for RUNBOOK-FIXES item 10: the owned sshd drop-in must
// sort FIRST (00-quantum-hardening.conf) so sshd's first-value-wins rule
// beats vendor drop-ins like 00-arvan-root-login.conf that set
// PasswordAuthentication yes; and the plan must REPORT conflicting
// earlier drop-ins so the operator sees them.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withSshDropInDir points the sshd_config.d seam at the fake host root.
func withSshDropInDir(t *testing.T, root string) {
	t.Helper()
	old := sshDropInDir
	sshDropInDir = filepath.Join(root, "etc/ssh/sshd_config.d")
	t.Cleanup(func() { sshDropInDir = old })
}

func TestDropInNameSortsFirst(t *testing.T) {
	root := t.TempDir()
	withSshDropInDir(t, root)
	if err := os.MkdirAll(filepath.Join(root, "etc/ssh/sshd_config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The vendor drop-in the arvan image ships: 01-arvan-root-login.conf.
	// With the OLD 60- name it sorted FIRST and beat us; with the 00- name
	// WE sort first and the scan must NOT flag it (we win).
	arvan := filepath.Join(root, "etc/ssh/sshd_config.d/01-arvan-root-login.conf")
	if err := os.WriteFile(arvan, []byte("PasswordAuthentication yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ours := sshDropInPath
	if base := filepath.Base(ours); !strings.HasPrefix(base, "00-") {
		t.Fatalf("owned drop-in must sort first (00- prefix), got %q", base)
	}
	if conflicts := sshdDropInConflicts(sshDropInDir, ours, []string{"PasswordAuthentication"}); len(conflicts) != 0 {
		t.Fatalf("01- vendor must NOT conflict with our 00- drop-in: %v", conflicts)
	}
	// A file that genuinely sorts BEFORE ours is the real conflict.
	earlier := filepath.Join(root, "etc/ssh/sshd_config.d/00-arvan-root-login.conf")
	if err := os.WriteFile(earlier, []byte("PasswordAuthentication yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	conflicts := sshdDropInConflicts(sshDropInDir, ours, []string{"PasswordAuthentication"})
	if len(conflicts) != 1 || !strings.Contains(conflicts[0], "00-arvan-root-login.conf") ||
		!strings.Contains(conflicts[0], "PasswordAuthentication") {
		t.Fatalf("conflicts = %v, want the earlier arvan file on PasswordAuthentication", conflicts)
	}
}

func TestDropInNoFalseConflicts(t *testing.T) {
	root := t.TempDir()
	withSshDropInDir(t, root)

	if err := os.MkdirAll(filepath.Join(root, "etc/ssh/sshd_config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A vendor drop-in that sorts after ours (50-) and a comment-only
	// file that sorts before: neither conflicts.
	after := filepath.Join(root, "etc/ssh/sshd_config.d/50-late.conf")
	if err := os.WriteFile(after, []byte("PasswordAuthentication yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	comment := filepath.Join(root, "etc/ssh/sshd_config.d/00-comment.conf")
	if err := os.WriteFile(comment, []byte("# PasswordAuthentication yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ours := sshDropInPath
	conflicts := sshdDropInConflicts(sshDropInDir, ours, []string{"PasswordAuthentication"})
	if len(conflicts) != 0 {
		t.Fatalf("false conflicts: %v", conflicts)
	}
}

func TestDropInConflictSurfacesInPlan(t *testing.T) {
	h := newFakeHost(t) // Detect machinery (proc/keys seams)
	_ = h
	// The conflict-scan seam points at ITS OWN dir (not the fake host's):
	// the vendor drop-in lives there and sorts before our 00- prefix.
	confDir := t.TempDir()
	withSshDropInDir(t, confDir)
	vendor := filepath.Join(confDir, "etc/ssh/sshd_config.d/00-arvan-root-login.conf")
	os.MkdirAll(filepath.Dir(vendor), 0o755)
	if err := os.WriteFile(vendor, []byte("PasswordAuthentication yes\nPermitRootLogin yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	setProcValue(t, "net/ipv4/tcp_syncookies", "1")
	withKeys(t)

	no := true
	prof := Profile{Version: ProfileVersion, Name: "t", SSH: &SSHSpec{KeyOnly: &no, PermitRoot: "no", MaxAuthTries: 4}}
	plan, err := PlanProfile(prof, Detect(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range plan.Items {
		if it.Kind == KindSSHConfig &&
			strings.Contains(it.Summary, "00-arvan-root-login.conf") &&
			strings.Contains(it.Summary, "WARNING: conflicting earlier drop-ins") {
			found = true
		}
	}
	if !found {
		t.Fatalf("plan does not surface the conflicting vendor drop-in: %+v", plan.Items)
	}
}
