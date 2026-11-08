// exec.go — the execution and filesystem seams. Every host command goes
// through Run; every owned file through writeFileAtomic/readFile. Tests
// swap the seams (or point the paths at a temp dir) so nothing reaches the
// host (same discipline as the agent package's runner/fwRun seams).

package hardening

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// Run executes one host command with a hard timeout and returns combined
// output. Tests install a fake; production uses exec.CommandContext.
var Run = func(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// run runs one command with the default hardening timeout.
func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return Run(ctx, 15*time.Second, name, args...)
}

// StateDir holds journals, baselines and generated rollback scripts.
var StateDir = "/var/lib/quantum-agent/hardening"

// Owned file paths (vars so tests redirect them).
var (
	sshDropInPath      = "/etc/ssh/sshd_config.d/00-quantum-hardening.conf"
	sysctlDropInPath   = "/etc/sysctl.d/99-quantum-hardening.conf"
	netoptSysctlPath   = "/etc/sysctl.d/99-quantum-netopt.conf" // read-only co-existence check
	fail2banJailPath   = "/etc/fail2ban/jail.d/quantum-hardening.local"
	journaldDropInPath = "/etc/systemd/journald.conf.d/99-quantum-persistent.conf"
	authorizedKeyGlobs = []string{"/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"}
)

// sysctlProcRoot is where kernel sysctl values are read from (Linux /proc).
var sysctlProcRoot = "/proc/sys"

// journaldLogDir is the persistent-journal directory journald watches
// (var: hermetic tests redirect it into a temp dir).
var journaldLogDir = "/var/log/journal"

// writeFileAtomic writes content to path via temp+rename (the store
// convention: a crash never leaves a half-written owned file).
func writeFileAtomic(path, content string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hardening-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

// validation shapes
var (
	sysctlKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_.-]+(/[0-9]+)?$`)
	cidrRe      = regexp.MustCompile(`^[0-9a-fA-F.:]+(/[0-9]{1,3})?$`)
	portRe      = regexp.MustCompile(`^[0-9]{1,5}$`)
)

// errTestNoHost is what the test runner returns when a test did not stub
// the specific command — any appearance in a passing test is a bug.
var errTestNoHost = errors.New("hardening test runner: no host commands")
