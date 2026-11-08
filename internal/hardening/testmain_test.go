// testmain_test.go — hermetic test harness for the hardening package.
// TestMain redirects every owned path into a throwaway directory and stubs
// the Run seam to FAIL by default: nothing reaches the host unless a test
// installs an explicit fake (the agent package's TestMain discipline).
//
// fakeHost answers the detection/read commands with canned text and records
// every executed argv so tests can assert command ORDER — which is exactly
// what safe-apply correctness is about.

package hardening

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHost is the stubbed host: canned responses (exact or by prefix), a
// call log, and optional per-command failures. Unknown commands succeed
// with empty output — hermeticity comes from Run being stubbed, and
// mutating commands (ufw allow <dynamic port>) are too many to enumerate.
type fakeHost struct {
	mu              sync.Mutex
	responses       map[string]string // joined argv -> output
	prefixResponses []prefixResp      // longest-prefix match
	failures        map[string]bool   // joined argv -> must fail
	failByCommand   map[string]bool   // command name (argv[0]) -> must fail
	calls           []string          // every executed argv, in order
}

type prefixResp struct {
	prefix string
	out    string
}

func (h *fakeHost) key(name string, args []string) string {
	return strings.TrimSpace(name + " " + strings.Join(args, " "))
}

func (h *fakeHost) resp(name string, args []string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	k := h.key(name, args)
	h.calls = append(h.calls, k)
	if h.failures[k] || h.failByCommand[name] {
		return "fake failure for " + k, errors.New("exit status 1")
	}
	// Emulate sysctl so read-back verification sees what apply wrote (the
	// real `sysctl -p` changes kernel state; the fake updates the proc tree).
	if name == "sysctl" && len(args) == 2 && args[0] == "-p" {
		h.sysctlApplyFile(args[1])
		return "", nil
	}
	if name == "sysctl" && len(args) == 2 && args[0] == "-w" {
		if i := strings.Index(args[1], "="); i > 0 {
			h.setProc(args[1][:i], args[1][i+1:])
		}
		return "", nil
	}
	if out, ok := h.responses[k]; ok {
		return out, nil
	}
	best := -1
	for i, pr := range h.prefixResponses {
		if strings.HasPrefix(k, pr.prefix) && (best < 0 || len(pr.prefix) > len(h.prefixResponses[best].prefix)) {
			best = i
		}
	}
	if best >= 0 {
		return h.prefixResponses[best].out, nil
	}
	return "", nil
}

// sysctlApplyFile emulates `sysctl -p <file>`: writes every key=value from
// the drop-in into the fake proc tree.
func (h *fakeHost) sysctlApplyFile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			h.setProc(strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]))
		}
	}
}

// setProc writes one fake kernel sysctl value.
func (h *fakeHost) setProc(key, value string) {
	path := filepath.Join(sysctlProcRoot, strings.ReplaceAll(key, ".", "/"))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	_ = os.WriteFile(path, []byte(value+"\n"), 0o644)
}

// callsIndex returns the index of the first call containing substr.
func (h *fakeHost) callsIndex(t *testing.T, substr string) int {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, c := range h.calls {
		if strings.Contains(c, substr) {
			return i
		}
	}
	t.Fatalf("fakeHost: command containing %q was never called; calls:\n%s", substr, strings.Join(h.calls, "\n"))
	return -1
}

func (h *fakeHost) called(t *testing.T, substr string) {
	t.Helper()
	h.callsIndex(t, substr)
}

func (h *fakeHost) notCalled(t *testing.T, substr string) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.calls {
		if strings.Contains(c, substr) {
			t.Fatalf("fakeHost: command containing %q must not run, but ran: %s", substr, c)
		}
	}
}

// newFakeHost installs a host with sane Ubuntu-24.04-ish detection answers
// and returns it. Everything is restored via t.Cleanup.
func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{
		failByCommand: map[string]bool{},
		prefixResponses: []prefixResp{
			// Any is-active probe of an (unknown, dynamic) unit answers active.
			{prefix: "systemctl is-active", out: "active"},
			{prefix: "ufw status", out: ""},
		},
		responses: map[string]string{
			"ufw status": "Status: active",
			"ufw status verbose": "Status: active\n" +
				"Logging: on (low)\n" +
				"Default: deny (incoming), allow (outgoing), disabled (routed)\n" +
				"To                         Action      From\n" +
				"--                         ------      ----\n" +
				"22/tcp                     LIMIT IN    Anywhere\n",
			"ufw status numbered": "[ 1] 22/tcp                     LIMIT IN    Anywhere (quantum:hardening:service:ssh)\n" +
				"[ 2] 22/tcp (v6)                LIMIT IN    Anywhere (v6)\n",
			"ss -tlnp": "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n" +
				"LISTEN 0      4096       0.0.0.0:22         0.0.0.0:*          users:((\"sshd\",pid=1,fd=3))\n",
			"systemctl is-active ssh":               "active",
			"systemctl list-unit-files ssh.service": "UNIT FILE             STATE   VENDOR-PRESET\nssh.service            enabled enabled\n",
			"systemctl is-active sshd":              "inactive",
			"fail2ban-client version":               "1.0.2-3",
			"systemctl is-active fail2ban":          "active",
			"systemctl is-enabled fail2ban":         "enabled",
			"timedatectl show -p NTPActive --value": "no",
			"sshd -t":                               "",
			"/usr/sbin/sshd -t":                     "",
			"iptables -S":                           "",
		},
		failures: map[string]bool{},
	}
	oldRun := Run
	Run = func(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
		out, err := h.resp(name, args)
		return []byte(out), err
	}
	t.Cleanup(func() { Run = oldRun })

	// Redirect the world into a throwaway tree.
	root := t.TempDir()
	oldState, oldSsh, oldSys, oldNetopt, oldF2b, oldJdrop, oldKeys, oldProc, oldJournal := StateDir, sshDropInPath, sysctlDropInPath, netoptSysctlPath, fail2banJailPath, journaldDropInPath, authorizedKeyGlobs, sysctlProcRoot, journaldLogDir
	StateDir = filepath.Join(root, "state")
	sshDropInPath = filepath.Join(root, "etc/ssh/sshd_config.d/00-quantum-hardening.conf")
	sysctlDropInPath = filepath.Join(root, "etc/sysctl.d/99-quantum-hardening.conf")
	netoptSysctlPath = filepath.Join(root, "etc/sysctl.d/99-quantum-netopt.conf")
	fail2banJailPath = filepath.Join(root, "etc/fail2ban/jail.d/quantum-hardening.local")
	journaldDropInPath = filepath.Join(root, "etc/systemd/journald.conf.d/99-quantum-persistent.conf")
	journaldLogDir = filepath.Join(root, "var/log/journal")
	sysctlProcRoot = filepath.Join(root, "proc/sys")
	authorizedKeyGlobs = []string{filepath.Join(root, "root/.ssh/authorized_keys")}
	t.Cleanup(func() {
		StateDir, sshDropInPath, sysctlDropInPath, netoptSysctlPath, fail2banJailPath, journaldDropInPath, authorizedKeyGlobs, sysctlProcRoot, journaldLogDir =
			oldState, oldSsh, oldSys, oldNetopt, oldF2b, oldJdrop, oldKeys, oldProc, oldJournal
	})

	// Shrink the timing knobs so failure-path tests stay fast.
	oldSettle, oldDeadline, oldInterval := listenerSettle, sshPathProbeDeadline, sshPathProbeInterval
	listenerSettle = 0
	sshPathProbeDeadline = 50 * time.Millisecond
	sshPathProbeInterval = 5 * time.Millisecond
	t.Cleanup(func() {
		listenerSettle, sshPathProbeDeadline, sshPathProbeInterval = oldSettle, oldDeadline, oldInterval
	})

	return h
}

// fakeBanner installs a banner probe stub: SSH banner for ports in ok,
// connection refused otherwise.
func fakeBanner(t *testing.T, ok map[int]bool) {
	t.Helper()
	old := bannerProbe
	bannerProbe = func(addr string, timeout time.Duration) (string, error) {
		var port int
		if _, err := fmt.Sscanf(addr, "127.0.0.1:%d", &port); err != nil {
			return "", err
		}
		if ok[port] {
			return "SSH-2.0-OpenSSH_9.6p1", nil
		}
		return "", errors.New("connection refused")
	}
	t.Cleanup(func() { bannerProbe = old })
}

// setProcValue writes a sysctl value the way the kernel would report it.
func setProcValue(t *testing.T, key, value string) {
	t.Helper()
	path := filepath.Join(sysctlProcRoot, strings.ReplaceAll(key, ".", "/"))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// withKeys writes an authorized_keys file so the key-only guard allows
// enforcement. user "root" writes the root file, anything else /home/<u>.
func withKeys(t *testing.T, users ...string) {
	t.Helper()
	for _, u := range users {
		var path string
		if u == "root" {
			path = authorizedKeyGlobs[0]
		} else {
			base := filepath.Dir(filepath.Dir(authorizedKeyGlobs[0])) // <root>/root/.ssh -> <root>
			path = filepath.Join(base, "home", u, ".ssh", "authorized_keys")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("ssh-ed25519 AAAAC3Nza test@"+u+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMain(m *testing.M) {
	// Belt and braces: until a test installs newFakeHost, Run fails loudly
	// instead of touching the host.
	Run = func(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
		return nil, errTestNoHost
	}
	code := m.Run()
	os.Exit(code)
}
