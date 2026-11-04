package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMain points configDir, frpDir and backhaulDir at throwaway directories
// for the whole run so no test can read or write the real /etc/gre-panel
// (error journal, audit log, peers, sessions, ...), /etc/frp or /etc/backhaul,
// and stubs runSystemctl.
// withTempConfig points configDir at a fresh temp dir for one test, so files
// the test writes never reach another test or the host.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gre-panel-test-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create test configDir:", err)
		os.Exit(1)
	}
	configDir = dir
	frpDir = filepath.Join(dir, "frp")
	backhaulDir = filepath.Join(dir, "backhaul")
	revpathSysctlConf = filepath.Join(dir, "sysctl.d", "99-quantum-revpath.conf")
	runSystemctl = func(args ...string) error { return nil }
	// Host commands that go through the runner fail by default; tests that
	// need output install their own stub. Nothing here ever reaches the host.
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("test runner: no host commands")
	}
	dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("test dialer: no network")
	}
	// The spoke half of the reverse-path matrix dials a spoke panel over
	// HTTP; tests must opt in explicitly. Nothing here ever reaches the net.
	spokeFetcher = func(p peerRecord) *SpokeProbeReport { return nil }
	// The post-switch health run sleeps then probes; tests opt in explicitly.
	tunnelHealthAutoRun = false
	// detectPublicIP's "what is my IP" fallback must not reach the internet.
	externalIPLookup = func() string { return "" }
	externalIP6Lookup = func() string { return "" }
	// Engine switches: units "run" once restarted, and no post-start wait.
	engineServiceActive = func(string) bool { return true }
	engineVerifyDelay = 0
	// Backhaul/Bagher port counters run iptables; tests opt in.
	carrierCounters = func() (uint64, uint64, bool) { return 0, 0, false }
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// withTmpConfig points configDir at a temp dir for the test and returns
// it (helper carried over from the monolith's update_channel_test.go).
func withTmpConfig(t *testing.T) string {
	t.Helper()
	old := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = old })
	return configDir
}

// TestMain points configDir, frpDir and backhaulDir at throwaway directories
// for the whole run so no test can read or write the real /etc/gre-panel
// (error journal, audit log, peers, sessions, ...), /etc/frp or /etc/backhaul,
// and stubs runSystemctl.
// withTempConfig points configDir at a fresh temp dir for one test, so files
// the test writes never reach another test or the host.
func withTempConfig(t *testing.T) {
	t.Helper()
	// Agent adaptation of the monolith helper: there are no controller hub
	// sessions to drain, so this only rotates the configDir seam.
	old := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = old })
}
