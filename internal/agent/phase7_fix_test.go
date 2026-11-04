package agent

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func writeServedCert(t *testing.T, cn string) {
	t.Helper()
	c, k := testCertPEM(t, cn)
	if err := os.WriteFile(tlsCertFile(), []byte(c), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tlsKeyFile(), []byte(k), 0600); err != nil {
		t.Fatal(err)
	}
}

func servedCN(t *testing.T, port int) string {
	t.Helper()
	var cn string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			cn = conn.ConnectionState().PeerCertificates[0].Subject.CommonName
			_ = conn.Close()
			return cn
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("HTTPS listener on %d not reachable", port)
	return ""
}

// M7: a certificate change is picked up without restarting the listener, so
// the request that triggered it (renew/upload over HTTPS) is not cut.
// M7: a certificate renewed by certbot's own timer is copied in and served.
// M11: no GRE interface is only a problem where GRE is used.
func TestGreExpected(t *testing.T) {
	old := engineUnitDir
	engineUnitDir = t.TempDir()
	t.Cleanup(func() { engineUnitDir = old })
	if greExpected(tunnelStatus{Engine: "backhaul"}) {
		t.Error("standalone Backhaul does not use GRE")
	}
	if greExpected(tunnelStatus{}) {
		t.Error("no GRE unit installed: GRE not expected")
	}
	_ = os.WriteFile(filepath.Join(engineUnitDir, "gre-tunnel.service"), []byte("[Service]\n"), 0644)
	if !greExpected(tunnelStatus{Engine: "frp"}) {
		t.Error("FRP over GRE with a gre-tunnel unit expects GRE")
	}
}

// L16: an empty snapshot must not wipe the latency history.
// L9: after a reset the tracker only primes, it does not alert on old state.
func TestAlertTrackerResetPrimesAgain(t *testing.T) {
	tr := newAlertTracker()
	now := time.Now()
	c := alertConfig{MinGapSec: 0}
	tr.observe(now, []linkSnap{{Name: "p1", State: stateHealthy}}, c)
	tr.reset()
	if ev := tr.observe(now, []linkSnap{{Name: "p1", State: stateDown}}, c); len(ev) != 0 {
		t.Fatalf("alert fired on the first observation after reset: %+v", ev)
	}
	if ev := tr.observe(now.Add(time.Minute), []linkSnap{{Name: "p1", State: stateHealthy}}, c); len(ev) != 1 {
		t.Fatalf("real change after reset not reported: %+v", ev)
	}
}

// L7: updating one Telegram field keeps the others.
// M6: the backup key is only released with the panel password.
// M9: without Bagher, the snapshot status runs nothing and creates no key.
func TestBagherSnapshotStatusWithoutConfig(t *testing.T) {
	old := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = old })
	st := getSSHFwdSnapshotStatus()
	if st["has_config"] != false || st["is_active"] != false {
		t.Fatalf("got %+v", st)
	}
	if _, err := os.Stat(defaultSSHFwdKeyPath()); err == nil && strings.HasPrefix(defaultSSHFwdKeyPath(), configDir) {
		t.Fatal("snapshot status generated an SSH key")
	}
}
