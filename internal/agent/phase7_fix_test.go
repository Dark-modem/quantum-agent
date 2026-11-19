package agent

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/infra"
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
	old := infra.EngineUnitDir
	infra.EngineUnitDir = t.TempDir()
	t.Cleanup(func() { infra.EngineUnitDir = old })
	if greExpected(tunnelStatus{Engine: "backhaul"}) {
		t.Error("standalone Backhaul does not use GRE")
	}
	if greExpected(tunnelStatus{}) {
		t.Error("no GRE unit installed: GRE not expected")
	}
	_ = os.WriteFile(filepath.Join(infra.EngineUnitDir, "gre-tunnel.service"), []byte("[Service]\n"), 0644)
	if !greExpected(tunnelStatus{Engine: "frp"}) {
		t.Error("FRP over GRE with a gre-tunnel unit expects GRE")
	}
}

// TestAlertTrackerResetPrimesAgain went with newAlertTracker in §6.A3 —
// nothing in the agent's reachable graph constructs the legacy alert
// tracker (the live alert semantics are the panel's).

// L7: updating one Telegram field keeps the others.
// M6: the backup key is only released with the panel password.
// M9: without Bagher, the snapshot status runs nothing and creates no key.
func TestBagherSnapshotStatusWithoutConfig(t *testing.T) {
	old := infra.ConfigDir
	infra.ConfigDir = t.TempDir()
	t.Cleanup(func() { infra.ConfigDir = old })
	st := getSSHFwdSnapshotStatus()
	if st["has_config"] != false || st["is_active"] != false {
		t.Fatalf("got %+v", st)
	}
	if _, err := os.Stat(defaultSSHFwdKeyPath()); err == nil && strings.HasPrefix(defaultSSHFwdKeyPath(), infra.ConfigDir) {
		t.Fatal("snapshot status generated an SSH key")
	}
}
