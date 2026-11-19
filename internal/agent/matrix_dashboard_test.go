package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func matrixDashboardFixture(t *testing.T, role string, service, connected bool) (*hostView, matrixState) {
	t.Helper()
	oldConfig, oldFRP, oldBH := configDir, frpDir, backhaulDir
	dir := t.TempDir()
	configDir, frpDir, backhaulDir = dir, filepath.Join(dir, "frp"), filepath.Join(dir, "backhaul")
	t.Cleanup(func() { configDir, frpDir, backhaulDir = oldConfig, oldFRP, oldBH })
	st := matrixState{Enabled: true, Network: matrixNetname, Role: role, Family: "ipv6", Port: 2097, Addr: "2001:db8::1", IP: matrixHubIP, Ports: []int{443, 8080}}
	if role == "hub" {
		st.Peers = []matrixPeer{{Name: "foreign", Addr: "2001:db8::2", IP: matrixFirstPeer}}
	} else {
		st.IP = matrixFirstPeer
	}
	if err := os.WriteFile(matrixStatePath(), mustJSON(st), 0600); err != nil {
		t.Fatal(err)
	}
	v := &hostView{inner: map[string]string{matrixIfaceName: st.IP + "/30"}, active: map[string]bool{matrixUnit: service}, dev: map[string]devCounters{matrixIfaceName: {1000, 2000}}, icmp: func(target string) icmpResult {
		if !strings.HasPrefix(target, matrixIfaceName+"|") {
			t.Fatalf("mesh probe not bound to qmx0: %q", target)
		}
		return icmpResult{OK: connected, Known: true, Ms: 12}
	}}
	return v, st
}

func TestMatrixServiceIsNotMeshConnection(t *testing.T) {
	v, st := matrixDashboardFixture(t, "hub", true, false)
	mx := matrixStatusFrom(st, v)
	if mx.Connected || mx.HealthState != stateDegraded {
		t.Fatalf("running service claimed connected: %+v", mx)
	}
	v.active[matrixUnit] = false
	mx = matrixStatusFrom(st, v)
	if mx.HealthState != stateDown || mx.Service || mx.Connected {
		t.Fatalf("stopped service: %+v", mx)
	}
	v.active[matrixUnit] = true
	v.icmp = func(string) icmpResult { return icmpResult{OK: true, Known: true, Ms: 10} }
	st.PeerSyncRequired = true
	mx = matrixStatusFrom(st, v)
	if mx.Connected || mx.HealthState != stateDegraded {
		t.Fatalf("pending edit claimed connected: %+v", mx)
	}
}

// TestMatrixTrafficAndFleetIsolation went with its dead entry points
// (trafficTunnelIfs, HubSnapshot.All/MatrixLinks) in §6.A3 — tests of the
// legacy monolith's dashboard path, which the agent no longer routes.
