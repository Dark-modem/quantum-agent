package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestMatrixTrafficAndFleetIsolation(t *testing.T) {
	resetTrafficState(t)
	data := devLines(map[string][2]uint64{"qmx0": {100, 200}, "ens5": {999999, 999999}})
	cur := trafficTunnelIfs(data)
	if len(cur) != 1 || cur["qmx0"] != [2]uint64{100, 200} {
		t.Fatalf("qmx0 real counters missing or NIC counted: %+v", cur)
	}
	if cur := trafficTunnelIfs(devLines(map[string][2]uint64{"ens5": {999, 999}})); len(cur) != 0 {
		t.Fatalf("invented Matrix traffic: %+v", cur)
	}
	v, st := matrixDashboardFixture(t, "node", true, true)
	snap := &HubSnapshot{At: time.Now(), Local: tunnelStatus{Matrix: matrixStatusFrom(st, v)}}
	links := snap.MatrixLinks()
	if len(links) != 1 || links[0].Engine != "matrix" || links[0].GreUp || links[0].FrpUp || !links[0].Linked || links[0].Rx == nil {
		t.Fatalf("fleet mislabeled Matrix: %+v", links)
	}
	if len(snap.All()) != 0 {
		t.Fatal("Matrix polluted legacy tunnel records")
	}
	targets := icmpTargets(snap)
	if _, ok := targets[matrixProbeKey(matrixHubIP)]; !ok {
		t.Fatalf("no qmx0-bound background mesh probe: %+v", targets)
	}
}
