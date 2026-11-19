package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

// The bugs behind wrong totals and speeds, one test each.

// resetTrafficState (was dashboard_test.go's helper; that file's remaining
// test went with the dead isTunnelInterface in §6.A3) zeroes the live
// traffic state between these tests.
func resetTrafficState(t *testing.T) {
	t.Helper()
	old := infra.ConfigDir
	infra.ConfigDir = t.TempDir()
	trafficStateMu.Lock()
	trafficStateInit, lifetimeUp, lifetimeDown, lastRawUp, lastRawDown, lastRawIf = false, 0, 0, 0, 0, nil
	lastSampleAt, speedDeltaUp, speedDeltaDown, currentSpeedUp, currentSpeedDown = time.Time{}, 0, 0, 0, 0
	trafficStateMu.Unlock()
	t.Cleanup(func() { infra.ConfigDir = old })
}

// devLines renders a /proc/net/dev snippet (was dashboard_test.go's helper).
func devLines(ifs map[string][2]uint64) string {
	s := "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets\n"
	for name, c := range ifs {
		s += fmt.Sprintf("  %s: %d 1 0 0 0 0 0 0 %d 1 0 0 0 0 0 0\n", name, c[0], c[1])
	}
	return s
}

// Two samplers shared the traffic state: the snapshot handed in a
// /proc/net/dev read seconds before the recorder's fresh one. Processed after
// it, every counter looked lower, was taken for a reset and each interface's
// whole counter was added again.
func TestTrafficSampleIgnoresOutOfOrderReading(t *testing.T) {
	resetTrafficState(t)
	const gb = 1 << 30
	t0 := time.Unix(1_800_000_000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	dev := func(rx uint64) string { return devLines(map[string][2]uint64{"gre-a": {rx, 0}}) }

	trafficSample(dev(5*gb), 0, 0, false, at(0))
	trafficSample(dev(5*gb+1000), 0, 0, false, at(5))
	m := trafficSample(dev(5*gb+400), 0, 0, false, at(3)) // the stale one
	if got := m["down"].(uint64); got != 1000 {
		t.Fatalf("down = %d after a stale reading, want 1000 (it used to add the whole 5 GB counter)", got)
	}
	m = trafficSample(dev(5*gb+3000), 0, 0, false, at(10))
	if got := m["down"].(uint64); got != 3000 {
		t.Fatalf("down = %d, want 3000", got)
	}
}

// Speed is bytes over the time between the two readings, not between two
// calls.
func TestTrafficSpeedUsesReadingTime(t *testing.T) {
	resetTrafficState(t)
	t0 := time.Unix(1_800_000_000, 0)
	dev := func(rx, tx uint64) string { return devLines(map[string][2]uint64{"gre-a": {rx, tx}}) }
	trafficSample(dev(0, 0), 0, 0, false, t0)
	m := trafficSample(dev(5_000_000, 1_000_000), 0, 0, false, t0.Add(5*time.Second))
	if d, u := m["speed_down"].(float64), m["speed_up"].(float64); d != 1_000_000 || u != 200_000 {
		t.Fatalf("speed = %v down / %v up, want 1000000 / 200000", d, u)
	}
	// carrier counters move in the same reading
	trafficSample(dev(5_000_000, 1_000_000), 100, 0, true, t0.Add(10*time.Second))
	m = trafficSample(dev(5_000_000, 1_000_000), 2_100, 0, true, t0.Add(12*time.Second))
	if d := m["speed_down"].(float64); d != 1000 {
		t.Fatalf("carrier speed = %v, want 1000", d)
	}
}

// What an interface moves while the panel is stopped (an update) counts: its
// last raw counters are kept on disk.
func TestTrafficCountsWhilePanelWasDown(t *testing.T) {
	resetTrafficState(t)
	t0 := time.Unix(1_800_000_000, 0)
	dev := func(rx uint64) string { return devLines(map[string][2]uint64{"gre-a": {rx, 0}, "gre-b": {7, 0}}) }
	trafficSample(dev(1000), 0, 0, false, t0)
	trafficSample(dev(1500), 9, 9, true, t0.Add(5*time.Second))
	trafficStateMu.Lock()
	saveTrafficStateLocked()
	// the panel restarts
	trafficStateInit, lifetimeUp, lifetimeDown, lastRawIf, lastSampleAt = false, 0, 0, nil, time.Time{}
	trafficStateMu.Unlock()

	m := trafficSample(dev(4500), 0, 0, true, t0.Add(60*time.Second))
	if got := m["down"].(uint64); got != 3500 {
		t.Fatalf("down = %d, want 3500 (500 before the restart, 3000 while stopped)", got)
	}
	var st persistentTrafficState
	b, _ := os.ReadFile(trafficStateFile())
	_ = json.Unmarshal(b, &st)
	if _, ok := st.LastIf["gre-a"]; !ok {
		t.Fatalf("per-interface counters not saved: %s", b)
	}
}

func TestBackhaulTag(t *testing.T) {
	d := "/etc/backhaul"
	for path, want := range map[string]string{
		d + "/config.toml":                                  "backhaul-server",
		d + "/server.toml":                                  "backhaul-server",
		d + "/client.toml":                                  "backhaul-client",
		d + "/server-3.toml":                                "backhaul-server-3",
		d + "/client-h2.toml":                               "backhaul-client-h2",
		d + "/udp/backhaul-server-3.toml":                   "backhaul-server-3",
		d + "/udp/backhaul-server.toml":                     "backhaul-server",
		d + "/udp/backhaul-udp-server-3.toml":               "backhaul-server-3",
		d + "/udp/backhaul-client.toml":                     "backhaul-client",
		filepath.Join(d, "udp", "backhaul-udp-client.toml"): "backhaul-client",
	} {
		if got := backhaulTag(path); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}

func TestBagherCarrierEnds(t *testing.T) {
	cfg := defaultSSHFwdConfig()
	if bagherCarrierEnds(cfg) != nil {
		t.Fatal("Bagher off: nothing to count")
	}
	cfg.Enabled, cfg.Role, cfg.RemoteHost, cfg.RemoteSSHPort = true, "iran", "198.51.100.1", 2222
	cfg.Links = []BagherLink{{ID: 2, RemoteHost: "198.51.100.2"}, {ID: 4, RemoteHost: "198.51.100.4", RemoteSSHPort: 22}}
	got := bagherCarrierEnds(cfg)
	want := []carrierEnd{{Port: 2222, Remote: "198.51.100.1", Tag: "bagher-1"}, {Port: 2222, Remote: "198.51.100.2", Tag: "bagher-2"},
		{Port: 22, Remote: "198.51.100.4", Tag: "bagher-4"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("end %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	// the foreign server counts its sshd only for the Iran server
	fo := defaultSSHFwdConfig()
	fo.Enabled, fo.Role, fo.RemoteHost = true, "foreign", "203.0.113.5"
	if e := bagherCarrierEnds(fo); len(e) != 1 || e[0] != (carrierEnd{Port: 22, From: "203.0.113.5", Tag: "bagher-1"}) {
		t.Fatalf("foreign end: %+v", e)
	}
	r := carrierRules(bagherCarrierEnds(fo), "eth0")
	for _, line := range []string{"-A QUANTUM_ACCT_IN -i eth0 -s 203.0.113.5/32 -p tcp --dport 22", "-A QUANTUM_ACCT_OUT -o eth0 -d 203.0.113.5/32 -p tcp --sport 22"} {
		if !strings.Contains(r, line+"\n") {
			t.Fatalf("missing %q in\n%s", line, r)
		}
	}
}

// iptables-save prints the rules with "-m tcp" and /32 added; each one must
// be traced back to its end.
func TestAcctRuleKey(t *testing.T) {
	for _, c := range []struct {
		rule string
		in   bool
		want acctKey
	}{
		{"-A QUANTUM_ACCT_IN -i eth0 -p tcp -m tcp --dport 3080", true, acctKey{Listen: true, Port: 3080}},
		{"-A QUANTUM_ACCT_OUT -o eth0 -p udp -m udp --sport 3080", false, acctKey{Listen: true, Port: 3080}},
		{"-A QUANTUM_ACCT_IN -i eth0 -s 203.0.113.5/32 -p tcp -m tcp --dport 22", true, acctKey{Listen: true, Port: 22, Peer: "203.0.113.5"}},
		{"-A QUANTUM_ACCT_OUT -o eth0 -d 203.0.113.5/32 -p tcp -m tcp --sport 22", false, acctKey{Listen: true, Port: 22, Peer: "203.0.113.5"}},
		{"-A QUANTUM_ACCT_IN -i eth0 -s 198.51.100.1/32 -p tcp -m tcp --sport 2222", true, acctKey{Port: 2222, Peer: "198.51.100.1"}},
		{"-A QUANTUM_ACCT_OUT -o eth0 -d 198.51.100.1/32 -p tcp -m tcp --dport 2222", false, acctKey{Port: 2222, Peer: "198.51.100.1"}},
	} {
		if got, ok := acctRuleKey(c.rule, c.in); !ok || got != c.want {
			t.Errorf("%s: %+v %v, want %+v", c.rule, got, ok, c.want)
		}
	}
}

// Each Backhaul unit and Bagher link gets its own counters, from the same
// iptables-save read as the total.
func TestCarrierTagCounters(t *testing.T) {
	oldDir, oldCfg, oldRunner := backhaulDir, infra.ConfigDir, infra.Runner
	backhaulDir, infra.ConfigDir = t.TempDir(), t.TempDir()
	_ = os.WriteFile(filepath.Join(backhaulDir, "server.toml"), []byte("[server]\nbind_addr = \"0.0.0.0:3080\"\n"), 0o600)
	_ = os.WriteFile(filepath.Join(backhaulDir, "server-3.toml"), []byte("[server]\nbind_addr = \"0.0.0.0:3090\"\n"), 0o600)
	cfg := defaultSSHFwdConfig()
	cfg.Enabled, cfg.Role, cfg.RemoteHost = true, "iran", "198.51.100.1"
	sshFwdMu.Lock()
	_ = saveSSHFwdConfigLocked(cfg)
	sshFwdMu.Unlock()
	save := "*filter\n:QUANTUM_ACCT_IN - [0:0]\n:QUANTUM_ACCT_OUT - [0:0]\n" +
		"[1:100] -A INPUT -j QUANTUM_ACCT_IN\n[1:100] -A OUTPUT -j QUANTUM_ACCT_OUT\n" +
		"[1:1000] -A QUANTUM_ACCT_IN -p tcp -m tcp --dport 3080\n[1:10] -A QUANTUM_ACCT_IN -p udp -m udp --dport 3080\n" +
		"[1:2000] -A QUANTUM_ACCT_OUT -p tcp -m tcp --sport 3080\n" +
		"[1:300] -A QUANTUM_ACCT_IN -p tcp -m tcp --dport 3090\n[1:400] -A QUANTUM_ACCT_OUT -p tcp -m tcp --sport 3090\n" +
		"[1:50] -A QUANTUM_ACCT_IN -s 198.51.100.1/32 -p tcp -m tcp --sport 22\n[1:60] -A QUANTUM_ACCT_OUT -d 198.51.100.1/32 -p tcp -m tcp --dport 22\nCOMMIT\n"
	infra.Runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "iptables-save" {
			return []byte(save), nil
		}
		return nil, nil // iptables-restore / iptables -C: accepted
	}
	reset := func() {
		carrierState.Lock()
		carrierState.at, carrierState.lastFailed = time.Time{}, time.Time{}
		carrierState.Unlock()
	}
	t.Cleanup(func() {
		backhaulDir, infra.ConfigDir, infra.Runner = oldDir, oldCfg, oldRunner
		carrierState.Lock()
		carrierState.sig, carrierState.at, carrierState.tags, carrierState.ok = "", time.Time{}, nil, false
		carrierState.Unlock()
	})
	reset()
	readCarrierCounters() // builds the chains: counters start at 0
	reset()
	rx, tx, ok := readCarrierCounters()
	if !ok || rx != 1360 || tx != 2460 {
		t.Fatalf("total %d/%d %v, want 1360/2460", rx, tx, ok)
	}
	tags := carrierTagCounters()
	for tag, want := range map[string][2]uint64{"backhaul-server": {1010, 2000}, "backhaul-server-3": {300, 400}, "bagher-1": {50, 60}} {
		if tags[tag] != want {
			t.Errorf("%s = %v, want %v (all: %v)", tag, tags[tag], want, tags)
		}
	}
}
