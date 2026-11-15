//go:build integration

// balancer_lab_integration_test.go — AGENT-19 TASK B: the "UDP stickiness
// after failover" question on REAL nftables and REAL netns UDP sinks.
//
// TOPOLOGY — four namespaces; the go test process itself runs as ROOT
// INSIDE the qdev19-host ROUTER netns (created and torn down by
// 00-ADMIN/tools/agent19-udp-lab.sh). This is deliberate: the WSL host
// netns runs ufw with INPUT/FORWARD policy DROP (the human's firewall —
// never touched by this lab), so any topology that ROUTES THROUGH the
// host netns is dropped on the floor. A fresh netns has NO firewall and
// its own nft/sysctl state, so:
//
//	qdev19-host (router = current netns of THIS process)
//	  v-q19-c   10.207.0.1/24   ← client uplink
//	  v-q19-a   10.208.0.1/30   ← sink A link
//	  v-q19-b   10.208.0.5/30   ← sink B link
//	  ip_forward=1, rp_filter=0, lo up, the balancer's REAL nft table
//	qdev19-cli   10.207.0.2/24 + secondary sources 10.207.0.3-… (uplink)
//	qdev19-a     10.208.0.2/30  (sink A, UDP :15901)
//	qdev19-b     10.208.0.6/30  (sink B, UDP :15902)
//
// The REAL forwardBalancer (fake engine for tunnel status, REAL nft apply —
// the seam is wrapped pass-through, never stubbed) renders the UDP forward:
//
//	udp dport 15900 dnat to jhash ip saddr mod 3 map { 0-1 : <A> . 15901, 2 : <B> . 15902 }
//
// Weights 2:1 (t1=A, t2=B). Verified, per phase:
//
//	set up     → nft ranges EXACT (script text + tick-report diag 0-1/2, total 3)
//	steady     → per-source stickiness (one source never straddles sinks);
//	             both sinks receive (bounded redraw rounds; the exact
//	             jhash distribution is NOT pinned — it is data-dependent)
//	kill A     → every source lands on B and STAYS on B across volleys
//	             (no flapping; the map collapse is one atomic nft -f swap)
//	A returns  → failback honors switch_back_s (live 20s window: re-admission
//	             is deferred while inside it, exact-weight ranges restored
//	             after it; the DEFAULT 300 is unit-pinned by
//	             TestBalancerSwitchBackStickyAway with the fake clock)
//
//	Run: 00-ADMIN/tools/agent19-udp-lab.sh   (wrapper: creates the router
//	      netns, runs BAL_LAB=1 go test -tags integration inside it as
//	      root, tears everything down with proof)
//
// Cleanup is t.Cleanup-driven with proof lines; the real host beyond the
// disposable netns/veths is never touched (no sysctls, no firewall).
package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-protocol"
)

const (
	balLabNSCli = "qdev19-cli"
	balLabNSA   = "qdev19-a"
	balLabNSB   = "qdev19-b"
	balLabVethC = "v-q19-c"
	balLabVethA = "v-q19-a"
	balLabVethB = "v-q19-b"
	// balLabSwitch is the LIVE switch_back_s. The DEFAULT 300 is unit-pinned
	// by TestBalancerSwitchBackStickyAway (fake clock); the live window must
	// outlive the failover volleys that precede the inside-window phase
	// (the window runs from FAILBACK-DETECTION, not from A's recovery).
	balLabSwitch = 20
	balLabPort   = 15900 // forward listen port (udp)
	balLabPortA  = 15901 // sink A target port
	balLabPortB  = 15902 // sink B target port
	balLabSinkA  = "10.208.0.2"
	balLabSinkB  = "10.208.0.6"
)

func balLabSkip(t *testing.T) {
	t.Helper()
	if os.Getenv("BAL_LAB") == "" {
		t.Skip("BAL_LAB not set (root + Linux; ip + nft + python3)")
	}
	if os.Geteuid() != 0 {
		t.Skip("the lab must run as ROOT inside the qdev19-host router netns (see 00-ADMIN/tools/agent19-udp-lab.sh): the balancer's nft -f apply has no sudo wrapper")
	}
}

// balLabRun runs one command in the CURRENT netns (the qdev19-host router —
// the test process lives inside it, so every nft/sysctl/link call lands on
// the ROUTER, never on the real WSL host).
func balLabRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v: %s", args, err, out)
	}
	return string(out)
}

// tiny python3 helpers (netns share the filesystem); sinks log one line
// per datagram: "src=<ip> data=<payload>".
const balLabSinkPy = `
import socket, sys
port = int(sys.argv[1]); log = open(sys.argv[2], "a", buffering=1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
while True:
    d, a = s.recvfrom(2048)
    log.write("src=%s data=%s\n" % (a[0], d.decode(errors="replace")))
`

const balLabSendPy = `
import socket, sys, time
host = sys.argv[1]; port = int(sys.argv[2]); src = sys.argv[3]; n = int(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
for i in range(n):
    s.sendto(("src-" + src + "-" + str(i)).encode(), (host, port))
    time.sleep(0.22)
`

// balLabVolley sends one datagram volley from every source address and
// returns, per source IP, which sink received its packets ("" = none).
// The sink logs are TRUNCATED per volley (never removed: the sinks hold
// them open O_APPEND — an unlink would strand their writes on the dead
// inode), so every volley attributes only its own datagrams.
func balLabVolley(t *testing.T, sources []string) map[string]string {
	t.Helper()
	for _, p := range []string{"/tmp/q19a.log", "/tmp/q19b.log"} {
		if err := os.WriteFile(p, []byte(""), 0644); err != nil {
			t.Fatalf("truncate %s: %v", p, err)
		}
	}
	var wg sync.WaitGroup
	for _, src := range sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			exec.Command("ip", "netns", "exec", balLabNSCli,
				"python3", "-c", balLabSendPy, "10.207.0.1", fmt.Sprint(balLabPort), src, "4").Run()
		}(src)
	}
	wg.Wait()
	time.Sleep(700 * time.Millisecond)
	attr := map[string]string{}
	for sink, log := range map[string]string{"A": "/tmp/q19a.log", "B": "/tmp/q19b.log"} {
		data, err := os.ReadFile(log)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "src=") {
				continue
			}
			fields := strings.Fields(line)
			ip := strings.TrimPrefix(fields[0], "src=")
			if prev, ok := attr[ip]; ok && prev != sink {
				attr[ip] = "MIXED"
			} else {
				attr[ip] = sink
			}
		}
	}
	return attr
}

// balLabSources returns n client source addresses from the client net's
// secondary pool (10.207.0.<from> .. to-exclusive).
func balLabSources(from, to int) []string {
	out := make([]string, 0, to-from)
	for i := from; i < to; i++ {
		out = append(out, fmt.Sprintf("10.207.0.%d", i))
	}
	return out
}

func TestBalancerUDPFailoverLab(t *testing.T) {
	balLabSkip(t)

	// kernel probes: netns + nft must both work inside the router netns.
	if out, err := exec.Command("ip", "netns", "list").CombinedOutput(); err != nil {
		t.Skipf("netns unavailable: %v: %s", err, out)
	}
	if out, err := exec.Command("nft", "list", "tables").CombinedOutput(); err != nil {
		t.Skipf("nft unavailable: %v: %s", err, out)
	}

	// save the ROUTER's knobs this lab touches (the router netns is thrown
	// away by the wrapper afterwards; the real host is never touched at all).
	fwdBefore := strings.TrimSpace(balLabRun(t, "sysctl", "-n", "net.ipv4.ip_forward"))
	rpBefore := strings.TrimSpace(balLabRun(t, "sysctl", "-n", "net.ipv4.conf.all.rp_filter"))

	clean := func() {
		for _, ns := range []string{balLabNSCli, balLabNSA, balLabNSB} {
			exec.Command("ip", "netns", "del", ns).Run()
		}
		for _, v := range []string{balLabVethC, balLabVethA, balLabVethB} {
			exec.Command("ip", "link", "del", v).Run()
		}
		exec.Command("nft", "delete", "table", "ip", "quantum-fwd").Run()
		exec.Command("pkill", "-f", "q19sink.py").Run()
	}
	clean()
	t.Cleanup(func() {
		clean()
		balLabRun(t, "sysctl", "-w", "net.ipv4.ip_forward="+fwdBefore)
		balLabRun(t, "sysctl", "-w", "net.ipv4.conf.all.rp_filter="+rpBefore)
		t.Logf("cleanup proof: %s/%s/%s netns + v-q19-* links + quantum-fwd table + sinks removed; router sysctls restored (%s/%s)",
			balLabNSCli, balLabNSA, balLabNSB, fwdBefore, rpBefore)
	})

	// loose rp_filter BEFORE the veths exist (new links inherit default),
	// forwarding on, lo up (local delivery to the router's own addresses),
	// then the three namespaces over three veth pairs.
	balLabRun(t, "sysctl", "-w", "net.ipv4.conf.default.rp_filter=0")
	balLabRun(t, "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
	balLabRun(t, "sysctl", "-w", "net.ipv4.ip_forward=1")
	balLabRun(t, "ip", "link", "set", "lo", "up")
	for _, c := range [][]string{
		{"ip", "netns", "add", balLabNSCli}, {"ip", "netns", "add", balLabNSA}, {"ip", "netns", "add", balLabNSB},
		{"ip", "link", "add", balLabVethC, "type", "veth", "peer", "name", balLabVethC + "-p"},
		{"ip", "link", "add", balLabVethA, "type", "veth", "peer", "name", balLabVethA + "-p"},
		{"ip", "link", "add", balLabVethB, "type", "veth", "peer", "name", balLabVethB + "-p"},
		{"ip", "link", "set", balLabVethC + "-p", "netns", balLabNSCli},
		{"ip", "link", "set", balLabVethA + "-p", "netns", balLabNSA},
		{"ip", "link", "set", balLabVethB + "-p", "netns", balLabNSB},
		{"ip", "addr", "add", "10.207.0.1/24", "dev", balLabVethC},
		{"ip", "addr", "add", "10.208.0.1/30", "dev", balLabVethA},
		{"ip", "addr", "add", "10.208.0.5/30", "dev", balLabVethB},
		{"ip", "link", "set", balLabVethC, "up"}, {"ip", "link", "set", balLabVethA, "up"}, {"ip", "link", "set", balLabVethB, "up"},
	} {
		balLabRun(t, c...)
	}
	balLabRun(t, "ip", "netns", "exec", balLabNSCli, "ip", "addr", "add", "10.207.0.2/24", "dev", balLabVethC+"-p")
	for i := 3; i <= 40; i++ { // 38 secondary source addresses (12 used per volley)
		balLabRun(t, "ip", "netns", "exec", balLabNSCli, "ip", "addr", "add",
			fmt.Sprintf("10.207.0.%d/24", i), "dev", balLabVethC+"-p")
	}
	for ns, dev := range map[string]string{balLabNSCli: balLabVethC + "-p", balLabNSA: balLabVethA + "-p", balLabNSB: balLabVethB + "-p"} {
		balLabRun(t, "ip", "netns", "exec", ns, "ip", "link", "set", dev, "up")
		balLabRun(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
	}
	balLabRun(t, "ip", "netns", "exec", balLabNSA, "ip", "addr", "add", balLabSinkA+"/30", "dev", balLabVethA+"-p")
	balLabRun(t, "ip", "netns", "exec", balLabNSB, "ip", "addr", "add", balLabSinkB+"/30", "dev", balLabVethB+"-p")
	// DNATed datagrams arrive at the sinks carrying CLIENT source addresses;
	// without a route back (and with the fresh netns' strict rp_filter) the
	// kernel drops them as martians before the sink socket ever sees them.
	balLabRun(t, "ip", "netns", "exec", balLabNSA, "ip", "route", "add", "default", "via", "10.208.0.1")
	balLabRun(t, "ip", "netns", "exec", balLabNSB, "ip", "route", "add", "default", "via", "10.208.0.5")
	for _, ns := range []string{balLabNSCli, balLabNSA, balLabNSB} {
		balLabRun(t, "ip", "netns", "exec", ns, "sysctl", "-w", "net.ipv4.conf.all.rp_filter=0")
		balLabRun(t, "ip", "netns", "exec", ns, "sysctl", "-w", "net.ipv4.conf.default.rp_filter=0")
	}
	if out, err := exec.Command("ip", "netns", "exec", balLabNSCli, "ping", "-c", "1", "-W", "2", "10.207.0.1").CombinedOutput(); err != nil {
		t.Fatalf("client->router link dead: %v: %s", err, out)
	}

	// sinks A and B (each logs src+payload per datagram).
	sinkA := exec.Command("ip", "netns", "exec", balLabNSA, "python3", "-c", balLabSinkPy,
		fmt.Sprint(balLabPortA), "/tmp/q19a.log")
	sinkA.Stderr = os.Stderr
	if err := sinkA.Start(); err != nil {
		t.Fatalf("sink A: %v", err)
	}
	t.Cleanup(func() { sinkA.Process.Kill() })
	sinkB := exec.Command("ip", "netns", "exec", balLabNSB, "python3", "-c", balLabSinkPy,
		fmt.Sprint(balLabPortB), "/tmp/q19b.log")
	sinkB.Stderr = os.Stderr
	if err := sinkB.Start(); err != nil {
		t.Fatalf("sink B: %v", err)
	}
	t.Cleanup(func() { sinkB.Process.Kill() })
	time.Sleep(500 * time.Millisecond)

	// the REAL balancer: fake engine for tunnel status, REAL nft apply —
	// the apply seam is wrapped PASS-THROUGH (record + forward), never
	// stubbed, so every asserted script was actually applied to the kernel
	// INSIDE THE ROUTER netns.
	fake := engine.NewFakeEngine("fake")
	reg := engine.NewRegistry()
	if err := reg.Register(fake); err != nil {
		t.Fatal(err)
	}
	mgr := engine.NewManager(reg)
	bal := newForwardBalancer(mgr, reg)
	var scriptMu sync.Mutex
	var scripts []string
	realApply := nftApplyScript
	nftApplyScript = func(s string) error {
		scriptMu.Lock()
		scripts = append(scripts, s)
		scriptMu.Unlock()
		return realApply(s)
	}
	// TestMain refuses host commands through the runner seam for every
	// test; the lab restores the REAL runner for its duration — every
	// command lands INSIDE the router netns (this process's netns), so
	// the host is still untouched.
	realRunner := runner
	runner = execRunner
	t.Cleanup(func() { bal.Stop(); nftApplyScript = realApply; runner = realRunner })
	lastScript := func() string {
		scriptMu.Lock()
		defer scriptMu.Unlock()
		if len(scripts) == 0 {
			return ""
		}
		return scripts[len(scripts)-1]
	}

	fake.SetForwardAddress("t1", balLabSinkA, balLabPortA)
	fake.SetForwardAddress("t2", balLabSinkB, balLabPortB)

	d := protocol.DesiredV2{
		Revision: "agent19-udp-lab",
		Engines:  []protocol.EngineSpec{{ID: "fake", Enabled: true}},
		Tunnels: []protocol.TunnelSpec{
			{ID: "t1", TopologyID: "topo-lab", LocalServer: "ir-1", RemoteServer: "hz-a", Engine: "fake", Enabled: true},
			{ID: "t2", TopologyID: "topo-lab", LocalServer: "ir-1", RemoteServer: "hz-b", Engine: "fake", Enabled: true},
		},
		Balancing: &protocol.BalancingPolicy{
			Weights: []protocol.WeightRule{
				{TopologyID: "topo-lab", LocalServer: "ir-1", RemoteServer: "hz-a", Weight: 2},
				{TopologyID: "topo-lab", LocalServer: "ir-1", RemoteServer: "hz-b", Weight: 1},
			},
			HealthCheck: protocol.HealthCheckParams{IntervalS: 1, TimeoutMS: 200, Probe: "engine", ConsecutiveDown: 2, ConsecutiveUp: 1},
			Failover:    protocol.FailoverRules{SwitchBackS: balLabSwitch},
		},
		TargetGroups: []protocol.TargetGroup{{ID: "grp-lab", TopologyID: "topo-lab"}},
		Forwards: []protocol.ForwardRule{
			{ID: "fw-lab", ListenPort: balLabPort, Proto: "udp", TargetGroup: "grp-lab", TargetPort: 0},
		},
	}
	engs, tuns := toEngineSpecs(d.Engines, d.Tunnels)
	if res := mgr.Reconcile(testCtx(), engs, tuns); len(res.Errors) != 0 {
		t.Fatalf("manager reconcile: %v", res.Errors)
	}
	bal.Reconcile(&d) // first pass → initial render applied for real

	// SET UP: the initial nft ranges must be EXACTLY the weighted split
	// (t1 sorts before t2 → A gets 0-1, B gets 2 of mod 3).
	wantMap := fmt.Sprintf("udp dport %d dnat to jhash ip saddr mod 3 map { 0-1 : %s . %d, 2-2 : %s . %d }",
		balLabPort, balLabSinkA, balLabPortA, balLabSinkB, balLabPortB)
	if got := strings.TrimSpace(lastScript()); !strings.Contains(got, wantMap) {
		t.Fatalf("initial nft ranges not exact:\n want substring: %s\n got script:\n%s", wantMap, got)
	}
	t.Logf("PASS setup: nft ranges exact (weights 2:1): %s", wantMap)

	rep := bal.tick() // one healthy pass: the diag ranges must agree
	var gotA, gotB string
	total := 0
	for _, td := range rep.Targets {
		if td.Reason != "selected" {
			continue
		}
		switch td.Tunnel {
		case "t1":
			gotA, total = td.NftRange, td.Total
		case "t2":
			gotB, total = td.NftRange, td.Total
		}
	}
	if gotA != "0-1" || gotB != "2-2" || total != 3 {
		t.Fatalf("tick-report diag ranges: t1=%q t2=%q total=%d (want 0-1 / 2 / 3)", gotA, gotB, total)
	}
	t.Logf("PASS setup: tick-report diag nft_range t1=%q t2=%q total=%d", gotA, gotB, total)

	// STEADY: per-source stickiness + both sinks receiving. The exact jhash
	// split is data-dependent (NOT asserted); a source that straddles sinks
	// across its volley IS a defect and is asserted away.
	steadyAttr := balLabVolley(t, balLabSources(2, 14))
	sticky, hitsA, hitsB := 0, 0, 0
	for ip, sink := range steadyAttr {
		switch sink {
		case "A":
			hitsA++
			sticky++
		case "B":
			hitsB++
			sticky++
		case "":
			t.Logf("  source %s: no packets delivered (dropped)", ip)
		default: // MIXED — the one real defect this phase hunts
			t.Fatalf("UDP source %s straddled sinks (%s) in steady state — flow-stickiness broken", ip, sink)
		}
	}
	if sticky == 0 || hitsA == 0 || hitsB == 0 {
		// jhash may bucket all drawn addresses into one range; redraw once
		// with different addresses before calling it a failure.
		steadyAttr = balLabVolley(t, balLabSources(14, 26))
		sticky, hitsA, hitsB = 0, 0, 0
		for ip, sink := range steadyAttr {
			switch sink {
			case "A":
				hitsA++
				sticky++
			case "B":
				hitsB++
				sticky++
			case "":
				t.Logf("  source %s: no packets delivered (dropped)", ip)
			default:
				t.Fatalf("UDP source %s straddled sinks (%s) in steady state — flow-stickiness broken", ip, sink)
			}
		}
	}
	if sticky == 0 {
		t.Fatalf("steady volley delivered nothing: %v", steadyAttr)
	}
	if hitsA == 0 || hitsB == 0 {
		t.Fatalf("steady volley reached only one sink (A=%d B=%d of %d sticky sources) across two address draws", hitsA, hitsB, sticky)
	}
	t.Logf("PASS steady: %d sources sticky, A=%d B=%d (both targets receiving)", sticky, hitsA, hitsB)

	// KILL A: sink down + health down ×ConsecutiveDown → the map collapses
	// to B-only (mod 1) in ONE atomic nft swap, and EVERY source lands on B
	// and STAYS on B (no flapping across two volleys).
	sinkA.Process.Kill()
	fake.SetHealth("t1", engine.Health{OK: false})
	var downRep balTickReport
	for i := 0; i < 5; i++ {
		time.Sleep(time.Second)
		downRep = bal.tick()
		if len(downRep.DetectedDown) == 1 && downRep.DetectedDown[0] == "t1" {
			break
		}
	}
	if len(downRep.DetectedDown) != 1 || downRep.DetectedDown[0] != "t1" {
		t.Fatalf("A death never detected: %+v", downRep.DetectedDown)
	}
	wantBOnly := fmt.Sprintf("udp dport %d dnat to jhash ip saddr mod 1 map { 0-0 : %s . %d }",
		balLabPort, balLabSinkB, balLabPortB)
	if got := strings.TrimSpace(lastScript()); !strings.Contains(got, wantBOnly) {
		t.Fatalf("post-failover nft ranges not exact:\n want substring: %s\n got script:\n%s", wantBOnly, got)
	}
	t.Logf("PASS failover: map collapsed to B-only: %s", wantBOnly)
	for volley := 1; volley <= 2; volley++ {
		attr := balLabVolley(t, balLabSources(2, 14))
		for ip, sink := range attr {
			if sink == "" {
				t.Fatalf("failover volley %d: source %s delivered NOTHING (B map broken)", volley, ip)
			}
			if sink != "B" {
				t.Fatalf("failover volley %d: source %s hit %s (want B-only; flapping/blackhole)", volley, ip, sink)
			}
		}
		time.Sleep(time.Second)
	}
	t.Logf("PASS failover: 2 volleys × every source → B only (no flapping)")

	// A RETURNS: failback must honor switch_back_s (live window) — inside
	// the window the recovered target stays OUT (B-only); past it, the
	// healthy tick re-admits with the exact weighted ranges restored.
	failoverAt := time.Now()
	sinkA = exec.Command("ip", "netns", "exec", balLabNSA, "python3", "-c", balLabSinkPy,
		fmt.Sprint(balLabPortA), "/tmp/q19a.log")
	sinkA.Stderr = os.Stderr
	if err := sinkA.Start(); err != nil {
		t.Fatalf("sink A restart: %v", err)
	}
	t.Cleanup(func() { sinkA.Process.Kill() })
	time.Sleep(400 * time.Millisecond)
	fake.SetHealth("t1", engine.Health{OK: true}) // running again, healthy

	inside := bal.tick() // ConsecutiveUp=1 satisfied → gated by the window only
	for _, td := range inside.Targets {
		if td.Tunnel == "t1" && td.Reason == "selected" {
			t.Fatalf("A re-admitted %v after failover — switch_back_s=%d not honored (sticky-away broken)",
				time.Since(failoverAt), balLabSwitch)
		}
	}
	if got := strings.TrimSpace(lastScript()); !strings.Contains(got, wantBOnly) {
		t.Fatalf("inside the switch_back window the map must stay B-only:\n%s", got)
	}
	attr := balLabVolley(t, balLabSources(2, 14))
	for ip, sink := range attr {
		if sink == "A" {
			t.Fatalf("inside the switch_back window a flow reached A (source %s) — failback sticky-away broken", ip)
		}
	}
	t.Logf("PASS failback (inside window): A healthy but held out (switch_back_s=%d); flows stay on B", balLabSwitch)

	for time.Since(failoverAt) < time.Duration(balLabSwitch)*time.Second+800*time.Millisecond {
		time.Sleep(300 * time.Millisecond)
	}
	// The balancer's OWN reconcile loop keeps ticking (Reconcile started
	// it), so the first healthy tick past the window re-admits t1 and the
	// one-shot DetectedUp is consumed there — the OBSERVABLE evidence is
	// the restored weighted map in the kernel-applied script plus real
	// packets reaching A again.
	var upRep balTickReport
	for i := 0; i < 10; i++ {
		upRep = bal.tick()
		if strings.Contains(strings.TrimSpace(lastScript()), wantMap) {
			break
		}
		time.Sleep(time.Second)
	}
	if got := strings.TrimSpace(lastScript()); !strings.Contains(got, wantMap) {
		t.Fatalf("post-failback nft ranges not exact (want the weighted 2:1 map restored after switch_back_s=%d):\n got:\n%s", balLabSwitch, got)
	}
	afterAttr := balLabVolley(t, balLabSources(14, 26))
	stickyAfter, reachedA := 0, false
	for ip, sink := range afterAttr {
		switch sink {
		case "A":
			reachedA = true
			stickyAfter++
		case "B":
			stickyAfter++
		case "":
			t.Logf("  source %s: no packets delivered (dropped)", ip)
		default:
			t.Fatalf("post-failback source %s straddled sinks (%s)", ip, sink)
		}
	}
	if !reachedA || stickyAfter == 0 {
		t.Fatalf("post-failback volley did not reach A (sticky=%d): %v", stickyAfter, afterAttr)
	}
	t.Logf("PASS failback (post window): t1 re-admitted (DetectedUp=%v — may have been consumed by the balancer's own loop), weighted map restored, A receiving again (%d sticky sources)",
		upRep.DetectedUp, stickyAfter)
}
