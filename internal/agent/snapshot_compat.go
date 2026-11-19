package agent

// Snapshot collection helpers ported verbatim from the controller
// monolith (snapshot.go @ a1e999c): the host view collector, unit state
// parsing, control-port enumeration and the probe caches. The periodic
// snapshot LOOP stays controller-side; the agent only does synchronous
// collects (directView/localStatus).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

// snapPool is the shared bounded worker pool for probe tasks.
var snapPool = newWorkPool(min(runtime.NumCPU(), 4))

const (
	icmpFirstJitter  = 3 * time.Second
	icmpRepeatJitter = 5 * time.Second
	probeOKTTL       = 15 * time.Second
	probeFailTTL     = 30 * time.Second
	snapTaskTimeout  = 6 * time.Second
)

// baseUnits are the base tunnel services, in role-detection order.
var baseUnits = []string{"frps", "frpc", "backhaul-server", "backhaul-client"}

// parseAddrShow parses `ip -o -4 addr show`: ifname -> first inet CIDR.
func parseAddrShow(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		name := strings.TrimSuffix(f[1], ":")
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i]
		}
		for i := 2; i+1 < len(f); i++ {
			if f[i] == "inet" {
				if _, seen := m[name]; !seen {
					m[name] = f[i+1]
				}
				break
			}
		}
	}
	return m
}

// parseIsActive maps `systemctl is-active a b c` output (one line per unit,
// same order) onto the unit names; ok=false when the line count does not match.
func parseIsActive(units []string, out string) (map[string]bool, bool) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != len(units) {
		return nil, false
	}
	m := make(map[string]bool, len(units))
	for i, u := range units {
		m[u] = strings.TrimSpace(lines[i]) == "active"
	}
	return m, true
}

func unitsFor(recs []peerRecord) []string {
	units := append([]string{}, baseUnits...)
	units = append(units, matrixUnit)
	seen := map[string]bool{}
	for _, u := range units {
		seen[u] = true
	}
	for _, p := range recs {
		if p.FrpsSvc != "" && !seen[p.FrpsSvc] {
			seen[p.FrpsSvc] = true
			units = append(units, p.FrpsSvc)
		}
	}
	return units
}

func controlPortsOf(recs []peerRecord, extra ...int) []int {
	var ports []int
	for _, p := range recs {
		ports = append(ports, p.FrpPort)
	}
	return append(ports, extra...)
}

// timedStep runs one collector sub-step and records its cost for /api/selfstats.
func timedStep(name string, f func()) {
	t := time.Now()
	f()
	recordSampler("snapshot."+name, time.Since(t))
}

// pingOnce is one ICMP echo with a hard timeout; ms is the wall time.
// Matrix probes have a distinct key and bind to qmx0: a reply through another
// tunnel or the host's default route is not evidence of a connected Matrix mesh.
func matrixProbeKey(target string) string { return matrixIfaceName + "|" + target }

func pingOnce(target string) (bool, float64) {
	start := time.Now()
	args := []string{"-c", "1", "-W", "2", target}
	if ip, ok := strings.CutPrefix(target, matrixIfaceName+"|"); ok {
		args = []string{"-I", matrixIfaceName, "-c", "1", "-W", "2", ip}
	}
	if _, err := infra.RunCmdTimeout(4*time.Second, "ping", args...); err != nil {
		return false, -1
	}
	return true, float64(time.Since(start).Microseconds()) / 1000
}

// directView collects a view with inline ICMP, for fresh synchronous reads
// (livePeers / localStatus). It never runs the connect probe.
func directView(recs []peerRecord) *hostView {
	v := collectHost(recs, nil)
	v.icmp = func(target string) icmpResult {
		ok, d := pingOnce(target)
		return icmpResult{OK: ok, Ms: d, Known: true}
	}
	return v
}

type probeEntry struct {
	r  connectResult
	at time.Time
}

type probeState struct {
	mu  sync.Mutex
	res map[int]probeEntry
}

func newProbeState() *probeState { return &probeState{res: map[int]probeEntry{}} }

func (c *probeState) lookup(id int) connectResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.res[id].r
}

// schedule queues a connect probe for each query whose cached result is stale.
func (c *probeState) schedule(now time.Time, qs []ctrlQuery) {
	keep := map[int]bool{}
	for _, q := range qs {
		keep[q.ID] = true
	}
	c.mu.Lock()
	for id := range c.res {
		if !keep[id] {
			delete(c.res, id)
		}
	}
	var stale []ctrlQuery
	for _, q := range qs {
		e, ok := c.res[q.ID]
		ttl := probeFailTTL
		if e.r.OK {
			ttl = probeOKTTL
		}
		if !ok || now.Sub(e.at) >= ttl {
			stale = append(stale, q)
		}
	}
	c.mu.Unlock()
	for _, q := range stale {
		q := q
		snapPool.submit("probe:"+strconv.Itoa(q.ID), snapTaskTimeout, func() {
			r := connectProbe(q)
			c.mu.Lock()
			c.res[q.ID] = probeEntry{r, time.Now()}
			c.mu.Unlock()
		})
	}
}

func parsePingMs(s string) float64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "ms"))
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return -1
	}
	return v
}

func peerOr(st tunnelStatus) string {
	if st.Gre.PeerIP != "" {
		return st.Gre.PeerIP
	}
	return st.GrePeer
}

// runQuantumCluster runs a quantum.sh subcommand for the cluster (join-hub,
// leave-hub), which installs units and may download a core.
func runQuantumCluster(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var cmd *exec.Cmd
	if script, err := greScriptPath(); err == nil {
		cmd = exec.CommandContext(ctx, "bash", append([]string{script}, args...)...)
	} else if infra.FileExists("/usr/local/bin/quantum") {
		cmd = exec.CommandContext(ctx, "/usr/local/bin/quantum", args...)
	} else {
		return "", fmt.Errorf("quantum script not found")
	}
	cmd.Env = append(os.Environ(), "GRE_SKIP_PANEL=1", "TERM=dumb", "GRE_PANEL_DIR="+infra.ConfigDir)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(stripANSI(string(out))), err
}

// collectHost gathers the per-tick host view with a fixed number of commands.
func collectHost(recs []peerRecord, prev map[string]devCounters) *hostView {
	v := &hostView{inner: map[string]string{}, active: map[string]bool{}, flowing: map[string]bool{}}
	timedStep("ip_tunnel", func() {
		if out, err := infra.RunCmdTimeout(5*time.Second, "ip", "tunnel", "show"); err == nil {
			v.tunnelShow, v.tunnelOK = string(out), true
		}
	})
	timedStep("ip_addr", func() {
		if out, err := infra.RunCmdTimeoutOut(5*time.Second, "ip", "-o", "-4", "addr", "show"); err == nil {
			v.inner = parseAddrShow(string(out))
		}
	})
	timedStep("systemctl", func() {
		units := unitsFor(recs)
		out, _ := infra.RunCmdTimeoutOut(5*time.Second, "systemctl", append([]string{"is-active"}, units...)...)
		if m, ok := parseIsActive(units, string(out)); ok {
			v.active = m
			return
		}
		for _, u := range units { // unexpected output shape: fall back to one call per unit
			o, _ := infra.RunCmdTimeoutOut(5*time.Second, "systemctl", "is-active", u)
			v.active[u] = strings.TrimSpace(string(o)) == "active"
		}
	})
	timedStep("netdev", func() {
		// The interface and the port counters are read together and stamped
		// with one time, so every speed is bytes over the time between two reads.
		v.devAt = time.Now()
		if b, err := os.ReadFile(filepath.Join(procRoot, "net/dev")); err == nil {
			v.devData = string(b)
			v.dev = parseNetDev(v.devData)
		}
		v.serverCounters, v.serverKnown = serverIfSelector.counters(v.dev, v.devAt, procRoot, serverSysRoot, serverNetProbe)
		if b, err := serverNetProbe.readFile(filepath.Join(procRoot, "sys/kernel/random/boot_id")); err == nil {
			v.bootID = strings.TrimSpace(string(b))
		}
		v.carrierRx, v.carrierTx, v.carrierOK = carrierCounters()
		if v.carrierOK {
			v.carrierTags = carrierTagCounters()
		}
		for name, c := range v.dev {
			if p, ok := prev[name]; ok && p != c {
				v.flowing[name] = true
			}
		}
	})
	timedStep("ss", func() {
		// Only the tunnel control sessions are matched, so ask ss for those ports:
		// unfiltered, ss -i dumps every socket on the host (about 42MB a tick at
		// 100k connections) and the kernel fills tcp_info for each.
		filter := ssPortFilter(controlPortsOf(recs, localStatusFrom(v).BindPort))
		if filter == "" {
			return // no tunnel ports: no session can match
		}
		if out, err := infra.RunCmdTimeoutOut(5*time.Second, "ss", "-Htin", "state", "established", filter); err == nil {
			v.sessions = parseSS(string(out))
		}
	})
	v.owners = portOwners(controlPortsOf(recs))
	return v
}

// sampler machinery (ported verbatim from the monolith metrics.go).
var (
	samplerMu    sync.Mutex
	samplerStats = map[string]*samplerStat{}
)

type samplerStat struct {
	runs     uint64
	total    time.Duration
	last     time.Duration
	max      time.Duration
	lastUnix int64
}

func recordSampler(name string, d time.Duration) {
	samplerMu.Lock()
	defer samplerMu.Unlock()
	s := samplerStats[name]
	if s == nil {
		s = &samplerStat{}
		samplerStats[name] = s
	}
	s.runs++
	s.total += d
	s.last = d
	if d > s.max {
		s.max = d
	}
	s.lastUnix = time.Now().Unix()
}

// snapProbe caches active connect probes (monolith snapshot.go var).
var snapProbe = newProbeState()

// mainTunnelFrom describes the base tunnel as a hub spoke, or nil when this
// machine is not an Iran hub or has no base tunnel configured.
func mainTunnelFrom(st tunnelStatus, v *hostView) *peerLive {
	if !strings.HasPrefix(st.Role, "iran") || !(st.Gre.Exists || st.FrpUp || len(st.Proxies) > 0) {
		return nil
	}
	name := "Tunnel"
	if st.RemotePub != "" {
		name = "Tunnel · " + st.RemotePub
	}
	rec := peerRecord{ID: mainTunnelID, Name: name, RemotePub: st.RemotePub, Engine: st.Engine,
		Transport: st.Transport, FrpPort: st.BindPort, Ports: st.ProxyPorts}
	l := &peerLive{peerRecord: rec, GreUp: st.Gre.Exists, FrpUp: st.FrpUp, GreInner: st.Gre.Inner}
	sig := LinkSignals{ServiceActive: st.FrpUp, GreIfUp: st.Gre.Exists}
	if st.FrpUp {
		r := controlSessionIn(v.sessions, ctrlQuery{ID: mainTunnelID, Port: st.BindPort}, v.owners)
		l.Linked, sig.Session, sig.TCPRTTms = r.Linked, r.Linked, r.RTTms
		if !r.Linked && v.connect != nil {
			if c := v.connect(mainTunnelID); c.OK {
				sig.ConnectRTTms = c.RTTms
			}
		}
	}
	if st.Gre.Inner != "" {
		l.icmpTarget = grePeerInner(st.Gre.Inner)
	}
	sig.TrafficFlowing = v.flowing["gre-tunnel"]
	// The base tunnel's bytes: its GRE interface, or its Backhaul unit's port
	// counters. It had none, so the hub's main tunnel never showed a speed.
	if st.Gre.Exists {
		l.Rx, l.Tx = v.traffic("gre-tunnel")
	} else {
		l.Rx, l.Tx = v.carrierTraffic(st.FrpSvc)
	}
	sig.Rx, sig.Tx = l.Rx, l.Tx
	l.applyHealth(sig, v.icmpFor(l.icmpTarget))
	return l
}

// MatrixLinks are independent fleet spokes, not the legacy GRE/FRP main tunnel.
// Negative IDs cannot collide with configured peer IDs or mainTunnelID (-1).
func (s *HubSnapshot) MatrixLinks() []peerLive {
	mx := s.Local.Matrix
	if mx == nil || !mx.Enabled {
		return nil
	}
	peers := mx.Peers
	if mx.Role == "node" {
		peers = []matrixPeerStatus{{Name: "Iran hub", Addr: mx.Addr, IP: matrixHubIP,
			PingOK: mx.HubPingOK, LatencyMs: mx.LatencyMs}}
	} else if len(peers) == 0 {
		peers = []matrixPeerStatus{{Name: "Matrix · waiting for foreign node", LatencyMs: -1}}
	}
	out := make([]peerLive, 0, len(peers))
	for i, p := range peers {
		state := stateDown
		if mx.Service {
			state = stateDegraded
		}
		if mx.Service && p.PingOK {
			state = stateHealthy
		}
		l := peerLive{peerRecord: peerRecord{ID: -200000 - i, Name: p.Name, RemotePub: p.Addr,
			Engine: "matrix", Transport: mx.Family, NoGre: true, Ports: mx.Ports, FrpPort: mx.Port},
			Linked: mx.Service && p.PingOK, PingOK: mx.Service && p.PingOK, HealthState: state,
			LatencyMs: -1, ICMPMs: -1, GreInner: mx.Inner, SnapshotAgeMs: s.AgeMs(), Reasons: []string{}}
		if l.PingOK {
			l.LatencyMs, l.LatencyKind, l.ICMPMs, l.ICMPOK = p.LatencyMs, "icmp", p.LatencyMs, true
			l.PingMs = strconv.FormatFloat(p.LatencyMs, 'f', 0, 64) + "ms"
		} else {
			l.Reasons = append(l.Reasons, mx.Reasons...)
		}
		// qmx0 counters belong to this pair, never invent per-peer counters.
		if len(peers) == 1 {
			l.Rx, l.Tx = mx.Rx, mx.Tx
		}
		out = append(out, l)
	}
	return out
}

func icmpTargets(s *HubSnapshot) map[string]bool {
	m := map[string]bool{}
	if s.Local.Gre.Inner != "" {
		m[grePeerInner(s.Local.Gre.Inner)] = s.LocalSession
	}
	if mx := s.Local.Matrix; mx != nil && mx.Enabled && mx.Service {
		if mx.Role == "node" {
			m[matrixProbeKey(matrixHubIP)] = false
		}
		for _, p := range mx.Peers {
			if p.IP != "" {
				m[matrixProbeKey(p.IP)] = false
			}
		}
	}
	for _, l := range s.All() {
		if l.icmpTarget != "" {
			m[l.icmpTarget] = m[l.icmpTarget] || (l.FrpUp && l.Linked)
		}
	}
	return m
}
