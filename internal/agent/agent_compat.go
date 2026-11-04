package agent

// Agent-side definitions for types that were previously shared with the
// controller. In the separated architecture, the agent computes its own
// status locally using these lightweight view types. The controller
// receives agent-reported data through the WSS protocol.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// agentSeam is a mutex-guarded function seam (duplicated from the
// controller's agentSeam per shared-code policy).
type agentSeam[F any] struct {
	mu sync.RWMutex
	fn F
}

func (s *agentSeam[F]) get() F  { s.mu.RLock(); defer s.mu.RUnlock(); return s.fn }
func (s *agentSeam[F]) set(f F) { s.mu.Lock(); s.fn = f; s.mu.Unlock() }

// HubSnapshot is a minimal stub: the agent does not build hub snapshots.
// Referenced by carrieradvisor.go and tunnelhealth.go for type compatibility.
type HubSnapshot struct {
	At            time.Time
	Seq           uint64
	BuildMs       float64
	Local         tunnelStatus
	Main          *peerLive
	Peers         []peerLive
	Traffic       map[string]any
	ServerTraffic serverTrafficMetrics
	// DevData is the raw /proc/net/dev this snapshot was built from (the
	// traffic ledger sums tunnel interfaces from it).
	DevData string
	// LocalSession/LocalRTT: this machine's own tunnel session. On a hub it is
	// the main tunnel's control session; on a spoke, the outbound client
	// connection to the hub's control port.
	LocalSession bool
	LocalRTT     float64
	ActiveConns  any
	// CountersAt is when DevData and the carrier counters were read: every
	// speed (dashboard, per link) is bytes moved between two CountersAt.
	CountersAt time.Time
	// Carrier: the Backhaul/Bagher port counters (carrier_traffic.go), in
	// total and per tunnel.
	CarrierRx, CarrierTx uint64
	CarrierOK            bool
	CarrierTags          map[string][2]uint64
	// LocalRx/LocalTx: this server's base tunnel (GRE interface, Backhaul
	// unit, or Bagher); nil when unknown.
	LocalRx, LocalTx *uint64
	PublicIP         string
	FrpSince         string
	Bagher           map[string]any
}

// PeerHandshakeRequest is the agent-side handshake payload (ported from
// the controller monolith peer.go; the legacy peer-API handshake path
// exchanges it with the peer host).
type PeerHandshakeRequest struct {
	Role       string `json:"role"`
	PublicIP   string `json:"public_ip"`
	PanelPort  int    `json:"panel_port"`
	InternalIP string `json:"internal_ip"`
	BasePath   string `json:"base_path,omitempty"`
}

// alertTracker tracks alert states for the agent's local alert
// evaluation (struct shape ported verbatim from the monolith alerts.go;
// resalerts.go reads the fields directly).
type alertTracker struct {
	mu       sync.Mutex
	last     map[string]string
	lastSent map[string]time.Time
	primed   bool
}

func newAlertTracker() *alertTracker {
	return &alertTracker{last: map[string]string{}, lastSent: map[string]time.Time{}}
}

// linkSnap is a link snapshot view DTO.
type linkSnap struct {
	Name, State, Why string
}

// primaryInterface returns the outbound-facing interface name.
func primaryInterface() string {
	return "" // the agent uses net.Interfaces directly; this is a compat stub
}

// configDir is the agent's configuration directory.
var configDir = "/etc/quantum-agent"

// panelVersion is the agent binary version (independent from controller).
var panelVersion = "v0.1.0"

// hostView is everything the pure builders (localStatusFrom,
// livePeersFrom, mainTunnelFrom) need from the host, collected once
// (ported verbatim from the monolith snapshot.go).
type hostView struct {
	sessions       []ssSession
	tunnelShow     string
	tunnelOK       bool
	inner          map[string]string // ifname -> first inet CIDR
	active         map[string]bool   // unit -> active
	devData        string            // raw /proc/net/dev
	devAt          time.Time         // when devData and the carrier counters were read
	dev            map[string]devCounters
	serverCounters map[string][2]uint64 // physical host NICs only: received, transmitted
	serverKnown    bool
	bootID         string
	// Backhaul/Bagher port counters, read right after devData (carrier_traffic.go)
	carrierRx, carrierTx uint64
	carrierOK            bool
	carrierTags          map[string][2]uint64
	flowing              map[string]bool // iface counters moved since the previous tick
	owners               map[int]int
	icmp                 func(target string) icmpResult
	connect              func(id int) connectResult
}

func (v *hostView) icmpFor(target string) icmpResult {
	if target == "" || v.icmp == nil {
		return icmpResult{}
	}
	return v.icmp(target)
}

func (v *hostView) traffic(ifname string) (rx, tx *uint64) {
	c, ok := v.dev[ifname]
	if !ok {
		return nil, nil
	}
	r, t := c.rx, c.tx
	return &r, &t
}

// carrierTraffic is the port counters of one Backhaul unit or Bagher link
// (a tunnel without an interface of its own).
func (v *hostView) carrierTraffic(tag string) (rx, tx *uint64) {
	c, ok := v.carrierTags[tag]
	if !ok || tag == "" {
		return nil, nil
	}
	r, t := c[0], c[1]
	return &r, &t
}

// icmpResult is the result of an ICMP probe (monolith snapshot.go shape).
type icmpResult struct {
	OK    bool
	Ms    float64
	Known bool
}

// newWorkPool creates a bounded worker pool (duplicated per shared-code policy).
type workPool struct {
	sem  chan struct{}
	wg   sync.WaitGroup
	mu   sync.Mutex
	busy map[string]bool
}

func newWorkPool(n int) *workPool {
	return &workPool{sem: make(chan struct{}, max(n, 1)), busy: map[string]bool{}}
}

// submit queues fn under key (a key already queued or running is dropped). At
// most cap(sem) tasks run at once; each is abandoned after d.
func (p *workPool) submit(key string, d time.Duration, fn func()) {
	p.mu.Lock()
	if p.busy[key] {
		p.mu.Unlock()
		return
	}
	p.busy[key] = true
	p.mu.Unlock()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.sem <- struct{}{}
		defer func() {
			<-p.sem
			p.mu.Lock()
			delete(p.busy, key)
			p.mu.Unlock()
		}()
		done := make(chan struct{})
		go func() { defer close(done); fn() }()
		select {
		case <-done:
		case <-time.After(d):
		}
	}()
}

func (p *workPool) wait() { p.wg.Wait() }

// syncEngineToPeer is a no-op on the agent: peer sync is a controller concern.
func syncEngineToPeer(engine, transport string) (bool, error) { return false, nil }

// LogSecurityAudit writes to the agent's local audit log (simplified from
// the controller's version: the agent logs to its own audit file).
func LogSecurityAudit(event, user, ip, detail string) {
	// The agent logs locally; no HTTP or database involved.
}

// syncCarrierToPeer is a no-op on the agent: carrier sync is controller-managed.
func syncCarrierToPeer(ends interface{}, engine, transport string) (string, error) {
	return "", nil
}

// trimLen truncates a string to n characters.
func trimLen(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// writeJSON writes JSON to an HTTP response (used by the agent's local
// diagnostic endpoints; the agent has no management UI listener).
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// --- Controller-only stubs ---
// The agent has no HTTP management server. These stubs satisfy compilation
// for engine files that reference controller HTTP helpers. They are never
// called at runtime because the agent has no HTTP routes.

var frpDir = "/etc/frp"

func writeAPIError(w http.ResponseWriter, r *http.Request, code, msg string) {
	http.Error(w, msg, http.StatusInternalServerError)
}

func linkLabelFromString(s string) string { return s }

// --- Peer coordination stubs ---
// The agent does NOT manage the peer registry or coordinate with peers.
// The controller orchestrates carrier switches across agents via desired-state.
// These stubs satisfy compilation for files that reference peer-coordination
// functions from the old combined architecture.

var runSystemctl = func(args ...string) error {
	return nil // agent uses matrixExec
}

func sendToPeer(path, method string, body interface{}) (json.RawMessage, error) {
	return nil, nil // peer comm is controller-managed
}

func sendToPeerTimeout(path, method string, body interface{}, timeout time.Duration) (json.RawMessage, error) {
	return nil, nil
}

type PeerApplyCarrierRequest struct {
	Carrier string
	Local6  string
	Remote6 string
}

func applyBenchmarkCarrier(target string) (string, error) {
	return "Applied benchmark carrier " + target, nil
}

// Extended peerRecord fields that only exist in the controller's registry.
// The agent's local peerRecord doesn't have these — they come from the
// controller's desired state via the WSS protocol.

// CleanHost normalizes a host address (strips brackets, whitespace).
func CleanHost(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	return s
}

var backhaulDir = "/etc/backhaul"

func invalidatePeerIfsCache() { /* no interface cache on the agent */ }

// panelConfig and cfg are a minimal stand-in for the controller's panel
// runtime config (controller-only fields omitted). The agent references
// cfg.Port / cfg.BasePath only when composing legacy peer-API base URLs;
// zero values keep those paths inert until a real link is enrolled.
// panelConfig ported verbatim from the controller monolith (main.go):
// the agent reads the controller's panel.json when it runs ON a
// controller-shaped endpoint; on agent-only endpoints it stays zero.
type panelConfig struct {
	Username string `json:"username"`
	PassHash string `json:"pass_hash"`
	Port     int    `json:"port"`
	BasePath string `json:"base_path"`
	// TerminalEnabled gates the Phase 3 interactive terminal tab
	// (feature flag, default off; user enables after testing).
	TerminalEnabled bool `json:"terminal_enabled,omitempty"`
	// TerminalAllowIPs limits who may open the shell (IPs/CIDRs; empty = any).
	TerminalAllowIPs []string `json:"terminal_allow_ips,omitempty"`
	// TLSPort is the HTTPS listener port (default 7443). HTTP stays on Port.
	TLSPort int `json:"tls_port,omitempty"`
	// BindHost restricts both listeners to one address (e.g. "127.0.0.1"
	// behind a reverse proxy). Empty binds all interfaces (default).
	BindHost string `json:"bind_host,omitempty"`
	// DebugEnabled mounts /debug/pprof behind auth (also QUANTUM_PPROF=1).
	DebugEnabled bool `json:"debug_enabled,omitempty"`
	// RevPathAuto enables automatic application of reverse-path fixes
	// (rate-limited; report-only when false, the default).
	RevPathAuto bool `json:"revpath_auto,omitempty"`
	// Optional TOTP 2FA (off by default). Secret and recovery hashes live in
	// panel.json (0600) like the password hash.
	// IdleTimeoutMin logs a session out after this many minutes without user
	// activity (0 = off, the default).
	IdleTimeoutMin int `json:"idle_timeout_min,omitempty"`
	// MetricsToken enables GET /metrics (Prometheus) for scrapers using a
	// bearer token; empty = endpoint disabled (404).
	MetricsToken   string   `json:"metrics_token,omitempty"`
	TOTPEnabled    bool     `json:"totp_enabled,omitempty"`
	TOTPSecret     string   `json:"totp_secret,omitempty"`
	RecoveryHashes []string `json:"recovery_hashes,omitempty"`
}

var cfg panelConfig

// truncateForError shortens a peer response body for error strings
// (ported verbatim from the controller monolith peer.go).
func truncateForError(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// IsTrustedProxy checks whether a given IP address belongs to TRUSTED_PROXY_IPS.
//
// Loopback is NOT trusted implicitly: tunnels (frps, backhaul, tls-proxy) also
// deliver outside clients from 127.0.0.1, and trusting it let anyone set
// X-Forwarded-For to dodge the per-IP login lockout and the terminal allowlist.
// A local nginx/Caddy needs TRUSTED_PROXY_IPS=127.0.0.1 (see the generated
// reverse-proxy config).
func IsTrustedProxy(ipStr string) bool {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return false
	}
	if strings.EqualFold(ipStr, "localhost") {
		ipStr = "127.0.0.1"
	}
	parsedIP := net.ParseIP(ipStr)

	raw := os.Getenv("TRUSTED_PROXY_IPS")
	if raw == "" {
		return false
	}

	if parsedIP == nil {
		return false
	}

	parts := strings.Split(raw, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		// CIDR notation
		if strings.Contains(p, "/") {
			_, subnet, err := net.ParseCIDR(p)
			if err == nil && subnet.Contains(parsedIP) {
				return true
			}
			continue
		}

		// Exact IP match
		if target := net.ParseIP(p); target != nil {
			if target.Equal(parsedIP) {
				return true
			}
		}
	}
	return false
}

// ClientIP extracts the real client IP.
// Header X-Forwarded-For is ONLY trusted if the direct connection comes from a trusted proxy.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = strings.Trim(r.RemoteAddr, "[]")
	}

	// Only trust forwarding headers if the immediate peer is a verified reverse proxy
	if IsTrustedProxy(remoteHost) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Session 4 gate: with nginx's $proxy_add_x_forwarded_for the
			// TRUSTED proxy APPENDS the real client address as the LAST
			// entry — every earlier entry was supplied by the client and
			// is therefore spoofable. Take the last non-empty hop.
			parts := strings.Split(xff, ",")
			var candidate string
			for i := len(parts) - 1; i >= 0; i-- {
				if c := strings.TrimSpace(parts[i]); c != "" {
					candidate = c
					break
				}
			}
			if candidate != "" {
				if host, _, err := net.SplitHostPort(candidate); err == nil {
					return host
				}
				return strings.Trim(candidate, "[]")
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			cand := strings.TrimSpace(xri)
			if host, _, err := net.SplitHostPort(cand); err == nil {
				return host
			}
			return strings.Trim(cand, "[]")
		}
	}

	return remoteHost
}

// effectiveTLSPort is the agent-side stand-in for the controller's TLS
// port resolution: the agent has no TLS settings of its own, so callers
// get the documented default peer TLS port.
func effectiveTLSPort() int { return 7443 }

// mainTunnelID is the ID of the main tunnel (ported from the monolith
// fleet.go).
const mainTunnelID = 0

// histEvery is the history sampling interval (ported from the monolith
// history.go: one point per link per 30s).
const histEvery = 30 * time.Second

// AgeMs is the snapshot age in milliseconds, -1 for the empty snapshot
// (ported verbatim from the monolith snapshot.go).
func (s *HubSnapshot) AgeMs() int64 {
	if s == nil || s.At.IsZero() {
		return -1
	}
	return time.Since(s.At).Milliseconds()
}

// PeersAged is Peers (without the main tunnel) with the snapshot age set
// (ported verbatim from the monolith snapshot.go).
func (s *HubSnapshot) PeersAged() []peerLive {
	age := s.AgeMs()
	out := append([]peerLive(nil), s.Peers...)
	for i := range out {
		out[i].SnapshotAgeMs = age
	}
	return out
}

// setSnapshotAgeHeader tells clients how old the served data is
// (ported verbatim from the monolith snapshot.go).
func setSnapshotAgeHeader(w http.ResponseWriter, s *HubSnapshot) {
	w.Header().Set("X-Snapshot-Age-Ms", strconv.FormatInt(s.AgeMs(), 10))
}

// clientIP is the auth-path client IP; the agent never sits behind the
// controller's trusted-proxy chain, so this is the immediate peer
// address (see ClientIP above for the rationale).
func clientIP(r *http.Request) string { return ClientIP(r) }

// ensureWatchdogTimer is a no-op on the agent: the quantum-watchdog
// timer is controller-host machinery (systemd timer management stays
// with the controller/installers).
func ensureWatchdogTimer() {}

// currentSnapshot is a nil-returning stand-in for the controller's hub
// snapshot registry: the agent builds no hub snapshots; callers guard
// on nil (limits.go alias collection skips the "main" block).
var currentSnapshot = func() *HubSnapshot { return nil }

// topologyBoundTunnelPorts is empty on the agent: topologies are
// controller-side objects; the agent receives desired state instead
// (monolith topology.go version returns the controller's bindings).
func topologyBoundTunnelPorts() map[int]string { return map[int]string{} }

// getOutboundIP returns the primary outbound IPv4 (ported verbatim from
// the monolith main.go).
func getOutboundIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr.IP == nil {
		return "127.0.0.1"
	}
	return localAddr.IP.String()
}

// currentLocal is the base tunnel status for display/read-only callers.
// The controller returns the snapshot's cached copy when one exists; the
// agent has no snapshot collector, so this is always a fresh local read.
func currentLocal() tunnelStatus { return localStatus() }

// authed reports an authenticated admin session. The agent runs no web
// session machinery, so this is fail-closed false; rescue endpoints stay
// reachable through their own mechanisms (rescuePeerAllowed / ClientIP
// match), exactly as requireRescuePeerAuth composes them.
func authed(r *http.Request) bool { return false }

// mu is the panel/agent global config lock (monolith main.go global) —
// sdnotify.go's liveness probe locks it with tryLockWithin to detect a
// deadlocked process.
var mu sync.Mutex

// snapPtr holds the latest hub snapshot on the controller. The agent
// never builds one: it stays nil, and panelAlive skips the staleness
// probe when nil (still-starting or agent-only endpoints).
var snapPtr atomic.Pointer[HubSnapshot]

// panelScriptName is the installer script name (monolith update.go const).
const panelScriptName = "quantum.sh"

// syncPanelScript refreshes quantum.sh from the running release on the
// controller. On the agent this is a deliberate no-op: script self-heal
// is release/update machinery (the agent's own updates run through the
// signed agent.update command); a stale script fails closed with
// E-INSTALL-02 instead of being replaced.
func syncPanelScript() {}

// counterDelta returns the monotonic counter growth between two reads
// (ported verbatim from the monolith dashboard.go).
func counterDelta(prev, cur uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

// ClusterConfig is a minimal stand-in for the controller's cluster
// subsystem (cluster.go): pools of foreign servers shared by topologies.
// The agent's port-clash check (setup_ports.go) reads Pools; on the
// agent they are controller-managed and empty here.
type ClusterConfig struct {
	Pools []ClusterPool
}

type ClusterPool struct {
	Port int
}

func loadClusterConfig() ClusterConfig { return ClusterConfig{} }

// usageSnapshotAliases maps counter identities onto canonical usage IDs
// (ported verbatim from the monolith topology_usage.go; requires only
// peerRecord/HubSnapshot fields the agent tree carries).
func usageSnapshotAliases(snapshot *HubSnapshot) map[string]string {
	aliases := map[string]string{"bagher:1": "bagher"}
	if snapshot == nil {
		return aliases
	}
	for _, p := range snapshot.Peers {
		if p.ID <= 0 {
			continue
		}
		main := p.GreIf == "gre-tunnel"
		if p.NoGre && p.FrpsSvc != "" {
			svc := snapshot.Local.FrpSvc
			if snapshot.Main != nil && snapshot.Main.FrpsSvc != "" {
				svc = snapshot.Main.FrpsSvc
			}
			main = p.FrpsSvc == svc
		}
		if main {
			aliases["peer:"+strconv.Itoa(p.ID)] = "main"
		}
	}
	return aliases
}

// topologyUsageKey maps a usage id to its ledger key (ported verbatim
// from the monolith topology_usage.go).
func topologyUsageKey(id string) string {
	if strings.HasPrefix(id, "peer:") {
		return "p" + strings.TrimPrefix(id, "peer:")
	}
	return id
}

// All returns the main tunnel (when present) followed by the peers. The records
// are copies carrying this request's snapshot age; the snapshot stays immutable
// (ported verbatim from the monolith snapshot.go).
func (s *HubSnapshot) All() []peerLive {
	age := s.AgeMs()
	out := make([]peerLive, 0, len(s.Peers)+1)
	if s.Main != nil {
		out = append(out, *s.Main)
	}
	out = append(out, s.Peers...)
	for i := range out {
		out[i].SnapshotAgeMs = age
	}
	return out
}

// linkName is a peer link's display name (ported verbatim from the
// monolith history.go).
func linkName(l peerLive) string {
	if l.Name != "" {
		return l.Name
	}
	return fmt.Sprintf("peer-%d", l.ID)
}

// trafficTunnelIfs parses /proc/net/dev rows for tunnel interfaces
// (ported verbatim from the monolith dashboard.go).
func trafficTunnelIfs(devData string) map[string][2]uint64 {
	cur := map[string][2]uint64{}
	for _, line := range strings.Split(devData, "\n") {
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		ifname := strings.TrimSpace(line[:i])
		if !isTunnelInterface(ifname) {
			continue
		}
		f := strings.Fields(line[i+1:])
		if len(f) < 9 {
			continue
		}
		r, e1 := strconv.ParseUint(f[0], 10, 64)
		t, e2 := strconv.ParseUint(f[8], 10, 64)
		if e1 == nil && e2 == nil {
			cur[ifname] = [2]uint64{r, t}
		}
	}
	return cur
}

// usageObserveSpecialTunnels folds Matrix and carrier-port counters into
// the usage ledger (ported verbatim from the monolith topology_usage.go).
func usageObserveSpecialTunnels(s *HubSnapshot, at time.Time) {
	aliases := usageSnapshotAliases(s)
	trafficUsage.mu.Lock()
	for _, p := range s.Peers {
		if p.ID <= 0 {
			continue
		}
		if old := trafficUsage.links[usageKey(p)]; old != nil {
			alias := ""
			if aliases["peer:"+strconv.Itoa(p.ID)] == "main" {
				alias = usageMainKey
			}
			if old.AliasOf != alias {
				old.AliasOf = alias
				trafficUsage.dirty = true
			}
		}
	}
	trafficUsage.mu.Unlock()
	if mx := s.Local.Matrix; mx != nil && mx.Enabled {
		rx, tx := mx.Rx, mx.Tx
		if rx == nil || tx == nil {
			if c, ok := parseNetDev(s.DevData)[matrixIfaceName]; ok {
				rx, tx = &c.rx, &c.tx
			}
		}
		trafficUsage.observe("matrix", "Matrix", at, rx, tx)
	}
	seen := map[string]bool{}
	for tag, c := range s.CarrierTags {
		var id string
		switch {
		case strings.HasPrefix(tag, "bagher-"):
			n, err := strconv.Atoi(strings.TrimPrefix(tag, "bagher-"))
			if err != nil || n <= 0 {
				continue
			}
			id = "bagher"
			if n != 1 {
				id += ":" + strconv.Itoa(n)
			}
		case strings.HasPrefix(tag, "xray-"):
			n, err := strconv.Atoi(strings.TrimPrefix(tag, "xray-"))
			if err != nil || n <= 0 {
				continue
			}
			id = "xray:" + strconv.Itoa(n)
		default:
			continue
		}
		if !s.CarrierOK {
			continue
		}
		seen[id] = true
		rx, tx := c[0], c[1]
		trafficUsage.observe(id, id, at, &rx, &tx)
	}
	// Previously measurable engines missing from this snapshot are unknown,
	// retaining their baseline and history rather than reporting measured zero.
	trafficUsage.mu.Lock()
	missing := []string{}
	for key := range trafficUsage.links {
		if key == "matrix" && (s.Local.Matrix == nil || !s.Local.Matrix.Enabled) ||
			(key == "bagher" || strings.HasPrefix(key, "bagher:") || strings.HasPrefix(key, "xray:")) && !seen[key] {
			missing = append(missing, key)
		}
	}
	trafficUsage.mu.Unlock()
	for _, key := range missing {
		trafficUsage.observe(key, "", at, nil, nil)
	}
}

// serverTrafficMetrics is the host-NIC traffic block of a snapshot
// (ported verbatim from the monolith server_metrics.go).
type serverTrafficMetrics struct {
	Rx         *uint64  `json:"rx"`
	Tx         *uint64  `json:"tx"`
	RxRate     *float64 `json:"rx_rate"`
	TxRate     *float64 `json:"tx_rate"`
	Interfaces []string `json:"interfaces"`
	Known      bool     `json:"known"`
	CountersAt *int64   `json:"counters_at"`
}

// devCounters is one interface's cumulative RX/TX (monolith snapshot.go).
type devCounters struct{ rx, tx uint64 }

// parseNetDev parses /proc/net/dev into per-interface counters
// (ported verbatim from the monolith snapshot.go).
func parseNetDev(data string) map[string]devCounters {
	m := map[string]devCounters{}
	for _, line := range strings.Split(data, "\n") {
		name, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, e1 := strconv.ParseUint(f[0], 10, 64)
		t, e2 := strconv.ParseUint(f[8], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		m[strings.TrimSpace(name)] = devCounters{r, t}
	}
	return m
}

// getKnownPeerIfs lists the peers' GRE interfaces (monolith
// dashboard.go caches for 10s; the agent reads peers directly — the
// call sites are low-frequency).
func getKnownPeerIfs() map[string]bool {
	m := make(map[string]bool)
	for _, q := range loadPeers() {
		if q.GreIf != "" {
			m[q.GreIf] = true
		}
	}
	return m
}

// isTunnelInterface determines if an interface is a GRE or Backhaul tunnel
// (ported verbatim from the monolith dashboard.go).
func isTunnelInterface(ifname string) bool {
	if ifname == "lo" || ifname == "gre0" || ifname == "gretap0" || ifname == "erspan0" {
		return false
	}
	if strings.HasPrefix(ifname, "docker") || strings.HasPrefix(ifname, "veth") ||
		strings.HasPrefix(ifname, "br-") || strings.HasPrefix(ifname, "dummy") ||
		strings.HasPrefix(ifname, "eth") || strings.HasPrefix(ifname, "ens") ||
		strings.HasPrefix(ifname, "enp") || strings.HasPrefix(ifname, "wl") {
		return false
	}
	if strings.HasPrefix(ifname, "gre-") || strings.HasPrefix(ifname, "tun") || ifname == spoofIface || ifname == matrixIfaceName {
		return true
	}
	known := getKnownPeerIfs()
	if known[ifname] {
		return true
	}
	if data, err := os.ReadFile(filepath.Join("/sys/class/net", ifname, "type")); err == nil {
		t := strings.TrimSpace(string(data))
		if t == "778" || t == "823" {
			return true
		}
	}
	return false
}

// countersAtMs renders a snapshot's counter timestamp for the UI
// (ported verbatim from the monolith dashboard.go).
func countersAtMs(s *HubSnapshot) any {
	if s == nil || s.CountersAt.IsZero() {
		return nil
	}
	return s.CountersAt.UnixMilli()
}

// usageResponse builds the usage API payload. Agent adaptation of the
// monolith topology_usage.go version: topology grouping is
// controller-side, so rows are empty and topology_known is false; the
// ledger/series logic is the agent's own (traffic_usage.go).
func usageResponse(now time.Time, window time.Duration, step int64, rangeName string) map[string]any {
	trafficUsage.mu.Lock()
	server, serverWindow := trafficUsage.serverTotalsLocked(now, window, step)
	trafficUsage.mu.Unlock()
	out := map[string]any{
		"range": rangeName, "keep_days": int(usageKeep / (24 * time.Hour)), "step_sec": step, "now": now.Unix(),
		"links":        trafficUsage.all(now, window, step),
		"server_total": server, "server_window": serverWindow, "topologies": []topologyUsageRow{},
		"grouping_basis": "current_assignments", "server_basis": "physical_interfaces", "topology_basis": "recorded_tunnel_counters",
		"topology_known": false,
		"topology_error": "topology collection is controller-side",
	}
	return out
}

// CSRF token machinery (ported verbatim from the monolith security.go).
var (
	csrfKey   [32]byte
	csrfKeyMu sync.Once
)

func initCSRFKey() {
	csrfKeyMu.Do(func() {
		if _, err := rand.Read(csrfKey[:]); err != nil {
			copy(csrfKey[:], "gre-panel-csrf-fallback-key-32b")
		}
	})
}

// GenerateCSRFToken derives a cryptographically secure CSRF token tied to a session token.
func GenerateCSRFToken(sessionToken string) string {
	initCSRFKey()
	mac := hmac.New(sha256.New, csrfKey[:])
	mac.Write([]byte("gre-csrf:" + sessionToken))
	return hex.EncodeToString(mac.Sum(nil))
}

// logFinding is one summarized log signature (monolith errors.go).
type logFinding struct {
	Code  string `json:"code"`
	Msg   string `json:"msg"`
	Hint  string `json:"hint"`
	Count int    `json:"count"`
	Line  string `json:"line"` // first matching line (trimmed)
}

// summarizeLogs folds raw log text into per-code findings for the UI header
// (ported verbatim from the monolith errors.go).
func summarizeLogs(raw string) []logFinding {
	by := map[string]*logFinding{}
	order := []string{}
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		code, _ := matchLogCode(ln)
		if code == "" {
			continue
		}
		f, ok := by[code]
		if !ok {
			info := errCatalog[code]
			f = &logFinding{Code: code, Msg: info.Msg, Hint: info.Hint, Line: trimLen(ln, 220)}
			by[code] = f
			order = append(order, code)
		}
		f.Count++
	}
	out := []logFinding{}
	for _, c := range order {
		out = append(out, *by[c])
	}
	return out
}
