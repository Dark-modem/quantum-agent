package agent

// Legacy Xray tunnel state + the live carrier-accounting view.
//
// REFACTOR-PLAN-AGENT §6.A3: the legacy Xray Tunnel implementation (37/41
// funcs — deadcode-RTA-unreachable from main: bundle make/parse/import, the
// apply/rollback engine, the systemd unit management, the health prober, the
// dashboard views and handlers) is deleted; xray_driver.go is the LIVE Xray
// engine and was never touched by this stage. What survives is what the
// reachable graph uses:
//
//   - the link state store (loadXrayState/saveXrayState/writeFileAtomic):
//     xrayCarrierEnds reads it for the QUANTUM_ACCT_* carrier accounting
//     (acct.go), and the surviving carrier-ends test writes it as a fixture;
//   - xrayCarrierEnds itself (carrier_traffic.go's xray leg);
//   - the core version/install seam (xrayVersion/xrayInstallCmd/startXrayInstall);
//   - the health-probe seams (xrayProbe/xrayTCPPing/xrayConns) and the SNI
//     tester seam (xraySNIDial) — prod-unreachable after the purge but
//     kept verbatim (test suites and a future re-arm compile against them).
//
// xrayTag survives: xrayCarrierEnds tags the carrier ends with it, and the
// carrier-ends test asserts the exact tags.

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

var xrayMu sync.Mutex

// xrayState is every Xray link on this server. Link IDs are never reused, so
// an old unit name never points at a new link.
type xrayState struct {
	Links  []XrayLink `json:"links"`
	NextID int        `json:"next_id"`
	// PublicIP is this server's address as the bundles carry it.
	PublicIP string `json:"public_ip,omitempty"`
}

func xrayStatePath() string { return filepath.Join(infra.ConfigDir, "xray.json") }
func xrayTag(id int) string { return fmt.Sprintf("xray-%d", id) }

func loadXrayState() xrayState {
	var s xrayState
	if data, err := os.ReadFile(xrayStatePath()); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	for _, l := range s.Links {
		if l.ID >= s.NextID {
			s.NextID = l.ID + 1
		}
	}
	if s.NextID < 1 {
		s.NextID = 1
	}
	return s
}

// saveXrayState writes the link state. §6.A3 note: prod-unreachable (the
// legacy handlers that saved it are deleted); TestXrayCarrierEnds uses it to
// persist the fixture state for xrayCarrierEnds.
func saveXrayState(s xrayState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(xrayStatePath(), data, 0o600)
}

// writeFileAtomic writes through a temp file and a rename, so a crash never
// leaves half a config.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func xrayCarrierEnds() []carrierEnd {
	var ends []carrierEnd
	for _, l := range loadXrayState().Links {
		if l.Disabled {
			continue
		}
		udp := l.Profile.Transport == "kcp"
		ip := infra.CarrierIP(xrayDialAddress(l))
		if l.serverEnd() {
			// listening: count only the other server, when its address is known
			from := ""
			if l.Remote != "" && !l.Profile.CDN { // through a CDN they come from its addresses
				from = infra.CarrierIP(l.Remote)
			}
			ends = append(ends, carrierEnd{Port: l.TunnelPort, From: from, UDP: udp, Tag: xrayTag(l.ID)})
		} else if ip != "" {
			ends = append(ends, carrierEnd{Port: l.TunnelPort, Remote: ip, UDP: udp, Tag: xrayTag(l.ID)})
		}
	}
	return ends
}

// ---- core: version and install ----

var xrayVersionCache = struct {
	sync.Mutex
	mod time.Time
	v   string
}{}

// xrayVersion is the installed core's version line ("Xray 26.3.27 ...").
func xrayVersion() string {
	st, err := os.Stat(xrayBinPath)
	if err != nil {
		return ""
	}
	xrayVersionCache.Lock()
	defer xrayVersionCache.Unlock()
	if st.ModTime().Equal(xrayVersionCache.mod) && xrayVersionCache.v != "" {
		return xrayVersionCache.v
	}
	out, err := infra.RunCmdTimeoutOut(10*time.Second, xrayBinPath, "version")
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if f := strings.Fields(line); len(f) >= 2 {
		line = f[0] + " " + f[1]
	}
	xrayVersionCache.mod, xrayVersionCache.v = st.ModTime(), line
	return line
}

var xrayInstall = struct {
	sync.Mutex
	Running bool
	Done    bool
	OK      bool
	Log     string
}{}

// xrayInstallCmd installs the pinned core through quantum.sh; swappable for tests.
var xrayInstallCmd = func() (string, error) { return runQuantumCluster(15*time.Minute, "xray", "install") }

// startXrayInstall runs the install in the background; GET /api/xray shows it.
func startXrayInstall() bool {
	xrayInstall.Lock()
	defer xrayInstall.Unlock()
	if xrayInstall.Running {
		return false
	}
	xrayInstall.Running, xrayInstall.Done, xrayInstall.OK, xrayInstall.Log = true, false, false, ""
	go func() {
		out, err := xrayInstallCmd()
		xrayInstall.Lock()
		defer xrayInstall.Unlock()
		if len(out) > 4000 {
			out = out[len(out)-4000:]
		}
		xrayInstall.Running, xrayInstall.Done, xrayInstall.Log = false, true, out
		xrayInstall.OK = err == nil && infra.FileExists(xrayBinPath)
		if err != nil && out == "" {
			xrayInstall.Log = err.Error()
		}
	}()
	return true
}

// ---- health-probe seams ----
// §6.A3 note: xrayCheckHealth (their only consumer) is deleted; the seams
// stay verbatim for the tests and a future re-arm.

var xrayProbe = func(port int) (float64, error) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return 0, fmt.Errorf("the probe port is closed: is the link's Xray running?")
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+xrayProbeHost+"\r\n\r\n"); err != nil {
		return 0, err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("no answer from the other end through the link")
	}
	if !strings.HasPrefix(line, "HTTP/1.1 403") {
		return 0, fmt.Errorf("unexpected answer through the link")
	}
	return float64(time.Since(start).Microseconds()) / 1000, nil
}

// xrayTCPPing is one TCP handshake to host:port: the network's round trip.
var xrayTCPPing = func(host string, port int) (float64, error) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return 0, err
	}
	c.Close()
	return float64(time.Since(start).Microseconds()) / 1000, nil
}

// xrayConns counts the tunnel's open TCP connections: to the other server's
// tunnel port on the dialing end, on our tunnel port on the listening end.
var xrayConns = func(l XrayLink) int {
	filter := fmt.Sprintf("( sport = :%d )", l.TunnelPort)
	if !l.serverEnd() {
		// only to the other server: other programs dial port 443 too
		filter = fmt.Sprintf("( dport = :%d )", l.TunnelPort)
		if ip := infra.CarrierIP(xrayDialAddress(l)); ip != "" {
			filter = fmt.Sprintf("( dport = :%d and dst %s )", l.TunnelPort, infra.URLHost(ip))
		}
	}
	out, err := infra.RunCmdTimeoutOut(3*time.Second, "ss", "-Htn", "state", "established", filter)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// ---- SNI tester ----

// xraySNIResult says whether a site can lend Reality its handshake: TLS 1.3
// with h2, reached from this server.
type xraySNIResult struct {
	SNI   string  `json:"sni"`
	OK    bool    `json:"ok"`
	TLS13 bool    `json:"tls13"`
	H2    bool    `json:"h2"`
	MS    float64 `json:"ms,omitempty"`
	Error string  `json:"error,omitempty"`
}

// xraySNIDial measures one candidate site's TLS handshake. §6.A3 note: kept
// verbatim (seam); xrayTestSNIs — the legacy dashboard batch tester — is
// deleted with it.
var xraySNIDial = func(sni string) xraySNIResult {
	r := xraySNIResult{SNI: sni}
	start := time.Now()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", net.JoinHostPort(sni, "443"),
		&tls.Config{ServerName: sni, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12})
	if err != nil {
		r.Error = err.Error()
		if len(r.Error) > 160 {
			r.Error = r.Error[:160]
		}
		return r
	}
	st := c.ConnectionState()
	c.Close()
	r.MS = float64(time.Since(start).Microseconds()) / 1000
	r.TLS13, r.H2 = st.Version == tls.VersionTLS13, st.NegotiatedProtocol == "h2"
	r.OK = r.TLS13 && r.H2
	if !r.OK {
		r.Error = "needs TLS 1.3 and h2"
	}
	return r
}
