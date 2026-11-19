package agent

// Carrier swap: change how one tunnel travels (its engine and transport) on
// both of its servers, started from the Iran side.
//
//  1. The foreign server is told first, over the peer API: the main tunnel's
//     Peer Link, or the peer's own token for every other tunnel. It accepts,
//     answers at once and switches a moment later, so the answer is never lost
//     to its own switch.
//  2. This server switches the tunnel's units (with the engine switch's
//     rollback when a unit does not come up).
//  3. The swap only counts once the tunnel's control session is back. When it
//     is not back within swapVerifyWait, both servers are put back on the old
//     carrier, so a carrier the network blocks cannot strand the tunnel.
//
// When the foreign panel cannot be reached the admin may still swap this side
// alone ("manual"): the answer carries the new bundle for the foreign server.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// carrierChoice is one way a tunnel can travel: "frp:kcp", "backhaul:tcpmux",
// "gre-backhaul:wssmux", ...
type carrierChoice struct {
	Engine    string `json:"engine"`
	Transport string `json:"transport"`
}

// ID is the choice's carrier id ("frp:tcp", "wss:8443", …). §6.A3 note:
// prod-unreachable (the legacy peer-swap handlers are deleted);
// TestPeerCarrierFromRecord still asserts it.
func (c carrierChoice) ID() string { return c.Engine + ":" + c.Transport }

// swapTunnel is everything a swap needs to know about one tunnel.
type swapTunnel struct {
	ID        int           `json:"id"`
	Name      string        `json:"name"`
	Main      bool          `json:"main"`
	Current   carrierChoice `json:"current"`
	GreOK     bool          `json:"gre_ok"` // GRE carriers are possible (the tunnel has GRE addresses and a GRE unit)
	Port      int           `json:"port"`
	RemotePub string        `json:"remote_pub"`
	Ports     []int         `json:"-"`
	Raw       []string      `json:"-"`
	LocalPub  string        `json:"-"`
	LocalGre  string        `json:"-"`
	PeerGre   string        `json:"-"`
	Token     string        `json:"-"`
	rec       *peerRecord
}

var errSwapForeign = errors.New("swap the carrier from the Iran server: it switches this server too")

var perPeerUnitRe = regexp.MustCompile(`^(?:frps|backhaul-server)-(\d+)$`)

// isMainUnit: the base tunnel's own units (peers have frps-N / backhaul-server-N).
// resolveSwapTunnel finds tunnel id: 0 is the base tunnel, N a peers.json record.
// peerCarrier is the carrier a peers.json record runs on.
func peerCarrier(p peerRecord) carrierChoice {
	eng := strings.ToLower(p.Engine)
	if eng == "" {
		eng = "frp"
		if strings.HasPrefix(p.FrpsSvc, "backhaul") {
			eng = "gre-backhaul"
			if p.NoGre {
				eng = "backhaul"
			}
		}
	}
	if eng == "frp" {
		t := strings.ToLower(p.FRPTransport)
		if !frpProtocolOK(t) {
			t = "tcp"
		}
		return carrierChoice{Engine: eng, Transport: t}
	}
	t := strings.ToLower(p.Transport)
	if !backhaulTransportOK(t) {
		t = "tcpmux"
	}
	return carrierChoice{Engine: eng, Transport: t}
}

// mainFRPProtocol is the FRP client protocol of the base tunnel as far as the
// Iran side knows it: the last swap, the record, the carrier setting.
// mainCarrierID is the base tunnel's carrier for /api/status (file reads only).
func recordRawPorts(p peerRecord) []string {
	if len(p.RawPorts) > 0 {
		return append([]string(nil), p.RawPorts...)
	}
	var out []string
	for _, n := range p.Ports {
		out = append(out, strconv.Itoa(n))
	}
	return out
}

type setupMeta struct {
	LocalPub   string `json:"local_public"`
	RemotePub  string `json:"remote_public"`
	Token      string `json:"token"`
	IranGre    string `json:"iran_gre"`
	ForeignGre string `json:"foreign_gre"`
	Ports      string `json:"ports"`
}

// ---- swap state: the carrier each tunnel was last swapped to ----

// ---- this server's half ----

// swapLocalFn switches this server's side of a tunnel; a var for tests.
var swapLocalFn = swapLocal

func swapLocal(t swapTunnel, to carrierChoice) (string, error) {
	if to.needsGRE() && !t.GreOK {
		return "", fmt.Errorf("%s needs GRE, and this tunnel was set up without it", carrierLabel(to))
	}
	if t.Main {
		out, err := switchTunnelEngineWith(to.Engine, to.Transport, engineOpts{Ports: t.Ports, Raw: t.Raw})
		if err != nil {
			return out, err
		}
		if t.rec != nil {
			updatePeerRecord(t.rec.ID, func(p *peerRecord) { recordCarrier(p, to, mainUnitFor(to)) })
		}
		openCarrierFirewall(t.Port, to)
		return out, nil
	}
	return switchPeerCarrier(*t.rec, to)
}

func mainUnitFor(to carrierChoice) string {
	if to.Engine == "frp" {
		return "frps"
	}
	return "backhaul-server"
}

func recordCarrier(p *peerRecord, to carrierChoice, svc string) {
	p.Engine, p.FrpsSvc = to.Engine, svc
	p.NoGre = to.Engine == "backhaul"
	if to.Engine == "frp" {
		p.FRPTransport, p.Transport = to.Transport, ""
		if to.Transport == "tcp" {
			p.FRPTransport = ""
		}
	} else {
		p.Transport, p.FRPTransport = to.Transport, ""
	}
}

// openCarrierFirewall opens the control port for the new carrier: UDP too
// (kcp, quic, Backhaul udp), and quic's port+1.
func openCarrierFirewall(port int, to carrierChoice) {
	if port <= 0 {
		return
	}
	ports := []int{port}
	if to.Engine == "frp" && to.Transport == "quic" {
		q := port + 1
		if q > 65535 {
			q = port - 1
		}
		ports = append(ports, q)
	}
	allowUFWPorts(ports)
}

// updatePeerRecord rewrites one peers.json record.
func updatePeerRecord(id int, fn func(p *peerRecord)) error {
	data, err := os.ReadFile(peersFile())
	if err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	var peers []peerRecord
	if raw, ok := doc["peers"]; ok {
		if err := json.Unmarshal(raw, &peers); err != nil {
			return err
		}
	}
	found := false
	for i := range peers {
		if peers[i].ID == id {
			fn(&peers[i])
			found = true
		}
	}
	if !found {
		return fmt.Errorf("peer %d not found", id)
	}
	raw, err := json.Marshal(peers)
	if err != nil {
		return err
	}
	doc["peers"] = raw
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := writeTokenFile(peersFile(), append(out, '\n')); err != nil {
		return err
	}
	invalidatePeerIfsCache()
	return nil
}

func engineBinaryPath(name string) string {
	for _, d := range engineBinDirs {
		if p := filepath.Join(d, name); executableFile(p) {
			return p
		}
	}
	if name == "backhaul" {
		for _, p := range backhaulExtraBins {
			if executableFile(p) {
				return p
			}
		}
	}
	return filepath.Join("/usr/local/bin", name)
}

// switchPeerCarrier moves peer p (frps-N or backhaul-server-N) onto another
// carrier: the new unit and config are written, the old engine's unit and
// config are removed once the new one runs, and any failure puts the old
// ones back.
func switchPeerCarrier(p peerRecord, to carrierChoice) (string, error) {
	cur := peerCarrier(p)
	id := p.ID
	frpSvc, bhSvc := fmt.Sprintf("frps-%d", id), fmt.Sprintf("backhaul-server-%d", id)
	newSvc := frpSvc
	if to.Engine != "frp" {
		newSvc = bhSvc
	}
	oldSvc := p.FrpsSvc
	if oldSvc == "" {
		oldSvc = frpSvc
		if cur.Engine != "frp" {
			oldSvc = bhSvc
		}
	}
	bin := "frps"
	if to.Engine != "frp" {
		bin = "backhaul"
	}
	if !engineBinaryPresent(bin) {
		return "", fmt.Errorf("%s binary not found (install it with `quantum` first); nothing was changed", bin)
	}
	token := p.Token
	if token == "" {
		return "", fmt.Errorf("tunnel %d has no token in peers.json; nothing was changed", id)
	}
	if p.FrpPort <= 0 {
		return "", fmt.Errorf("tunnel %d has no control port; nothing was changed", id)
	}
	greIf := p.GreIf
	if greIf == "" || greIf == "none" {
		greIf = fmt.Sprintf("gre-t%d", id)
	}
	udpSvc := backhaulUDPUnit(bhSvc)
	tx := newUnitSwitchTx([]string{greIf, frpSvc, bhSvc, udpSvc})

	var out strings.Builder
	fmt.Fprintf(&out, "Switching tunnel %d to %s...\n", id, carrierLabel(to))
	_ = runSystemctl("stop", oldSvc)
	if newSvc != oldSvc {
		_ = runSystemctl("stop", newSvc)
	}
	if to.needsGRE() {
		if err := runSystemctl("start", greIf+".service"); err != nil {
			return out.String(), tx.rollback(fmt.Errorf("start %s: %w", greIf, err))
		}
	}

	unitPath := filepath.Join(engineUnitDir, newSvc+".service")
	tx.backup(unitPath)
	after := ""
	if to.needsGRE() {
		after = " " + greIf + ".service"
	}
	switch to.Engine {
	case "frp":
		conf := filepath.Join(frpDir, frpSvc+".toml")
		tx.backup(conf)
		if err := writeEngineFile(frpDir, frpSvc+".toml", frpsServerToml(p.FrpPort, token)); err != nil {
			return out.String(), tx.rollback(err)
		}
		if err := writeUnitFile(unitPath, engineUnit("FRP Server Service (peer "+strconv.Itoa(id)+")", after,
			engineBinaryPath("frps")+" -c "+conf)); err != nil {
			return out.String(), tx.rollback(err)
		}
	default:
		conf := filepath.Join(backhaulDir, fmt.Sprintf("server-%d.toml", id))
		tx.backup(conf)
		raw := recordRawPorts(p)
		if err := writeBackhaulServerConfig(conf, fmt.Sprintf("0.0.0.0:%d", p.FrpPort), to.Transport, token, raw); err != nil {
			return out.String(), tx.rollback(fmt.Errorf("write backhaul config: %w", err))
		}
		if err := writeUnitFile(unitPath, engineUnit("Backhaul Server Tunnel ("+bhSvc+")", after,
			engineBinaryPath("backhaul")+" -c "+conf)); err != nil {
			return out.String(), tx.rollback(err)
		}
	}
	_ = runSystemctl("daemon-reload")
	if err := tx.start(newSvc); err != nil {
		return out.String(), tx.rollback(err)
	}
	fmt.Fprintf(&out, "%s configured and started.\n", newSvc)

	// The old engine goes away for good, so it does not grab the control
	// port at the next boot. Its files stay in tx until the swap is done.
	if newSvc != oldSvc {
		_ = runSystemctl("disable", oldSvc)
		oldConf := filepath.Join(frpDir, frpSvc+".toml")
		if cur.Engine != "frp" {
			oldConf = filepath.Join(backhaulDir, fmt.Sprintf("server-%d.toml", id))
			_ = runSystemctl("disable", "--now", udpSvc)
			for _, f := range []string{filepath.Join(engineUnitDir, udpSvc+".service"), filepath.Join(backhaulDir, "udp", bhSvc+".toml")} {
				tx.backup(f)
				_ = os.Remove(f)
			}
		}
		for _, f := range []string{filepath.Join(engineUnitDir, oldSvc+".service"), oldConf} {
			tx.backup(f)
			_ = os.Remove(f)
		}
		_ = runSystemctl("daemon-reload")
	}
	if err := updatePeerRecord(id, func(r *peerRecord) {
		recordCarrier(r, to, newSvc)
		if r.GreIf == "" || r.GreIf == "none" {
			if to.needsGRE() {
				r.GreIf = greIf
			}
		}
	}); err != nil {
		return out.String(), tx.rollback(fmt.Errorf("update peers.json: %w", err))
	}
	openCarrierFirewall(p.FrpPort, to)
	return out.String(), nil
}

// frpsServerToml is the frps config quantum.sh peer_write_frps writes.
func frpsServerToml(port int, token string) string {
	_, maxPool := effectivePoolValues()
	quic := port + 1
	if quic > 65535 {
		quic = port - 1
	}
	return fmt.Sprintf(`bindAddr = "0.0.0.0"
bindPort = %d
kcpBindPort = %d
quicBindPort = %d
auth.method = "token"
auth.token = %q
%stransport.tcpKeepalive = 15
transport.heartbeatTimeout = 45
transport.maxPoolCount = %d
`, port, port, quic, token, tcpMuxTomlLines(), maxPool)
}

func engineUnit(desc, after, exec string) string {
	return fmt.Sprintf(`[Unit]
Description=%s
After=network.target network-online.target%s
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=%s
Restart=always
RestartSec=3s
LimitNOFILE=1048576
LimitNPROC=512000
TasksMax=infinity
CPUWeight=100

[Install]
WantedBy=multi-user.target
`, desc, after, exec)
}

func writeUnitFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// newUnitSwitchTx is newEngineSwitchTx for a given unit list (the first one is
// the GRE unit, which a rollback leaves running).
func newUnitSwitchTx(svcs []string) *engineSwitchTx {
	tx := &engineSwitchTx{wasActive: map[string]bool{}, files: map[string][]byte{}, svcs: svcs}
	for _, s := range svcs {
		tx.wasActive[s] = engineServiceActive(s)
	}
	return tx
}

// isMainUnit reports whether the unit is the main tunnel's (not a per-peer
// frps/backhaul-server-N). §6.A3: held for tunnel.go (out of this stage's
// named scope).
func isMainUnit(svc string) bool {
	switch svc {
	case "frps", "frpc", "backhaul-server", "backhaul-client":
		return true
	}
	return false
}

// needsGRE reports whether the choice runs behind a GRE interface on both
// ends (frp and gre-backhaul do; wss/xray dial directly).
func (c carrierChoice) needsGRE() bool { return c.Engine == "frp" || c.Engine == "gre-backhaul" }

// swapStatePath is the peer-swap state file. §6.A3: held for loadSwapState
// (tunnel.go — out of this stage's named scope — compiles against the chain).
func swapStatePath() string { return filepath.Join(configDir, "carrier_swap.json") }

// loadSwapState reads the per-tunnel carrier the peer swap last applied.
// §6.A3: prod-unreachable (the legacy peer-swap handlers are deleted);
// mainFRPProtocol above (held for tunnel.go) still reads it.
func loadSwapState() map[int]string {
	swapStateMu.Lock()
	defer swapStateMu.Unlock()
	m := map[int]string{}
	if data, err := os.ReadFile(swapStatePath()); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

// mainFRPProtocol is the main tunnel's frp transport. §6.A3: held for
// tunnel.go (out of this stage's named scope).
func mainFRPProtocol(legacy *peerRecord) string {
	if c := loadSwapState()[0]; strings.HasPrefix(c, "frp:") && frpProtocolOK(strings.TrimPrefix(c, "frp:")) {
		return strings.TrimPrefix(c, "frp:")
	}
	if legacy != nil && frpProtocolOK(legacy.FRPTransport) {
		return legacy.FRPTransport
	}
	if a := loadCarrierConfig().ActiveCarrier; strings.HasPrefix(a, "frp:") {
		if p := strings.TrimPrefix(a, "frp:"); frpProtocolOK(p) {
			return p
		} else if p == "ws" {
			return "websocket"
		}
	}
	return "tcp"
}

// mainCarrierID is the main tunnel's carrier id ("" when it is not one of
// ours). §6.A3: held for tunnel.go (out of this stage's named scope).
func mainCarrierID(st tunnelStatus) string {
	if !isMainUnit(st.FrpSvc) || st.Engine == "" {
		return ""
	}
	if st.Engine != "frp" {
		t := st.Transport
		if !backhaulTransportOK(t) {
			t = "tcpmux"
		}
		return st.Engine + ":" + t
	}
	if st.FrpSvc == "frpc" { // the foreign side knows its own protocol
		if data, err := os.ReadFile(filepath.Join(frpDir, "frpc.toml")); err == nil {
			for _, l := range strings.Split(string(data), "\n") {
				if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && strings.TrimSpace(k) == "transport.protocol" {
					if p := strings.Trim(strings.TrimSpace(v), `"'`); frpProtocolOK(p) {
						return "frp:" + p
					}
				}
			}
		}
		return "frp:tcp"
	}
	var legacy *peerRecord
	for _, p := range loadPeers() {
		if p.Legacy {
			c := p
			legacy = &c
			break
		}
	}
	return "frp:" + mainFRPProtocol(legacy)
}

func carrierLabel(c carrierChoice) string {
	switch c.Engine {
	case "frp":
		return "GRE + FRP (" + c.Transport + ")"
	case "gre-backhaul":
		return "Backhaul over GRE (" + c.Transport + ")"
	}
	return "Backhaul (" + c.Transport + ")"
}

// ---- the foreign server's half ----

// peerSwapRequest asks a foreign server to move its tunnel to a carrier.
type peerSwapRequest struct {
	Engine    string   `json:"engine"`
	Transport string   `json:"transport"`
	Port      int      `json:"port,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
	Raw       []string `json:"raw,omitempty"`
	Remote    string   `json:"remote,omitempty"`   // the Iran server's public address
	PeerGre   string   `json:"peer_gre,omitempty"` // the Iran server's GRE inner address
	DelayMs   int      `json:"delay_ms,omitempty"`
}

type foreignSwapState struct {
	State   string `json:"state"` // "", "switching", "ok", "failed"
	Carrier string `json:"carrier,omitempty"`
	Error   string `json:"error,omitempty"`
	At      string `json:"at,omitempty"`
	Seq     int    `json:"seq"`
}

var (
	swapStateMu    sync.Mutex // guards loadSwapState's file reads (held, §6.A3)
	foreignSwapMu  sync.Mutex
	foreignSwapNow foreignSwapState
	// foreignSwitchFn is the foreign side's switch; a var for tests.
	foreignSwitchFn = switchTunnelEngineWith
)

// POST /api/peer/swap-carrier (foreign side)
// GET /api/peer/swap-status (foreign side): the last swap and this tunnel's ports.
// ---- reaching a tunnel's foreign panel ----

var errNoPeerLink = errors.New("no Peer Link to the foreign server")

// swapCall sends one peer API request to the foreign server of t; a var so
// tests never reach a real panel.
var swapCall = swapCallReal

func swapCallReal(t swapTunnel, method, path string, payload any, timeout time.Duration) ([]byte, error) {
	if t.Main {
		c := loadPeerConfig()
		if c.Role != "master" || c.PeerSecret == "" {
			return nil, errNoPeerLink
		}
		return sendToPeerTimeout(path, method, payload, timeout)
	}
	return tunnelPeerCall(t, method, path, payload, timeout)
}

// tunnelLink is what this hub learned about one peer's foreign panel (from
// that panel's handshake, or the last call that worked).
type tunnelLink struct {
	PanelPort  int    `json:"panel_port,omitempty"`
	BasePath   string `json:"base_path,omitempty"`
	InternalIP string `json:"internal_ip,omitempty"`
	PublicIP   string `json:"public_ip,omitempty"`
	LastURL    string `json:"last_url,omitempty"`
	TLSPin     string `json:"tls_pin,omitempty"`
	Seen       string `json:"seen,omitempty"`
}

func tunnelLinksPath() string { return filepath.Join(configDir, "tunnel_links.json") }

var tunnelLinksMu sync.Mutex

func loadTunnelLinks() map[int]tunnelLink {
	tunnelLinksMu.Lock()
	defer tunnelLinksMu.Unlock()
	return readTunnelLinksLocked()
}

func readTunnelLinksLocked() map[int]tunnelLink {
	m := map[int]tunnelLink{}
	if data, err := os.ReadFile(tunnelLinksPath()); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

func updateTunnelLink(id int, fn func(l *tunnelLink)) {
	tunnelLinksMu.Lock()
	defer tunnelLinksMu.Unlock()
	m := readTunnelLinksLocked()
	l := m[id]
	fn(&l)
	m[id] = l
	if data, err := json.MarshalIndent(m, "", "  "); err == nil {
		_ = os.WriteFile(tunnelLinksPath(), data, 0600)
	}
}

// tunnelPeerBases lists the foreign panel's base URLs, best first: the one
// that worked last, then the GRE inner address and the public one on the
// learned port and the usual ones, plain HTTP before HTTPS.
func tunnelPeerBases(t swapTunnel, l tunnelLink) []string {
	var hosts []string
	seenH := map[string]bool{}
	for _, h := range []string{t.PeerGre, l.InternalIP, t.RemotePub, l.PublicIP} {
		if h = CleanHost(h); h != "" && !seenH[h] {
			seenH[h] = true
			hosts = append(hosts, h)
		}
	}
	var ports []int
	seenP := map[int]bool{}
	for _, p := range []int{l.PanelPort, 7777, cfg.Port} {
		if p > 0 && p <= 65535 && !seenP[p] {
			seenP[p] = true
			ports = append(ports, p)
		}
	}
	var out []string
	if l.LastURL != "" {
		out = append(out, l.LastURL)
	}
	for _, h := range hosts {
		for _, p := range ports {
			for _, s := range []string{"http", "https"} {
				u := fmt.Sprintf("%s://%s", s, net.JoinHostPort(h, strconv.Itoa(p)))
				if u != l.LastURL {
					out = append(out, u)
				}
			}
		}
	}
	return out
}

func tunnelPeerCall(t swapTunnel, method, path string, payload any, timeout time.Duration) ([]byte, error) {
	var body []byte
	if payload != nil {
		var err error
		if body, err = json.Marshal(payload); err != nil {
			return nil, err
		}
	}
	secrets := []string{}
	if t.Token != "" {
		secrets = append(secrets, t.Token)
	}
	if c := loadPeerConfig(); c.PeerSecret != "" && c.PeerSecret != t.Token {
		secrets = append(secrets, c.PeerSecret)
	}
	if len(secrets) == 0 {
		return nil, errNoPeerLink
	}
	l := loadTunnelLinks()[t.ID]
	pin := l.TLSPin
	tr := &http.Transport{
		DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // checked against the pin below (trust on first use)
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errors.New("no TLS certificate")
				}
				sum := sha256.Sum256(raw[0])
				got := hex.EncodeToString(sum[:])
				if pin == "" {
					pin = got
					updateTunnelLink(t.ID, func(x *tunnelLink) { x.TLSPin = got })
					return nil
				}
				if subtle.ConstantTimeCompare([]byte(pin), []byte(got)) != 1 {
					return errors.New("foreign panel TLS certificate changed (pinned fingerprint does not match)")
				}
				return nil
			},
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: timeout, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var lastErr error
	dead := map[string]bool{}
	for _, base := range tunnelPeerBases(t, l) {
		host := base
		if i := strings.Index(base, "://"); i >= 0 {
			host = base[i+3:]
		}
		if dead[host] {
			continue
		}
		for _, sec := range secrets {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			req, err := http.NewRequestWithContext(ctx, method, base+peerRoutePrefix+path, bytes.NewReader(body))
			if err != nil {
				cancel()
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Peer-Secret", sec)
			resp, err := client.Do(req)
			if err != nil {
				cancel()
				lastErr = err
				var ne net.Error
				if errors.As(err, &ne) || strings.Contains(err.Error(), "refused") {
					dead[host] = true
				}
				break
			}
			data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			cancel()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 && json.Valid(data) {
				if l.LastURL != base {
					updateTunnelLink(t.ID, func(x *tunnelLink) { x.LastURL = base })
				}
				return data, nil
			}
			lastErr = fmt.Errorf("foreign panel answered HTTP %d: %s", resp.StatusCode, truncateForError(data))
			if resp.StatusCode != http.StatusNotFound {
				break // the secret was right; another one will not help
			}
		}
	}
	if lastErr == nil {
		lastErr = errNoPeerLink
	}
	return nil, lastErr
}

// tunnelTokenOwner is the peer whose tunnel token is secret (0: none). The
// main tunnel's token is the Peer Link secret and is handled before this.
type tunnelCtxKey struct{}

// requireTunnelSecretHidden lets a peer's foreign server (which holds that
// peer's token, not the Peer Link secret) introduce itself and ping, so the
// hub learns where its panel answers. Every failure is a bare 404.
// tunnelHandshake records a peer's foreign panel (port, base path, addresses).
// ---- the swap job ----

type swapStep struct {
	Key    string `json:"key"`   // check | foreign | local | verify | revert
	State  string `json:"state"` // pending | run | ok | fail | skip
	Detail string `json:"detail,omitempty"`
}

type swapJob struct {
	ID       int        `json:"id"`
	Name     string     `json:"name"`
	From     string     `json:"from"`
	To       string     `json:"to"`
	Manual   bool       `json:"manual"`
	State    string     `json:"state"` // running | ok | failed | reverted | manual
	Error    string     `json:"error,omitempty"`
	Note     string     `json:"note,omitempty"`
	Bundle   string     `json:"bundle,omitempty"`
	Steps    []swapStep `json:"steps"`
	Started  string     `json:"started"`
	Finished string     `json:"finished,omitempty"`
	TookMs   int64      `json:"took_ms,omitempty"`
	started  time.Time
}

var (
	swapJobsMu sync.Mutex
	swapJobs   = map[int]*swapJob{}
	// Waits and polls; vars so tests run in milliseconds.
	swapVerifyWait  = 45 * time.Second
	swapRevertWait  = 30 * time.Second
	swapPollEvery   = time.Second
	swapForeignWait = 1500 * time.Millisecond
	// swapLinkedFn reports whether tunnel t's control session is up.
	swapLinkedFn = swapLinked
)

// swapLinked: the tunnel's control session is established (all carriers keep
// one on TCP, Backhaul's udp transport included); for FRP also a forwarded
// port that frps opened, which it only does once frpc logged in.
func swapLinked(t swapTunnel, to carrierChoice) bool {
	q := ctrlQuery{ID: t.ID, Port: t.Port, RemotePub: t.RemotePub, PeerGre: t.PeerGre}
	var ctrl []int
	if t.Port > 0 {
		ctrl = append(ctrl, t.Port)
	}
	for _, p := range loadPeers() {
		if p.FrpPort > 0 && p.FrpPort != t.Port {
			ctrl = append(ctrl, p.FrpPort)
		}
	}
	if controlSessionIn(parseSS(ssEstablished()), q, portOwners(ctrl)).Linked {
		return true
	}
	if to.Engine == "frp" {
		for i, p := range t.Ports {
			if i >= 4 {
				break
			}
			if c, err := dialFn("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)), 500*time.Millisecond); err == nil {
				_ = c.Close()
				return true
			}
		}
	}
	return false
}

// tellForeign asks the foreign server to switch. ok=false: it could not be
// reached or refused, err says why. An older panel without swap-carrier is
// sent the old apply-engine (it answers only after switching, so that call
// runs in the background).
// foreignFailed reports a failure the foreign server recorded for this swap.
// waitLinked polls until the tunnel is linked, the foreign side reports a
// failure, or wait runs out.
// swapBundle is the setup bundle for the foreign server on the new carrier.
// ---- HTTP ----

// GET /api/tunnel/swap?id=N[&probe=1]
// swapView is what the swap dialog needs about tunnel id on this server.
// POST /api/tunnel/swap {"id": N, "carrier": "backhaul:wssmux", "manual": false}
// startSwapOn checks that tunnel t can move to carrier to and starts the swap.
// ---- swapping from the foreign server ----
//
// The foreign panel cannot run a swap itself: the Iran side holds the ports,
// the tokens and the other tunnels. It asks the Iran server instead, which
// runs the swap as if it was started there (the foreign server is told
// first, both switch, both go back when the tunnel does not reconnect). The
// Iran server knows the caller by its secret: the Peer Link secret is the
// main tunnel, a peer's own token that peer's tunnel.

var errOldIranPanel = errors.New("the Iran server did not take the request: it runs an older panel, or its Peer Link secret differs from this server's. Update it, or do this from the Iran server")

// peerCallJSON sends one request to the Iran server over the Peer Link and
// stops at the first JSON answer, whatever its status, so a request that
// starts something is never sent twice. Status 404 with no data: no address
// knew the route (an older panel). A var so tests never reach a real panel.
var peerCallJSON = peerCallJSONReal

func peerCallJSONReal(method, path string, payload any, timeout time.Duration) (int, []byte, error) {
	c := loadPeerConfig()
	if c.PeerSecret == "" {
		return 0, nil, errNoPeerLink
	}
	var body []byte
	if payload != nil {
		var err error
		if body, err = json.Marshal(payload); err != nil {
			return 0, nil, err
		}
	}
	tr := &http.Transport{TLSClientConfig: peerTLSConfig(&c)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: timeout, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var lastErr error
	notFound := false
	dead := map[string]bool{}
	for _, target := range peerTargetURLs(c, path) {
		host := target
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		if i := strings.Index(host, "/"); i >= 0 {
			host = host[:i]
		}
		if dead[host] {
			continue
		}
		req, err := http.NewRequest(method, target, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Peer-Secret", c.PeerSecret)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			dead[host] = true
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if json.Valid(data) {
			markPeerSeen()
			return resp.StatusCode, data, nil
		}
		if resp.StatusCode == http.StatusNotFound {
			notFound = true
		}
	}
	if notFound {
		return http.StatusNotFound, nil, nil
	}
	if lastErr == nil {
		lastErr = errNoPeerLink
	}
	return 0, nil, lastErr
}

// peerAnswerErr is the error an Iran panel answered with.
// foreignSwapView is the swap dialog on a foreign server: the Iran server's
// view of this tunnel, minus what this server lacks.
// relaySwapToIran asks the Iran server to swap this tunnel's carrier.
// swapCallerTunnel is the tunnel whose foreign server sent r: a peer's token
// names that peer, the Peer Link secret the main tunnel.
// GET /api/peer/swap-request[?probe=1] (Iran side)
// POST /api/peer/swap-request {"carrier": "backhaul:wssmux"} (Iran side)
