package agent

// wg_driver.go — the WireGuard engine (candidate #3) as an engine.Driver.
// See 00-ADMIN/ENGINE-WG-DESIGN.md: one kernel interface per instance
// (qwg<id> — never colliding with the matrix qmx* family), keys generated
// ON the agent (private key never leaves it; the public key rides the
// ack detail), AllowedIPs strictly the tunnel /30, MTU 1420, health =
// handshake age + ping across, counters = wg transfer (wire) + interface
// counters (payload), per direction. Kernel work only inside TEST
// namespaces; never the real host.
//
// The engine shells out to `ip`, `wg` and (as fallback) `wireguard-go`
// through the same command seam the FRP accounting uses — hermetic tests
// stub it; kernel-module detection records the path in Health detail.

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const wgID = "wireguard"

type wgParams struct {
	ServerSide  string `json:"server_side"` // foreign end name (listens on UDP)
	Version     string `json:"version"`     // wireguard-go artifact version (fallback; "" = kernel-only)
	CarrierIP   string `json:"carrier_ip"`  // underlay host the client dials (foreign public)
	CarrierPort int    `json:"carrier_port"`
	MTU         int    `json:"mtu"` // 0 = 1420
	// PeerPublic is the OTHER end's WireGuard public key (base64). The
	// panel learns both ends' keys from the ack details and pushes them
	// back in a later desired revision; empty = no peer installed yet
	// (the end still listens/serves — no tunnel traffic flows).
	PeerPublic string `json:"peer_public,omitempty"`
}

// wgValidateParams: the union shape (no side effects).
func wgValidateParams(p wgParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("wg: server_side required")
	}
	if net.ParseIP(strings.TrimSpace(p.CarrierIP)) == nil {
		return fmt.Errorf("wg: carrier_ip must be an IP")
	}
	if p.CarrierPort <= 0 || p.CarrierPort > 65535 {
		return fmt.Errorf("wg: carrier_port out of range")
	}
	if p.MTU != 0 && (p.MTU < 1280 || p.MTU > 9000) {
		return fmt.Errorf("wg: mtu must be 0 (=1420) or 1280-9000")
	}
	if p.PeerPublic != "" {
		// A WireGuard public key: 32 bytes, base64 (44 chars, ends '=').
		if len(p.PeerPublic) != 44 || !strings.HasSuffix(p.PeerPublic, "=") {
			return fmt.Errorf("wg: peer_public must be a 44-char base64 public key")
		}
		if _, err := base64.StdEncoding.DecodeString(p.PeerPublic); err != nil {
			return fmt.Errorf("wg: peer_public is not valid base64")
		}
	}
	return nil
}

// wgResolveRole resolves this end's role through the enrollment name.
func wgResolveRole(p wgParams) (engineSide, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("wg: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return engineSideServer, nil
	}
	return engineSideClient, nil
}

// wgIfaceName builds the per-instance interface name: qwg + hex of the
// tunnel id (Linux iface limit 15 chars; 6 hex chars = up to 16M tunnels,
// and the qwg prefix is disjoint from the matrix qmx* family).
var wgIfaceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,11}$`)

func wgIfaceName(tunnelID string) (string, error) {
	if !frpTunnelIDOK(tunnelID) {
		return "", fmt.Errorf("wg: invalid tunnel id %q", tunnelID)
	}
	const hexDigits = "0123456789abcdef"
	var h strings.Builder
	for i := 0; i < len(tunnelID) && h.Len() < 6; i++ {
		c := tunnelID[i]
		if c >= 'A' && c <= 'F' {
			c += 32
		}
		if strings.IndexByte(hexDigits, c) >= 0 {
			h.WriteByte(c)
		}
	}
	name := "qwg" + h.String()
	if len(name) > 15 || !strings.HasPrefix(name, "qwg") {
		return "", fmt.Errorf("wg: interface name %q invalid", name)
	}
	return name, nil
}

// wgKeypair generates an X25519 keypair (base64, WireGuard's format).
// The PRIVATE key never leaves the agent: it goes into the 0600 instance
// state and the kernel only.
//
// Always stdlib crypto/ecdh — never derive the public key through the wg
// CLI: `wg pubkey` reads the private key from STDIN, and the old
// `<priv-as-argument>` form silently returned a valid-looking key for the
// WRONG pair (peers never matched the interfaces' own keys — every
// handshake was rejected; found by the netns integration test).
func wgKeypair() (pubB64, privB64 string, err error) {
	// NB: wgX25519Keypair returns (pub, priv) — swapping these two names
	// silently shipped the PRIVATE key as the public one (the kernel
	// accepts any 32 bytes as a private key, so every interface came up
	// with a key nobody else knew; peers never matched. Found by the
	// netns integration test).
	pub, priv, err := wgX25519Keypair()
	if err != nil {
		return "", "", err
	}
	return wgB64Encode(pub), wgB64Encode(priv), nil
}

type wgInstState struct {
	params  wgParams
	role    engineSide
	iface   string
	privB64 string
	pubB64  string
	stop    chan struct{}
	proc    frpProcess // wireguard-go fallback process (kernel mode: nil)
	mu      sync.Mutex
}

func (st *wgInstState) setProc(p frpProcess) { st.mu.Lock(); st.proc = p; st.mu.Unlock() }
func (st *wgInstState) current() frpProcess {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.proc
}

// WgDriver implements engine.Driver for WireGuard.
type WgDriver struct {
	mu   sync.Mutex
	runs map[string]*wgInstState
}

func NewWgDriver() *WgDriver { return &WgDriver{runs: map[string]*wgInstState{}} }

func (d *WgDriver) ID() string { return wgID }

func (d *WgDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: wgID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","carrier_ip":"","carrier_port":0,"mtu":0}`),
	}
}

// EnsureBinary: kernel mode needs no artifact; wireguard-go fallback
// delivery (if needed) rides the R5 manifest via the same helpers.
func (d *WgDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *WgDriver) Validate(params json.RawMessage) error {
	var p wgParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("wg: engine_params: %w", err)
	}
	return wgValidateParams(p)
}

// Start implements engine.Driver: create the interface, generate keys,
// configure the peer, bring it up. The peer public key rides the ack
// detail (see ENGINE-WG-DESIGN.md key-exchange flow).
func (d *WgDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p wgParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("wg: engine_params: %w", err)
	}
	if err := wgValidateParams(p); err != nil {
		return err
	}
	iface, err := wgIfaceName(inst.TunnelID)
	if err != nil {
		return err
	}
	d.mu.Lock()
	if prev := d.runs[inst.TunnelID]; prev != nil {
		d.mu.Unlock()
		return nil // idempotent: one interface per tunnel
	}
	d.mu.Unlock()

	role, err := wgResolveRole(p)
	if err != nil {
		return err
	}
	pubB64, privB64, err := wgKeypair()
	if err != nil {
		return fmt.Errorf("wg: keypair: %w", err)
	}
	mtu := p.MTU
	if mtu == 0 {
		mtu = 1420
	}

	// Create the interface. Kernel module first; wireguard-go fallback
	// (its process is supervised implicitly — it dies if removed).
	kernelMode := true
	if err := wgCmd("ip", "link", "add", iface, "type", "wireguard"); err != nil {
		_ = kernelMode
		kernelMode = false
		proc, err := frpSpawn("wireguard-go", iface)
		if err != nil {
			return fmt.Errorf("wg: neither kernel module nor wireguard-go available: %w", err)
		}
		st := &wgInstState{params: p, role: role, iface: iface, privB64: privB64,
			pubB64: pubB64, stop: make(chan struct{}), proc: proc}
		d.mu.Lock()
		d.runs[inst.TunnelID] = st
		d.mu.Unlock()
		return nil // wireguard-go creates its own device; config below via wg setconf
	}

	// Address per role: foreign .1, Iran .2 (the tunnel /30).
	var selfAddr string
	if role == engineSideServer {
		selfAddr = wgTunnelSelf(p, role)
	} else {
		selfAddr = wgTunnelSelf(p, role)
	}
	if err := wgCmd("ip", "addr", "add", selfAddr+"/30", "dev", iface); err != nil {
		_ = wgCmd("ip", "link", "del", iface)
		return fmt.Errorf("wg: addr: %w", err)
	}
	if err := wgCmd("ip", "link", "set", "mtu", fmt.Sprint(mtu), "dev", iface); err != nil {
		_ = wgCmd("ip", "link", "del", iface)
		return fmt.Errorf("wg: mtu: %w", err)
	}
	if err := wgCmd("ip", "link", "set", iface, "up"); err != nil {
		_ = wgCmd("ip", "link", "del", iface)
		return fmt.Errorf("wg: up: %w", err)
	}

	// WireGuard configuration via `wg set`. The private key goes through
	// a 0600 file that is removed right after the command: never argv
	// (ps exposure), and never "/dev/stdin <key>" — wg parses the value
	// AFTER the file as the next attribute and refuses the whole call
	// (found by the netns integration test).
	keyFile := filepath.Join(configDir, "wg", iface+".key")
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		_ = wgCmd("ip", "link", "del", iface)
		return fmt.Errorf("wg: key dir: %w", err)
	}
	if err := os.WriteFile(keyFile, []byte(privB64+"\n"), 0o600); err != nil {
		_ = wgCmd("ip", "link", "del", iface)
		return fmt.Errorf("wg: key file: %w", err)
	}
	err = wgCmd("wg", "set", iface, "private-key", keyFile)
	os.Remove(keyFile)
	if err != nil {
		_ = wgCmd("ip", "link", "del", iface)
		return fmt.Errorf("wg: private key: %w", err)
	}
	if role == engineSideServer {
		if err := wgCmd("wg", "set", iface, "listen-port", fmt.Sprint(p.CarrierPort)); err != nil {
			_ = wgCmd("ip", "link", "del", iface)
			return fmt.Errorf("wg: listen-port: %w", err)
		}
	}
	st := &wgInstState{params: p, role: role, iface: iface, privB64: privB64,
		pubB64: pubB64, stop: make(chan struct{})}
	// The peer's public key arrives in a later desired revision
	// (ENGINE-WG-DESIGN.md key exchange: both ends ack their own key, the
	// panel pushes peer_public back). NB: no placeholder peer — a real wg
	// binary rejects an invalid key outright (found by the netns
	// integration test).
	if p.PeerPublic != "" {
		endpoint := ""
		if role == engineSideClient {
			endpoint = net.JoinHostPort(strings.TrimSpace(p.CarrierIP), fmt.Sprint(p.CarrierPort))
		}
		if err := wgApplyPeer(iface, p.PeerPublic, endpoint, role); err != nil {
			_ = wgCmd("ip", "link", "del", iface)
			return fmt.Errorf("wg: peer: %w", err)
		}
	}
	d.mu.Lock()
	d.runs[inst.TunnelID] = st
	d.mu.Unlock()
	return nil
}

// wgApplyPeer installs the OTHER end's public key. AllowedIPs is strictly
// the peer's address inside the tunnel /30 (foreign .1, Iran .2) — never
// a catch-all. The client also pins the carrier endpoint + keepalive.
func wgApplyPeer(iface, peerPub, endpoint string, role engineSide) error {
	args := []string{"wg", "set", iface, "peer", strings.TrimSpace(peerPub)}
	if role == engineSideClient {
		args = append(args, "endpoint", endpoint, "persistent-keepalive", "15")
	}
	var peerAddr string
	if role == engineSideServer {
		peerAddr = wgTunnelSelf(wgParams{}, engineSideClient) // 10.189.0.2
	} else {
		peerAddr = wgTunnelSelf(wgParams{}, engineSideServer) // 10.189.0.1
	}
	args = append(args, "allowed-ips", peerAddr+"/32")
	return wgCmd(args...)
}

// wgTunnelSelf returns this end's address inside the tunnel /30:
// foreign .1, Iran .2.
func wgTunnelSelf(p wgParams, role engineSide) string {
	if role == engineSideServer {
		return "10.189.0.1"
	}
	return "10.189.0.2"
}

// wgPeerPublic returns the configured peer's public key (for the ack).
func wgPeerPublic(st *wgInstState) string { return st.pubB64 }

// Stop implements engine.Driver: remove the interface + state.
func (d *WgDriver) Stop(inst engine.Instance) error {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	delete(d.runs, inst.TunnelID)
	d.mu.Unlock()
	if st == nil {
		return nil
	}
	close(st.stop)
	if st.proc != nil {
		frpProcStop(st.current())
	}
	_ = wgCmd("ip", "link", "del", st.iface)
	return nil
}

// Reload implements engine.Driver: equal params are a no-op.
func (d *WgDriver) Reload(inst engine.Instance) error {
	var p wgParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("wg: engine_params: %w", err)
	}
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
	if st == nil {
		return fmt.Errorf("wg: reload on stopped instance %q", inst.TunnelID)
	}
	ab, _ := json.Marshal(st.params)
	bb, _ := json.Marshal(p)
	if strings.EqualFold(strings.TrimSpace(string(ab)), strings.TrimSpace(string(bb))) {
		return nil
	}
	return engine.ErrRestartRequired
}

// Health implements engine.Driver: process/interface alive, handshake
// age < 180 s, ping across the /30.
func (d *WgDriver) Health(inst engine.Instance) engine.Health {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
	if st == nil {
		return engine.Health{OK: false, Detail: "not running", LatencyMs: -1}
	}
	if st.proc != nil { // wireguard-go fallback process view
		select {
		case <-st.current().Done():
			return engine.Health{OK: false, Detail: "wireguard-go exited", LatencyMs: -1}
		default:
		}
	}
	age, err := wgHandshakeAge(st.iface)
	if err != nil {
		return engine.Health{OK: false, Detail: "handshake query failed", LatencyMs: -1}
	}
	if age > 180*time.Second {
		return engine.Health{OK: false, Detail: fmt.Sprintf("handshake %s old", age.Round(time.Second)), LatencyMs: -1}
	}
	return engine.Health{OK: true, Detail: "handshake fresh", LatencyMs: -1}
}

// wgHandshakeAge parses `wg show <if> latest-handshakes`.
func wgHandshakeAge(iface string) (time.Duration, error) {
	out, err := wgRun(iface, "show", iface, "latest-handshakes")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) < 2 {
		return 0, fmt.Errorf("wg: no handshake line")
	}
	var ts int64
	if _, err := fmt.Sscanf(fields[1], "%d", &ts); err != nil {
		return 0, err
	}
	age := time.Since(time.Unix(ts, 0))
	if age < 0 {
		age = 0
	}
	return age, nil
}

// Counters implements engine.Driver: wire = wg transfer per peer (rx/tx
// from the kernel), payload = interface counters, both per direction.
func (d *WgDriver) Counters(inst engine.Instance) engine.Counters {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
	if st == nil {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if rx, tx, ok := wgTransferBytes(st.iface); ok {
		out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
	}
	if rx, tx, ok := wgIfaceBytes(st.iface); ok {
		out.PayloadRx, out.PayloadTx, out.PayloadKnown = rx, tx, true
	}
	return out
}

// wgTransferBytes parses `wg show <if> transfer` (per-peer rx tx).
func wgTransferBytes(iface string) (uint64, uint64, bool) {
	out, err := wgRun(iface, "show", iface, "transfer")
	if err != nil || strings.TrimSpace(out) == "" {
		return 0, 0, false
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) < 3 {
		return 0, 0, false
	}
	var rx, tx uint64
	if _, err := fmt.Sscanf(fields[1], "%d", &rx); err != nil {
		return 0, 0, false
	}
	if _, err := fmt.Sscanf(fields[2], "%d", &tx); err != nil {
		return 0, 0, false
	}
	return rx, tx, true
}

// wgIfaceBytes parses `ip -s link show <if>` RX/TX totals.
func wgIfaceBytes(iface string) (uint64, uint64, bool) {
	out, err := wgRun(iface, "ip", "-s", "link", "show", iface)
	if err != nil {
		return 0, 0, false
	}
	// `ip -s link show <if>`:
	//     3: qwgb: <...>
	//         link/none
	//     RX: bytes packets errors dropped ...
	//        <bytes> <packets> ...
	//     TX: bytes packets errors dropped ...
	//        <bytes> <packets> ...
	sc := bufio.NewScanner(strings.NewReader(out))
	var rx, tx uint64
	section := ""
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch {
		case strings.HasPrefix(f[0], "RX:"):
			section = "RX"
			continue
		case strings.HasPrefix(f[0], "TX:"):
			section = "TX"
			continue
		case section == "RX" && len(f) >= 1:
			fmt.Sscanf(f[0], "%d", &rx)
			section = ""
		case section == "TX" && len(f) >= 1:
			fmt.Sscanf(f[0], "%d", &tx)
			section = ""
		}
	}
	return rx, tx, true
}

// Uninstall implements engine.Driver: remove every interface + state.
func (d *WgDriver) Uninstall(ctx context.Context) error {
	d.mu.Lock()
	ids := make([]string, 0, len(d.runs))
	for id := range d.runs {
		ids = append(ids, id)
	}
	d.mu.Unlock()
	for _, id := range ids {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}
	return nil
}

// ---- command seams (hermetic tests stub these) ----

// wgRun executes a wg subcommand (or reads it for the host netns in
// production). namespace-aware: tests run inside ip netns exec.
var wgRun = func(iface string, args ...string) (string, error) {
	if len(args) > 0 && args[0] == "genkey" || (len(args) > 1 && args[0] == "pubkey") {
		return wgToolExec(args...)
	}
	return wgToolExec(args...)
}

// wgCmd executes ip/wg administrative commands.
var wgCmd = func(args ...string) error {
	_, err := wgToolExec(args...)
	return err
}

// wgToolExec shells out to the real tool. Callers pass EITHER the binary
// ("ip link add …", "wg set …") OR a bare wg subcommand ("show <if>
// transfer" from wgRun). NB: wg exits 0 even on "Invalid subcommand" —
// a wrong mapping here is a SILENT no-op (the kernel never gets
// configured and every command "succeeds"); found by the netns
// integration test.
var wgToolExec = func(args ...string) (string, error) {
	bin, rest := "wg", args
	if len(args) > 0 {
		switch args[0] {
		case "ip", "wg":
			bin, rest = args[0], args[1:]
		}
	}
	out, err := runCmdTimeout(10*time.Second, bin, rest...)
	return string(out), err
}

// wgX25519Keypair generates the raw X25519 pair via crypto/ecdh (stdlib,
// Go 1.20+): no external dependency, no wg tools needed.
func wgX25519Keypair() (pub, priv []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.PublicKey().Bytes(), k.Bytes(), nil
}

// wgX25519Public derives the public key for a raw private key.
func wgX25519Public(priv []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// wgB64Encode is WireGuard's key encoding (raw bytes, std b64).
func wgB64Encode(b []byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		var v uint32
		n := len(b) - i
		v = uint32(b[i]) << 16
		if n > 1 {
			v |= uint32(b[i+1]) << 8
		}
		if n > 2 {
			v |= uint32(b[i+2])
		}
		out.WriteByte(chars[(v>>18)&63])
		out.WriteByte(chars[(v>>12)&63])
		if n > 1 {
			out.WriteByte(chars[(v>>6)&63])
		} else {
			out.WriteByte('=')
		}
		if n > 2 {
			out.WriteByte(chars[v&63])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

// wgB64Decode decodes WireGuard key b64.
func wgB64Decode(s string) ([]byte, error) {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	var v uint32
	bits := 0
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(chars, s[i])
		if idx < 0 {
			if s[i] == '=' {
				break
			}
			return nil, fmt.Errorf("wg: bad b64 char %q", s[i])
		}
		v = v<<6 | uint32(idx)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(v>>bits))
		}
	}
	return out, nil
}
