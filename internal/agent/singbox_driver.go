package agent

// singbox_driver.go — the sing-box engine driver over the VENDORED core
// (quantum-cores sing-box-v1.14.4, GPL-3.0 — AGENT-31). Exec-a-binary:
// per the C-Tunnel ruling the GPL binary is an external core — the driver
// renders the upstream JSON config through typed structs and runs
// `sing-box run -c <cfg>` (upstream cobra CLI verified: cmd.go's
// persistent -c flag + cmd_run.go; `sing-box version` for reporting).
//
// Tunnel shape (AGENT-31 scope — what fits our desired-state model):
//   SERVER (foreign): the protocol's INBOUND (carrier listen) + a direct
//     outbound — it dials the destinations the tunnel requests from ITS
//     network.
//   CLIENT (iran): dials OUT through the protocol OUTBOUND, offering:
//     - local_mode=proxy:   a mixed (SOCKS+HTTP) ingress on local_port —
//       the classic Iran proxy-exit shape (everything rides the tunnel);
//     - local_mode=forward: a DIRECT inbound listening on local_port with
//       override_address=forward_addr — a directed Iran→foreign
//       port-forward (the override destination is requested THROUGH the
//       tunnel and dialed by the server end; route rule pins the inbound
//       to the carrier outbound).
//   The REVERSE direction (public port on the foreign end → Iran-local
//   target) has NO sing-box primitive without a reverse listener — gost
//   rtcp/rudp, frp and backhaul cover that shape (AGENT-31 report scope).
//   Out of scope: DNS servers, route rule sets, clash API, tun/endpoints
//   (wireguard/openvpn/tailscale), and the protocols that cannot host our
//   two-end shape (ssh/snell/openvpn are outbound-only upstream;
//   shadowtls needs an upstream TLS app).
//
// Field names cite the upstream option structs: ListenOptions
// (listen/listen_port), TrojanInboundOptions (users[].password),
// VLESSUser.UUID, VMessOutboundOptions (uuid/security), Shadowsocks
// (method/password), Hysteria2 (users[].password, up_mbps/down_mbps,
// obfs{type,password}), TUIC (uuid/password/congestion_control),
// AnyTLS (password), TLS options (enabled/server_name/insecure/
// certificate_path/key_path), DirectInboundOptions (override_address/
// override_port/network).

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-agent/internal/infra"
)

const singboxID = "singbox"

// singBoxProtocols is the allowlist: the protocols that fit our two-end
// tunnel model. TLS-required ones (upstream hard-codes TLS in these
// protocols) must carry the cert pair.
var singBoxProtocols = map[string]bool{
	"shadowsocks": true, "vless": true, "vmess": true,
	"trojan": true, "hysteria2": true, "tuic": true, "anytls": true,
}

// singBoxTLSRequired lists the protocols that are TLS-only upstream.
var singBoxTLSRequired = map[string]bool{
	"trojan": true, "hysteria2": true, "tuic": true, "anytls": true,
}

// singBoxUDPCarrier protocols ride QUIC (the carrier socket is UDP).
func singBoxUDPCarrier(protocol string) bool {
	return protocol == "hysteria2" || protocol == "tuic"
}

type singboxParams struct {
	ServerSide string `json:"server_side"`  // the end hosting the sing-box SERVER (foreign)
	Version    string `json:"version"`      // artifact version (cache key)
	Artifact   string `json:"artifact"`     // name template with {arch}
	SHA256Amd  string `json:"sha256_amd64"` // pinned fallback
	SHA256Arm  string `json:"sha256_arm64"`
	SigAmd     string `json:"signature_amd64"`
	SigArm     string `json:"signature_arm64"`
	ServerAddr string `json:"server_addr"` // carrier "host:port" — server listen / client dial
	Protocol   string `json:"protocol"`    // shadowsocks|vless|vmess|trojan|hysteria2|tuic|anytls
	// Auth fields — per-protocol: uuid for vless/vmess/tuic; password for
	// trojan/anytls; method+password for shadowsocks. The validate step
	// enforces exactly the fields the chosen protocol needs (and refuses
	// dead secrets for the others).
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	SSMethod string `json:"ss_method,omitempty"`
	// hysteria2 bandwidth + tuic congestion (optional).
	UpMbps     int    `json:"up_mbps,omitempty"`
	DownMbps   int    `json:"down_mbps,omitempty"`
	Congestion string `json:"congestion,omitempty"` // cubic|new_reno|bbr
	// TLS: required for trojan/hysteria2/tuic/anytls (upstream TLS-only);
	// optional for vless/vmess (when set, client tls.enabled=true).
	TLSCert  string `json:"tls_cert,omitempty"` // server certificate_path (PEM path)
	TLSKey   string `json:"tls_key,omitempty"`  // server key_path
	SNI      string `json:"sni,omitempty"`      // client server_name (default = server host)
	Insecure bool   `json:"insecure,omitempty"` // client insecure (self-signed labs)
	// Client-end ingress (exactly one of the two modes).
	LocalMode   string `json:"local_mode"`             // proxy|forward
	LocalPort   int    `json:"local_port"`             // the Iran-end ingress listen
	ForwardAddr string `json:"forward_addr,omitempty"` // mode=forward: "host:port" dialed by the SERVER end
}

func (p singboxParams) singboxArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	return enginePinForArch(EnginePin{Version: p.Version, Artifact: p.Artifact,
		SHA256Amd: p.SHA256Amd, SHA256Arm: p.SHA256Arm, SigAmd: p.SigAmd, SigArm: p.SigArm})
}

func singboxValidateParams(p singboxParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("singbox: server_side required")
	}
	if err := backhaulValidateArtifactPins2(p.Version, p.Artifact, p.SHA256Amd, p.SigAmd,
		p.SHA256Arm, p.SigArm, singboxID); err != nil {
		return err
	}
	if _, _, e := net.SplitHostPort(p.ServerAddr); e != nil {
		return fmt.Errorf("singbox: server_addr must be host:port")
	}
	proto := strings.ToLower(strings.TrimSpace(p.Protocol))
	if !singBoxProtocols[proto] {
		return fmt.Errorf("singbox: protocol %q not supported (%s; outbound-only ssh/snell/openvpn and endpoint shapes wireguard/tun/tailscale are out of scope)", p.Protocol, "shadowsocks|vless|vmess|trojan|hysteria2|tuic|anytls")
	}
	if singBoxTLSRequired[proto] {
		if strings.TrimSpace(p.TLSCert) == "" || strings.TrimSpace(p.TLSKey) == "" {
			return fmt.Errorf("singbox: protocol %s is TLS-only upstream — tls_cert and tls_key are required (self-signed pairs are fine with client insecure)", p.Protocol)
		}
	}
	for _, a := range []struct{ label, v string }{{"tls_cert", p.TLSCert}, {"tls_key", p.TLSKey}} {
		if a.v != "" && (len(a.v) > 256 || strings.ContainsAny(a.v, "\"'`\n\r$;&|<>")) {
			return fmt.Errorf("singbox: %s must be a ≤256-char path without quotes/shell metacharacters", a.label)
		}
	}
	switch proto {
	case "shadowsocks":
		if err := engineVerifySecretShape("singbox ss_method", p.SSMethod, 3, 32); err != nil {
			return err
		}
		if err := engineVerifySecretShape("singbox password", p.Password, 8, 128); err != nil {
			return err
		}
		if p.UUID != "" {
			return fmt.Errorf("singbox: uuid is dead weight for protocol %s — refuse it rather than carry a secret nobody reads", proto)
		}
	case "vless", "vmess":
		if err := engineVerifySecretShape("singbox uuid", p.UUID, 16, 64); err != nil {
			return err
		}
		if p.Password != "" || p.SSMethod != "" {
			return fmt.Errorf("singbox: password/ss_method are dead weight for protocol %s", proto)
		}
	case "trojan", "anytls":
		if err := engineVerifySecretShape("singbox password", p.Password, 8, 128); err != nil {
			return err
		}
		if p.UUID != "" || p.SSMethod != "" {
			return fmt.Errorf("singbox: uuid/ss_method are dead weight for protocol %s", proto)
		}
	case "hysteria2":
		if err := engineVerifySecretShape("singbox password", p.Password, 8, 128); err != nil {
			return err
		}
		if p.UUID != "" || p.SSMethod != "" {
			return fmt.Errorf("singbox: uuid/ss_method are dead weight for protocol %s", proto)
		}
		if p.UpMbps < 0 || p.UpMbps > 100000 || p.DownMbps < 0 || p.DownMbps > 100000 {
			return fmt.Errorf("singbox: up_mbps/down_mbps out of range (0 = unset)")
		}
	case "tuic":
		if err := engineVerifySecretShape("singbox uuid", p.UUID, 16, 64); err != nil {
			return err
		}
		if err := engineVerifySecretShape("singbox password", p.Password, 8, 128); err != nil {
			return err
		}
		if p.SSMethod != "" {
			return fmt.Errorf("singbox: ss_method is dead weight for protocol %s", proto)
		}
		if p.Congestion != "" && p.Congestion != "cubic" && p.Congestion != "new_reno" && p.Congestion != "bbr" {
			return fmt.Errorf("singbox: congestion must be cubic|new_reno|bbr (upstream enum)")
		}
	}
	if p.SNI != "" && (len(p.SNI) > 253 || strings.ContainsAny(p.SNI, "\"'\n\r\\ ")) {
		return fmt.Errorf("singbox: sni must be a hostname-shaped ≤253-char string")
	}
	switch p.LocalMode {
	case "proxy":
		if p.ForwardAddr != "" {
			return fmt.Errorf("singbox: forward_addr is only valid with local_mode=forward")
		}
	case "forward":
		if _, _, e := net.SplitHostPort(p.ForwardAddr); e != nil || len(p.ForwardAddr) > 128 ||
			strings.ContainsAny(p.ForwardAddr, "\"'\n\r") {
			return fmt.Errorf("singbox: forward_addr must be a 1-128 host:port string (dialed by the server end)")
		}
	default:
		return fmt.Errorf("singbox: local_mode must be proxy|forward")
	}
	if p.LocalPort <= 0 || p.LocalPort > 65535 {
		return fmt.Errorf("singbox: local_port out of range")
	}
	return nil
}

func singboxResolveRole(p singboxParams) (string, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("singbox: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return "server", nil
	}
	return "client", nil
}

type singboxInstState struct {
	engineInst
	params singboxParams
	role   string
}

// SingboxDriver implements engine.Driver for the vendored sing-box core.
type SingboxDriver struct {
	runs *instTable[singboxInstState]
}

func NewSingboxDriver() *SingboxDriver {
	return &SingboxDriver{runs: newInstTable[singboxInstState]()}
}

func (d *SingboxDriver) ID() string { return singboxID }

func (d *SingboxDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: singboxID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","server_addr":"0.0.0.0:8388","protocol":"shadowsocks|vless|vmess|trojan|hysteria2|tuic|anytls","uuid":"","password":"","ss_method":"aes-256-gcm","up_mbps":0,"down_mbps":0,"congestion":"cubic|new_reno|bbr","tls_cert":"","tls_key":"","sni":"","insecure":false,"local_mode":"proxy|forward","local_port":0,"forward_addr":"host:port"}`)}
}

func (d *SingboxDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *SingboxDriver) Validate(params json.RawMessage) error {
	var p singboxParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("singbox: engine_params: %w", err)
	}
	return singboxValidateParams(p)
}

func singboxEngineDir() string { return engineEngineDir(singboxID) }

func singboxBinDir(version string) string {
	return filepath.Join(singboxEngineDir(), "bin", version)
}

func singboxConfigPath(tunnelID string) string {
	return filepath.Join(singboxEngineDir(), "instances", tunnelID+".json")
}

// ---- typed sing-box config (marshaled — never string-concatenated) ------

type sbUser struct {
	Name     string `json:"name,omitempty"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
}

type sbTLS struct {
	Enabled         bool   `json:"enabled"`
	ServerName      string `json:"server_name,omitempty"`
	Insecure        bool   `json:"insecure,omitempty"`
	CertificatePath string `json:"certificate_path,omitempty"`
	KeyPath         string `json:"key_path,omitempty"`
}

type sbObfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

// sbEntry is one inbound/outbound: the protocol-specific fields ride the
// generic map ONLY through charset-validated params (no free-form JSON).
type sbEntry struct {
	Type            string `json:"type"`
	Tag             string `json:"tag"`
	Listen          string `json:"listen,omitempty"`
	ListenPort      uint16 `json:"listen_port,omitempty"`
	Network         string `json:"network,omitempty"`
	OverrideAddress string `json:"override_address,omitempty"`
	OverridePort    uint16 `json:"override_port,omitempty"`
	// server-side protocol fields
	Users []sbUser `json:"users,omitempty"`
	TLS   *sbTLS   `json:"tls,omitempty"`
	Obfs  *sbObfs  `json:"obfs,omitempty"`
	// client-side dial fields
	Server            string `json:"server,omitempty"`
	ServerPort        uint16 `json:"server_port,omitempty"`
	UUID              string `json:"uuid,omitempty"`
	Security          string `json:"security,omitempty"`
	Method            string `json:"method,omitempty"`
	Password          string `json:"password,omitempty"`
	UpMbps            int    `json:"up_mbps,omitempty"`
	DownMbps          int    `json:"down_mbps,omitempty"`
	CongestionControl string `json:"congestion_control,omitempty"`
}

type sbRouteRule struct {
	Inbound  []string `json:"inbound,omitempty"`
	Outbound string   `json:"outbound,omitempty"`
}

type sbConfig struct {
	Inbounds  []sbEntry     `json:"inbounds"`
	Outbounds []sbEntry     `json:"outbounds"`
	Route     *sbRouteBlock `json:"route,omitempty"`
}

type sbRouteBlock struct {
	Rules []sbRouteRule `json:"rules,omitempty"`
}

// singboxRenderConfig builds the end's config for the chosen protocol.
// The carrier listen is server_addr's port; the client dials server_addr.
func singboxRenderConfig(role string, p singboxParams) sbConfig {
	proto := strings.ToLower(strings.TrimSpace(p.Protocol))
	_, carrierPort, _ := net.SplitHostPort(p.ServerAddr)
	cPort, _ := strconv.ParseUint(carrierPort, 10, 16)
	var cfg sbConfig
	clientTLS := func() *sbTLS {
		if !singBoxTLSRequired[proto] && strings.TrimSpace(p.TLSCert) == "" {
			return nil // plain vless/vmess/shadowsocks
		}
		t := &sbTLS{Enabled: true}
		if p.SNI != "" {
			t.ServerName = p.SNI
		}
		if p.Insecure {
			t.Insecure = true
		}
		return t
	}
	if role == "server" {
		in := sbEntry{Type: proto, Tag: "carrier-in",
			Listen: "0.0.0.0", ListenPort: uint16(cPort)}
		// protocol auth
		switch proto {
		case "shadowsocks":
			in.Method = p.SSMethod
			in.Password = p.Password
		case "vless", "vmess", "tuic":
			in.Users = []sbUser{{Name: "quantum", UUID: p.UUID, Password: p.Password}}
		case "trojan", "anytls", "hysteria2":
			in.Users = []sbUser{{Name: "quantum", Password: p.Password}}
		}
		if proto == "hysteria2" {
			if p.UpMbps > 0 || p.DownMbps > 0 {
				in.UpMbps, in.DownMbps = p.UpMbps, p.DownMbps
			}
		}
		// TLS: required protocols always; vless/vmess when certs are set.
		if singBoxTLSRequired[proto] || strings.TrimSpace(p.TLSCert) != "" {
			in.TLS = &sbTLS{Enabled: true,
				CertificatePath: p.TLSCert, KeyPath: p.TLSKey}
		}
		cfg.Inbounds = []sbEntry{in}
		// the FIRST outbound is sing-box's default route target: direct
		// dials the requested destinations from the server's network.
		cfg.Outbounds = []sbEntry{{Type: "direct", Tag: "direct-out"}}
		return cfg
	}
	// CLIENT (iran): dial out through the protocol outbound.
	out := sbEntry{Type: proto, Tag: "carrier-out",
		Server:     p.ServerAddr[:strings.LastIndex(p.ServerAddr, ":")],
		ServerPort: uint16(cPort)}
	switch proto {
	case "shadowsocks":
		out.Method = p.SSMethod
		out.Password = p.Password
	case "vless", "vmess", "tuic":
		out.UUID = p.UUID
		out.Password = p.Password
		if proto == "vmess" {
			out.Security = "auto"
		}
		if proto == "tuic" && p.Congestion != "" {
			out.CongestionControl = p.Congestion
		}
	case "trojan", "anytls", "hysteria2":
		out.Password = p.Password
	}
	if proto == "hysteria2" {
		if p.UpMbps > 0 {
			out.UpMbps = p.UpMbps
		}
		if p.DownMbps > 0 {
			out.DownMbps = p.DownMbps
		}
	}
	if t := clientTLS(); t != nil {
		out.TLS = t
	}
	if p.LocalMode == "proxy" {
		cfg.Inbounds = []sbEntry{{Type: "mixed", Tag: "ingress-in",
			Listen: "127.0.0.1", ListenPort: uint16(p.LocalPort)}}
		// the single outbound is the default route: everything through
		// the tunnel (no direct fallback — no leak).
		cfg.Outbounds = []sbEntry{out}
		return cfg
	}
	host, fPort, _ := net.SplitHostPort(p.ForwardAddr)
	fp, _ := strconv.ParseUint(fPort, 10, 16)
	cfg.Inbounds = []sbEntry{{Type: "direct", Tag: "forward-in",
		Listen: "127.0.0.1", ListenPort: uint16(p.LocalPort),
		OverrideAddress: host, OverridePort: uint16(fp)}}
	cfg.Outbounds = []sbEntry{out, {Type: "direct", Tag: "direct-out"}}
	cfg.Route = &sbRouteBlock{Rules: []sbRouteRule{{Inbound: []string{"forward-in"}, Outbound: "carrier-out"}}}
	return cfg
}

func singboxEnsureBinary(ctx context.Context, p singboxParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("singbox: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.singboxArtifactPin(); pinErr == nil &&
		engineCacheHit(singboxBinDir(p.Version), pinnedSHA, []string{"sing-box"}) {
		return singboxBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("singbox: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, singboxID,
		func() (string, string, string, error) { return p.singboxArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := singboxBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"sing-box"}) {
		return dir, nil
	}
	body, err := frpFetchArtifact(ctx, downloadURL)
	if err != nil {
		return "", err
	}
	if err := engine.VerifyArtifact(body, sha256Hex, sigB64, key); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("singbox: cache dir: %w", err)
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"sing-box": true}); err != nil {
		return "", fmt.Errorf("singbox: %w", err)
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("singbox: cache marker: %w", err)
	}
	return dir, nil
}

// singboxSpawn runs `sing-box run -c <cfg>` (upstream cobra CLI).
var singboxSpawn = func(binPath, cfgPath string) (frpProcess, error) {
	cmd := exec.Command(binPath, "run", "-c", cfgPath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("singbox: start: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

func (d *SingboxDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p singboxParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("singbox: engine_params: %w", err)
	}
	if err := singboxValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("singbox: invalid tunnel id %q", inst.TunnelID)
	}
	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual[singboxParams](prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}
	role, err := singboxResolveRole(p)
	if err != nil {
		return err
	}
	binDir, err := singboxEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "sing-box")
	cfg := singboxRenderConfig(role, p)
	raw, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("singbox: render config: %w", err)
	}
	cfgPath := singboxConfigPath(inst.TunnelID)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("singbox: config dir: %w", err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		return fmt.Errorf("singbox: write config: %w", err)
	}
	proc, err := singboxSpawn(binPath, cfgPath)
	if err != nil {
		_ = os.Remove(cfgPath)
		return err
	}
	st := &singboxInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		cfg: cfgPath, binPath: binPath}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, st.binPath, st.cfg, singboxSpawn)
	// Wire accounting on the SERVER end; the carrier socket is UDP for
	// the QUIC protocols (hysteria2/tuic), TCP for the rest.
	if role == "server" {
		proto := "tcp"
		if singBoxUDPCarrier(p.Protocol) {
			proto = "udp"
		}
		if port := enginePortOf(p.ServerAddr); port > 0 {
			if err := acctWireRulesAddProto(acctChainsDriver, inst.TunnelID, port, port, proto); err != nil {
				fmt.Fprintf(os.Stderr, "singbox: wire accounting unavailable: %v\n", err)
			}
		}
	}
	return nil
}

func (d *SingboxDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.role == "server" {
			proto := "tcp"
			if singBoxUDPCarrier(st.params.Protocol) {
				proto = "udp"
			}
			if port := enginePortOf(st.params.ServerAddr); port > 0 {
				_ = acctWireRulesDelProto(acctChainsDriver, inst.TunnelID, port, port, proto)
			}
		}
	})
	return nil
}

func (d *SingboxDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, singboxID, inst.TunnelID, inst.Params,
		func(st *singboxInstState) singboxParams { return st.params }, engineParamsEqual[singboxParams])
}

func (d *SingboxDriver) Health(inst engine.Instance) engine.Health {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Health{OK: false, Detail: "not running", LatencyMs: -1}
	}
	select {
	case <-st.current().Done():
		return engine.Health{OK: false, Detail: "process exited", LatencyMs: -1}
	default:
	}
	detail := "sing-box server running (" + st.params.Protocol + " carrier)"
	if st.role != "server" {
		detail = "sing-box client running (" + st.params.Protocol + ")"
	}
	return engine.Health{OK: true, Detail: detail, LatencyMs: -1}
}

// Counters: the SERVER end's wire view on the carrier port (proto-aware
// tcp/udp rules); no machine-readable per-connection payload stats in the
// config surface we drive — payload stays Unknown, honestly.
func (d *SingboxDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil || st.role != "server" {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if port := enginePortOf(st.params.ServerAddr); port > 0 {
		if rx, tx, ok := acctWireBytes(inst.TunnelID, port, port); ok {
			out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
		}
	}
	return out
}

func (d *SingboxDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, singboxEngineDir())
	return nil
}

// singboxVersionProbe runs `sing-box version` (bounded; seam-able) and
// parses "sing-box version X.Y.Z" (cmd_version.go's shape).
var singboxVersionProbe = func(binPath string) (string, error) {
	out, err := infra.RunCmdTimeout(10*time.Second, binPath, "version")
	if err != nil {
		return "", err
	}
	f := strings.Fields(strings.TrimSpace(string(out)))
	if len(f) >= 3 && f[0] == "sing-box" && f[1] == "version" {
		return f[2], nil
	}
	return "", fmt.Errorf("singbox: unexpected version output")
}

// singboxInstalledVersion reports the INSTALLED core version for
// Describe() (the §2.22 pattern): newest cached artifact probed with
// `sing-box version`; the build-pin version reported honestly without.
func singboxInstalledVersion() string {
	base := filepath.Join(singboxEngineDir(), "bin")
	entries, err := os.ReadDir(base)
	if err != nil {
		return singboxPinnedVersion
	}
	best := ""
	for _, e := range entries {
		if !e.IsDir() || !infra.FileExists(filepath.Join(base, e.Name(), "sing-box")) {
			continue
		}
		if ctVersionLess(best, e.Name()) {
			best = e.Name()
		}
	}
	if best == "" {
		return singboxPinnedVersion
	}
	if v, err := singboxVersionProbe(filepath.Join(base, best, "sing-box")); err == nil && v != "" {
		return v
	}
	return best
}

// singboxPinnedVersion is the build-time core pin (the OVERNIGHT-C
// release; §2.22 fallback when no artifact is cached yet).
const singboxPinnedVersion = "1.14.4"
