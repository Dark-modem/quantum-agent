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
//
// OVERNIGHT-A3 (morning human order — the A2-era won't-expose verdicts
// are OVERRIDDEN; every claim below is verified against the pinned
// v1.14.4 source (release commit c005f3530) AND the vendored binary's
// build tags (with_quic, with_tailscale, with_gvisor, with_utls, ...):
//
//	hysteria   hysteria v1 in+out registered under with_quic (include/
//	           quic.go) — ON in the vendored build (hysteria2/tuic prove
//	           the tag live). QUIC+TLS: certs required.
//	shadowtls  in+out registered unconditionally (include/registry.go).
//	           The server side is a CHAINED INBOUND: the shadowtls
//	           inbound's `detour` feeds the decrypted inner stream into
//	           the inner shadowsocks inbound (docs/configuration/shared/
//	           listen.md #detour); the client nests the ss outbound
//	           INSIDE the shadowtls outbound (ss detour → stls).
//	snell      in+out registered unconditionally (the A2-era "outbound-
//	           only" claim is STALE for v1.14.4 — protocol/snell has
//	           RegisterInbound). version 5=obfs/6=v6 inbound, 4/6
//	           outbound; the driver pairs v6↔v6 (option/snell.go enums).
//	tor        outbound registered unconditionally (protocol/tor — bine):
//	           drives the operator-supplied tor daemon (executable_path
//	           required). Outbound-only: both ends render the ingress→tor
//	           exit shape; there is no tor "server".
//	tailscale  the tailscale ENDPOINT under with_tailscale — ON in the
//	           vendored build (include/tailscale.go). Both ends join the
//	           tailnet (auth_key required); DERP relay is built in.
//	           cloudflared is cronet-gated (EXCLUDED from the vendored
//	           build — upstream NOTICE) and masque does not exist in
//	           sing-box at all (v1.14.4 has no masque protocol — grep
//	           proven): both stay blocked-by-upstream, documented in the
//	           A3 report and the overnight checker.
var singBoxProtocols = map[string]bool{
	"shadowsocks": true, "vless": true, "vmess": true,
	"trojan": true, "hysteria2": true, "tuic": true, "anytls": true,
	"hysteria": true, "shadowtls": true, "snell": true,
	"naive": true, "tor": true, "tailscale": true,
}

// singBoxTLSRequired lists the protocols that are TLS-only upstream.
var singBoxTLSRequired = map[string]bool{
	"trojan": true, "hysteria2": true, "tuic": true, "anytls": true,
	"hysteria": true, "naive": true,
}

// singBoxUDPCarrier protocols ride QUIC (the carrier socket is UDP).
func singBoxUDPCarrier(protocol string) bool {
	switch protocol {
	case "hysteria2", "tuic", "hysteria":
		return true
	}
	return false
}

// singBoxNoCarrier: the protocols whose tunnel does not ride a
// host-to-host carrier socket at all (tor IS the network; tailscale joins
// a tailnet) — no carrier_addr, no wire accounting, health = process.
func singBoxNoCarrier(protocol string) bool {
	return protocol == "tor" || protocol == "tailscale"
}

// singBoxClientBlocked lists protocols whose CLIENT half cannot run in
// the vendored build. naive's outbound is cronet-gated
// (include/naive_outbound.go, build tag with_naive_outbound — the
// vendored binary EXCLUDES it because cronet-go ships no arm64 library,
// per the cores NOTICE): the server half (the naive INBOUND — registered
// unconditionally, accepts the naive HTTP/2 CONNECT + padding protocol)
// is real and served by this driver; the matching client is naiveproxy
// (BSD-3-Clause, vendorable as an external core — a cores wave) or a
// sing-box rebuild with the tag.
var singBoxClientBlocked = map[string]bool{
	"naive": true,
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
	// OVERNIGHT-A3 per-protocol knobs (all optional unless the protocol
	// demands them — see singboxValidateParams):
	Obfs string `json:"obfs,omitempty"` // hysteria v1 obfs password (plain string upstream)
	// shadowtls: the camouflage TLS site the handshake completes with
	// (ShadowTLSHandshakeOptions.server — upstream docs use a real TLS
	// site; version 1-3, default 3). The INNER shadowsocks credentials
	// ride ss_method + ss_password (the shadowtls layer's own secret is
	// Password — one params object drives both layers).
	ShadowTLSHandshake string `json:"shadowtls_handshake,omitempty"` // host:port
	ShadowTLSVersion   int    `json:"shadowtls_version,omitempty"`   // default 3
	SSPassword         string `json:"ss_password,omitempty"`         // shadowtls inner shadowsocks password
	// snell: version 6 default (inbound enum 5,6 / outbound 4,6 — the
	// driver pairs 6↔6; option/snell.go).
	SnellVersion int `json:"snell_version,omitempty"`
	// tor: the operator-supplied tor daemon path (protocol/tor uses bine,
	// which spawns it; DataDirectory rides under the engine dir).
	TorExecPath string `json:"tor_exec_path,omitempty"`
	// naive (server half): the HTTP Basic username (auth.User).
	NaiveUsername string `json:"naive_username,omitempty"`
	// tailscale: the tailnet auth key (required), plus optional knobs.
	TailscaleAuthKey   string `json:"tailscale_auth_key,omitempty"`
	TailscaleStateDir  string `json:"tailscale_state_dir,omitempty"`
	TailscaleHostname  string `json:"tailscale_hostname,omitempty"`
	TailscaleEphemeral bool   `json:"tailscale_ephemeral,omitempty"`
	TailscaleExitNode  string `json:"tailscale_exit_node,omitempty"`
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
	proto := strings.ToLower(strings.TrimSpace(p.Protocol))
	switch proto {
	case "masque":
		// sing-box has NO masque protocol at all (v1.14.4 — grep-proven;
		// the gost masque service is the honest equivalent). Fail with
		// the pointer, never a silent accept.
		return fmt.Errorf("singbox: protocol masque does not exist in sing-box (any version) — use engine:gost service=masque (HTTP/3 CONNECT-UDP/CONNECT)")
	}
	// tor/tailscale do not ride a host-to-host carrier socket.
	if !singBoxNoCarrier(proto) {
		if _, _, e := net.SplitHostPort(p.ServerAddr); e != nil {
			return fmt.Errorf("singbox: server_addr must be host:port")
		}
	}
	if !singBoxProtocols[proto] {
		return fmt.Errorf("singbox: protocol %q not supported (shadowsocks|vless|vmess|trojan|hysteria2|hysteria|tuic|anytls|shadowtls|snell|naive|tor|tailscale)", p.Protocol)
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
		if p.SSPassword != "" {
			return fmt.Errorf("singbox: ss_password is only valid with protocol shadowtls (the inner shadowsocks layer)")
		}
	case "vless", "vmess":
		if err := engineVerifySecretShape("singbox uuid", p.UUID, 16, 64); err != nil {
			return err
		}
		if p.Password != "" || p.SSMethod != "" || p.SSPassword != "" {
			return fmt.Errorf("singbox: password/ss_method are dead weight for protocol %s", proto)
		}
	case "trojan", "anytls":
		if err := engineVerifySecretShape("singbox password", p.Password, 8, 128); err != nil {
			return err
		}
		if p.UUID != "" || p.SSMethod != "" || p.SSPassword != "" {
			return fmt.Errorf("singbox: uuid/ss_method are dead weight for protocol %s", proto)
		}
	case "hysteria2":
		if err := engineVerifySecretShape("singbox password", p.Password, 8, 128); err != nil {
			return err
		}
		if p.UUID != "" || p.SSMethod != "" || p.SSPassword != "" {
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
		if p.SSMethod != "" || p.SSPassword != "" {
			return fmt.Errorf("singbox: ss_method is dead weight for protocol %s", proto)
		}
		if p.Congestion != "" && p.Congestion != "cubic" && p.Congestion != "new_reno" && p.Congestion != "bbr" {
			return fmt.Errorf("singbox: congestion must be cubic|new_reno|bbr (upstream enum)")
		}
	case "hysteria":
		// hysteria v1: auth_str (the shared secret) + optional obfs
		// password; TLS required (QUIC+TLS — checked above).
		if err := engineVerifySecretShape("singbox password", p.Password, 8, 128); err != nil {
			return err
		}
		if p.UUID != "" || p.SSMethod != "" || p.SSPassword != "" {
			return fmt.Errorf("singbox: uuid/ss_method are dead weight for protocol %s", proto)
		}
		if p.Obfs != "" {
			if err := engineVerifySecretShape("singbox obfs", p.Obfs, 1, 128); err != nil {
				return err
			}
		}
		if p.UpMbps < 0 || p.UpMbps > 100000 || p.DownMbps < 0 || p.DownMbps > 100000 {
			return fmt.Errorf("singbox: up_mbps/down_mbps out of range (0 = unset)")
		}
	case "shadowtls":
		// shadowtls wraps an inner shadowsocks pair: BOTH ss_method and
		// password are the INNER ss credentials; the shadowtls password is
		// Password? No — the shadowtls layer needs its own secret. The
		// driver pairs: shadowtls password = p.Password, inner ss
		// credentials = p.SSMethod + p.SSPassword (both required — one
		// params object drives both layers).
		if err := engineVerifySecretShape("singbox shadowtls password", p.Password, 8, 128); err != nil {
			return err
		}
		if err := engineVerifySecretShape("singbox ss_method (inner)", p.SSMethod, 3, 32); err != nil {
			return err
		}
		if err := engineVerifySecretShape("singbox ss_password (inner)", p.SSPassword, 8, 128); err != nil {
			return err
		}
		if p.UUID != "" {
			return fmt.Errorf("singbox: uuid is dead weight for protocol %s", proto)
		}
		if p.ShadowTLSVersion != 0 && (p.ShadowTLSVersion < 1 || p.ShadowTLSVersion > 3) {
			return fmt.Errorf("singbox: shadowtls_version must be 1-3 (default 3)")
		}
		if p.ShadowTLSHandshake != "" {
			if _, _, e := net.SplitHostPort(p.ShadowTLSHandshake); e != nil || len(p.ShadowTLSHandshake) > 253 ||
				strings.ContainsAny(p.ShadowTLSHandshake, "\"'\n\r ") {
				return fmt.Errorf("singbox: shadowtls_handshake must be a host:port ≤253 chars (the camouflage TLS site)")
			}
		}
	case "snell":
		if err := engineVerifySecretShape("singbox psk", p.Password, 8, 128); err != nil {
			return err
		}
		if p.UUID != "" || p.SSMethod != "" || p.SSPassword != "" {
			return fmt.Errorf("singbox: uuid/ss_method are dead weight for protocol %s", proto)
		}
		if p.SnellVersion != 0 && p.SnellVersion != 6 && p.SnellVersion != 5 {
			return fmt.Errorf("singbox: snell_version must be 5 (obfs) or 6 (default)")
		}
	case "naive":
		// server-half only (see singBoxClientBlocked): the naive INBOUND
		// needs username+password users + TLS (checked above).
		if err := engineVerifySecretShape("singbox naive_username", p.NaiveUsername, 3, 64); err != nil {
			return err
		}
		if err := engineVerifySecretShape("singbox password", p.Password, 8, 128); err != nil {
			return err
		}
		if p.UUID != "" || p.SSMethod != "" || p.SSPassword != "" {
			return fmt.Errorf("singbox: uuid/ss_method are dead weight for protocol %s", proto)
		}
	case "tor":
		if p.TorExecPath == "" || len(p.TorExecPath) > 256 ||
			strings.ContainsAny(p.TorExecPath, "\"'`\n\r$;&|<> ") {
			return fmt.Errorf("singbox: tor_exec_path must be a ≤256-char path without quotes/shell metacharacters/whitespace (the tor daemon binary sing-box's tor outbound drives)")
		}
		if p.Password != "" || p.UUID != "" || p.SSMethod != "" || p.SSPassword != "" {
			return fmt.Errorf("singbox: password/uuid/ss_method are dead weight for protocol %s", proto)
		}
		if p.LocalMode != "proxy" {
			return fmt.Errorf("singbox: protocol tor is outbound-only (the tor network IS the target) — local_mode must be proxy")
		}
	case "tailscale":
		if err := engineVerifySecretShape("singbox tailscale_auth_key", p.TailscaleAuthKey, 16, 256); err != nil {
			return err
		}
		if p.Password != "" || p.UUID != "" || p.SSMethod != "" || p.SSPassword != "" {
			return fmt.Errorf("singbox: password/uuid/ss_method are dead weight for protocol %s", proto)
		}
		if p.TailscaleHostname != "" && (len(p.TailscaleHostname) > 63 || !gostHostnameSafe(p.TailscaleHostname)) {
			return fmt.Errorf("singbox: tailscale_hostname must be a hostname-safe ≤63-char label")
		}
		if p.TailscaleExitNode != "" && (len(p.TailscaleExitNode) > 253 || strings.ContainsAny(p.TailscaleExitNode, "\"'\n\r ")) {
			return fmt.Errorf("singbox: tailscale_exit_node must be a ≤253-char tailnet host or IP")
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
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","server_addr":"0.0.0.0:8388","protocol":"shadowsocks|vless|vmess|trojan|hysteria2|hysteria|tuic|anytls|shadowtls|snell|naive|tor|tailscale","uuid":"","password":"","ss_method":"aes-256-gcm","up_mbps":0,"down_mbps":0,"congestion":"cubic|new_reno|bbr","tls_cert":"","tls_key":"","sni":"","insecure":false,"local_mode":"proxy|forward","local_port":0,"forward_addr":"host:port","obfs":"","shadowtls_handshake":"www.apple.com:443","shadowtls_version":3,"snell_version":6,"tor_exec_path":"","naive_username":"","tailscale_auth_key":"","tailscale_state_dir":"","tailscale_hostname":"","tailscale_ephemeral":false,"tailscale_exit_node":""}`)}
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
	// OVERNIGHT-A3: the naive inbound's auth.User (username+password) and
	// the hysteria v1 user's auth_str.
	Username string `json:"username,omitempty"`
	AuthStr  string `json:"auth_str,omitempty"`
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

// sbHandshake is the shadowtls inbound's camouflage handshake target
// (ShadowTLSHandshakeOptions = ServerOptions).
type sbHandshake struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
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
	// OVERNIGHT-A3: the chained-inbound detour (shadowtls inbound → the
	// inner shadowsocks inbound — docs/configuration/shared/listen.md
	// #detour: "connections will be forwarded to the specified inbound").
	Detour string `json:"detour,omitempty"`
	// server-side protocol fields
	Users []sbUser `json:"users,omitempty"`
	TLS   *sbTLS   `json:"tls,omitempty"`
	Obfs  any      `json:"obfs,omitempty"`
	// OVERNIGHT-A3 protocol fields (all cited from the upstream option
	// structs: HysteriaInboundOptions.Obfs string, ShadowTLSInboundOptions
	// version/password/handshake, SnellInboundOptions version/psk,
	// TorOutboundOptions executable_path, TailscaleEndpointOptions).
	Version        int          `json:"version,omitempty"`
	PSK            string       `json:"psk,omitempty"`
	Handshake      *sbHandshake `json:"handshake,omitempty"`
	ExecutablePath string       `json:"executable_path,omitempty"`
	DataDirectory  string       `json:"data_directory,omitempty"`
	AuthKey        string       `json:"auth_key,omitempty"`
	StateDirectory string       `json:"state_directory,omitempty"`
	Hostname       string       `json:"hostname,omitempty"`
	Ephemeral      bool         `json:"ephemeral,omitempty"`
	ExitNode       string       `json:"exit_node,omitempty"`
	// client-side dial fields
	Server            string `json:"server,omitempty"`
	ServerPort        uint16 `json:"server_port,omitempty"`
	UUID              string `json:"uuid,omitempty"`
	Security          string `json:"security,omitempty"`
	Method            string `json:"method,omitempty"`
	Password          string `json:"password,omitempty"`
	AuthStr           string `json:"auth_str,omitempty"` // hysteria v1 outbound AuthString
	UpMbps            int    `json:"up_mbps,omitempty"`
	DownMbps          int    `json:"down_mbps,omitempty"`
	CongestionControl string `json:"congestion_control,omitempty"`
}

// sbEndpoint is one endpoints[] entry (v1.14.4 endpoint registry:
// wireguard/openvpn/tailscale — the tailscale endpoint joins the
// tailnet; DERP relay is built in).
type sbEndpoint struct {
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	AuthKey        string `json:"auth_key"`
	StateDirectory string `json:"state_directory,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	Ephemeral      bool   `json:"ephemeral,omitempty"`
	ExitNode       string `json:"exit_node,omitempty"`
}

type sbRouteRule struct {
	Inbound  []string `json:"inbound,omitempty"`
	Outbound string   `json:"outbound,omitempty"`
}

type sbConfig struct {
	Inbounds  []sbEntry     `json:"inbounds"`
	Outbounds []sbEntry     `json:"outbounds"`
	Endpoints []sbEndpoint  `json:"endpoints,omitempty"`
	Route     *sbRouteBlock `json:"route,omitempty"`
}

type sbRouteBlock struct {
	Rules []sbRouteRule `json:"rules,omitempty"`
}

// singboxRenderConfig builds the end's config for the chosen protocol.
// The carrier listen is server_addr's port; the client dials server_addr.
func singboxRenderConfig(role string, p singboxParams) sbConfig {
	proto := strings.ToLower(strings.TrimSpace(p.Protocol))
	var cPort uint64
	if !singBoxNoCarrier(proto) {
		_, carrierPort, _ := net.SplitHostPort(p.ServerAddr)
		cPort, _ = strconv.ParseUint(carrierPort, 10, 16)
	}
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
		// OVERNIGHT-A3: shadowtls's server side is a CHAINED INBOUND pair
		// (the shadowtls inbound's detour feeds the decrypted inner stream
		// into the inner shadowsocks inbound — docs listen.md #detour).
		if proto == "shadowtls" {
			innerPort := cPort + 1
			if innerPort > 65535 {
				innerPort = cPort - 1
			}
			ssIn := sbEntry{Type: "shadowsocks", Tag: "ss-inner",
				Listen: "127.0.0.1", ListenPort: uint16(innerPort),
				Method: p.SSMethod, Password: p.SSPassword}
			stlsVer := p.ShadowTLSVersion
			if stlsVer == 0 {
				stlsVer = 3
			}
			hs := "www.apple.com"
			hsPort := uint64(443)
			if p.ShadowTLSHandshake != "" {
				h, hp, _ := net.SplitHostPort(p.ShadowTLSHandshake)
				hs = h
				hsPort, _ = strconv.ParseUint(hp, 10, 16)
			}
			stlsIn := sbEntry{Type: "shadowtls", Tag: "carrier-in",
				Listen: "0.0.0.0", ListenPort: uint16(cPort),
				Version: stlsVer, Password: p.Password,
				Handshake: &sbHandshake{Server: hs, ServerPort: uint16(hsPort)},
				Detour:    "ss-inner"}
			cfg.Inbounds = []sbEntry{ssIn, stlsIn}
			cfg.Outbounds = []sbEntry{{Type: "direct", Tag: "direct-out"}}
			return cfg
		}
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
		case "hysteria":
			// HysteriaInboundOptions: users[].auth_str + obfs (plain
			// string) + up/down Mbps.
			in.Users = []sbUser{{Name: "quantum", AuthStr: p.Password}}
			if p.Obfs != "" {
				in.Obfs = p.Obfs
			}
			if p.UpMbps > 0 || p.DownMbps > 0 {
				in.UpMbps, in.DownMbps = p.UpMbps, p.DownMbps
			}
		case "snell":
			// SnellInboundOptions: version (5 obfs / 6 v6) + psk.
			ver := p.SnellVersion
			if ver == 0 {
				ver = 6
			}
			in.Version, in.PSK = ver, p.Password
		case "naive":
			// NaiveInboundOptions: users (auth.User username/password).
			in.Users = []sbUser{{Username: p.NaiveUsername, Password: p.Password}}
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
		// tailscale: BOTH ends join the tailnet via the endpoint; on the
		// server the endpoint accepts tailnet connections whose default
		// route target is the direct outbound above.
		if proto == "tailscale" {
			cfg.Endpoints = []sbEndpoint{singboxTailscaleEndpoint(p)}
		}
		return cfg
	}
	// CLIENT (iran): dial out through the protocol outbound. OVERNIGHT-A3:
	// shadowtls nests the inner ss outbound INSIDE the shadowtls outbound
	// (the ss outbound's detour = the shadowtls tag — DialerOptions.detour
	// chains the dial); tor/tailscale have no carrier outbound at all.
	if proto == "shadowtls" {
		stlsVer := p.ShadowTLSVersion
		if stlsVer == 0 {
			stlsVer = 3
		}
		stlsOut := sbEntry{Type: "shadowtls", Tag: "stls-wrap",
			Server:     p.ServerAddr[:strings.LastIndex(p.ServerAddr, ":")],
			ServerPort: uint16(cPort),
			Version:    stlsVer, Password: p.Password}
		// the inner ss outbound dials the SERVER-side inner listener
		// (127.0.0.1:innerPort — the shadowtls tunnel delivers the stream
		// to the chained ss-in regardless of the dial address).
		innerPort := cPort + 1
		if innerPort > 65535 {
			innerPort = cPort - 1
		}
		ssOut := sbEntry{Type: "shadowsocks", Tag: "carrier-out",
			Server: "127.0.0.1", ServerPort: uint16(innerPort),
			Method: p.SSMethod, Password: p.SSPassword,
			Detour: "stls-wrap"}
		outbounds := []sbEntry{ssOut, stlsOut}
		return singboxClientIngress(p, cfg, outbounds, nil)
	}
	if proto == "tor" {
		// tor outbound: bine spawns the operator's tor daemon; the ingress
		// exits INTO the tor network (outbound-only upstream — there is no
		// tor server to host).
		torOut := sbEntry{Type: "tor", Tag: "tor-out",
			ExecutablePath: p.TorExecPath,
			DataDirectory:  filepath.Join(singboxEngineDir(), "tor-data")}
		return singboxClientIngress(p, cfg, []sbEntry{torOut}, nil)
	}
	if proto == "tailscale" {
		// the endpoint joins the tailnet; the route rule targets its tag
		// (endpoints are outbound-manager dialables in v1.11+ — box.go
		// constructs the outbound manager WITH the endpoint manager, and
		// protocol/tailscale/endpoint.go implements the outbound
		// interfaces).
		epTag := "ts-ep"
		cfg.Endpoints = []sbEndpoint{singboxTailscaleEndpoint(p)}
		host, fPort, _ := net.SplitHostPort(p.ForwardAddr)
		fp, _ := strconv.ParseUint(fPort, 10, 16)
		var ingress sbEntry
		var rules []sbRouteRule
		if p.LocalMode == "proxy" {
			ingress = sbEntry{Type: "mixed", Tag: "ingress-in",
				Listen: "127.0.0.1", ListenPort: uint16(p.LocalPort)}
			rules = []sbRouteRule{{Inbound: []string{"ingress-in"}, Outbound: epTag}}
		} else {
			ingress = sbEntry{Type: "direct", Tag: "forward-in",
				Listen: "127.0.0.1", ListenPort: uint16(p.LocalPort),
				OverrideAddress: host, OverridePort: uint16(fp)}
			rules = []sbRouteRule{{Inbound: []string{"forward-in"}, Outbound: epTag}}
		}
		cfg.Inbounds = []sbEntry{ingress}
		cfg.Outbounds = []sbEntry{{Type: "direct", Tag: "direct-out"}}
		cfg.Route = &sbRouteBlock{Rules: rules}
		return cfg
	}
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
	case "hysteria":
		// HysteriaOutboundOptions: auth_str + obfs string + up/down.
		out.AuthStr = p.Password
		if p.Obfs != "" {
			out.Obfs = p.Obfs
		}
		if p.UpMbps > 0 {
			out.UpMbps = p.UpMbps
		}
		if p.DownMbps > 0 {
			out.DownMbps = p.DownMbps
		}
	case "snell":
		ver := p.SnellVersion
		if ver == 0 {
			ver = 6
		}
		out.Version, out.PSK = ver, p.Password
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
	return singboxClientIngress(p, cfg, []sbEntry{out}, nil)
}

// singboxClientIngress renders the client-end ingress around the given
// outbounds (the FIRST outbound is sing-box's default route — proxy mode
// has exactly one route target, forward mode pins its rule to the
// outbound tagged "carrier-out"). extraRules ride after the ingress rule.
func singboxClientIngress(p singboxParams, cfg sbConfig, outbounds []sbEntry, extraRules []sbRouteRule) sbConfig {
	if p.LocalMode == "proxy" {
		cfg.Inbounds = []sbEntry{{Type: "mixed", Tag: "ingress-in",
			Listen: "127.0.0.1", ListenPort: uint16(p.LocalPort)}}
		// the single outbound is the default route: everything through
		// the tunnel (no direct fallback — no leak).
		cfg.Outbounds = outbounds
		return cfg
	}
	host, fPort, _ := net.SplitHostPort(p.ForwardAddr)
	fp, _ := strconv.ParseUint(fPort, 10, 16)
	cfg.Inbounds = []sbEntry{{Type: "direct", Tag: "forward-in",
		Listen: "127.0.0.1", ListenPort: uint16(p.LocalPort),
		OverrideAddress: host, OverridePort: uint16(fp)}}
	cfg.Outbounds = append(outbounds, sbEntry{Type: "direct", Tag: "direct-out"})
	rules := []sbRouteRule{{Inbound: []string{"forward-in"}, Outbound: "carrier-out"}}
	cfg.Route = &sbRouteBlock{Rules: append(rules, extraRules...)}
	return cfg
}

// singboxTailscaleEndpoint renders the tailscale endpoint
// (TailscaleEndpointOptions — with_tailscale is ON in the vendored
// build; the state directory lives under the engine dir unless the
// operator overrides it).
func singboxTailscaleEndpoint(p singboxParams) sbEndpoint {
	stateDir := p.TailscaleStateDir
	if stateDir == "" {
		stateDir = filepath.Join(singboxEngineDir(), "tailscale-state")
	}
	return sbEndpoint{Type: "tailscale", Tag: "ts-ep",
		AuthKey:        p.TailscaleAuthKey,
		StateDirectory: stateDir,
		Hostname:       p.TailscaleHostname,
		Ephemeral:      p.TailscaleEphemeral,
		ExitNode:       p.TailscaleExitNode,
	}
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
	// OVERNIGHT-A3: the naive CLIENT half cannot run in the vendored
	// build (the outbound is cronet-gated — with_naive_outbound excluded
	// because cronet-go ships no arm64 library). The server half (the
	// naive INBOUND, registered unconditionally) is real and rendered
	// below; the client end fails with the typed pointer instead of
	// pretending.
	proto := strings.ToLower(strings.TrimSpace(p.Protocol))
	if role == "client" && singBoxClientBlocked[proto] {
		return fmt.Errorf("singbox: protocol %s has no client half in the vendored sing-box build (with_naive_outbound is cronet-gated and excluded — cronet-go has no arm64 library); the matching client is naiveproxy (BSD-3-Clause, vendorable external core — cores wave) or a sing-box rebuild with the tag; the server half IS exposed by this driver", proto)
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
