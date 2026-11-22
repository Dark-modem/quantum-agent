package agent

// gost_driver.go — the gost engine (go-gost/gost v3, MIT — license
// verified from the upstream tree at the pinned release; the release
// tarball itself ships LICENSE) as an engine.Driver per
// 00-ADMIN/ENGINE-GUIDE.md's production checklist. Exec-a-binary.
//
// Tunnel shape (reverse port forwarding, verified against the upstream
// port-forwarding docs — gost.run/en/tutorials/port-forwarding):
//
//	server (foreign): gost -L "relay+ws://:<carrier>?bind=true"
//	    a Relay service over the ONE carrier (websocket) with the BIND
//	    capability: it accepts the client's registration and opens the
//	    remote-forward listener ON the foreign host.
//	client (Iran):    gost -L "rtcp://:<public>/<localAddr>" -F "relay+ws://<carrier>"
//	    remote-TCP forward: the rtcp listener binds <public> on the
//	    CHAIN END (the foreign host); connections there tunnel back to
//	    localAddr on the Iran machine.
//
// ONE carrier family by design (task scope): ws. wss is rejected at
// Validate with a clear message (TLS cert management is a separate
// slice; fail closed rather than ship an unencrypted-shaped surprise).
//
// OVERNIGHT-A gap-close update: the carrier allowlist covers the
// cert-free relay carriers of the shipped binary (ws|tcp|dtls|quic|grpc|
// http2|kcp|obfs-http|obfs-tls|ftcp|mws — all verified against the
// upstream cmd/gost/register.go registration list), and mode=tcp|udp
// picks rtcp|rudp.
//
// OVERNIGHT-A2 wave 2: the TLS-family carriers (tls|mtls|h2|http3|h3|
// wt|utls) are exposed through operator cert paths (tls_cert/tls_key —
// the e2e metadata keys certFile/keyFile), ssh/sshd through
// ssh_user/ssh_password (URL userinfo), transport=ss is the
// shadowsocks URL shape (ss_method/ss_password), relay+pht joins the
// plain set, and the ingress param (socks5|http|socks4) flips the data
// port to the IRAN end (local proxy exit through the carrier). The raw
// icmp carrier stays out (CAP_NET_RAW niche; udp2raw's icmp mode covers
// the sealed-carrier shape).
//
// OVERNIGHT-A3 (morning human order — the curated won't-expose verdicts
// are OVERRIDDEN): the five remaining gost service families are exposed
// through the additive `service` param ("" = the historical relay tunnel;
// every previous param keeps its meaning and default). Shapes verified
// against go-gost/x v0.28.1 (the pinned binary's module) + go-gost/docs:
//
//   tap          L2 bridge over UDP frames (docs/tutorials/tuntap.md):
//                server `tap://:<port>?net=<srv>&name=&mtu=&gw=&route=`
//                client `tap://:0/<server>:<port>?net=<cli>&...` — the
//                tap listener IS a UDP-frame service (listener resolves
//                the addr as UDP; frames ride raw UDP, no relay).
//   redirect-tcp transparent TCP proxy (SO_ORIGINAL_DST — handler/
//                redirect/tcp/handler_linux.go): client
//                `redirect://:<port>` + -F relay chain; the host's nat
//                REDIRECT rules are installed by THIS driver, additive
//                and comment-tagged gostdrv-<tunnelid> (upstream's own
//                e2e pre-installs the same rules).
//   redirect-udp UDP transparent proxy (TPROXY — listener_linux.go sets
//                IP_TRANSPARENT+IP_RECVORIGDSTADDR): client `redu://:<port>`
//                + -F relay chain + mangle TPROXY / ip-rule / ip-route
//                rules, same tagged additive discipline.
//   sni          SNI/Host routing proxy (docs/tutorials/protocols/sni.md
//                `gost -L sni://:443`): client `sni://:<port>` + -F relay
//                chain — targets dialed from the foreign end.
//   masque       MASQUE over HTTP/3 (handler/masque doc comment: "must be
//                paired with an HTTP/3 listener (registered as h3)";
//                connectors/masque + dialers/h3-masque docs): server
//                `masque+h3://:port?certFile=&keyFile=` (QUIC+TLS —
//                certs REQUIRED), client
//                `-L socks5://:<port> -F masque+h3-masque://<server>` —
//                CONNECT (TCP) and CONNECT-UDP (RFC 9298) both client-
//                supported upstream.
//
// Strictly typed args (no shell, no config file): the CLI form above is
// fully specified by four typed fields, built with fmt.Sprintf and passed
// as separate exec args — nothing free-form reaches a shell.
//
// Health (the warmup gate, checklist item 11): the rtcp listener on the
// foreign host binds the public port only while the client's relay
// connection is live — a successful dial to 127.0.0.1:<public> on the
// SERVER end proves the tunnel is registered end to end (the same gate
// shape as the rathole driver), retried 0/300/800ms.
//
// Counters: wire = iptables on the carrier port (server end); payload
// stays Unknown (gost v3's trafficStats surface requires the operator's
// API service setup — no per-instance machine-readable stats in the OSS
// binary; verified against the config reference).

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"strings"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const gostID = "gost"

type gostParams struct {
	ServerSide  string `json:"server_side"`  // the end hosting the gost RELAY (foreign)
	Version     string `json:"version"`      // artifact version (cache key)
	Artifact    string `json:"artifact"`     // name template with {arch}
	SHA256Amd   string `json:"sha256_amd64"` // pinned fallback
	SHA256Arm   string `json:"sha256_arm64"`
	SigAmd      string `json:"signature_amd64"`
	SigArm      string `json:"signature_arm64"`
	CarrierAddr string `json:"carrier_addr"` // server: relay+ws listen "0.0.0.0:port"; client: dial "host:port"
	PublicPort  int    `json:"public_port"`  // the PUBLIC data port opened on the foreign host (rtcp)
	LocalAddr   string `json:"local_addr"`   // client-side target "127.0.0.1:port"
	Transport   string `json:"transport"`    // carrier scheme, default ws (see gostAllowedTransports)
	// Mode picks the reverse-forwarding family (OVERNIGHT-A gap-close):
	// "tcp" (default) = rtcp (public TCP port on the foreign host);
	// "udp" = rudp (public UDP port). "" = tcp for backward compat.
	Mode string `json:"mode,omitempty"`
	// OVERNIGHT-A2 additions (all optional; "" preserves the wave-1 shape):
	// operator-cert delivery for the TLS-family carriers (paths land in
	// argv only — never a shell; gost reads them from disk):
	TLSCert string `json:"tls_cert,omitempty"` // certFile metadata (PEM path)
	TLSKey  string `json:"tls_key,omitempty"`  // keyFile metadata (PEM path)
	// SSH-carrier auth (relay+ssh / relay+sshd — gost URL userinfo):
	SSHUser     string `json:"ssh_user,omitempty"`
	SSHPassword string `json:"ssh_password,omitempty"`
	// shadowsocks carrier (transport=ss): the cipher method + password
	// ride the ss:// URL userinfo (e2e-verified shape: handler/connector
	// auth username=<method> password=<secret>).
	SSMethod   string `json:"ss_method,omitempty"`
	SSPassword string `json:"ss_password,omitempty"`
	// uTLS client fingerprint for relay+utls (e2e metadata.fingerprint).
	UTLSFingerprint string `json:"utls_fingerprint,omitempty"`
	// Ingress flips the data-port end: "" (default) = reverse port
	// forwarding (public port on the FOREIGN end, rtcp/rudp); a non-empty
	// value makes the IRAN end run that ingress proxy locally and chain
	// OUT through the carrier (the foreign relay dials arbitrary targets):
	// the classic gost proxy-exit shape.
	Ingress string `json:"ingress,omitempty"` // "" | socks5 | http | socks4
	// OVERNIGHT-A3 service families (all optional; "" = the historical
	// relay tunnel above, fully backward compatible). See the header
	// comment for the upstream-verified shape of each.
	Service string `json:"service,omitempty"` // "" | tap | redirect-tcp | redirect-udp | sni | masque
	// tap service: the two ends' TAP device config (the tap bridge rides
	// raw UDP frames between the devices — docs/tutorials/tuntap.md).
	TapNet         string `json:"tap_net,omitempty"`          // client-end device CIDR, e.g. 10.66.0.1/24
	TapNetServer   string `json:"tap_net_server,omitempty"`   // server-end device CIDR, e.g. 10.66.0.2/24
	TapName        string `json:"tap_name,omitempty"`         // device name (default gost's system preset)
	TapMTU         int    `json:"tap_mtu,omitempty"`          // device MTU (upstream default 1420)
	TapGW          string `json:"tap_gw,omitempty"`           // device gateway IP (optional)
	TapRoute       string `json:"tap_route,omitempty"`        // client-end route CIDRs, comma-separated
	TapRouteServer string `json:"tap_route_server,omitempty"` // server-end route CIDRs
	// redirect-tcp/udp service: the transparent-proxy firewall scope.
	// The gost listener is rendered regardless; the REDIRECT/TPROXY rules
	// are installed ONLY when RedirectIface names an interface (additive,
	// tagged gostdrv-<tunnelid>, recorded-spec teardown — never OUTPUT,
	// so the host's own traffic is never hijacked; documented).
	RedirectIface string `json:"redirect_iface,omitempty"`
	// masque service: optional HTTP Basic auth (handler/masque supports
	// proxy authentication; the client dials with URL userinfo).
	MasqueUser     string `json:"masque_user,omitempty"`
	MasquePassword string `json:"masque_password,omitempty"`
}

// gostAllowedTransports is the relay-carrier allowlist (OVERNIGHT-A
// gap-close + OVERNIGHT-A2 wave 2), mirrored from the shipped binary's
// registration list (upstream cmd/gost/register.go): every entry below
// has a listener package in go-gost/x and composes with the relay
// handler as "relay+<scheme>". Cert-family schemes (tls/mtls/h2/http3/
// h3/wt/utls) are exposed ONLY with operator cert paths (tls_cert/
// tls_key — verified against the e2e metadata keys); ssh/sshd with
// ssh_user/ssh_password; pht is plain (no certs); "ss" is the
// shadowsocks carrier (not a relay+ scheme — its own URL shape).
var gostAllowedTransports = map[string]bool{
	"ws": true, "tcp": true, "dtls": true, "quic": true, "grpc": true,
	"http2": true, "kcp": true, "obfs-http": true, "obfs-tls": true,
	"ftcp": true, "mws": true, "pht": true,
	"tls": true, "mtls": true, "h2": true, "http3": true, "h3": true,
	"wt": true, "utls": true, "ssh": true, "sshd": true, "ss": true,
}

// gostCertCarriers need certFile/keyFile metadata at the LISTENING (server)
// end. quic-family (http3/h3/wt) are quic+TLS; h2/utls ride TLS too.
var gostCertCarriers = map[string]bool{
	"tls": true, "mtls": true, "h2": true, "http3": true, "h3": true,
	"wt": true, "utls": true,
}

// gostSSHCarriers authenticate through URL userinfo.
var gostSSHCarriers = map[string]bool{
	"ssh": true, "sshd": true,
}

// gostIngressSchemes maps the Ingress param to gost listener schemes.
var gostIngressSchemes = map[string]string{
	"socks5": "socks5", "http": "http", "socks4": "socks4",
}

// gostAllowedServices is the OVERNIGHT-A3 service-family allowlist
// ("" = the historical relay tunnel).
var gostAllowedServices = map[string]bool{
	"": true, "tap": true, "redirect-tcp": true, "redirect-udp": true,
	"sni": true, "masque": true,
}

// gostServiceUDP reports the services whose carrier/listen socket is UDP
// (tap frames ride raw UDP; masque rides QUIC).
func gostServiceUDP(service string) bool {
	return service == "tap" || service == "masque"
}

// gostUDPCarrier reports the transports whose carrier socket is UDP.
func gostUDPCarrier(transport string) bool {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "quic", "kcp", "dtls", "http3", "h3", "wt":
		return true
	}
	return false
}

func (p gostParams) gostArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	arch := strings.ToLower(runtime.GOARCH)
	if !strings.Contains(p.Artifact, "{arch}") {
		return "", "", "", fmt.Errorf("gost: artifact template must contain {arch}")
	}
	name = strings.ReplaceAll(p.Artifact, "{arch}", arch)
	switch arch {
	case "amd64":
		return name, p.SHA256Amd, p.SigAmd, nil
	case "arm64":
		return name, p.SHA256Arm, p.SigArm, nil
	}
	return "", "", "", fmt.Errorf("gost: no artifact pin for GOARCH %q", arch)
}

func gostValidateParams(p gostParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("gost: server_side required")
	}
	if err := backhaulValidateArtifactPins2(p.Version, p.Artifact, p.SHA256Amd, p.SigAmd, p.SHA256Arm, p.SigArm, gostID); err != nil {
		return err
	}
	t := strings.ToLower(strings.TrimSpace(p.Transport))
	if t == "" {
		t = "ws" // historical default (backward compatible)
	}
	if !gostAllowedTransports[t] {
		return fmt.Errorf("gost: transport %q not supported (carrier allowlist: ws|tcp|dtls|quic|grpc|http2|kcp|obfs-http|obfs-tls|ftcp|mws|pht|tls|mtls|h2|http3|h3|wt|utls|ssh|sshd|ss)", p.Transport)
	}
	switch strings.ToLower(strings.TrimSpace(p.Mode)) {
	case "", "tcp", "udp":
	default:
		return fmt.Errorf("gost: mode %q not supported (tcp|udp — rtcp|rudp)", p.Mode)
	}
	// OVERNIGHT-A2: per-carrier requirements + charset discipline for the
	// new params (every one lands in argv or in a gost URL, never a shell).
	needsCert := gostCertCarriers[t]
	if needsCert {
		if strings.TrimSpace(p.TLSCert) == "" || strings.TrimSpace(p.TLSKey) == "" {
			return fmt.Errorf("gost: transport %q is a TLS-family carrier — tls_cert and tls_key (PEM paths on this host) are required", p.Transport)
		}
	}
	for _, a := range []struct{ label, v string }{{"tls_cert", p.TLSCert}, {"tls_key", p.TLSKey}} {
		if a.v != "" && (len(a.v) > 256 || strings.ContainsAny(a.v, "\"'`\n\r$;&|<>")) {
			return fmt.Errorf("gost: %s must be a ≤256-char path without quotes/shell metacharacters", a.label)
		}
	}
	if gostSSHCarriers[t] && (strings.TrimSpace(p.SSHUser) == "" || strings.TrimSpace(p.SSHPassword) == "") {
		return fmt.Errorf("gost: transport %q needs ssh_user and ssh_password", p.Transport)
	}
	for _, a := range []struct{ label, v string }{{"ssh_user", p.SSHUser}, {"ssh_password", p.SSHPassword},
		{"ss_method", p.SSMethod}, {"ss_password", p.SSPassword}, {"utls_fingerprint", p.UTLSFingerprint}} {
		if a.v != "" && (len(a.v) > 128 || strings.ContainsAny(a.v, "\"'@:/\n\r?&#")) {
			return fmt.Errorf("gost: %s must be ≤128 URL-safe chars (no quotes/@/:/?/#)", a.label)
		}
	}
	if t == "ss" {
		if strings.TrimSpace(p.SSMethod) == "" || strings.TrimSpace(p.SSPassword) == "" {
			return fmt.Errorf("gost: transport ss needs ss_method (e.g. aes-256-gcm) and ss_password")
		}
	}
	ing := strings.ToLower(strings.TrimSpace(p.Ingress))
	if ing != "" {
		if _, ok := gostIngressSchemes[ing]; !ok {
			return fmt.Errorf("gost: ingress %q not supported (socks5|http|socks4)", p.Ingress)
		}
	}
	// (the raw icmp carrier is not in the allowlist — the generic error
	// above names the honest alternative)
	svc := strings.ToLower(strings.TrimSpace(p.Service))
	if !gostAllowedServices[svc] {
		return fmt.Errorf("gost: service %q not supported (empty=relay tunnel|tap|redirect-tcp|redirect-udp|sni|masque)", p.Service)
	}
	if ing != "" && svc != "" {
		return fmt.Errorf("gost: ingress and service are mutually exclusive (service %q renders its own data shape)", p.Service)
	}
	// OVERNIGHT-A3 per-service requirements. Every string below lands in
	// a gost URL or an iptables arg — the same CLI-safe charset discipline
	// as the historical params (argv-only exec, never a shell).
	switch svc {
	case "tap":
		// each end needs its own device CIDR; the UDP "carrier" is the tap
		// frame socket (relay params like Transport are unused here).
		if err := gostValidateCIDR("tap_net", p.TapNet); err != nil {
			return err
		}
		if err := gostValidateCIDR("tap_net_server", p.TapNetServer); err != nil {
			return err
		}
		if p.TapName != "" && (len(p.TapName) > 15 || strings.ContainsAny(p.TapName, "\"'/\\\n\r ") ||
			!gostHostnameSafe(p.TapName)) {
			return fmt.Errorf("gost: tap_name must be a ≤15-char device-name-safe string")
		}
		if p.TapMTU != 0 && (p.TapMTU < 576 || p.TapMTU > 9000) {
			return fmt.Errorf("gost: tap_mtu out of range (576-9000; upstream default 1420)")
		}
		if p.TapGW != "" {
			if ip := net.ParseIP(p.TapGW); ip == nil || len(p.TapGW) > 45 || strings.ContainsAny(p.TapGW, "\"'\n\r") {
				return fmt.Errorf("gost: tap_gw must be an IP address")
			}
		}
		if err := gostValidateRouteList("tap_route", p.TapRoute); err != nil {
			return err
		}
		if err := gostValidateRouteList("tap_route_server", p.TapRouteServer); err != nil {
			return err
		}
	case "redirect-tcp", "redirect-udp":
		if p.RedirectIface != "" && (len(p.RedirectIface) > 15 || strings.ContainsAny(p.RedirectIface, "\"'/\\\n\r ;&|$") ||
			!gostHostnameSafe(p.RedirectIface)) {
			return fmt.Errorf("gost: redirect_iface must be a ≤15-char interface name (iptables-safe)")
		}
	case "masque":
		if strings.TrimSpace(p.TLSCert) == "" || strings.TrimSpace(p.TLSKey) == "" {
			return fmt.Errorf("gost: service masque is QUIC+TLS — tls_cert and tls_key are required (the h3 listener terminates TLS)")
		}
		for _, a := range []struct{ label, v string }{{"masque_user", p.MasqueUser}, {"masque_password", p.MasquePassword}} {
			if a.v != "" && (len(a.v) > 128 || strings.ContainsAny(a.v, "\"'@:/\n\r?&#")) {
				return fmt.Errorf("gost: %s must be ≤128 URL-safe chars (no quotes/@/:/?/#)", a.label)
			}
		}
	}
	if _, port, err := net.SplitHostPort(strings.TrimSpace(p.CarrierAddr)); err != nil || port == "" {
		return fmt.Errorf("gost: carrier_addr must be host:port")
	}
	if p.CarrierAddr != strings.TrimSpace(p.CarrierAddr) || strings.ContainsAny(p.CarrierAddr, "\"'\\\n\r") {
		return fmt.Errorf("gost: carrier_addr not CLI-safe")
	}
	// public_port: required by the relay tunnel (rtcp/rudp listen) and by
	// the redirect/sni/masque local service port; unused by tap (both ends
	// bind the carrier UDP socket from carrier_addr).
	needPublic := svc == "" || svc == "redirect-tcp" || svc == "redirect-udp" || svc == "sni" || svc == "masque"
	if needPublic && (p.PublicPort <= 0 || p.PublicPort > 65535) {
		return fmt.Errorf("gost: public_port out of range")
	}
	// local_addr is the tunnel shape's client-side target only — the
	// redirect/sni/masque services dial arbitrary targets through the
	// relay and tap has no L4 target at all.
	if svc == "" {
		if _, _, err := net.SplitHostPort(strings.TrimSpace(p.LocalAddr)); err != nil ||
			p.LocalAddr != strings.TrimSpace(p.LocalAddr) || strings.ContainsAny(p.LocalAddr, "\"'\\\n\r") {
			return fmt.Errorf("gost: local_addr must be a CLI-safe host:port")
		}
	}
	return nil
}

// gostHostnameSafe reports a hostname/iface/device-name-safe charset.
func gostHostnameSafe(s string) bool {
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.'
		if !ok {
			return false
		}
	}
	return true
}

// gostValidateCIDR checks an addr/CIDR param for the tap device config.
func gostValidateCIDR(label, v string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("gost: %s required (the tap device's addr/CIDR, e.g. 10.66.0.1/24)", label)
	}
	if len(v) > 43 || strings.ContainsAny(v, "\"\\\n\r ") {
		return fmt.Errorf("gost: %s must be a ≤43-char CIDR without quotes/whitespace", label)
	}
	if _, _, err := net.ParseCIDR(v); err != nil {
		if ip := net.ParseIP(v); ip == nil {
			return fmt.Errorf("gost: %s must be a CIDR or IP", label)
		}
	}
	return nil
}

// gostValidateRouteList checks a comma-separated CIDR route list.
func gostValidateRouteList(label, v string) error {
	if v == "" {
		return nil
	}
	if len(v) > 256 || strings.ContainsAny(v, "\"'\\\n\r ") {
		return fmt.Errorf("gost: %s must be ≤256 chars of comma-separated CIDRs without quotes/whitespace", label)
	}
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(part); err != nil {
			return fmt.Errorf("gost: %s entry %q must be a CIDR", label, part)
		}
	}
	return nil
}

func gostResolveRole(p gostParams) (string, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("gost: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return "server", nil
	}
	return "client", nil
}

// gostInstState is one RUNNING instance's state. The proc/stop/binPath
// base rides the shared engineInst (A1); cfg stays empty (args-form —
// no config file is written or removed).
type gostInstState struct {
	engineInst
	params gostParams
	role   string
}

// GostDriver implements engine.Driver for gost v3.
type GostDriver struct {
	runs *instTable[gostInstState]
}

func NewGostDriver() *GostDriver {
	return &GostDriver{runs: newInstTable[gostInstState]()}
}

func (d *GostDriver) ID() string { return gostID }

func (d *GostDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: gostID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","carrier_addr":"0.0.0.0:23344","public_port":0,"local_addr":"127.0.0.1:5201","transport":"ws|tcp|dtls|quic|grpc|http2|kcp|obfs-http|obfs-tls|ftcp|mws|pht|tls|mtls|h2|http3|h3|wt|utls|ssh|sshd|ss","mode":"tcp|udp","tls_cert":"","tls_key":"","ssh_user":"","ssh_password":"","ss_method":"aes-256-gcm","ss_password":"","utls_fingerprint":"chrome","ingress":"","service":"|tap|redirect-tcp|redirect-udp|sni|masque","tap_net":"10.66.0.1/24","tap_net_server":"10.66.0.2/24","tap_name":"","tap_mtu":1420,"tap_gw":"","tap_route":"","redirect_iface":"","masque_user":"","masque_password":""}`)}
}

func (d *GostDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *GostDriver) Validate(params json.RawMessage) error {
	var p gostParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("gost: engine_params: %w", err)
	}
	return gostValidateParams(p)
}

func gostEngineDir() string {
	return engineEngineDir(gostID)
}

// gostEnsureBinary: manifest-first (engine "gost"), pinned fallback.
func gostEnsureBinary(ctx context.Context, p gostParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("gost: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.gostArtifactPin(); pinErr == nil && engineCacheHit(gostBinDir(p.Version), pinnedSHA, []string{"gost"}) {
		return gostBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("gost: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, gostID,
		func() (string, string, string, error) { return p.gostArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := gostBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"gost"}) {
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
		return "", fmt.Errorf("gost: cache dir: %w", err)
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"gost": true}); err != nil {
		return "", err
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("gost: cache marker: %w", err)
	}
	return dir, nil
}

func gostBinDir(version string) string {
	return filepath.Join(gostEngineDir(), "bin", version)
}

// gostSpawn runs gost with its typed args (the config is the ARG LIST —
// no shell, no free-form file).
var gostSpawn = func(binPath string, args []string) (frpProcess, error) {
	cmd := exec.Command(binPath, args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("gost: start: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

// gostCarrierScheme resolves the end's carrier scheme: the validated
// transport, defaulting to the historical "ws" (backward compatible —
// the empty string was and stays ws).
func gostCarrierScheme(p gostParams) string {
	t := strings.ToLower(strings.TrimSpace(p.Transport))
	if t == "" {
		return "ws"
	}
	return t
}

// gostURLQuery builds the metadata query string for one end of the
// carrier URL (OVERNIGHT-A2): cert paths for the TLS family, the uTLS
// fingerprint on the dialing end, and the relay bind flag. Values are
// charset-validated upstream of this point (gostValidateParams) — plain
// concatenation is safe because argv-only exec never re-parses a shell.
func gostURLQuery(role, transport string, p gostParams) string {
	var q []string
	// bind=true arms the relay for reverse (rtcp/rudp) listeners; in
	// ingress mode and the redirect/sni services the client chains OUT
	// (no reverse registration), so the server is a plain relay — no bind.
	isIngress := gostIngressSchemes[strings.ToLower(strings.TrimSpace(p.Ingress))] != ""
	svc := strings.ToLower(strings.TrimSpace(p.Service))
	if role == "server" && transport != "ss" && !isIngress && svc != "redirect-tcp" && svc != "redirect-udp" && svc != "sni" {
		q = append(q, "bind=true")
	}
	if gostCertCarriers[transport] {
		q = append(q, "certFile="+p.TLSCert, "keyFile="+p.TLSKey)
	}
	if transport == "utls" && role != "server" {
		fp := strings.ToLower(strings.TrimSpace(p.UTLSFingerprint))
		if fp == "" {
			fp = "chrome"
		}
		q = append(q, "fingerprint="+fp)
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + strings.Join(q, "&")
}

// gostHostPort renders the address part of a gost URL for one end:
// server binds the carrier port; client dials the full carrier_addr.
func gostHostPort(role, transport string, p gostParams) string {
	port := enginePortOf(p.CarrierAddr)
	if transport == "ss" {
		// ss://method:pass@addr
		if role == "server" {
			return fmt.Sprintf("%s:%s@:%d", p.SSMethod, p.SSPassword, port)
		}
		return fmt.Sprintf("%s:%s@%s", p.SSMethod, p.SSPassword, strings.TrimSpace(p.CarrierAddr))
	}
	if role == "server" {
		if gostSSHCarriers[transport] {
			return fmt.Sprintf("%s:%s@:%d", p.SSHUser, p.SSHPassword, port)
		}
		return fmt.Sprintf(":%d", port)
	}
	if gostSSHCarriers[transport] {
		return fmt.Sprintf("%s:%s@%s", p.SSHUser, p.SSHPassword, strings.TrimSpace(p.CarrierAddr))
	}
	return strings.TrimSpace(p.CarrierAddr)
}

// gostArgs renders the end's strictly-typed CLI. OVERNIGHT-A2: TLS-family
// carriers carry certFile/keyFile (and the utls client fingerprint) in
// the URL query; transport=ss swaps the relay composition for the
// shadowsocks URL shape; ingress modes replace the client's rtcp/rudp
// listener with the local ingress proxy (the classic gost exit shape).
// OVERNIGHT-A3: the service families take over the whole render (see the
// header comment for each shape's upstream citation).
func gostArgs(role, transport string, p gostParams) []string {
	switch strings.ToLower(strings.TrimSpace(p.Service)) {
	case "tap":
		return gostTapArgs(role, p)
	case "redirect-tcp", "redirect-udp":
		return gostRedirectArgs(role, transport, p)
	case "sni":
		return gostSNIArgs(role, transport, p)
	case "masque":
		return gostMasqueArgs(role, p)
	}
	host := gostHostPort(role, transport, p)
	q := gostURLQuery(role, transport, p)
	if role == "server" {
		if transport == "ss" {
			return []string{"-L", "ss://" + host}
		}
		return []string{"-L", fmt.Sprintf("relay+%s://%s%s", transport, host, q)}
	}
	fwd := "rtcp"
	if strings.EqualFold(strings.TrimSpace(p.Mode), "udp") {
		fwd = "rudp"
	}
	listen := fmt.Sprintf("%s://:%d/%s", fwd, p.PublicPort, strings.TrimSpace(p.LocalAddr))
	if ing, ok := gostIngressSchemes[strings.ToLower(strings.TrimSpace(p.Ingress))]; ok {
		// ingress mode: the public port binds on THIS (client) end as the
		// local proxy; traffic chains OUT through the carrier.
		listen = fmt.Sprintf("%s://:%d", ing, p.PublicPort)
	}
	forward := fmt.Sprintf("relay+%s://%s", transport, host)
	if transport == "ss" {
		forward = "ss://" + host
	}
	// the client end's own metadata rides the forward URL (utls
	// fingerprint; cert params are server-side only and were appended
	// to the server's URL by the caller above).
	if transport == "utls" {
		fp := strings.ToLower(strings.TrimSpace(p.UTLSFingerprint))
		if fp == "" {
			fp = "chrome"
		}
		forward += "?fingerprint=" + fp
	}
	return []string{"-L", listen, "-F", forward}
}

// ---- OVERNIGHT-A3 service families --------------------------------------

// gostTapQuery renders the shared tap metadata (docs/tutorials/tuntap.md:
// net/name/mtu/gw/route — the tap listener resolves the addr as UDP and
// bridges the device's frames).
func gostTapQuery(net_ string, p gostParams) string {
	q := []string{"net=" + net_}
	if p.TapName != "" {
		q = append(q, "name="+p.TapName)
	}
	if p.TapMTU > 0 {
		q = append(q, "mtu="+fmt.Sprint(p.TapMTU))
	}
	if p.TapGW != "" {
		q = append(q, "gw="+p.TapGW)
	}
	return strings.Join(q, "&")
}

// gostTapArgs renders the L2 tap bridge: the server binds the UDP frame
// socket (`tap://:port?...`), the client's device forwards its frames to
// the server's socket (`tap://:0/server:port?...` — the URL path IS the
// upstream forward target).
func gostTapArgs(role string, p gostParams) []string {
	host := strings.TrimSpace(p.CarrierAddr)
	port := enginePortOf(p.CarrierAddr)
	if role == "server" {
		q := gostTapQuery(p.TapNetServer, p)
		if p.TapRouteServer != "" {
			q += "&route=" + p.TapRouteServer
		}
		return []string{"-L", fmt.Sprintf("tap://:%d?%s", port, q)}
	}
	q := gostTapQuery(p.TapNet, p)
	if p.TapRoute != "" {
		q += "&route=" + p.TapRoute
	}
	return []string{"-L", fmt.Sprintf("tap://:0/%s?%s", host, q)}
}

// gostRedirectArgs renders the transparent-proxy services: the client
// runs the red/redu listener locally and chains OUT through the relay
// (the SO_ORIGINAL_DST/TPROXY original destination is dialed from the
// foreign end); the server stays a plain relay (no bind — no reverse
// registration, same semantics as ingress mode).
func gostRedirectArgs(role, transport string, p gostParams) []string {
	scheme := "redirect"
	if strings.EqualFold(strings.TrimSpace(p.Service), "redirect-udp") {
		scheme = "redu"
	}
	if role == "server" {
		return []string{"-L", fmt.Sprintf("relay+%s://:%d", transport, enginePortOf(p.CarrierAddr))}
	}
	listen := fmt.Sprintf("%s://:%d", scheme, p.PublicPort)
	forward := fmt.Sprintf("relay+%s://%s", transport, strings.TrimSpace(p.CarrierAddr))
	return []string{"-L", listen, "-F", forward}
}

// gostSNIArgs renders the SNI/Host routing proxy (docs/tutorials/
// protocols/sni.md `gost -L sni://:443` — handler sni on the tcp
// listener): the client routes by ClientHello SNI / HTTP Host and dials
// the target through the relay chain.
func gostSNIArgs(role, transport string, p gostParams) []string {
	if role == "server" {
		return []string{"-L", fmt.Sprintf("relay+%s://:%d", transport, enginePortOf(p.CarrierAddr))}
	}
	return []string{"-L", fmt.Sprintf("sni://:%d", p.PublicPort),
		"-F", fmt.Sprintf("relay+%s://%s", transport, strings.TrimSpace(p.CarrierAddr))}
}

// gostMasqueArgs renders the MASQUE-over-HTTP/3 pair. LAB-VERIFIED
// (2026-11-22, gost v3.3.3 in netns): the registry name "h3" is the PHT
// listener in x v0.28.1 and 404s every CONNECT — the masque-capable
// HTTP/3 listener (the one that injects the http.Request/ResponseWriter
// metadata handler/masque consumes, listener/http3/listener.go
// handleFunc) registers as "http3". The handler/masque doc comment's
// "registered as h3" is stale upstream. Server:
// `masque+http3://:port?certFile=&keyFile=` (QUIC+TLS, operator cert
// pair in the URL query); client `socks5://:<port>` →
// `-F masque+h3-masque://server:port` (connectors/masque +
// dialers/h3-masque; CONNECT-TCP + CONNECT-UDP both client-supported).
// Optional HTTP Basic auth rides URL userinfo on both ends; secure=false
// skips operator-cert verification (self-signed pairs are the norm here).
func gostMasqueArgs(role string, p gostParams) []string {
	host := strings.TrimSpace(p.CarrierAddr)
	var userinfo string
	if p.MasqueUser != "" {
		userinfo = p.MasqueUser + ":" + p.MasquePassword + "@"
	}
	if role == "server" {
		return []string{"-L", fmt.Sprintf("masque+http3://%s:%d?certFile=%s&keyFile=%s",
			userinfo, enginePortOf(p.CarrierAddr), p.TLSCert, p.TLSKey)}
	}
	return []string{"-L", fmt.Sprintf("socks5://:%d", p.PublicPort),
		"-F", fmt.Sprintf("masque+h3-masque://%s%s?secure=false", userinfo, host)}
}

// Start implements engine.Driver.
func (d *GostDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p gostParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("gost: engine_params: %w", err)
	}
	if err := gostValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("gost: invalid tunnel id %q", inst.TunnelID)
	}
	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual[gostParams](prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}

	role, err := gostResolveRole(p)
	if err != nil {
		return err
	}
	binDir, err := gostEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "gost")
	proc, err := gostSpawn(binPath, gostArgs(role, gostCarrierScheme(p), p))
	if err != nil {
		return err
	}
	st := &gostInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		binPath: binPath}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, st.binPath, "", func(b, _ string) (frpProcess, error) {
		return gostSpawn(b, gostArgs(st.role, gostCarrierScheme(st.params), st.params))
	})
	if role == "server" {
		if port := enginePortOf(p.CarrierAddr); port > 0 {
			proto := "tcp"
			if gostUDPCarrier(p.Transport) || gostServiceUDP(strings.ToLower(strings.TrimSpace(p.Service))) {
				proto = "udp"
			}
			if err := acctWireRulesAddProto(acctChainsDriver, inst.TunnelID, port, port, proto); err != nil {
				fmt.Fprintf(os.Stderr, "gost: wire accounting unavailable: %v\n", err)
			}
		}
	}
	// OVERNIGHT-A3: the transparent-proxy firewall leg lives on the CLIENT
	// end (the red/redu listener + the iptables REDIRECT/TPROXY rules are
	// a pair). Install only when the operator scoped an interface.
	if role == "client" && p.RedirectIface != "" {
		svc := strings.ToLower(strings.TrimSpace(p.Service))
		if svc == "redirect-tcp" || svc == "redirect-udp" {
			if err := gostRedirectRulesAdd(inst.TunnelID, svc, p.RedirectIface, p.PublicPort); err != nil {
				fmt.Fprintf(os.Stderr, "gost: redirect rules unavailable: %v\n", err)
			}
		}
	}
	return nil
}

// supervise was the local copy of the capped-backoff supervisor; A1
// deleted it — Start calls the shared engineSupervise directly (same
// 2s→15s backoff, same re-rendered args on respawn, Stop closes the
// stop channel first).

// Stop implements engine.Driver: the shared teardown order (cfg stays
// empty for the args-form driver — nothing to remove), with the server
// end's carrier-port accounting rule as the driver-specific hook.
func (d *GostDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.role == "server" {
			if port := enginePortOf(st.params.CarrierAddr); port > 0 {
				proto := "tcp"
				if gostUDPCarrier(st.params.Transport) || gostServiceUDP(strings.ToLower(strings.TrimSpace(st.params.Service))) {
					proto = "udp"
				}
				_ = acctWireRulesDelProto(acctChainsDriver, inst.TunnelID, port, port, proto)
			}
		}
		// the redirect firewall leg mirrors the process (client end).
		if st.role == "client" && st.params.RedirectIface != "" {
			svc := strings.ToLower(strings.TrimSpace(st.params.Service))
			if svc == "redirect-tcp" || svc == "redirect-udp" {
				gostRedirectRulesDel(inst.TunnelID, svc, st.params.RedirectIface, st.params.PublicPort)
			}
		}
	})
	return nil
}

// gostHealthDial seams the public-port health dial (the integration test
// routes it through the server namespace).
var gostHealthDial = func(port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

// Health implements engine.Driver: process alive; on the SERVER end the
// rtcp listener binds the public port only while the client's relay
// connection is live — the dial is the end-to-end signal (warmup gate,
// item 11), retried 0/300/800ms.
func (d *GostDriver) Health(inst engine.Instance) engine.Health {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Health{OK: false, Detail: "not running", LatencyMs: -1}
	}
	alive := true
	select {
	case <-st.current().Done():
		alive = false
	default:
	}
	if !alive {
		return engine.Health{OK: false, Detail: "process exited", LatencyMs: -1}
	}
	if st.role != "server" {
		return engine.Health{OK: true, Detail: "gost client running", LatencyMs: -1}
	}
	// rudp (mode=udp) binds a UDP public port — a TCP dial can never prove
	// it; the process-alive check stays the honest signal (OVERNIGHT-A).
	// Ingress mode (OVERNIGHT-A2) binds the public port on the CLIENT end
	// — the server end has no data port to dial; process-alive it is.
	// Service families (OVERNIGHT-A3): tap/masque ride UDP sockets (dial
	// N/A), redirect/sni put the data port on the CLIENT end (plain relay
	// server — dial N/A).
	if strings.EqualFold(strings.TrimSpace(st.params.Mode), "udp") ||
		gostIngressSchemes[strings.ToLower(strings.TrimSpace(st.params.Ingress))] != "" ||
		strings.TrimSpace(st.params.Service) != "" {
		return engine.Health{OK: true, Detail: "gost server running (" + strings.ToLower(strings.TrimSpace(st.params.Service)) + " service; dial gate N/A)", LatencyMs: -1}
	}
	start := time.Now()
	delays := []time.Duration{0, 300 * time.Millisecond, 800 * time.Millisecond}
	var lastErr error
	for _, dl := range delays {
		if dl > 0 {
			time.Sleep(dl)
		}
		if err := gostHealthDial(st.params.PublicPort); err == nil {
			return engine.Health{OK: true, Detail: "gost tunnel registered (public port answering)",
				LatencyMs: float64(time.Since(start).Milliseconds())}
		} else {
			lastErr = err
		}
	}
	return engine.Health{OK: false, Detail: "public port not answering (client not registered): " + lastErr.Error(),
		LatencyMs: float64(time.Since(start).Milliseconds())}
}

// Counters: the SERVER end's wire view (iptables on the carrier port);
// payload stays Unknown (no per-instance machine-readable stats in the
// OSS v3 binary).
func (d *GostDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil || st.role != "server" {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if port := enginePortOf(st.params.CarrierAddr); port > 0 {
		if rx, tx, ok := acctWireBytes(inst.TunnelID, port, port); ok {
			out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
		}
	}
	return out
}

// Uninstall implements engine.Driver.
func (d *GostDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, gostEngineDir())
	return nil
}

// Reload implements engine.Driver: equal params are a no-op, anything
// else is a restart (gost has no live reload).
func (d *GostDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, gostID, inst.TunnelID, inst.Params,
		func(st *gostInstState) gostParams { return st.params }, engineParamsEqual[gostParams])
}
