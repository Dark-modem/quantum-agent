package agent

// xray_driver.go — the Xray-core engine (VLESS + Reality, candidate #2
// from ENGINE-CANDIDATES.md) as an engine.Driver. See
// 00-ADMIN/ENGINE-XRAY-DESIGN.md for the topology: the FOREIGN end is the
// Xray server (VLESS+Reality inbound + dokodemo-door per forwarded port),
// the IRAN end is the Xray client (vless outbound dialing OUT with
// Reality settings + freedom outbound to the embedded destination).
//
// Production shape (ENGINE-GUIDE.md PRODUCTION CHECKLIST): release-style
// tarball with directory entries, role resolution via the enrollment
// name, supervisor with capped backoff, per-instance counters (wire from
// nftables on the carrier port; payload from Xray's StatsService per
// direction), Uninstall on idle, R5 manifest delivery with pinned
// fallback. The Reality private key is a SECRET: 0600 instance config
// only, never logged/audited/reported (asserted in tests). The config is
// rendered through typed structs — no string concatenation of untrusted
// values.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/Dark-modem/quantum-agent/internal/infra"

	"strings"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const xrayID = "xray"

type xrayParams struct {
	ServerSide        string `json:"server_side"`        // foreign end name (hosts the Xray server)
	Version           string `json:"version"`            // artifact version (cache key)
	Artifact          string `json:"artifact"`           // name TEMPLATE with {arch}
	SHA256Amd         string `json:"sha256_amd64"`       // pinned fallback
	SHA256Arm         string `json:"sha256_arm64"`       // pinned fallback
	SigAmd            string `json:"signature_amd64"`    // pinned fallback
	SigArm            string `json:"signature_arm64"`    // pinned fallback
	RemoteAddr        string `json:"remote_addr"`        // foreign public host (carrier + dokodemo)
	CarrierPort       int    `json:"carrier_port"`       // foreign VLESS+Reality port
	PublicPort        int    `json:"public_port"`        // foreign dokodemo port (forwarded service)
	LocalAddr         string `json:"local_addr"`         // Iran-side target host
	LocalPort         int    `json:"local_port"`         // Iran-side target port
	ServerName        string `json:"server_name"`        // Reality SNI (camouflage handshake)
	Dest              string `json:"dest"`               // Reality camouflage target host:port
	ShortID           string `json:"short_id"`           // Reality shortId (hex, <=16 chars)
	RealityPublicKey  string `json:"reality_public_key"` // base64url x25519 public
	RealityPrivateKey string `json:"reality_private_key"`
	Flow              string `json:"flow"`     // e.g. xtls-rprx-vision
	UUID              string `json:"uuid"`     // VLESS user id
	APIPort           int    `json:"api_port"` // loopback StatsService port (server end; 0 = off)
	// Transport picks the carrier under REALITY (OVERNIGHT-A gap-close):
	// upstream infra/conf/transport_internet.go TransportProtocol.Build —
	// REALITY supports RAW(tcp), XHTTP and gRPC only. Default tcp (the
	// historical shape). ws/httpupgrade are upstream-deprecated AND not
	// reality-capable; tls/other protocols are the cert-bound next wave.
	Transport string `json:"transport,omitempty"`
	// XHTTPPath is the xhttpSettings path (default "/"; both ends must
	// match — the panel sends one params object to both ends).
	XHTTPPath string `json:"xhttp_path,omitempty"`
	// GrpcServiceName is the grpcSettings serviceName (default
	// "quantum-reverse"; both ends must match).
	GrpcServiceName string `json:"grpc_service_name,omitempty"`
	// OVERNIGHT-A5: the carrier family. "" (default) = the historical
	// VLESS+Reality bridge/portal reverse topology — every existing param
	// keeps its meaning. "hysteria2" = the QUIC carrier pair (probe-proven
	// on the vendored v26.3.27 core: hysteria2 inbound+outbound
	// Configuration OK; the v24.12.31 core rejects protocol hysteria — the
	// cores upgrade ships xray-v26.3.27 as latest): SERVER (foreign)
	// renders the hysteria2 inbound (version 2, users auth, QUIC+TLS) +
	// freedom outbound (dials requested targets from its network); CLIENT
	// (iran) renders the hysteria2 outbound (version 2, auth) + the local
	// socks/http inbounds riding it (SocksPort/HTTPPort). The Reality/
	// dokodemo/reverse machinery does NOT render in this family (dead
	// fields are refused — fail closed).
	// OVERNIGHT-A8: the carrier family is ONE shared params object for
	// three mutually exclusive renderings — "" (default) = the historical
	// VLESS+Reality bridge/portal reverse topology, "hysteria2" = the QUIC
	// proxy-exit pair (OVERNIGHT-A5), "masque" = the MASQUE/HTTP3 proxy-exit
	// pair. Every param of the OTHER families is dead weight on a carrier
	// and REFUSED (one cross-product table — see xrayRefuseDead).
	Carrier string `json:"carrier,omitempty"` // "" | hysteria2 | masque
	// hysteria2 carrier auth (the shared password; HysteriaUserConfig.auth).
	HysteriaAuth string `json:"hysteria_auth,omitempty"`
	// tls_cert/tls_key are PEM PATHS on the host that renders the server
	// end (repo convention: gost_driver.go, hysteria_driver.go,
	// singbox_driver.go) — the hysteria2 and masque inbounds are TLS.
	// Required by both carriers (the masque render passes them verbatim as
	// tlsSettings.certificates[].certificateFile/keyFile — upstream
	// infra/conf/transport_security.go:248-258). Dead on the Reality
	// carrier (Reality needs no certificate).
	TLSCert string `json:"tls_cert,omitempty"` // certificateFile (absolute PEM path)
	TLSKey  string `json:"tls_key,omitempty"`  // keyFile (absolute PEM path)
	// OVERNIGHT-A8: the masque carrier knobs (upstream 74cbdf4 — the
	// probe-proven shapes on the v26.11.9 core; citations in the validate
	// and render blocks):
	//   masque_email + masque_pass = settings.users[] (upstream
	//   MasqueServerConfig: non-empty, no ':'); the email+pass ALSO ride the
	//   client's masqueSettings.user/pass — the only source of the HTTP
	//   Basic Authorization header the inbound demands;
	//   masque_address = settings.address[] — REQUIRED upstream: the masque
	//   TUN context prefix whose address must be a HOST address
	//   (10.127.8.1/24, never 10.127.8.0/24 or .255/24);
	//   masque_host = masqueSettings.host, the HTTP authority (default =
	//   the dial address; it is also the client's tlsSettings.serverName);
	//   masque_mtu = settings.mtu (0 = upstream default 1280; else
	//   1280..65535); masque_remote_dns = the client's settings.remoteDNS
	//   (bare IPs; upstream default = Cloudflare 1.1.1.1/1.0.0.1/…).
	// All dead on the other carriers.
	MasqueEmail string `json:"masque_email,omitempty"`
	MasquePass  string `json:"masque_pass,omitempty"` // SECRET — 0600 config only
	MasqueHost  string `json:"masque_host,omitempty"`
	MasqueMTU   int    `json:"masque_mtu,omitempty"`
	// MasqueAddress is REQUIRED for carrier masque (server-side TUN
	// context, a host prefix such as 10.127.8.1/24).
	MasqueAddress string `json:"masque_address,omitempty"`
	// MasqueRemoteDNS is optional (client-side bare IPs, comma-separated).
	MasqueRemoteDNS string `json:"masque_remote_dns,omitempty"`
	// pin_sha256 = the client's tlsSettings.pinnedPeerCertSha256 — REQUIRED
	// for carrier masque: allowInsecure is a REMOVED upstream feature and
	// without a pin Xray verifies against the system roots, which a
	// self-signed pair never passes. A STRING upstream (never an array,
	// never base64): comma-separated, ':' stripped (OpenSSL format), hex,
	// exactly 32 bytes per entry = the SHA-256 of the certificate's DER
	// (`openssl x509 -in cert.pem -outform DER | sha256sum`). A LEAF pin is
	// accepted at once; a CA pin verifies the chain against it and needs
	// serverName. Dead on the other carriers.
	PinSHA256 string `json:"pin_sha256,omitempty"`
	// OVERNIGHT-A3 (morning human order): optional SOCKS/HTTP ingress
	// inbounds on the CLIENT end. Probe-proven against the vendored
	// v24.12.31 binary (`xray run -test` accepts protocol socks with
	// auth noauth + udp true, and protocol http — Configuration OK).
	// 0 = off (default — the historical shape). Traffic rides the carrier
	// outbound (route rules pin the inbounds to it; no direct fallback —
	// nothing leaks). The SERVER end never renders them (the Iran
	// proxy-exit shape is the only useful direction).
	SocksPort int `json:"socks_port,omitempty"`
	HTTPPort  int `json:"http_port,omitempty"`
}

// xrayAllowedTransports mirrors the REALITY-capable upstream transports
// (transport_internet.go: "REALITY only supports RAW, XHTTP and gRPC").
var xrayAllowedTransports = map[string]bool{
	"": true, "tcp": true, "xhttp": true, "grpc": true,
}

func (p xrayParams) xrayArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	return enginePinForArch(EnginePin{Version: p.Version, Artifact: p.Artifact,
		SHA256Amd: p.SHA256Amd, SHA256Arm: p.SHA256Arm, SigAmd: p.SigAmd, SigArm: p.SigArm})
}

// ---- carrier families: the ONE cross-product dead-field table (A8 G6) ----
//
// xrayParams is ONE shared object for three mutually exclusive renderings:
// "" (the VLESS+Reality reverse topology), "hysteria2" (the QUIC proxy-exit
// pair, A5) and "masque" (the MASQUE/HTTP3 proxy-exit pair, A8). A param
// that belongs to ANOTHER family never renders on this carrier — set
// anyway it is a silent misconfiguration (an operator believes a key, a
// cert or a pin is in play while the running config ignores it), so every
// carrier refuses every other family's member: fail closed. Error strings
// carry the LABEL only — masque_pass / tls_key / uuid are secrets.

type xrayDeadField struct {
	label string
	v     string
}

// xrayRealityFields: the Reality/dokodemo family (string members; the int
// members public_port/local_port/api_port/transport are handled in
// xrayRefuseDead, flow globally).
func xrayRealityFields(p xrayParams) []xrayDeadField {
	return []xrayDeadField{
		{"server_name", p.ServerName}, {"dest", p.Dest}, {"short_id", p.ShortID},
		{"reality_public_key", p.RealityPublicKey}, {"reality_private_key", p.RealityPrivateKey},
		{"uuid", p.UUID}, {"local_addr", p.LocalAddr},
	}
}

// xrayHysteriaFields: the hysteria2 family.
func xrayHysteriaFields(p xrayParams) []xrayDeadField {
	return []xrayDeadField{{"hysteria_auth", p.HysteriaAuth}}
}

// xrayTLSFields: the operator PEM path pair (hysteria2 + masque only).
func xrayTLSFields(p xrayParams) []xrayDeadField {
	return []xrayDeadField{{"tls_cert", p.TLSCert}, {"tls_key", p.TLSKey}}
}

// xrayMasqueFields: the masque family (string members; masque_mtu is an
// int, handled in xrayRefuseDead).
func xrayMasqueFields(p xrayParams) []xrayDeadField {
	return []xrayDeadField{
		{"masque_email", p.MasqueEmail}, {"masque_pass", p.MasquePass}, {"masque_host", p.MasqueHost},
		{"masque_address", p.MasqueAddress}, {"masque_remote_dns", p.MasqueRemoteDNS},
		{"pin_sha256", p.PinSHA256},
	}
}

// xrayCarrierFamily normalizes the carrier param ("" = reality-reverse).
func xrayCarrierFamily(p xrayParams) string {
	return strings.ToLower(strings.TrimSpace(p.Carrier))
}

// xrayMasque reports the masque carrier.
func xrayMasque(p xrayParams) bool { return xrayCarrierFamily(p) == "masque" }

// xrayCarrierLabel names a normalized carrier in error strings.
func xrayCarrierLabel(carrier string) string {
	if carrier == "" {
		return "reality-reverse"
	}
	return carrier
}

// xrayRefuseDead fails closed on every OTHER family's member set on this
// carrier: the string members through the table above, plus the int
// members — public_port/local_port and the transport sub-params ride the
// Reality inbound only, api_port renders the StatsService API on the
// Reality server end only (on the proxy-exit carriers nothing listens
// there yet Health would probe it — never healthy), masque_mtu rides the
// masque inbound only. An unknown carrier is refused here too.
func xrayRefuseDead(carrier string, p xrayParams) error {
	var dead []xrayDeadField
	switch carrier {
	case "":
		dead = append(xrayHysteriaFields(p), xrayTLSFields(p)...)
		dead = append(dead, xrayMasqueFields(p)...)
	case "hysteria2":
		dead = append(xrayRealityFields(p), xrayMasqueFields(p)...)
	case "masque":
		dead = append(xrayRealityFields(p), xrayHysteriaFields(p)...)
	default:
		return fmt.Errorf("xray: carrier %q not supported (empty=reality-reverse | hysteria2 | masque)", p.Carrier)
	}
	for _, f := range dead {
		if strings.TrimSpace(f.v) != "" {
			return fmt.Errorf("xray: %s is dead weight for carrier %s (it does not render there — fail closed)", f.label, xrayCarrierLabel(carrier))
		}
	}
	if carrier != "" {
		if p.PublicPort != 0 || p.LocalPort != 0 {
			return fmt.Errorf("xray: public_port/local_port are dead weight for carrier %s (the client's socks_port/http_port are the ingress)", carrier)
		}
		for _, f := range []xrayDeadField{{"transport", p.Transport}, {"xhttp_path", p.XHTTPPath}, {"grpc_service_name", p.GrpcServiceName}} {
			if strings.TrimSpace(f.v) != "" {
				return fmt.Errorf("xray: %s is dead weight for carrier %s (it rides the Reality inbound only)", f.label, carrier)
			}
		}
		if p.APIPort != 0 {
			return fmt.Errorf("xray: api_port is dead weight for carrier %s (no StatsService inbound renders — Health would probe nothing)", carrier)
		}
	}
	if carrier != "masque" && p.MasqueMTU != 0 {
		return fmt.Errorf("xray: masque_mtu is dead weight for carrier %s", xrayCarrierLabel(carrier))
	}
	return nil
}

// xrayVerifyPEMPaths bounds the operator cert/key PATHS like the sibling
// drivers (gost_driver.go / singbox_driver.go: <=256 chars, no quotes or
// shell metacharacters) and requires an ABSOLUTE path — Xray resolves a
// relative certificateFile/keyFile against its own working directory,
// never what the operator meant.
func xrayVerifyPEMPaths(p xrayParams) error {
	for _, a := range []struct{ label, v string }{{"tls_cert", p.TLSCert}, {"tls_key", p.TLSKey}} {
		v := strings.TrimSpace(a.v)
		if len(v) > 256 || strings.ContainsAny(v, "\"'`\\\n\r$;&|<>") {
			return fmt.Errorf("xray: %s must be a <=256-char PEM path without quotes or shell metacharacters", a.label)
		}
		if !strings.HasPrefix(v, "/") {
			return fmt.Errorf("xray: %s must be an ABSOLUTE PEM path on the host that renders it (Xray resolves relative paths against its own working directory)", a.label)
		}
	}
	return nil
}

// xrayMasqueHost resolves the HTTP authority: explicit masque_host, else
// the dial address.
func xrayMasqueHost(p xrayParams) string {
	if h := strings.TrimSpace(p.MasqueHost); h != "" {
		return h
	}
	return strings.TrimSpace(p.RemoteAddr)
}

// xrayMasqueTLSName is the TLS serverName for the client end. The HTTP
// authority may carry a port (masqueSettings.host is passed through to
// the :authority), but a TLS ServerName never may: strip the port and the
// IPv6 brackets, or Go's TLS handshake rejects the name before the pin is
// checked.
func xrayMasqueTLSName(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}

// xrayMasqueHostOK mirrors upstream MasqueConfig.Build
// (infra/conf/transport_method.go:846-849): the host must round-trip
// url.Parse("https://"+host) with u.Host == host (no scheme, path,
// userinfo), plus the driver's shape discipline (<=253, no quotes or
// whitespace — it rides the JSON config and the TLS serverName).
func xrayMasqueHostOK(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "\"'\\\n\r\t ") {
		return false
	}
	u, err := url.Parse("https://" + host)
	return err == nil && u.Host == host
}

// xrayParsePin mirrors upstream TLSConfig.Build (infra/conf/
// transport_security.go:365-380): comma-separated entries, whitespace
// trimmed, ':' stripped (OpenSSL format), hex-decoded, exactly 32 bytes
// each; empty entries are skipped. Returns the entry count. REQUIRED for
// carrier masque: allowInsecure is a REMOVED feature and without a pin
// Xray verifies against the system roots — a self-signed pair never
// passes (transport/internet/tls/config.go:396-405). A LEAF pin (the
// SHA-256 of the certificate's DER) is accepted at once (:299-305); a CA
// pin verifies the chain against it and needs serverName (:306-311).
func xrayParsePin(pin string) (int, error) {
	n := 0
	for _, v := range strings.Split(pin, ",") {
		v = strings.ReplaceAll(strings.TrimSpace(v), ":", "")
		if v == "" {
			continue
		}
		raw, err := hex.DecodeString(v)
		if err != nil {
			return 0, fmt.Errorf("xray: pin_sha256 entry %d is not hex (the OpenSSL ':' format and either hex case are accepted; never base64)", n+1)
		}
		if len(raw) != 32 {
			return 0, fmt.Errorf("xray: pin_sha256 entry %d must decode to exactly 32 bytes (64 hex chars — the SHA-256 of the certificate's DER)", n+1)
		}
		n++
	}
	if n == 0 {
		return 0, errors.New("xray: pin_sha256 is required for carrier masque (allowInsecure was removed upstream; a self-signed pair only passes with pinnedPeerCertSha256 = the hex SHA-256 of the certificate's DER)")
	}
	return n, nil
}

// xrayMasqueAddressOK mirrors upstream proxy/masque/pool.go:20-38
// (newAddressPool): a valid CIDR prefix whose address is a plain IPv4/IPv6
// HOST address — not the network address, not the IPv4 broadcast, no
// v4-in-v6, no zone — and which leaves at least one assignable address.
// infra/conf/masque.go:84-97 additionally REQUIRES address (non-empty) and
// allows at most one v4 + one v6 prefix (one is rendered — trivially met).
func xrayMasqueAddressOK(s string) error {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return errors.New("xray: masque_address is required and must be a CIDR prefix such as 10.127.8.1/24 (the server's masque TUN context)")
	}
	server := prefix.Addr()
	if server.Is4In6() || server.Zone() != "" {
		return errors.New("xray: masque_address must be a plain IPv4 or IPv6 host prefix (no v4-in-v6, no zone)")
	}
	masked := prefix.Masked()
	last := xrayPrefixLast(masked)
	if server == masked.Addr() || (server.Is4() && server == last) {
		return errors.New("xray: masque_address must be a HOST address inside its prefix, not the network or broadcast address (e.g. 10.127.8.1/24, never 10.127.8.0/24 or 10.127.8.255/24)")
	}
	if server.Is4() {
		last = last.Prev()
	}
	if masked.Addr().Next() == last {
		return errors.New("xray: masque_address leaves no addresses to assign (use a prefix of /30 or shorter for IPv4, /127 or shorter for IPv6)")
	}
	return nil
}

// xrayPrefixLast is pool.go lastAddr: the prefix's last address.
func xrayPrefixLast(prefix netip.Prefix) netip.Addr {
	b := prefix.Addr().AsSlice()
	for i := prefix.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr
}

// xrayValidateMasque is the masque carrier's own contract (upstream
// 74cbdf4; every rule cites its file:line — see the params block for the
// field semantics). Runs AFTER xrayRefuseDead cleared the other families.
func xrayValidateMasque(p xrayParams) error {
	if strings.TrimSpace(p.TLSCert) == "" || strings.TrimSpace(p.TLSKey) == "" {
		return errors.New("xray: carrier masque is TLS — tls_cert and tls_key are required (PEM paths on the foreign host: tlsSettings.certificates[].certificateFile/keyFile)")
	}
	if err := xrayVerifyPEMPaths(p); err != nil {
		return err
	}
	if err := engineVerifySecretShape("xray masque_pass", p.MasquePass, 8, 128); err != nil {
		return err
	}
	// masque.go:64-77: non-empty, no ':' (it is also masqueSettings.user,
	// the HTTP Basic name — transport_method.go:874-883). NO '@' rule
	// upstream; the shape discipline is the driver's (JSON/log safety).
	if p.MasqueEmail == "" || len(p.MasqueEmail) > 128 || strings.Contains(p.MasqueEmail, ":") ||
		strings.ContainsAny(p.MasqueEmail, "\"'\\\n\r\t ") {
		return errors.New("xray: masque_email must be a 1-128 char string without ':', quotes, backslash or whitespace (upstream MasqueServerConfig: non-empty, no ':'; it also rides masqueSettings.user as the HTTP Basic name)")
	}
	if _, err := xrayParsePin(p.PinSHA256); err != nil {
		return err
	}
	if err := xrayMasqueAddressOK(p.MasqueAddress); err != nil {
		return err
	}
	// masque.go:99-101 (dialer.go:31 MinPacketSize): 0 or 1280..65535.
	if p.MasqueMTU != 0 && (p.MasqueMTU < 1280 || p.MasqueMTU > 65535) {
		return errors.New("xray: masque_mtu must be 0 (upstream default 1280) or between 1280 and 65535")
	}
	if strings.TrimSpace(p.RemoteAddr) == "" || strings.ContainsAny(p.RemoteAddr, "\"'\\\n\r ") {
		return errors.New("xray: remote_addr required for carrier masque (the foreign dial address)")
	}
	if !xrayMasqueHostOK(xrayMasqueHost(p)) {
		return errors.New("xray: masque_host must be a host[:port] authority without scheme, path, userinfo or whitespace (<=253 chars)")
	}
	// masque.go:27-32: each remoteDNS entry must netip.ParseAddr.
	for _, s := range strings.Split(p.MasqueRemoteDNS, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if _, err := netip.ParseAddr(s); err != nil {
			return errors.New("xray: masque_remote_dns entries must be bare IP addresses, comma-separated (upstream: netip.ParseAddr)")
		}
	}
	if p.SocksPort == 0 && p.HTTPPort == 0 {
		return errors.New("xray: carrier masque needs socks_port or http_port (the iran-end ingress)")
	}
	return nil
}

// xrayValidateParams checks the union shape. Secrets are shape-checked
// only (printable ASCII, bounded) — never logged with their value.
func xrayValidateParams(p xrayParams) error {
	// The carrier family gate (OVERNIGHT-A5/A8): every carrier refuses the
	// other families' members (xrayRefuseDead — one cross-product table),
	// then applies its own contract.
	carrier := xrayCarrierFamily(p)
	switch carrier {
	case "":
		if err := xrayRefuseDead(carrier, p); err != nil {
			return err
		}
	case "masque":
		if err := xrayRefuseDead(carrier, p); err != nil {
			return err
		}
		if err := xrayValidateMasque(p); err != nil {
			return err
		}
	case "hysteria2":
		if strings.TrimSpace(p.TLSCert) == "" || strings.TrimSpace(p.TLSKey) == "" {
			return fmt.Errorf("xray: carrier hysteria2 is QUIC+TLS — tls_cert and tls_key are required")
		}
		if err := xrayVerifyPEMPaths(p); err != nil {
			return err
		}
		if err := engineVerifySecretShape("xray hysteria_auth", p.HysteriaAuth, 8, 128); err != nil {
			return err
		}
		if err := xrayRefuseDead(carrier, p); err != nil {
			return err
		}
		// the dial host (RemoteAddr doubles as the carrier host here).
		if strings.TrimSpace(p.RemoteAddr) == "" || strings.ContainsAny(p.RemoteAddr, "\"'\\n\\r\\") {
			return fmt.Errorf("xray: remote_addr required for carrier hysteria2 (the foreign host)")
		}
		// the client needs an ingress or the tunnel carries nothing.
		if p.SocksPort == 0 && p.HTTPPort == 0 {
			return fmt.Errorf("xray: carrier hysteria2 needs socks_port or http_port (the iran-end ingress)")
		}
	default:
		return fmt.Errorf("xray: carrier %q not supported (empty=reality-reverse | hysteria2 | masque)", p.Carrier)
	}
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("xray: server_side required")
	}
	if strings.TrimSpace(p.Version) == "" || len(p.Version) > 64 ||
		strings.ContainsAny(p.Version, "/\\\"' \t\n\r") {
		return fmt.Errorf("xray: version must be 1-64 safe chars")
	}
	if !strings.Contains(p.Artifact, "{arch}") || strings.ContainsAny(p.Artifact, " \t\n\r\"\\") {
		return fmt.Errorf("xray: artifact must be a name template containing {arch}")
	}
	for _, a := range []struct{ sha, sig string }{{p.SHA256Amd, p.SigAmd}, {p.SHA256Arm, p.SigArm}} {
		if len(a.sha) != 64 || strings.ContainsAny(a.sha, " \t\n\r") {
			return fmt.Errorf("xray: sha256 pin must be 64 hex chars")
		}
		if len(a.sig) < 64 || len(a.sig) > 512 || strings.ContainsAny(a.sig, " \t\n\r") {
			return fmt.Errorf("xray: signature pin must be base64 (64-512 chars)")
		}
	}
	// CarrierPort is the carrier listen/dial port on ALL families.
	if p.CarrierPort <= 0 || p.CarrierPort > 65535 {
		return fmt.Errorf("xray: carrier_port out of range")
	}
	// The Reality/dokodemo family checks run on the DEFAULT carrier only —
	// carrier=hysteria2|masque refuses those fields outright (above).
	if carrier == "" {
		if p.PublicPort <= 0 || p.PublicPort > 65535 {
			return fmt.Errorf("xray: public_port out of range")
		}
		if strings.TrimSpace(p.LocalAddr) == "" || strings.ContainsAny(p.LocalAddr, "\"'\n\r\\") ||
			p.LocalPort <= 0 || p.LocalPort > 65535 {
			return fmt.Errorf("xray: local_addr/local_port invalid")
		}
		if strings.TrimSpace(p.RemoteAddr) == "" || strings.ContainsAny(p.RemoteAddr, "\"'\n\r\\") {
			return fmt.Errorf("xray: remote_addr invalid")
		}
		if err := engineVerifySecretShape("xray server_name", p.ServerName, 1, 253); err != nil {
			return err
		}
		if err := engineVerifySecretShape("xray dest", p.Dest, 3, 253); err != nil {
			return err
		}
		if len(p.ShortID) > 16 || strings.ContainsAny(p.ShortID, "\"'\n\r\\ ") {
			return fmt.Errorf("xray: short_id must be <=16 chars without quotes")
		}
		if _, err := hex.DecodeString(p.ShortID); err != nil && p.ShortID != "" {
			return fmt.Errorf("xray: short_id must be hex")
		}
		if err := engineVerifySecretShape("xray reality_public_key", p.RealityPublicKey, 32, 64); err != nil {
			return err
		}
		if err := engineVerifySecretShape("xray reality_private_key", p.RealityPrivateKey, 32, 64); err != nil {
			return err
		}
		if err := engineVerifySecretShape("xray uuid", p.UUID, 16, 64); err != nil {
			return err
		}
	}
	if strings.Contains(p.Flow, "\"") || strings.Contains(p.Flow, "\n") || len(p.Flow) > 64 {
		return fmt.Errorf("xray: flow invalid")
	}
	// OVERNIGHT-A transport allowlist (REALITY-capable only, see the
	// params note) + the per-transport sub-params' charset discipline
	// (both ride the JSON config, so quotes/backslashes are injection).
	switch strings.ToLower(strings.TrimSpace(p.Transport)) {
	case "", "tcp", "xhttp", "grpc":
	default:
		return fmt.Errorf("xray: transport %q not supported under REALITY (tcp|xhttp|grpc; ws/httpupgrade are upstream-deprecated and not reality-capable; tls is the cert-bound next wave)", p.Transport)
	}
	if p.XHTTPPath != "" {
		if len(p.XHTTPPath) > 128 || !strings.HasPrefix(p.XHTTPPath, "/") ||
			strings.ContainsAny(p.XHTTPPath, "\"'\\\n\r ") {
			return fmt.Errorf("xray: xhttp_path must be a /-rooted 1-128 char path without quotes/whitespace")
		}
	}
	if p.GrpcServiceName != "" {
		if len(p.GrpcServiceName) > 64 || strings.ContainsAny(p.GrpcServiceName, "\"'\\\n\r ") {
			return fmt.Errorf("xray: grpc_service_name must be 1-64 chars without quotes/whitespace")
		}
	}
	// The driver's carrier is ALWAYS the bridge/portal reverse link, whose
	// underlying protocol is mux.cool (upstream docs: "the reverse proxy
	// has Mux enabled by default"). Vision flow corrupts the mux.cool
	// framing: with flow=xtls-rprx-vision the reverse channel establishes
	// but DATA STALLS (lab-verified 2026-11-08, xray v24.12.31: vision
	// variant hung, flow-empty variant carried 2.3 Gbit/s). Fail closed.
	if strings.TrimSpace(p.Flow) != "" {
		return fmt.Errorf("xray: flow must be empty — the reverse carrier multiplexes by itself (mux.cool); vision flow stalls all data through it")
	}
	if p.APIPort < 0 || p.APIPort > 65535 {
		return fmt.Errorf("xray: api_port out of range")
	}
	// OVERNIGHT-A3: the optional socks/http ingress ports — in-range and
	// non-colliding with every port this driver already binds.
	for _, a := range []struct {
		label string
		port  int
	}{{"socks_port", p.SocksPort}, {"http_port", p.HTTPPort}} {
		if a.port == 0 {
			continue
		}
		if a.port < 1 || a.port > 65535 {
			return fmt.Errorf("xray: %s out of range (0 = off)", a.label)
		}
		for _, other := range []int{p.CarrierPort, p.PublicPort, p.APIPort, p.APIPort + 1} {
			if other > 0 && other == a.port {
				return fmt.Errorf("xray: %s collides with an already-bound port (%d)", a.label, other)
			}
		}
	}
	return nil
}

// xrayResolveRole resolves this end's role through the enrollment name.
func xrayResolveRole(p xrayParams) (engineSide, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("xray: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return engineSideServer, nil
	}
	return engineSideClient, nil
}

// ---- typed Xray config (marshaled — never string-concatenated) ----

type xrayUser struct {
	ID         string `json:"id"`
	Flow       string `json:"flow,omitempty"`
	Level      int    `json:"level"`
	Encryption string `json:"encryption"`
}

// xrayRealityServer is the Reality decryption block for the VLESS
// inbound (server end): terminate the handshake against the real
// camouflage site; private key NEVER logged.
type xrayRealityServer struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest"`
	Xver        int      `json:"xver"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
}

// xrayRealityClient is the Reality client block for the VLESS outbound
// (Iran end): show=false (no fingerprint leak into logs), SNI pinned.
type xrayRealityClient struct {
	Show        bool   `json:"show"`
	Fingerprint string `json:"fingerprint"`
	ServerName  string `json:"serverName"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	SpiderX     string `json:"spiderX"`
}

type xrayInboundSettings struct {
	Clients        []xrayUser `json:"clients,omitempty"`
	Decryption     string     `json:"decryption,omitempty"`
	Address        string     `json:"address,omitempty"`
	Port           int        `json:"port,omitempty"`
	Network        string     `json:"network,omitempty"`
	FollowRedirect bool       `json:"followRedirect,omitempty"`
	// OVERNIGHT-A3 socks inbound fields (infra/conf/socks.go:
	// SocksServerConfig Auth "noauth"|"password", UDP). The http inbound
	// needs no settings block (HTTPServerConfig is empty by default).
	Auth string `json:"auth,omitempty"`
	UDP  bool   `json:"udp,omitempty"`
}

type xrayStreamSettings struct {
	Network  string               `json:"network"`
	Security string               `json:"security"`
	Reality  *xrayRealityServer   `json:"realitySettings,omitempty"`
	XHTTP    *xrayXHTTPSettings   `json:"xhttpSettings,omitempty"`
	GRPC     *xrayGRPCSettings    `json:"grpcSettings,omitempty"`
	Masque   *xrayMasqueTransport `json:"masqueSettings,omitempty"`
	TLS      *xrayTLSServer       `json:"tlsSettings,omitempty"`
}

// xrayXHTTPSettings is the xhttpSettings block (upstream
// infra/conf/transport_method.go SplitHTTPConfig — path is the field both
// ends must share; everything else keeps upstream defaults).
type xrayXHTTPSettings struct {
	Path string `json:"path,omitempty"`
	Mode string `json:"mode,omitempty"`
}

// xrayGRPCSettings is the grpcSettings block (upstream GRPCConfig —
// serviceName is the field both ends must share).
type xrayGRPCSettings struct {
	ServiceName string `json:"serviceName,omitempty"`
}

type xraySockopt struct {
	Mark int `json:"mark,omitempty"`
}

type xrayInbound struct {
	Tag      string `json:"tag"`
	Listen   string `json:"listen"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	// Settings carries the per-protocol inbound settings:
	// *xrayInboundSettings for vless/socks/http/dokodemo,
	// *xrayHysteriaInboundSettings for the hysteria carrier (OVERNIGHT-A5).
	Settings       any                 `json:"settings,omitempty"`
	StreamSettings *xrayStreamSettings `json:"streamSettings,omitempty"`
	Sniffing       *xraySniffing       `json:"sniffing,omitempty"`
}

type xraySniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride,omitempty"`
}

type xrayOutboundSettings struct {
	Vnext    []xrayVnext            `json:"vnext,omitempty"`
	Address  string                 `json:"address,omitempty"`
	Port     int                    `json:"port,omitempty"`
	Response *xrayBlackholeResponse `json:"response,omitempty"`
}

// xrayBlackholeResponse is the blackhole outbound's optional answer
// ({"response":{"type":"http"}} answers probes with an HTTP 403).
type xrayBlackholeResponse struct {
	Type string `json:"type"`
}

type xrayVnext struct {
	Address string     `json:"address"`
	Port    int        `json:"port"`
	Users   []xrayUser `json:"users"`
}

type xrayStreamClient struct {
	Network  string               `json:"network"`
	Security string               `json:"security"`
	Reality  *xrayRealityClient   `json:"realitySettings,omitempty"`
	XHTTP    *xrayXHTTPSettings   `json:"xhttpSettings,omitempty"`
	GRPC     *xrayGRPCSettings    `json:"grpcSettings,omitempty"`
	Masque   *xrayMasqueTransport `json:"masqueSettings,omitempty"`
	TLS      *xrayTLSClient       `json:"tlsSettings,omitempty"`
}

// OVERNIGHT-A8: the masque carrier types (upstream 74cbdf4, probe-proven
// on the v26.11.9 core). proxy/masque/client.go:62-67 + server.go:126-131
// REQUIRE the masque transport AND security "tls" (the TLS checks are
// client.go:67 / server.go:131); the server's tlsSettings carry the
// certificateFile/keyFile pair (infra/conf/transport_security.go:248-258)
// and the client's pinnedPeerCertSha256 is a STRING — allowInsecure was
// REMOVED upstream.
type xrayMasqueTransport struct {
	Host string `json:"host,omitempty"`
	// User/Pass: the HTTP Basic credentials. The inbound ALWAYS demands
	// them (server.go:272-282: BasicAuth → validator.get → 401) and
	// masqueSettings.user/pass is the ONLY source of the Authorization
	// header (transport_method.go:874-883) — rendered on the CLIENT end.
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"` // SECRET — 0600 config only
}

type xrayTLSServer struct {
	Certificates []xrayTLSCert `json:"certificates"`
}

type xrayTLSCert struct {
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
}

type xrayTLSClient struct {
	ServerName           string `json:"serverName,omitempty"`
	PinnedPeerCertSha256 string `json:"pinnedPeerCertSha256,omitempty"`
}

// xrayMasqueInboundSettings is the server-side masque inbound settings
// (infra/conf/masque.go MasqueServerConfig: users email+pass, address =
// the REQUIRED masque TUN context prefixes, mtu 0|1280..65535).
type xrayMasqueInboundSettings struct {
	Users   []xrayMasqueUser `json:"users"`
	Address []string         `json:"address"`
	MTU     uint32           `json:"mtu,omitempty"`
}

type xrayMasqueUser struct {
	Email string `json:"email"`
	Pass  string `json:"pass"`
}

// xrayMasqueOutboundSettings is the client-side masque outbound settings
// (infra/conf/masque.go MasqueClientConfig: address/port required,
// remoteDNS bare IPs — upstream default = Cloudflare when unset).
type xrayMasqueOutboundSettings struct {
	Address   string   `json:"address"`
	Port      int      `json:"port"`
	RemoteDNS []string `json:"remoteDNS,omitempty"`
}

// xrayMasqueRemoteDNS splits the optional comma-separated bare IPs (nil
// when unset — upstream's default DNS list then applies).
func xrayMasqueRemoteDNS(p xrayParams) []string {
	var out []string
	for _, s := range strings.Split(p.MasqueRemoteDNS, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// xrayCarrierTransport resolves the validated carrier transport ("tcp"
// when empty) — the same string rides both ends' streamSettings.network.
func xrayCarrierTransport(p xrayParams) string {
	t := strings.ToLower(strings.TrimSpace(p.Transport))
	if t == "" {
		return "tcp"
	}
	return t
}

// xrayStreamTransport applies the chosen transport to a SERVER-end
// streamSettings (tcp keeps the historical bare shape — no sub-blocks).
func xrayStreamTransport(s *xrayStreamSettings, p xrayParams) {
	s.Network = xrayCarrierTransport(p)
	switch s.Network {
	case "xhttp":
		path := p.XHTTPPath
		if path == "" {
			path = "/"
		}
		s.XHTTP = &xrayXHTTPSettings{Path: path}
	case "grpc":
		name := p.GrpcServiceName
		if name == "" {
			name = "quantum-reverse"
		}
		s.GRPC = &xrayGRPCSettings{ServiceName: name}
	}
}

// xrayStreamClientTransport is the client-end mirror of
// xrayStreamTransport (same fields, client reality struct).
func xrayStreamClientTransport(s *xrayStreamClient, p xrayParams) {
	s.Network = xrayCarrierTransport(p)
	switch s.Network {
	case "xhttp":
		path := p.XHTTPPath
		if path == "" {
			path = "/"
		}
		s.XHTTP = &xrayXHTTPSettings{Path: path}
	case "grpc":
		name := p.GrpcServiceName
		if name == "" {
			name = "quantum-reverse"
		}
		s.GRPC = &xrayGRPCSettings{ServiceName: name}
	}
}

type xrayOutbound struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	// Settings carries the per-protocol settings block: *xrayOutboundSettings
	// for vless/freedom/blackhole, *xrayHysteriaSettings for the hysteria
	// carrier (OVERNIGHT-A5) — exactly one is set per rendered outbound.
	Settings       any               `json:"settings,omitempty"`
	StreamSettings *xrayStreamClient `json:"streamSettings,omitempty"`
	Mux            *xrayMux          `json:"mux,omitempty"`
}

// xrayHysteriaSettings is the hysteria carrier's outbound settings
// (HysteriaClientConfig: version REQUIRED = 2, server address/port, users
// auth) — probe-proven on the vendored v26.3.27 core.
type xrayHysteriaSettings struct {
	Version int                `json:"version"`
	Address string             `json:"address,omitempty"`
	Port    int                `json:"port,omitempty"`
	Users   []xrayHysteriaUser `json:"users,omitempty"`
}

type xrayHysteriaUser struct {
	Auth string `json:"auth"`
}

// xrayHysteriaInboundSettings is the server-side hysteria2 inbound settings
// (HysteriaServerConfig: version REQUIRED = 2, users auth).
type xrayHysteriaInboundSettings struct {
	Version int                `json:"version"`
	Users   []xrayHysteriaUser `json:"users"`
}

type xrayMux struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"`
}

type xrayAPI struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services"`
}

type xrayRoutingRule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

type xrayConfig struct {
	Reverse   *xrayReverse   `json:"reverse,omitempty"`
	Log       *xrayLog       `json:"log,omitempty"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
	Routing   *xrayRouting   `json:"routing,omitempty"`
	API       *xrayAPI       `json:"api,omitempty"`
	Stats     *struct{}      `json:"stats,omitempty"`
	Policy    *xrayPolicy    `json:"policy,omitempty"`
}

type xrayLog struct {
	LogLevel string `json:"loglevel"`
}

type xrayRouting struct {
	DomainStrategy string            `json:"domainStrategy"`
	Rules          []xrayRoutingRule `json:"rules"`
}

type xrayPolicy struct {
	Levels map[string]xrayPolicyLevel `json:"levels"`
	System *xraySystemPolicy          `json:"system,omitempty"`
}

type xrayPolicyLevel struct {
	StatsUserUplink   bool `json:"statsUserUplink,omitempty"`
	StatsUserDownlink bool `json:"statsUserDownlink,omitempty"`
}

// xraySystemPolicy carries the system-scope policy flags. Without
// statsInboundUplink/Downlink, Xray-core's getStatCounter (v24.12.31
// app/proxyman/inbound/always.go) never registers the per-inbound traffic
// counters — statsquery answers with an EMPTY stats list and Counters
// would stay zero even with the API reachable (B-AG4, second half).
type xraySystemPolicy struct {
	StatsInboundUplink   bool `json:"statsInboundUplink"`
	StatsInboundDownlink bool `json:"statsInboundDownlink"`
}

type xrayReverse struct {
	Bridges []xrayBridge `json:"bridges,omitempty"`
	Portals []xrayPortal `json:"portals,omitempty"`
}

type xrayBridge struct {
	Tag    string `json:"tag"`
	Domain string `json:"domain"`
}

type xrayPortal struct {
	Tag    string `json:"tag"`
	Domain string `json:"domain"`
}

// xrayPortalDomain is the internal domain both ends share for the
// reverse channel (it is NOT a DNS name — the routing matches on it).
const xrayPortalDomain = "quantum.rev.internal"

// xrayBuildConfig renders the end's config through typed structs, using
// Xray's NATIVE REVERSE feature (bridge/portal) — the frp-equivalent
// shape: the Iran end (bridge) dials OUT to the foreign portal, keeping
// reverse channels open; public connections on the foreign dokodemo ride
// those channels to the Iran-local service. Role decides which half:
// SERVER (foreign) = portal; CLIENT (iran) = bridge + the vless-out
// carrier with Reality client settings.
func xrayBuildConfig(role engineSide, p xrayParams) xrayConfig {
	// OVERNIGHT-A5: the hysteria2 carrier family (probe-proven on the
	// upgraded v26.3.27 core — hysteria2 inbound+outbound Configuration OK).
	// The QUIC carrier replaces the Reality reverse machinery: SERVER =
	// hysteria2 inbound + freedom (dials requested targets from its
	// network); CLIENT = hysteria2 outbound + the local socks/http
	// inbounds riding it (first-outbound default route).
	if strings.EqualFold(strings.TrimSpace(p.Carrier), "hysteria2") {
		cfg := xrayConfig{Log: &xrayLog{LogLevel: "warning"}}
		if role == engineSideServer {
			cfg.Inbounds = []xrayInbound{{
				Tag: "hysteria-in", Listen: "0.0.0.0", Port: p.CarrierPort, Protocol: "hysteria",
				Settings: &xrayHysteriaInboundSettings{Version: 2,
					Users: []xrayHysteriaUser{{Auth: p.HysteriaAuth}}},
			}}
			cfg.Outbounds = []xrayOutbound{{Tag: "direct", Protocol: "freedom"}}
			return cfg
		}
		cfg.Outbounds = []xrayOutbound{{
			Tag: "carrier-out", Protocol: "hysteria",
			Settings: &xrayHysteriaSettings{Version: 2,
				Address: p.RemoteAddr,
				Port:    p.CarrierPort,
				Users:   []xrayHysteriaUser{{Auth: p.HysteriaAuth}}},
		}}
		cfg.Routing = &xrayRouting{Rules: []xrayRoutingRule{}}
		if p.SocksPort > 0 {
			cfg.Inbounds = append(cfg.Inbounds, xrayInbound{
				Tag: "socks-in", Listen: "127.0.0.1", Port: p.SocksPort, Protocol: "socks",
				Settings: &xrayInboundSettings{Auth: "noauth", UDP: true},
			})
			cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRoutingRule{
				Type: "field", InboundTag: []string{"socks-in"}, OutboundTag: "carrier-out",
			})
		}
		if p.HTTPPort > 0 {
			cfg.Inbounds = append(cfg.Inbounds, xrayInbound{
				Tag: "http-in", Listen: "127.0.0.1", Port: p.HTTPPort, Protocol: "http",
			})
			cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRoutingRule{
				Type: "field", InboundTag: []string{"http-in"}, OutboundTag: "carrier-out",
			})
		}
		return cfg
	}
	// OVERNIGHT-A8: the masque carrier family (upstream 74cbdf4, probe-proven
	// on the v26.11.9 core — proxy/masque/client.go:62-67 + server.go:126-131
	// REQUIRE the masque transport AND security "tls"). SERVER (foreign)
	// = the masque inbound (users email+pass, the REQUIRED address[] TUN
	// context, optional mtu, the TLS certificateFile/keyFile pair) + freedom
	// (dials requested targets from its network); CLIENT (iran) = the masque
	// outbound (address/port, optional remoteDNS, the Basic-auth user/pass,
	// the leaf-DER pin) + the local socks/http inbounds riding it.
	if strings.EqualFold(strings.TrimSpace(p.Carrier), "masque") {
		cfg := xrayConfig{Log: &xrayLog{LogLevel: "warning"}}
		host := xrayMasqueHost(p)
		if role == engineSideServer {
			cfg.Inbounds = []xrayInbound{{
				Tag: "masque-in", Listen: "0.0.0.0", Port: p.CarrierPort, Protocol: "masque",
				Settings: &xrayMasqueInboundSettings{
					Users:   []xrayMasqueUser{{Email: p.MasqueEmail, Pass: p.MasquePass}},
					Address: []string{p.MasqueAddress},
					MTU:     uint32(p.MasqueMTU),
				},
				StreamSettings: &xrayStreamSettings{
					Network: "masque", Security: "tls",
					Masque: &xrayMasqueTransport{Host: host},
					TLS: &xrayTLSServer{Certificates: []xrayTLSCert{{
						CertificateFile: p.TLSCert, KeyFile: p.TLSKey}}},
				},
			}}
			cfg.Outbounds = []xrayOutbound{{Tag: "direct", Protocol: "freedom"}}
			return cfg
		}
		cfg.Outbounds = []xrayOutbound{{
			Tag: "carrier-out", Protocol: "masque",
			Settings: &xrayMasqueOutboundSettings{
				Address: p.RemoteAddr, Port: p.CarrierPort,
				RemoteDNS: xrayMasqueRemoteDNS(p),
			},
			StreamSettings: &xrayStreamClient{
				Network: "masque", Security: "tls",
				// the ONLY source of the Authorization header the inbound
				// demands (server.go:272-282) — without it every session
				// is a 401 (`run -test` cannot see it: the config builds).
				Masque: &xrayMasqueTransport{Host: host, User: p.MasqueEmail, Pass: p.MasquePass},
				TLS: &xrayTLSClient{
					ServerName:           xrayMasqueTLSName(host),
					PinnedPeerCertSha256: p.PinSHA256,
				},
			},
		}}
		cfg.Routing = &xrayRouting{Rules: []xrayRoutingRule{}}
		if p.SocksPort > 0 {
			cfg.Inbounds = append(cfg.Inbounds, xrayInbound{
				Tag: "socks-in", Listen: "127.0.0.1", Port: p.SocksPort, Protocol: "socks",
				Settings: &xrayInboundSettings{Auth: "noauth", UDP: true},
			})
			cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRoutingRule{
				Type: "field", InboundTag: []string{"socks-in"}, OutboundTag: "carrier-out",
			})
		}
		if p.HTTPPort > 0 {
			cfg.Inbounds = append(cfg.Inbounds, xrayInbound{
				Tag: "http-in", Listen: "127.0.0.1", Port: p.HTTPPort, Protocol: "http",
			})
			cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRoutingRule{
				Type: "field", InboundTag: []string{"http-in"}, OutboundTag: "carrier-out",
			})
		}
		return cfg
	}
	cfg := xrayConfig{Log: &xrayLog{LogLevel: "warning"}}
	if role == engineSideServer {
		// Portal: the Reality carrier inbound feeds the reverse portal;
		// the public dokodemo rides the reverse channels toward Iran.
		cfg.Inbounds = []xrayInbound{
			{
				Tag: "vless-in", Listen: "0.0.0.0", Port: p.CarrierPort, Protocol: "vless",
				Settings: &xrayInboundSettings{
					Clients:    []xrayUser{{ID: p.UUID, Flow: p.Flow}},
					Decryption: "none",
				},
				StreamSettings: &xrayStreamSettings{
					Network: "tcp", Security: "reality",
					Reality: &xrayRealityServer{
						Dest:        p.Dest,
						ServerNames: []string{p.ServerName},
						PrivateKey:  p.RealityPrivateKey,
						ShortIDs:    []string{p.ShortID},
					},
				},
				Sniffing: &xraySniffing{Enabled: true, DestOverride: []string{"http", "tls"}},
			},
			{
				Tag: "dokodemo-" + fmt.Sprint(p.PublicPort), Listen: "0.0.0.0", Port: p.PublicPort,
				Protocol: "dokodemo-door",
				Settings: &xrayInboundSettings{
					Address: p.LocalAddr, Port: p.LocalPort, Network: "tcp",
				},
			},
		}
		cfg.Outbounds = []xrayOutbound{{Tag: "direct", Protocol: "freedom"}}
		cfg.Reverse = &xrayReverse{Portals: []xrayPortal{{Tag: "rev-portal", Domain: xrayPortalDomain}}}
		// OVERNIGHT-A: the carrier transport rides the Reality inbound
		// (tcp keeps the bare shape; xhttp/grpc add their settings blocks).
		xrayStreamTransport(cfg.Inbounds[0].StreamSettings, p)
		cfg.Routing = &xrayRouting{Rules: []xrayRoutingRule{
			{Type: "field", InboundTag: []string{"vless-in"}, OutboundTag: "rev-portal"},
			{Type: "field", InboundTag: []string{"dokodemo-" + fmt.Sprint(p.PublicPort)}, OutboundTag: "rev-portal"},
		}}
		if p.APIPort > 0 {
			// The warmup probe entry (RUNBOOK/PHASE8: Health must not
			// report the tunnel healthy until a through-tunnel probe
			// succeeds). A loopback dokodemo asking for probe.quantum
			// rides the reverse channel to the bridge, whose blackhole
			// answers HTTP — a full round trip proves the channel
			// CARRIES DATA, not just that the carrier TCP accepted.
			cfg.Inbounds = append(cfg.Inbounds, xrayInbound{
				Tag: "probe-in", Listen: "127.0.0.1", Port: p.APIPort + 1, Protocol: "dokodemo-door",
				Settings:       &xrayInboundSettings{Address: xrayProbeHost, Port: 80, Network: "tcp"},
				StreamSettings: &xrayStreamSettings{Network: "tcp"},
			})
			cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRoutingRule{
				Type: "field", InboundTag: []string{"probe-in"}, OutboundTag: "rev-portal",
			})
			cfg.Inbounds = append(cfg.Inbounds, xrayInbound{
				Tag: "api-in", Listen: "127.0.0.1", Port: p.APIPort, Protocol: "dokodemo-door",
				Settings:       &xrayInboundSettings{Address: "127.0.0.1"},
				StreamSettings: &xrayStreamSettings{Network: "tcp"},
			})
			// B-AG4 (AGENT-22): the API is NOT a regular outbound — the
			// Commander app (Xray-core v24.12.31 app/commander/commander.go
			// Start) registers its internal gRPC listener as an OUTBOUND
			// tagged with api.tag, and connections reach it only through a
			// routing rule whose outboundTag equals that tag. api.tag is
			// therefore aligned with the rule below ("api"). The old shape
			// (api.tag="api-in" + a BLACKHOLE outbound named "api") fed
			// every stats dial into the blackhole — StatsService never
			// answered, the stats gate failed and Counters stayed empty
			// (dormant in production: the panel leaves api_port unset, so
			// this branch never rendered; the family integration sets it).
			// No "api" outbound is rendered here anymore. The system policy
			// flips the per-inbound counter registration (see
			// xraySystemPolicy) — without it the StatsService answers but
			// every stats list comes back EMPTY (B-AG4's "Counters stay
			// empty" second half).
			cfg.API = &xrayAPI{Tag: "api", Services: []string{"StatsService"}}
			cfg.Stats = &struct{}{}
			cfg.Policy = &xrayPolicy{
				Levels: map[string]xrayPolicyLevel{"0": {}},
				System: &xraySystemPolicy{StatsInboundUplink: true, StatsInboundDownlink: true},
			}
			cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRoutingRule{
				Type: "field", InboundTag: []string{"api-in"}, OutboundTag: "api",
			})
		}
		return cfg
	}
	// Bridge: the vless outbound dials OUT through Reality; the reverse
	// bridge rides it and forwards to freedom (the Iran-local service).
	carrierOut := xrayOutbound{
		Tag: "carrier-out", Protocol: "vless",
		StreamSettings: &xrayStreamClient{
			Network: "tcp", Security: "reality",
			Reality: &xrayRealityClient{
				Show: false, Fingerprint: "chrome", ServerName: p.ServerName,
				PublicKey: p.RealityPublicKey, ShortID: p.ShortID, SpiderX: "",
			},
		},
		Settings: &xrayOutboundSettings{
			Vnext: []xrayVnext{{Address: p.RemoteAddr, Port: p.CarrierPort,
				Users: []xrayUser{{ID: p.UUID, Flow: p.Flow, Encryption: "none"}}}},
		},
	}
	// OVERNIGHT-A: mirror the server's carrier transport on the dialing
	// end (xhttp/grpc settings must match both ends exactly).
	xrayStreamClientTransport(carrierOut.StreamSettings, p)
	cfg.Outbounds = []xrayOutbound{carrierOut,
		{Tag: "local", Protocol: "freedom"},
		// The warmup probe's answer: connections the portal sent down the
		// reverse channel asking for probe.quantum get an HTTP response
		// from the blackhole — a full round trip through the channel.
		{Tag: "probe", Protocol: "blackhole",
			Settings: &xrayOutboundSettings{Response: &xrayBlackholeResponse{Type: "http"}}},
	}
	cfg.Reverse = &xrayReverse{Bridges: []xrayBridge{{Tag: "rev-bridge", Domain: xrayPortalDomain}}}
	cfg.Routing = &xrayRouting{Rules: []xrayRoutingRule{
		// Upstream docs (reverse bridge): ONLY the channel-establishment
		// requests carry the internal domain — route THOSE to the carrier.
		// Everything else arriving from the portal must go to the local
		// service; without the domain filter the first rule matches all
		// bridge traffic and portal-returned data LOOPS back into the
		// carrier (lab-verified: 11,705 dials in seconds vs 5 with the
		// filter; first-match-wins made the local rule dead code).
		{Type: "field", InboundTag: []string{"rev-bridge"},
			Domain: []string{"full:" + xrayPortalDomain}, OutboundTag: "carrier-out"},
		// The probe MUST come before the catch-all local rule
		// (first-match-wins).
		{Type: "field", InboundTag: []string{"rev-bridge"},
			Domain: []string{"full:" + xrayProbeHost}, OutboundTag: "probe"},
		{Type: "field", InboundTag: []string{"rev-bridge"}, OutboundTag: "local"},
	}}
	// OVERNIGHT-A3: the optional local SOCKS/HTTP ingress (the Iran
	// proxy-exit shape — everything offered here rides the carrier out;
	// the rules run BEFORE the bridge rules would matter only if the
	// inbounds collided, which validation refuses; appended after the
	// rev-bridge rules because those match by tag and never overlap).
	if p.SocksPort > 0 {
		cfg.Inbounds = append(cfg.Inbounds, xrayInbound{
			Tag: "socks-in", Listen: "127.0.0.1", Port: p.SocksPort, Protocol: "socks",
			Settings: &xrayInboundSettings{Auth: "noauth", UDP: true},
		})
		cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRoutingRule{
			Type: "field", InboundTag: []string{"socks-in"}, OutboundTag: "carrier-out",
		})
	}
	if p.HTTPPort > 0 {
		cfg.Inbounds = append(cfg.Inbounds, xrayInbound{
			Tag: "http-in", Listen: "127.0.0.1", Port: p.HTTPPort, Protocol: "http",
		})
		cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRoutingRule{
			Type: "field", InboundTag: []string{"http-in"}, OutboundTag: "carrier-out",
		})
	}
	return cfg
}

// xrayInstState is one RUNNING instance's state (supervisor target).
// The proc/stop/cfg/binPath base rides the shared engineInst (A1).
type xrayInstState struct {
	engineInst
	params xrayParams
	role   engineSide
}

// XrayDriver implements engine.Driver for Xray-core.
type XrayDriver struct {
	runs *instTable[xrayInstState]
}

func NewXrayDriver() *XrayDriver { return &XrayDriver{runs: newInstTable[xrayInstState]()} }

func (d *XrayDriver) ID() string { return xrayID }

func (d *XrayDriver) Describe() engine.EngineInfo {
	// The panel derives its wizard from this flat key→placeholder map (the
	// catalog's params_schema takes precedence, <=4 KiB): EVERY xrayParams
	// key is listed (TestXrayMasqueDescribeSchema reflects the struct),
	// with honest JSON types — ports/mtu numeric, enums as "a|b" hints,
	// secrets/paths as EMPTY strings (never a value).
	return engine.EngineInfo{ID: xrayID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","sha256_amd64":"","sha256_arm64":"","signature_amd64":"","signature_arm64":"","carrier":"|hysteria2|masque","remote_addr":"","carrier_port":0,"public_port":0,"local_addr":"","local_port":0,"server_name":"","dest":"","short_id":"","reality_public_key":"","reality_private_key":"","flow":"","uuid":"","api_port":0,"transport":"tcp|xhttp|grpc","xhttp_path":"/","grpc_service_name":"quantum-reverse","hysteria_auth":"","tls_cert":"","tls_key":"","masque_email":"","masque_pass":"","masque_host":"","masque_mtu":0,"masque_address":"10.127.8.1/24","masque_remote_dns":"","pin_sha256":"","socks_port":0,"http_port":0}`)}
}

// EnsureBinary: the Manager calls this before the first instance starts;
// the download happens in Start via xrayEnsureBinary with the resolved
// coordinates (manifest-first, pinned fallback).
func (d *XrayDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *XrayDriver) Validate(params json.RawMessage) error {
	var p xrayParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("xray: engine_params: %w", err)
	}
	return xrayValidateParams(p)
}

func xrayConfigPath(tunnelID string) string {
	return filepath.Join(xrayEngineDir(), "instances", tunnelID+".json")
}

func xrayBinDir(version string) string { return filepath.Join(xrayEngineDir(), "bin", version) }

func xrayEngineDir() string { return engineEngineDir(xrayID) }

// xrayEnsureBinary: R5 manifest first, pinned fallback, same trust model
// as FRP/Backhaul. Installs the single `xray` binary.
func xrayEnsureBinary(ctx context.Context, p xrayParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("xray: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.xrayArtifactPin(); pinErr == nil && engineCacheHit(xrayBinDir(p.Version), pinnedSHA, []string{"xray"}) {
		return xrayBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("xray: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, xrayID,
		func() (string, string, string, error) { return p.xrayArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := xrayBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"xray"}) {
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
		return "", fmt.Errorf("xray: cache dir: %w", err)
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"xray": true}); err != nil {
		return "", err
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("xray: cache marker: %w", err)
	}
	return dir, nil
}

// Start implements engine.Driver.
func (d *XrayDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p xrayParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("xray: engine_params: %w", err)
	}
	if err := xrayValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("xray: invalid tunnel id %q", inst.TunnelID)
	}
	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual[xrayParams](prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}
	// OVERNIGHT-A8 (G9): both masque ends create a TUN device (proxy/masque/
	// server.go:185 at start, client.go:330 at the first tunnel) — a kernel
	// op. Fail closed FIRST with the honest pointer (the EasyTier shape),
	// before any download or render: without it the host reports an
	// opaque "process exited".
	if xrayMasque(p) && !xrayTunAvailable() {
		return fmt.Errorf("xray: carrier masque needs /dev/net/tun on this host — both ends create a TUN device (load the tun module; many VPS containers lack it)")
	}
	role, err := xrayResolveRole(p)
	if err != nil {
		return err
	}
	binDir, err := xrayEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "xray")
	// OVERNIGHT-A8 (G3): the version gate on the RESOLVED binary — before
	// any config is written or process spawned (see xrayMasqueVersionGate).
	if xrayMasque(p) {
		if err := xrayMasqueVersionGate(binPath); err != nil {
			return err
		}
	}
	cfg := xrayBuildConfig(role, p)
	cfgPath := xrayConfigPath(inst.TunnelID)
	if err := xrayWriteConfigFile(cfgPath, cfg); err != nil {
		return err
	}
	proc, err := xraySpawn(binPath, cfgPath)
	if err != nil {
		_ = os.Remove(cfgPath)
		return err
	}
	st := &xrayInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		cfg: cfgPath, binPath: binPath}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, binPath, cfgPath, xraySpawn)
	// Wire accounting on the SERVER end's carrier port (the client's dial
	// port is shared and cannot be attributed per instance). Proto-aware
	// (A8 G8): the QUIC/HTTP3 carriers count on udp rules.
	if role == engineSideServer {
		if err := acctWireRulesAddProto(acctChainsDriver, inst.TunnelID, p.CarrierPort, p.CarrierPort, xrayWireProto(p)); err != nil {
			fmt.Fprintf(os.Stderr, "xray: wire accounting unavailable: %v\n", err)
		}
	}
	return nil
}

// xrayArgv is the exact argv of one instance: the config PATH only — no
// secret ever rides the command line (ps/audit would show it).
func xrayArgv(cfgPath string) []string { return []string{"run", "-c", cfgPath} }

// xraySpawn runs the Xray binary: `xray run -c <cfg>` (upstream CLI).
// Same process-shape contract as frpSpawn (frpProcess + Done channel).
var xraySpawn = func(binPath, cfgPath string) (frpProcess, error) {
	cmd := exec.Command(binPath, xrayArgv(cfgPath)...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("xray: start %s: %w", binPath, err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

// xrayWritePrivateFile is the ONE materialization path for everything
// that carries a secret: parent dir 0700, file 0600. Start's instance
// config and the lab dump's throwaway key both go through it.
func xrayWritePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("xray: dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("xray: write file: %w", err)
	}
	return nil
}

// xrayWriteConfigFile renders + materializes one instance config exactly
// as Start writes it: json.MarshalIndent of the typed structs (never
// string concatenation) through xrayWritePrivateFile — the file carries
// the Reality private key / the masque users' pass. Removed on Stop by
// engineStopInst and when the spawn fails. The lab dump test writes the
// same bytes through the same function.
func xrayWriteConfigFile(path string, cfg xrayConfig) error {
	cfgBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("xray: render config: %w", err)
	}
	return xrayWritePrivateFile(path, cfgBytes)
}

// xrayWireProto is the carrier's wire protocol for the iptables accounting
// rules: the QUIC/HTTP3 carriers (hysteria2; masque — transport/internet/
// masque/dialer.go:44-47 forces Network_UDP) count on udp rules, the
// Reality carrier rides tcp.
func xrayWireProto(p xrayParams) string {
	switch xrayCarrierFamily(p) {
	case "hysteria2", "masque":
		return "udp"
	}
	return "tcp"
}

// xrayInboundTag is the carrier-facing inbound tag the StatsService counts
// under (the Counters prefix) — per family.
func xrayInboundTag(p xrayParams) string {
	switch xrayCarrierFamily(p) {
	case "hysteria2":
		return "hysteria-in"
	case "masque":
		return "masque-in"
	}
	return "vless-in"
}

// xrayTunAvailable checks /dev/net/tun (the TUN creation is a kernel op —
// the EasyTier seam shape; OVERNIGHT-A8 G9).
var xrayTunAvailable = func() bool {
	return infra.FileExists("/dev/net/tun")
}

// xrayMasqueMinVersion is the first Xray-core release shipping the masque
// proxy + transport (registered in infra/conf/xray.go). Older cores fail
// the config build — `infra/conf: Config: unknown transport protocol:
// masque`, exit 23 (probe: v24.12.31 on the exact server render) — and
// the supervisor would loop on it. Threshold given by the A8 brief.
const xrayMasqueMinVersion = "26.9.30"

// xrayVersionProbe runs `<bin> version` and returns the bare version
// ("26.11.9" from `Xray 26.11.9 (Xray, Penetrates Everything.) 676eaf6
// (go1.27.3 linux/amd64)`). Seam: hermetic tests script it; the legacy
// xrayVersion() in xray.go probes the OLD panel binary and is not this.
var xrayVersionProbe = func(binPath string) (string, error) {
	out, err := infra.RunCmdTimeoutOut(10*time.Second, binPath, "version")
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	f := strings.Fields(line)
	if len(f) < 2 || !strings.EqualFold(f[0], "xray") {
		return "", fmt.Errorf("unexpected version output %q", line)
	}
	return strings.TrimLeft(f[1], "vV"), nil
}

// xrayVersionLess is the NUMERIC dotted compare (ctVersionLess) with a
// tolerated "v" prefix — never the panel's plain-string pick
// ("26.11.9" < "26.3.27" by bytes: the G3 trap).
func xrayVersionLess(a, b string) bool {
	return ctVersionLess(strings.TrimLeft(strings.TrimSpace(a), "vV"), strings.TrimLeft(strings.TrimSpace(b), "vV"))
}

// xrayMasqueVersionGate fails closed unless the PROBED version of the
// resolved core is >= xrayMasqueMinVersion. Why the probe and not
// p.Version: the params version is only the CACHE KEY — xrayEnsureBinary
// stores the binary under bin/<params.version>/ regardless of which core
// the manifest resolved, and the manifest pick is a plain-STRING compare
// over every uploaded version ("26.11.9" < "26.3.27": a panel still
// holding the A5 26.3.27 pack resolves it — no masque). The probe is the
// only honest signal of what will run; an unprobeable core is unknown —
// refused too.
func xrayMasqueVersionGate(binPath string) error {
	v, err := xrayVersionProbe(binPath)
	if err != nil {
		return fmt.Errorf("xray: carrier masque needs Xray >= %s — cannot probe the resolved core's version (cache dir %s): %v", xrayMasqueMinVersion, filepath.Base(filepath.Dir(binPath)), err)
	}
	if xrayVersionLess(v, xrayMasqueMinVersion) {
		return fmt.Errorf("xray: carrier masque needs Xray >= %s but the resolved core is %s (older cores reject the config: unknown transport protocol: masque). The params version is only the cache key: the manifest pick is a plain-string compare over every uploaded xray — upload the newer pack or pin version/artifact/sha256 in engine_params", xrayMasqueMinVersion, v)
	}
	return nil
}

// Stop implements engine.Driver: the shared teardown order, with the
// server end's carrier-port accounting rule (proto-aware, A8 G8) as the
// driver-specific hook.
func (d *XrayDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.role == engineSideServer {
			_ = acctWireRulesDelProto(acctChainsDriver, inst.TunnelID, st.params.CarrierPort, st.params.CarrierPort, xrayWireProto(st.params))
		}
	})
	return nil
}

// Reload implements engine.Driver: equal params are a no-op, anything
// else is a restart.
func (d *XrayDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, xrayID, inst.TunnelID, inst.Params,
		func(st *xrayInstState) xrayParams { return st.params }, engineParamsEqual[xrayParams])
}

// Health implements engine.Driver: the process alive, and on the SERVER
// end (api_port configured) the StatsService must answer — a real probe
// of the engine's control plane. The CLIENT end also probes the stats
// API when configured (both ends may run one for local visibility).
func (d *XrayDriver) Health(inst engine.Instance) engine.Health {
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
	if st.role == engineSideServer && st.params.APIPort > 0 {
		start := time.Now()
		err := xrayStatsPing(st.params.APIPort)
		lat := float64(time.Since(start).Milliseconds())
		if err != nil {
			return engine.Health{OK: false, Detail: "stats API not answering", LatencyMs: lat}
		}
		// Warmup gate (PHASE8 1b): NOT healthy until a through-tunnel
		// probe succeeds. The bridge registers its reverse-channel pool
		// lazily; before that, public connections hit an empty worker
		// list and are dropped — the balancer must not route yet. The
		// probe rides the portal's loopback probe inbound through the
		// reverse channel and expects the bridge's HTTP answer.
		probeDeadline := time.Now().Add(1600 * time.Millisecond)
		delays := []time.Duration{0, 300 * time.Millisecond, 800 * time.Millisecond}
		var lastErr error
		for _, d := range delays {
			if d > 0 {
				if time.Now().After(probeDeadline) {
					break
				}
				time.Sleep(d)
			}
			if lastErr = xrayProbeFn(st.params.APIPort + 1); lastErr == nil {
				return engine.Health{OK: true, Detail: "xray server running, api ok, tunnel probe ok", LatencyMs: lat}
			}
		}
		return engine.Health{OK: false, Detail: "through-tunnel probe failed (warmup or broken channel): " + lastErr.Error(), LatencyMs: lat}
	}
	detail := "xray process running"
	if proto := xrayWireProto(st.params); proto == "udp" {
		// A8 G8: name the wire the carrier counts on (QUIC/HTTP3 = udp).
		detail += " (carrier " + xrayCarrierLabel(xrayCarrierFamily(st.params)) + ", wire " + proto + ")"
	}
	return engine.Health{OK: true, Detail: detail, LatencyMs: -1}
}

// Counters implements engine.Driver: the SERVER end reports wire bytes
// (iptables on the carrier port) AND payload bytes per direction from
// the StatsService: the carrier-facing inbound (vless-in on Reality,
// hysteria-in / masque-in on the proxy-exit carriers — A8 G8) is the
// tunnel-facing side. We report that pair as payload.
func (d *XrayDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil || st.role != engineSideServer || st.params.APIPort <= 0 {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if rx, tx, ok := acctWireBytes(inst.TunnelID, st.params.CarrierPort, st.params.CarrierPort); ok {
		out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
	}
	up, down, ok := xrayStatTraffic(st.params.APIPort, "inbound>>>"+xrayInboundTag(st.params))
	if ok {
		// vless-in uplink = bytes handed TO the carrier from the dokodemo
		// (= payload tx into the tunnel); downlink = bytes delivered OUT
		// to the dokodemo (= payload rx from the tunnel).
		out.PayloadTx, out.PayloadRx, out.PayloadKnown = up, down, true
	}
	return out
}

// xrayStatTraffic queries the StatsService via `xray api statsquery`
// (the real binary's own gRPC client — no protobuf dependency here) and
// returns (uplink, downlink) for the given tag prefix.
// xrayTunnelProbe sends a tiny HTTP request through the FULL tunnel: the
// portal's probe-in inbound (dokodemo → probe.quantum:80) rides the
// reverse channel to the bridge, whose blackhole answers HTTP — a full
// round trip proves the channel carries DATA (the local dokodemo accept
// alone proves nothing: it completes before the far end is dialed).
func xrayTunnelProbe(probePort int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(probePort)), 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("GET /probe HTTP/1.0\r\nHost: " + xrayProbeHost + "\r\n\r\n")); err != nil {
		return err
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(buf[:n], []byte("HTTP/")) {
		return fmt.Errorf("unexpected probe answer %q", buf[:n])
	}
	return nil
}

// xrayProbeFn seams the through-tunnel probe (hermetic tests stub it; the
// integration runs the real dial through the tunnel).
var xrayProbeFn = xrayTunnelProbe

func xrayStatsPing(apiPort int) error {
	up, down, ok := xrayStatTraffic(apiPort, "inbound>>>")
	if !ok {
		return fmt.Errorf("stats unavailable")
	}
	_ = up
	_ = down
	return nil
}

// xrayStatTraffic queries the StatsService via the real binary's own
// gRPC client (xray api statsquery) and returns (uplink, downlink, ok)
// for the given tag prefix.
func xrayStatTraffic(apiPort int, prefix string) (uint64, uint64, bool) {
	return execCommandJSON(apiPort, prefix)
}

// Uninstall implements engine.Driver.
func (d *XrayDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, xrayEngineDir())
	return nil
}

// ForwardAddress implements engine.ForwardAddresser: the balancer's DNAT
// target for this tunnel = the foreign dokodemo (remote host + public
// port), the same delivery shape as FRP. Server role → 127.0.0.1:public
// (the dokodemo is local to the server end); client role → remote host.
func (d *XrayDriver) ForwardAddress(inst engine.Instance) (string, int, bool) {
	var p xrayParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return "", 0, false
	}
	role, err := xrayResolveRole(p)
	if err != nil {
		return "", 0, false
	}
	if role == engineSideServer {
		return "127.0.0.1", p.PublicPort, true
	}
	host := strings.TrimSpace(p.RemoteAddr)
	if h, _, serr := net.SplitHostPort(host); serr == nil {
		host = h
	}
	if host == "" {
		return "", 0, false
	}
	return host, p.PublicPort, true
}

// xrayParamsJSON is test/ops helper.
func xrayParamsJSON(p xrayParams) json.RawMessage { return infra.MustJSON(p) }

// execCommandJSON runs `xray api statsquery --server=...` and returns the
// parsed counters for the prefix. Seam-able for tests.
var execCommandJSON = func(apiPort int, prefix string) (uint64, uint64, bool) {
	binDir := xrayBinDir("")
	bin := filepath.Join(binDir, "xray")
	c := &http.Client{Timeout: 3 * time.Second}
	_ = c // placeholder for the real CLI invocation below
	cmd := exec.Command(bin, "api", "statsquery", fmt.Sprintf("--server=127.0.0.1:%d", apiPort))
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, false
	}
	// The CLI's response is proto-flavored JSON: the list key is "stat"
	// (SINGULAR — StatsQueryResponse.Stat, v24.12.31
	// app/stats/command/command.pb.go) with numeric values, e.g.
	// {"stat":[{"name":"inbound>>>api-in>>>traffic>>>uplink","value":170}]}
	// (verified against the real binary). The old "stats" key never
	// matched anything, so Counters parsed empty even when the API
	// answered — B-AG4's third layer.
	var parsed struct {
		Stats []struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
		} `json:"stat"`
	}
	if json.Unmarshal(out, &parsed) != nil {
		return 0, 0, false
	}
	var up, down uint64
	for _, s := range parsed.Stats {
		if !strings.HasPrefix(s.Name, prefix) {
			continue
		}
		switch {
		case strings.HasSuffix(s.Name, ">>>uplink"):
			up = uint64(s.Value)
		case strings.HasSuffix(s.Name, ">>>downlink"):
			down = uint64(s.Value)
		}
	}
	return up, down, true
}
