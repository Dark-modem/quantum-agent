package agent

// waterwall_driver.go — the WaterWall engine (radkesvat/WaterWall v1.6.0,
// MPL-2.0 — binaries-only external core per the cores separation, released
// dual-arch in quantum-cores waterwall/) as an engine.Driver per
// 00-ADMIN/ENGINE-GUIDE.md. OVERNIGHT-A5 (the final integration wave).
//
// WaterWall is a NODE-CHAIN engine: core.json names misc settings + config
// files; each config is a DAG of typed nodes
// ({name, type, settings, next}) whose ORDER is part of the design. The
// driver renders the two ends of the desired-state tunnel as node chains
// citing the upstream tunnels/*/description.md placements + examples:
//
//	server (foreign): [carrier Listener …method server nodes… → TcpConnector(local_addr:local_port)]
//	client (iran):    [TcpListener(:local_port) …method client nodes… → carrier Connector(server_addr)]
//
// The 18 methods (quantum-cores waterwall/MANIFEST.json methods[], mirrored
// from the upstream tunnels/ tree): quic, kcp, enet, reality, trojan, vless,
// vmess, wireguard, rtmp, gns, bgp4, http, socks5, fake-tcp, obfuscator,
// connection-fisher, connection-stripe, mux. Verified chains:
//   quic    UdpListener → QuicServer → TcpConnector   | TcpListener → QuicClient → UdpConnector
//   kcp     UdpListener → KcpServer → TcpConnector    | TcpListener → KcpClient → UdpConnector
//   enet    UdpListener → EnetServer → TcpConnector   | TcpListener → EnetClient → UdpConnector
//   reality TcpListener → RealityServer → TcpConnector | TcpListener → RealityClient → TcpConnector
//   trojan  TcpListener → TlsServer → TrojanServer → TcpUdpConnector | TcpListener → TrojanClient → TlsClient → TcpConnector
//   vless   TcpListener → TlsServer → VlessServer → TcpUdpConnector  | TcpListener → VlessClient → TlsClient → TcpConnector
//   vmess   TcpListener → [TlsServer] → VmessServer → TcpUdpConnector | TcpListener → VmessClient → [TlsClient] → TcpConnector
//   wireguard UdpListener → WireGuardServer → TcpUdpConnector (+AuthenticationServer sidecar per the
//             connection example) | TunDevice → WireGuardClient → UdpConnector (L3 — TunDevice node)
//   rtmp    TcpListener → RtmpServer → TcpConnector | TcpListener → RtmpClient → [TlsClient] → TcpConnector
//   gns     UdpListener → [ObfuscatorServer] → GnsServer → TcpConnector | TcpListener → [ObfuscatorClient] → GnsClient → UdpConnector
//   bgp4    TcpListener → Bgp4Server → TcpConnector | TcpListener → Bgp4Client → TcpConnector
//   http    TcpListener → HttpProxyServer → TcpConnector (+AuthenticationServer/Client sidecars when authed)
//   socks5  TcpListener → Socks5Server → TcpConnector | TcpListener → Socks5Client → TcpConnector
//   fake-tcp server: RawSocket → IpOverrider → FakeTcpHeaderServer → PacketsToConnection → UdpConnector
//           client: UdpListener → ConnectionToPackets → FakeTcpHeaderClient → IpOverrider → RawSocket (L3, CAP_NET_RAW)
//   obfuscator UdpListener → ObfuscatorServer → TcpConnector | TcpListener → ObfuscatorClient → UdpConnector
//   connection-fisher TcpListener → ConnectionFisherServer → TcpConnector | TcpListener → ConnectionFisherClient → TcpConnector
//   connection-stripe TcpListener → TlsServer → ConnectionStripeServer → TcpConnector | TcpListener → ConnectionStripeClient → TlsClient → TcpConnector
//   mux     TcpListener → MuxServer → UdpOverTcpServer → UdpConnector | UdpListener → UdpOverTcpClient → MuxClient → TcpConnector
//
// Honesty notes: the wireguard/fake-tcp chains bind node-level L3 devices
// (TunDevice/RawSocket — the binary creates them; agents run as root) and
// the reverse direction (public port on the foreign end → iran-local
// target) has no per-tunnel primitive here — gost rtcp/frp/backhaul own it
// (the "reverse chain" upstream feature is a chain-composition mode, not a
// distinct carrier). The anti-analysis companions (Disturber, BlackHole,
// ConnectionFisher decoys) are chain-composition nodes — connection-fisher
// IS exposed as a method; Disturber/BlackHole stay documented (they are
// traffic-shaping decorations, not carriers).
//
// Exec: the binary reads core.json from its CWD (readme.md) — the driver
// writes core.json + config.json per instance (0600) and spawns the binary
// with Dir=instanceDir (argv-only, no shell). Secrets (uuid/passwords/
// private keys) live only in the instance config; never logged.

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

const wwID = "waterwall"

type waterwallParams struct {
	ServerSide string `json:"server_side"`  // the end hosting the WaterWall SERVER (foreign)
	Version    string `json:"version"`      // artifact version (cache key)
	Artifact   string `json:"artifact"`     // name template with {arch}
	SHA256Amd  string `json:"sha256_amd64"` // pinned fallback
	SHA256Arm  string `json:"sha256_arm64"`
	SigAmd     string `json:"signature_amd64"`
	SigArm     string `json:"signature_arm64"`
	Method     string `json:"method"`      // one of wwMethods (see the map below)
	ServerAddr string `json:"server_addr"` // carrier "host:port" — server listen / client dial
	LocalAddr  string `json:"local_addr"`  // server-end dial target host (the tunnel's destination)
	LocalPort  int    `json:"local_port"`  // client-end ingress listen AND the server-end target port
	// per-method auth/TLS fields (charset-validated; the render consumes
	// exactly the fields the chosen method needs and REFUSES dead ones):
	AuthPassword string `json:"auth_password,omitempty"` // trojan/reality/socks5/http/bgp4/fake-tcp auth
	AuthUser     string `json:"auth_user,omitempty"`     // socks5/http username (with auth_password)
	UUID         string `json:"uuid,omitempty"`          // vless/vmess user id
	TLSCert      string `json:"tls_cert,omitempty"`      // TlsServer cert-file / QuicServer cert-file
	TLSKey       string `json:"tls_key,omitempty"`       // TlsServer key-file / QuicServer key-file
	SNI          string `json:"sni,omitempty"`           // QuicClient sni / TlsClient server-name
	// wireguard (mode=connection per the upstream connection example):
	WGPrivateKey string `json:"wg_private_key,omitempty"`
	WGAuthSecret string `json:"wg_auth_secret,omitempty"` // the AuthenticationClient/Server shared secret
	// gns/obfuscator xor layer (the upstream obfuscated example):
	ObfsMethod string `json:"obfs_method,omitempty"` // xor (upstream example method)
	ObfsKey    int    `json:"obfs_key,omitempty"`    // xor_key byte (0-255)
	// kcp/enet/gns common:
	SendMTU int  `json:"send_mtu,omitempty"` // 0 = upstream default
	KcpFEC  bool `json:"kcp_fec,omitempty"`  // KcpServer fec (default false)
	// rtmp:
	RtmpApp    string `json:"rtmp_app,omitempty"`    // the announced application
	RtmpStream string `json:"rtmp_stream,omitempty"` // the announced stream key
	// http/socks5:
	NoAuth bool `json:"no_auth,omitempty"` // http/socks5 without auth (loopback entries only)
	// fake-tcp:
	FakeTCPPort int `json:"fake_tcp_port,omitempty"` // FakeTcpHeaderServer server-port (0 = default)
	// fake-tcp: the iran host's raw-reachable IP (the REAL source address
	// the client's RawSocket emits and the server's RawSocket captures —
	// the per-end context the A5 one-params-object model lacked; REQUIRED
	// for method=fake-tcp). The server's real IP rides server_addr's host.
	FakeTCPClientIP string `json:"fake_tcp_client_ip,omitempty"`
	// quic client trust override (self-signed pairs — the upstream docs:
	// explicit verify=false disables trust/name checks while retaining the
	// encrypted handshake). Additive — dead on non-quic methods.
	WWInsecure bool `json:"ww_insecure,omitempty"`
	// reverse chain (method=reverse): the PUBLIC listener port on the
	// foreign end (public users hit foreign:reverse_port; the traffic rides
	// the Bridge-paired reverse channel to the iran-local target).
	ReversePort int `json:"reverse_port,omitempty"`
}

// wwMethods is the 18-method allowlist (the cores MANIFEST methods[] ids,
// mirrored from the upstream tunnels/ tree). Values: the carrier edge proto
// ("tcp"|"udp"|"raw") for accounting + whether the method is TLS-bearing
// (cert pair required) + L3 device note.
type wwMethodSpec struct {
	carrier string // tcp|udp|raw
	tls     bool   // the chain includes TlsServer/QuicServer (cert pair required)
	l3      bool   // node-level device chains (TunDevice/RawSocket)
}

var wwMethods = map[string]wwMethodSpec{
	"quic":              {carrier: "udp", tls: true},
	"kcp":               {carrier: "udp"},
	"enet":              {carrier: "udp"},
	"reality":           {carrier: "tcp"},
	"trojan":            {carrier: "tcp", tls: true},
	"vless":             {carrier: "tcp", tls: true},
	"vmess":             {carrier: "tcp"},
	"wireguard":         {carrier: "udp", l3: true},
	"rtmp":              {carrier: "tcp"},
	"gns":               {carrier: "udp"},
	"bgp4":              {carrier: "tcp"},
	"http":              {carrier: "tcp"},
	"socks5":            {carrier: "tcp"},
	"fake-tcp":          {carrier: "udp", l3: true},
	"obfuscator":        {carrier: "udp"},
	"connection-fisher": {carrier: "tcp"},
	"connection-stripe": {carrier: "tcp", tls: true},
	"mux":               {carrier: "tcp"},
	// OVERNIGHT-A6: the reverse chain (tunnels/ReverseClient+ReverseServer
	// + the Bridge pair — "Bridge → ReverseClient" adjacency is a chain
	// DESIGN rule upstream: no node between them). Server: the carrier
	// listener → ReverseServer → BridgeA, and TcpListener(:reverse_port) →
	// BridgeB (pair A) — public users hit the foreign :reverse_port and the
	// traffic rides the reverse channel to the iran-local target. Client:
	// BridgeC → ReverseClient → carrier dial, and TcpConnector(local) →
	// BridgeD (pair C) — the iran-local service stays behind NAT.
	"reverse": {carrier: "tcp"},
}

func (p waterwallParams) wwArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	return enginePinForArch(EnginePin{Version: p.Version, Artifact: p.Artifact,
		SHA256Amd: p.SHA256Amd, SHA256Arm: p.SHA256Arm, SigAmd: p.SigAmd, SigArm: p.SigArm})
}

// wwSafe is the charset gate for EVERY string that lands in a node's
// settings (JSON-mshaled, but the discipline is the same as the other
// drivers: no quotes/backslashes/control chars — the values are data, not
// structure).
func wwSafe(label, v string, max int) error {
	if len(v) > max || strings.ContainsAny(v, "\"'\\\n\r\t `$;&|<>@") {
		return fmt.Errorf("waterwall: %s must be a ≤%d-char string without quotes/backslashes/control characters", label, max)
	}
	return nil
}

func wwValidateHost(label, v string, max int) error {
	if strings.TrimSpace(v) == "" || len(v) > max {
		return fmt.Errorf("waterwall: %s required (1-%d chars)", label, max)
	}
	if strings.ContainsAny(v, "\"'\\\n\r\t `@/:") {
		return fmt.Errorf("waterwall: %s must be a bare host/IP without port or metacharacters", label)
	}
	return nil
}

func waterwallValidateParams(p waterwallParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("waterwall: server_side required")
	}
	if err := backhaulValidateArtifactPins2(p.Version, p.Artifact, p.SHA256Amd, p.SigAmd,
		p.SHA256Arm, p.SigArm, wwID); err != nil {
		return err
	}
	spec, ok := wwMethods[p.Method]
	if !ok {
		keys := make([]string, 0, len(wwMethods))
		for k := range wwMethods {
			keys = append(keys, k)
		}
		return fmt.Errorf("waterwall: method %q not supported (%s)", p.Method, strings.Join(keys, "|"))
	}
	if _, _, e := net_SplitHostPort(p.ServerAddr); e != nil {
		return fmt.Errorf("waterwall: server_addr must be host:port")
	}
	if err := wwValidateHost("local_addr", p.LocalAddr, 253); err != nil {
		return err
	}
	if p.LocalPort <= 0 || p.LocalPort > 65535 {
		return fmt.Errorf("waterwall: local_port out of range")
	}
	// per-method requirements + dead-field refusals (the render consumes
	// exactly what the method needs — dead secrets are refused, not carried).
	uses := func(fields ...string) bool {
		for _, f := range fields {
			if f == "auth" && (p.AuthPassword != "" || p.AuthUser != "") {
				return true
			}
			if f == "uuid" && p.UUID != "" {
				return true
			}
			if f == "tls" && (p.TLSCert != "" || p.TLSKey != "") {
				return true
			}
			if f == "wg" && (p.WGPrivateKey != "" || p.WGAuthSecret != "") {
				return true
			}
			if f == "obfs" && (p.ObfsMethod != "" || p.ObfsKey != 0) {
				return true
			}
			if f == "rtmp" && (p.RtmpApp != "" || p.RtmpStream != "") {
				return true
			}
		}
		return false
	}
	// required secrets per method
	switch p.Method {
	case "trojan", "reality", "bgp4", "fake-tcp", "reverse":
		if err := engineVerifySecretShape("waterwall auth_password", p.AuthPassword, 8, 128); err != nil {
			return err
		}
		if p.Method == "fake-tcp" {
			// the per-end real-IP context (OVERNIGHT-A8): the iran host's
			// raw-reachable IP is REQUIRED; the carrier host must be a bare
			// IP (raw-socket fake-TCP framing targets a bare address — no
			// DNS in the raw path).
			if strings.TrimSpace(p.FakeTCPClientIP) == "" || len(p.FakeTCPClientIP) > 45 ||
				strings.ContainsAny(p.FakeTCPClientIP, "\"'\n\r ") ||
				net.ParseIP(strings.TrimSpace(p.FakeTCPClientIP)) == nil {
				return fmt.Errorf("waterwall: method fake-tcp needs fake_tcp_client_ip — a bare IP (the iran host's raw-reachable address; the per-end real-IP context)")
			}
			if h, _, e := net.SplitHostPort(strings.TrimSpace(p.ServerAddr)); e != nil ||
				net.ParseIP(h) == nil {
				return fmt.Errorf("waterwall: method fake-tcp needs server_addr's host as a bare IP (the raw carrier has no DNS)")
			}
		}
	case "vless", "vmess":
		if err := engineVerifySecretShape("waterwall uuid", p.UUID, 16, 64); err != nil {
			return err
		}
	case "wireguard":
		if err := engineVerifySecretShape("waterwall wg_private_key", p.WGPrivateKey, 16, 128); err != nil {
			return err
		}
		if err := engineVerifySecretShape("waterwall wg_auth_secret", p.WGAuthSecret, 8, 128); err != nil {
			return err
		}
	case "http", "socks5":
		if p.NoAuth {
			if p.AuthPassword != "" || p.AuthUser != "" {
				return fmt.Errorf("waterwall: no_auth forbids auth_user/auth_password")
			}
		} else {
			if err := engineVerifySecretShape("waterwall auth_password", p.AuthPassword, 4, 128); err != nil {
				return err
			}
			if err := engineVerifySecretShape("waterwall auth_user", p.AuthUser, 1, 64); err != nil {
				return err
			}
		}
	}
	// TLS-bearing methods need the cert pair (fail closed)
	if spec.tls {
		if strings.TrimSpace(p.TLSCert) == "" || strings.TrimSpace(p.TLSKey) == "" {
			return fmt.Errorf("waterwall: method %s is TLS-bearing — tls_cert and tls_key are required", p.Method)
		}
	}
	// dead-field refusals per method family
	type fam struct {
		label string
		ok    bool
	}
	for _, f := range []fam{
		{"auth", p.Method == "trojan" || p.Method == "reality" || p.Method == "bgp4" ||
			p.Method == "fake-tcp" || p.Method == "http" || p.Method == "socks5" || p.Method == "reverse"},
		{"uuid", p.Method == "vless" || p.Method == "vmess"},
		{"wg", p.Method == "wireguard"},
		{"rtmp", p.Method == "rtmp"},
		{"obfs", p.Method == "gns" || p.Method == "obfuscator"},
	} {
		if !f.ok && uses(f.label) {
			return fmt.Errorf("waterwall: %s fields are dead weight for method %s", f.label, p.Method)
		}
	}
	// charsets for everything that renders
	for _, a := range []struct {
		label, v string
		max      int
	}{{"tls_cert", p.TLSCert, 256}, {"tls_key", p.TLSKey, 256}, {"sni", p.SNI, 253},
		{"auth_user", p.AuthUser, 64}, {"rtmp_app", p.RtmpApp, 64}, {"rtmp_stream", p.RtmpStream, 64},
		{"obfs_method", p.ObfsMethod, 16}} {
		if a.v != "" {
			if err := wwSafe(a.label, a.v, a.max); err != nil {
				return err
			}
		}
	}
	for _, a := range []struct {
		label, v string
		max      int
	}{{"auth_password", p.AuthPassword, 128}, {"wg_private_key", p.WGPrivateKey, 128},
		{"wg_auth_secret", p.WGAuthSecret, 128}} {
		if a.v != "" {
			if err := wwSafe(a.label, a.v, a.max); err != nil {
				return err
			}
		}
	}
	if p.ObfsMethod != "" && p.ObfsMethod != "xor" {
		return fmt.Errorf("waterwall: obfs_method %q not supported (xor — the upstream obfuscated example method)", p.ObfsMethod)
	}
	if p.ObfsKey < 0 || p.ObfsKey > 255 {
		return fmt.Errorf("waterwall: obfs_key must be 0-255 (the xor byte)")
	}
	if p.SendMTU != 0 && (p.SendMTU < 576 || p.SendMTU > 9000) {
		return fmt.Errorf("waterwall: send_mtu out of range (576-9000; 0 = upstream default)")
	}
	if p.FakeTCPPort != 0 && (p.FakeTCPPort < 1 || p.FakeTCPPort > 65535) {
		return fmt.Errorf("waterwall: fake_tcp_port out of range")
	}
	// OVERNIGHT-A6: the reverse chain's public listener.
	if p.Method == "reverse" {
		if p.ReversePort <= 0 || p.ReversePort > 65535 {
			return fmt.Errorf("waterwall: method reverse needs reverse_port 1-65535 (the foreign public listener)")
		}
		if p.ReversePort == p.LocalPort {
			return fmt.Errorf("waterwall: reverse_port must differ from local_port (the two listeners collide)")
		}
	}
	return nil
}

// net_SplitHostPort wraps net.SplitHostPort (kept local so the driver file
// stays self-documenting about what it validates).
func net_SplitHostPort(s string) (string, string, error) { return net.SplitHostPort(s) }

// ---- typed node-chain rendering ------------------------------------------

// wwNode is one config node. Settings is built in code with literal keys and
// charset-validated values only — json.Marshal handles quoting.
type wwNode struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Settings map[string]any `json:"settings,omitempty"`
	Next     string         `json:"next,omitempty"`
}

type wwConfig struct {
	Name  string   `json:"name"`
	Nodes []wwNode `json:"nodes"`
}

type wwCore struct {
	Misc    map[string]any `json:"misc"`
	Configs []string       `json:"configs"`
}

// wwCarrierPort extracts the carrier port.
func wwCarrierPort(p waterwallParams) int {
	_, port, _ := net_SplitHostPort(p.ServerAddr)
	n, _ := strconv.Atoi(port)
	return n
}

// wwChain renders one end's node chain for the method. The chain edges cite
// the upstream tunnels/*/description.md placements (see the header).
func wwChain(role string, p waterwallParams) wwConfig {
	host := strings.TrimSpace(p.LocalAddr)
	entry := "in"
	carrierOut := "carrier"
	var nodes []wwNode
	join := func(ns ...wwNode) {
		for i := 0; i < len(ns)-1; i++ {
			ns[i].Next = ns[i+1].Name
		}
		nodes = append(nodes, ns...)
	}
	mtu := p.SendMTU
	carrierHost := p.ServerAddr[:strings.LastIndex(p.ServerAddr, ":")]
	cPort := wwCarrierPort(p)
	// helper constructors keep the chains readable
	tcpIn := func(port int) wwNode {
		return wwNode{Name: entry, Type: "TcpListener",
			Settings: map[string]any{"address": "0.0.0.0", "port": port}}
	}
	tcpDial := func(addr string, port int) wwNode {
		return wwNode{Name: "target", Type: "TcpConnector",
			Settings: map[string]any{"address": addr, "port": port}}
	}
	udpIn := func(port int) wwNode {
		return wwNode{Name: entry, Type: "UdpListener",
			Settings: map[string]any{"address": "0.0.0.0", "port": port}}
	}
	udpDial := func(addr string, port int) wwNode {
		return wwNode{Name: carrierOut, Type: "UdpConnector",
			Settings: map[string]any{"address": addr, "port": port}}
	}
	tlsSrv := func(next string) wwNode {
		return wwNode{Name: "tls", Type: "TlsServer", Next: next,
			Settings: map[string]any{"cert-file": p.TLSCert, "key-file": p.TLSKey}}
	}
	tlsCli := func(next string) wwNode {
		s := map[string]any{}
		if p.SNI != "" {
			s["server-name"] = p.SNI
		}
		return wwNode{Name: "tls", Type: "TlsClient", Next: next, Settings: s}
	}
	authSrv := func(next string) wwNode {
		return wwNode{Name: "auth", Type: "AuthenticationServer", Next: next,
			Settings: map[string]any{"auth-clients": []map[string]any{{"name": "quantum", "secret": p.WGAuthSecret}}}}
	}
	authCli := func(next string) wwNode {
		return wwNode{Name: "accounts", Type: "AuthenticationClient", Next: next,
			Settings: map[string]any{"name": "quantum", "secret": p.WGAuthSecret}}
	}
	switch p.Method {
	case "quic":
		if role == "server" {
			join(udpIn(cPort),
				wwNode{Name: "q", Type: "QuicServer", Next: "target",
					Settings: map[string]any{"cert-file": p.TLSCert, "key-file": p.TLSKey, "protocol": "h3"}},
				tcpDial(host, p.LocalPort))
		} else {
			// the sni field is REQUIRED nonempty upstream (lab-verified:
			// "QUIC settings->sni must be a nonempty string") — default to
			// the carrier host like the other drivers do.
			sni := p.SNI
			if sni == "" {
				sni = carrierHost
			}
			qs := map[string]any{"protocol": "h3", "sni": sni}
			if p.WWInsecure {
				qs["verify"] = false
			}
			join(tcpIn(p.LocalPort), wwNode{Name: "q", Type: "QuicClient", Next: carrierOut, Settings: qs},
				udpDial(carrierHost, cPort))
		}
	case "kcp":
		ks := map[string]any{}
		if mtu > 0 {
			ks["send-mtu"] = mtu
		}
		if p.KcpFEC {
			ks["fec"] = true
		}
		if role == "server" {
			join(udpIn(cPort), wwNode{Name: "k", Type: "KcpServer", Next: "target", Settings: ks}, tcpDial(host, p.LocalPort))
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "k", Type: "KcpClient", Next: carrierOut, Settings: ks},
				udpDial(carrierHost, cPort))
		}
	case "enet":
		es := map[string]any{}
		if mtu > 0 {
			es["send-mtu"] = mtu
		}
		if role == "server" {
			join(udpIn(cPort), wwNode{Name: "e", Type: "EnetServer", Next: "target", Settings: es}, tcpDial(host, p.LocalPort))
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "e", Type: "EnetClient", Next: carrierOut, Settings: es},
				udpDial(carrierHost, cPort))
		}
	case "reality":
		rs := map[string]any{"password": p.AuthPassword}
		if p.SNI != "" {
			rs["server-name"] = p.SNI
		}
		if role == "server" {
			join(tcpIn(cPort), wwNode{Name: "r", Type: "RealityServer", Next: "target", Settings: rs}, tcpDial(host, p.LocalPort))
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "r", Type: "RealityClient", Next: carrierOut, Settings: rs},
				tcpDial(carrierHost, cPort))
		}
	case "trojan":
		ts := map[string]any{"password": p.AuthPassword}
		if role == "server" {
			join(tcpIn(cPort), tlsSrv("t"), wwNode{Name: "t", Type: "TrojanServer", Next: "target", Settings: ts},
				wwNode{Name: "target", Type: "TcpUdpConnector", Settings: map[string]any{"address": host, "port": p.LocalPort}})
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "t", Type: "TrojanClient", Next: "tls", Settings: ts},
				tlsCli(carrierOut), tcpDial(carrierHost, cPort))
		}
	case "vless":
		vs := map[string]any{"uuid": p.UUID}
		if role == "server" {
			join(tcpIn(cPort), tlsSrv("v"), wwNode{Name: "v", Type: "VlessServer", Next: "target", Settings: vs},
				wwNode{Name: "target", Type: "TcpUdpConnector", Settings: map[string]any{"address": host, "port": p.LocalPort}})
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "v", Type: "VlessClient", Next: "tls", Settings: vs},
				tlsCli(carrierOut), tcpDial(carrierHost, cPort))
		}
	case "vmess":
		vs := map[string]any{"uuid": p.UUID}
		if role == "server" {
			join(tcpIn(cPort), tlsSrv("v"), wwNode{Name: "v", Type: "VmessServer", Next: "target", Settings: vs},
				wwNode{Name: "target", Type: "TcpUdpConnector", Settings: map[string]any{"address": host, "port": p.LocalPort}})
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "v", Type: "VmessClient", Next: "tls", Settings: vs},
				tlsCli(carrierOut), tcpDial(carrierHost, cPort))
		}
	case "wireguard":
		ws := map[string]any{"privatekey": p.WGPrivateKey, "mode": "connection", "auth-client-node-name": "accounts"}
		if role == "server" {
			join(udpIn(cPort), wwNode{Name: "wg", Type: "WireGuardServer", Next: "target", Settings: ws}, authSrv("target"),
				wwNode{Name: "target", Type: "TcpUdpConnector", Settings: map[string]any{"address": host, "port": p.LocalPort}})
		} else {
			join(wwNode{Name: entry, Type: "TunDevice", Settings: map[string]any{}},
				wwNode{Name: "wg", Type: "WireGuardClient", Next: "accounts", Settings: ws}, authCli(carrierOut),
				udpDial(carrierHost, cPort))
		}
	case "rtmp":
		rcli := map[string]any{}
		if p.RtmpApp != "" {
			rcli["app"] = p.RtmpApp
		}
		if p.RtmpStream != "" {
			rcli["stream"] = p.RtmpStream
		}
		if role == "server" {
			join(tcpIn(cPort), wwNode{Name: "r", Type: "RtmpServer", Next: "target", Settings: map[string]any{}}, tcpDial(host, p.LocalPort))
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "r", Type: "RtmpClient", Next: "target", Settings: rcli},
				tcpDial(carrierHost, cPort))
		}
	case "gns":
		gs := map[string]any{}
		if mtu > 0 {
			gs["send-mtu"] = mtu
		}
		obs := map[string]any{"method": "xor", "xor_key": p.ObfsKey, "skip": "none", "tls_record_header": false}
		if role == "server" {
			if p.ObfsMethod != "" {
				join(udpIn(cPort), wwNode{Name: "o", Type: "ObfuscatorServer", Next: "g", Settings: obs},
					wwNode{Name: "g", Type: "GnsServer", Next: "target", Settings: gs}, tcpDial(host, p.LocalPort))
			} else {
				join(udpIn(cPort), wwNode{Name: "g", Type: "GnsServer", Next: "target", Settings: gs}, tcpDial(host, p.LocalPort))
			}
		} else {
			if p.ObfsMethod != "" {
				join(tcpIn(p.LocalPort), wwNode{Name: "o", Type: "ObfuscatorClient", Next: "g", Settings: obs},
					wwNode{Name: "g", Type: "GnsClient", Next: carrierOut, Settings: gs}, udpDial(carrierHost, cPort))
			} else {
				join(tcpIn(p.LocalPort), wwNode{Name: "g", Type: "GnsClient", Next: carrierOut, Settings: gs},
					udpDial(carrierHost, cPort))
			}
		}
	case "bgp4":
		bs := map[string]any{"password": p.AuthPassword}
		if role == "server" {
			join(tcpIn(cPort), wwNode{Name: "b", Type: "Bgp4Server", Next: "target", Settings: bs}, tcpDial(host, p.LocalPort))
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "b", Type: "Bgp4Client", Next: carrierOut, Settings: bs},
				tcpDial(carrierHost, cPort))
		}
	case "http":
		var hs map[string]any
		if p.NoAuth {
			hs = map[string]any{"no-auth": true}
		} else {
			hs = map[string]any{"users": []map[string]any{{"username": p.AuthUser, "password": p.AuthPassword}}}
		}
		if role == "server" {
			join(tcpIn(cPort), wwNode{Name: "h", Type: "HttpProxyServer", Next: "target", Settings: hs}, tcpDial(host, p.LocalPort))
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "h", Type: "HttpProxyClient", Next: carrierOut, Settings: hs},
				tcpDial(carrierHost, cPort))
		}
	case "socks5":
		var ss map[string]any
		if p.NoAuth {
			ss = map[string]any{"no-auth": true}
		} else {
			ss = map[string]any{"accounts": []map[string]any{{"username": p.AuthUser, "password": p.AuthPassword}}}
		}
		if role == "server" {
			join(tcpIn(cPort), wwNode{Name: "s", Type: "Socks5Server", Next: "target", Settings: ss}, tcpDial(host, p.LocalPort))
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "s", Type: "Socks5Client", Next: carrierOut, Settings: ss},
				tcpDial(carrierHost, cPort))
		}
	case "fake-tcp":
		// OVERNIGHT-A8: the FULL upstream shape (tunnels/FakeTcpHeaderClient|
		// Server/examples/client|server/config.json) with the per-end real-IP
		// overrides the A5 minimal render lacked. The simulated context
		// (10.90.0.1 = the simulated client, 10.90.0.2 = the simulated
		// server, the 40000/40001-40016 fake-TCP ports) is rendered from the
		// upstream example constants on BOTH ends — the pair agrees by
		// construction. The real IPs: client = FakeTCPClientIP, server =
		// server_addr's host (validation requires a bare IP).
		cliReal := strings.TrimSpace(p.FakeTCPClientIP)
		fs := map[string]any{"password": p.AuthPassword}
		if p.FakeTCPPort > 0 {
			fs["server-port"] = p.FakeTCPPort
		} else {
			fs["server-port"] = 40000 // the upstream example default
		}
		header := map[string]any{
			"client-port-range":  []int{40001, 40016},
			"sequence":           "random_port",
			"increment-sequence": true,
			"window":             65535,
		}
		ctP := map[string]any{
			"source-ipv4":    "10.90.0.1",
			"target-address": "10.90.0.2",
			"port":           5300,
			"mtu":            1479,
		}
		if role == "server" {
			// RawSocket(capture cliReal) → IpOverrider → FakeTcpHeaderServer
			// → PacketsToConnection → UdpConnector(local target)
			nodes = append(nodes,
				wwNode{Name: "raw", Type: "RawSocket", Next: "ip", Settings: map[string]any{
					"capture-filter-mode": "source-ip",
					"capture-ips":         []string{cliReal},
					"capture-protocols":   []int{6},
				}},
				wwNode{Name: "ip", Type: "IpOverrider", Next: "f", Settings: map[string]any{
					"down": map[string]any{
						"source-ip": map[string]any{"ipv4": carrierHost},
						"dest-ip":   map[string]any{"ipv4": cliReal},
					},
					"up": map[string]any{
						"source-ip": map[string]any{"ipv4": "10.90.0.1"},
						"dest-ip":   map[string]any{"ipv4": "10.90.0.2"},
					},
				}},
				wwNode{Name: "f", Type: "FakeTcpHeaderServer", Next: "p", Settings: wwMergeMaps(fs, header)},
				wwNode{Name: "p", Type: "PacketsToConnection", Next: "carrier", Settings: map[string]any{}},
				udpDial(host, p.LocalPort))
		} else {
			// UdpListener(:local_port) → ConnectionToPackets →
			// FakeTcpHeaderClient → IpOverrider → RawSocket(capture srvReal)
			u := udpIn(p.LocalPort)
			u.Next = "p"
			nodes = append(nodes,
				u,
				wwNode{Name: "p", Type: "ConnectionToPackets", Next: "f", Settings: ctP},
				wwNode{Name: "f", Type: "FakeTcpHeaderClient", Next: "ip", Settings: wwMergeMaps(fs, map[string]any{
					"acknowledgment": 67890,
				})},
				wwNode{Name: "ip", Type: "IpOverrider", Next: "raw", Settings: map[string]any{
					"up": map[string]any{
						"source-ip": map[string]any{"ipv4": cliReal},
						"dest-ip":   map[string]any{"ipv4": carrierHost},
					},
					"down": map[string]any{
						"source-ip": map[string]any{"ipv4": "10.90.0.2"},
						"dest-ip":   map[string]any{"ipv4": "10.90.0.1"},
					},
				}},
				wwNode{Name: "raw", Type: "RawSocket", Settings: map[string]any{
					"capture-filter-mode": "source-ip",
					"capture-ips":         []string{carrierHost},
					"capture-protocols":   []int{6},
				}})
			_ = header
		}
	case "obfuscator":
		obs := map[string]any{"method": "xor", "xor_key": p.ObfsKey, "skip": "none", "tls_record_header": false}
		if role == "server" {
			join(udpIn(cPort), wwNode{Name: "o", Type: "ObfuscatorServer", Next: "target", Settings: obs}, tcpDial(host, p.LocalPort))
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "o", Type: "ObfuscatorClient", Next: carrierOut, Settings: obs},
				udpDial(carrierHost, cPort))
		}
	case "connection-fisher":
		if role == "server" {
			join(tcpIn(cPort), wwNode{Name: "f", Type: "ConnectionFisherServer", Next: "target", Settings: map[string]any{}}, tcpDial(host, p.LocalPort))
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "f", Type: "ConnectionFisherClient", Next: carrierOut, Settings: map[string]any{}},
				tcpDial(carrierHost, cPort))
		}
	case "connection-stripe":
		if role == "server" {
			join(tcpIn(cPort), tlsSrv("cs"), wwNode{Name: "cs", Type: "ConnectionStripeServer", Next: "target", Settings: map[string]any{}}, tcpDial(host, p.LocalPort))
		} else {
			join(tcpIn(p.LocalPort), wwNode{Name: "cs", Type: "ConnectionStripeClient", Next: "tls", Settings: map[string]any{}},
				tlsCli(carrierOut), tcpDial(carrierHost, cPort))
		}
	case "mux":
		if role == "server" {
			join(tcpIn(cPort), wwNode{Name: "m", Type: "MuxServer", Next: "uot"},
				wwNode{Name: "uot", Type: "UdpOverTcpServer", Next: "target"},
				wwNode{Name: "target", Type: "UdpConnector", Settings: map[string]any{"address": host, "port": p.LocalPort}})
		} else {
			join(udpIn(p.LocalPort), wwNode{Name: "uot", Type: "UdpOverTcpClient", Next: "m"},
				wwNode{Name: "m", Type: "MuxClient", Next: carrierOut},
				tcpDial(carrierHost, cPort))
		}
	case "reverse":
		// OVERNIGHT-A6: the Bridge-paired reverse tunnel (tunnels/
		// ReverseClient+ReverseServer: "Bridge → ReverseClient" adjacency;
		// bridges point at each other by name). Two chain segments per
		// config (multiple roots — the Bridge pair stitches them):
		//   server: TcpListener(:carrier) → ReverseServer → BridgeA
		//           TcpListener(:reverse_port) → BridgeB(pair A)
		//   client: BridgeC(pair D) → ReverseClient → TcpConnector(carrier)
		//           TcpConnector(local) → BridgeD(pair C)
		// The reverse secret rides AuthPassword (reverse-secret).
		secret := map[string]any{"reverse-secret": p.AuthPassword}
		if role == "server" {
			rev := wwNode{Name: "rev", Type: "ReverseServer", Next: "bridge-a", Settings: secret}
			nodes = append(nodes,
				wwNode{Name: entry, Type: "TcpListener",
					Settings: map[string]any{"address": "0.0.0.0", "port": cPort}, Next: rev.Name},
				rev,
				wwNode{Name: "bridge-a", Type: "Bridge", Settings: map[string]any{"pair": "bridge-b"}},
				wwNode{Name: "pub", Type: "TcpListener",
					Settings: map[string]any{"address": "0.0.0.0", "port": p.ReversePort},
					Next:     "bridge-b"},
				wwNode{Name: "bridge-b", Type: "Bridge", Settings: map[string]any{"pair": "bridge-a"}})
		} else {
			rc := wwNode{Name: "rev", Type: "ReverseClient", Next: carrierOut, Settings: secret}
			nodes = append(nodes,
				wwNode{Name: "bridge-c", Type: "Bridge", Settings: map[string]any{"pair": "bridge-d"}, Next: rc.Name},
				rc,
				tcpDial(carrierHost, cPort),
				wwNode{Name: "target", Type: "TcpConnector",
					Settings: map[string]any{"address": host, "port": p.LocalPort},
					Next:     "bridge-d"},
				wwNode{Name: "bridge-d", Type: "Bridge", Settings: map[string]any{"pair": "bridge-c"}})
		}
	}
	return wwConfig{Name: "quantum-" + p.Method + "-" + role, Nodes: nodes}
}

// waterwallRenderFiles builds the two config files (core.json + config.json)
// for one end. The binary reads core.json from its CWD.
func waterwallRenderFiles(role string, p waterwallParams) (core []byte, cfg []byte, err error) {
	ram := "client"
	if role == "server" {
		ram = "server"
	}
	coreObj := wwCore{Misc: map[string]any{"workers": 1, "ram-profile": ram,
		"tcp-tune": false, "try-enabling-bbr": false}, Configs: []string{"config.json"}}
	cfgObj := wwChain(role, p)
	if core, err = json.MarshalIndent(coreObj, "", " "); err != nil {
		return nil, nil, err
	}
	if cfg, err = json.MarshalIndent(cfgObj, "", " "); err != nil {
		return nil, nil, err
	}
	return core, cfg, nil
}

func waterwallEngineDir() string { return engineEngineDir(wwID) }

func waterwallBinDir(version string) string {
	return filepath.Join(waterwallEngineDir(), "bin", version)
}

func waterwallInstanceDir(tunnelID string) string {
	return filepath.Join(waterwallEngineDir(), "instances", tunnelID)
}

// waterwallSpawn runs the binary bare from the instance dir (core.json CWD
// contract — readme.md). argv-only.
var waterwallSpawn = func(binPath, dir string) (frpProcess, error) {
	cmd := exec.Command(binPath)
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("waterwall: start: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

// waterwallEnsureBinary: manifest-first (engine "waterwall"), pinned
// fallback; the tarball carries waterwall/waterwall.
func waterwallEnsureBinary(ctx context.Context, p waterwallParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("waterwall: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.wwArtifactPin(); pinErr == nil &&
		engineCacheHit(waterwallBinDir(p.Version), pinnedSHA, []string{"waterwall"}) {
		return waterwallBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("waterwall: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, wwID,
		func() (string, string, string, error) { return p.wwArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := waterwallBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"waterwall"}) {
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
		return "", fmt.Errorf("waterwall: cache dir: %w", err)
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"waterwall": true}); err != nil {
		return "", fmt.Errorf("waterwall: %w", err)
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("waterwall: cache marker: %w", err)
	}
	return dir, nil
}

type waterwallInstState struct {
	engineInst
	params waterwallParams
	role   string
}

// WaterwallDriver implements engine.Driver for the vendored WaterWall core.
type WaterwallDriver struct {
	runs *instTable[waterwallInstState]
}

func NewWaterwallDriver() *WaterwallDriver {
	return &WaterwallDriver{runs: newInstTable[waterwallInstState]()}
}

// wwMergeMaps composes two settings maps (base first, overrides win) —
// the fake-tcp header fields ride the base password/server-port map.
func wwMergeMaps(base, overrides map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(overrides))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overrides {
		out[k] = v
	}
	return out
}

func (d *WaterwallDriver) ID() string { return wwID }

func (d *WaterwallDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: wwID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","method":"quic|kcp|enet|reality|trojan|vless|vmess|wireguard|rtmp|gns|bgp4|http|socks5|fake-tcp|obfuscator|connection-fisher|connection-stripe|mux|reverse","server_addr":"0.0.0.0:4433","local_addr":"127.0.0.1","local_port":0,"auth_password":"","auth_user":"","uuid":"","tls_cert":"","tls_key":"","sni":"","wg_private_key":"","wg_auth_secret":"","obfs_method":"xor","obfs_key":90,"send_mtu":0,"kcp_fec":false,"rtmp_app":"","rtmp_stream":"","no_auth":false,"fake_tcp_port":0,"reverse_port":0}`)}
}

func (d *WaterwallDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *WaterwallDriver) Validate(params json.RawMessage) error {
	var p waterwallParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("waterwall: engine_params: %w", err)
	}
	return waterwallValidateParams(p)
}

func waterwallResolveRole(p waterwallParams) (string, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("waterwall: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return "server", nil
	}
	return "client", nil
}

func (d *WaterwallDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p waterwallParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("waterwall: engine_params: %w", err)
	}
	if err := waterwallValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("waterwall: invalid tunnel id %q", inst.TunnelID)
	}
	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual[waterwallParams](prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}
	role, err := waterwallResolveRole(p)
	if err != nil {
		return err
	}
	binDir, err := waterwallEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "waterwall")
	dir := waterwallInstanceDir(inst.TunnelID)
	core, cfg, err := waterwallRenderFiles(role, p)
	if err != nil {
		return fmt.Errorf("waterwall: render: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("waterwall: instance dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "core.json"), core, 0o600); err != nil {
		return fmt.Errorf("waterwall: write core.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), cfg, 0o600); err != nil {
		return fmt.Errorf("waterwall: write config.json: %w", err)
	}
	proc, err := waterwallSpawn(binPath, dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	st := &waterwallInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		binPath: binPath, cfg: dir}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, st.binPath, "", func(b, _ string) (frpProcess, error) {
		return waterwallSpawn(b, dir)
	})
	// wire accounting on the server end's carrier port (raw-carrier methods
	// have no per-port socket to tag — skipped honestly).
	if role == "server" {
		if spec := wwMethods[p.Method]; spec.carrier != "raw" {
			proto := spec.carrier
			if proto == "tcp" || proto == "udp" {
				if port := wwCarrierPort(p); port > 0 {
					if err := acctWireRulesAddProto(acctChainsDriver, inst.TunnelID, port, port, proto); err != nil {
						fmt.Fprintf(os.Stderr, "waterwall: wire accounting unavailable: %v\n", err)
					}
				}
			}
		}
	}
	return nil
}

func (d *WaterwallDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.role == "server" {
			if spec := wwMethods[st.params.Method]; spec.carrier == "tcp" || spec.carrier == "udp" {
				if port := wwCarrierPort(st.params); port > 0 {
					_ = acctWireRulesDelProto(acctChainsDriver, inst.TunnelID, port, port, spec.carrier)
				}
			}
		}
		if st.cfg != "" {
			_ = os.RemoveAll(st.cfg) // the whole instance dir (core.json + config.json)
		}
	})
	return nil
}

func (d *WaterwallDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, wwID, inst.TunnelID, inst.Params,
		func(st *waterwallInstState) waterwallParams { return st.params }, engineParamsEqual[waterwallParams])
}

// Health: process-alive; on the server end a TCP-carrier dial proves the
// listener is bound (udp/raw carriers — process-alive, honestly).
func (d *WaterwallDriver) Health(inst engine.Instance) engine.Health {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Health{OK: false, Detail: "not running", LatencyMs: -1}
	}
	select {
	case <-st.current().Done():
		return engine.Health{OK: false, Detail: "process exited", LatencyMs: -1}
	default:
	}
	if st.role == "server" && wwMethods[st.params.Method].carrier == "tcp" {
		start := time.Now()
		if err := gostHealthDial(wwCarrierPort(st.params)); err == nil {
			return engine.Health{OK: true, Detail: "waterwall tunnel registered (carrier answering)",
				LatencyMs: float64(time.Since(start).Milliseconds())}
		}
		return engine.Health{OK: false, Detail: "carrier port not answering", LatencyMs: -1}
	}
	return engine.Health{OK: true, Detail: "waterwall " + st.role + " running (" + st.params.Method + ")", LatencyMs: -1}
}

// Counters: the SERVER end's wire view on the carrier port (tcp/udp
// carriers); raw/L3 carriers stay Unknown, honestly.
func (d *WaterwallDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil || st.role != "server" {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if spec := wwMethods[st.params.Method]; spec.carrier == "tcp" || spec.carrier == "udp" {
		if port := wwCarrierPort(st.params); port > 0 {
			if rx, tx, ok := acctWireBytes(inst.TunnelID, port, port); ok {
				out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
			}
		}
	}
	return out
}

func (d *WaterwallDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, waterwallEngineDir())
	return nil
}

// waterwallVersionProbe: `Waterwall version` (the C2 smoke shape), bounded.
var waterwallVersionProbe = func(binPath string) (string, error) {
	out, err := infra.RunCmdTimeout(10*time.Second, binPath, "version")
	if err != nil {
		return "", err
	}
	f := strings.Fields(strings.TrimSpace(string(out)))
	if len(f) >= 3 && f[0] == "Waterwall" && f[1] == "version" {
		return f[2], nil
	}
	return "", fmt.Errorf("waterwall: unexpected version output")
}

func waterwallInstalledVersion() string {
	base := filepath.Join(waterwallEngineDir(), "bin")
	entries, err := os.ReadDir(base)
	if err != nil {
		return waterwallPinnedVersion
	}
	best := ""
	for _, e := range entries {
		if !e.IsDir() || !infra.FileExists(filepath.Join(base, e.Name(), "waterwall")) {
			continue
		}
		if ctVersionLess(best, e.Name()) {
			best = e.Name()
		}
	}
	if best == "" {
		return waterwallPinnedVersion
	}
	if v, err := waterwallVersionProbe(filepath.Join(base, best, "waterwall")); err == nil && v != "" {
		return v
	}
	return best
}

const waterwallPinnedVersion = "1.6.0"
