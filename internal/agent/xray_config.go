package agent

// Xray Tunnel ("xray"): a port forward over Xray-core between the
// Iran server and a foreign server, like Bagher and Backhaul. Users connect to
// the Iran server's ports; Xray carries each connection to 127.0.0.1:<the same
// port> on the foreign server, where the service (often a 3x-ui inbound)
// listens.
//
//	direct:  Iran dials the foreign server (Iran is the VLESS client).
//	reverse: the foreign server dials Iran (VLESS reverse proxy: Iran's
//	         inbound hands the users' connections back down the link the
//	         foreign server opened), for when Iran cannot reach it.
//
// REFACTOR-PLAN-AGENT §6.A3: this file used to BUILD the legacy tunnel's
// configs (buildXrayConfig/xrayStream, key/certificate generation, link
// validation, presets — 24/27 funcs deadcode-RTA-unreachable from main; the
// legacy handlers that used them are purged). What survives is the LINK
// SHAPE the live xray_driver.go consumes (XrayLink and its profile/key
// types, the mode/side/tag constants) and the three helpers the reachable
// graph still calls: serverEnd (xrayCarrierEnds in xray.go, xrayConns),
// xrayPortOK and xrayDialAddress (xrayCarrierEnds, xrayConns). The driver
// renders its own wire config from these types.

import (
	"encoding/json"
)

const (
	xrayModeDirect  = "direct"
	xrayModeReverse = "reverse"
	xraySideIran    = "iran"
	xraySideForeign = "foreign"

	xrayFlowVision = "xtls-rprx-vision"
	// Inbound and outbound tags; the routing rules refer to them.
	xrayTagUsers   = "users"     // Iran: the users' ports
	xrayTagTunnel  = "tunnel"    // the VLESS link (outbound on the dialing side, inbound on the other)
	xrayTagReverse = "reverse"   // Iran in reverse mode: the users' way down the foreign server's link
	xrayTagFromIR  = "from-iran" // foreign in reverse mode: connections that arrive from Iran
	xrayTagDirect  = "direct"
	xrayTagBlock   = "block"
	xrayTagProbe   = "probe"

	// xrayProbeHost is the name the probe asks for; it never leaves Xray.
	xrayProbeHost = "probe.quantum"
)

// XrayLink is one tunnel between this server and one other server. Both ends
// keep the same link (the bundle carries it); Side says which end this is.
type XrayLink struct {
	ID   int    `json:"id"`
	Name string `json:"name,omitempty"`
	Mode string `json:"mode"` // direct | reverse
	Side string `json:"side"` // iran | foreign: this server
	// Remote is the other server's address: the foreign server on Iran, the
	// Iran server on the foreign server.
	Remote string `json:"remote"`
	// TunnelPort is where the VLESS server end listens: the foreign server in
	// direct mode, the Iran server in reverse mode.
	TunnelPort int   `json:"tunnel_port"`
	Ports      []int `json:"ports"` // service ports, the same on both ends
	UDP        bool  `json:"udp"`
	// Listen is the address the users' ports bind on Iran ("" = every address).
	Listen  string          `json:"listen,omitempty"`
	Profile XrayProfile     `json:"profile"`
	Keys    XrayKeys        `json:"keys"`
	Expert  json.RawMessage `json:"expert,omitempty"` // merged over the generated config

	// Iran only: the loopback port the panel probes the link through.
	ProbePort int  `json:"probe_port,omitempty"`
	Disabled  bool `json:"disabled,omitempty"` // stopped by the user
}

// XrayKeys are the link's secrets. The Reality private key lives only on the
// end that serves Reality.
type XrayKeys struct {
	UUID       string `json:"uuid"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	ShortID    string `json:"short_id,omitempty"`
	// TLS without a certificate of the user's own: one the panel makes for the
	// SNI (PEM). The key lives only on the TLS server end; the dialing end
	// pins the certificate, or, through a CDN, checks the CDN's real one.
	TLSCert string `json:"tls_cert,omitempty"`
	TLSKey  string `json:"tls_key,omitempty"`
}

// XrayProfile is how the link looks on the wire. A beginner picks a preset
// (xrayPresets); every field stays editable.
type XrayProfile struct {
	Preset    string `json:"preset,omitempty"`
	Transport string `json:"transport"` // raw | xhttp | grpc | ws | httpupgrade | kcp
	Security  string `json:"security"`  // reality | tls | none
	Vision    bool   `json:"vision,omitempty"`

	SNI         string `json:"sni,omitempty"`
	Target      string `json:"target,omitempty"` // Reality: whose handshake it borrows (default SNI:443)
	Fingerprint string `json:"fingerprint,omitempty"`
	SpiderX     string `json:"spider_x,omitempty"`
	Xver        int    `json:"xver,omitempty"` // PROXY protocol to the Reality target

	Path      string `json:"path,omitempty"` // xhttp / ws / httpupgrade path, gRPC service name
	Host      string `json:"host,omitempty"` // HTTP Host header
	XHTTPMode string `json:"xhttp_mode,omitempty"`
	// CDN: the dialing end goes through a CDN (Cloudflare) to the SNI domain,
	// whose DNS record points at the TLS server end.
	CDN bool `json:"cdn,omitempty"`
	// Address is dialed instead of the other server (a CDN's clean IP).
	Address  string `json:"address,omitempty"`
	CertFile string `json:"cert_file,omitempty"` // TLS server end: the user's own certificate
	KeyFile  string `json:"key_file,omitempty"`

	Mux        int    `json:"mux,omitempty"` // mux concurrency, 0 = off
	XUDP       int    `json:"xudp,omitempty"`
	TFO        bool   `json:"tfo,omitempty"`
	Congestion string `json:"congestion,omitempty"` // tcpCongestion: bbr, cubic, …
	MPTCP      bool   `json:"mptcp,omitempty"`
	Mark       int    `json:"mark,omitempty"`

	Fragment *XrayFragment `json:"fragment,omitempty"` // dialing end only
	Noise    *XrayNoise    `json:"noise,omitempty"`    // dialing end, UDP (mKCP) only
	KCP      *XrayKCP      `json:"kcp,omitempty"`
}

// XrayFragment splits the dialing end's first packets (finalmask "fragment").
type XrayFragment struct {
	Packets string `json:"packets"` // "tlshello" or a range such as "1-3"
	Length  string `json:"length"`  // "100-200"
	Delay   string `json:"delay"`   // "10-20" ms
}

// XrayNoise is what the dialing end sends before its first real UDP packet
// (finalmask "noise"): Count packets of random bytes (Length) or of a fixed
// Packet (str, hex or base64), Delay ms apart.
type XrayNoise struct {
	Type   string `json:"type"`             // rand | str | hex | base64
	Packet string `json:"packet,omitempty"` // str / hex / base64
	Length string `json:"length,omitempty"` // rand: bytes, "10-60"
	Delay  string `json:"delay,omitempty"`  // ms, "10-20"
	Count  int    `json:"count,omitempty"`  // 1-10, default 1
}

// XrayKCP is mKCP's tuning. Password keys the mkcp-aes128gcm mask (what the
// old "seed" did), which both ends need.
type XrayKCP struct {
	MTU        int    `json:"mtu,omitempty"`
	TTI        int    `json:"tti,omitempty"`
	Up         int    `json:"up,omitempty"`   // uplinkCapacity, MB/s
	Down       int    `json:"down,omitempty"` // downlinkCapacity, MB/s
	Congestion bool   `json:"congestion,omitempty"`
	Password   string `json:"password,omitempty"`
}

// serverEnd reports whether this end runs the VLESS inbound: the foreign
// server in direct mode, the Iran server in reverse mode.
func (l XrayLink) serverEnd() bool { return (l.Mode == xrayModeDirect) == (l.Side == xraySideForeign) }

// listens are the ports this end binds: the users' ports on Iran and the
// tunnel port on the VLESS server end. §6.A3: held for xray_coexist.go
// (out of this stage's named scope).
func (l XrayLink) listens() (tcp, udp []int) {
	if l.Side == xraySideIran {
		tcp = append(tcp, l.Ports...)
		if l.ProbePort > 0 {
			tcp = append(tcp, l.ProbePort)
		}
		if l.UDP {
			udp = append(udp, l.Ports...)
		}
	}
	if l.serverEnd() {
		if l.Profile.Transport == "kcp" {
			udp = append(udp, l.TunnelPort)
		} else {
			tcp = append(tcp, l.TunnelPort)
		}
	}
	return tcp, udp
}

func xrayPortOK(p int) bool { return p > 0 && p <= 65535 }

// xrayDialAddress is what the dialing end connects to: the CDN address when
// one is set, else the other server.
func xrayDialAddress(l XrayLink) string {
	if l.Profile.Address != "" {
		return l.Profile.Address
	}
	if l.Profile.CDN {
		return l.Profile.SNI // the domain, which the CDN answers for
	}
	return l.Remote
}
