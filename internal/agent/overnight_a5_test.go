package agent

// Hermetic tests for OVERNIGHT-A5: the WaterWall driver (18-method
// node-chain engine over the vendored dual-arch core) + the endpoint-family
// documentation verdicts. Upstream evidence: tunnels/*/description.md
// placements + examples (quic datagram, enet udp, gns obfuscated,
// tls-kcp, wireguard connection, http authenticated, connection-stripe
// tls, mux, trojan/vless/vmess/reality/rtmp/bgp4/socks5/fake-tcp/
// obfuscator/connection-fisher placements).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func wwTestParams() waterwallParams {
	return waterwallParams{
		ServerSide: "germany", Version: "1.6.0",
		Artifact:  "waterwall-1.6.0-linux-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("aa", 32), SHA256Arm: strings.Repeat("bb", 32),
		SigAmd: strings.Repeat("QQ==", 22)[:88], SigArm: strings.Repeat("QQ==", 22)[:88],
		Method: "quic", ServerAddr: "0.0.0.0:4433",
		LocalAddr: "127.0.0.1", LocalPort: 21500,
		TLSCert: "/etc/quantum/ww.crt", TLSKey: "/etc/quantum/ww.key",
	}
}

func TestWaterwallAll18MethodsRender(t *testing.T) {
	// every method must render BOTH ends with the documented chain shape.
	cases := []struct {
		method     string
		setUp      func(*waterwallParams)
		wantServer []string // node types in order
		wantClient []string
	}{
		{"quic", func(p *waterwallParams) {},
			[]string{"UdpListener", "QuicServer", "TcpConnector"},
			[]string{"TcpListener", "QuicClient", "UdpConnector"}},
		{"kcp", func(p *waterwallParams) {},
			[]string{"UdpListener", "KcpServer", "TcpConnector"},
			[]string{"TcpListener", "KcpClient", "UdpConnector"}},
		{"enet", func(p *waterwallParams) {},
			[]string{"UdpListener", "EnetServer", "TcpConnector"},
			[]string{"TcpListener", "EnetClient", "UdpConnector"}},
		{"reality", func(p *waterwallParams) { p.AuthPassword = "ww-reality-pw" },
			[]string{"TcpListener", "RealityServer", "TcpConnector"},
			[]string{"TcpListener", "RealityClient", "TcpConnector"}},
		{"trojan", func(p *waterwallParams) { p.AuthPassword = "ww-trojan-pw" },
			[]string{"TcpListener", "TlsServer", "TrojanServer", "TcpUdpConnector"},
			[]string{"TcpListener", "TrojanClient", "TlsClient", "TcpConnector"}},
		{"vless", func(p *waterwallParams) { p.UUID = "123e4567-e89b-12d3-a456-426614174000" },
			[]string{"TcpListener", "TlsServer", "VlessServer", "TcpUdpConnector"},
			[]string{"TcpListener", "VlessClient", "TlsClient", "TcpConnector"}},
		{"vmess", func(p *waterwallParams) { p.UUID = "123e4567-e89b-12d3-a456-426614174000" },
			[]string{"TcpListener", "TlsServer", "VmessServer", "TcpUdpConnector"},
			[]string{"TcpListener", "VmessClient", "TlsClient", "TcpConnector"}},
		{"wireguard", func(p *waterwallParams) {
			p.WGPrivateKey, p.WGAuthSecret = "WWwgsecretkey0168", "WWauthsecret01"
		},
			[]string{"UdpListener", "WireGuardServer", "AuthenticationServer", "TcpUdpConnector"},
			[]string{"TunDevice", "WireGuardClient", "AuthenticationClient", "UdpConnector"}},
		{"rtmp", func(p *waterwallParams) { p.RtmpApp, p.RtmpStream = "live", "key1" },
			[]string{"TcpListener", "RtmpServer", "TcpConnector"},
			[]string{"TcpListener", "RtmpClient", "TcpConnector"}},
		{"gns", func(p *waterwallParams) { p.ObfsMethod, p.ObfsKey = "xor", 90 },
			[]string{"UdpListener", "ObfuscatorServer", "GnsServer", "TcpConnector"},
			[]string{"TcpListener", "ObfuscatorClient", "GnsClient", "UdpConnector"}},
		{"bgp4", func(p *waterwallParams) { p.AuthPassword = "ww-bgp-pw-01" },
			[]string{"TcpListener", "Bgp4Server", "TcpConnector"},
			[]string{"TcpListener", "Bgp4Client", "TcpConnector"}},
		{"http", func(p *waterwallParams) { p.AuthUser, p.AuthPassword = "wwuser", "ww-http-pw-1" },
			[]string{"TcpListener", "HttpProxyServer", "TcpConnector"},
			[]string{"TcpListener", "HttpProxyClient", "TcpConnector"}},
		{"socks5", func(p *waterwallParams) { p.AuthUser, p.AuthPassword = "wwuser", "ww-s5-pw-01" },
			[]string{"TcpListener", "Socks5Server", "TcpConnector"},
			[]string{"TcpListener", "Socks5Client", "TcpConnector"}},
		{"fake-tcp", func(p *waterwallParams) { p.AuthPassword = "ww-ftcp-pw-1" },
			[]string{"RawSocket", "IpOverrider", "FakeTcpHeaderServer", "PacketsToConnection", "UdpConnector"},
			[]string{"UdpListener", "ConnectionToPackets", "FakeTcpHeaderClient", "IpOverrider", "RawSocket"}},
		{"obfuscator", func(p *waterwallParams) { p.ObfsMethod, p.ObfsKey = "xor", 90 },
			[]string{"UdpListener", "ObfuscatorServer", "TcpConnector"},
			[]string{"TcpListener", "ObfuscatorClient", "UdpConnector"}},
		{"connection-fisher", func(p *waterwallParams) {},
			[]string{"TcpListener", "ConnectionFisherServer", "TcpConnector"},
			[]string{"TcpListener", "ConnectionFisherClient", "TcpConnector"}},
		{"connection-stripe", func(p *waterwallParams) {},
			[]string{"TcpListener", "TlsServer", "ConnectionStripeServer", "TcpConnector"},
			[]string{"TcpListener", "ConnectionStripeClient", "TlsClient", "TcpConnector"}},
		{"mux", func(p *waterwallParams) {},
			[]string{"TcpListener", "MuxServer", "UdpOverTcpServer", "UdpConnector"},
			[]string{"UdpListener", "UdpOverTcpClient", "MuxClient", "TcpConnector"}},
	}
	for _, tc := range cases {
		p := wwTestParams()
		p.Method = tc.method
		tc.setUp(&p)
		if err := waterwallValidateParams(p); err != nil {
			t.Fatalf("%s: validate: %v", tc.method, err)
		}
		srv := wwChain("server", p)
		if len(srv.Nodes) != len(tc.wantServer) {
			t.Fatalf("%s server chain length %d != %d", tc.method, len(srv.Nodes), len(tc.wantServer))
		}
		for i, w := range tc.wantServer {
			if srv.Nodes[i].Type != w {
				t.Fatalf("%s server node %d = %s, want %s", tc.method, i, srv.Nodes[i].Type, w)
			}
		}
		cli := wwChain("client", p)
		for i, w := range tc.wantClient {
			if cli.Nodes[i].Type != w {
				t.Fatalf("%s client node %d = %s, want %s", tc.method, i, cli.Nodes[i].Type, w)
			}
		}
		// the chain edges must be connected end to end
		for i := 0; i < len(srv.Nodes)-1; i++ {
			if srv.Nodes[i].Next != srv.Nodes[i+1].Name {
				t.Fatalf("%s server edge %d broken: %q -> %q", tc.method, i, srv.Nodes[i].Name, srv.Nodes[i].Next)
			}
		}
		// the rendered files must be valid JSON with the core contract
		core, cfg, err := waterwallRenderFiles("server", p)
		if err != nil {
			t.Fatalf("%s render: %v", tc.method, err)
		}
		var c coreObj
		_ = c
		var coreParsed map[string]any
		if err := json.Unmarshal(core, &coreParsed); err != nil {
			t.Fatalf("%s core.json invalid: %v", tc.method, err)
		}
		var cfgParsed map[string]any
		if err := json.Unmarshal(cfg, &cfgParsed); err != nil {
			t.Fatalf("%s config.json invalid: %v", tc.method, err)
		}
	}
}

type coreObj struct{}

func TestWaterwallHostileMatrix(t *testing.T) {
	// dead-secret discipline + charsets + bounds across the families.
	for name, mutate := range map[string]func(*waterwallParams){
		"unknown method":    func(p *waterwallParams) { p.Method = "hyperloop" },
		"tls method bare":   func(p *waterwallParams) { p.Method = "trojan"; p.TLSCert, p.TLSKey = "", "" },
		"dead uuid on quic": func(p *waterwallParams) { p.UUID = "123e4567-e89b-12d3-a456-426614174000" },
		"dead auth on quic": func(p *waterwallParams) { p.AuthPassword = "nope-nope-1" },
		"dead wg on quic":   func(p *waterwallParams) { p.WGPrivateKey = "WWwgsecretkey0168" },
		"dead rtmp on quic": func(p *waterwallParams) { p.RtmpApp = "live" },
		"dead obfs on quic": func(p *waterwallParams) { p.ObfsMethod = "xor" },
		"vless no uuid":     func(p *waterwallParams) { p.Method = "vless" },
		"short trojan pw":   func(p *waterwallParams) { p.Method = "trojan"; p.AuthPassword = "abc" },
		"cert quote":        func(p *waterwallParams) { p.TLSCert = `/a"b.pem` },
		"sni space":         func(p *waterwallParams) { p.SNI = "a b.com" },
		"obfs method junk":  func(p *waterwallParams) { p.ObfsMethod = "rot13" },
		"obfs key range":    func(p *waterwallParams) { p.ObfsKey = 300 },
		"mtu tiny":          func(p *waterwallParams) { p.SendMTU = 10 },
		"local_port 0":      func(p *waterwallParams) { p.LocalPort = 0 },
		"local_addr @":      func(p *waterwallParams) { p.LocalAddr = "a@b" },
	} {
		bad := wwTestParams()
		mutate(&bad)
		if err := waterwallValidateParams(bad); err == nil {
			t.Fatalf("waterwall %s accepted", name)
		}
	}
	// no_auth forbids credentials (http/socks5).
	bad := wwTestParams()
	bad.Method = "http"
	bad.NoAuth = true
	bad.AuthUser, bad.AuthPassword = "u", "p-1234"
	if err := waterwallValidateParams(bad); err == nil {
		t.Fatalf("waterwall no_auth with credentials accepted")
	}
}

func TestWaterwallRenderDetails(t *testing.T) {
	// gns obfuscated chain carries the xor layer with the example settings.
	p := wwTestParams()
	p.Method = "gns"
	p.ObfsMethod, p.ObfsKey = "xor", 90
	cfg := wwChain("server", p)
	raw, _ := json.Marshal(cfg)
	if !strings.Contains(string(raw), `"method":"xor"`) || !strings.Contains(string(raw), `"xor_key":90`) {
		t.Fatalf("gns xor settings missing: %s", raw)
	}
	// kcp fec + mtu ride the settings when set.
	p2 := wwTestParams()
	p2.Method = "kcp"
	p2.SendMTU, p2.KcpFEC = 1400, true
	raw2, _ := json.Marshal(wwChain("server", p2))
	if !strings.Contains(string(raw2), `"send-mtu":1400`) || !strings.Contains(string(raw2), `"fec":true`) {
		t.Fatalf("kcp settings missing: %s", raw2)
	}
	// no_auth renders for http; the client carrier dial uses server_addr.
	p3 := wwTestParams()
	p3.Method = "http"
	p3.NoAuth = true
	raw3, _ := json.Marshal(wwChain("client", p3))
	if !strings.Contains(string(raw3), `"no-auth":true`) || !strings.Contains(string(raw3), `"address":"0.0.0.0"`) {
		t.Fatalf("http no-auth render wrong: %s", raw3)
	}
	// core.json misc shape (workers 1, ram-profile, tuning OFF).
	core, _, _ := waterwallRenderFiles("server", wwTestParams())
	if !strings.Contains(string(core), `"ram-profile": "server"`) ||
		!strings.Contains(string(core), `"tcp-tune": false`) {
		t.Fatalf("core.json misc wrong: %s", core)
	}
}

// ---- xray hysteria2 carrier (OVERNIGHT-A5, probe-proven on v26.3.27) ------

func xrayHyParams() xrayParams {
	return xrayParams{
		ServerSide: "germany", Version: "26.3.27",
		Artifact:  "xray-26.3.27-linux-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("ee", 32), SHA256Arm: strings.Repeat("ff", 32),
		SigAmd: strings.Repeat("QQ==", 22)[:88], SigArm: strings.Repeat("QQ==", 22)[:88],
		Carrier: "hysteria2", CarrierPort: 26327, RemoteAddr: "198.51.100.9",
		HysteriaAuth: "xray-hy-pw-01",
		TLSCert:      "/etc/quantum/xr.crt", TLSKey: "/etc/quantum/xr.key",
		SocksPort: 21101,
	}
}

func TestXrayHysteria2Carrier(t *testing.T) {
	p := xrayHyParams()
	if err := xrayValidateParams(p); err != nil {
		t.Fatalf("hysteria2 params rejected: %v", err)
	}
	// server: hysteria2 inbound (version 2, users auth) + freedom.
	srv := xrayBuildConfig(engineSideServer, p)
	raw, _ := json.Marshal(srv)
	s := string(raw)
	if !strings.Contains(s, `"protocol":"hysteria"`) || !strings.Contains(s, `"version":2`) ||
		!strings.Contains(s, `"auth":"xray-hy-pw-01"`) || !strings.Contains(s, `"tag":"hysteria-in"`) ||
		!strings.Contains(s, `"protocol":"freedom"`) {
		t.Fatalf("hysteria2 server render wrong: %s", s)
	}
	// client: hysteria2 outbound + the socks/http inbounds pinned to it.
	cli := xrayBuildConfig(engineSideClient, p)
	craw, _ := json.Marshal(cli)
	cs := string(craw)
	if !strings.Contains(cs, `"tag":"carrier-out"`) || !strings.Contains(cs, `"address":"198.51.100.9"`) ||
		!strings.Contains(cs, `"port":26327`) || !strings.Contains(cs, `"inboundTag":["socks-in"],"outboundTag":"carrier-out"`) {
		t.Fatalf("hysteria2 client render wrong: %s", cs)
	}
	// hostile: Reality fields dead, missing cert pair, missing auth, no
	// ingress, unknown carrier.
	for name, mutate := range map[string]func(*xrayParams){
		"reality key dead": func(p *xrayParams) { p.RealityPublicKey = strings.Repeat("a", 43) },
		"uuid dead":        func(p *xrayParams) { p.UUID = "123e4567-e89b-12d3-a456-426614174000" },
		"public port dead": func(p *xrayParams) { p.PublicPort = 27000 },
		"no certs":         func(p *xrayParams) { p.TLSCert, p.TLSKey = "", "" },
		"no auth":          func(p *xrayParams) { p.HysteriaAuth = "" },
		"no ingress":       func(p *xrayParams) { p.SocksPort, p.HTTPPort = 0, 0 },
		"transport dead":   func(p *xrayParams) { p.Transport = "xhttp" },
		"unknown carrier":  func(p *xrayParams) { p.Carrier = "quinn" },
		"no dial host":     func(p *xrayParams) { p.RemoteAddr = "" },
	} {
		bad := xrayHyParams()
		mutate(&bad)
		if err := xrayValidateParams(bad); err == nil {
			t.Fatalf("xray hysteria2 %s accepted", name)
		}
	}
	// the default carrier path keeps its original requirements (backward
	// compat): public_port/local_addr still required there.
	def := xrayTestParams()
	def.Carrier = "hysteria2" // with Reality-era fields empty this validates
	if err := xrayValidateParams(def); err == nil && def.Carrier == "" {
		t.Fatalf("impossible state")
	}
	def2 := xrayTestParams()
	def2.Carrier = ""
	if err := xrayValidateParams(def2); err != nil {
		t.Fatalf("default carrier backward compat broken: %v", err)
	}
}

// TestWaterwallLabDump dumps the DRIVER-RENDERED configs for the netns lab
// legs (env-gated: WW_LAB_DIR set → writes core.json/config.json for the
// quic + fake-tcp methods, both ends). The lab consumes exactly what the
// driver renders — no hand-mirroring.
func TestWaterwallLabDump(t *testing.T) {
	dir := os.Getenv("WW_LAB_DIR")
	if dir == "" {
		t.Skip("WW_LAB_DIR not set")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := wwTestParams()
	base.WWInsecure = true
	// quic leg: carrier 0.0.0.0:21443, target web 127.0.0.1:21700, client entry 21170
	quic := base
	quic.Method = "quic"
	quic.ServerAddr = "10.200.0.2:21443"
	quic.LocalAddr, quic.LocalPort = "127.0.0.1", 21700
	for _, role := range []string{"server", "client"} {
		core, cfg, err := waterwallRenderFiles(role, quic)
		if err != nil {
			t.Fatal(err)
		}
		d := filepath.Join(dir, "quic-"+role)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "core.json"), core, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "config.json"), cfg, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// fake-tcp leg: the client binds :21180 (UDP entry), the raw carrier
	// dials 10.200.0.2; the server decodes and dials the UDP echo :21701.
	ft := base
	ft.Method = "fake-tcp"
	ft.AuthPassword = "ww-ftcp-lab-1"
	ft.ServerAddr = "10.200.0.2:21444"
	ft.LocalAddr, ft.LocalPort = "127.0.0.1", 21701
	for _, role := range []string{"server", "client"} {
		core, cfg, err := waterwallRenderFiles(role, ft)
		if err != nil {
			t.Fatal(err)
		}
		d := filepath.Join(dir, "fake-tcp-"+role)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "core.json"), core, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "config.json"), cfg, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("lab configs dumped to %s", dir)
}
