package agent

// Hermetic tests for the OVERNIGHT-A3 wave: the morning human order
// ("ADD ALL remaining methods") lifted the curated won't-expose verdicts.
// Every assert cites the upstream evidence recorded in OVERNIGHT-A3-REPORT.md:
//   gost     — go-gost/x v0.28.1 listener/handler registry names (tap,
//              red/redir/redirect, redu, sni, masque+h3, masque+h3-masque),
//              docs/tutorials/tuntap.md (tap UDP frame shape), docs/
//              tutorials/protocols/sni.md, handler/masque doc comment,
//              connectors/masque + dialers/h3-masque reference docs.
//   frp      — pkg/config/v1/server.go vhost fields, pkg/config/v1/
//              proxy.go HTTPProxyConfig/HTTPSProxyConfig/TCPMuxProxyConfig.
//   xray     — vendored v24.12.31 probe: socks (auth noauth + udp) and
//              http inbounds parse OK; hysteria/masque = "unknown config id".
//   singbox  — v1.14.4 (c005f3530) include/registry.go + vendored build
//              tags (with_quic, with_tailscale); option/{hysteria,
//              shadowtls,snell,naive,tor,tailscale}.go field names.

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---- gost service families ------------------------------------------------

func TestGostServiceAllowlist(t *testing.T) {
	p := gostTestParams()
	for _, svc := range []string{"tap", "redirect-tcp", "redirect-udp", "sni", "masque"} {
		p.Service = svc
		// per-service required fields are checked per family below; here
		// only the allowlist gate matters (invalid combos error anyway).
		if !gostAllowedServices[svc] {
			t.Fatalf("service %s missing from the allowlist", svc)
		}
	}
	p.Service = "dns"
	if err := gostValidateParams(p); err == nil || !strings.Contains(err.Error(), "service") {
		t.Fatalf("unknown service accepted: %v", err)
	}
	// ingress and service are mutually exclusive (both render the data
	// listener — a combined shape is not defined upstream).
	bad := gostTestParams()
	bad.Service, bad.Ingress = "sni", "socks5"
	if err := gostValidateParams(bad); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("ingress+service accepted: %v", err)
	}
}

func TestGostTapService(t *testing.T) {
	p := gostTestParams()
	p.Service = "tap"
	p.CarrierAddr = "198.51.100.9:23400"
	p.TapNet, p.TapNetServer = "10.66.0.1/24", "10.66.0.2/24"
	p.TapName, p.TapMTU, p.TapGW = "qtap0", 1420, "10.66.0.254"
	p.TapRoute = "192.168.1.0/24,192.168.2.0/24"
	p.TapRouteServer = "192.168.9.0/24"
	if err := gostValidateParams(p); err != nil {
		t.Fatalf("tap params rejected: %v", err)
	}
	// the server binds the UDP frame socket with ITS device config; the
	// client forwards its frames to the server (the URL path IS the
	// upstream forward target — docs/tutorials/tuntap.md).
	srv := gostArgs("server", "ws", p)
	if len(srv) != 2 || srv[0] != "-L" {
		t.Fatalf("tap server args shape: %v", srv)
	}
	if !strings.HasPrefix(srv[1], "tap://:23400?net=10.66.0.2/24&") ||
		!strings.Contains(srv[1], "name=qtap0") || !strings.Contains(srv[1], "mtu=1420") ||
		!strings.Contains(srv[1], "gw=10.66.0.254") || !strings.Contains(srv[1], "route=192.168.9.0/24") {
		t.Fatalf("tap server URL shape wrong: %s", srv[1])
	}
	cli := gostArgs("client", "ws", p)
	if !strings.HasPrefix(cli[1], "tap://:0/198.51.100.9:23400?net=10.66.0.1/24&") ||
		!strings.Contains(cli[1], "route=192.168.1.0/24,192.168.2.0/24") {
		t.Fatalf("tap client URL shape wrong: %s", cli[1])
	}
	// hostile: junk CIDRs, device names, MTUs and gateways never render.
	for name, mutate := range map[string]func(*gostParams){
		"bad net":        func(p *gostParams) { p.TapNet = "not-a-cidr" },
		"missing net":    func(p *gostParams) { p.TapNet = "" },
		"missing srvnet": func(p *gostParams) { p.TapNetServer = "" },
		"device quote":   func(p *gostParams) { p.TapName = `qt"ap` },
		"device slash":   func(p *gostParams) { p.TapName = "qt/ap" },
		"mtu tiny":       func(p *gostParams) { p.TapMTU = 10 },
		"gw junk":        func(p *gostParams) { p.TapGW = "999.1.1.1" },
		"route junk":     func(p *gostParams) { p.TapRoute = "10.0.0.0/not-cidr" },
	} {
		bad := gostTestParams()
		bad.Service = "tap"
		bad.CarrierAddr = "198.51.100.9:23400"
		bad.TapNet, bad.TapNetServer = "10.66.0.1/24", "10.66.0.2/24"
		mutate(&bad)
		if err := gostValidateParams(bad); err == nil {
			t.Fatalf("gost tap %s accepted", name)
		}
	}
}

func TestGostRedirectServices(t *testing.T) {
	for _, svc := range []string{"redirect-tcp", "redirect-udp"} {
		p := gostTestParams()
		p.Service = svc
		if err := gostValidateParams(p); err != nil {
			t.Fatalf("%s params rejected: %v", svc, err)
		}
		scheme := "redirect"
		if svc == "redirect-udp" {
			scheme = "redu"
		}
		// client: the transparent listener + the relay chain out.
		cli := gostArgs("client", "ws", p)
		if !strings.HasPrefix(cli[1], scheme+"://:25203") {
			t.Fatalf("%s client listener wrong: %s", svc, cli[1])
		}
		if !strings.Contains(cli[3], "relay+ws://0.0.0.0:23344") {
			t.Fatalf("%s client chain wrong: %s", svc, cli[3])
		}
		// server: a PLAIN relay — no bind=true (no reverse registration,
		// same semantics as ingress mode).
		srv := gostArgs("server", "ws", p)
		if !strings.HasPrefix(srv[1], "relay+ws://:23344") || strings.Contains(srv[1], "bind=true") {
			t.Fatalf("%s server must be a plain unbound relay: %s", svc, srv[1])
		}
	}
	// the rule sets render tagged + exact (additive-only discipline).
	tcpRules := gostRedirectRuleArgs("tid1", "redirect-tcp", "eth5", 25203)
	joined := strings.Join(tcpRules[0], " ")
	if !strings.Contains(joined, "-t nat") || !strings.Contains(joined, "gostdrv-tid1") ||
		!strings.Contains(joined, "REDIRECT --to-ports 25203") {
		t.Fatalf("redirect-tcp rule args wrong: %s", joined)
	}
	udpJoined := strings.Join(gostRedirectRuleArgs("tid1", "redirect-udp", "eth5", 25203)[0], " ")
	if !strings.Contains(udpJoined, "-t mangle") || !strings.Contains(udpJoined, "TPROXY") ||
		!strings.Contains(udpJoined, "--on-port 25203") || !strings.Contains(udpJoined, "--tproxy-mark 0x1/0x1") {
		t.Fatalf("redirect-udp rule args wrong: %s", udpJoined)
	}
	// hostile: interface names are iptables args — metacharacters never pass.
	bad := gostTestParams()
	bad.Service, bad.RedirectIface = "redirect-tcp", `eth"; rm -rf`
	if err := gostValidateParams(bad); err == nil {
		t.Fatalf("redirect_iface metacharacters accepted")
	}
}

func TestGostSNIService(t *testing.T) {
	p := gostTestParams()
	p.Service = "sni"
	if err := gostValidateParams(p); err != nil {
		t.Fatalf("sni params rejected: %v", err)
	}
	cli := gostArgs("client", "ws", p)
	if !strings.HasPrefix(cli[1], "sni://:25203") {
		t.Fatalf("sni client listener wrong: %s", cli[1])
	}
	if !strings.Contains(cli[3], "relay+ws://0.0.0.0:23344") {
		t.Fatalf("sni client chain wrong: %s", cli[3])
	}
	srv := gostArgs("server", "ws", p)
	if strings.Contains(srv[1], "bind=true") {
		t.Fatalf("sni server must be a plain relay: %s", srv[1])
	}
}

func TestGostMasqueService(t *testing.T) {
	p := gostTestParams()
	p.Service = "masque"
	p.CarrierAddr = "198.51.100.9:23450"
	// QUIC+TLS: the cert pair is REQUIRED, fail closed.
	if err := gostValidateParams(p); err == nil || !strings.Contains(err.Error(), "masque") {
		t.Fatalf("masque without certs accepted")
	}
	p.TLSCert, p.TLSKey = "/etc/quantum/masque.pem", "/etc/quantum/masque.key"
	if err := gostValidateParams(p); err != nil {
		t.Fatalf("masque params rejected: %v", err)
	}
	srv := gostArgs("server", "ws", p)
	// handler masque + listener h3 (the upstream pairing requirement),
	// certs in the URL query (the h3 listener terminates TLS).
	if !strings.HasPrefix(srv[1], "masque+http3://:23450?certFile=/etc/quantum/masque.pem&keyFile=/etc/quantum/masque.key") {
		t.Fatalf("masque server URL wrong: %s", srv[1])
	}
	cli := gostArgs("client", "ws", p)
	// client: local socks5 entry → masque+h3-masque chain node (the
	// connectors/masque + dialers/h3-masque pair; secure=false skips
	// operator-cert verification).
	if !strings.HasPrefix(cli[1], "socks5://:25203") {
		t.Fatalf("masque client ingress wrong: %s", cli[1])
	}
	if !strings.HasPrefix(cli[3], "masque+h3-masque://198.51.100.9:23450?secure=false") {
		t.Fatalf("masque client chain wrong: %s", cli[3])
	}
	// optional HTTP Basic auth rides URL userinfo on both ends.
	p.MasqueUser, p.MasquePassword = "mq", "mqpass"
	if err := gostValidateParams(p); err != nil {
		t.Fatalf("masque with auth rejected: %v", err)
	}
	srv = gostArgs("server", "ws", p)
	if !strings.HasPrefix(srv[1], "masque+http3://mq:mqpass@:23450?") {
		t.Fatalf("masque server userinfo wrong: %s", srv[1])
	}
	cli = gostArgs("client", "ws", p)
	if !strings.Contains(cli[3], "masque+h3-masque://mq:mqpass@198.51.100.9:23450") {
		t.Fatalf("masque client userinfo wrong: %s", cli[3])
	}
	// hostile: userinfo metacharacters.
	bad := gostTestParams()
	bad.Service, bad.TLSCert, bad.TLSKey = "masque", "/c.pem", "/k.pem"
	bad.MasqueUser = "u@ser"
	if err := gostValidateParams(bad); err == nil {
		t.Fatalf("masque_user metacharacters accepted")
	}
	// the tap/masque carriers are UDP for accounting.
	if !gostServiceUDP("tap") || !gostServiceUDP("masque") || gostServiceUDP("sni") {
		t.Fatalf("gostServiceUDP wrong")
	}
}

// ---- frp vhost family -------------------------------------------------------

func frpVhostBase() frpParams {
	p := frpTestParams()
	p.ProxyType = "http"
	p.VhostHTTPPort = 23080
	p.CustomDomains = []string{"app.example.com"}
	return p
}

func TestFrpVhostValidation(t *testing.T) {
	for _, pt := range []string{"http", "https", "tcpmux"} {
		p := frpTestParams()
		p.ProxyType = pt
		if err := frpValidateParams(p); err == nil {
			t.Fatalf("%s accepted without its vhost port", pt)
		}
	}
	p := frpVhostBase()
	if err := frpValidateParams(p); err != nil {
		t.Fatalf("http vhost params rejected: %v", err)
	}
	// no domain → refused (frps routes by domain — DomainConfig).
	p.CustomDomains, p.SubDomain = nil, ""
	if err := frpValidateParams(p); err == nil || !strings.Contains(err.Error(), "custom_domains or subdomain") {
		t.Fatalf("vhost without domain accepted")
	}
	// hostile: domain charsets, locations, auth, host rewrite.
	for name, mutate := range map[string]func(*frpParams){
		"domain quote":  func(p *frpParams) { p.CustomDomains = []string{`a"b.com`} },
		"domain space":  func(p *frpParams) { p.CustomDomains = []string{"a b.com"} },
		"subdomain /":   func(p *frpParams) { p.SubDomain = "a/b" },
		"location bad":  func(p *frpParams) { p.Locations = []string{"api"} },
		"rewrite junk":  func(p *frpParams) { p.HostHeaderRewrite = "a b" },
		"httpuser tok":  func(p *frpParams) { p.HTTPUser = "u\"er" },
		"secretKey mix": func(p *frpParams) { p.SecretKey = "shhhhh" },
	} {
		bad := frpVhostBase()
		mutate(&bad)
		if err := frpValidateParams(bad); err == nil {
			t.Fatalf("frp vhost %s accepted", name)
		}
	}
	// frpSecretProxy stays false for the vhost family — NO visitor frpc.
	if frpSecretProxy("http") || frpSecretProxy("https") || frpSecretProxy("tcpmux") {
		t.Fatalf("vhost family flagged as secret-proxy (visitor would spawn)")
	}
}

func TestFrpVhostRender(t *testing.T) {
	// server: frps opens the vhost ports (pkg/config/v1/server.go names).
	p := frpVhostBase()
	p.HostHeaderRewrite = "real.example.com"
	p.VhostHTTPSPort = 23443
	p.TCPMuxPort = 23444
	p.TCPMuxPassthrough = true
	p.SubDomainHost = "frps.example.com"
	srv := frpRenderConfig("tid-vh", "server", p)
	for _, want := range []string{
		"vhostHTTPPort = 23080", "vhostHTTPSPort = 23443",
		"tcpmuxHTTPConnectPort = 23444", "tcpmuxPassthrough = true",
		`subDomainHost = "frps.example.com"`,
	} {
		if !strings.Contains(srv, want) {
			t.Fatalf("frps vhost render missing %q:\n%s", want, srv)
		}
	}
	// client http: DomainConfig + locations + rewrite; NO remotePort.
	cli := frpRenderConfig("tid-vh", "client", p)
	if strings.Contains(cli, "remotePort") {
		t.Fatalf("vhost proxy must NOT carry remotePort:\n%s", cli)
	}
	for _, want := range []string{
		`type = "http"`, `customDomains = ["app.example.com"]`,
		`hostHeaderRewrite = "real.example.com"`,
	} {
		if !strings.Contains(cli, want) {
			t.Fatalf("frpc http render missing %q:\n%s", want, cli)
		}
	}
	// client https: TLS passthrough — DomainConfig only.
	p2 := frpTestParams()
	p2.ProxyType = "https"
	p2.VhostHTTPSPort = 23443
	p2.SubDomain = "app"
	cliHTTPS := frpRenderConfig("tid-vh2", "client", p2)
	if !strings.Contains(cliHTTPS, `type = "https"`) || !strings.Contains(cliHTTPS, `subdomain = "app"`) {
		t.Fatalf("frpc https render wrong:\n%s", cliHTTPS)
	}
	// client tcpmux: multiplexer httpconnect + basic auth.
	p3 := frpTestParams()
	p3.ProxyType = "tcpmux"
	p3.TCPMuxPort = 23444
	p3.CustomDomains = []string{"mux.example.com"}
	p3.HTTPUser, p3.HTTPPassword = "mux", "muxpass"
	cliMux := frpRenderConfig("tid-vh3", "client", p3)
	for _, want := range []string{`type = "tcpmux"`, `multiplexer = "httpconnect"`,
		`customDomains = ["mux.example.com"]`, `httpUser = "mux"`, `httpPassword = "muxpass"`} {
		if !strings.Contains(cliMux, want) {
			t.Fatalf("frpc tcpmux render missing %q:\n%s", want, cliMux)
		}
	}
	// the vhost ports ARE the accounting + forward-address ports.
	if ports := frpVhostPorts(p); len(ports) != 1 || ports[0] != 23080 {
		t.Fatalf("frpVhostPorts(http) wrong: %v", ports)
	}
	if ports := frpVhostPorts(p3); len(ports) != 1 || ports[0] != 23444 {
		t.Fatalf("frpVhostPorts(tcpmux) wrong: %v", ports)
	}
}

// ---- xray socks/http inbounds -----------------------------------------------

func TestXraySocksHTTPInbounds(t *testing.T) {
	p := xrayTestParams()
	p.SocksPort, p.HTTPPort = 21091, 21092
	if err := xrayValidateParams(p); err != nil {
		t.Fatalf("xray socks/http params rejected: %v", err)
	}
	cfg := xrayBuildConfig(engineSideClient, p)
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)
	// socks inbound: noauth + udp (the probe-proven v24.12.31 shape),
	// loopback-bound, routed to the carrier outbound.
	if !strings.Contains(s, `"tag":"socks-in"`) || !strings.Contains(s, `"protocol":"socks"`) ||
		!strings.Contains(s, `"auth":"noauth"`) || !strings.Contains(s, `"udp":true`) {
		t.Fatalf("xray socks-in render wrong: %s", s)
	}
	if !strings.Contains(s, `"tag":"http-in"`) || !strings.Contains(s, `"protocol":"http"`) {
		t.Fatalf("xray http-in render wrong: %s", s)
	}
	if !strings.Contains(s, `"inboundTag":["socks-in"],"outboundTag":"carrier-out"`) ||
		!strings.Contains(s, `"inboundTag":["http-in"],"outboundTag":"carrier-out"`) {
		t.Fatalf("xray socks/http route rules missing: %s", s)
	}
	// the SERVER end never renders the local inbounds.
	scfg := xrayBuildConfig(engineSideServer, p)
	sraw, _ := json.Marshal(scfg)
	if strings.Contains(string(sraw), "socks-in") || strings.Contains(string(sraw), "http-in") {
		t.Fatalf("xray server must not render the local inbounds: %s", string(sraw))
	}
	// hostile: collisions and out-of-range ports fail closed.
	for name, mutate := range map[string]func(*xrayParams){
		"collide carrier": func(p *xrayParams) { p.SocksPort = p.CarrierPort },
		"collide public":  func(p *xrayParams) { p.HTTPPort = p.PublicPort },
		"out of range":    func(p *xrayParams) { p.SocksPort = 70000 },
	} {
		bad := xrayTestParams()
		mutate(&bad)
		if err := xrayValidateParams(bad); err == nil {
			t.Fatalf("xray %s accepted", name)
		}
	}
}

// ---- sing-box A3 protocols ---------------------------------------------------

func sbCleanParams() singboxParams {
	p := singboxTestParams()
	p.SSMethod, p.SSPassword, p.UUID, p.Password = "", "", "", ""
	return p
}

func sbTLSPaths(p *singboxParams) { p.TLSCert, p.TLSKey = "/etc/q/c.pem", "/etc/q/k.pem" }

func TestSingboxHysteriaV1(t *testing.T) {
	p := sbCleanParams()
	p.Protocol = "hysteria"
	p.Password = "hy-pass-01"
	p.Obfs = "obfspass"
	p.UpMbps, p.DownMbps = 50, 200
	sbTLSPaths(&p)
	if err := singboxValidateParams(p); err != nil {
		t.Fatalf("hysteria params rejected: %v", err)
	}
	// TLS is required (QUIC+TLS) — fail closed.
	noTLS := p
	noTLS.TLSCert, noTLS.TLSKey = "", ""
	if err := singboxValidateParams(noTLS); err == nil || !strings.Contains(err.Error(), "TLS-only") {
		t.Fatalf("hysteria without certs accepted")
	}
	srv := singboxRenderConfig("server", p)
	b, _ := json.Marshal(srv)
	s := string(b)
	// HysteriaInboundOptions: users[].auth_str + obfs string + up/down.
	if !strings.Contains(s, `"type":"hysteria"`) || !strings.Contains(s, `"auth_str":"hy-pass-01"`) ||
		!strings.Contains(s, `"obfs":"obfspass"`) || !strings.Contains(s, `"up_mbps":50`) ||
		!strings.Contains(s, `"down_mbps":200`) {
		t.Fatalf("hysteria server render wrong: %s", s)
	}
	cli := singboxRenderConfig("client", p)
	cb, _ := json.Marshal(cli)
	cs := string(cb)
	// HysteriaOutboundOptions: top-level auth_str.
	if !strings.Contains(cs, `"auth_str":"hy-pass-01"`) || !strings.Contains(cs, `"server_port":8388`) {
		t.Fatalf("hysteria client render wrong: %s", cs)
	}
	if !singBoxUDPCarrier("hysteria") {
		t.Fatalf("hysteria must ride the udp accounting family")
	}
}

func TestSingboxShadowTLS(t *testing.T) {
	p := sbCleanParams()
	p.Protocol = "shadowtls"
	p.Password = "stls-pass-01" // the shadowtls layer secret
	p.SSMethod, p.SSPassword = "aes-256-gcm", "inner-pass-01"
	p.ServerAddr = "0.0.0.0:8390"
	p.ShadowTLSHandshake = "www.apple.com:443"
	if err := singboxValidateParams(p); err != nil {
		t.Fatalf("shadowtls params rejected: %v", err)
	}
	srv := singboxRenderConfig("server", p)
	b, _ := json.Marshal(srv)
	s := string(b)
	// the chained inbound pair: stls-in (version 3 + handshake + detour
	// "ss-inner") over ss-in (loopback inner listener).
	if !strings.Contains(s, `"type":"shadowtls"`) || !strings.Contains(s, `"version":3`) ||
		!strings.Contains(s, `"handshake":{"server":"www.apple.com","server_port":443}`) ||
		!strings.Contains(s, `"detour":"ss-inner"`) {
		t.Fatalf("shadowtls server render wrong: %s", s)
	}
	if !strings.Contains(s, `"tag":"ss-inner"`) || !strings.Contains(s, `"listen":"127.0.0.1"`) ||
		!strings.Contains(s, `"listen_port":8391`) {
		t.Fatalf("shadowtls inner ss inbound wrong: %s", s)
	}
	cli := singboxRenderConfig("client", p)
	cb, _ := json.Marshal(cli)
	cs := string(cb)
	// the ss outbound nests INSIDE the shadowtls outbound (detour).
	if !strings.Contains(cs, `"tag":"stls-wrap"`) || !strings.Contains(cs, `"detour":"stls-wrap"`) ||
		!strings.Contains(cs, `"tag":"carrier-out"`) || !strings.Contains(cs, `"server":"127.0.0.1"`) {
		t.Fatalf("shadowtls client render wrong: %s", cs)
	}
	// hostile: missing inner credentials, bad handshake, bad version.
	for name, mutate := range map[string]func(*singboxParams){
		"no inner pass": func(p *singboxParams) { p.SSPassword = "" },
		"no stls pass":  func(p *singboxParams) { p.Password = "" },
		"bad handshake": func(p *singboxParams) { p.ShadowTLSHandshake = "no-port" },
		"bad version":   func(p *singboxParams) { p.ShadowTLSVersion = 9 },
	} {
		bad := singboxTestParams()
		bad.Protocol = "shadowtls"
		bad.Password, bad.SSMethod, bad.SSPassword = "stls-pass-01", "aes-256-gcm", "inner-pass-01"
		mutate(&bad)
		if err := singboxValidateParams(bad); err == nil {
			t.Fatalf("shadowtls %s accepted", name)
		}
	}
}

func TestSingboxSnell(t *testing.T) {
	p := sbCleanParams()
	p.Protocol = "snell"
	p.Password = "snell-psk-01"
	p.SnellVersion = 6
	if err := singboxValidateParams(p); err != nil {
		t.Fatalf("snell params rejected: %v", err)
	}
	srv := singboxRenderConfig("server", p)
	b, _ := json.Marshal(srv)
	s := string(b)
	// SnellInboundOptions: version + psk.
	if !strings.Contains(s, `"type":"snell"`) || !strings.Contains(s, `"version":6`) ||
		!strings.Contains(s, `"psk":"snell-psk-01"`) {
		t.Fatalf("snell server render wrong: %s", s)
	}
	cli := singboxRenderConfig("client", p)
	cb, _ := json.Marshal(cli)
	if !strings.Contains(string(cb), `"psk":"snell-psk-01"`) {
		t.Fatalf("snell client render wrong: %s", string(cb))
	}
	bad := sbCleanParams()
	bad.Protocol, bad.Password, bad.SnellVersion = "snell", "snell-psk-01", 5
	if err := singboxValidateParams(bad); err != nil {
		t.Fatalf("snell v5 rejected: %v", err)
	}
	bad.SnellVersion = 4
	if err := singboxValidateParams(bad); err == nil {
		t.Fatalf("snell v4 accepted (outbound-only enum)")
	}
}

func TestSingboxNaiveServerHalf(t *testing.T) {
	p := sbCleanParams()
	p.Protocol = "naive"
	p.NaiveUsername, p.Password = "nvuser", "naive-pass-01"
	sbTLSPaths(&p)
	if err := singboxValidateParams(p); err != nil {
		t.Fatalf("naive params rejected: %v", err)
	}
	srv := singboxRenderConfig("server", p)
	b, _ := json.Marshal(srv)
	s := string(b)
	// NaiveInboundOptions: users username/password + TLS.
	if !strings.Contains(s, `"type":"naive"`) || !strings.Contains(s, `"username":"nvuser"`) ||
		!strings.Contains(s, `"password":"naive-pass-01"`) || !strings.Contains(s, `"enabled":true`) {
		t.Fatalf("naive server render wrong: %s", s)
	}
	// the CLIENT half is blocked by the vendored build — the typed error
	// names the exact tag and the honest paths (no fake entries).
	if !singBoxClientBlocked["naive"] {
		t.Fatalf("naive must be client-blocked")
	}
}

func TestSingboxTorAndTailscale(t *testing.T) {
	// tor: outbound-only — both ends render the ingress→tor exit shape.
	p := sbCleanParams()
	p.Protocol = "tor"
	p.TorExecPath = "/usr/bin/tor"
	p.ServerAddr = ""
	if err := singboxValidateParams(p); err != nil {
		t.Fatalf("tor params rejected: %v", err)
	}
	cli := singboxRenderConfig("client", p)
	b, _ := json.Marshal(cli)
	s := string(b)
	if !strings.Contains(s, `"type":"tor"`) || !strings.Contains(s, `"executable_path":"/usr/bin/tor"`) {
		t.Fatalf("tor client render wrong: %s", s)
	}
	// hostile: exec-path metacharacters + non-proxy local_mode.
	bad := sbCleanParams()
	bad.Protocol, bad.TorExecPath = "tor", "/usr/bin/to r"
	if err := singboxValidateParams(bad); err == nil {
		t.Fatalf("tor exec path with whitespace accepted")
	}
	bad.TorExecPath = "/usr/bin/tor"
	bad.LocalMode = "forward"
	if err := singboxValidateParams(bad); err == nil || !strings.Contains(err.Error(), "outbound-only") {
		t.Fatalf("tor forward mode accepted")
	}

	// tailscale: the endpoint joins the tailnet; the route rule targets
	// its tag. Both ends render it; DERP is built in.
	p2 := sbCleanParams()
	p2.Protocol = "tailscale"
	p2.TailscaleAuthKey = "tskey-auth-abc123def456"
	p2.ServerAddr = ""
	p2.TailscaleHostname = "quantum-ir"
	p2.TailscaleEphemeral = true
	if err := singboxValidateParams(p2); err != nil {
		t.Fatalf("tailscale params rejected: %v", err)
	}
	cli2 := singboxRenderConfig("client", p2)
	b2, _ := json.Marshal(cli2)
	s2 := string(b2)
	if !strings.Contains(s2, `"endpoints":[{"type":"tailscale","tag":"ts-ep","auth_key":"tskey-auth-abc123def456"`) ||
		!strings.Contains(s2, `"ephemeral":true`) || !strings.Contains(s2, `"hostname":"quantum-ir"`) ||
		!strings.Contains(s2, `"outbound":"ts-ep"`) {
		t.Fatalf("tailscale client render wrong: %s", s2)
	}
	srv2 := singboxRenderConfig("server", p2)
	sv, _ := json.Marshal(srv2)
	if !strings.Contains(string(sv), `"endpoints":[`) {
		t.Fatalf("tailscale server must render the endpoint: %s", string(sv))
	}
	bad2 := sbCleanParams()
	bad2.Protocol, bad2.ServerAddr = "tailscale", ""
	if err := singboxValidateParams(bad2); err == nil || !strings.Contains(err.Error(), "auth_key") {
		t.Fatalf("tailscale without auth_key accepted")
	}
}

func TestSingboxMasqueRefused(t *testing.T) {
	p := singboxTestParams()
	p.Protocol = "masque"
	err := singboxValidateParams(p)
	if err == nil || !strings.Contains(err.Error(), "gost") {
		t.Fatalf("masque must be refused with the gost pointer (no fake entries): %v", err)
	}
}

// ---- the blocked entries stay honest ----------------------------------------

func TestA3BlockedVerdictsDocumented(t *testing.T) {
	// xray: hysteria/masque are blocked-by-upstream-version on the pinned
	// v24.12.31 (probe: "unknown config id") — the driver must NOT accept
	// them as sing-box-style protocol params; the honest pointer is the
	// dedicated hysteria engine (AGENT-31). The singbox masque refusal is
	// covered above; this test pins the constants that keep the report's
	// claims true.
	if singBoxNoCarrier("tor") != true || singBoxNoCarrier("tailscale") != true ||
		singBoxNoCarrier("shadowtls") != false {
		t.Fatalf("singBoxNoCarrier drifted")
	}
	if singboxPinnedVersion != "1.14.4" {
		t.Fatalf("singbox pin drifted: %s", singboxPinnedVersion)
	}
}
