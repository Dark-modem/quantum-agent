package agent

// Hermetic tests for the OVERNIGHT-A gap-close (one branch over the six
// existing engines): the new transports/modes each upstream source
// documents and this driver now exposes, the hostile-input rejections of
// every new allowlist, and the exact render shapes the new params
// produce. The upstream method lists these assert against live in
// 00-ADMIN/overnight/methods/<name>.json (inventoried from the cloned
// sources at the pinned commits).

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---- backhaul: tcpmux/udp transports + accept_udp + phantom-tls ban -----

func TestBackhaulNewTransportsValidateRender(t *testing.T) {
	for _, tr := range []string{"tcpmux", "udp"} {
		p := backhaulTestParams()
		p.Transport = tr
		raw, _ := json.Marshal(p)
		if err := NewBackhaulDriver().Validate(raw); err != nil {
			t.Fatalf("transport %s rejected: %v", tr, err)
		}
	}
	// The phantom "tls" (upstream v0.7.2 has NO plain tls transport) must
	// be refused with the honest message, not silently produce a config
	// upstream fatal-exits on.
	p := backhaulTestParams()
	p.Transport = "tls"
	raw, _ := json.Marshal(p)
	err := NewBackhaulDriver().Validate(raw)
	if err == nil || !strings.Contains(err.Error(), "does not exist upstream") {
		t.Fatalf("phantom tls transport: err = %v, want the upstream-absence message", err)
	}
	// accept_udp renders server-side only (upstream ClientConfig has no
	// accept_udp field — verified from config/config.go).
	p = backhaulTestParams()
	p.AcceptUDP = true
	cfg := backhaulRenderConfig("server", p)
	if !strings.Contains(cfg, "accept_udp = true") {
		t.Fatalf("server config missing accept_udp:\n%s", cfg)
	}
	if strings.Contains(backhaulRenderConfig("client", p), "accept_udp") {
		t.Fatalf("client config must not carry accept_udp (upstream client struct has no such field)")
	}
	// udp carrier accounting must be -p udp (the proto helper is
	// asserted directly in TestAcctWireRulesProtoArgList).
	if !backhaulUDPCarrier("udp") || backhaulUDPCarrier("tcp") || backhaulUDPCarrier("wss") {
		t.Fatal("backhaulUDPCarrier misclassifies the udp carrier")
	}
}

// ---- rathole: transport choice + service_type udp + prefer_ipv6 ---------

func TestRatholeTransportsAndServiceType(t *testing.T) {
	// noise stays the default (empty transport) — byte-shape unchanged.
	p := ratholeTestParams()
	srv := ratholeRenderConfig("server", "q1", p, "NOISEPRIV")
	for _, want := range []string{`[server.transport]`, `type = "noise"`, `local_private_key = "NOISEPRIV"`} {
		if !strings.Contains(srv, want) {
			t.Fatalf("noise default server shape broken:\n%s", srv)
		}
	}
	// tcp carrier: no transport block, and the client needs NO noise key.
	p.Transport = "tcp"
	srv = ratholeRenderConfig("server", "q1", p, "")
	if strings.Contains(srv, "transport") {
		t.Fatalf("tcp carrier must render no transport block:\n%s", srv)
	}
	cli := ratholeRenderConfig("client", "q1", p, "")
	if strings.Contains(cli, "remote_public_key") || strings.Contains(cli, "noise") {
		t.Fatalf("tcp carrier client must not carry noise material:\n%s", cli)
	}
	// websocket carrier: plain ws (tls=false) on both ends.
	p.Transport = "websocket"
	for _, cfg := range []string{
		ratholeRenderConfig("server", "q1", p, ""),
		ratholeRenderConfig("client", "q1", p, ""),
	} {
		for _, want := range []string{`type = "websocket"`, `tls = false`} {
			if !strings.Contains(cfg, want) {
				t.Fatalf("websocket carrier missing %q:\n%s", want, cfg)
			}
		}
	}
	// service_type=udp renders into BOTH service blocks; prefer_ipv6
	// rides the client service only.
	p.Transport = ""
	p.ServiceType = "udp"
	p.PreferIPv6 = true
	srv = ratholeRenderConfig("server", "q1", p, "")
	cli = ratholeRenderConfig("client", "q1", p, "")
	if strings.Count(srv, `type = "udp"`) != 1 || strings.Count(cli, `type = "udp"`) != 1 {
		t.Fatalf("udp service type not rendered into both service blocks:\n--server--\n%s\n--client--\n%s", srv, cli)
	}
	if !strings.Contains(cli, "prefer_ipv6 = true") || strings.Contains(srv, "prefer_ipv6") {
		t.Fatalf("prefer_ipv6 placement wrong:\n--server--\n%s\n--client--\n%s", srv, cli)
	}
	// hostile: tls transport, dead noise material on non-noise carriers,
	// bad service_type, and injection through the new strings.
	for name, mutate := range map[string]func(*ratholeParams){
		"tls-transport": func(p *ratholeParams) { p.Transport = "tls" },
		"bad-transport": func(p *ratholeParams) { p.Transport = "noise\n[evil]" },
		"noise-on-tcp":  func(p *ratholeParams) { p.Transport = "tcp"; p.NoiseServerPublic = strings.Repeat("A", 43) + "=" },
		"bad-svc-type":  func(p *ratholeParams) { p.ServiceType = "grpc" },
		"inj-svc-type":  func(p *ratholeParams) { p.ServiceType = "udp\"\n[evil]" },
		"noise-on-ws":   func(p *ratholeParams) { p.Transport = "websocket"; p.NoiseServerPublic = strings.Repeat("A", 43) + "=" },
	} {
		bad := ratholeTestParams()
		mutate(&bad)
		if err := ratholeValidateParams(bad); err == nil {
			t.Fatalf("rathole %s params accepted", name)
		}
	}
	// websocket + tcp carriers accept a client with no noise material.
	for _, tr := range []string{"tcp", "websocket"} {
		ok := ratholeTestParams()
		ok.Transport = tr
		ok.NoiseServerPublic = ""
		if err := ratholeValidateParams(ok); err != nil {
			t.Fatalf("transport %s without noise key rejected: %v", tr, err)
		}
	}
}

// ---- gost: carrier allowlist + rudp mode ---------------------------------

func TestGostCarriersAndMode(t *testing.T) {
	p := gostTestParams()
	// every allowlisted carrier renders relay+<scheme> on BOTH ends.
	for _, tr := range []string{"ws", "tcp", "dtls", "quic", "grpc", "http2", "kcp", "obfs-http", "obfs-tls", "ftcp", "mws"} {
		p.Transport = tr
		p.Mode = ""
		srv := gostArgs("server", gostCarrierScheme(p), p)
		cli := gostArgs("client", gostCarrierScheme(p), p)
		if !strings.Contains(srv[1], "relay+"+tr+"://") {
			t.Fatalf("carrier %s missing from server args: %v", tr, srv)
		}
		if !strings.Contains(cli[3], "relay+"+tr+"://") {
			t.Fatalf("carrier %s missing from client forward args: %v", tr, cli)
		}
	}
	// empty transport stays ws (backward compat).
	p.Transport = ""
	if got := gostCarrierScheme(p); got != "ws" {
		t.Fatalf("empty transport resolved to %q, want ws", got)
	}
	// mode=udp swaps rtcp for rudp.
	p.Transport = "quic"
	p.Mode = "udp"
	cli := gostArgs("client", gostCarrierScheme(p), p)
	if !strings.Contains(cli[1], "rudp://") || strings.Contains(cli[1], "rtcp://") {
		t.Fatalf("mode=udp must render rudp: %v", cli)
	}
	p.Mode = "tcp"
	cli = gostArgs("client", gostCarrierScheme(p), p)
	if !strings.Contains(cli[1], "rtcp://") {
		t.Fatalf("mode=tcp must render rtcp: %v", cli)
	}
	// hostile: cert-bound carriers stay out; mode allowlist; udp-carrier
	// classification drives the accounting proto.
	for _, bad := range []string{"wss", "tls", "mtls", "h2", "utls", "http3", "wt", "ssh", "icmp", "ws\n[evil]"} {
		p.Transport = bad
		if err := gostValidateParams(p); err == nil {
			t.Fatalf("carrier %q accepted", bad)
		}
	}
	p.Transport = "quic"
	p.Mode = "relay+tcp://evil"
	if err := gostValidateParams(p); err == nil {
		t.Fatal("injection through mode accepted")
	}
	for tr, want := range map[string]bool{"quic": true, "kcp": true, "dtls": true, "ws": false, "grpc": false, "tcp": false} {
		if got := gostUDPCarrier(tr); got != want {
			t.Fatalf("gostUDPCarrier(%q) = %v, want %v", tr, got, want)
		}
	}
}

// ---- frp: proxy_type udp + transport kcp/quic/websocket + flags ----------

func TestFRPProxyTypeTransportFlags(t *testing.T) {
	p := frpTestParams()
	// udp proxy: type rides the client proxy block; the server side is
	// shape-unchanged (allowPorts already covers remote_port).
	p.ProxyType = "udp"
	p.Transport = ""
	cli := frpRenderConfig("t1", "client", p)
	if !strings.Contains(cli, `type = "udp"`) {
		t.Fatalf("udp proxy type not rendered:\n%s", cli)
	}
	if strings.Contains(frpRenderConfig("t1", "server", p), "proxy") {
		t.Fatal("server config must stay proxy-free")
	}
	// kcp transport renders transport.protocol on BOTH ends; tcp (and
	// empty) render nothing — byte-shape preserved for old tunnels.
	p.Transport = "kcp"
	if !strings.Contains(frpRenderConfig("t1", "server", p), `transport.protocol = "kcp"`) {
		t.Fatal("server missing transport.protocol")
	}
	if !strings.Contains(frpRenderConfig("t1", "client", p), `transport.protocol = "kcp"`) {
		t.Fatal("client missing transport.protocol")
	}
	p.Transport = ""
	if strings.Contains(frpRenderConfig("t1", "client", p), "transport") {
		t.Fatal("empty transport must render no transport block (historical shape)")
	}
	// encryption/compression flags ride the proxy block only.
	p.UseEncryption = true
	p.UseCompression = true
	cli = frpRenderConfig("t1", "client", p)
	for _, want := range []string{"useEncryption = true", "useCompression = true"} {
		if !strings.Contains(cli, want) {
			t.Fatalf("client proxy missing %q:\n%s", want, cli)
		}
	}
	// hostile: cert-bound wss, unknown types, injection shapes.
	for name, mutate := range map[string]func(*frpParams){
		"wss":           func(p *frpParams) { p.Transport = "wss" },
		"bad-transport": func(p *frpParams) { p.Transport = "kcp\"\n[evil]" },
		"bad-proxy":     func(p *frpParams) { p.ProxyType = "stcp" },
		"inj-proxy":     func(p *frpParams) { p.ProxyType = "udp\"\n[[proxies]]" },
	} {
		bad := frpTestParams()
		mutate(&bad)
		if err := frpValidateParams(bad); err == nil {
			t.Fatalf("frp %s accepted", name)
		}
	}
	for tr, want := range map[string]bool{"kcp": true, "quic": true, "websocket": false, "tcp": false, "": false} {
		if got := frpUDPCarrier(tr); got != want {
			t.Fatalf("frpUDPCarrier(%q) = %v, want %v", tr, got, want)
		}
	}
	// the historical default params still validate (backward compat).
	if err := frpValidateParams(frpTestParams()); err != nil {
		t.Fatalf("default frp params no longer valid: %v", err)
	}
}

// ---- xray: xhttp/grpc carriers under REALITY ------------------------------

func TestXrayRealityTransports(t *testing.T) {
	p := xrayTestParams()
	// tcp (default) keeps the historical bare stream shape.
	cfg := xrayBuildConfig(engineSideServer, p)
	b, _ := json.Marshal(cfg)
	if strings.Contains(string(b), "xhttpSettings") || strings.Contains(string(b), "grpcSettings") {
		t.Fatal("default tcp shape must carry no xhttp/grpc sub-blocks")
	}
	// xhttp: both ends carry the SAME path under their stream settings.
	p.Transport = "xhttp"
	p.XHTTPPath = "/quantum-stream"
	srv := xrayBuildConfig(engineSideServer, p)
	cli := xrayBuildConfig(engineSideClient, p)
	sb, _ := json.Marshal(srv.Inbounds[0].StreamSettings)
	cb, _ := json.Marshal(cli.Outbounds[0].StreamSettings)
	if !strings.Contains(string(sb), `"network":"xhttp"`) || !strings.Contains(string(sb), `"path":"/quantum-stream"`) {
		t.Fatalf("server xhttp stream broken: %s", sb)
	}
	if !strings.Contains(string(cb), `"network":"xhttp"`) || !strings.Contains(string(cb), `"path":"/quantum-stream"`) {
		t.Fatalf("client xhttp stream broken: %s", cb)
	}
	if !strings.Contains(string(sb), `"security":"reality"`) || !strings.Contains(string(cb), `"security":"reality"`) {
		t.Fatal("xhttp carrier must stay under REALITY")
	}
	// grpc: serviceName shared, default when unset.
	p.Transport = "grpc"
	p.GrpcServiceName = ""
	srv = xrayBuildConfig(engineSideServer, p)
	cli = xrayBuildConfig(engineSideClient, p)
	sb, _ = json.Marshal(srv.Inbounds[0].StreamSettings)
	cb, _ = json.Marshal(cli.Outbounds[0].StreamSettings)
	if !strings.Contains(string(sb), `"serviceName":"quantum-reverse"`) ||
		!strings.Contains(string(cb), `"serviceName":"quantum-reverse"`) {
		t.Fatalf("grpc default serviceName missing:\n%s\n%s", sb, cb)
	}
	p.GrpcServiceName = "svc-1"
	srv = xrayBuildConfig(engineSideServer, p)
	sb, _ = json.Marshal(srv.Inbounds[0].StreamSettings)
	if !strings.Contains(string(sb), `"serviceName":"svc-1"`) {
		t.Fatalf("explicit grpc serviceName missing: %s", sb)
	}
	// hostile: non-reality transports, upstream-removed transports,
	// injection through the sub-params.
	for name, mutate := range map[string]func(*xrayParams){
		"ws":       func(p *xrayParams) { p.Transport = "ws" },
		"quic":     func(p *xrayParams) { p.Transport = "quic" },
		"h2":       func(p *xrayParams) { p.Transport = "http" },
		"inj-tr":   func(p *xrayParams) { p.Transport = "grpc\"\n" },
		"inj-path": func(p *xrayParams) { p.Transport = "xhttp"; p.XHTTPPath = "/x\"}" },
		"bad-path": func(p *xrayParams) { p.Transport = "xhttp"; p.XHTTPPath = "no-slash" },
		"inj-svc":  func(p *xrayParams) { p.Transport = "grpc"; p.GrpcServiceName = "a b" },
	} {
		bad := xrayTestParams()
		mutate(&bad)
		if err := xrayValidateParams(bad); err == nil {
			t.Fatalf("xray %s accepted", name)
		}
	}
	// the historical default params still validate (backward compat).
	if err := xrayValidateParams(xrayTestParams()); err != nil {
		t.Fatalf("default xray params no longer valid: %v", err)
	}
}

// ---- udp2raw companion: raw/cipher/auth modes + RST-rule scope ------------

func TestWGCompanionRawModes(t *testing.T) {
	p := wgTestParams()
	c := wgCompanionTest()
	// default (empty) stays faketcp with NO cipher/auth flags — the
	// historical arg shape is preserved byte-for-byte.
	args := wgCompanionUDP2RawArgs(engineSideServer, p, c, 51931)
	joined := strings.Join(args, " ")
	for _, want := range []string{"--raw-mode faketcp"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("default companion args missing %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "cipher-mode") || strings.Contains(joined, "auth-mode") {
		t.Fatalf("empty cipher/auth must render no flags: %s", joined)
	}
	// udp + icmp raw modes pass through; cipher/auth flags ride along.
	c.RawMode = "icmp"
	c.CipherMode = "aes128cbc"
	c.AuthMode = "hmac_sha1"
	args = wgCompanionUDP2RawArgs(engineSideServer, p, c, 51931)
	joined = strings.Join(args, " ")
	for _, want := range []string{"--raw-mode icmp", "--cipher-mode aes128cbc", "--auth-mode hmac_sha1"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("mode args missing %q: %s", want, joined)
		}
	}
	// easyfaketcp is the upstream alias.
	c.RawMode = "easyfaketcp"
	if !strings.Contains(strings.Join(wgCompanionUDP2RawArgs(engineSideServer, p, c, 51931), " "), "--raw-mode easyfaketcp") {
		t.Fatal("easyfaketcp alias not passed through")
	}
	// hostile: out-of-allowlist modes and injection shapes.
	for name, mutate := range map[string]func(*wgCompanion){
		"bad-raw":    func(c *wgCompanion) { c.RawMode = "gre" },
		"inj-raw":    func(c *wgCompanion) { c.RawMode = "udp\n--evil" },
		"bad-cipher": func(c *wgCompanion) { c.CipherMode = "aes-gcm" },
		"bad-auth":   func(c *wgCompanion) { c.AuthMode = "sha256" },
		"inj-cipher": func(c *wgCompanion) { c.CipherMode = "xor; rm -rf" },
	} {
		bad := wgCompanionTest()
		mutate(bad)
		if err := bad.validate(); err == nil {
			t.Fatalf("companion %s accepted", name)
		}
	}
	// the kernel-RST guard applies ONLY to the fake-TCP family.
	for mode, want := range map[string]bool{
		"": true, "faketcp": true, "easyfaketcp": true, "udp": false, "icmp": false,
	} {
		c.RawMode = mode
		if got := c.fakeTCPFamily(); got != want {
			t.Fatalf("fakeTCPFamily(%q) = %v, want %v", mode, got, want)
		}
		if got := wgCompanionIptablesRule(c); (got > 0) != want {
			t.Fatalf("RST rule for raw-mode %q = %d (want rule: %v)", mode, got, want)
		}
	}
	// the historical default companion still validates.
	if err := wgCompanionTest().validate(); err != nil {
		t.Fatalf("default companion no longer valid: %v", err)
	}
}

// ---- acct: the proto-parameterized accounting helper ----------------------

func TestAcctWireRulesProtoArgList(t *testing.T) {
	var calls [][]string
	orig := acctIptables
	acctIptables = func(args ...string) ([]byte, error) {
		calls = append(calls, args)
		return nil, nil
	}
	t.Cleanup(func() { acctIptables = orig })

	if err := acctWireRulesAddProto(acctChainsDriver, "t1", 5201, 5201, "udp"); err != nil {
		t.Fatalf("udp add: %v", err)
	}
	// acctWireRulesEnsure runs first (chain create/check calls), so the
	// two -A appends are the LAST two calls.
	if len(calls) < 2 ||
		strings.Join(calls[len(calls)-2], " ") != "-A FRPDRV_ACCT_IN -p udp --dport 5201 -m comment --comment frpdrv-t1" ||
		strings.Join(calls[len(calls)-1], " ") != "-A FRPDRV_ACCT_OUT -p udp --sport 5201 -m comment --comment frpdrv-t1" {
		t.Fatalf("udp add arg shape wrong: %v", calls)
	}
	calls = nil
	if err := acctWireRulesDelProto(acctChainsDriver, "t1", 5201, 5201, "udp"); err != nil {
		t.Fatalf("udp del: %v", err)
	}
	if len(calls) < 1 || !strings.HasPrefix(strings.Join(calls[len(calls)-2], " "), "-D FRPDRV_ACCT_IN -p udp") {
		t.Fatalf("udp del arg shape wrong: %v", calls)
	}
	// the tcp wrappers still emit the historical -p tcp shapes.
	calls = nil
	if err := acctWireRulesAdd(acctChainsDriver, "t1", 5201, 5201); err != nil {
		t.Fatalf("tcp add: %v", err)
	}
	if len(calls) < 2 ||
		!strings.Contains(strings.Join(calls[len(calls)-2], " "), "-p tcp") ||
		!strings.Contains(strings.Join(calls[len(calls)-1], " "), "-p tcp") {
		t.Fatalf("tcp wrapper lost its proto: %v", calls)
	}
	// any other proto is refused (fail closed, never interpolated).
	calls = nil
	if err := acctWireRulesAddProto(acctChainsDriver, "t1", 5201, 5201, "icmp"); err == nil {
		t.Fatal("icmp accounting proto accepted")
	}
	if err := acctWireRulesAddProto(acctChainsDriver, "t1", 5201, 5201, "tcp; evil"); err == nil {
		t.Fatal("injection proto accepted")
	}
	if len(calls) != 0 {
		t.Fatalf("refused protos must not reach iptables: %v", calls)
	}
}
