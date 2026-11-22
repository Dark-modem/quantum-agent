package agent

// Hermetic tests for the OVERNIGHT-A2 gap-close wave 2: gost TLS-family/
// ssh/ss/pht carriers + ingress modes, frp's secret-proxy family
// (stcp/sudp/xtcp with the foreign-end visitor frpc), rathole's PKCS12
// TLS carrier. Every assert cites the upstream evidence recorded in the
// A2 report (e2e metadata keys, VisitorBaseConfig, TlsConfig pkcs12).

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---- gost wave 2 ----------------------------------------------------------

func TestGostCertCarriers(t *testing.T) {
	p := gostTestParams()
	// TLS-family carriers are refused WITHOUT the operator cert pair...
	for _, tr := range []string{"tls", "mtls", "h2", "http3", "h3", "wt", "utls"} {
		p.Transport = tr
		p.TLSCert, p.TLSKey = "", ""
		if err := gostValidateParams(p); err == nil {
			t.Fatalf("carrier %s accepted without tls_cert/tls_key", tr)
		}
		// ...and render certFile/keyFile into the server URL with them.
		p.TLSCert, p.TLSKey = "/etc/quantum/cert.pem", "/etc/quantum/key.pem"
		if err := gostValidateParams(p); err != nil {
			t.Fatalf("carrier %s with certs rejected: %v", tr, err)
		}
		args := gostArgs("server", gostCarrierScheme(p), p)
		if !strings.Contains(args[1], "certFile=/etc/quantum/cert.pem") ||
			!strings.Contains(args[1], "keyFile=/etc/quantum/key.pem") {
			t.Fatalf("carrier %s server args missing cert metadata: %v", tr, args)
		}
	}
	// utls: the CLIENT side carries the fingerprint (chrome default).
	p.Transport = "utls"
	cli := gostArgs("client", gostCarrierScheme(p), p)
	if !strings.Contains(cli[3], "fingerprint=chrome") {
		t.Fatalf("utls client args missing fingerprint: %v", cli)
	}
	p.UTLSFingerprint = "Firefox"
	cli = gostArgs("client", gostCarrierScheme(p), p)
	if !strings.Contains(cli[3], "fingerprint=firefox") {
		t.Fatalf("utls explicit fingerprint missing: %v", cli)
	}
	// hostile: shell metacharacters and quotes never reach the URLs.
	for name, mutate := range map[string]func(*gostParams){
		"cert quote":  func(p *gostParams) { p.TLSCert = "/a\"b.pem" },
		"cert shell":  func(p *gostParams) { p.TLSKey = "/a;b.pem" },
		"fp junk":     func(p *gostParams) { p.Transport = "utls"; p.UTLSFingerprint = "ch@ome" },
		"ss pass @":   func(p *gostParams) { p.Transport = "ss"; p.SSMethod = "aes-256-gcm"; p.SSPassword = "pa@ss" },
		"ssh bad url": func(p *gostParams) { p.Transport = "ssh"; p.SSHUser = "ro:ot"; p.SSHPassword = "pw" },
	} {
		bad := gostTestParams()
		bad.TLSCert, bad.TLSKey = "/c.pem", "/k.pem"
		mutate(&bad)
		if err := gostValidateParams(bad); err == nil {
			t.Fatalf("gost %s accepted", name)
		}
	}
}

func TestGostSSAndSSHAndPHT(t *testing.T) {
	p := gostTestParams()
	// shadowsocks carrier: NOT a relay+ scheme — its own URL shape on
	// both ends (e2e-verified: handler/connector auth username=method).
	p.Transport = "ss"
	p.SSMethod, p.SSPassword = "aes-256-gcm", "secret-pass-01"
	if err := gostValidateParams(p); err != nil {
		t.Fatalf("ss rejected: %v", err)
	}
	srv := gostArgs("server", "ss", p)
	if srv[1] != "ss://aes-256-gcm:secret-pass-01@:23344" {
		t.Fatalf("ss server URL wrong: %v", srv)
	}
	cli := gostArgs("client", "ss", p)
	if !strings.Contains(cli[1], "rtcp://") || cli[3] != "ss://aes-256-gcm:secret-pass-01@0.0.0.0:23344" {
		t.Fatalf("ss client args wrong: %v", cli)
	}
	// ss without credentials is refused.
	p.SSPassword = ""
	if err := gostValidateParams(p); err == nil {
		t.Fatal("ss without password accepted")
	}
	// ssh carrier: userinfo rides both ends; missing auth refused.
	p.Transport = "ssh"
	p.SSHUser, p.SSHPassword = "quantum", "ssh-pass-01"
	p.SSMethod, p.SSPassword = "", ""
	if err := gostValidateParams(p); err != nil {
		t.Fatalf("ssh rejected: %v", err)
	}
	srv = gostArgs("server", "ssh", p)
	if !strings.Contains(srv[1], "relay+ssh://quantum:ssh-pass-01@:23344") {
		t.Fatalf("ssh server args wrong: %v", srv)
	}
	p.SSHUser = ""
	if err := gostValidateParams(p); err == nil {
		t.Fatal("ssh without user accepted")
	}
	// pht: plain (no certs needed), composes like the other plain carriers.
	p.Transport = "pht"
	if err := gostValidateParams(p); err == nil {
		// pht without ssh params is fine — but Transport=ssh check above
		// cleared ssh creds; pht needs none.
	} else {
		t.Fatalf("pht rejected: %v", err)
	}
	srv = gostArgs("server", "pht", p)
	if !strings.Contains(srv[1], "relay+pht://:23344?bind=true") {
		t.Fatalf("pht server args wrong: %v", srv)
	}
	// the quic-family carriers are UDP sockets (accounting drives off this).
	for tr, want := range map[string]bool{"http3": true, "h3": true, "wt": true, "pht": false, "tls": false} {
		if got := gostUDPCarrier(tr); got != want {
			t.Fatalf("gostUDPCarrier(%q) = %v, want %v", tr, got, want)
		}
	}
}

func TestGostIngressModes(t *testing.T) {
	p := gostTestParams()
	// ingress flips the data port to the CLIENT end (local proxy exit).
	p.Ingress = "socks5"
	if err := gostValidateParams(p); err != nil {
		t.Fatalf("socks5 ingress rejected: %v", err)
	}
	cli := gostArgs("client", "ws", p)
	if !strings.Contains(cli[1], "socks5://:25203") || strings.Contains(cli[1], "rtcp") {
		t.Fatalf("ingress client listener wrong: %v", cli)
	}
	srv := gostArgs("server", "ws", p)
	if strings.Contains(srv[1], "bind=true") {
		t.Fatalf("ingress server must NOT bind (plain relay): %v", srv)
	}
	// http + socks4 ingress render their own schemes.
	for ing, scheme := range map[string]string{"http": "http", "socks4": "socks4"} {
		p.Ingress = ing
		cli = gostArgs("client", "ws", p)
		if !strings.Contains(cli[1], scheme+"://") {
			t.Fatalf("ingress %s missing scheme: %v", ing, cli)
		}
	}
	// hostile: unknown ingress values.
	p.Ingress = "tun"
	if err := gostValidateParams(p); err == nil {
		t.Fatal("ingress tun accepted (out of scope by design)")
	}
	p.Ingress = "socks5\n[evil]"
	if err := gostValidateParams(p); err == nil {
		t.Fatal("ingress injection accepted")
	}
	// the historical shape is preserved when Ingress is empty.
	p0 := gostTestParams()
	cli0 := gostArgs("client", "ws", p0)
	if !strings.Contains(cli0[1], "rtcp://") {
		t.Fatalf("empty ingress must keep rtcp: %v", cli0)
	}
}

// ---- frp secret-proxy family ----------------------------------------------

func TestFRPSecretProxies(t *testing.T) {
	p := frpTestParams()
	// tcp (default) with a dead secret is refused...
	p.SecretKey = "sk-secret-01"
	if err := frpValidateParams(p); err == nil {
		t.Fatal("secret_key accepted on proxy_type tcp")
	}
	// ...stcp/sudp/xtcp need it, render it, and arm the visitor.
	for _, pt := range []string{"stcp", "sudp", "xtcp"} {
		p.ProxyType = pt
		p.SecretKey = "sk-secret-01"
		if err := frpValidateParams(p); err != nil {
			t.Fatalf("%s rejected: %v", pt, err)
		}
		cli := frpRenderConfig("t1", "client", p)
		for _, want := range []string{`type = "` + pt + `"`, `secretKey = "sk-secret-01"`} {
			if !strings.Contains(cli, want) {
				t.Fatalf("%s client config missing %q:\n%s", pt, want, cli)
			}
		}
		vis := frpVisitorConfig("t1", p)
		for _, want := range []string{
			`serverAddr = "127.0.0.1"`, `serverPort = 7000`,
			`name = "t1-visitor"`, `type = "` + pt + `"`,
			`serverName = "t1"`, `secretKey = "sk-secret-01"`,
			`bindAddr = "0.0.0.0"`, `bindPort = 34001`,
		} {
			if !strings.Contains(vis, want) {
				t.Fatalf("%s visitor config missing %q:\n%s", pt, want, vis)
			}
		}
	}
	// hostile: short secret, injection secret, tcp+secret mix.
	for name, mutate := range map[string]func(*frpParams){
		"short sk": func(p *frpParams) { p.SecretKey = "short" },
		"inj sk":   func(p *frpParams) { p.SecretKey = "a\"b\nc" },
		"tcp + sk": func(p *frpParams) { p.ProxyType = "tcp"; p.SecretKey = "sk-secret-01" },
		"bad type": func(p *frpParams) { p.ProxyType = "http" },
	} {
		bad := frpTestParams()
		bad.ProxyType = "stcp"
		bad.SecretKey = "sk-secret-01"
		mutate(&bad)
		if err := frpValidateParams(bad); err == nil {
			t.Fatalf("frp %s accepted", name)
		}
	}
	// visitor-only helper consistency.
	if !frpSecretProxy("sudp") || frpSecretProxy("udp") || frpSecretProxy("") {
		t.Fatal("frpSecretProxy misclassifies")
	}
	// the historical default params still validate (backward compat).
	if err := frpValidateParams(frpTestParams()); err != nil {
		t.Fatalf("default frp params no longer valid: %v", err)
	}
}

// ---- rathole TLS (PKCS12) carrier ------------------------------------------

func TestRatholeTLSCarrier(t *testing.T) {
	p := ratholeTestParams()
	// bare tls is refused with the pkcs12 guidance...
	p.Transport = "tls"
	if err := ratholeValidateParams(p); err == nil {
		t.Fatal("bare tls accepted")
	}
	// ...and the full pair renders into BOTH ends' transport blocks.
	p.PKCS12Path = "/etc/quantum/rathole.p12"
	p.PKCS12Password = "p12-pass-01"
	if err := ratholeValidateParams(p); err != nil {
		t.Fatalf("tls with pkcs12 rejected: %v", err)
	}
	srv := ratholeRenderConfig("server", "q1", p, "")
	for _, want := range []string{`type = "tls"`, `pkcs12 = "/etc/quantum/rathole.p12"`, `pkcs12_password = "p12-pass-01"`} {
		if !strings.Contains(srv, want) {
			t.Fatalf("tls server config missing %q:\n%s", want, srv)
		}
	}
	cli := ratholeRenderConfig("client", "q1", p, "")
	if !strings.Contains(cli, `[client.transport.tls]`) || !strings.Contains(cli, `pkcs12 = "`) {
		t.Fatalf("tls client config missing the pkcs12 block:\n%s", cli)
	}
	// hostile: password-only pair, quote injection through the path.
	bad := ratholeTestParams()
	bad.Transport = "tls"
	bad.PKCS12Password = "p12-pass-01"
	if err := ratholeValidateParams(bad); err == nil {
		t.Fatal("tls with password-only accepted")
	}
	bad = ratholeTestParams()
	bad.Transport = "tls"
	bad.PKCS12Path = "/a\"b.p12"
	bad.PKCS12Password = "p12-pass-01"
	if err := ratholeValidateParams(bad); err == nil {
		t.Fatal("pkcs12_path quote injection accepted")
	}
	// the wave-1 shapes are untouched (noise default renders as before).
	ok := ratholeTestParams()
	srv = ratholeRenderConfig("server", "q1", ok, "NOISEPRIV")
	if !strings.Contains(srv, `type = "noise"`) {
		t.Fatalf("noise default broken by the tls addition:\n%s", srv)
	}
}

// ---- all six engines' default shapes still validate (wave-1 compat) --------

func TestOvernightA2BackwardCompat(t *testing.T) {
	raw, _ := json.Marshal(backhaulTestParams())
	if err := NewBackhaulDriver().Validate(raw); err != nil {
		t.Fatalf("backhaul defaults broke: %v", err)
	}
	raw, _ = json.Marshal(gostTestParams())
	if err := NewGostDriver().Validate(raw); err != nil {
		t.Fatalf("gost defaults broke: %v", err)
	}
	raw, _ = json.Marshal(frpTestParams())
	if err := NewFRPDriver().Validate(raw); err != nil {
		t.Fatalf("frp defaults broke: %v", err)
	}
	raw, _ = json.Marshal(ratholeTestParams())
	if err := NewRatholeDriver().Validate(raw); err != nil {
		t.Fatalf("rathole defaults broke: %v", err)
	}
	raw, _ = json.Marshal(xrayTestParams())
	if err := NewXrayDriver().Validate(raw); err != nil {
		t.Fatalf("xray defaults broke: %v", err)
	}
	if err := wgCompanionTest().validate(); err != nil {
		t.Fatalf("udp2raw companion defaults broke: %v", err)
	}
}
