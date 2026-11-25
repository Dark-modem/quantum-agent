package agent

// Hermetic tests for OVERNIGHT-A8: the xray `carrier: masque` family on the
// v26.11.9 core. Upstream evidence (03-RESEARCH/overnight-sources/xray-core
// @ 74cbdf4): infra/conf/masque.go (MasqueServerConfig: users email+pass,
// address REQUIRED = host prefix, mtu 0|1280..65535; MasqueClientConfig:
// address/port, remoteDNS bare IPs), infra/conf/transport_method.go
// (MasqueConfig: host round-trips url.Parse("https://"+host); user/pass are
// the ONLY source of the HTTP Basic Authorization header),
// infra/conf/transport_security.go (pinnedPeerCertSha256 is a STRING:
// comma-separated, ':' stripped, hex, exactly 32 bytes; allowInsecure is a
// removed feature), proxy/masque/server.go:272-282 (BasicAuth → validator →
// 401), proxy/masque/pool.go:20-38 (host-address rule),
// transport/internet/masque/dialer.go:44-47 (QUIC = UDP).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-agent/internal/infra"
)

const a8LabPin = "dd533ce8cc3ae6b1e3b3da2a6c95c7e5efb255b3730e1ad5a080b9735c317c84"

// xrayMasqueTestParams is a COMPLETE, validated masque pair: the lab
// addressing (foreign 10.127.8.2:8443, TUN context 10.127.8.1/24), the
// email+pass users, the PEM PATH pair on the foreign host, the leaf-DER
// pin, both ingress ports, and host/mtu/remote_dns unset (upstream
// defaults). The artifact triple matches xraySetTestEnv's served pack.
func xrayMasqueTestParams() xrayParams {
	return xrayParams{
		ServerSide: "germany", Version: "25.9.30",
		Artifact:  "xray-25.9.30-linux-{arch}.tar.gz",
		SHA256Amd: xrayTestPins.amd, SHA256Arm: xrayTestPins.arm,
		SigAmd: xrayTestPins.sigAmd, SigArm: xrayTestPins.sigArm,
		RemoteAddr: "10.127.8.2", CarrierPort: 8443,
		Carrier: "masque",
		TLSCert: "/etc/quantum/xray-masque.crt", TLSKey: "/etc/quantum/xray-masque.key",
		MasqueEmail: "a8-lab@quantum.test", MasquePass: "a8-lab-pass-01",
		MasqueAddress: "10.127.8.1/24",
		PinSHA256:     a8LabPin,
		SocksPort:     1081, HTTPPort: 8081,
	}
}

// TestXrayMasqueExactShapeBothEnds renders BOTH ends through the REAL
// validate+render path and locks the exact JSON: the server's REQUIRED
// address[], the users, the TLS certificateFile/keyFile pair and the host;
// the client's Basic-auth user/pass (the only source of the Authorization
// header — without it the inbound answers 401), the leaf pin, host
// defaulting to the dial address, and the socks+http ingress pinned to
// carrier-out. The file the driver writes must be the indented same object.
func TestXrayMasqueExactShapeBothEnds(t *testing.T) {
	p := xrayMasqueTestParams()
	if err := xrayValidateParams(p); err != nil {
		t.Fatalf("masque params rejected: %v", err)
	}
	const wantServer = `{"log":{"loglevel":"warning"},"inbounds":[{"tag":"masque-in","listen":"0.0.0.0","port":8443,"protocol":"masque","settings":{"users":[{"email":"a8-lab@quantum.test","pass":"a8-lab-pass-01"}],"address":["10.127.8.1/24"]},"streamSettings":{"network":"masque","security":"tls","masqueSettings":{"host":"10.127.8.2"},"tlsSettings":{"certificates":[{"certificateFile":"/etc/quantum/xray-masque.crt","keyFile":"/etc/quantum/xray-masque.key"}]}}}],"outbounds":[{"tag":"direct","protocol":"freedom"}]}`
	const wantClient = `{"log":{"loglevel":"warning"},"inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":1081,"protocol":"socks","settings":{"auth":"noauth","udp":true}},{"tag":"http-in","listen":"127.0.0.1","port":8081,"protocol":"http"}],"outbounds":[{"tag":"carrier-out","protocol":"masque","settings":{"address":"10.127.8.2","port":8443},"streamSettings":{"network":"masque","security":"tls","masqueSettings":{"host":"10.127.8.2","user":"a8-lab@quantum.test","pass":"a8-lab-pass-01"},"tlsSettings":{"serverName":"10.127.8.2","pinnedPeerCertSha256":"dd533ce8cc3ae6b1e3b3da2a6c95c7e5efb255b3730e1ad5a080b9735c317c84"}}}],"routing":{"domainStrategy":"","rules":[{"type":"field","inboundTag":["socks-in"],"outboundTag":"carrier-out"},{"type":"field","inboundTag":["http-in"],"outboundTag":"carrier-out"}]}}`
	srv := xrayBuildConfig(engineSideServer, p)
	sj, _ := json.Marshal(srv)
	if string(sj) != wantServer {
		t.Fatalf("masque SERVER render drifted:\n got: %s\nwant: %s", sj, wantServer)
	}
	cli := xrayBuildConfig(engineSideClient, p)
	cj, _ := json.Marshal(cli)
	if string(cj) != wantClient {
		t.Fatalf("masque CLIENT render drifted:\n got: %s\nwant: %s", cj, wantClient)
	}
	// The materialized file = the indented same object (what Start writes).
	dir := t.TempDir()
	path := filepath.Join(dir, "instances", "a8.json")
	if err := xrayWriteConfigFile(path, srv); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wantIndent, _ := json.MarshalIndent(srv, "", "  ")
	if string(data) != string(wantIndent) {
		t.Fatalf("materialized server config differs from the render:\n%s", data)
	}
	fi, _ := os.Stat(path)
	if runtime.GOOS == "linux" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v, want 0600 (it carries masque_pass)", fi.Mode().Perm())
	}
	// The client end never carries the key path (server-only material).
	if strings.Contains(string(cj), p.TLSKey) || strings.Contains(string(cj), p.TLSCert) {
		t.Fatalf("client render carries the server's cert/key paths: %s", cj)
	}
	// The server end never carries the pin (client-only material).
	if strings.Contains(string(sj), a8LabPin) {
		t.Fatalf("server render carries the client pin: %s", sj)
	}
}

// TestXrayMasqueLabDump writes the DRIVER-RENDERED configs for the real
// v26.11.9 `xray run -test` gate (env-gated: A8_LAB_DIR + A8_LAB_CERT +
// A8_LAB_KEY point at the probe PEM pair). No traffic is generated: the
// masque ends create a TUN device, so a live leg needs CAP_NET_ADMIN.
func TestXrayMasqueLabDump(t *testing.T) {
	dir := os.Getenv("A8_LAB_DIR")
	if dir == "" {
		t.Skip("A8_LAB_DIR not set")
	}
	cert, key := os.Getenv("A8_LAB_CERT"), os.Getenv("A8_LAB_KEY")
	if cert == "" || key == "" {
		t.Skip("A8_LAB_CERT/A8_LAB_KEY not set")
	}
	p := xrayMasqueTestParams()
	p.TLSCert, p.TLSKey = cert, key
	if err := xrayValidateParams(p); err != nil {
		t.Fatalf("lab params rejected: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := xrayWriteConfigFile(filepath.Join(dir, "server.json"), xrayBuildConfig(engineSideServer, p)); err != nil {
		t.Fatal(err)
	}
	if err := xrayWriteConfigFile(filepath.Join(dir, "client.json"), xrayBuildConfig(engineSideClient, p)); err != nil {
		t.Fatal(err)
	}
}

// TestXrayMasqueRenderOptions: explicit host (HTTP authority + SNI), mtu
// and remoteDNS ride their exact upstream fields; socks-only ingress
// renders one inbound + one rule.
func TestXrayMasqueRenderOptions(t *testing.T) {
	p := xrayMasqueTestParams()
	p.MasqueHost = "masque.lab.test"
	p.MasqueMTU = 1280
	p.MasqueRemoteDNS = "1.1.1.1,2606:4700:4700::1111"
	p.HTTPPort = 0
	if err := xrayValidateParams(p); err != nil {
		t.Fatalf("masque options rejected: %v", err)
	}
	sj, _ := json.Marshal(xrayBuildConfig(engineSideServer, p))
	for _, want := range []string{`"address":["10.127.8.1/24"],"mtu":1280`, `"masqueSettings":{"host":"masque.lab.test"}`} {
		if !strings.Contains(string(sj), want) {
			t.Fatalf("server render missing %s:\n%s", want, sj)
		}
	}
	cj, _ := json.Marshal(xrayBuildConfig(engineSideClient, p))
	for _, want := range []string{`"settings":{"address":"10.127.8.2","port":8443,"remoteDNS":["1.1.1.1","2606:4700:4700::1111"]}`,
		`"masqueSettings":{"host":"masque.lab.test","user":"a8-lab@quantum.test","pass":"a8-lab-pass-01"}`,
		`"tlsSettings":{"serverName":"masque.lab.test","pinnedPeerCertSha256":"` + a8LabPin + `"}`,
		`"rules":[{"type":"field","inboundTag":["socks-in"],"outboundTag":"carrier-out"}]}`} {
		if !strings.Contains(string(cj), want) {
			t.Fatalf("client render missing %s:\n%s", want, cj)
		}
	}
	if strings.Contains(string(cj), `"http-in"`) || strings.Contains(string(cj), `"mtu"`) {
		t.Fatalf("client render leaked a server-only/http field:\n%s", cj)
	}
	// Default mtu stays unset (upstream default 1280 — never rendered as 0).
	p2 := xrayMasqueTestParams()
	sj2, _ := json.Marshal(xrayBuildConfig(engineSideServer, p2))
	if strings.Contains(string(sj2), `"mtu"`) {
		t.Fatalf("default mtu must not render:\n%s", sj2)
	}
	// An explicit host may carry the authority port, but the TLS
	// ServerName must be the bare host: Go's TLS handshake rejects
	// "host:port" as a name before the pin can be evaluated.
	p3 := xrayMasqueTestParams()
	p3.MasqueHost = "masque.lab.test:8443"
	cj3, _ := json.Marshal(xrayBuildConfig(engineSideClient, p3))
	for _, want := range []string{`"masqueSettings":{"host":"masque.lab.test:8443"`,
		`"serverName":"masque.lab.test"`} {
		if !strings.Contains(string(cj3), want) {
			t.Fatalf("host:port TLS split wrong, missing %s:\n%s", want, cj3)
		}
	}
	if strings.Contains(string(cj3), `"serverName":"masque.lab.test:8443"`) {
		t.Fatalf("TLS ServerName carries the authority port:\n%s", cj3)
	}
}

// TestXrayMasqueHostileMatrix: every refusal path of the masque carrier,
// table-driven. The error strings must never echo the field VALUES
// (masque_pass / tls_key are secrets; the pin and paths are operator data).
func TestXrayMasqueHostileMatrix(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*xrayParams)
		want   string // substring the error must carry
	}{
		{"no tls cert", func(p *xrayParams) { p.TLSCert = "" }, "tls_cert"},
		{"no tls key", func(p *xrayParams) { p.TLSKey = "" }, "tls_key"},
		{"tls cert relative", func(p *xrayParams) { p.TLSCert = "relative/xray.crt" }, "tls_cert"},
		{"tls key quote", func(p *xrayParams) { p.TLSKey = `/etc/x"y.key` }, "tls_key"},
		{"tls cert too long", func(p *xrayParams) { p.TLSCert = "/" + strings.Repeat("a", 300) }, "tls_cert"},
		{"email empty", func(p *xrayParams) { p.MasqueEmail = "" }, "masque_email"},
		{"email colon", func(p *xrayParams) { p.MasqueEmail = "a:b@quantum.test" }, "masque_email"},
		{"email space", func(p *xrayParams) { p.MasqueEmail = "a b@quantum.test" }, "masque_email"},
		{"email quote", func(p *xrayParams) { p.MasqueEmail = `a"b@quantum.test` }, "masque_email"},
		{"email too long", func(p *xrayParams) { p.MasqueEmail = strings.Repeat("a", 130) + "@x.test" }, "masque_email"},
		{"pass short", func(p *xrayParams) { p.MasquePass = "short" }, "masque_pass"},
		{"pass empty", func(p *xrayParams) { p.MasquePass = "" }, "masque_pass"},
		{"pass quote", func(p *xrayParams) { p.MasquePass = `abc"defgh1234` }, "masque_pass"},
		{"pin empty", func(p *xrayParams) { p.PinSHA256 = "" }, "pin_sha256"},
		{"pin 63 hex", func(p *xrayParams) { p.PinSHA256 = strings.Repeat("ab", 31) + "a" }, "pin_sha256"},
		{"pin non-hex 64", func(p *xrayParams) { p.PinSHA256 = strings.Repeat("zz", 32) }, "pin_sha256"},
		{"pin base64", func(p *xrayParams) { p.PinSHA256 = "3VM86ax45zvNbEJ8nqJxK1l0qk5fT7wYzM2UeR9pQ1s=" }, "pin_sha256"},
		{"pin colon format wrong length", func(p *xrayParams) { p.PinSHA256 = strings.Repeat("dd:", 30) + "dd" }, "32 bytes"},
		{"pin whitespace only", func(p *xrayParams) { p.PinSHA256 = " , " }, "pin_sha256"},
		{"host with path", func(p *xrayParams) { p.MasqueHost = "masque.lab.test/x" }, "masque_host"},
		{"host with space", func(p *xrayParams) { p.MasqueHost = "masque lab" }, "masque_host"},
		{"host with userinfo", func(p *xrayParams) { p.MasqueHost = "u@masque.lab.test" }, "masque_host"},
		{"host with scheme", func(p *xrayParams) { p.MasqueHost = "https://masque.lab.test" }, "masque_host"},
		{"host too long", func(p *xrayParams) { p.MasqueHost = strings.Repeat("a.", 127) + "a" }, "masque_host"},
		{"mtu negative", func(p *xrayParams) { p.MasqueMTU = -1 }, "masque_mtu"},
		{"mtu 1", func(p *xrayParams) { p.MasqueMTU = 1 }, "masque_mtu"},
		{"mtu 1279 (upstream rejects <1280)", func(p *xrayParams) { p.MasqueMTU = 1279 }, "masque_mtu"},
		{"mtu 65536", func(p *xrayParams) { p.MasqueMTU = 65536 }, "masque_mtu"},
		{"address empty (REQUIRED upstream)", func(p *xrayParams) { p.MasqueAddress = "" }, "masque_address"},
		{"address not a prefix", func(p *xrayParams) { p.MasqueAddress = "10.127.8.1" }, "masque_address"},
		{"address network address", func(p *xrayParams) { p.MasqueAddress = "10.127.8.0/24" }, "masque_address"},
		{"address broadcast", func(p *xrayParams) { p.MasqueAddress = "10.127.8.255/24" }, "masque_address"},
		{"address /32 leaves nothing", func(p *xrayParams) { p.MasqueAddress = "10.127.8.1/32" }, "masque_address"},
		{"address /31 broadcast", func(p *xrayParams) { p.MasqueAddress = "10.127.8.1/31" }, "masque_address"},
		{"address v4-in-v6", func(p *xrayParams) { p.MasqueAddress = "::ffff:10.127.8.1/120" }, "masque_address"},
		{"address zone", func(p *xrayParams) { p.MasqueAddress = "fe80::1%eth0/64" }, "masque_address"},
		{"remote dns not an ip", func(p *xrayParams) { p.MasqueRemoteDNS = "dns.local" }, "masque_remote_dns"},
		{"remote dns host:port", func(p *xrayParams) { p.MasqueRemoteDNS = "1.1.1.1:53" }, "masque_remote_dns"},
		{"remote dns list junk", func(p *xrayParams) { p.MasqueRemoteDNS = "1.1.1.1,nope" }, "masque_remote_dns"},
		{"no remote addr", func(p *xrayParams) { p.RemoteAddr = "" }, "remote_addr"},
		{"remote addr quote", func(p *xrayParams) { p.RemoteAddr = `10.127.8."2` }, "remote_addr"},
		{"no ingress port", func(p *xrayParams) { p.SocksPort, p.HTTPPort = 0, 0 }, "socks_port or http_port"},
		{"socks port collides with carrier", func(p *xrayParams) { p.SocksPort = 8443 }, "collides"},
		{"http port out of range", func(p *xrayParams) { p.HTTPPort = 70000 }, "http_port"},
		{"api_port set (no API inbound renders)", func(p *xrayParams) { p.APIPort = 21599 }, "api_port"},
		{"carrier port 0", func(p *xrayParams) { p.CarrierPort = 0 }, "carrier_port"},
		{"no server side", func(p *xrayParams) { p.ServerSide = "" }, "server_side"},
		{"no version", func(p *xrayParams) { p.Version = "" }, "version"},
		{"artifact without arch", func(p *xrayParams) { p.Artifact = "xray.tar.gz" }, "artifact"},
		{"short sha pin", func(p *xrayParams) { p.SHA256Amd = "abc" }, "sha256"},
		{"short signature pin", func(p *xrayParams) { p.SigArm = "abc" }, "signature"},
		{"unknown carrier", func(p *xrayParams) { p.Carrier = "quinn" }, "not supported"},
	}
	for _, tc := range cases {
		bad := xrayMasqueTestParams()
		tc.mutate(&bad)
		err := xrayValidateParams(bad)
		if err == nil {
			t.Fatalf("masque %s accepted", tc.name)
		}
		if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: error %q lacks %q", tc.name, err, tc.want)
		}
		// No secret/value echo in the error string.
		for _, secret := range []string{bad.MasquePass, bad.TLSKey, bad.PinSHA256} {
			if secret != "" && strings.Contains(err.Error(), secret) {
				t.Fatalf("%s: error echoes a field value: %q", tc.name, err)
			}
		}
	}
	// Upstream-exact ACCEPTS: the colon (OpenSSL) pin format, upper-case hex,
	// several comma-separated pins, an email without '@' (upstream only
	// forbids ':'), an IPv6 context, mtu bounds 0/1280/65535, host:port.
	for name, mutate := range map[string]func(*xrayParams){
		"pin colon format": func(p *xrayParams) {
			p.PinSHA256 = strings.ToLower(strings.Join(splitEvery(a8LabPin, 2), ":"))
		},
		"pin upper hex":      func(p *xrayParams) { p.PinSHA256 = strings.ToUpper(a8LabPin) },
		"two pins + blanks":  func(p *xrayParams) { p.PinSHA256 = a8LabPin + " , " + strings.Repeat("ee", 32) },
		"email without @":    func(p *xrayParams) { p.MasqueEmail = "iran" },
		"ipv6 context":       func(p *xrayParams) { p.MasqueAddress = "fd00:8::1/64" },
		"mtu 1280":           func(p *xrayParams) { p.MasqueMTU = 1280 },
		"mtu 65535":          func(p *xrayParams) { p.MasqueMTU = 65535 },
		"host with port":     func(p *xrayParams) { p.MasqueHost = "masque.lab.test:8443" },
		"remote dns v6 only": func(p *xrayParams) { p.MasqueRemoteDNS = "2606:4700:4700::1111" },
		"http-only ingress":  func(p *xrayParams) { p.SocksPort = 0 },
		"carrier normalized": func(p *xrayParams) { p.Carrier = " Masque " },
	} {
		ok := xrayMasqueTestParams()
		mutate(&ok)
		if err := xrayValidateParams(ok); err != nil {
			t.Fatalf("masque %s rejected: %v", name, err)
		}
	}
	// The Validate entry point (JSON path) agrees.
	d := NewXrayDriver()
	if err := d.Validate(infra.MustJSON(xrayMasqueTestParams())); err != nil {
		t.Fatalf("Validate rejected the masque pair: %v", err)
	}
	bad := xrayMasqueTestParams()
	bad.MasqueAddress = ""
	if err := d.Validate(infra.MustJSON(bad)); err == nil {
		t.Fatal("Validate accepted a masque pair without address")
	}
}

func splitEvery(s string, n int) []string {
	var out []string
	for i := 0; i < len(s); i += n {
		if i+n > len(s) {
			out = append(out, s[i:])
			break
		}
		out = append(out, s[i:i+n])
	}
	return out
}

// TestXrayDeadFieldCrossProduct: EVERY carrier refuses EVERY param of the
// other families (one shared table) — a value set on a carrier that never
// renders it is a silent misconfiguration. Error strings carry labels
// only.
func TestXrayDeadFieldCrossProduct(t *testing.T) {
	type setter struct {
		label string
		set   func(*xrayParams)
	}
	realityFields := []setter{
		{"server_name", func(p *xrayParams) { p.ServerName = "www.microsoft.com" }},
		{"dest", func(p *xrayParams) { p.Dest = "www.microsoft.com:443" }},
		{"short_id", func(p *xrayParams) { p.ShortID = "0123abcd" }},
		{"reality_public_key", func(p *xrayParams) { p.RealityPublicKey = strings.Repeat("a", 43) }},
		{"reality_private_key", func(p *xrayParams) { p.RealityPrivateKey = "qJmA9N5S_9fNnE2wC8bXlQ0V0kL2wE8dG7fH6jK5lM0" }},
		{"uuid", func(p *xrayParams) { p.UUID = "b831381d-6324-4d53-ad4f-8cda48b30811" }},
		{"local_addr", func(p *xrayParams) { p.LocalAddr = "127.0.0.1" }},
		{"public_port", func(p *xrayParams) { p.PublicPort = 5201 }},
		{"local_port", func(p *xrayParams) { p.LocalPort = 5202 }},
		{"api_port", func(p *xrayParams) { p.APIPort = 21599 }},
		{"transport", func(p *xrayParams) { p.Transport = "xhttp" }},
		{"xhttp_path", func(p *xrayParams) { p.XHTTPPath = "/x" }},
		{"grpc_service_name", func(p *xrayParams) { p.GrpcServiceName = "quantum-reverse" }},
	}
	hysteriaFields := []setter{
		{"hysteria_auth", func(p *xrayParams) { p.HysteriaAuth = "xray-hy-pw-01" }},
	}
	tlsFields := []setter{
		{"tls_cert", func(p *xrayParams) { p.TLSCert = "/etc/quantum/x.crt" }},
		{"tls_key", func(p *xrayParams) { p.TLSKey = "/etc/quantum/x.key" }},
	}
	masqueFields := []setter{
		{"masque_email", func(p *xrayParams) { p.MasqueEmail = "someone@quantum.test" }},
		{"masque_pass", func(p *xrayParams) { p.MasquePass = "someone-pass-01" }},
		{"masque_host", func(p *xrayParams) { p.MasqueHost = "masque.lab.test" }},
		{"masque_mtu", func(p *xrayParams) { p.MasqueMTU = 1280 }},
		{"masque_address", func(p *xrayParams) { p.MasqueAddress = "10.127.8.1/24" }},
		{"masque_remote_dns", func(p *xrayParams) { p.MasqueRemoteDNS = "1.1.1.1" }},
		{"pin_sha256", func(p *xrayParams) { p.PinSHA256 = a8LabPin }},
	}
	carriers := []struct {
		name    string
		base    func() xrayParams
		carrier string
		dead    []setter
	}{
		{"reality", xrayTestParams, "", append(append(append([]setter{}, hysteriaFields...), tlsFields...), masqueFields...)},
		{"hysteria2", xrayHyParams, "hysteria2", append(append([]setter{}, realityFields...), masqueFields...)},
		{"masque", xrayMasqueTestParams, "masque", append(append([]setter{}, realityFields...), hysteriaFields...)},
	}
	for _, c := range carriers {
		for _, f := range c.dead {
			p := c.base()
			if p.Carrier != c.carrier {
				t.Fatalf("%s base has carrier %q", c.name, p.Carrier)
			}
			f.set(&p)
			err := xrayValidateParams(p)
			if err == nil {
				t.Fatalf("carrier %s accepted dead field %s", c.name, f.label)
			}
			if !strings.Contains(err.Error(), f.label) {
				t.Fatalf("carrier %s dead field %s: error %q does not name it", c.name, f.label, err)
			}
			// The refused VALUE never rides the error (secrets!).
			for _, secret := range []string{p.MasquePass, p.HysteriaAuth, p.RealityPrivateKey, p.TLSKey, p.UUID} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Fatalf("carrier %s dead field %s: error echoes a value: %q", c.name, f.label, err)
				}
			}
		}
		// Each base validates on its own carrier.
		if err := xrayValidateParams(c.base()); err != nil {
			t.Fatalf("%s base rejected: %v", c.name, err)
		}
	}
	// flow stays globally refused (mux.cool) on every carrier.
	for carrier, base := range map[string]func() xrayParams{
		"":          xrayTestParams,
		"hysteria2": xrayHyParams,
		"masque":    xrayMasqueTestParams,
	} {
		p := base()
		p.Flow = "xtls-rprx-vision"
		err := xrayValidateParams(p)
		if err == nil || !strings.Contains(err.Error(), "flow") {
			t.Fatalf("carrier %q accepted flow: %v", carrier, err)
		}
	}
}

// TestXrayMasqueDescribeSchema: ParamsSchema is valid JSON under the
// panel's 4 KiB cap, lists EVERY xrayParams key (so the wizard can offer
// masque_address / pin_sha256 / masque_remote_dns), keeps honest JSON
// types, and never carries a secret value.
func TestXrayMasqueDescribeSchema(t *testing.T) {
	info := NewXrayDriver().Describe()
	if len(info.ParamsSchema) > 4096 {
		t.Fatalf("params_schema is %d bytes (panel cap 4096)", len(info.ParamsSchema))
	}
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(info.ParamsSchema, &schema); err != nil {
		t.Fatalf("params_schema is not valid JSON: %v\n%s", err, info.ParamsSchema)
	}
	typ := reflect.TypeOf(xrayParams{})
	missing := []string{}
	for i := 0; i < typ.NumField(); i++ {
		key := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if key == "" || key == "-" {
			continue
		}
		if _, ok := schema[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("params_schema lacks keys: %v", missing)
	}
	// Honest types: ports/mtu are numbers, carrier an enum hint, the rest
	// strings.
	for _, k := range []string{"carrier_port", "public_port", "local_port", "api_port", "socks_port", "http_port", "masque_mtu"} {
		var n int
		if err := json.Unmarshal(schema[k], &n); err != nil {
			t.Fatalf("schema %s is not numeric: %s", k, schema[k])
		}
	}
	for _, k := range []string{"masque_address", "pin_sha256", "masque_remote_dns", "masque_email", "masque_pass", "masque_host", "tls_cert", "tls_key", "hysteria_auth"} {
		var s string
		if err := json.Unmarshal(schema[k], &s); err != nil {
			t.Fatalf("schema %s is not a string: %s", k, schema[k])
		}
		if s != "" && k != "masque_address" {
			t.Fatalf("schema %s must stay an empty placeholder (secrets never ride Describe): %q", k, s)
		}
	}
	var carrier string
	_ = json.Unmarshal(schema["carrier"], &carrier)
	for _, want := range []string{"hysteria2", "masque"} {
		if !strings.Contains(carrier, want) {
			t.Fatalf("carrier hint %q lacks %q", carrier, want)
		}
	}
	if strings.Contains(string(info.ParamsSchema), "a8-lab-pass") {
		t.Fatal("Describe leaks a secret")
	}
}

// TestXrayMasqueVersionGateSeam: the gate compares the PROBED version of
// the resolved binary (the params version is only the cache key — the
// manifest pick may resolve a different core) against the first
// masque-capable release.
func TestXrayMasqueVersionGateSeam(t *testing.T) {
	orig := xrayVersionProbe
	t.Cleanup(func() { xrayVersionProbe = orig })
	for _, tc := range []struct {
		probe    string
		probeErr bool
		wantErr  bool
	}{
		{"24.12.31", false, true}, // unknown transport protocol: masque
		{"26.3.27", false, true},  // the A5 pack: 26.3 < 26.9 numerically
		{"26.9.29", false, true},
		{"26.9.30", false, false},
		{"26.11.9", false, false},
		{"v26.11.9", false, false},
		{"27.1.0", false, false},
		{"", true, true}, // probe failure = unknown = fail closed
		{"garbage", true, true},
	} {
		xrayVersionProbe = func(string) (string, error) {
			if tc.probeErr {
				return "", context.DeadlineExceeded
			}
			return tc.probe, nil
		}
		err := xrayMasqueVersionGate("/nonexistent/xray")
		if tc.wantErr && err == nil {
			t.Fatalf("probed %q: gate let an old/unknown core through", tc.probe)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("probed %q: gate refused a capable core: %v", tc.probe, err)
		}
		if err != nil && !strings.Contains(err.Error(), xrayMasqueMinVersion) {
			t.Fatalf("probed %q: error lacks the minimum version: %v", tc.probe, err)
		}
	}
	// The numeric compare must NOT be the panel's plain-string pick
	// ("26.11.9" < "26.3.27" by bytes — G3).
	if !xrayVersionLess("26.3.27", "26.11.9") || xrayVersionLess("26.11.9", "26.3.27") {
		t.Fatal("xrayVersionLess compares strings, not numbers")
	}
}

// TestXrayMasqueStartGatesAndAccounting drives Start/Health/Stop through
// the seams: the TUN gate fails closed first, the version gate fails
// closed before any config is written or process spawned, a capable core
// starts with UDP wire accounting (QUIC) and the 0600 config carrying
// masque_pass; Stop deletes the UDP rules and the config; nothing the
// driver exposes (Health detail, Describe, argv) carries a secret.
func TestXrayMasqueStartGatesAndAccounting(t *testing.T) {
	_, leaked := xraySetTestEnv(t)
	p := xrayMasqueTestParams() // built after the env (the pins are the served pack's)
	inst := engine.Instance{TunnelID: "a8-t1", LocalServer: "germany", RemoteServer: "iran",
		Params: infra.MustJSON(p)}

	origTun, origProbe := xrayTunAvailable, xrayVersionProbe
	t.Cleanup(func() { xrayTunAvailable, xrayVersionProbe = origTun, origProbe })
	xrayTunAvailable = func() bool { return true }
	xrayVersionProbe = func(string) (string, error) { return "26.11.9", nil }

	var iptCalls [][]string
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) {
		iptCalls = append(iptCalls, append([]string{}, args...))
		return nil, nil
	}
	t.Cleanup(func() { acctIptables = origIpt })

	// (1) TUN gate: no TUN → fail closed, nothing spawned.
	xrayTunAvailable = func() bool { return false }
	d := NewXrayDriver()
	if err := d.Start(context.Background(), inst); err == nil || !strings.Contains(err.Error(), "/dev/net/tun") {
		t.Fatalf("TUN gate did not fail closed: %v", err)
	}
	if d.runs.len() != 0 {
		t.Fatal("instance registered despite the TUN gate")
	}
	xrayTunAvailable = func() bool { return true }

	// (2) Version gate: an old resolved core → fail closed BEFORE writing
	// the config or spawning (the spawn seam would have recorded it in
	// `leaked` — it must stay empty).
	xrayVersionProbe = func(string) (string, error) { return "26.3.27", nil }
	err := d.Start(context.Background(), inst)
	if err == nil || !strings.Contains(err.Error(), "26.3.27") || !strings.Contains(err.Error(), xrayMasqueMinVersion) {
		t.Fatalf("version gate did not fail closed with the honest reason: %v", err)
	}
	if _, serr := os.Stat(xrayConfigPath("a8-t1")); serr == nil {
		t.Fatal("a config was written despite the version gate")
	}
	if leaked.Len() != 0 || d.runs.len() != 0 {
		t.Fatalf("something was spawned/registered despite the version gate (leaked=%d bytes, runs=%d)", leaked.Len(), d.runs.len())
	}
	// probe failure = unknown = fail closed too.
	xrayVersionProbe = func(string) (string, error) { return "", context.DeadlineExceeded }
	if err := d.Start(context.Background(), inst); err == nil || !strings.Contains(err.Error(), "probe") {
		t.Fatalf("unprobeable core started: %v", err)
	}

	// (3) A capable core starts: server end, UDP wire rules, 0600 config.
	xrayVersionProbe = func(string) (string, error) { return "26.11.9", nil }
	iptCalls = nil
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("capable core refused: %v", err)
	}
	cfgPath := xrayConfigPath("a8-t1")
	data, rerr := os.ReadFile(cfgPath)
	if rerr != nil {
		t.Fatalf("server config not written: %v", rerr)
	}
	if !strings.Contains(string(data), p.MasqueAddress) || !strings.Contains(string(data), `"masque-in"`) {
		t.Fatalf("server config lacks the masque TUN context / inbound tag:\n%s", data)
	}
	if !strings.Contains(string(data), p.MasquePass) {
		t.Fatal("server config lacks masque_pass (the inbound needs it)")
	}
	if runtime.GOOS == "linux" {
		if fi, _ := os.Stat(cfgPath); fi.Mode().Perm() != 0o600 {
			t.Fatalf("config mode = %v, want 0600", fi.Mode().Perm())
		}
	}
	udpAdd := false
	for _, c := range iptCalls {
		if len(c) > 4 && c[0] == "-A" && c[2] == "-p" && c[3] == "udp" {
			udpAdd = true
		}
		if len(c) > 4 && c[0] == "-A" && c[2] == "-p" && c[3] == "tcp" {
			t.Fatalf("masque (QUIC = UDP) installed a TCP wire rule: %v", c)
		}
	}
	if !udpAdd {
		t.Fatalf("masque server end installed no UDP wire rule: %v", iptCalls)
	}
	// Health/Counters/Describe carry no secret.
	h := d.Health(inst)
	if !h.OK || strings.Contains(h.Detail, p.MasquePass) {
		t.Fatalf("masque health wrong/leaky: %+v", h)
	}
	if !strings.Contains(h.Detail, "udp") {
		t.Fatalf("health detail should name the udp wire for masque: %+v", h)
	}
	if c := d.Counters(inst); c.PayloadKnown || c.WireKnown {
		t.Fatalf("masque counters must be unknown without api_port: %+v", c)
	}
	if strings.Contains(string(d.Describe().ParamsSchema), p.MasquePass) {
		t.Fatal("Describe leaks masque_pass")
	}
	// argv = run -c <cfg> only.
	argv := strings.Join(xrayArgv(cfgPath), " ")
	if argv != "run -c "+cfgPath || strings.Contains(argv, p.MasquePass) {
		t.Fatalf("argv carries more than the config path: %q", argv)
	}
	// (4) Stop: the UDP rules go and the config file is removed.
	iptCalls = nil
	if err := d.Stop(inst); err != nil {
		t.Fatal(err)
	}
	udpDel := false
	for _, c := range iptCalls {
		if len(c) > 4 && c[0] == "-D" && c[2] == "-p" && c[3] == "udp" {
			udpDel = true
		}
	}
	if !udpDel {
		t.Fatalf("Stop deleted no UDP wire rule: %v", iptCalls)
	}
	if _, serr := os.Stat(cfgPath); serr == nil {
		t.Fatal("config survived Stop")
	}
	if h := d.Health(inst); h.OK {
		t.Fatal("alive after Stop")
	}
	// The carrier-derived inbound tag (StatsService counters).
	if xrayInboundTag(xrayMasqueTestParams()) != "masque-in" ||
		xrayInboundTag(xrayHyParams()) != "hysteria-in" || xrayInboundTag(xrayTestParams()) != "vless-in" {
		t.Fatal("xrayInboundTag mapping wrong")
	}
	if xrayWireProto(xrayMasqueTestParams()) != "udp" || xrayWireProto(xrayHyParams()) != "udp" ||
		xrayWireProto(xrayTestParams()) != "tcp" {
		t.Fatal("xrayWireProto mapping wrong")
	}
}

// TestXrayMasqueClientEndStartsToo: the CLIENT end (iran) starts with the
// same params (socks/http ingress riding carrier-out), no wire rules.
func TestXrayMasqueClientEndStartsToo(t *testing.T) {
	xraySetTestEnv(t)
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test:7777", BasePath: "bp", Name: "iran-1"}, true
	}
	origTun, origProbe := xrayTunAvailable, xrayVersionProbe
	xrayTunAvailable = func() bool { return true }
	xrayVersionProbe = func(string) (string, error) { return "26.11.9", nil }
	var iptCalls [][]string
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) {
		iptCalls = append(iptCalls, append([]string{}, args...))
		return nil, nil
	}
	t.Cleanup(func() {
		frpLoadIdentity, xrayTunAvailable, xrayVersionProbe, acctIptables = origIdent, origTun, origProbe, origIpt
	})
	p := xrayMasqueTestParams()
	d := NewXrayDriver()
	inst := engine.Instance{TunnelID: "a8-c1", LocalServer: "iran-1", RemoteServer: "germany",
		Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	data, err := os.ReadFile(xrayConfigPath("a8-c1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"tag": "carrier-out"`, `"user": "a8-lab@quantum.test"`, `"pinnedPeerCertSha256": "` + a8LabPin + `"`, `"tag": "socks-in"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("client config missing %s:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), p.TLSKey) {
		t.Fatal("client config carries the server key path")
	}
	for _, c := range iptCalls {
		if len(c) > 3 && (c[0] == "-A" || c[0] == "-D") {
			t.Fatalf("client end must not touch the server's wire rules: %v", c)
		}
	}
	if err := d.Stop(inst); err != nil {
		t.Fatal(err)
	}
}
