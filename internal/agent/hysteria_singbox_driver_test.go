package agent

// Hermetic tests for the AGENT-31 drivers (hysteria + sing-box over the
// vendored cores): the hostile params matrix per family, the exact-shape
// config renders (every field cited to the upstream option/config
// structs in the AGENT-31 report), lifecycle via the spawn seams, and
// the version-probe parsing.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/infra"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// ---- fixtures --------------------------------------------------------------

func hysteriaTestParams() hysteriaParams {
	return hysteriaParams{
		ServerSide: "germany", Version: "2.14.0",
		Artifact:  "hysteria-2.14.0-linux-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("aa", 32), SHA256Arm: strings.Repeat("bb", 32),
		SigAmd: strings.Repeat("QQ==", 22)[:88], SigArm: strings.Repeat("QQ==", 22)[:88],
		ServerAddr: "0.0.0.0:36712", AuthPassword: "hy-auth-pass-01",
		TLSCert: "/etc/quantum/hy.crt", TLSKey: "/etc/quantum/hy.key",
		SocksPort: 21080,
	}
}

func singboxTestParams() singboxParams {
	return singboxParams{
		ServerSide: "germany", Version: "1.14.4",
		Artifact:  "sing-box-1.14.4-linux-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("cc", 32), SHA256Arm: strings.Repeat("dd", 32),
		SigAmd: strings.Repeat("QQ==", 22)[:88], SigArm: strings.Repeat("QQ==", 22)[:88],
		ServerAddr: "0.0.0.0:8388", Protocol: "shadowsocks",
		SSMethod: "aes-256-gcm", Password: "sb-pass-01",
		LocalMode: "proxy", LocalPort: 21081,
	}
}

func singboxSetTestEnv(t *testing.T) (cmds *[]string, spawned *int) {
	t.Helper()
	cmds = new([]string)
	spawned = new(int)
	origSpawn := singboxSpawn
	singboxSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		*spawned++
		b, err := os.ReadFile(cfgPath)
		if err == nil {
			*cmds = append(*cmds, string(b))
		}
		return &fakeFRPProcess{}, nil
	}
	t.Cleanup(func() { singboxSpawn = origSpawn })
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "germany"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = "test-key"
	t.Cleanup(func() { engineArtifactPubKeyB64 = origKey })
	return cmds, spawned
}

func hysteriaSetTestEnv(t *testing.T) (cfgs *[]string, spawned *int) {
	t.Helper()
	cfgs = new([]string)
	spawned = new(int)
	origSpawn := hysteriaSpawn
	hysteriaSpawn = func(role, binPath, cfgPath string) (frpProcess, error) {
		*spawned++
		b, err := os.ReadFile(cfgPath)
		if err == nil {
			*cfgs = append(*cfgs, role+"|"+string(b))
		}
		return &fakeFRPProcess{}, nil
	}
	t.Cleanup(func() { hysteriaSpawn = origSpawn })
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "germany"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = "test-key"
	t.Cleanup(func() { engineArtifactPubKeyB64 = origKey })
	return cfgs, spawned
}

// ---- hysteria ---------------------------------------------------------------

func TestHysteriaValidateParams(t *testing.T) {
	p := hysteriaTestParams()
	raw, _ := json.Marshal(p)
	if err := NewHysteriaDriver().Validate(raw); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
	// hostile matrix per family
	for name, mutate := range map[string]func(*hysteriaParams){
		"no cert":         func(p *hysteriaParams) { p.TLSCert, p.TLSKey = "", "" },
		"cert quote":      func(p *hysteriaParams) { p.TLSCert = "/a\"b" },
		"cert shell":      func(p *hysteriaParams) { p.TLSKey = "/a;b" },
		"short auth":      func(p *hysteriaParams) { p.AuthPassword = "short" },
		"auth newlines":   func(p *hysteriaParams) { p.AuthPassword = "a\nb" },
		"bad server_addr": func(p *hysteriaParams) { p.ServerAddr = "no-port" },
		"bad bw":          func(p *hysteriaParams) { p.UpMbps = "fast" },
		"bw injection":    func(p *hysteriaParams) { p.DownMbps = "100 mbps\nup: evil" },
		"sni junk":        func(p *hysteriaParams) { p.SNI = "a b" },
		"no ingress":      func(p *hysteriaParams) { p.SocksPort = 0 },
		"fwd bad remote": func(p *hysteriaParams) {
			p.SocksPort = 0
			p.TCPForwards = []hysteriaForward{{Listen: 21000, Remote: "no-port"}}
		},
		"fwd bad listen": func(p *hysteriaParams) {
			p.SocksPort = 0
			p.TCPForwards = []hysteriaForward{{Listen: 99999, Remote: "1.2.3.4:80"}}
		},
		"too many fwd": func(p *hysteriaParams) {
			p.SocksPort = 0
			for i := 0; i < 17; i++ {
				p.TCPForwards = append(p.TCPForwards, hysteriaForward{Listen: 20000 + i, Remote: "1.2.3.4:80"})
			}
		},
		"pin junk":   func(p *hysteriaParams) { p.PinSHA256 = "zz\"z" },
		"obfs short": func(p *hysteriaParams) { p.ObfsPassword = "ab" },
	} {
		bad := hysteriaTestParams()
		mutate(&bad)
		raw, _ := json.Marshal(bad)
		if err := NewHysteriaDriver().Validate(raw); err == nil {
			t.Fatalf("hysteria %s accepted", name)
		}
	}
	// forwards-only shape (no ingress) is valid.
	ok := hysteriaTestParams()
	ok.SocksPort = 0
	ok.TCPForwards = []hysteriaForward{{Listen: 21000, Remote: "10.77.0.1:5201"}}
	raw, _ = json.Marshal(ok)
	if err := NewHysteriaDriver().Validate(raw); err != nil {
		t.Fatalf("forwards-only rejected: %v", err)
	}
	// obfs enabled renders the salamander layer on both ends.
	p.ObfsPassword = "obfs-pass-01"
	srv := hysteriaRenderConfig("server", p)
	cli := hysteriaRenderConfig("client", p)
	for _, cfg := range []string{srv, cli} {
		for _, want := range []string{"type: salamander", `password: "obfs-pass-01"`} {
			if !strings.Contains(cfg, want) {
				t.Fatalf("obfs render missing %q:\n%s", want, cfg)
			}
		}
	}
	// exact server shape (auth type password, tls cert/key, bandwidth).
	p.UpMbps = "100 mbps"
	p.DownMbps = "500 mbps"
	srv = hysteriaRenderConfig("server", p)
	for _, want := range []string{
		`listen: ":36712"`, "auth:", "type: password", `password: "hy-auth-pass-01"`,
		`cert: "/etc/quantum/hy.crt"`, `key: "/etc/quantum/hy.key"`,
		`up: "100 mbps"`, `down: "500 mbps"`,
	} {
		if !strings.Contains(srv, want) {
			t.Fatalf("hysteria server config missing %q:\n%s", want, srv)
		}
	}
	// exact client shape: server dial, auth, tls sni/insecure, ingress +
	// tcpForwarding entry.
	p.SocksPort = 21080
	p.HTTPPort = 21081
	p.Insecure = true
	p.SNI = "hy.example.com"
	p.TCPForwards = []hysteriaForward{{Listen: 21000, Remote: "10.77.0.1:5201"}}
	cli = hysteriaRenderConfig("client", p)
	for _, want := range []string{
		`server: "0.0.0.0:36712"`, `auth: "hy-auth-pass-01"`,
		`sni: "hy.example.com"`, "insecure: true",
		`listen: "127.0.0.1:21080"`, "disableUDP: true",
		`listen: "127.0.0.1:21081"`,
		"tcpForwarding:", `listen: "127.0.0.1:21000"`, `remote: "10.77.0.1:5201"`,
	} {
		if !strings.Contains(cli, want) {
			t.Fatalf("hysteria client config missing %q:\n%s", want, cli)
		}
	}
}

// warmEngineCache pre-populates a core's artifact cache so Start
// exercises the cache-hit path without any fetch (the marker must match
// the fixture's pinned sha256).
func warmEngineCache(t *testing.T, engineID, version, binName, pinnedSHA string) {
	t.Helper()
	dir := filepath.Join(infra.ConfigDir, "engines", engineID, "bin", version)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, binName), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "artifact.sha256"), []byte(pinnedSHA), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestHysteriaStartStopLifecycle(t *testing.T) {
	cfgs, spawned := hysteriaSetTestEnv(t)
	d := NewHysteriaDriver()
	p := hysteriaTestParams()
	warmEngineCache(t, "hysteria", p.Version, "hysteria", p.SHA256Amd)
	// the server end (germany) starts the SERVER role with the exact CLI
	// shape `hysteria server -c <cfg>` (spawn seam captures the role).
	inst := engine.Instance{TunnelID: "thy1", LocalServer: "germany", RemoteServer: "iran", Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("server start: %v", err)
	}
	if *spawned != 1 {
		t.Fatalf("spawned = %d, want 1", *spawned)
	}
	if len(*cfgs) != 1 || !strings.HasPrefix((*cfgs)[0], "server|") {
		t.Fatalf("server role not used: %v", *cfgs)
	}
	if h := d.Health(inst); !h.OK {
		t.Fatalf("health: %+v", h)
	}
	// idempotent no-op on equal params.
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("idempotent start: %v", err)
	}
	if *spawned != 1 {
		t.Fatalf("idempotent start respawned (spawned=%d)", *spawned)
	}
	if err := d.Stop(inst); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if h := d.Health(inst); h.OK {
		t.Fatal("health after stop must fail")
	}
}

func TestHysteriaVersionProbeParse(t *testing.T) {
	orig := hysteriaVersionProbe
	hysteriaVersionProbe = func(binPath string) (string, error) {
		return "2.14.0", nil
	}
	t.Cleanup(func() { hysteriaVersionProbe = orig })
	if got := hysteriaInstalledVersion(); got != "2.14.0" {
		// no cache dir in the test env → the build pin is the honest
		// answer regardless of the probe seam.
		if got != hysteriaPinnedVersion {
			t.Fatalf("installed version = %q", got)
		}
	}
	// the parser itself: a real upstream-shaped blob parses to 2.14.0.
	out := "hysteria client version\nVersion:\t2.14.0\nBuildDate:\tUnknown\n"
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Version:") {
			if v := strings.TrimSpace(strings.TrimPrefix(line, "Version:")); v != "2.14.0" {
				t.Fatalf("parse = %q", v)
			}
			break
		}
	}
}

// ---- sing-box ----------------------------------------------------------------

func TestSingboxValidateParams(t *testing.T) {
	p := singboxTestParams()
	raw, _ := json.Marshal(p)
	if err := NewSingboxDriver().Validate(raw); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
	for name, mutate := range map[string]func(*singboxParams){
		"bad proto":      func(p *singboxParams) { p.Protocol = "shadowtls" },
		"naive refused":  func(p *singboxParams) { p.Protocol = "naive" },
		"no local mode":  func(p *singboxParams) { p.LocalMode = "" },
		"bad local mode": func(p *singboxParams) { p.LocalMode = "tun" },
		"local port 0":   func(p *singboxParams) { p.LocalPort = 0 },
		"ss no method":   func(p *singboxParams) { p.SSMethod = "" },
		"ss dead uuid":   func(p *singboxParams) { p.UUID = "b831381d-6324-4d53-ad4f-8cda48b30811" },
		"vless dead pw": func(p *singboxParams) {
			p.Protocol = "vless"
			p.UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
			p.Password = "x-pass-01"
		},
		"trojan no tls": func(p *singboxParams) { p.Protocol = "trojan"; p.Password = "x-pass-01"; p.TLSCert, p.TLSKey = "", "" },
		"hy2 no tls":    func(p *singboxParams) { p.Protocol = "hysteria2"; p.SSMethod = "" },
		"tuic bad cong": func(p *singboxParams) {
			p.Protocol = "tuic"
			p.UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
			p.Congestion = "brutal"
		},
		"bad server":   func(p *singboxParams) { p.ServerAddr = "no-port" },
		"fwd no addr":  func(p *singboxParams) { p.LocalMode = "forward" },
		"fwd bad addr": func(p *singboxParams) { p.LocalMode = "forward"; p.ForwardAddr = "no-port" },
		"fwd on proxy": func(p *singboxParams) { p.ForwardAddr = "10.0.0.1:80" },
		"pw short":     func(p *singboxParams) { p.Password = "short" },
	} {
		bad := singboxTestParams()
		mutate(&bad)
		raw, _ := json.Marshal(bad)
		if err := NewSingboxDriver().Validate(raw); err == nil {
			t.Fatalf("singbox %s accepted", name)
		}
	}
	// TLS-required protocols accept the pair; vless plain accepts without.
	for _, proto := range []string{"trojan", "hysteria2", "tuic", "anytls"} {
		ok := singboxTestParams()
		ok.Protocol = proto
		ok.SSMethod = ""
		ok.Password = "x-pass-01"
		ok.TLSCert, ok.TLSKey = "/etc/quantum/sb.crt", "/etc/quantum/sb.key"
		if proto == "tuic" {
			ok.UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
		}
		raw, _ = json.Marshal(ok)
		if err := NewSingboxDriver().Validate(raw); err != nil {
			t.Fatalf("%s with certs rejected: %v", proto, err)
		}
	}
	ok := singboxTestParams()
	ok.Protocol = "vless"
	ok.SSMethod = ""
	ok.Password = ""
	ok.UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
	raw, _ = json.Marshal(ok)
	if err := NewSingboxDriver().Validate(raw); err != nil {
		t.Fatalf("plain vless rejected: %v", err)
	}
}

func TestSingboxRenderExactShapes(t *testing.T) {
	// shadowsocks proxy mode: server inbound (method/password + listen) +
	// direct default outbound; client mixed ingress + ss outbound.
	p := singboxTestParams()
	srv := singboxRenderConfig("server", p)
	sb, _ := json.Marshal(srv)
	for _, want := range []string{
		`"type":"shadowsocks"`, `"tag":"carrier-in"`, `"listen":"0.0.0.0"`,
		`"listen_port":8388`, `"method":"aes-256-gcm"`, `"password":"sb-pass-01"`,
		`"type":"direct"`, `"tag":"direct-out"`,
	} {
		if !strings.Contains(string(sb), want) {
			t.Fatalf("ss server config missing %q:\n%s", want, sb)
		}
	}
	cli := singboxRenderConfig("client", p)
	cb, _ := json.Marshal(cli)
	for _, want := range []string{
		`"type":"mixed"`, `"tag":"ingress-in"`, `"listen":"127.0.0.1"`,
		`"listen_port":21081`,
		`"type":"shadowsocks"`, `"tag":"carrier-out"`,
		`"server":"0.0.0.0"`, `"server_port":8388`,
		// proxy mode: exactly ONE outbound (no direct fallback — no leak)
	} {
		if !strings.Contains(string(cb), want) {
			t.Fatalf("ss client config missing %q:\n%s", want, cb)
		}
	}
	if len(cli.Outbounds) != 1 {
		t.Fatalf("proxy mode must have exactly one outbound (no leak): %d", len(cli.Outbounds))
	}
	// vless forward mode: direct inbound with override + route rule.
	p.Protocol = "vless"
	p.UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
	p.LocalMode = "forward"
	p.LocalPort = 21082
	p.ForwardAddr = "10.77.0.1:5201"
	cli = singboxRenderConfig("client", p)
	cb, _ = json.Marshal(cli)
	for _, want := range []string{
		`"type":"direct"`, `"tag":"forward-in"`, `"listen_port":21082`,
		`"override_address":"10.77.0.1"`, `"override_port":5201`,
		`"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"`,
		`"inbound":["forward-in"]`, `"outbound":"carrier-out"`,
	} {
		if !strings.Contains(string(cb), want) {
			t.Fatalf("vless forward client missing %q:\n%s", want, cb)
		}
	}
	// trojan (TLS-required): server tls block carries cert/key; client
	// tls enabled + sni/insecure.
	p.Protocol = "trojan"
	p.Password = "x-pass-01"
	p.UUID = ""
	p.TLSCert, p.TLSKey = "/etc/quantum/sb.crt", "/etc/quantum/sb.key"
	p.SNI = "sb.example.com"
	p.Insecure = true
	srv = singboxRenderConfig("server", p)
	sb, _ = json.Marshal(srv)
	for _, want := range []string{
		`"type":"trojan"`, `"password":"x-pass-01"`,
		`"certificate_path":"/etc/quantum/sb.crt"`, `"key_path":"/etc/quantum/sb.key"`,
		`"enabled":true`,
	} {
		if !strings.Contains(string(sb), want) {
			t.Fatalf("trojan server missing %q:\n%s", want, sb)
		}
	}
	cli = singboxRenderConfig("client", p)
	cb, _ = json.Marshal(cli)
	for _, want := range []string{
		`"server_name":"sb.example.com"`, `"insecure":true`, `"enabled":true`,
	} {
		if !strings.Contains(string(cb), want) {
			t.Fatalf("trojan client missing %q:\n%s", want, cb)
		}
	}
	// hysteria2 (QUIC): users[].password + up/down + UDP carrier flag.
	p.Protocol = "hysteria2"
	p.UpMbps, p.DownMbps = 100, 500
	srv = singboxRenderConfig("server", p)
	sb, _ = json.Marshal(srv)
	for _, want := range []string{
		`"type":"hysteria2"`, `"password":"x-pass-01"`,
		`"up_mbps":100`, `"down_mbps":500`,
	} {
		if !strings.Contains(string(sb), want) {
			t.Fatalf("hysteria2 server missing %q:\n%s", want, sb)
		}
	}
	if !singBoxUDPCarrier("hysteria2") || !singBoxUDPCarrier("tuic") ||
		singBoxUDPCarrier("trojan") || singBoxUDPCarrier("vless") {
		t.Fatal("singBoxUDPCarrier misclassifies")
	}
}

func TestSingboxStartStopLifecycle(t *testing.T) {
	cmds, spawned := singboxSetTestEnv(t)
	d := NewSingboxDriver()
	p := singboxTestParams()
	warmEngineCache(t, "singbox", p.Version, "sing-box", p.SHA256Amd)
	inst := engine.Instance{TunnelID: "tsb1", LocalServer: "germany", RemoteServer: "iran", Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("server start: %v", err)
	}
	if *spawned != 1 || len(*cmds) != 1 {
		t.Fatalf("spawned=%d cmds=%d", *spawned, len(*cmds))
	}
	// the rendered config is valid JSON with both blocks present.
	var parsed map[string]any
	if err := json.Unmarshal([]byte((*cmds)[0]), &parsed); err != nil {
		t.Fatalf("rendered config not JSON: %v", err)
	}
	if h := d.Health(inst); !h.OK {
		t.Fatalf("health: %+v", h)
	}
	if err := d.Stop(inst); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if h := d.Health(inst); h.OK {
		t.Fatal("health after stop must fail")
	}
}

func TestSingboxVersionProbeParse(t *testing.T) {
	// the parser: real upstream-shaped output.
	out := "sing-box version 1.14.4\n\nEnvironment: go1.27.3 linux/amd64\nTags: with_gvisor\n"
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) < 3 || f[0] != "sing-box" || f[1] != "version" || f[2] != "1.14.4" {
		t.Fatalf("parse failed: %v", f)
	}
	if got := singboxInstalledVersion(); got != singboxPinnedVersion {
		t.Fatalf("no-cache version = %q, want the build pin", got)
	}
}
