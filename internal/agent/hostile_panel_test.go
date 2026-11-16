package agent

// hostile_panel_test.go — AGENT-21 ingest audit: everything the agent
// ACCEPTS from the panel must fail safe against a hostile/compromised
// panel. One test per ingest family:
//
//	 1. engine_params per driver Validate — every value that reaches a
//	    rendered config must reject the characters that break that render
//	    (quotes/backslash/newlines/whitespace for TOML-rendered strings);
//	    fields with allowlist semantics (transport, method, ports, IPs,
//	    regexes) reject the whole smuggle set
//	 2. the balancer's DNAT targets (static panel Target + driver forward
//	    addresses) — nothing but a parsed IPv4 literal may reach the nft
//	    transaction the agent applies as root
//	 3. the command allowlist + confirm gating — unknown ops refused
//	    BEFORE any execution; hostile payloads rejected by the handlers
//	 4. agent.update request validation + the same-origin download rule
//	 5. carrier fou:/wss: remainders (they ride as ONE argv element into
//	    the installed quantum script — decimal ports only)
//	 6. the panel WS frame cap (a hostile panel cannot stream an
//	    unbounded frame into the agent's memory)
//	 7. malformed DesiredV2 documents (wrong types / invalid params JSON)
//	 8. hardening profile documents (the module's Validate gate)
//	 9. matrix settings (the v1 desired path's validation)
//
// Everything here is hermetic: loopback only, no host commands, no netns.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-agent/internal/hardening"
	"github.com/Dark-modem/quantum-protocol"
	"github.com/gorilla/websocket"
)

// smuggleSet is the shared smuggle set: shell metacharacters, argv-style
// flags, traversal and unicode. Applied wholesale to fields whose shape
// must reject ALL of it (allowlists, IP literals, regexes).
var smuggleSet = []string{
	"; rm -rf /", "$(id)", "`id`", "\nrm -rf /", "\rX", "--flag=1",
	"../../etc/passwd", "a\"b", "a'b", "a\\b", "a b", "\u200b", "\u00e9",
	"a;b", "a|b", "a&b", "$PATH", "\x7f",
}

// quoteBreakSet is the subset that breaks a quoted string in a rendered
// config: quotes, backslash, newline, CR. Every driver that renders a
// panel string into a quoted config file must reject all of it. (Spaces
// are NOT render-breaking in quoted TOML; frp additionally rejects them
// per its own stricter charset — asserted in the frp test.)
var quoteBreakSet = []string{"a\"b", "a\\b", "\nrm -rf /", "\rX"}

// wsRejectSet adds whitespace to quoteBreakSet (the frp addr charset).
var wsRejectSet = []string{"a\"b", "a\\b", "\nrm -rf /", "\rX", "a b", "\ta"}

// ---- 1. engine_params per driver ---------------------------------------

func TestHostileFRPParamsFailClosed(t *testing.T) {
	base := frpTestParams()
	// server_addr/local_addr are rendered into the TOML with plain
	// quoting (phase-21 F2 fix): the frp charset (quotes, backslash,
	// whitespace, newlines) must fail.
	for _, field := range []struct {
		label string
		set   func(p frpParams, v string) frpParams
	}{
		{"server_addr", func(p frpParams, v string) frpParams { p.ServerAddr = v; return p }},
		{"local_addr", func(p frpParams, v string) frpParams { p.LocalAddr = v; return p }},
		{"token", func(p frpParams, v string) frpParams { p.Token = v; return p }},
		{"version", func(p frpParams, v string) frpParams { p.Version = v; return p }},
		{"artifact", func(p frpParams, v string) frpParams { p.Artifact = v; return p }},
	} {
		for _, hostile := range wsRejectSet {
			p := field.set(base, hostile)
			if err := frpValidateParams(p); err == nil {
				t.Fatalf("frp %s=%q must fail validation", field.label, hostile)
			}
		}
	}
	// The full smuggle set on the REGEX-gated pins and the port range.
	for _, hostile := range smuggleSet {
		p := base
		p.SHA256Amd = hostile
		if err := frpValidateParams(p); err == nil {
			t.Fatalf("frp sha256_amd64=%q must fail", hostile)
		}
	}
	// Extra frp shapes: bad pins, port ranges, allow range order, lengths.
	bad := []func(p frpParams) frpParams{
		func(p frpParams) frpParams { p.SHA256Amd = "zz"; return p },
		func(p frpParams) frpParams { p.SHA256Amd = strings.Repeat("ab", 31); return p }, // 62 chars
		func(p frpParams) frpParams { p.SigAmd = ""; return p },
		func(p frpParams) frpParams { p.ServerPort = 0; return p },
		func(p frpParams) frpParams { p.ServerPort = 65536; return p },
		func(p frpParams) frpParams { p.RemotePort = -1; return p },
		func(p frpParams) frpParams { p.DashPort = 70000; return p },
		func(p frpParams) frpParams { p.AllowMin = 400; p.AllowMax = 300; return p },
		func(p frpParams) frpParams { p.ServerSide = strings.Repeat("x", 129); return p },
		func(p frpParams) frpParams { p.Artifact = "no-template-here.tar.gz"; return p },
	}
	for i, f := range bad {
		if err := frpValidateParams(f(base)); err == nil {
			t.Fatalf("frp bad-case %d must fail", i)
		}
	}
	if err := frpValidateParams(base); err != nil {
		t.Fatalf("baseline params must validate: %v", err)
	}
}

func TestHostileBackhaulParamsFailClosed(t *testing.T) {
	p := backhaulParams{
		ServerSide: "iran", Version: "0.7.2", Artifact: "backhaul-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("ab", 32), SigAmd: strings.Repeat("A", 68),
		SHA256Arm: strings.Repeat("cd", 32), SigArm: strings.Repeat("B", 68),
		Transport: "tls", Token: "tok-12345678", BindAddr: "0.0.0.0:443",
		RemoteAddr: "198.51.100.9:443", Ports: []string{"5201=127.0.0.1:5201"}, WebPort: 0,
	}
	for _, field := range []struct {
		label string
		set   func(p backhaulParams, v string) backhaulParams
	}{
		{"token", func(p backhaulParams, v string) backhaulParams { p.Token = v; return p }},
		{"bind_addr", func(p backhaulParams, v string) backhaulParams { p.BindAddr = v; return p }},
		{"remote_addr", func(p backhaulParams, v string) backhaulParams { p.RemoteAddr = v; return p }},
		{"version", func(p backhaulParams, v string) backhaulParams { p.Version = v; return p }},
	} {
		// backhaul renders with Go %q (any byte escapes safely), so its
		// own charset (quotes/newlines) is the pin — a backslash is
		// render-safe there and correctly accepted.
		for _, hostile := range []string{"a\"b", "\nrm -rf /", "\rX"} {
			if err := backhaulValidateParams(field.set(p, hostile)); err == nil {
				t.Fatalf("backhaul %s=%q must fail", field.label, hostile)
			}
		}
	}
	// transport is an ALLOWLIST: the whole smuggle set fails.
	for _, hostile := range smuggleSet {
		if err := backhaulValidateParams(field2Backhaul(p, hostile)); err == nil {
			t.Fatalf("backhaul transport=%q must fail", hostile)
		}
	}
	// A hostile PORT MAPPING entry (upstream-parsed string): the render
	// is Go %q-quoted, so the pin is backhaul's own charset (quotes/
	// newlines break it; a `;` inside the quoted string is upstream
	// parse-refused data, not an escape).
	for _, hostile := range []string{"a\"b", "\nrm -rf /", "\rX", strings.Repeat("x", 129)} {
		p2 := p
		p2.Ports = []string{hostile}
		if err := backhaulValidateParams(p2); err == nil {
			t.Fatalf("backhaul ports entry %q must fail", hostile)
		}
	}
	if err := backhaulValidateParams(p); err != nil {
		t.Fatalf("baseline: %v", err)
	}
}

func field2Backhaul(p backhaulParams, v string) backhaulParams { p.Transport = v; return p }

func TestHostileRatholeGostWstChiselParamsFailClosed(t *testing.T) {
	// rathole: host:port fields (charset + SplitHostPort) and token.
	rp := ratholeParams{
		ServerSide: "iran", Version: "0.5.0", Artifact: "rathole-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("ab", 32), SigAmd: "AAAA", SHA256Arm: strings.Repeat("cd", 32), SigArm: "BBBB",
		ServerAddr: "198.51.100.9:7000", ServiceAddr: "0.0.0.0:34001",
		LocalAddr: "127.0.0.1:5201", Token: "tok-12345678",
	}
	for _, hostile := range []string{"a\"b", "\nrm -rf /", "\rX"} { // rathole's own charset (render is Go %q)
		for _, field := range []string{"server_addr", "service_addr", "local_addr", "token"} {
			p := rp
			switch field {
			case "server_addr":
				p.ServerAddr = hostile
			case "service_addr":
				p.ServiceAddr = hostile
			case "local_addr":
				p.LocalAddr = hostile
			case "token":
				p.Token = hostile
			}
			if err := ratholeValidateParams(p); err == nil {
				t.Fatalf("rathole %s=%q must fail", field, hostile)
			}
		}
	}
	// Every addr field must ALSO be host:port — the whole smuggle set
	// fails the SplitHostPort gate.
	for _, hostile := range smuggleSet {
		p := rp
		p.ServerAddr = hostile
		if err := ratholeValidateParams(p); err == nil {
			t.Fatalf("rathole server_addr=%q must fail", hostile)
		}
	}

	// gost: charset fields + the transport allowlist.
	gp := gostParams{
		ServerSide: "iran", Version: "3.3.3", Artifact: "gost-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("ab", 32), SigAmd: "AAAA", SHA256Arm: strings.Repeat("cd", 32), SigArm: "BBBB",
		CarrierAddr: "0.0.0.0:8443", PublicPort: 34001, LocalAddr: "127.0.0.1:5201", Transport: "ws",
	}
	for _, hostile := range quoteBreakSet {
		p := gp
		p.CarrierAddr = hostile
		if err := gostValidateParams(p); err == nil {
			t.Fatalf("gost carrier_addr=%q must fail", hostile)
		}
		p2 := gp
		p2.LocalAddr = hostile
		if err := gostValidateParams(p2); err == nil {
			t.Fatalf("gost local_addr=%q must fail", hostile)
		}
	}
	for _, hostile := range smuggleSet {
		p := gp
		p.Transport = hostile
		if err := gostValidateParams(p); err == nil {
			t.Fatalf("gost transport=%q must fail", hostile)
		}
	}

	// wstunnel: charset fields.
	wp := wstParams{
		ServerSide: "iran", Version: "10.1.9", Artifact: "wstunnel-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("ab", 32), SigAmd: "AAAA", SHA256Arm: strings.Repeat("cd", 32), SigArm: "BBBB",
		RemoteAddr: "198.51.100.9", WsPort: 8443, RemotePort: 34001, LocalAddr: "127.0.0.1", LocalPort: 5201,
	}
	for _, hostile := range quoteBreakSet {
		p := wp
		p.RemoteAddr = hostile
		if err := wstValidateParams(p); err == nil {
			t.Fatalf("wstunnel remote_addr=%q must fail", hostile)
		}
		p2 := wp
		p2.LocalAddr = hostile
		if err := wstValidateParams(p2); err == nil {
			t.Fatalf("wstunnel local_addr=%q must fail", hostile)
		}
	}

	// chisel: charset fields + auth shape.
	cp := chiselParams{
		ServerSide: "iran", Version: "1.10.1", Artifact: "chisel-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("ab", 32), SigAmd: "AAAA", SHA256Arm: strings.Repeat("cd", 32), SigArm: "BBBB",
		RemoteAddr: "198.51.100.9", ServerPort: 8443, RemotePort: 34001,
		LocalAddr: "127.0.0.1", LocalPort: 5201, Auth: "user:pass",
	}
	for _, hostile := range quoteBreakSet {
		p := cp
		p.RemoteAddr = hostile
		if err := chiselValidateParams(p); err == nil {
			t.Fatalf("chisel remote_addr=%q must fail", hostile)
		}
		p2 := cp
		p2.LocalAddr = hostile
		if err := chiselValidateParams(p2); err == nil {
			t.Fatalf("chisel local_addr=%q must fail", hostile)
		}
		p3 := cp
		p3.Auth = hostile
		if err := chiselValidateParams(p3); err == nil {
			t.Fatalf("chisel auth=%q must fail", hostile)
		}
	}
}

func TestHostileXrayCtunnelWgParamsFailClosed(t *testing.T) {
	// xray: charset fields + secret-shape fields.
	xp := xrayParams{
		ServerSide: "iran", Version: "24.12.31", Artifact: "xray-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("ab", 32), SigAmd: "AAAA", SHA256Arm: strings.Repeat("cd", 32), SigArm: "BBBB",
		RemoteAddr: "198.51.100.9", CarrierPort: 443, PublicPort: 34001,
		LocalAddr: "127.0.0.1", LocalPort: 5201, ServerName: "camo.example",
		Dest: "camo.example:443", RealityPublicKey: strings.Repeat("k", 43) + "=",
		RealityPrivateKey: strings.Repeat("p", 43) + "=", UUID: "0e8f4e10-8a2e-4f5f-9c1d-2b3a4d5e6f70",
	}
	for _, hostile := range quoteBreakSet {
		for _, field := range []string{"remote_addr", "local_addr", "server_name", "dest", "uuid"} {
			p := xp
			switch field {
			case "remote_addr":
				p.RemoteAddr = hostile
			case "local_addr":
				p.LocalAddr = hostile
			case "server_name":
				p.ServerName = hostile
			case "dest":
				p.Dest = hostile
			case "uuid":
				p.UUID = hostile
			}
			if err := xrayValidateParams(p); err == nil {
				t.Fatalf("xray %s=%q must fail", field, hostile)
			}
		}
	}
	// The flow field is fail-closed by DESIGN (empty only — mux.cool).
	for _, hostile := range append(append([]string{}, smuggleSet...), "xtls-rprx-vision") {
		p := xp
		p.Flow = hostile
		if err := xrayValidateParams(p); err == nil {
			t.Fatalf("xray flow=%q must fail (mux.cool rule)", hostile)
		}
	}

	// ctunnel: charset fields + allowlisted method/proto/direction.
	tp := ctunnelParams{
		ServerSide: "iran", Version: "1.1.1", Artifact: "ctunnel-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("ab", 32), SigAmd: "AAAA", SHA256Arm: strings.Repeat("cd", 32), SigArm: "BBBB",
		Method: "dtls-1.3", Direction: "reverse", ForeignAddr: "198.51.100.9:443",
		CarrierPort: 443, PublicPort: 34001, LocalAddr: "127.0.0.1:5201",
		Proto: "tcp", Secret: strings.Repeat("ab", 32),
	}
	for _, hostile := range quoteBreakSet {
		p := tp
		p.ForeignAddr = hostile
		if err := ctValidateParams(p); err == nil {
			t.Fatalf("ctunnel foreign_addr=%q must fail", hostile)
		}
		p2 := tp
		p2.LocalAddr = hostile
		if err := ctValidateParams(p2); err == nil {
			t.Fatalf("ctunnel local_addr=%q must fail", hostile)
		}
		p3 := tp
		p3.Secret = hostile
		if err := ctValidateParams(p3); err == nil {
			t.Fatalf("ctunnel secret=%q must fail", hostile)
		}
	}
	for _, hostile := range smuggleSet {
		p := tp
		p.Method = hostile
		if err := ctValidateParams(p); err == nil {
			t.Fatalf("ctunnel method=%q must fail", hostile)
		}
	}

	// wireguard: IP-literal carrier, base64 peer, MTU bounds.
	gp := wgParams{
		ServerSide: "iran", CarrierIP: "198.51.100.9", CarrierPort: 51820, MTU: 1350,
	}
	for _, hostile := range smuggleSet {
		p := gp
		p.CarrierIP = hostile
		if err := wgValidateParams(p); err == nil {
			t.Fatalf("wg carrier_ip=%q must fail", hostile)
		}
		p2 := gp
		p2.PeerPublic = hostile
		if err := wgValidateParams(p2); err == nil {
			t.Fatalf("wg peer_public=%q must fail", hostile)
		}
	}
	for _, mtu := range []int{-1, 100, 1279, 9001, 65535} {
		p := gp
		p.MTU = mtu
		if err := wgValidateParams(p); err == nil {
			t.Fatalf("wg mtu=%d must fail", mtu)
		}
	}
}

// TestValidateRejectsWrongTypedParams: engine_params arriving as non-object
// JSON must fail every driver's Validate (the preflight gate before
// anything starts). A huge member inside valid JSON decodes — the frame
// cap (TestPanelWSFrameReadLimit) bounds the transport size.
func TestValidateRejectsWrongTypedParams(t *testing.T) {
	reg, err := AgentEngines()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"frp", "backhaul", "rathole", "gost", "wstunnel", "chisel", "xray", "ctunnel", "wireguard", "matrix"} {
		drv, ok := reg.Driver(id)
		if !ok {
			t.Fatalf("engine %q missing from the agent registry", id)
		}
		for _, raw := range []string{`[1,2,3]`, `"hello"`, `42`, `null`, `{invalid`, `{"instance":123}`} {
			if e := drv.Validate(json.RawMessage(raw)); e == nil {
				t.Fatalf("%s: params %s must fail validation", id, raw)
			}
		}
	}
}

// ---- 2. balancer DNAT targets -------------------------------------------

// balHostileFixture builds a balancer over a fake engine with one running
// tunnel in topology "topo", plus the apply seam recording every script.
func balHostileFixture(t *testing.T, forwardHost string) (*forwardBalancer, *[]string) {
	t.Helper()
	fake := engine.NewFakeEngine("fake")
	fake.SetForwardAddress("t1", forwardHost, 15901)
	reg := engine.NewRegistry()
	if err := reg.Register(fake); err != nil {
		t.Fatal(err)
	}
	mgr := engine.NewManager(reg)
	res := mgr.Reconcile(context.Background(),
		[]engine.EngineSpec{{ID: "fake", Enabled: true}},
		[]engine.TunnelSpec{{ID: "t1", TopologyID: "topo", LocalServer: "iran", RemoteServer: "germany",
			Engine: "fake", Enabled: true, Params: json.RawMessage(`{}`)}})
	if len(res.Errors) > 0 {
		t.Fatalf("manager reconcile: %v", res.Errors)
	}
	bal := newForwardBalancer(mgr, reg)
	var scripts []string
	old := nftApplyScript
	nftApplyScript = func(s string) error { scripts = append(scripts, s); return nil }
	t.Cleanup(func() { nftApplyScript = old })
	return bal, &scripts
}

func TestBalancerHostileStaticTargetsRefused(t *testing.T) {
	bal, scripts := balHostileFixture(t, "10.189.0.9")
	hostile := []string{
		"10.189.0.9; flush ruleset", "10.189.0.9 } table ip evil {", "$(touch /tmp/pwn)",
		"10.189.0.9\nflush ruleset", "evil.example", "10.189.0.9 comment \"x\"",
		"10.189.0.9-10.189.0.10", "2001:db8::1", "[2001:db8::1]:15901",
	}
	for i, target := range hostile {
		doc := protocol.DesiredV2{
			Revision: "1",
			Forwards: []protocol.ForwardRule{{ID: "f1", ListenPort: 15000 + i, Proto: "tcp", Target: target, TargetPort: 15901}},
		}
		bal.Reconcile(&doc)
		rep := bal.tick()
		bal.Stop()
		for _, s := range *scripts {
			for _, bad := range []string{"flush", "evil", "touch", "comment", "ruleset", "example"} {
				if strings.Contains(s, bad) {
					t.Fatalf("hostile target %q leaked into nft script:\n%s", target, s)
				}
			}
			if strings.Contains(s, "dport "+strconv.Itoa(15000+i)) {
				t.Fatalf("refused forward %q still rendered a dport rule:\n%s", target, s)
			}
		}
		if len(rep.Errors) == 0 {
			t.Fatalf("target %q must be refused with an error", target)
		}
	}
}

func TestBalancerHostileDriverForwardTargetSkipped(t *testing.T) {
	balDoc := func() *protocol.DesiredV2 {
		return &protocol.DesiredV2{
			Revision:     "1",
			TargetGroups: []protocol.TargetGroup{{ID: "g1", TopologyID: "topo"}},
			Forwards:     []protocol.ForwardRule{{ID: "f1", ListenPort: 15900, Proto: "tcp", TargetGroup: "g1"}},
			Balancing:    &protocol.BalancingPolicy{HealthCheck: protocol.HealthCheckParams{IntervalS: 1, Probe: "engine"}},
		}
	}
	// The tunnel's forward address comes from engine_params (panel): a
	// hostile value must be skipped per-target, never rendered.
	for _, hostile := range []string{"10.189.0.9; flush ruleset", "evil.example", "$(id)"} {
		bal, scripts := balHostileFixture(t, hostile)
		bal.Reconcile(balDoc())
		rep := bal.tick()
		bal.Stop()
		for _, s := range *scripts {
			if strings.Contains(s, "flush") || strings.Contains(s, "evil") || strings.Contains(s, "$(id)") {
				t.Fatalf("hostile driver forward address %q leaked into nft script:\n%s", hostile, s)
			}
		}
		saw := false
		for _, tg := range rep.Targets {
			if tg.Tunnel == "t1" && tg.Reason == "invalid-target" {
				saw = true
			}
		}
		if !saw {
			t.Fatalf("hostile driver address %q must surface as invalid-target (diag %+v)", hostile, rep.Targets)
		}
	}

	// Regression: a legit IPv4 forward address still renders.
	bal, scripts := balHostileFixture(t, "10.189.0.9")
	bal.Reconcile(balDoc())
	bal.tick()
	bal.Stop()
	rendered := false
	for _, s := range *scripts {
		if strings.Contains(s, "10.189.0.9") {
			rendered = true
		}
	}
	if !rendered {
		t.Fatalf("legit IP target must render; scripts:\n%s", strings.Join(*scripts, "\n---\n"))
	}
}

// TestRenderForwardChainRefusesNonIPDirectCall: the renderer's own
// defense-in-depth for any caller that bypasses the balancer's tick.
func TestRenderForwardChainRefusesNonIPDirectCall(t *testing.T) {
	r := forwardRender{ID: "f1", ListenPort: 15900, Proto: "tcp", TargetPort: 15901,
		Targets: []balTarget{
			{TunnelID: "good", IP: "10.189.0.2", Port: 15901, Weight: 1},
			{TunnelID: "evil", IP: "10.189.0.2; flush ruleset", Port: 15901, Weight: 1},
		}}
	script := renderForwardChain("tcp", r)
	if strings.Contains(script, "flush") {
		t.Fatalf("hostile target leaked into the rendered chain:\n%s", script)
	}
	if !strings.Contains(script, "0-0 : 10.189.0.2") {
		t.Fatalf("the legit target must survive:\n%s", script)
	}
	r.Targets = []balTarget{{TunnelID: "evil", IP: "$(id)", Port: 15901, Weight: 1}}
	script = renderForwardChain("tcp", r)
	if strings.Contains(script, "$(id)") || strings.Contains(script, "dnat") {
		t.Fatalf("all-hostile rule must render the fail-fast pass-through:\n%s", script)
	}
}

// ---- 3. command allowlist + confirm ------------------------------------

func TestHostileCommandsRefusedBeforeExecution(t *testing.T) {
	var calls int
	oldRunner := runner
	runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls++
		return nil, nil
	}
	t.Cleanup(func() { runner = oldRunner })

	run := func(op string, params map[string]string) agentCommandResult {
		return agentRunCommand(agentCommand{ID: "h", Op: op, Params: params})
	}

	// 3a. Outside the allowlist: refused with ZERO host commands. This is
	// the whole agent-side exec story: there is no generic exec surface.
	for _, op := range []string{
		"shell", "exec", "diag.sh", "matrix.exec", "hardening.applyx",
		"firewall.apply ", "port.check2", "agent.update ", "carrier.set",
		"matrix.restart;rm", "NETOPT.APPLY", "netopt.apply extra",
	} {
		res := run(op, map[string]string{"confirm": "yes"})
		if res.OK || res.Error != "operation not allowed" {
			t.Fatalf("op %q: want refused, got %+v", op, res)
		}
	}
	if calls != 0 {
		t.Fatalf("refused ops must never execute (calls=%d)", calls)
	}

	// 3b. Mutating ops WITHOUT confirm=yes: refused before the handler.
	for _, op := range []string{"firewall.apply", "firewall.teardown", "netopt.apply",
		"netopt.rollback", "netopt.revert", "hardening.apply", "hardening.rollback"} {
		res := run(op, nil)
		if res.OK || !strings.Contains(res.Error, "confirm=yes") {
			t.Fatalf("op %q without confirm: want confirm error, got %+v", op, res)
		}
	}
	if calls != 0 {
		t.Fatalf("unconfirmed mutations must never execute (calls=%d)", calls)
	}

	// 3c. Confirmed but hostile payload: the handler's own validation
	// refuses; no host command runs.
	hostilePayloads := []string{
		`{"owner":"tunnel:at_x; rm -rf /","add":[{"port":22,"proto":"tcp"}]}`,
		`{"owner":"admin:$(id)","add":[{"port":22,"proto":"tcp"}]}`,
		`{"owner":"tunnel:ok","add":[{"port":0,"proto":"tcp"}]}`,
		`{"owner":"tunnel:ok","add":[{"port":22,"proto":"udp; rm"}]}`,
		`not json at all`,
	}
	for _, payload := range hostilePayloads {
		res := run("firewall.apply", map[string]string{"confirm": "yes", "payload": payload})
		if res.OK {
			t.Fatalf("firewall.apply payload %q must fail", payload)
		}
	}
	if calls != 0 {
		t.Fatalf("hostile payloads must never execute (calls=%d)", calls)
	}

	// 3d. netopt.profile.*: allowlisted but with NO agent handler — the
	// confirm gate still applies first, then the unknown-op error. Nothing
	// may execute either way.
	res := run("netopt.profile.apply", nil)
	if res.OK || !strings.Contains(res.Error, "confirm=yes") {
		t.Fatalf("netopt.profile.apply without confirm: got %+v", res)
	}
	res = run("netopt.profile.apply", map[string]string{"confirm": "yes"})
	if res.OK || !strings.Contains(res.Error, "unknown typed operation") {
		t.Fatalf("netopt.profile.apply with confirm: want unknown-op, got %+v", res)
	}
	if calls != 0 {
		t.Fatalf("netopt.profile.* must never execute (calls=%d)", calls)
	}

	// 3e. agent.update with a hostile request: validated BEFORE the
	// background runner starts; nothing downloads. (A cross-origin URL
	// that PASSES the request shape is refused later at the DOWNLOAD by
	// the same-origin rule — asserted in
	// TestHostileUpdateRequestAndArtifactVerify.)
	for _, tc := range []struct{ version, url, sha string }{
		{"v1; rm -rf /", "https://panel.example/linux-amd64/agent-v1", strings.Repeat("ab", 32)},
		{"v1", "http://panel.example/linux-amd64/agent-v1", strings.Repeat("ab", 32)},
		{"v1", "https://panel.example/linux-amd64/agent", "zz-not-hex"},
		// The arch token in the QUERY string does not satisfy the gate.
		{"v1", "https://panel.example/agent?arch=linux-amd64", strings.Repeat("ab", 32)},
	} {
		res := run("agent.update", map[string]string{
			"version": tc.version, "url": tc.url, "sha256": tc.sha, "signature": "AAAA"})
		if res.OK {
			t.Fatalf("agent.update %v must be refused", tc)
		}
	}
	if calls != 0 {
		t.Fatalf("hostile updates must never execute (calls=%d)", calls)
	}
}

// ---- 4. agent.update ----------------------------------------------------

func TestHostileUpdateRequestAndArtifactVerify(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	valid := agentUpdateRequest{
		Version: "v1.2.3", URL: "https://panel.example/updates/agent-linux-amd64-v1.2.3",
		SHA256Hex: sha, Signature: "AAAA",
	}
	if err := agentUpdateValidateRequest(valid, false); err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	bad := []agentUpdateRequest{
		{Version: "v1.2.3", URL: "http://panel.example/linux-amd64/x", SHA256Hex: sha},
		{Version: "not v", URL: "https://panel.example/linux-amd64/x", SHA256Hex: sha},
		{Version: "v" + strings.Repeat("1", 65), URL: "https://panel.example/linux-amd64/x", SHA256Hex: sha}, // 66 chars > cap
		{Version: "v1.2.3", URL: "https://panel.example/agent", SHA256Hex: sha},                              // no arch on PATH
		{Version: "v1.2.3", URL: "https://panel.example/linux-amd64/x", SHA256Hex: "short"},
	}
	for i, req := range bad {
		if err := agentUpdateValidateRequest(req, false); err == nil {
			t.Fatalf("bad update request %d (%+v) must fail", i, req)
		}
	}

	// Same-origin rule: the enrollment credential rides only the enrolled
	// controller origin, and a hostile URL cannot smuggle its host past it.
	ident := agentIdentity{Server: "https://panel.example:7443", BasePath: "panel"}
	for _, u := range []string{
		"https://panel.example:7443/panel/api/agent/artifact/x",
		"https://PANEL.EXAMPLE:7443/panel/api/agent/artifact/x", // host match is case-insensitive
	} {
		if !agentSameOrigin(ident.Server, u) {
			t.Fatalf("same-origin must accept %q", u)
		}
	}
	for _, u := range []string{
		"https://evil.example/panel/api/agent/artifact/x",
		"https://panel.example:7443.evil.example/x",
		"https://panel.example@evil.example/x", // userinfo trick: host is evil.example
		"https://panel.example:7443:8443/x",
		"http://panel.example:7443/x", // scheme change
		"", "not a url",
	} {
		if agentSameOrigin(ident.Server, u) {
			t.Fatalf("same-origin must refuse %q", u)
		}
	}
	if _, err := agentUpdateDownload("https://evil.example/x", ident); err == nil ||
		!strings.Contains(err.Error(), "not on the controller origin") {
		t.Fatalf("cross-origin download must be refused, got %v", err)
	}

	// Artifact verification without a pinned key fails closed. The check
	// order runs sha-mismatch BEFORE the key check, so the fixture's
	// sha256 must match the artifact to actually reach the key gate.
	oldKey := agentUpdatePubKeyPEM
	t.Cleanup(func() { agentUpdatePubKeyPEM = oldKey })
	agentUpdatePubKeyPEM = ""
	art := []byte("artifact-bytes")
	sum := sha256.Sum256(art)
	req := valid
	req.SHA256Hex = hex.EncodeToString(sum[:])
	req.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64)) // well-formed, unverified
	if err := agentUpdateVerifyArtifact(art, req); err == nil ||
		!strings.Contains(err.Error(), "signature verification unavailable") {
		t.Fatalf("no pinned key must fail closed, got %v", err)
	}
	// And with a pinned key, a bogus signature is refused.
	agentUpdatePubKeyPEM = updateTestPubKeyPEM()
	if err := agentUpdateVerifyArtifact(art, req); err == nil ||
		!strings.Contains(err.Error(), "signature verification FAILED") {
		t.Fatalf("bogus signature must fail verification, got %v", err)
	}
}

// updateTestPubKeyPEM builds a throwaway ed25519 public key in PEM SPKI
// form (never the release key).
func updateTestPubKeyPEM() string {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// ---- 5. carrier fou:/wss: remainders ------------------------------------

func TestHostileCarrierRemaindersRefused(t *testing.T) {
	// The remainders ride as ONE argv element into the installed quantum
	// script; only decimal ports may pass (phase-21 F5 fix).
	for _, bad := range []string{
		"fou:; rm -rf /", "fou:$(touch /tmp/pwn)", "fou:443\nrm x", "fou:443; rm x",
		"fou:0", "fou:70000", "fou: 443", "fou:abc", "fou:", "fou:-1",
		"fou:+443", "wss:abc", "wss:", "wss:0", "wss:99999", "wss:; id",
	} {
		if err := carrierApplicable(bad); err == nil {
			t.Fatalf("carrier %q must fail", bad)
		}
	}
	for _, good := range []string{"direct", "wss", "fou:443", "fou:55555", "wss:8443", "6to4", "4in6", "frp:tcp", "frp:kcp"} {
		if err := carrierApplicable(good); err != nil {
			t.Fatalf("carrier %q must apply: %v", good, err)
		}
	}
	// applyCarrierMode refuses BEFORE the script would run: point the
	// script seam at a nonexistent path so a leak would surface as a
	// "script not found" error, never an execution.
	t.Setenv("QUANTUM_SCRIPT", "/nonexistent/quantum.sh")
	for _, bad := range []string{"fou:; rm -rf /", "wss:$(id)", "fou:0", "backhaul:0.7.2"} {
		_, err := applyCarrierMode(bad)
		if err == nil {
			t.Fatalf("applyCarrierMode(%q) must fail", bad)
		}
		if strings.Contains(err.Error(), "script not found") {
			t.Fatalf("applyCarrierMode(%q) must be refused BEFORE the script lookup", bad)
		}
	}
	// A valid target gets past validation (then hits the missing script —
	// the documented no-script behavior).
	if _, err := applyCarrierMode("fou:443"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("valid fou:443 must reach the script seam, got %v", err)
	}
}

// ---- 6. panel WS frame cap ----------------------------------------------

func TestPanelWSFrameReadLimit(t *testing.T) {
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != agentWSPath {
			http.NotFound(w, r)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		// One frame beyond the cap: the client must refuse to buffer it.
		_ = c.WriteMessage(websocket.TextMessage, make([]byte, agentPanelReadLimit+1))
	}))
	t.Cleanup(srv.Close)

	ident := agentIdentity{ID: "agt_rl", Key: "k", Server: srv.URL, BasePath: ""}
	ws, err := dialAgentWS(ident)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()
	if _, _, err := ws.ReadMessage(); err == nil || !strings.Contains(err.Error(), "read limit") {
		t.Fatalf("oversized panel frame must hit the read limit, got %v", err)
	}
}

// ---- 7. malformed DesiredV2 ---------------------------------------------

func TestHostileDesiredV2FailsSafe(t *testing.T) {
	// Wrong top-level types never decode: the session answers malformed
	// and the document is not applied. (An opaque hardening OBJECT does
	// decode — json.RawMessage — and is validated by the hardening
	// module's own gate: TestHostileHardeningProfilesRefused.)
	for _, raw := range []string{
		`{"revision":"1","tunnels":"not-a-list"}`,
		`{"revision":"1","engines":{"id":"x"}}`,
		`{"revision":"1","forwards":[{"id":42}]}`,
		`{"revision":{}}`,
		`not json`,
	} {
		var d protocol.DesiredV2
		if json.Unmarshal([]byte(raw), &d) == nil {
			t.Fatalf("hostile doc %q must not decode", raw)
		}
	}

	// Per-tunnel validation: empty id/engine and non-JSON engine_params
	// are refused before the Manager sees them. (An engine_params ARRAY
	// is valid JSON at this layer and is refused by the driver's own
	// Validate — family 1 covers that.)
	for _, tun := range []protocol.TunnelSpec{
		{ID: "  ", Engine: "frp"},
		{ID: "t1", Engine: ""},
		{ID: "t1", Engine: "frp", EngineParams: json.RawMessage(`{invalid`)},
	} {
		if err := validateTunnelSpec(tun); err == nil {
			t.Fatalf("tunnel %+v must fail validation", tun)
		}
	}
	if err := validateTunnelSpec(protocol.TunnelSpec{ID: "t1", Engine: "frp", EngineParams: json.RawMessage(`{"a":1}`)}); err != nil {
		t.Fatalf("valid tunnel must pass: %v", err)
	}

	// Hostile SELF stamps (R6): a whitespace Self.Name trims to "" at the
	// apply layer, and the role resolution FAILS CLOSED on an empty self
	// (isolated configDir = no enrollment identity → error, never a
	// guessed role).
	withTmpConfig(t)
	role, rerr := frpResolveRole(frpTestParams(), "  ")
	if rerr == nil || role != "" {
		t.Fatalf("blank self name must fail role resolution closed, got %q err=%v", role, rerr)
	}
}

// ---- 8. hardening profiles ----------------------------------------------

func TestHostileHardeningProfilesRefused(t *testing.T) {
	// Dispatch("plan") runs Detect (host commands through hardening.Run):
	// stub the seam fail-closed for the test; hostile profiles must be
	// refused by Validate BEFORE any plan item could run anyway.
	oldRun := hardening.Run
	hardening.Run = func(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
		return nil, errors.New("hostile-panel test: no host commands")
	}
	t.Cleanup(func() { hardening.Run = oldRun })

	hostile := []string{
		`{"version":1,"name":"base\"; rm -rf /"}`,
		`{"version":1,"name":"base$(id)"}`,
		`{"version":1,"name":"base\nx"}`,
		`{"version":2,"name":"ok"}`, // wrong profile version
		`{"version":1,"name":"ok","firewall":{"allows":[{"port":0,"proto":"tcp","owner":"x:y"}]}}`,
		`{"version":1,"name":"ok","firewall":{"allows":[{"port":22,"proto":"tcp; rm","owner":"x:y"}]}}`,
		`{"version":1,"name":"ok","firewall":{"allows":[{"port":22,"proto":"tcp","owner":"x y"}]}}`,
		`{"version":1,"name":"ok","firewall":{"allows":[{"port":22,"proto":"tcp","owner":"x:y","from":"10.0.0.0/8; rm"}]}}`,
		`{"version":1,"name":"ok","sysctl":[{"key":"net.ipv4.conf.all.rp_filter","value":"1\nnet.ipv4.ip_forward=1"}]}`,
		`{"version":1,"name":"ok","sysctl":[{"key":"1; rm -rf","value":"1"}]}`,
		`{"version":1,"name":"ok","ssh":{"port":70000}}`,
		`{"version":1,"name":"ok","ssh":{"permit_root":"no; rm"}}`,
		`not json`,
	}
	for _, prof := range hostile {
		res := hardening.Dispatch(context.Background(), hardening.Request{Op: "plan", Profile: prof})
		if res.Ok {
			t.Fatalf("hostile hardening profile must be refused: %s", prof)
		}
		if res.Plan != nil {
			t.Fatalf("hostile profile must never produce a plan: %s", prof)
		}
	}
}

// ---- 9. matrix settings (v1 desired path) -------------------------------

func TestHostileMatrixSettingsRefused(t *testing.T) {
	for _, tc := range []struct {
		family string
		addr   string
		port   int
		ports  []int
	}{
		{"ipv4", "10.0.0.1; rm -rf", 65000, []int{80}},
		{"ipv4", "$(id)", 65000, []int{80}},
		{"ipv4", "not-an-ip", 65000, []int{80}},
		{"ipv4\n", "10.0.0.1", 65000, []int{80}},
		{"ipv6", "10.0.0.1", 65000, []int{80}}, // family/address mismatch
		{"ipv4", "127.0.0.1", 65000, []int{80}},
		{"ipv4", "0.0.0.0", 65000, []int{80}},
		{"ipv4", "10.0.0.1", 22, []int{80}}, // port below 1024
		{"ipv4", "10.0.0.1", 70000, []int{80}},
		{"ipv4", "10.0.0.1", 65000, nil},
		{"ipv4", "10.0.0.1", 65000, []int{0}},
		{"ipv4", "10.0.0.1", 65000, []int{-1}},
		{"ipv4", "10.0.0.1", 65000, []int{80, 80}}, // duplicate
	} {
		if err := validateMatrixSettings(tc.family, tc.addr, tc.port, tc.ports); err == nil {
			t.Fatalf("matrix settings %+v must fail", tc)
		}
	}
	if err := validateMatrixSettings("ipv4", "10.0.0.1", 65000, []int{80, 81}); err != nil {
		t.Fatalf("valid settings refused: %v", err)
	}
}
