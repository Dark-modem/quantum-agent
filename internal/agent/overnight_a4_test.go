package agent

// Hermetic tests for OVERNIGHT-A4: the hysteria2 feature variants (gecko
// obfs + udphop port hopping). Upstream evidence (hysteria v2.14.0 source):
//   - obfs: client.go/server.go serverConfigObfs{Type,Salamander,Gecko} +
//     extras/obfs/gecko.go WrapPacketConnGecko (password required,
//     min/max 0 = defaults 512/1200, bound 2048, min<=max, salamander
//     wrapped inside with the SAME password).
//   - udphop: client.go isPortHoppingPort ('-' or ',') +
//     fillServerAddr → udphop.ResolveUDPHopAddr; server.go
//     resolveServerListenAddr parses the port union and the binary
//     SELF-INSTALLS firewall.SetupUDPPortRedirect; transport.udp.
//     hopInterval via HopIntervalConfig.normalized (>=5s, default 30s).

import (
	"strings"
	"testing"
)

func TestHysteriaGeckoObfs(t *testing.T) {
	p := hysteriaTestParams()
	p.ObfsType = "gecko"
	p.ObfsPassword = "gecko-pass-01"
	p.ObfsMinPkt, p.ObfsMaxPkt = 300, 1500
	if err := hysteriaValidateParams(p); err != nil {
		t.Fatalf("gecko params rejected: %v", err)
	}
	srv := hysteriaRenderConfig("server", p)
	if !strings.Contains(srv, "type: gecko") ||
		!strings.Contains(srv, `password: "gecko-pass-01"`) ||
		!strings.Contains(srv, "minPacketSize: 300") || !strings.Contains(srv, "maxPacketSize: 1500") {
		t.Fatalf("gecko server render wrong:\n%s", srv)
	}
	cli := hysteriaRenderConfig("client", p)
	if !strings.Contains(cli, "type: gecko") || !strings.Contains(cli, "minPacketSize: 300") {
		t.Fatalf("gecko client render wrong:\n%s", cli)
	}
	// explicit salamander renders the A2 shape (both ends).
	p2 := hysteriaTestParams()
	p2.ObfsType = "salamander"
	p2.ObfsPassword = "sal-pass-01"
	if err := hysteriaValidateParams(p2); err != nil {
		t.Fatalf("salamander params rejected: %v", err)
	}
	if s := hysteriaRenderConfig("server", p2); !strings.Contains(s, "type: salamander") ||
		!strings.Contains(s, `password: "sal-pass-01"`) {
		t.Fatalf("explicit salamander render wrong:\n%s", s)
	}
	// backward compat: "" + obfs_password keeps the A2 salamander shape.
	p3 := hysteriaTestParams()
	p3.ObfsPassword = "legacy-pass-01"
	if err := hysteriaValidateParams(p3); err != nil {
		t.Fatalf("legacy shape rejected: %v", err)
	}
	if s := hysteriaRenderConfig("client", p3); !strings.Contains(s, "type: salamander") {
		t.Fatalf("legacy shape must render salamander:\n%s", s)
	}
	// hostile: junk type, gecko knobs on salamander, bad bounds, dead type.
	for name, mutate := range map[string]func(*hysteriaParams){
		"bad type":   func(p *hysteriaParams) { p.ObfsType = "rotor" },
		"pkt on sal": func(p *hysteriaParams) { p.ObfsType = "salamander"; p.ObfsMinPkt = 300; p.ObfsMaxPkt = 500 },
		"min>max": func(p *hysteriaParams) {
			p.ObfsType = "gecko"
			p.ObfsPassword = "p"
			p.ObfsMinPkt = 1500
			p.ObfsMaxPkt = 300
		},
		"over buffer": func(p *hysteriaParams) {
			p.ObfsType = "gecko"
			p.ObfsPassword = "p"
			p.ObfsMinPkt = 1
			p.ObfsMaxPkt = 4096
		},
		"type no pwd": func(p *hysteriaParams) { p.ObfsType = "gecko"; p.ObfsPassword = "" },
	} {
		bad := hysteriaTestParams()
		mutate(&bad)
		if err := hysteriaValidateParams(bad); err == nil {
			t.Fatalf("hysteria %s accepted", name)
		}
	}
}

func TestHysteriaUdphop(t *testing.T) {
	// range server_addr: the server listen rides the union verbatim (the
	// binary self-installs the UDP redirect); the client dials the range
	// and hops with transport.udp.hopInterval.
	p := hysteriaTestParams()
	p.ServerAddr = "198.51.100.9:20000-50000"
	p.HopInterval = "30s"
	if err := hysteriaValidateParams(p); err != nil {
		t.Fatalf("udphop params rejected: %v", err)
	}
	srv := hysteriaRenderConfig("server", p)
	if !strings.Contains(srv, `listen: ":20000-50000"`) {
		t.Fatalf("udphop server listen wrong:\n%s", srv)
	}
	cli := hysteriaRenderConfig("client", p)
	if !strings.Contains(cli, `server: "198.51.100.9:20000-50000"`) ||
		!strings.Contains(cli, `hopInterval: "30s"`) {
		t.Fatalf("udphop client render wrong:\n%s", cli)
	}
	// comma-list hop ports are valid upstream too.
	p2 := hysteriaTestParams()
	p2.ServerAddr = "198.51.100.9:443,8443"
	if err := hysteriaValidateParams(p2); err != nil {
		t.Fatalf("comma hop range rejected: %v", err)
	}
	// single-port params keep the historical shape (no transport block).
	p3 := hysteriaTestParams()
	if err := hysteriaValidateParams(p3); err != nil {
		t.Fatalf("plain params rejected: %v", err)
	}
	if s := hysteriaRenderConfig("client", p3); strings.Contains(s, "hopInterval") {
		t.Fatalf("plain shape must not render transport.udp:\n%s", s)
	}
	// hostile: reversed ranges, junk elements, bad durations, 5s floor.
	for name, mutate := range map[string]func(*hysteriaParams){
		"reversed range": func(p *hysteriaParams) { p.ServerAddr = "198.51.100.9:50000-20000" },
		"junk element":   func(p *hysteriaParams) { p.ServerAddr = "198.51.100.9:20000-abcd" },
		"port 0":         func(p *hysteriaParams) { p.ServerAddr = "198.51.100.9:0-50000" },
		"short interval": func(p *hysteriaParams) { p.HopInterval = "4s" },
		"bad duration":   func(p *hysteriaParams) { p.HopInterval = "soon" },
		"interval 1h+":   func(p *hysteriaParams) { p.HopInterval = "2h" },
		"interval chars": func(p *hysteriaParams) { p.HopInterval = `30"; rm` },
	} {
		bad := hysteriaTestParams()
		mutate(&bad)
		if err := hysteriaValidateParams(bad); err == nil {
			t.Fatalf("hysteria %s accepted", name)
		}
	}
	// the 5s floor passes at exactly 5s (upstream bound).
	p4 := hysteriaTestParams()
	p4.HopInterval = "5s"
	if err := hysteriaValidateParams(p4); err != nil {
		t.Fatalf("5s interval rejected (upstream lower bound): %v", err)
	}
}
