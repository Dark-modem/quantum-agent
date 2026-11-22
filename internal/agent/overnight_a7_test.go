package agent

// Hermetic tests for OVERNIGHT-A7: the EasyTier mesh driver. Upstream
// evidence: the vendored v2.7.1 binary's `easytier-core --help` (the
// authoritative flag surface — network-name/network-secret/-i/--dhcp/
// -p/--peers/-l/--listeners/-n/--proxy-networks/--mtu) + the OVERNIGHT-D2
// wiring spec.

import (
	"context"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-agent/internal/infra"
)

func etTestParams() easytierParams {
	return easytierParams{
		ServerSide: "germany", Version: "2.7.1",
		Artifact:  "easytier-2.7.1-linux-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("aa", 32), SHA256Arm: strings.Repeat("bb", 32),
		SigAmd: strings.Repeat("QQ==", 22)[:88], SigArm: strings.Repeat("QQ==", 22)[:88],
		NetworkName: "quantum-mesh", NetworkSecret: "et-secret-01",
		RemoteAddr: "198.51.100.9", ListenerPort: 11010,
		NodeIPv4: "10.126.126.1/24",
	}
}

func TestEasytierArgsBothEnds(t *testing.T) {
	p := etTestParams()
	if err := easytierValidateParams(p); err != nil {
		t.Fatalf("params rejected: %v", err)
	}
	srv := easytierArgs("server", p)
	s := strings.Join(srv, " ")
	// the exact v2.7.1 flag shapes
	if !strings.Contains(s, "--network-name quantum-mesh") ||
		!strings.Contains(s, "--network-secret et-secret-01") ||
		!strings.Contains(s, "-l tcp://0.0.0.0:11010") ||
		!strings.Contains(s, "-i 10.126.126.1/24") {
		t.Fatalf("easytier server args wrong: %s", s)
	}
	cli := easytierArgs("client", p)
	c := strings.Join(cli, " ")
	if !strings.Contains(c, "-p tcp://198.51.100.9:11010") ||
		!strings.Contains(c, "-i 10.126.126.1/24") {
		t.Fatalf("easytier client args wrong: %s", c)
	}
	// dhcp variant: --dhcp with the initial pool CIDR.
	p2 := etTestParams()
	p2.NodeIPv4 = ""
	p2.Dhcp = true
	p2.DhcpCIDR = "10.66.0.0/24"
	if err := easytierValidateParams(p2); err != nil {
		t.Fatalf("dhcp params rejected: %v", err)
	}
	if !strings.Contains(strings.Join(easytierArgs("client", p2), " "), "--dhcp 10.66.0.0/24") {
		t.Fatalf("dhcp args wrong: %v", easytierArgs("client", p2))
	}
	// forward-only: neither dhcp nor -i → NO TUN flag rendered.
	p3 := etTestParams()
	p3.NodeIPv4 = ""
	if err := easytierValidateParams(p3); err != nil {
		t.Fatalf("forward-only params rejected: %v", err)
	}
	if strings.Contains(strings.Join(easytierArgs("client", p3), " "), "-i ") {
		t.Fatalf("forward-only node must not render -i: %v", easytierArgs("client", p3))
	}
	// proxy-networks + mtu + the udp carrier.
	p4 := etTestParams()
	p4.Carrier = "udp"
	p4.ProxyNetworks = "192.168.1.0/24,192.168.2.0/24"
	p4.Mtu = 1380
	if err := easytierValidateParams(p4); err != nil {
		t.Fatalf("proxy/mtu params rejected: %v", err)
	}
	a4 := strings.Join(easytierArgs("server", p4), " ")
	if !strings.Contains(a4, "-l udp://0.0.0.0:11010") ||
		!strings.Contains(a4, "--proxy-networks 192.168.1.0/24,192.168.2.0/24") ||
		!strings.Contains(a4, "--mtu 1380") {
		t.Fatalf("proxy/mtu/udp args wrong: %s", a4)
	}
	// the udp-carrier accounting mapping (wg/quic/udp → udp; the rest tcp).
	if !easytierUDPProto("udp") || !easytierUDPProto("wg") || !easytierUDPProto("quic") ||
		easytierUDPProto("tcp") || easytierUDPProto("ws") {
		t.Fatalf("easytierUDPProto wrong")
	}
}

func TestEasytierHostileMatrix(t *testing.T) {
	for name, mutate := range map[string]func(*easytierParams){
		"open mesh":        func(p *easytierParams) { p.NetworkSecret = "" },
		"short secret":     func(p *easytierParams) { p.NetworkSecret = "abc" },
		"name quote":       func(p *easytierParams) { p.NetworkName = "mesh\"bad" },
		"unknown carrier":  func(p *easytierParams) { p.Carrier = "grpc" },
		"port 0":           func(p *easytierParams) { p.ListenerPort = 0 },
		"remote host:port": func(p *easytierParams) { p.RemoteAddr = "1.2.3.4:11010" },
		"dhcp and static":  func(p *easytierParams) { p.Dhcp = true; p.NodeIPv4 = "10.126.126.1/24" },
		"dhcp cidr junk":   func(p *easytierParams) { p.Dhcp = true; p.DhcpCIDR = "not-a-cidr" },
		"node ip junk":     func(p *easytierParams) { p.NodeIPv4 = "10.126.126.1" },
		"proxy junk":       func(p *easytierParams) { p.ProxyNetworks = "192.168.1.0/not-cidr" },
		"proxy space":      func(p *easytierParams) { p.ProxyNetworks = "192.168.1.0/24 192.168.2.0/24" },
		"mtu tiny":         func(p *easytierParams) { p.Mtu = 10 },
	} {
		bad := etTestParams()
		mutate(&bad)
		if err := easytierValidateParams(bad); err == nil {
			t.Fatalf("easytier %s accepted", name)
		}
	}
	// the TUN presence gate: a self-addressing node without /dev/net/tun
	// fails closed (the seam points at a nonexistent path in the test).
	orig := easytierTunAvailable
	easytierTunAvailable = func() bool { return false }
	defer func() { easytierTunAvailable = orig }()
	d := NewEasytierDriver()
	p := etTestParams()
	inst := engine.Instance{TunnelID: "et-tid", LocalServer: "germany", RemoteServer: "iran", Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), inst); err == nil ||
		!strings.Contains(err.Error(), "/dev/net/tun") {
		t.Fatalf("tun gate did not fail closed: %v", err)
	}
}
