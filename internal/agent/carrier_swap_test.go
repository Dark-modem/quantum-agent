package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseCarrierChoice, the TestSwap* suite and TestForeignSwapAcceptsThenSwitches
// went with the legacy peer-swap handlers in §6.A3 (their entry points are
// deleted dead code).
func TestPeerCarrierFromRecord(t *testing.T) {
	cases := []struct {
		p    peerRecord
		want string
	}{
		{peerRecord{FrpsSvc: "frps-2"}, "frp:tcp"},
		{peerRecord{FrpsSvc: "frps-2", FRPTransport: "quic"}, "frp:quic"},
		{peerRecord{FrpsSvc: "backhaul-server-3", NoGre: true, Transport: "wssmux"}, "backhaul:wssmux"},
		{peerRecord{FrpsSvc: "backhaul-server-3"}, "gre-backhaul:tcpmux"},
		{peerRecord{Engine: "backhaul", Transport: "bogus"}, "backhaul:tcpmux"},
	}
	for _, c := range cases {
		if got := peerCarrier(c.p).ID(); got != c.want {
			t.Errorf("peerCarrier(%+v) = %s, want %s", c.p, got, c.want)
		}
	}
}

// swapLab: a hub with one FRP peer (id 2) and its files on disk.
func swapLab(t *testing.T) peerRecord {
	t.Helper()
	engineLab(t, []string{"frps", "frpc", "backhaul"}, []string{"gre-t2"})
	oldV := backhaulCoreVersion
	backhaulCoreVersion = func() string { return "v0.7.2" }
	t.Cleanup(func() { backhaulCoreVersion = oldV })
	for _, d := range []string{frpDir, backhaulDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p := peerRecord{ID: 2, Name: "nl", LocalPub: "5.5.5.5", RemotePub: "92.2.2.2", FrpPort: 7001,
		LocalGre: "10.80.2.1", PeerGre: "10.80.2.2", Ports: []int{2083, 8443}, Token: "tok-2",
		GreIf: "gre-t2", FrpsSvc: "frps-2"}
	writePeersJSON(t, p)
	mustWrite(t, filepath.Join(frpDir, "frps-2.toml"), "bindPort = 7001\n")
	mustWrite(t, filepath.Join(engineUnitDir, "frps-2.service"), "[Service]\nExecStart=/usr/local/bin/frps -c frps-2.toml\n")
	t.Cleanup(func() {
		for _, f := range []string{peersFile(), filepath.Join(frpDir, "frps-2.toml"), filepath.Join(backhaulDir, "server-2.toml"), swapStatePath(), tunnelLinksPath()} {
			_ = os.Remove(f)
		}
	})
	return p
}

func writePeersJSON(t *testing.T, peers ...peerRecord) {
	t.Helper()
	data, _ := json.MarshalIndent(map[string]any{"peers": peers}, "", "  ")
	mustWrite(t, peersFile(), string(data))
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestSwitchPeerCarrierFRPToBackhaul(t *testing.T) {
	p := swapLab(t)
	calls := recordSystemctl(t, "")
	if out, err := switchPeerCarrier(p, carrierChoice{Engine: "backhaul", Transport: "wssmux"}); err != nil {
		t.Fatalf("switch: %v (%s)", err, out)
	}
	conf := readFile(t, filepath.Join(backhaulDir, "server-2.toml"))
	for _, want := range []string{`bind_addr = "0.0.0.0:7001"`, `transport = "wssmux"`, `token = "tok-2"`, `"2083"`, `"8443"`} {
		if !strings.Contains(conf, want) {
			t.Errorf("server-2.toml lacks %s:\n%s", want, conf)
		}
	}
	unit := readFile(t, filepath.Join(engineUnitDir, "backhaul-server-2.service"))
	if !strings.Contains(unit, "server-2.toml") || strings.Contains(unit, "gre-t2.service") {
		t.Errorf("standalone Backhaul unit should run server-2.toml and not wait for GRE:\n%s", unit)
	}
	for _, gone := range []string{filepath.Join(frpDir, "frps-2.toml"), filepath.Join(engineUnitDir, "frps-2.service")} {
		if _, err := os.Stat(gone); err == nil {
			t.Errorf("%s should be removed after the swap", gone)
		}
	}
	got := findPeer(2)
	if got == nil || got.Engine != "backhaul" || got.Transport != "wssmux" || got.FrpsSvc != "backhaul-server-2" || !got.NoGre || got.Token != "tok-2" || got.GreIf != "gre-t2" {
		t.Errorf("peers.json not updated: %+v", got)
	}
	joined := strings.Join(*calls, "\n")
	for _, want := range []string{"stop frps-2", "restart backhaul-server-2", "disable frps-2"} {
		if !strings.Contains(joined, want) {
			t.Errorf("systemctl calls lack %q:\n%s", want, joined)
		}
	}
}

func TestSwitchPeerCarrierBackToFRPOverGRE(t *testing.T) {
	p := swapLab(t)
	recordSystemctl(t, "")
	if _, err := switchPeerCarrier(p, carrierChoice{Engine: "gre-backhaul", Transport: "tcpmux"}); err != nil {
		t.Fatal(err)
	}
	if u := readFile(t, filepath.Join(engineUnitDir, "backhaul-server-2.service")); !strings.Contains(u, "gre-t2.service") {
		t.Errorf("Backhaul over GRE must start after gre-t2:\n%s", u)
	}
	p2 := *findPeer(2)
	if _, err := switchPeerCarrier(p2, carrierChoice{Engine: "frp", Transport: "kcp"}); err != nil {
		t.Fatal(err)
	}
	conf := readFile(t, filepath.Join(frpDir, "frps-2.toml"))
	for _, want := range []string{"bindPort = 7001", "kcpBindPort = 7001", "quicBindPort = 7002", `auth.token = "tok-2"`} {
		if !strings.Contains(conf, want) {
			t.Errorf("frps-2.toml lacks %s:\n%s", want, conf)
		}
	}
	if _, err := os.Stat(filepath.Join(backhaulDir, "server-2.toml")); err == nil {
		t.Error("the Backhaul config should be gone after moving back to FRP")
	}
	got := findPeer(2)
	if got.Engine != "frp" || got.FRPTransport != "kcp" || got.FrpsSvc != "frps-2" || got.NoGre {
		t.Errorf("peers.json not updated: %+v", got)
	}
}

func TestSwitchPeerCarrierRollsBack(t *testing.T) {
	p := swapLab(t)
	recordSystemctl(t, "restart backhaul-server-2")
	before := readFile(t, peersFile())
	if _, err := switchPeerCarrier(p, carrierChoice{Engine: "backhaul", Transport: "tcpmux"}); err == nil {
		t.Fatal("a unit that does not start must fail the switch")
	}
	if readFile(t, filepath.Join(frpDir, "frps-2.toml")) != "bindPort = 7001\n" {
		t.Error("the old frps config must be put back")
	}
	if _, err := os.Stat(filepath.Join(engineUnitDir, "frps-2.service")); err != nil {
		t.Error("the old frps unit must be kept")
	}
	if _, err := os.Stat(filepath.Join(backhaulDir, "server-2.toml")); err == nil {
		t.Error("the new Backhaul config must be removed again")
	}
	if readFile(t, peersFile()) != before {
		t.Error("peers.json must not change on a failed switch")
	}
}

func TestSwitchPeerCarrierRefusesMissingBinary(t *testing.T) {
	p := swapLab(t)
	engineLab(t, []string{"frps"}, []string{"gre-t2"})
	calls := recordSystemctl(t, "")
	if _, err := switchPeerCarrier(p, carrierChoice{Engine: "backhaul", Transport: "tcpmux"}); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("want a missing-binary error, got %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("no unit may be touched: %v", *calls)
	}
}

// swapStubs replaces the network and the local switch with recorders.
func TestForeignFRPSwitchUsesTheGivenPortsAndProtocol(t *testing.T) {
	engineLab(t, []string{"frpc", "frps", "backhaul"}, []string{"backhaul-server", "backhaul-client"})
	recordSystemctl(t, "")
	_ = os.MkdirAll(frpDir, 0o755)
	t.Cleanup(func() { _ = os.Remove(filepath.Join(frpDir, "frpc.toml")) })
	_, err := switchTunnelEngineWith("frp", "quic", engineOpts{Port: 7001, Ports: []int{2083, 8443}, PeerGre: "10.80.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	conf := readFile(t, filepath.Join(frpDir, "frpc.toml"))
	for _, want := range []string{`serverAddr = "10.80.2.1"`, "serverPort = 7002", `transport.protocol = "quic"`, "remotePort = 2083", "remotePort = 8443"} {
		if !strings.Contains(conf, want) {
			t.Errorf("frpc.toml lacks %s:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "remotePort = 443\n") {
		t.Error("the default ports must not replace the given ones")
	}
}
