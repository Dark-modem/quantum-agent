package agent

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pipeDial returns a dialFn whose far end runs serve; every dial is counted and
// its address recorded.
func pipeDial(t *testing.T, serve func(c net.Conn)) (*atomic.Int32, *[]string) {
	t.Helper()
	var n atomic.Int32
	var mu sync.Mutex
	var addrs []string
	prev := dialFn
	dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		n.Add(1)
		mu.Lock()
		addrs = append(addrs, addr)
		mu.Unlock()
		if serve == nil {
			return nil, errors.New("connection refused")
		}
		a, b := net.Pipe()
		go func() { defer b.Close(); serve(b) }()
		return a, nil
	}
	t.Cleanup(func() { dialFn = prev })
	return &n, &addrs
}

func withBinaries(t *testing.T, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	oldDirs, oldExtra := engineBinDirs, backhaulExtraBins
	engineBinDirs, backhaulExtraBins = []string{dir}, nil
	t.Cleanup(func() { engineBinDirs, backhaulExtraBins = oldDirs, oldExtra })
}

func banner(c net.Conn)   { _, _ = c.Write([]byte("SSH-2.0-test\r\n")) }
func echo(c net.Conn)     { b := make([]byte, 64); n, _ := c.Read(b); _, _ = c.Write(b[:n]) }
func silent(c net.Conn)   { _, _ = io.Copy(io.Discard, c) }
func slamShut(c net.Conn) {}

func okTarget() thTarget {
	return thTarget{id: 1, name: "p1", engine: "frp", role: "peer", unit: "frps-1", svcUp: true, linked: true,
		latMs: 12.5, latKind: "tcp", ctrlPort: 7001, ports: []int{8001}, hosts: []string{"127.0.0.1"}}
}

func TestTunnelHealthVerdicts(t *testing.T) {
	withBinaries(t, "frps", "backhaul")
	cases := []struct {
		name    string
		mod     func(*thTarget)
		serve   func(net.Conn)
		verdict string
		layers  TunnelLayers
		reason  string
	}{
		{"pass banner", nil, banner, VerdictPass, TunnelLayers{layerOK, layerOK, layerOK}, "banner"},
		{"pass echo", nil, echo, VerdictPass, TunnelLayers{layerOK, layerOK, layerOK}, "data path OK on port 8001"},
		{"pass held open", nil, silent, VerdictPass, TunnelLayers{layerOK, layerOK, layerOK}, "held open"},
		{"data fail while session live", nil, slamShut, VerdictFail, TunnelLayers{layerOK, layerOK, layerFail}, "data probe on port 8001 failed"},
		{"data dial refused", nil, nil, VerdictFail, TunnelLayers{layerOK, layerOK, layerFail}, "data probe"},
		{"service down", func(x *thTarget) { x.svcUp, x.linked = false, false }, banner, VerdictFail, TunnelLayers{layerFail, layerSkipped, layerSkipped}, "frps-1 is configured but not active"},
		{"session absent, peer pings", func(x *thTarget) { x.linked, x.icmpOK = false, true }, banner, VerdictFail, TunnelLayers{layerOK, layerFail, layerSkipped}, "session expected but absent"},
		{"session absent, cached tcp probe", func(x *thTarget) { x.linked, x.probeCached = false, true }, banner, VerdictFail, TunnelLayers{layerOK, layerFail, layerSkipped}, "peer answers TCP"},
		{"nothing answers", func(x *thTarget) { x.linked = false }, nil, VerdictUnreachable, TunnelLayers{layerOK, layerUnknown, layerSkipped}, "peer not answering on any path — cannot tell engine health"},
		{"binary missing frp", func(x *thTarget) { x.unit = "frpc" }, banner, VerdictFail, TunnelLayers{layerFail, layerSkipped, layerSkipped}, "engine binary missing (frpc"},
		{"control port only", func(x *thTarget) { x.ports = nil }, banner, VerdictPass, TunnelLayers{layerOK, layerOK, layerSkipped}, "no forwarded port to probe — control port only"},
		{"control port only unreachable", func(x *thTarget) { x.ports = nil }, nil, VerdictFail, TunnelLayers{layerOK, layerOK, layerFail}, "control port only"},
		{"backhaul ok", func(x *thTarget) { x.engine, x.unit = "backhaul", "frps-2" }, echo, VerdictPass, TunnelLayers{layerOK, layerOK, layerOK}, ""},
		{"live session, no address", func(x *thTarget) { x.hosts = nil }, echo, VerdictUnreachable, TunnelLayers{layerOK, layerOK, layerUnknown}, "no address to probe"},
		{"no unit configured", func(x *thTarget) { x.svcUp, x.linked, x.unit = false, false, "" }, banner, VerdictFail, TunnelLayers{layerFail, layerSkipped, layerSkipped}, "no tunnel service configured"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pipeDial(t, c.serve)
			tg := okTarget()
			if c.mod != nil {
				c.mod(&tg)
			}
			e := checkTunnel(tg, "now")
			if e.Verdict != c.verdict || e.Layers != c.layers || !strings.Contains(e.Reason, c.reason) {
				t.Fatalf("got %s %+v %q; want %s %+v containing %q", e.Verdict, e.Layers, e.Reason, c.verdict, c.layers, c.reason)
			}
		})
	}
}

func TestTunnelHealthBackhaulBinaryMissing(t *testing.T) {
	withBinaries(t, "frps") // no backhaul
	pipeDial(t, banner)
	tg := okTarget()
	tg.engine = "gre-backhaul"
	e := checkTunnel(tg, "now")
	if e.Verdict != VerdictFail || e.Layers.Service != layerFail || !strings.Contains(e.Reason, "engine binary missing (backhaul") {
		t.Fatalf("got %s %+v %q", e.Verdict, e.Layers, e.Reason)
	}
}

// A host that connects but slams shut must not mask a healthy second host.
func TestTunnelHealthMultiHostFallback(t *testing.T) {
	withBinaries(t, "frps")
	prev := dialFn
	calls := 0
	dialFn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		calls++
		if strings.HasSuffix(addr, ":8001") && calls == 1 {
			a, b := net.Pipe()
			b.Close() // immediate close, no input
			return a, nil
		}
		a, b := net.Pipe()
		go func() { defer b.Close(); echo(b) }()
		return a, nil
	}
	defer func() { dialFn = prev }()
	tg := okTarget()
	tg.hosts = []string{"10.0.0.1", "10.0.0.2"}
	e := checkTunnel(tg, "now")
	if e.Verdict != VerdictPass {
		t.Fatalf("second host must rescue the probe: got %s %q", e.Verdict, e.Reason)
	}
	if calls != 2 {
		t.Fatalf("both hosts must be tried, got %d dials", calls)
	}
}

func TestTunnelHealthEngineDerivation(t *testing.T) {
	for _, c := range []struct {
		declared, unit string
		gre            bool
		want           string
	}{
		{"", "frps", false, "frp"}, {"", "backhaul-server", false, "backhaul"}, {"", "backhaul-client", true, "gre-backhaul"},
		{"gre-backhaul", "frps-1", false, "gre-backhaul"}, {"weird", "frps-2", false, "frp"},
	} {
		if got := thEngine(c.declared, c.unit, c.gre); got != c.want {
			t.Errorf("thEngine(%q,%q,%v)=%q want %q", c.declared, c.unit, c.gre, got, c.want)
		}
	}
}

func liveSnapshot(peers ...peerLive) *HubSnapshot {
	return &HubSnapshot{At: time.Now(), Peers: peers}
}

func peerFor(id int, svc, engine string, up, linked bool, ports ...int) peerLive {
	return peerLive{peerRecord: peerRecord{ID: id, Name: "p" + string(rune('0'+id)), FrpsSvc: svc, Engine: engine, FrpPort: 7000 + id, RemotePub: "198.51.100." + string(rune('0'+id)), Ports: ports},
		FrpUp: up, Linked: linked, LatencyMs: -1}
}

// The engine-switch hook must be fire-and-forget and gated by the auto-run flag.
func TestTunnelHealthSwitchHook(t *testing.T) {
	b, err := os.ReadFile("tunnel.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\tgo runTunnelHealthOnce()\n\n\treturn outMsg.String(), nil") {
		t.Error("switchTunnelEngine must `go runTunnelHealthOnce()` just before its success return")
	}
	resetTunnelHealth()
	start := time.Now()
	runTunnelHealthOnce() // flag is off in tests: returns at once, writes nothing
	if time.Since(start) > time.Second || tunnelHealthCached() != nil {
		t.Fatal("runTunnelHealthOnce must be inert while tunnelHealthAutoRun is false")
	}
	if _, err := switchTunnelEngine("invalid_engine", "tcp"); err == nil {
		t.Fatal("invalid engine must still be rejected")
	}
}
