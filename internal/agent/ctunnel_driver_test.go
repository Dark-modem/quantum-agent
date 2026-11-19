package agent

// Hermetic tests for the ctunnel driver: validate shapes, the env-file
// rendering for both roles and both directions, the deterministic
// two-end addressing, the upstream-parity forward rules, the spawn
// shape with stubbed seams, the relay (TCP+UDP), and the through-tunnel
// health probe. No host touches: every command seam is stubbed.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/infra"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

func ctTestParams() ctunnelParams {
	return ctunnelParams{
		ServerSide: "germany", Version: ctPinnedVersion,
		Artifact:  "ctunnel-" + ctPinnedVersion + "-linux-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("aa", 32), SHA256Arm: strings.Repeat("bb", 32),
		SigAmd: strings.Repeat("QQ==", 22)[:88], SigArm: strings.Repeat("QQ==", 22)[:88],
		Method: "dtls-1.3", Direction: "reverse",
		ForeignAddr: "203.0.113.10:24312",
		CarrierPort: 24312, PublicPort: 25207,
		LocalAddr: "127.0.0.1:25201", Proto: "tcp",
		Secret: strings.Repeat("ab", 32), Padding: 0, MTU: 0,
	}
}

func ctSetTestEnv(t *testing.T) (cmds *[]string, spawned *int) {
	t.Helper()
	cmds = new([]string)
	spawned = new(int)
	origSpawn := ctSpawn
	ctSpawn = func(binPath string, args []string) (frpProcess, error) {
		*spawned++
		*cmds = append(*cmds, binPath+" "+strings.Join(args, " "))
		return &fakeFRPProcess{}, nil
	}
	t.Cleanup(func() { ctSpawn = origSpawn })
	origIP := ctIPCmd
	ctIPCmd = func(args ...string) error {
		*cmds = append(*cmds, "ip "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { ctIPCmd = origIP })
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) {
		*cmds = append(*cmds, strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() { acctIptables = origIpt })
	origSysctl := ctSysctl
	ctSysctl = func(args ...string) error {
		*cmds = append(*cmds, "sysctl "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { ctSysctl = origSysctl })
	origSave := acctIptablesSave
	acctIptablesSave = func() ([]byte, error) { return []byte(""), nil }
	t.Cleanup(func() { acctIptablesSave = origSave })
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "germany"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = "test-pinned-key"
	origCfg := infra.ConfigDir
	infra.ConfigDir = t.TempDir()
	// Warm the artifact cache so Start never needs the network.
	binDir := ctBinDir(ctPinnedVersion)
	_ = os.MkdirAll(binDir, 0o700)
	_ = os.WriteFile(filepath.Join(binDir, "ctunnel-engine"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	_ = os.WriteFile(filepath.Join(binDir, "artifact.sha256"), []byte(strings.Repeat("aa", 32)), 0o600)
	t.Cleanup(func() {
		frpLoadIdentity = origIdent
		engineArtifactPubKeyB64 = origKey
		infra.ConfigDir = origCfg
	})
	return cmds, spawned
}

func TestCtunnelValidateParams(t *testing.T) {
	d := NewCtunnelDriver()
	raw, _ := json.Marshal(ctTestParams())
	if err := d.Validate(raw); err != nil {
		t.Fatalf("valid rejected: %v", err)
	}
	for name, mutate := range map[string]func(*ctunnelParams){
		"bad method":      func(p *ctunnelParams) { p.Method = "gre" },
		"rev+ prefix":     func(p *ctunnelParams) { p.Method = "rev+dtls-1.3" },
		"kernel method":   func(p *ctunnelParams) { p.Method = "vxlan" },
		"bad direction":   func(p *ctunnelParams) { p.Direction = "sideways" },
		"bad proto":       func(p *ctunnelParams) { p.Proto = "sctp" },
		"bad foreign":     func(p *ctunnelParams) { p.ForeignAddr = "no-port" },
		"foreign quotes":  func(p *ctunnelParams) { p.ForeignAddr = `203.0.113.10:"1"` },
		"carrier port 0":  func(p *ctunnelParams) { p.CarrierPort = 0 },
		"ports equal":     func(p *ctunnelParams) { p.PublicPort = 24312 },
		"bad local_addr":  func(p *ctunnelParams) { p.LocalAddr = "127.0.0.1" },
		"local quotes":    func(p *ctunnelParams) { p.LocalAddr = `12"1:1` },
		"secret short":    func(p *ctunnelParams) { p.Secret = strings.Repeat("ab", 16) },
		"secret non-hex":  func(p *ctunnelParams) { p.Secret = strings.Repeat("z", 64) },
		"padding neg":     func(p *ctunnelParams) { p.Padding = -1 },
		"padding 256":     func(p *ctunnelParams) { p.Padding = 256 },
		"mtu 1279":        func(p *ctunnelParams) { p.MTU = 1279 },
		"mtu 1501":        func(p *ctunnelParams) { p.MTU = 1501 },
		"no arch templ":   func(p *ctunnelParams) { p.Artifact = "ctunnel.tar.gz" },
		"bad sha":         func(p *ctunnelParams) { p.SHA256Arm = "short" },
		"empty server":    func(p *ctunnelParams) { p.ServerSide = " " },
		"bad sig":         func(p *ctunnelParams) { p.SigAmd = "" },
		"version missing": func(p *ctunnelParams) { p.Version = "" },
	} {
		p := ctTestParams()
		mutate(&p)
		raw, _ := json.Marshal(p)
		if err := d.Validate(raw); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// Defaults are accepted: empty direction/proto/padding/mtu.
	p := ctTestParams()
	p.Direction, p.Proto, p.Padding, p.MTU = "", "", 0, 0
	raw, _ = json.Marshal(p)
	if err := d.Validate(raw); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
}

func TestCtunnelEnvRendering(t *testing.T) {
	p := ctTestParams()
	iran := ctDeriveFor("t-env", "iran")
	kharej := ctDeriveFor("t-env", "kharej")
	if iran.selfTun != "10.77."+fmt.Sprint(iran.index)+".1" || kharej.selfTun != "10.77."+fmt.Sprint(kharej.index)+".2" {
		t.Fatalf("tunnel-ip convention broken: iran=%s kharej=%s", iran.selfTun, kharej.selfTun)
	}
	if iran.index != kharej.index || iran.iface != kharej.iface {
		t.Fatal("both ends must derive the same index/iface from one tunnel id")
	}
	if iran.peerTun != kharej.selfTun || kharej.peerTun != iran.selfTun {
		t.Fatal("peer tunnel addresses must mirror")
	}
	if len(iran.iface) > 15 {
		t.Fatalf("iface %q exceeds IFNAMSIZ", iran.iface)
	}

	// reverse: iran passive (roams), kharej dials the foreign address.
	env := string(ctEnvText(p, "iran", "reverse", iran))
	if !strings.Contains(env, "ROLE=iran") || !strings.Contains(env, "REVERSE=1") {
		t.Fatalf("reverse iran env wrong:\n%s", env)
	}
	if !strings.Contains(env, "REMOTE_IP=0.0.0.0") {
		t.Fatalf("reverse iran must roam (REMOTE_IP=0.0.0.0):\n%s", env)
	}
	if !strings.Contains(env, "SECRET="+p.Secret) || !strings.Contains(env, "KIND=dtls-1.3") {
		t.Fatalf("env missing kind/secret:\n%s", env)
	}
	// MTU default: 1500 - 66 (dtls-1.3) - 16 (default padding) = 1418.
	if !strings.Contains(env, "MTU=1418") {
		t.Fatalf("mtu default wrong:\n%s", env)
	}
	envK := string(ctEnvText(p, "kharej", "reverse", kharej))
	if !strings.Contains(envK, "REMOTE_IP=203.0.113.10") || !strings.Contains(envK, "REVERSE=1") {
		t.Fatalf("reverse kharej must dial the foreign address:\n%s", envK)
	}

	// direct: iran dials, kharej roams; REVERSE=0.
	envD := string(ctEnvText(p, "iran", "direct", iran))
	if !strings.Contains(envD, "REMOTE_IP=203.0.113.10") || !strings.Contains(envD, "REVERSE=0") {
		t.Fatalf("direct iran must dial:\n%s", envD)
	}
	envDK := string(ctEnvText(p, "kharej", "direct", kharej))
	if !strings.Contains(envDK, "REMOTE_IP=0.0.0.0") || !strings.Contains(envDK, "REVERSE=0") {
		t.Fatalf("direct kharej must roam:\n%s", envDK)
	}
	// FORWARDS stays empty: the driver owns the DNAT.
	if !strings.Contains(env, "FORWARDS=\n") {
		t.Fatalf("FORWARDS must stay empty (driver-owned rules):\n%s", env)
	}
}

func TestCtunnelForwardRuleArgs(t *testing.T) {
	args := ctForwardRuleArgs("t1", "tcp", 25207, 25201, "10.77.128.1", "10.77.128.2")
	if len(args) != 4 {
		t.Fatalf("tcp: %d rule args", len(args))
	}
	joined := make([]string, 0, len(args))
	for _, a := range args {
		joined = append(joined, strings.Join(a, " "))
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{
		`-t nat -A PREROUTING -p tcp --dport 25207 -m addrtype --dst-type LOCAL -m comment --comment ctdrv-t1 -j DNAT --to-destination 10.77.128.2:25201`,
		`-t nat -A POSTROUTING -d 10.77.128.2/32 -m comment --comment ctdrv-t1 -j SNAT --to-source 10.77.128.1`,
		`-I FORWARD -d 10.77.128.2/32 -m comment --comment ctdrv-t1 -j ACCEPT`,
		`-I FORWARD -s 10.77.128.2/32 -m comment --comment ctdrv-t1 -j ACCEPT`,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing rule:\nwant: %s\ngot:\n%s", want, all)
		}
	}
	// udp/both extend the set.
	if got := len(ctForwardRuleArgs("t1", "both", 25207, 25201, "10.77.128.1", "10.77.128.2")); got != 8 {
		t.Fatalf("both: %d rules", got)
	}
	// The kharej end's relay INPUT accepts (insert-first, scoped, tagged).
	in := ctRelayInputRuleArgs("t1", "ctqx", "both", 25201)
	if len(in) != 2 {
		t.Fatalf("relay input: %d rules", len(in))
	}
	if got := strings.Join(in[0], " "); !strings.Contains(got, "-I INPUT -i ctqx -p tcp --dport 25201 -j ACCEPT -m comment --comment ctdrv-t1") {
		t.Fatalf("relay INPUT rule wrong: %s", got)
	}
}

func TestCtunnelArgsShape(t *testing.T) {
	cmds, spawned := ctSetTestEnv(t)
	d := NewCtunnelDriver()
	p := ctTestParams()
	inst := engine.Instance{TunnelID: "ct1", LocalServer: "germany", RemoteServer: "iran",
		Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	if *spawned != 1 {
		t.Fatalf("spawned = %d", *spawned)
	}
	joined := strings.Join(*cmds, "\n")
	// The spawn line: ctunnel-engine -config <0600 env file>.
	if !strings.Contains(joined, "ctunnel-engine -config ") {
		t.Fatalf("spawn args wrong:\n%s", joined)
	}
	// The TUN came up BEFORE the engine (the engine attaches to an
	// existing interface): tuntap add precedes the spawn line in the log.
	iTuntap := strings.Index(joined, "ip tuntap add")
	iSpawn := strings.Index(joined, "ctunnel-engine -config")
	if iTuntap < 0 || iSpawn < 0 || iTuntap > iSpawn {
		t.Fatalf("TUN must exist before spawn:\n%s", joined)
	}
	// The server-side (iran role) end installs DNAT/SNAT + carrier accounting.
	if !strings.Contains(joined, "--to-destination 10.77.") {
		t.Fatalf("no DNAT on the server end:\n%s", joined)
	}
	if !strings.Contains(joined, "sysctl -qw net.ipv4.ip_forward=1") {
		t.Fatalf("ip_forward sysctl missing on the server end:\n%s", joined)
	}
	if !strings.Contains(joined, "-A CTDRV_ACCT_IN -p udp --dport 24312") {
		t.Fatalf("no carrier accounting:\n%s", joined)
	}
	// The env file is 0600 and carries the secret.
	envPath := ctEnvPath("ct1")
	fi, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("env file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("env file mode %v, want 0600", fi.Mode().Perm())
	}
	// Idempotent Start.
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatal(err)
	}
	if *spawned != 1 {
		t.Fatalf("idempotent Start spawned again: %d", *spawned)
	}

	// The kharej (client) end: no DNAT, relay instead; REMOTE_IP set.
	*cmds = (*cmds)[:0]
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "iran-1"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	if err := d.Start(context.Background(), engine.Instance{TunnelID: "ct2",
		LocalServer: "iran", RemoteServer: "germany", Params: infra.MustJSON(p)}); err != nil {
		t.Fatal(err)
	}
	clientJoined := strings.Join(*cmds, "\n")
	if strings.Contains(clientJoined, "PREROUTING") {
		t.Fatalf("client end must not install DNAT:\n%s", clientJoined)
	}
	if !strings.Contains(clientJoined, "ip tuntap add") {
		t.Fatalf("client end TUN setup missing:\n%s", clientJoined)
	}

	// Health on the server end: the through-probe is stubbed — unhealthy
	// until it passes (the warmup gate shape). The real probe dial is
	// exercised against loopback listeners in TestCtunnelProbeThrough.
	origProbe := ctProbeDial
	ctProbeDial = func(addr string, timeout time.Duration) error {
		return fmt.Errorf("stub: no tunnel path")
	}
	if h := d.Health(engine.Instance{TunnelID: "ct1"}); h.OK {
		ctProbeDial = origProbe
		t.Fatalf("health without a tunnel: %+v", h)
	}
	ctProbeDial = func(addr string, timeout time.Duration) error { return nil }
	if h := d.Health(engine.Instance{TunnelID: "ct1"}); !h.OK {
		ctProbeDial = origProbe
		t.Fatalf("health with a passing probe: %+v", h)
	}
	ctProbeDial = origProbe
	// Stop unwinds: env removed, iface deleted, rules removed.
	if err := d.Stop(engine.Instance{TunnelID: "ct1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(envPath); !os.IsNotExist(err) {
		t.Fatalf("env file survived Stop: %v", err)
	}
	if err := d.Stop(engine.Instance{TunnelID: "ct-nonexistent"}); err != nil {
		t.Fatalf("Stop of unknown instance must be a no-op: %v", err)
	}
	if err := d.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if infra.FileExists(ctEngineDir()) {
		t.Fatal("engine dir left after Uninstall")
	}
}

func TestCtunnelReloadAndForwardAddress(t *testing.T) {
	ctSetTestEnv(t)
	d := NewCtunnelDriver()
	p := ctTestParams()
	inst := engine.Instance{TunnelID: "ct3", LocalServer: "germany", RemoteServer: "iran",
		Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Stop(inst) })
	// Equal params: no-op.
	if err := d.Reload(inst); err != nil {
		t.Fatalf("equal reload: %v", err)
	}
	// Changed params: restart required.
	p2 := p
	p2.PublicPort = 25300
	if err := d.Reload(engine.Instance{TunnelID: "ct3", Params: infra.MustJSON(p2)}); err != engine.ErrRestartRequired {
		t.Fatalf("changed reload: %v", err)
	}
	// ForwardAddress: the iran end answers via the kharej tunnel IP.
	host, port, ok := d.ForwardAddress(inst)
	if !ok || host != ctDeriveFor("ct3", "iran").peerTun || port != 25201 {
		t.Fatalf("ForwardAddress = %s:%d ok=%v", host, port, ok)
	}
}

func TestCtunnelProbeThrough(t *testing.T) {
	// hold-open listener (accepts and holds): healthy.
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	go func() {
		for {
			c, err := hold.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 1)
				_, _ = c.Read(buf) // hold open until the probe gives up
			}(c)
		}
	}()
	if err := ctProbeThrough(hold.Addr().String(), 700*time.Millisecond); err != nil {
		t.Fatalf("hold-open must be healthy: %v", err)
	}
	// instant-close listener: unhealthy (relay's target dial failed).
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close()
	go func() {
		for {
			c, err := dead.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if err := ctProbeThrough(dead.Addr().String(), 2*time.Second); err == nil {
		t.Fatal("instant-close must be unhealthy")
	}
	// refused dial: unhealthy.
	if err := ctProbeThrough("127.0.0.1:1", 500*time.Millisecond); err == nil {
		t.Fatal("refused dial must be unhealthy")
	}
}

func TestCtunnelRelayTCPAndUDP(t *testing.T) {
	// The local target: an echo server (TCP + UDP) the relay dials.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	var echoWG sync.WaitGroup
	echoWG.Add(1)
	go func() {
		defer echoWG.Done()
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = fmt.Fprintf(c, "ack:")
				_, _ = io.Copy(c, c)
				c.Close()
			}(c)
		}
	}()
	echoAddr := echo.Addr().String()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	relay := ctStartRelay(stop, "127.0.0.1:0", echoAddr, "both")
	t.Cleanup(relay.Close)
	deadline := time.Now().Add(3 * time.Second)
	for !relay.Ready(true, true) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !relay.Ready(true, true) {
		t.Fatal("relay not ready")
	}
	// TCP through the relay: the target's ack comes back.
	conn, err := net.DialTimeout("tcp", relay.tcpLn.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil || string(buf) != "ack:" {
		t.Fatalf("tcp relay: %v %q", err, buf)
	}
	// The relay dials the target: writes echo back.
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf2 := make([]byte, 1)
	if _, err := conn.Read(buf2); err != nil || buf2[0] != 'x' {
		t.Fatalf("tcp echo through relay: %v %q", err, buf2)
	}
	// UDP through the relay (session-mapped proxy).
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, src, err := udpEcho.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpEcho.WriteToUDP(buf[:n], src)
		}
	}()
	// Start a second relay aimed at the UDP echo's real address.
	stop2 := make(chan struct{})
	t.Cleanup(func() { close(stop2) })
	relay2 := ctStartRelay(stop2, "127.0.0.1:0", udpEcho.LocalAddr().String(), "udp")
	t.Cleanup(relay2.Close)
	deadline = time.Now().Add(3 * time.Second)
	for !relay2.Ready(false, true) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !relay2.Ready(false, true) {
		t.Fatal("udp relay not ready")
	}
	c, err := net.Dial("udp", relay2.udpConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	rbuf := make([]byte, 4)
	if _, err := c.Read(rbuf); err != nil || string(rbuf) != "ping" {
		t.Fatalf("udp relay echo: %v %q", err, rbuf)
	}
	// Close stops the listeners (echo first, so its accept loop exits).
	echo.Close()
	echoWG.Wait()
	udpEcho.Close()
	relay.Close()
	relay2.Close()
}
