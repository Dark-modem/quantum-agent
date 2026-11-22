package agent

// Hermetic tests for the ctunnel v2 driver: validate shapes across the
// 6 families, the env-file rendering for both roles and both directions,
// the deterministic two-end addressing, the upstream-parity forward rules,
// the kernel-direct device sequences (arg-list, additive, exact teardown),
// the L4 engine-only shape, the spawn shape with stubbed seams, the relay
// (TCP+UDP), the through-tunnel health probe, and the §2.22 version
// reporting. No host touches: every command seam is stubbed.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
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

// ctSetTestEnv stubs EVERY host seam the v2 driver can reach, records the
// executed commands, and warms the artifact cache so Start never needs the
// network.
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
	origTC := ctTCCmd
	ctTCCmd = func(args ...string) error {
		*cmds = append(*cmds, "tc "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { ctTCCmd = origTC })
	origWg := ctWgCmd
	ctWgCmd = func(args ...string) error {
		*cmds = append(*cmds, "wg "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { ctWgCmd = origWg })
	origIpt := acctIptables
	acctIptables = func(args ...string) ([]byte, error) {
		*cmds = append(*cmds, strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() { acctIptables = origIpt })
	origIpt6 := ctIP6Tables
	ctIP6Tables = func(args ...string) ([]byte, error) {
		*cmds = append(*cmds, "ip6tables "+strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() { ctIP6Tables = origIpt6 })
	origLocal := ctLocalIPFor
	ctLocalIPFor = func(peerIP string) (string, error) { return "198.51.100.2", nil }
	t.Cleanup(func() { ctLocalIPFor = origLocal })
	origSysctl := ctSysctl
	ctSysctl = func(args ...string) error {
		*cmds = append(*cmds, "sysctl "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { ctSysctl = origSysctl })
	origSave := acctIptablesSave
	acctIptablesSave = func() ([]byte, error) { return []byte(""), nil }
	t.Cleanup(func() { acctIptablesSave = origSave })
	origProbe := ctVersionProbe
	ctVersionProbe = func(binPath string) (string, error) { return ctPinnedVersion, nil }
	t.Cleanup(func() { ctVersionProbe = origProbe })
	ctVerMu.Lock()
	ctVerCached = ""
	ctVerMu.Unlock()
	t.Cleanup(func() {
		ctVerMu.Lock()
		ctVerCached = ""
		ctVerMu.Unlock()
	})
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
	// A kernel family WITHOUT artifact pins is valid (no engine to fetch).
	p := ctTestParams()
	p.Method = "gre"
	p.Direction = "direct"
	p.Version, p.Artifact, p.SHA256Amd, p.SHA256Arm, p.SigAmd, p.SigArm = "", "", "", "", "", ""
	p.PeerAddr = "203.0.113.11:24312"
	raw, _ = json.Marshal(p)
	if err := d.Validate(raw); err != nil {
		t.Fatalf("kernel-direct without pins rejected: %v", err)
	}
	// The SAME kernel family in reverse DOES need the pins (engine carrier).
	p2 := p
	p2.Direction = "reverse"
	raw, _ = json.Marshal(p2)
	if err := d.Validate(raw); err == nil {
		t.Fatal("kernel-reverse without pins accepted")
	}
	// Hostile matrix per family / cross-family fields.
	for name, mutate := range map[string]func(*ctunnelParams){
		"unknown method":    func(p *ctunnelParams) { p.Method = "gre-x" },
		"empty method":      func(p *ctunnelParams) { p.Method = "" },
		"l4 direct":         func(p *ctunnelParams) { p.Method = "tcp"; p.Direction = "direct" },
		"icmp with port":    func(p *ctunnelParams) { p.Method = "icmp"; p.CarrierPort = 24312 },
		"needs port 0":      func(p *ctunnelParams) { p.Method = "quic-v1"; p.CarrierPort = 0 },
		"port range":        func(p *ctunnelParams) { p.CarrierPort = 65536 },
		"ports equal":       func(p *ctunnelParams) { p.PublicPort = 24312 },
		"l4 non-loopback":   func(p *ctunnelParams) { p.Method = "tcpmux"; p.LocalAddr = "10.0.0.1:8080" },
		"sni on dtls":       func(p *ctunnelParams) { p.SNI = "cdn.example.com" },
		"lanes on vxlan":    func(p *ctunnelParams) { p.Method = "vxlan"; p.Lanes = 4 },
		"lanes 9":           func(p *ctunnelParams) { p.Method = "gre"; p.Lanes = 9 },
		"padding on gre":    func(p *ctunnelParams) { p.Method = "gre"; p.Padding = 16 },
		"v6 underlay v4 fr": func(p *ctunnelParams) { p.Method = "ip6gre"; p.ForeignAddr = "203.0.113.10:24312" },
		"secret short":      func(p *ctunnelParams) { p.Secret = strings.Repeat("ab", 16) },
		"secret non-hex":    func(p *ctunnelParams) { p.Secret = strings.Repeat("z", 64) },
		"no secret wg":      func(p *ctunnelParams) { p.Method = "wireguard"; p.Secret = ""; p.CarrierPort = 24312 },
		"padding neg":       func(p *ctunnelParams) { p.Padding = -1 },
		"padding 256":       func(p *ctunnelParams) { p.Padding = 256 },
		"mtu 1279":          func(p *ctunnelParams) { p.MTU = 1279 },
		"mtu 1501":          func(p *ctunnelParams) { p.MTU = 1501 },
		"no arch templ":     func(p *ctunnelParams) { p.Artifact = "ctunnel.tar.gz" },
		"bad sha":           func(p *ctunnelParams) { p.SHA256Arm = "short" },
		"empty server":      func(p *ctunnelParams) { p.ServerSide = " " },
		"bad sig":           func(p *ctunnelParams) { p.SigAmd = "" },
		"version missing":   func(p *ctunnelParams) { p.Version = "" },
		"bad direction":     func(p *ctunnelParams) { p.Direction = "sideways" },
		"bad proto":         func(p *ctunnelParams) { p.Proto = "sctp" },
		"bad foreign":       func(p *ctunnelParams) { p.ForeignAddr = "no-port" },
		"foreign quotes":    func(p *ctunnelParams) { p.ForeignAddr = `203.0.113.10:"1"` },
		"bad local_addr":    func(p *ctunnelParams) { p.LocalAddr = "127.0.0.1" },
		"local quotes":      func(p *ctunnelParams) { p.LocalAddr = `12"1:1` },
		"rate 100001":       func(p *ctunnelParams) { p.Method = "gre"; p.RateMbps = 100001 },
	} {
		p := ctTestParams()
		mutate(&p)
		raw, _ := json.Marshal(p)
		if err := d.Validate(raw); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// icmp without a carrier port is VALID (the engine derives the id).
	pI := ctTestParams()
	pI.Method, pI.CarrierPort = "icmp", 0
	raw, _ = json.Marshal(pI)
	if err := d.Validate(raw); err != nil {
		t.Fatalf("icmp without port rejected: %v", err)
	}
	// Defaults are accepted: empty direction/proto/padding/mtu.
	p = ctTestParams()
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
	if iran.selfRev4 == kharej.selfRev4 || kharej.peerRev4 != iran.selfRev4 {
		t.Fatal("reverse-carrier pairs must mirror by role")
	}
	if len(iran.iface) > 13 { // +"-r" must still fit IFNAMSIZ 15
		t.Fatalf("iface %q leaves no room for the -r carrier suffix", iran.iface)
	}

	// reverse: iran passive (roams), kharej dials the foreign address.
	env := string(ctEnvText(p, "iran", "reverse", iran, "t-env"))
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
	// The v2 env keys are always present.
	for _, want := range []string{"CARRIER_LOCAL6=fd00:78:", "CARRIER_REMOTE6=", "LANES=1", "RATE_MBIT=0", "FORWARDS="} {
		if !strings.Contains(env, want) {
			t.Fatalf("v2 env key %q missing:\n%s", want, env)
		}
	}
	envK := string(ctEnvText(p, "kharej", "reverse", kharej, "t-env"))
	if !strings.Contains(envK, "REMOTE_IP=203.0.113.10") || !strings.Contains(envK, "REVERSE=1") {
		t.Fatalf("reverse kharej must dial the foreign address:\n%s", envK)
	}

	// direct: iran dials, kharej roams; REVERSE=0.
	envD := string(ctEnvText(p, "iran", "direct", iran, "t-env"))
	if !strings.Contains(envD, "REMOTE_IP=203.0.113.10") || !strings.Contains(envD, "REVERSE=0") {
		t.Fatalf("direct iran must dial:\n%s", envD)
	}
	envDK := string(ctEnvText(p, "kharej", "direct", kharej, "t-env"))
	if !strings.Contains(envDK, "REMOTE_IP=0.0.0.0") || !strings.Contains(envDK, "REVERSE=0") {
		t.Fatalf("direct kharej must roam:\n%s", envDK)
	}
	// FORWARDS stays empty for interface families: the driver owns the DNAT.
	if !strings.Contains(env, "FORWARDS=\n") {
		t.Fatalf("FORWARDS must stay empty (driver-owned rules):\n%s", env)
	}
	// L4 methods: the engine binds the forwards itself — FORWARDS carries
	// the mapping; secret rides (their L4 peerauth); no TUN keys change.
	l4 := p
	l4.Method = "tcpmux"
	l4.SNI = ""
	envL4 := string(ctEnvText(l4, "iran", "reverse", iran, "t-env"))
	if !strings.Contains(envL4, fmt.Sprintf("FORWARDS=%d=25201", l4.PublicPort)) {
		t.Fatalf("L4 FORWARDS mapping missing:\n%s", envL4)
	}
	// Kernel-reverse: the engine opens <dev>-r with the 172.31 pair.
	kg := ctTestParams()
	kg.Method, kg.Secret = "gre", strings.Repeat("cd", 32)
	envKG := string(ctEnvText(kg, "iran", "reverse", iran, "t-env"))
	if !strings.Contains(envKG, "DEV="+iran.iface+"-r") ||
		!strings.Contains(envKG, "LOCAL_IP="+iran.selfRev4) ||
		!strings.Contains(envKG, "REMOTE_IP="+iran.peerRev4) {
		t.Fatalf("kernel-reverse env must name the carrier TUN + 172.31 pair:\n%s", envKG)
	}
	// wireguard env carries the DERIVED key pair, never the raw secret.
	wg := ctTestParams()
	wg.Method, wg.Secret, wg.CarrierPort = "wireguard", strings.Repeat("ef", 32), 24312
	envWG := string(ctEnvText(wg, "iran", "reverse", iran, "t-env"))
	if strings.Contains(envWG, "SECRET=") {
		t.Fatalf("wireguard env must not carry the raw secret:\n%s", envWG)
	}
	priv, pub := ctWireGuardKeys(wg.Secret, "iran")
	_, peerPub := ctWireGuardKeys(wg.Secret, "kharej")
	if !strings.Contains(envWG, "WG_PRIVATE="+priv) || !strings.Contains(envWG, "WG_PEER_PUBLIC="+peerPub) {
		t.Fatalf("wireguard derived keys missing:\n%s", envWG)
	}
	_ = pub
	// The derivation is deterministic and mirrors across ends.
	priv2, pub2 := ctWireGuardKeys(wg.Secret, "iran")
	if priv != priv2 || pub != pub2 {
		t.Fatal("wireguard derivation must be deterministic")
	}
	// The interop KDF: reimplemented independently in the test (HMAC-SHA256
	// keyed by the raw secret, message "ctunnel-v1|" + label) and compared
	// with the driver's derivation.
	raw, _ := hex.DecodeString(wg.Secret)
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte("ctunnel-v1|wg-key|iran"))
	k := ctDeriveSubkey(wg.Secret, "wg-key|iran")
	if fmt.Sprintf("%x", k[:]) != fmt.Sprintf("%x", mac.Sum(nil)) {
		t.Fatalf("DeriveSubkey interop mismatch")
	}
	// xfrm SPI derivation stays clear of the reserved range.
	spi, key := ctIPsecSA(wg.Secret, "iran")
	v := parseHexUint(spi)
	if v < 0x1000 || key == "" || len(key) != 2+72 { // 36 bytes hex + 0x
		t.Fatalf("ipsec SA derivation wrong: spi=%s keylen=%d", spi, len(key))
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
	// The v6-inner variant (sit/ip6ip6) mirrors the same four rules.
	v6 := ctForwardRuleV6Args("t1", "tcp", 25207, 25201, "fd00:77:80::1", "fd00:77:80::2")
	if len(v6) != 4 {
		t.Fatalf("v6 rules: %d", len(v6))
	}
	v6all := strings.Join([]string{strings.Join(v6[0], " "), strings.Join(v6[1], " ")}, "\n")
	if !strings.Contains(v6all, "--to-destination [fd00:77:80::2]:25201") ||
		!strings.Contains(v6all, "-d fd00:77:80::2/128") {
		t.Fatalf("v6 DNAT/SNAT wrong:\n%s", v6all)
	}
	// MSS clamp + notrack: additive, tagged, exact-del shapes.
	mss := ctMSSClampArgs("t1", "ctqx")
	if len(mss) != 2 || !strings.Contains(strings.Join(mss[0], " "), "--clamp-mss-to-pmtu") {
		t.Fatalf("mss clamp wrong: %v", mss)
	}
	nt := ctNotrackArgs("t1", "203.0.113.10")
	if len(nt) != 12 { // 6 protocols × (PREROUTING + OUTPUT)
		t.Fatalf("notrack rules: %d", len(nt))
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
	// The env file is 0600 and carries the secret (the perm bit is a
	// unix-only assertion — Windows FileModes do not map 1:1).
	envPath := ctEnvPath("ct1")
	fi, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("env file: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
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

// TestCtunnelKernelDirectStart proves the gre DIRECT shape: NO engine
// process, NO env file, the kernel device + addr + MSS + notrack via
// arg-list, DNAT on the iran end, and a Stop that deletes exactly what
// Start created.
func TestCtunnelKernelDirectStart(t *testing.T) {
	cmds, spawned := ctSetTestEnv(t)
	d := NewCtunnelDriver()
	p := ctTestParams()
	p.Method = "gre"
	p.Direction = "direct" // the kernel-direct shape (no engine carrier)
	p.PeerAddr = "203.0.113.11:24312"
	p.Version, p.Artifact, p.SHA256Amd, p.SHA256Arm, p.SigAmd, p.SigArm = "", "", "", "", "", ""
	inst := engine.Instance{TunnelID: "ctg", LocalServer: "germany", RemoteServer: "iran",
		Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("gre direct Start: %v", err)
	}
	if *spawned != 0 {
		t.Fatalf("kernel-direct must not spawn the engine (spawned %d)", *spawned)
	}
	if infra.FileExists(ctEnvPath("ctg")) {
		t.Fatal("kernel-direct must not write an env file")
	}
	joined := strings.Join(*cmds, "\n")
	// The rule rows appear in their -C check form first (the valid
	// exactly-once check; the hermetic seam confirms existence so the -A
	// add is skipped — the spec fragment is what the assertion proves).
	for _, want := range []string{
		`ip link add name ctq`, `type gre`, `remote 203.0.113.10`,
		`ip addr add 10.77.`, `peer 10.77.`, `/32`,
		`-t raw -C PREROUTING -s 203.0.113.10/32 -p 47`,
		`-t mangle -C FORWARD -o ctq`, `--clamp-mss-to-pmtu`,
		`-t nat -C PREROUTING -p tcp --dport 25207`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("gre-direct missing %q:\n%s", want, joined)
		}
	}
	// No engine — health comes from the through-probe only.
	origProbe := ctProbeDial
	ctProbeDial = func(addr string, timeout time.Duration) error { return nil }
	if h := d.Health(inst); !h.OK {
		ctProbeDial = origProbe
		t.Fatalf("kernel-direct health: %+v", h)
	}
	ctProbeDial = origProbe
	// Stop deletes exactly the created objects.
	*cmds = (*cmds)[:0]
	if err := d.Stop(inst); err != nil {
		t.Fatal(err)
	}
	stopJoined := strings.Join(*cmds, "\n")
	if !strings.Contains(stopJoined, "ip link del dev ctq") {
		t.Fatalf("kernel device not deleted on Stop:\n%s", stopJoined)
	}
	if strings.Contains(stopJoined, "ctunnel-engine") {
		t.Fatalf("kernel-direct Stop must not touch the engine:\n%s", stopJoined)
	}
	delCount := strings.Count(stopJoined, "-D")
	if delCount == 0 {
		t.Fatal("no iptables rules deleted on Stop")
	}
}

// TestCtunnelL4Start proves the L4 shape: engine-only, NO interface, NO
// iptables forward rules — the env carries FORWARDS and the engine binds
// the public port itself; health probes the public listener.
func TestCtunnelL4Start(t *testing.T) {
	cmds, spawned := ctSetTestEnv(t)
	d := NewCtunnelDriver()
	p := ctTestParams()
	p.Method = "wssmux"
	p.SNI = "cdn.example.com"
	inst := engine.Instance{TunnelID: "ctl4", LocalServer: "germany", RemoteServer: "iran",
		Params: infra.MustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("L4 Start: %v", err)
	}
	if *spawned != 1 {
		t.Fatalf("L4 must spawn the engine (spawned %d)", *spawned)
	}
	joined := strings.Join(*cmds, "\n")
	if strings.Contains(joined, "ip tuntap add") {
		t.Fatalf("L4 must not create an interface:\n%s", joined)
	}
	if strings.Contains(joined, "PREROUTING") {
		t.Fatalf("L4 must not install DNAT (the engine binds the port):\n%s", joined)
	}
	if !strings.Contains(joined, fmt.Sprintf("-A CTDRV_ACCT_IN -p tcp --dport %d", p.PublicPort)) {
		t.Fatalf("L4 public-port accounting missing:\n%s", joined)
	}
	envPath := ctEnvPath("ctl4")
	envBytes, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	env := string(envBytes)
	if !strings.Contains(env, fmt.Sprintf("FORWARDS=%d=25201", p.PublicPort)) ||
		!strings.Contains(env, "SNI=cdn.example.com") || !strings.Contains(env, "REVERSE=1") {
		t.Fatalf("L4 env wrong:\n%s", env)
	}
	// Health (iran end): the stubbed probe targets the public listener.
	var probed string
	origProbe := ctProbeDial
	ctProbeDial = func(addr string, timeout time.Duration) error {
		probed = addr
		return nil
	}
	if h := d.Health(inst); !h.OK {
		ctProbeDial = origProbe
		t.Fatalf("L4 health: %+v", h)
	}
	ctProbeDial = origProbe
	if want := net.JoinHostPort("127.0.0.1", fmt.Sprint(p.PublicPort)); probed != want {
		t.Fatalf("L4 health probe = %s, want %s", probed, want)
	}
	_ = cmds
}

// TestCtunnelAllMethodsCovered walks ALL 49 methods: each validates, each
// renders an env, kernel-direct families run Start/Stop with exact
// per-method device kinds. This is the ALL-49 gate.
func TestCtunnelAllMethodsCovered(t *testing.T) {
	cmds, spawned := ctSetTestEnv(t)
	d := NewCtunnelDriver()
	if got := len(ctMethods); got != 49 {
		t.Fatalf("catalog has %d methods, want 49", got)
	}
	fams := map[ctFamily]int{}
	for _, spec := range ctMethods {
		fams[spec.family]++
	}
	want := map[ctFamily]int{ctFamKernelL3: 16, ctFamKernelL2: 7, ctFamUDPCrypt: 11,
		ctFamStealth: 2, ctFamRevL4: 9, ctFamGaming: 4}
	for f, n := range want {
		if fams[f] != n {
			t.Fatalf("family %s has %d methods, want %d", f, fams[f], n)
		}
	}
	// Every method name from the cores manifest mirror must resolve here
	// (the manifest names the published truth — the driver must accept all).
	manifestMethods := ctMethodList()
	if len(manifestMethods) != 49 {
		t.Fatalf("ctMethodList = %d", len(manifestMethods))
	}
	for _, name := range manifestMethods {
		p := ctTestParams()
		p.Method = name
		if name == "icmp" {
			p.CarrierPort = 0
		}
		if !ctMethods[name].userspace {
			// kernel families: pins optional AND direction=direct (the
			// engine carrier shape is exercised in the reverse tests).
			p.Version, p.Artifact, p.SHA256Amd, p.SHA256Arm, p.SigAmd, p.SigArm = "", "", "", "", "", ""
			p.Direction = "direct"
			p.PeerAddr = "203.0.113.11:24312"
		}
		if name == "ip6gre" || name == "ip6gretap" || name == "ipip6" || name == "ip6ip6" {
			p.ForeignAddr = "[2001:db8::10]:24312"
		}
		raw, _ := json.Marshal(p)
		if err := d.Validate(raw); err != nil {
			t.Fatalf("method %s rejected: %v", name, err)
		}
		iran := ctDeriveFor("t-all", "iran")
		env := string(ctEnvText(p, "iran", ctDefaultDirection(p.Direction), iran, "t-all"))
		if !strings.Contains(env, "KIND="+name) {
			t.Fatalf("method %s env KIND wrong:\n%s", name, env)
		}
	}
	// Kernel-direct start/stop for every driver-side kernel kind (both v4
	// and v6 underlay, lanes, FOU) — exact device-kind per method.
	kernelKinds := map[string]string{
		"gre": "type gre", "gretap": "type gretap", "ipip": "type ipip",
		"sit": "type sit", "vxlan": "type vxlan", "geneve": "type geneve",
		"xgre": "type gre", "ecmp-lanes": "type gre", "xgre-ip": "type ipip",
		"ip6gre": "type ip6gre", "ip6gretap": "type ip6gretap",
		"bareudp": "type bareudp", "l2tpv3": "l2tp add tunnel",
		"wireguard": "type wireguard", "xfrm-ipsec": "type gre",
		"fou-gre": "type gre", "gue-ipip": "type ipip",
		"6to4": "type sit", "6to4-gre": "type sit", "ipip6": "-6 tunnel add",
		"ip6ip6": "-6 tunnel add",
	}
	for name, want := range kernelKinds {
		p := ctTestParams()
		p.Method = name
		p.Direction = "direct" // driver-side kernel shape
		p.PeerAddr = "203.0.113.11:24312"
		p.Version, p.Artifact, p.SHA256Amd, p.SHA256Arm, p.SigAmd, p.SigArm = "", "", "", "", "", ""
		if name == "ip6gre" || name == "ip6gretap" || name == "ipip6" || name == "ip6ip6" {
			p.ForeignAddr = "[2001:db8::10]:24312"
		}
		if name == "ip6ip6" || name == "sit" {
			p.CarrierPort = 0 // no FOU for the v6-inner-only methods here
		}
		inst := engine.Instance{TunnelID: "ctk-" + name, LocalServer: "germany", RemoteServer: "iran",
			Params: infra.MustJSON(p)}
		*cmds = (*cmds)[:0]
		if err := d.Start(context.Background(), inst); err != nil {
			t.Fatalf("kernel method %s Start: %v", name, err)
		}
		joined := strings.Join(*cmds, "\n")
		if !strings.Contains(joined, want) {
			t.Fatalf("method %s missing device shape %q:\n%s", name, want, joined)
		}
		if *spawned != 0 {
			t.Fatalf("method %s spawned the engine", name)
		}
		if err := d.Stop(inst); err != nil {
			t.Fatalf("method %s Stop: %v", name, err)
		}
	}
	// The userspace + L4 methods all spawn the engine (icmp + faketcp + the
	// udp-crypt family + gaming + L4 + eoip/etherip).
	for _, name := range []string{"quic-v1", "icmp", "faketcp", "game-udp", "tcp", "udp", "wssmux", "eoip", "etherip", "stun-turn", "gtp-u", "esp-udp", "game-kcp"} {
		p := ctTestParams()
		p.Method = name
		if name == "icmp" {
			p.CarrierPort = 0
		}
		inst := engine.Instance{TunnelID: "ctu-" + name, LocalServer: "germany", RemoteServer: "iran",
			Params: infra.MustJSON(p)}
		*cmds = (*cmds)[:0]
		*spawned = 0
		if err := d.Start(context.Background(), inst); err != nil {
			t.Fatalf("userspace method %s Start: %v", name, err)
		}
		if *spawned != 1 {
			t.Fatalf("method %s must spawn the engine (spawned %d)", name, *spawned)
		}
		if err := d.Stop(inst); err != nil {
			t.Fatalf("method %s Stop: %v", name, err)
		}
	}
}

// TestCtunnelWireBytesProtocolFilter proves the accounting parser only
// counts the instance's own protocol/port rows (the v2 per-proto filter).
func TestCtunnelWireBytesProtocolFilter(t *testing.T) {
	origSave := acctIptablesSave
	t.Cleanup(func() { acctIptablesSave = origSave })
	acctIptablesSave = func() ([]byte, error) {
		return []byte(strings.Join([]string{
			`[3200:1400000] -A CTDRV_ACCT_IN -p udp --dport 24312 -m comment --comment ctdrv-tw`,
			`[2100:900000] -A CTDRV_ACCT_OUT -p udp --sport 24312 -m comment --comment ctdrv-tw`,
			`[500:40000] -A CTDRV_ACCT_IN -p tcp --dport 24312 -m comment --comment ctdrv-tw`,
			`[100:8000] -A CTDRV_ACCT_IN -p udp --dport 24999 -m comment --comment ctdrv-tw`,
		}, "\n")), nil
	}
	rx, tx, ok := ctWireBytes("tw", "udp", 24312)
	if !ok || rx != 1400000 || tx != 900000 {
		t.Fatalf("wire bytes = %d/%d ok=%v", rx, tx, ok)
	}
	// The tcp row must not leak into a udp filter (and vice versa).
	rx2, _, ok2 := ctWireBytes("tw", "tcp", 24312)
	if !ok2 || rx2 != 40000 {
		t.Fatalf("tcp filter = %d ok=%v", rx2, ok2)
	}
}

// TestCtunnelVersionReporting proves Describe reports the INSTALLED
// version (probed via `ctunnel-engine -version`) and falls back to the
// build pin honestly.
func TestCtunnelVersionReporting(t *testing.T) {
	ctSetTestEnv(t)
	// No cached binaries: the pin.
	ctVerMu.Lock()
	ctVerCached = ""
	ctVerMu.Unlock()
	_ = os.RemoveAll(ctEngineDir())
	if v := ctInstalledVersion(); v != ctPinnedVersion {
		t.Fatalf("empty cache version = %s, want pin %s", v, ctPinnedVersion)
	}
	// A cached binary that reports a version: Describe() mirrors it.
	origProbe := ctVersionProbe
	ctVersionProbe = func(binPath string) (string, error) { return "2.0.0", nil }
	t.Cleanup(func() { ctVersionProbe = origProbe })
	_ = os.MkdirAll(ctBinDir("2.0.0"), 0o700)
	_ = os.WriteFile(filepath.Join(ctBinDir("2.0.0"), "ctunnel-engine"), []byte("bin"), 0o755)
	if v := ctInstalledVersion(); v != "2.0.0" {
		t.Fatalf("installed version = %s, want 2.0.0", v)
	}
	d := NewCtunnelDriver()
	info := d.Describe()
	if info.Version != "2.0.0" {
		t.Fatalf("Describe version = %s, want the installed 2.0.0", info.Version)
	}
	// The params schema advertises the 49-method list.
	var schema map[string]any
	if err := json.Unmarshal(info.ParamsSchema, &schema); err != nil {
		t.Fatal(err)
	}
	methods, ok := schema["method"].([]any)
	if !ok || len(methods) != 49 {
		t.Fatalf("schema methods = %d (ok=%v)", len(methods), ok)
	}
	// A probe failure falls back to the recorded dir name, then the pin.
	ctVersionProbe = func(binPath string) (string, error) { return "", fmt.Errorf("no exec") }
	if v := ctInstalledVersion(); v != "2.0.0" {
		t.Fatalf("fallback version = %s, want the dir name", v)
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
	// L4 ForwardAddress: the engine serves the public port locally.
	pl := ctTestParams()
	pl.Method = "tcpmux"
	instL4 := engine.Instance{TunnelID: "ct3l4", LocalServer: "germany", RemoteServer: "iran",
		Params: infra.MustJSON(pl)}
	if err := d.Start(context.Background(), instL4); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Stop(instL4) })
	host, port, ok = d.ForwardAddress(instL4)
	if !ok || host != "127.0.0.1" || port != pl.PublicPort {
		t.Fatalf("L4 ForwardAddress = %s:%d ok=%v", host, port, ok)
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

// ---- small test helpers ---------------------------------------------------

func parseHexUint(s string) uint64 {
	s = strings.TrimPrefix(s, "0x")
	v := uint64(0)
	for i := 0; i < len(s); i++ {
		var h int
		switch {
		case s[i] >= '0' && s[i] <= '9':
			h = int(s[i] - '0')
		case s[i] >= 'a' && s[i] <= 'f':
			h = int(s[i]-'a') + 10
		default:
			return 0
		}
		v = v*16 + uint64(h)
	}
	return v
}
