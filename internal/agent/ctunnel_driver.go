package agent

// ctunnel_driver.go — engine driver for C-Tunnel (github.com/CIAUB/C-Tunnel,
// AGPL-3.0 — license verified from the upstream tree; the text ships inside
// every artifact via the packer). Exec-a-binary: Quantum never links the
// upstream packages, the AGPL binary runs as a separate process and its
// LICENSE + SOURCE.txt ride the artifact.
//
// PINNED UPSTREAM: v1.1.x. C-Tunnel is an Iran/kharej L3 tunnel appliance:
// a per-tunnel env file (/etc/ctunnel/tunnels/NAME.env shape) drives the
// userspace data-plane binary `ctunnel-engine` (Go 1.22, zero deps), which
// carries IP packets over AES-256-GCM UDP transports with protocol-header
// mimicry (DTLS 1.3 / QUIC / SRTP / WireGuard / DNSCrypt / NTP /
// OpenVPN-DCO / rudp-fec — shape mimicry, NOT real protocol handshakes).
//
// ROLE MAPPING (the subtle part — C-Tunnel's roles are decoupled from
// geography and its port forwards ALWAYS live on the ctunnel-"iran" role
// end, gated there in scripts/ctunnel-kernel.sh):
//
//	server_side end  → ctunnel ROLE=iran   → holds the PUBLIC port + the
//	                                          kernel DNAT/SNAT (this driver
//	                                          adds them via arg-list exec —
//	                                          the upstream kernel script is
//	                                          NOT used; see below)
//	other end        → ctunnel ROLE=kharej → runs the in-agent relay to the
//	                                          Iran-local target service
//
// direction = "reverse" (default; the Quantum engine contract): REVERSE=1,
// the kharej end (Iran) dials OUT to the foreign iran end — the frp shape
// ("in REVERSE mode the kharej server dials in and the iran server only
// listens, so iran never opens a connection to a foreign IP").
// direction = "direct": REVERSE=0, the iran-role end dials OUT and the
// public forwarded port lives on the IRAN side (public Iran port → foreign
// service). Both shapes dial outward from one end only.
//
// Port exposure WITHOUT the upstream kernel script: ctunnel forwards
// public ports with iptables DNAT+SNAT (scripts/ctunnel-kernel.sh). The
// driver replicates exactly those rules (arg-list exec through the
// frpIptables seam, comment-tagged ctdrv-<tunnelid> so Del removes
// exactly what Add created) and adds NOTHING else: DNAT public:<port> →
// <kharej tunnel IP>:<target port>, SNAT → the iran end's tunnel IP (the
// SNAT is what routes return packets back through the tunnel).
//
// The in-agent RELAY (the creative composition): C-Tunnel's forwards can
// only reach services bound to 0.0.0.0 or the tunnel IP — a 127.0.0.1-bound
// service is unreachable by kernel DNAT (martian route). Every other
// Quantum engine dials the Iran-local target from userspace, so the
// driver runs a small TCP+UDP relay on the kharej-role end: it listens on
// THAT end's own tunnel IP:<target port> and dials params.local_addr
// (127.0.0.1 included). The DNAT always targets the relay — uniform
// behavior, and Quantum's universal local_addr contract holds. The relay
// lives entirely inside the running instance (listeners close on Stop;
// zero goroutines when the engine has zero instances).
//
// Health (warmup gate, checklist item 11): the server_side end dials the
// kharej end's tunnel IP through the L3 tunnel (encrypted carrier → TUN →
// relay → target accept) and holds the connection open: EOF/RST within
// the probe window = dead path; hold-open = healthy. A dial alone proves
// nothing (the relay accepts before dialing the target).
//
// Counters: wire = iptables counter chains on the carrier UDP port
// (server_side end; CTDRV_ACCT_IN/OUT, comment-scoped per instance).
// Payload = the per-tunnel TUN interface counters (inner, decrypted
// bytes) via netdev — known on BOTH ends (each agent reports its own
// view). C-Tunnel v1.1.x has no per-instance machine-readable stats API
// (the web panel is cookie+CSRF human surface) — the TUN counters ARE the
// engine's own accounting, not a guess.
//
// IPv6 (documented honestly):
//   - carrier/underlay: the UDP-Crypt engine is hard-coded IPv4
//     (net.ListenUDP("udp4") / ResolveUDPAddr("udp4") upstream) — v6
//     underlay is NOT available for the userspace methods (the kernel L3
//     methods have v6 variants but need the root kernel script — rejected
//     for this driver; see the engine report).
//   - inner traffic: the tunnel is L3 point-to-point; inner v6 works when
//     the inner service and routes use it — UNVERIFIED in this phase (the
//     integration tests v4 end to end; v6 inner marked UNVERIFIED).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const ctunnelID = "ctunnel"

// ctPinnedVersion is the upstream CLI/env shape this driver renders
// (Describe() reports it; the artifact version param must match).
const ctPinnedVersion = "1.1.1"

// ctMethods — the userspace UDP-Crypt family (all AES-256-GCM with
// per-direction keys; the exact upstream KIND strings from
// pkg/catalog/catalog.go). Kernel L3/L2 methods are deliberately NOT
// exposed: they need scripts/ctunnel-kernel.sh (root shell script doing
// kernel mutations) — outside the Quantum driver contract.
var ctMethods = map[string]bool{
	"dtls-1.3":     true,
	"quic-v1":      true,
	"srtp-direct":  true,
	"wg-stealth":   true,
	"rudp-fec":     true,
	"dnscrypt-udp": true,
	"ntp-direct":   true,
	"openvpn-dco":  true,
}

type ctunnelParams struct {
	ServerSide  string `json:"server_side"`  // the end holding the PUBLIC port (ctunnel ROLE=iran; foreign for the default reverse shape)
	Version     string `json:"version"`      // artifact version (cache key), e.g. "1.1.1"
	Artifact    string `json:"artifact"`     // name template with {arch}
	SHA256Amd   string `json:"sha256_amd64"` // pinned fallback
	SHA256Arm   string `json:"sha256_arm64"`
	SigAmd      string `json:"signature_amd64"`
	SigArm      string `json:"signature_arm64"`
	Method      string `json:"method"`       // UDP-Crypt family (ctMethods)
	Direction   string `json:"direction"`    // "reverse" (default) | "direct"
	ForeignAddr string `json:"foreign_addr"` // the PEER's carrier address "host:port" (the dialing end dials it)
	CarrierPort int    `json:"carrier_port"` // UDP carrier port, panel-allocated (bound on the listening end)
	PublicPort  int    `json:"public_port"`  // PUBLIC forwarded port on the server_side end, panel-allocated
	LocalAddr   string `json:"local_addr"`   // target service "host:port" on the non-server_side end (relay dials it)
	Proto       string `json:"proto"`        // "tcp" (default) | "udp" | "both"
	Secret      string `json:"secret"`       // tunnel secret, 64 hex chars (32 bytes) — 0600 env file only, never logged
	Padding     int    `json:"padding"`      // 0-255 (upstream per-packet padding)
	MTU         int    `json:"mtu"`          // 0 → default 1400; allowed 1200-1500
}

func (p ctunnelParams) ctArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	return enginePinForArch(EnginePin{Version: p.Version, Artifact: p.Artifact,
		SHA256Amd: p.SHA256Amd, SHA256Arm: p.SHA256Arm, SigAmd: p.SigAmd, SigArm: p.SigArm})
}

func ctDefaultDirection(d string) string {
	if strings.TrimSpace(d) == "" {
		return "reverse"
	}
	return strings.ToLower(strings.TrimSpace(d))
}

func ctDefaultProto(p string) string {
	if strings.TrimSpace(p) == "" {
		return "tcp"
	}
	return strings.ToLower(strings.TrimSpace(p))
}

func ctValidateParams(p ctunnelParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("ctunnel: server_side required")
	}
	if err := backhaulValidateArtifactPins2(p.Version, p.Artifact, p.SHA256Amd, p.SigAmd, p.SHA256Arm, p.SigArm, ctunnelID); err != nil {
		return err
	}
	if !ctMethods[strings.ToLower(strings.TrimSpace(p.Method))] {
		return fmt.Errorf("ctunnel: method must be one of the userspace UDP-Crypt family (dtls-1.3, quic-v1, srtp-direct, wg-stealth, rudp-fec, dnscrypt-udp, ntp-direct, openvpn-dco)")
	}
	if d := ctDefaultDirection(p.Direction); d != "reverse" && d != "direct" {
		return fmt.Errorf("ctunnel: direction must be reverse or direct")
	}
	if pr := ctDefaultProto(p.Proto); pr != "tcp" && pr != "udp" && pr != "both" {
		return fmt.Errorf("ctunnel: proto must be tcp, udp or both")
	}
	if _, port, err := net.SplitHostPort(strings.TrimSpace(p.ForeignAddr)); err != nil || port == "" {
		return fmt.Errorf("ctunnel: foreign_addr must be host:port")
	}
	if p.ForeignAddr != strings.TrimSpace(p.ForeignAddr) || strings.ContainsAny(p.ForeignAddr, "\"'\\\n\r") {
		return fmt.Errorf("ctunnel: foreign_addr not config-safe")
	}
	if p.CarrierPort <= 0 || p.CarrierPort > 65535 {
		return fmt.Errorf("ctunnel: carrier_port out of range")
	}
	if p.PublicPort <= 0 || p.PublicPort > 65535 {
		return fmt.Errorf("ctunnel: public_port out of range")
	}
	if p.PublicPort == p.CarrierPort {
		return fmt.Errorf("ctunnel: public_port must differ from carrier_port")
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(p.LocalAddr)); err != nil ||
		p.LocalAddr != strings.TrimSpace(p.LocalAddr) || strings.ContainsAny(p.LocalAddr, "\"'\\\n\r") {
		return fmt.Errorf("ctunnel: local_addr must be a config-safe host:port")
	}
	// Secret: 64 hex chars (32 bytes) — the upstream key-derivation
	// consumes it from the env file; shape-guarded for the file format.
	if len(p.Secret) != 64 {
		return fmt.Errorf("ctunnel: secret must be 64 hex chars (32 bytes)")
	}
	if _, err := hex.DecodeString(p.Secret); err != nil {
		return fmt.Errorf("ctunnel: secret must be hex")
	}
	if p.Padding < 0 || p.Padding > 255 {
		return fmt.Errorf("ctunnel: padding must be 0-255 (0 = upstream default 16)")
	}
	if p.MTU < 0 || p.MTU > 1500 || (p.MTU > 0 && p.MTU < 1280) {
		return fmt.Errorf("ctunnel: mtu must be 1280-1500 (0 = upstream default 1500-overhead-padding)")
	}
	return nil
}

// ctResolveRole resolves this end's role through the enrollment name:
// the server_side end runs ctunnel's "iran" role (public port + forwards),
// the other end runs "kharej". Fail-closed without an identity.
func ctResolveRole(p ctunnelParams) (string, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("ctunnel: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return "iran", nil
	}
	return "kharej", nil
}

// ctDerive is the per-instance addressing derived deterministically from
// the TunnelID so BOTH ends agree without communication (same tunnel row
// reaches both agents): iface name, upstream INDEX, and the point-to-point
// 10.77.N.0/30 pair. The iran-role end takes .1, the kharej end .2 (the
// upstream convention: the iran-role end's script DNATs to TUN_REMOTE4 =
// the kharej end's .2).
type ctDerive struct {
	iface    string
	index    int
	selfTun  string
	peerTun  string
	selfTun6 string
	peerTun6 string
}

func ctDeriveFor(tunnelID, role string) ctDerive {
	sum := sha256.Sum256([]byte("quantum-ctunnel:" + tunnelID))
	iface := "ctq" + hex.EncodeToString(sum[0:4]) // 12 chars ≤ IFNAMSIZ 15
	index := 128 + int(sum[4])%100                // 128-227: disjoint from an operator's sequential ctunnel indexes
	d := ctDerive{iface: iface, index: index}
	d.selfTun = fmt.Sprintf("10.77.%d.2", index)
	d.peerTun = fmt.Sprintf("10.77.%d.1", index)
	d.selfTun6 = fmt.Sprintf("fd00:77:%x::2", index)
	d.peerTun6 = fmt.Sprintf("fd00:77:%x::1", index)
	if role == "iran" {
		d.selfTun, d.peerTun = fmt.Sprintf("10.77.%d.1", index), fmt.Sprintf("10.77.%d.2", index)
		d.selfTun6, d.peerTun6 = fmt.Sprintf("fd00:77:%x::1", index), fmt.Sprintf("fd00:77:%x::2", index)
	}
	return d
}

// ctEnvText renders the per-instance env file (the upstream env contract,
// pkg/tunnel/env.go key set — only the keys the UDP-Crypt engine reads,
// plus the TUN addressing the driver itself applies). Written 0600:
// SECRET rides here and nowhere else.
//
// REMOTE_IP semantics (cmd/ctunnel-engine/main.go loadConfig): required
// unless passive (REVERSE=1 && ROLE=iran); "0.0.0.0" means roam-only —
// the end learns its peer from the first authenticated packet (NAT
// roaming). reverse → the kharej end dials the foreign address, the iran
// end roams; direct → the iran end dials the foreign address, the kharej
// end roams.
func ctEnvText(p ctunnelParams, role, direction string, d ctDerive) []byte {
	reverse := "0"
	if direction == "reverse" {
		reverse = "1"
	}
	remoteIP := "0.0.0.0"
	if (role == "kharej") == (direction == "reverse") {
		host, _, _ := net.SplitHostPort(strings.TrimSpace(p.ForeignAddr))
		remoteIP = host
	}
	lines := []string{
		"NAME=qc-" + d.iface,
		fmt.Sprintf("INDEX=%d", d.index),
		"DEV=" + d.iface,
		"ROLE=" + role,
		"KIND=" + strings.ToLower(strings.TrimSpace(p.Method)),
		"LOCAL_IP=0.0.0.0",
		"REMOTE_IP=" + remoteIP,
		"TUN_LOCAL4=" + d.selfTun,
		"TUN_REMOTE4=" + d.peerTun,
		fmt.Sprintf("PORT=%d", p.CarrierPort),
		fmt.Sprintf("MTU=%d", ctDefaultMTU(p.Method, p.MTU, p.Padding)),
		"REVERSE=" + reverse,
		"SECRET=" + p.Secret,
		fmt.Sprintf("PADDING=%d", ctDefaultPadding(p.Padding)),
		// FORWARDS stays EMPTY: the upstream kernel script's DNAT is NOT
		// used — this driver owns the equivalent rules via arg-list exec
		// (ctForwardRulesAdd), comment-tagged and removed on Stop.
		"FORWARDS=",
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// ctTargetPort is the target port the DNAT and the relay use (the port
// part of local_addr; the relay dials the FULL local_addr — host included).
func ctTargetPort(p ctunnelParams) int {
	_, port, err := net.SplitHostPort(strings.TrimSpace(p.LocalAddr))
	if err != nil {
		return 0
	}
	n := 0
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return 0
		}
		n = n*10 + int(port[i]-'0')
		if n > 65535 {
			return 0
		}
	}
	return n
}

// ctEngineArgs is the headless spawn line of ctunnel-engine: the ONLY
// flag is -config <env file> (cmd/ctunnel-engine/main.go — no positional
// argv, no short form; -selftest/-version are not used at runtime).
func ctEngineArgs(envPath string) []string {
	return []string{"-config", envPath}
}

// ctIPCmd executes the interface-admin commands the upstream kernel
// script would run (arg-list exec, never a shell). The engine opens the
// TUN by name via TUNSETIFF and expects the interface to already exist
// with its address and MTU set (upstream error text: "is the interface
// created by ctunnel-kernel?") — the driver replicates exactly the
// script's setup commands and deletes the interface on Stop.
var ctIPCmd = func(args ...string) error {
	_, err := runCmdTimeout(10*time.Second, "ip", args...)
	return err
}

// ctIfaceUp replicates ctunnel-kernel.sh's TUN setup for the UDP-Crypt
// path (the engine does NOT create or address the interface itself):
//
//	ip tuntap add dev "$DEV" mode tun multi_queue   (fallback: without)
//	ip link set dev "$DEV" mtu "$MTU" txqueuelen 10000 up
//	ip addr add "$TUN_LOCAL4" peer "$TUN_REMOTE4/32" dev "$DEV"
//
// plus the v6 inner pair: the engine is family-agnostic (it seals
// whatever the TUN yields) but NOTHING upstream configures inner v6 for
// UDP-Crypt — the driver adds a deterministic ULA pair so inner IPv6
// works (see the IPv6 matrix in the engine report).
func ctIfaceUp(iface string, mtu int, selfTun, peerTun, selfTun6, peerTun6 string) error {
	if err := ctIPCmd("tuntap", "add", "dev", iface, "mode", "tun", "multi_queue"); err != nil {
		if err2 := ctIPCmd("tuntap", "add", "dev", iface, "mode", "tun"); err2 != nil {
			// An existing interface from a previous run is fine — the
			// engine re-attaches via TUNSETIFF.
			if !strings.Contains(err2.Error(), "already exists") {
				return fmt.Errorf("ctunnel: tuntap add: %v / %v", err, err2)
			}
		}
	}
	for _, cmd := range [][]string{
		{"link", "set", "dev", iface, "mtu", fmt.Sprint(mtu), "txqueuelen", "10000", "up"},
		{"addr", "add", selfTun, "peer", peerTun + "/32", "dev", iface},
		{"-6", "addr", "add", selfTun6 + "/128", "peer", peerTun6 + "/128", "dev", iface},
	} {
		if err := ctIPCmd(cmd...); err != nil {
			if strings.Contains(err.Error(), "already exists") ||
				strings.Contains(err.Error(), "File exists") {
				continue
			}
			_ = ctIfaceDel(iface)
			return fmt.Errorf("ctunnel: iface setup (%v): %w", cmd[0], err)
		}
	}
	return nil
}

// ctIfaceDel removes the TUN (Stop/Uninstall; absence tolerated).
func ctIfaceDel(iface string) error {
	return ctIPCmd("link", "del", "dev", iface)
}

// ctOverheads are the upstream per-method carrier overheads
// (pkg/catalog/catalog.go, bytes) — the MTU default derives as
// 1500 - overhead - padding, exactly the CLI's DefaultMTU formula.
var ctOverheads = map[string]int{
	"dtls-1.3":     66,
	"quic-v1":      64,
	"srtp-direct":  65,
	"wg-stealth":   61,
	"rudp-fec":     65,
	"dnscrypt-udp": 65,
	"ntp-direct":   61,
	"openvpn-dco":  61,
}

func ctDefaultPadding(pad int) int {
	if pad <= 0 {
		return 16 // the upstream CLI default for the UDP-Crypt family
	}
	if pad > 255 {
		return 255
	}
	return pad
}

func ctDefaultMTU(method string, mtu, padding int) int {
	if mtu > 0 {
		return mtu
	}
	overhead, ok := ctOverheads[strings.ToLower(strings.TrimSpace(method))]
	if !ok {
		overhead = 66
	}
	v := 1500 - overhead - ctDefaultPadding(padding)
	if v < 1280 {
		v = 1280
	}
	return v
}

// ctComment is the per-instance iptables comment tag.
func ctComment(tunnelID string) string { return "ctdrv-" + tunnelID }

// ctSysctl executes host sysctls (seam-able; the integration test routes
// it through the server namespace). Upstream parity: the kernel script
// sets net.ipv4.ip_forward=1 before adding the forward rules.
var ctSysctl = func(args ...string) error {
	_, err := runCmdTimeout(10*time.Second, "sysctl", args...)
	return err
}

// ctProtosFor expands the proto param into the iptables protocol list.
func ctProtosFor(proto string) []string {
	switch proto {
	case "udp":
		return []string{"udp"}
	case "both":
		return []string{"tcp", "udp"}
	}
	return []string{"tcp"}
}

// ctForwardRulesAdd installs the PUBLIC-PORT rule set on the iran-role
// end (arg-list exec only — the upstream kernel script is never run),
// replicating scripts/ctunnel-kernel.sh's fw_apply for ONE tunnel:
//
//	iptables -t nat -A PREROUTING -p <p> --dport <public> -m addrtype
//	    --dst-type LOCAL -m comment --comment <tag> -j DNAT
//	    --to-destination <peerTun>:<target>
//	iptables -t nat -A POSTROUTING -d <peerTun>/32 -m comment
//	    --comment <tag> -j SNAT --to-source <selfTun>
//	iptables -I FORWARD -d <peerTun>/32 -m comment --comment <tag> -j ACCEPT
//	iptables -I FORWARD -s <peerTun>/32 -m comment --comment <tag> -j ACCEPT
//	sysctl -qw net.ipv4.ip_forward=1
//
// The DNAT'd packet dst = the PEER's tunnel IP — routed THROUGH the tun
// (not local), so ip_forward and the FORWARD accepts are required (the
// delivery into the target service happens on the far end's INPUT via
// the relay). Exactly-one via -C before Add; Del removes by full spec.
func ctForwardRulesAdd(tunnelID, iface, proto string, publicPort, targetPort int, selfTun, peerTun string) error {
	_ = iface
	if err := ctSysctl("-qw", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("ctunnel: ip_forward sysctl: %w", err)
	}
	for _, add := range ctForwardRuleArgs(tunnelID, proto, publicPort, targetPort, selfTun, peerTun) {
		chk := append([]string{"-C"}, add[1:]...)
		if _, err := frpIptables(chk...); err != nil {
			if _, err := frpIptables(add...); err != nil {
				return fmt.Errorf("ctunnel: forward rule (%s %s): %w", add[2], add[3], err)
			}
		}
	}
	return nil
}

// ctForwardRuleArgs renders the PUBLIC-PORT rule set (with real actions)
// for the iran-role end. Del swaps the -A/-I action for -D so exactly
// what Add created is removed.
func ctForwardRuleArgs(tunnelID, proto string, publicPort, targetPort int, selfTun, peerTun string) [][]string {
	cmt := ctComment(tunnelID)
	out := make([][]string, 0, len(ctProtosFor(proto))*4)
	for _, pr := range ctProtosFor(proto) {
		out = append(out,
			[]string{"-t", "nat", "-A", "PREROUTING", "-p", pr, "--dport", fmt.Sprint(publicPort),
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-m", "comment", "--comment", cmt, "-j", "DNAT",
				"--to-destination", net.JoinHostPort(peerTun, fmt.Sprint(targetPort))},
			[]string{"-t", "nat", "-A", "POSTROUTING", "-d", peerTun + "/32",
				"-m", "comment", "--comment", cmt, "-j", "SNAT", "--to-source", selfTun},
			[]string{"-I", "FORWARD", "-d", peerTun + "/32",
				"-m", "comment", "--comment", cmt, "-j", "ACCEPT"},
			[]string{"-I", "FORWARD", "-s", peerTun + "/32",
				"-m", "comment", "--comment", cmt, "-j", "ACCEPT"})
	}
	return out
}

// ctForwardRulesDel removes exactly this instance's rules (comment-
// scoped; errors on absent rules are non-fatal here — Stop must always
// succeed in unwinding).
func ctForwardRulesDel(tunnelID, iface, proto string, publicPort, targetPort int, selfTun, peerTun string) {
	for _, add := range ctForwardRuleArgs(tunnelID, proto, publicPort, targetPort, selfTun, peerTun) {
		del := append([]string{"-D"}, add[1:]...)
		_, _ = frpIptables(del...)
	}
}

// ctRelayInputRulesAdd/Del manage the kharej-role end's INPUT accepts for
// the relay delivery: packets arriving ON the tunnel interface addressed
// to the end's own tunnel IP:target must reach the in-agent relay even
// on hardened (drop-all INPUT) hosts — inserted FIRST, comment-tagged.
func ctRelayInputRuleArgs(tunnelID, iface, proto string, targetPort int) [][]string {
	cmt := ctComment(tunnelID)
	out := make([][]string, 0, len(ctProtosFor(proto)))
	for _, pr := range ctProtosFor(proto) {
		out = append(out, []string{"-I", "INPUT", "-i", iface, "-p", pr,
			"--dport", fmt.Sprint(targetPort), "-j", "ACCEPT",
			"-m", "comment", "--comment", cmt})
	}
	return out
}

func ctRelayInputRulesAdd(tunnelID, iface, proto string, targetPort int) error {
	for _, add := range ctRelayInputRuleArgs(tunnelID, iface, proto, targetPort) {
		chk := append([]string{"-C"}, add[1:]...)
		if _, err := frpIptables(chk...); err != nil {
			if _, err := frpIptables(add...); err != nil {
				return fmt.Errorf("ctunnel: relay INPUT rule: %w", err)
			}
		}
	}
	return nil
}

func ctRelayInputRulesDel(tunnelID, iface, proto string, targetPort int) {
	for _, add := range ctRelayInputRuleArgs(tunnelID, iface, proto, targetPort) {
		del := append([]string{"-D"}, add[1:]...)
		_, _ = frpIptables(del...)
	}
}

// Wire accounting on the carrier UDP port (server_side end): own chains,
// same shape as the FRP counters (per-instance comment-scoped rules read
// back from iptables-save -c).
const (
	ctAcctIn  = "CTDRV_ACCT_IN"
	ctAcctOut = "CTDRV_ACCT_OUT"
)

func ctWireRulesEnsure() error {
	if _, err := frpIptables("-N", ctAcctIn); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return err
	}
	if _, err := frpIptables("-N", ctAcctOut); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return err
	}
	if _, err := frpIptables("-C", "INPUT", "-j", ctAcctIn); err != nil {
		if _, err := frpIptables("-A", "INPUT", "-j", ctAcctIn); err != nil {
			return err
		}
	}
	if _, err := frpIptables("-C", "OUTPUT", "-j", ctAcctOut); err != nil {
		if _, err := frpIptables("-A", "OUTPUT", "-j", ctAcctOut); err != nil {
			return err
		}
	}
	return nil
}

func ctWireRulesAdd(tunnelID string, carrierPort int) error {
	if err := ctWireRulesEnsure(); err != nil {
		return err
	}
	cmt := ctComment(tunnelID)
	port := fmt.Sprint(carrierPort)
	if _, err := frpIptables("-A", ctAcctIn, "-p", "udp", "--dport", port,
		"-m", "comment", "--comment", cmt); err != nil {
		return err
	}
	if _, err := frpIptables("-A", ctAcctOut, "-p", "udp", "--sport", port,
		"-m", "comment", "--comment", cmt); err != nil {
		return err
	}
	return nil
}

func ctWireRulesDel(tunnelID string, carrierPort int) {
	cmt := ctComment(tunnelID)
	port := fmt.Sprint(carrierPort)
	_, _ = frpIptables("-D", ctAcctIn, "-p", "udp", "--dport", port, "-m", "comment", "--comment", cmt)
	_, _ = frpIptables("-D", ctAcctOut, "-p", "udp", "--sport", port, "-m", "comment", "--comment", cmt)
}

// ctWireBytes reads the instance's carrier counters (iptables-save -c,
// exact bytes; same parse shape as frpWireBytes).
func ctWireBytes(tunnelID string, carrierPort int) (rx, tx uint64, ok bool) {
	out, err := frpIptablesSave()
	if err != nil {
		return 0, 0, false
	}
	cmt := ctComment(tunnelID)
	rng := fmt.Sprint(carrierPort)
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, cmt) {
			continue
		}
		var isRx bool
		switch {
		case strings.Contains(line, "--dport "+rng+" "):
			isRx = true
		case strings.Contains(line, "--sport "+rng+" "):
		default:
			continue
		}
		i := strings.LastIndex(line, "[")
		j := strings.LastIndex(line, "]")
		if i < 0 || j <= i {
			continue
		}
		var v uint64
		parsed := false
		for _, tok := range strings.Fields(line[i+1 : j]) {
			parts := strings.SplitN(tok, ":", 2)
			if len(parts) != 2 {
				continue
			}
			n, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				continue
			}
			v, parsed = n, true
			break
		}
		if !parsed {
			continue
		}
		if isRx {
			rx += v
		} else {
			tx += v
		}
		ok = true
	}
	return rx, tx, ok
}

// ctRelay is the in-agent TCP+UDP relay on the kharej-role end: listens on
// the end's own tunnel IP:<target port>, dials params.local_addr. The
// bind retries with capped backoff (the TUN address exists only after the
// engine process is up). Zero goroutines after Close.
type ctRelay struct {
	mu         sync.Mutex
	closed     bool
	stop       <-chan struct{}
	tcpLn      net.Listener
	udpConn    *net.UDPConn
	udpWG      sync.WaitGroup
	dialTarget string
	wg         sync.WaitGroup
}

// ctStartRelay starts the requested listeners (proto tcp|udp|both) and
// returns immediately; binds happen on a retry goroutine and surface in
// Ready(). Close stops everything.
func ctStartRelay(stop <-chan struct{}, bindAddr, targetAddr, proto string) *ctRelay {
	r := &ctRelay{stop: stop, dialTarget: targetAddr}
	if proto == "tcp" || proto == "both" {
		r.wg.Add(1)
		go r.serveTCP(bindAddr)
	}
	if proto == "udp" || proto == "both" {
		r.wg.Add(1)
		go r.serveUDP(bindAddr)
	}
	return r
}

// Ready reports whether every requested listener is bound.
func (r *ctRelay) Ready(wantTCP, wantUDP bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if wantTCP && r.tcpLn == nil {
		return false
	}
	if wantUDP && r.udpConn == nil {
		return false
	}
	return true
}

func (r *ctRelay) closing() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// bindTCP retries the listen bind with capped backoff until it succeeds
// or the relay closes (the TUN address exists only once the engine is up).
func (r *ctRelay) bindTCP(addr string) net.Listener {
	backoff := 300 * time.Millisecond
	for {
		if r.closing() {
			return nil
		}
		select {
		case <-r.stop:
			return nil
		case <-time.After(backoff):
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
		if ln, err := net.Listen("tcp", addr); err == nil {
			return ln
		}
	}
}

func (r *ctRelay) serveTCP(bindAddr string) {
	defer r.wg.Done()
	for {
		ln := r.bindTCP(bindAddr)
		if ln == nil {
			return
		}
		r.mu.Lock()
		if r.closed {
			ln.Close()
			r.mu.Unlock()
			return
		}
		r.tcpLn = ln
		r.mu.Unlock()
		for {
			conn, err := ln.Accept()
			if err != nil {
				r.mu.Lock()
				r.tcpLn = nil
				r.mu.Unlock()
				select {
				case <-r.stop:
					return
				default:
				}
				break // rebind
			}
			r.wg.Add(1)
			go r.pipeTCP(conn)
		}
	}
}

// pipeTCP dials the local target for one accepted connection; a failed
// dial closes the upstream side immediately (the health gate reads that
// as EOF = unhealthy).
func (r *ctRelay) pipeTCP(upstream net.Conn) {
	defer r.wg.Done()
	select {
	case <-r.stop:
		upstream.Close()
		return
	default:
	}
	downstream, err := net.DialTimeout("tcp", r.dialTarget, 3*time.Second)
	if err != nil {
		upstream.Close()
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(downstream, upstream); done <- struct{}{} }()
	go func() { _, _ = io.Copy(upstream, downstream); done <- struct{}{} }()
	<-done
	upstream.Close()
	downstream.Close()
	<-done
}

func (r *ctRelay) serveUDP(bindAddr string) {
	defer r.wg.Done()
	for {
		// A UDP socket bound to the tunnel IP: the address must exist, so
		// retry until the engine brings the TUN up.
		var conn *net.UDPConn
		backoff := 300 * time.Millisecond
		for conn == nil {
			if r.closing() {
				return
			}
			select {
			case <-r.stop:
				return
			case <-time.After(backoff):
			}
			if backoff < 2*time.Second {
				backoff *= 2
			}
			ra, err := net.ResolveUDPAddr("udp", bindAddr)
			if err != nil {
				continue
			}
			c, err := net.ListenUDP("udp", ra)
			if err == nil {
				conn = c
			}
		}
		r.mu.Lock()
		if r.closed {
			conn.Close()
			r.mu.Unlock()
			return
		}
		r.udpConn = conn
		r.mu.Unlock()
		r.pumpUDP(conn)
		r.mu.Lock()
		r.udpConn = nil
		r.mu.Unlock()
		select {
		case <-r.stop:
			return
		default:
		}
	}
}

// pumpUDP is the session-mapped UDP proxy: one upstream socket per tunnel
// side source; replies ride the same session socket. Sessions close after
// 60s idle, and ALL of them close when the pump returns (Close/Stop — no
// goroutine or socket outlives the instance).
func (r *ctRelay) pumpUDP(conn *net.UDPConn) {
	defer conn.Close()
	type session struct {
		conn *net.UDPConn
		last time.Time
	}
	var (
		mu       sync.Mutex
		sessions = map[string]*session{}
	)
	closeAll := func(idle time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		for k, s := range sessions {
			if idle == 0 || time.Since(s.last) > idle {
				s.conn.Close()
				delete(sessions, k)
			}
		}
	}
	defer closeAll(0)
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	go func() {
		for range tick.C {
			if r.closing() {
				return
			}
			closeAll(60 * time.Second)
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		key := src.String()
		mu.Lock()
		s := sessions[key]
		if s == nil {
			up, derr := net.Dial("udp", r.dialTarget)
			if derr != nil {
				mu.Unlock()
				continue
			}
			s = &session{conn: up.(*net.UDPConn), last: time.Now()}
			sessions[key] = s
			go func(s *session, src *net.UDPAddr) {
				buf := make([]byte, 65535)
				for {
					n, err := s.conn.Read(buf)
					if err != nil {
						return
					}
					if _, werr := conn.WriteToUDP(buf[:n], src); werr != nil {
						return
					}
				}
			}(s, src)
		}
		s.last = time.Now()
		mu.Unlock()
		if _, werr := s.conn.Write(buf[:n]); werr != nil {
			mu.Lock()
			s.conn.Close()
			delete(sessions, key)
			mu.Unlock()
		}
	}
}

// Close stops every listener and pending goroutine.
func (r *ctRelay) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	ln := r.tcpLn
	uc := r.udpConn
	r.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	if uc != nil {
		uc.Close()
	}
}

// ctInstState is one RUNNING instance's state.
// ctInstState is one RUNNING instance's state. The proc/stop/binPath
// base rides the shared engineInst (A1); envPath stays its own field so
// Stop's teardown removes it in the exact original order (AFTER the
// rules are dropped — it holds the SECRET).
type ctInstState struct {
	engineInst
	params  ctunnelParams
	role    string // ctunnel role: "iran" (server_side end) | "kharej"
	dir     string
	iface   string
	selfTun string
	peerTun string
	envPath string
	relay   *ctRelay // kharej end only
}

// CtunnelDriver implements engine.Driver for C-Tunnel.
type CtunnelDriver struct {
	runs *instTable[ctInstState]
}

func NewCtunnelDriver() *CtunnelDriver { return &CtunnelDriver{runs: newInstTable[ctInstState]()} }

func (d *CtunnelDriver) ID() string { return ctunnelID }

func (d *CtunnelDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: ctunnelID, Version: ctPinnedVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","method":"dtls-1.3","direction":"reverse","foreign_addr":"host:port","carrier_port":0,"public_port":0,"local_addr":"127.0.0.1:5201","proto":"tcp","secret":"64-hex","padding":0,"mtu":1400}`)}
}

// EnsureBinary: the download happens in Start via ctEnsureBinary
// (manifest-first, pinned fallback) with the resolved coordinates.
func (d *CtunnelDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *CtunnelDriver) Validate(params json.RawMessage) error {
	var p ctunnelParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("ctunnel: engine_params: %w", err)
	}
	return ctValidateParams(p)
}

func ctEngineDir() string { return engineEngineDir(ctunnelID) }
func ctBinDir(version string) string {
	return filepath.Join(ctEngineDir(), "bin", version)
}
func ctEnvPath(tunnelID string) string {
	return filepath.Join(ctEngineDir(), "instances", tunnelID+".env")
}

// ctEnsureBinary: manifest-first (engine "ctunnel"), pinned fallback —
// the wstunnel shape. The artifact carries ONE binary: ctunnel-engine
// (the userspace data plane; the ctunnel CLI/panel is not shipped).
func ctEnsureBinary(ctx context.Context, p ctunnelParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("ctunnel: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.ctArtifactPin(); pinErr == nil && engineCacheHit(ctBinDir(p.Version), pinnedSHA, []string{"ctunnel-engine"}) {
		return ctBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("ctunnel: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := enginePinOrManifest(ctx, ident, ctunnelID,
		EnginePin{Version: p.Version, Artifact: p.Artifact, SHA256Amd: p.SHA256Amd, SHA256Arm: p.SHA256Arm,
			SigAmd: p.SigAmd, SigArm: p.SigArm},
		func() (string, string, string, error) { return p.ctArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := ctBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"ctunnel-engine"}) {
		return dir, nil
	}
	body, err := frpFetchArtifact(ctx, downloadURL)
	if err != nil {
		return "", err
	}
	if err := engine.VerifyArtifact(body, sha256Hex, sigB64, key); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("ctunnel: cache dir: %w", err)
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"ctunnel-engine": true}); err != nil {
		return "", err
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("ctunnel: cache marker: %w", err)
	}
	return dir, nil
}

// ctParamsEqual is the Reload no-op comparison. A1: delegates to the
// shared engineParamsEqual (the mustJSON string compare returned the
// same boolean for every value ctunnelParams can carry).
func ctParamsEqual(a, b ctunnelParams) bool {
	return engineParamsEqual(a, b)
}

var ctSpawn = func(binPath string, args []string) (frpProcess, error) {
	cmd := exec.Command(binPath, args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("ctunnel: start %s: %w", binPath, err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

// Start implements engine.Driver: validate → role → derive → verified
// binary → 0600 env file → spawn → supervise → (iran end) DNAT/SNAT +
// carrier accounting; (kharej end) in-agent relay.
func (d *CtunnelDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p ctunnelParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("ctunnel: engine_params: %w", err)
	}
	if err := ctValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("ctunnel: invalid tunnel id %q", inst.TunnelID)
	}
	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if ctParamsEqual(prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}
	role, err := ctResolveRole(p)
	if err != nil {
		return err
	}
	dir := ctDeriveFor(inst.TunnelID, role)
	binDir, err := ctEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "ctunnel-engine")
	direction := ctDefaultDirection(p.Direction)
	proto := ctDefaultProto(p.Proto)
	if err := os.MkdirAll(filepath.Dir(ctEnvPath(inst.TunnelID)), 0o700); err != nil {
		return fmt.Errorf("ctunnel: instance dir: %w", err)
	}
	envPath := ctEnvPath(inst.TunnelID)
	// 0600: the env file carries SECRET.
	if err := os.WriteFile(envPath, ctEnvText(p, role, direction, dir), 0o600); err != nil {
		return fmt.Errorf("ctunnel: write env: %w", err)
	}
	// The engine attaches to an EXISTING TUN (TUNSETIFF); the interface,
	// its addresses and its MTU are the driver's job (the upstream kernel
	// script's setup, replicated via arg-list exec).
	if err := ctIfaceUp(dir.iface, ctDefaultMTU(p.Method, p.MTU, p.Padding),
		dir.selfTun, dir.peerTun, dir.selfTun6, dir.peerTun6); err != nil {
		_ = os.Remove(envPath)
		return err
	}
	proc, err := ctSpawn(binPath, ctEngineArgs(envPath))
	if err != nil {
		_ = os.Remove(envPath)
		_ = ctIfaceDel(dir.iface)
		return err
	}
	st := &ctInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		binPath: binPath}, params: p, role: role, dir: direction, iface: dir.iface,
		selfTun: dir.selfTun, peerTun: dir.peerTun, envPath: envPath}
	target := strings.TrimSpace(p.LocalAddr)
	targetPort := ctTargetPort(p)
	if role == "kharej" {
		st.relay = ctStartRelay(st.stop, net.JoinHostPort(dir.selfTun, fmt.Sprint(targetPort)), target, proto)
	}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, binPath, "", func(b, _ string) (frpProcess, error) {
		return ctSpawn(b, ctEngineArgs(envPath))
	})
	if role == "iran" {
		if err := ctForwardRulesAdd(inst.TunnelID, dir.iface, proto, p.PublicPort, targetPort, dir.selfTun, dir.peerTun); err != nil {
			fmt.Fprintf(os.Stderr, "ctunnel: forward rules unavailable: %v\n", err)
		}
		if err := ctWireRulesAdd(inst.TunnelID, p.CarrierPort); err != nil {
			fmt.Fprintf(os.Stderr, "ctunnel: wire accounting unavailable: %v\n", err)
		}
	} else {
		// The relay's delivery: packets arriving on the tunnel interface
		// for the end's own tunnel IP:target must reach the in-agent relay.
		if err := ctRelayInputRulesAdd(inst.TunnelID, dir.iface, proto, targetPort); err != nil {
			fmt.Fprintf(os.Stderr, "ctunnel: relay INPUT rule unavailable: %v\n", err)
		}
	}
	return nil
}

// Stop implements engine.Driver: the shared teardown order with the
// ctunnel-specific hook — relay closed, the role's nft/iptables rules
// dropped, THEN the env file removed (it holds the SECRET; the order is
// the original one), then the TUN deleted (the engine re-attaches on
// respawn; ctIfaceUp tolerates an existing interface).
func (d *CtunnelDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.relay != nil {
			st.relay.Close()
		}
		if st.role == "iran" {
			ctForwardRulesDel(inst.TunnelID, st.iface, ctDefaultProto(st.params.Proto),
				st.params.PublicPort, ctTargetPort(st.params), st.selfTun, st.peerTun)
			ctWireRulesDel(inst.TunnelID, st.params.CarrierPort)
		} else {
			ctRelayInputRulesDel(inst.TunnelID, st.iface, ctDefaultProto(st.params.Proto),
				ctTargetPort(st.params))
		}
		_ = os.Remove(st.envPath)
		_ = ctIfaceDel(st.iface)
	})
	return nil
}

// Reload implements engine.Driver: equal params are a no-op, anything
// else is a restart (C-Tunnel has no live reload).
func (d *CtunnelDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, ctunnelID, inst.TunnelID, inst.Params,
		func(st *ctInstState) ctunnelParams { return st.params }, ctParamsEqual)
}

// ctProbeThrough performs the through-tunnel probe: dial the kharej end's
// tunnel IP:target port (traverses the encrypted carrier → TUN → relay →
// target accept) and hold: EOF/RST within the window = dead path (the
// relay closes instantly when the target dial fails); hold-open = healthy.
func ctProbeThrough(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("tunnel dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil || isNetTimeout(err) {
		// Bytes back = a real service; hold-open (read timeout) = the
		// relay's target dial succeeded and the service holds. Both prove
		// the full path.
		return nil
	}
	return fmt.Errorf("path closed before answering (target unreachable): %w", err)
}

func isNetTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// ctProbeDial seams the through-probe (the integration test routes it
// through the server namespace; hermetic tests stub it — a lab host may
// route the 10.77/16 tunnel range somewhere real).
var ctProbeDial = ctProbeThrough

// Health implements engine.Driver. iran end: the through-tunnel probe
// (warmup gate). kharej end: process alive + relay bound (+ TUN iface for
// udp-only, where no TCP probe exists — honestly labeled).
func (d *CtunnelDriver) Health(inst engine.Instance) engine.Health {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Health{OK: false, Detail: "not running", LatencyMs: -1}
	}
	select {
	case <-st.current().Done():
		return engine.Health{OK: false, Detail: "process exited", LatencyMs: -1}
	default:
	}
	proto := ctDefaultProto(st.params.Proto)
	if st.role != "iran" {
		wantTCP := proto == "tcp" || proto == "both"
		wantUDP := proto == "udp" || proto == "both"
		detail := "ctunnel running"
		if st.relay != nil {
			if !st.relay.Ready(wantTCP, wantUDP) {
				return engine.Health{OK: false, Detail: "relay not bound yet (waiting for the tunnel interface)", LatencyMs: -1}
			}
			detail = "ctunnel running; relay bound"
		}
		return engine.Health{OK: true, Detail: detail, LatencyMs: -1}
	}
	targetPort := ctTargetPort(st.params)
	start := time.Now()
	if err := ctProbeDial(net.JoinHostPort(st.peerTun, fmt.Sprint(targetPort)), 3*time.Second); err != nil {
		return engine.Health{OK: false, Detail: "through-tunnel probe failed: " + err.Error(),
			LatencyMs: float64(time.Since(start).Milliseconds())}
	}
	return engine.Health{OK: true, Detail: "through-tunnel probe ok", LatencyMs: float64(time.Since(start).Milliseconds())}
}

// Counters implements engine.Driver: wire (carrier UDP, iptables) on the
// iran end; payload = the per-tunnel TUN interface counters (inner bytes)
// on BOTH ends via netdev — each agent reports its own view honestly.
func (d *CtunnelDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if st.role == "iran" {
		if rx, tx, ok := ctWireBytes(inst.TunnelID, st.params.CarrierPort); ok {
			out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
		}
	}
	if data, err := agentReadNetDev(); err == nil {
		if c, ok := agentParseNetDev(data)[st.iface]; ok {
			out.PayloadRx, out.PayloadTx, out.PayloadKnown = c.Rx, c.Tx, true
		}
	}
	return out
}

// Uninstall implements engine.Driver: stop every instance, then remove
// the binary cache + instance envs + rules. Idle = zero processes, zero
// files, zero goroutines.
func (d *CtunnelDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, ctEngineDir())
	return nil
}

// ForwardAddress implements engine.ForwardAddresser: the through-tunnel
// address where the far target answers from THIS end. iran end → the
// kharej tunnel IP (through the tunnel); kharej end → the loopback target.
func (d *CtunnelDriver) ForwardAddress(inst engine.Instance) (string, int, bool) {
	var p ctunnelParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return "", 0, false
	}
	role, err := ctResolveRole(p)
	if err != nil {
		return "", 0, false
	}
	targetPort := ctTargetPort(p)
	if targetPort == 0 {
		return "", 0, false
	}
	if role == "iran" {
		return ctDeriveFor(inst.TunnelID, role).peerTun, targetPort, true
	}
	if h, _, err := net.SplitHostPort(strings.TrimSpace(p.LocalAddr)); err == nil && h != "" {
		return h, targetPort, true
	}
	return "127.0.0.1", targetPort, true
}

// Compile-time checks.
var (
	_ engine.Driver           = (*CtunnelDriver)(nil)
	_ engine.ForwardAddresser = (*CtunnelDriver)(nil)
)
