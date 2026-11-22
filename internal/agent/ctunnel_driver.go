package agent

// ctunnel_driver.go — engine driver for C-Tunnel v2.x (github.com/CIAUB/C-Tunnel,
// AGPL-3.0 — license verified from the upstream tree; the text ships inside
// every artifact via the packer). Exec-a-binary: Quantum never links the
// upstream packages, the AGPL binary runs as a separate process and its
// LICENSE + SOURCE.txt ride the artifact.
//
// PINNED UPSTREAM: v2.0.0 (the v2 replaces v1.1.1 completely — the
// ctunnel-v1.1.1 core release was removed by human order; this driver
// upgraded in the same wave, AGENT-30). C-Tunnel v2 is an Iran/kharej
// tunnel appliance with 49 methods across 6 families:
//
//	kernel-l3 ×16  sit/ipip/gre/ip6gre/ipip6/ip6ip6/6to4/6to4-gre/
//	               wireguard/xfrm-ipsec/fou-gre/gue-ipip/ecmp-lanes/
//	               bareudp/xgre/xgre-ip        (kernel tunnel devices)
//	kernel-l2  ×7  eoip/etherip (userspace TAP bridge) + gretap/ip6gretap/
//	               vxlan/geneve/l2tpv3          (kernel ethernet devices)
//	udp-crypt ×11  dtls-1.3/quic-v1/srtp-direct/wg-stealth/rudp-fec/
//	               dnscrypt-udp/ntp-direct/openvpn-dco/stun-turn/
//	               gtp-u/esp-udp                (TUN + ctunnel-engine)
//	stealth    ×2  faketcp/icmp                 (TUN + engine, raw carriers)
//	reverse-l4 ×9  tcp/tcpmux/pck/ws/wsmux/wss/wssmux/udp/udpmux
//	                                            (engine port-forwarding only)
//	gaming     ×4  game-udp/game-fec/game-dup (TUN + engine) +
//	               game-kcp (L4 port-forwarding)
//
// WHO RUNS WHAT (from their docs/ARCHITECTURE.md + scripts/ctunnel-kernel.sh
// + cmd/ctunnel-engine):
//   - userspace kinds: ctunnel-engine (TUN⇄UDP / TUN⇄raw / TAP⇄raw / L4);
//     the driver creates the TUN/TAP + addresses exactly like their kernel
//     script does for those kinds, then spawns the engine with the v2 env
//     file (-config).
//   - kernel kinds, DIRECT direction: the driver performs the kernel ops
//     itself via ARG-LIST exec (their ctunnel-kernel.sh is NOT used and NOT
//     shipped — it does non-additive work: fw_clear sweeps, global sysctl
//     writes, qdisc replaces on unknown devices). Quantum rules: additive
//     only, comment-tagged `ctdrv-<tunnelid>`, teardown removes exactly
//     what this instance created (per-tunnel isolation). No engine process.
//   - kernel kinds, REVERSE direction: their reverse-carrier design — the
//     engine carries the tunnel over an FRP-style encrypted TCP carrier:
//     the driver creates the carrier TUN `<dev>-r` (172.31.<index>.1/.2,
//     the engine opens <DEV>-r itself, revcarrier.go:74), then the KERNEL
//     device rides that TUN (its underlay), then spawns the engine with
//     REVERSE=1. Iran only listens; the kharej end dials out — the Quantum
//     "one end dials outward" contract holds.
//   - wireguard: kernel-only both directions (their script's shape): the
//     endpoint argument flips by direction; no engine.
//   - reverse-l4 + game-kcp: engine-only, NO interface, NO iptables — the
//     engine binds the public forwards itself (TCP+UDP per port) and the
//     carrier-dialing end delivers to 127.0.0.1:<target> (pkg/l4/client.go).
//     Quantum direction mapping: reverse only — direct L4 would bind the
//     public port on the non-server_side end (the listening side), which
//     breaks the Quantum public-port contract; validated fail-closed.
//
// ROLE MAPPING (unchanged from v1 — C-Tunnel's roles are decoupled from
// geography and its port forwards ALWAYS live on the ctunnel-"iran" role
// end):
//
//	server_side end  → ctunnel ROLE=iran   → holds the PUBLIC port + the
//	                                          forward rules / engine listeners
//	other end        → ctunnel ROLE=kharej → runs the in-agent relay to the
//	                                          Iran-local target service (TUN
//	                                          families) or dials the carrier
//
// direction = "reverse" (default; the Quantum engine contract): REVERSE=1,
// the kharej end (Iran) dials OUT to the foreign iran end. direction =
// "direct": REVERSE=0, the iran-role end dials OUT and the public forwarded
// port lives on the IRAN side. Both shapes dial outward from one end only.
//
// Port exposure WITHOUT their kernel script (TUN + kernel families): the
// driver replicates the script's fw_apply for ONE tunnel — DNAT
// public:<port> → <peer tunnel IP>:<target>, SNAT → the iran end's tunnel
// IP, FORWARD accepts, INPUT accept for the relay delivery, MSS clamp on
// the tunnel interface, and the raw-protocol conntrack skip — ALL comment-
// tagged ctdrv-<tunnelid> so Del removes exactly what Add created. For the
// two IPv6-inner-only methods (sit, ip6ip6) the same composition runs via
// ip6tables + the v6 inner pair (their inner addressing for those kinds is
// v6-only by design).
//
// The in-agent RELAY (unchanged from v1): C-Tunnel's forwards can only
// reach services bound to 0.0.0.0 or the tunnel IP — a 127.0.0.1-bound
// service is unreachable by kernel DNAT (martian route). Every other
// Quantum engine dials the Iran-local target from userspace, so the driver
// runs a small TCP+UDP relay on the kharej-role end (TUN + kernel families
// with forwards): it listens on THAT end's own tunnel IP:<target port> and
// dials params.local_addr (127.0.0.1 included). L4 families do NOT use the
// relay — the engine itself dials 127.0.0.1:<target>, so local_addr must be
// loopback-bound there (validated).
//
// Health (warmup gate): TUN/kernel families — the server_side end dials the
// kharej end's tunnel IP through the tunnel (encrypted carrier → TUN →
// relay → target accept) and holds the connection open: EOF/RST within the
// probe window = dead path. L4 families — the server_side end dials its own
// 127.0.0.1:<public_port> (the engine listener); every byte then rides the
// full path to the kharej end's 127.0.0.1:<target>, so hold-open proves the
// whole path.
//
// Counters: wire = iptables counter chains ONLY where the carrier is a
// real kernel socket — the UDP-carried TUN families (server_side end,
// carrier port) and the L4 families (server_side end, public port; the
// engine's listeners are normal kernel TCP/UDP). The raw-socket carriers
// (faketcp/icmp) and the raw-IP kernel carriers bypass the normal chains —
// honestly not counted (payload/netdev counters remain). Payload = the
// tunnel interface's netdev counters on BOTH ends (each agent reports its
// own view) for every interface-carrying family; L4 has no interface →
// payload unknown.
//
// Version reporting (§2.22 display): Describe() reports the INSTALLED
// ctunnel version — the newest cached artifact's binary is probed
// (`ctunnel-engine -version`, bounded 10s, seam-able, 60s cache); without
// a cached binary the build-time pin is reported. The panel stores the
// rich catalog per agent (PROTOCOL-REQUESTS R3) and displays it.
//
// IPv6 (documented honestly):
//   - carrier/underlay: the engine's userspace carriers are IPv4-only
//     upstream (ListenUDP("udp4"), AF_INET raw sockets) — v6 underlay is
//     available only on the kernel methods that have it by design
//     (ip6gre/ip6gretap/ipip6/ip6ip6; mirrored as ipver:"v6" in the cores
//     manifest). The userspace methods are ipver:"v4" there — no honest
//     "both" row exists.
//   - inner traffic: v6 inner rides the deterministic ULA pair (v1 shape);
//     the two v6-inner-only kernel methods use it as the ONLY inner pair.

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/infra"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const ctunnelID = "ctunnel"

// ctPinnedVersion is the upstream CLI/env shape this driver renders
// (Describe() falls back to it when no artifact is installed; the artifact
// version param must match).
const ctPinnedVersion = "2.0.0"

// ---- the method catalog (mirrored from their pkg/catalog/catalog.go v2.0.0;
// the cores MANIFEST.json methods[] block is the published mirror of this
// table — keep both in sync; family strings there = the ctFamily strings
// here). ----------------------------------------------------------------

type ctFamily string

const (
	ctFamKernelL3 ctFamily = "kernel-l3"
	ctFamKernelL2 ctFamily = "kernel-l2"
	ctFamUDPCrypt ctFamily = "udp-crypt"
	ctFamStealth  ctFamily = "stealth"
	ctFamRevL4    ctFamily = "reverse-l4"
	ctFamGaming   ctFamily = "gaming"
)

type ctMethodSpec struct {
	id            int
	family        ctFamily
	overhead      int  // bytes added on top of the inner packet (IPv4 underlay)
	needsPort     bool // always uses a carrier port
	supportsFOU   bool // optional UDP (FOU) wrapping with a port
	supportsLanes bool // parallel ECMP lanes
	ipv6Underlay  bool // carrier addresses must be IPv6
	userspace     bool // carried by ctunnel-engine (TUN/TAP) — engine REQUIRED
	mikrotik      bool // RouterOS commands can be generated for the peer
}

// l4 reports whether the method is layer-4 port-forwarding (no tunnel
// interface; their catalog L4(): FamilyReverseL4 || Name == "game-kcp").
func (s ctMethodSpec) l4() bool { return s.family == ctFamRevL4 || s.id == 49 }

// crypt reports whether the method is an encrypted layer-3 tunnel run by
// the engine with the tunnel secret (their Crypt()).
func (s ctMethodSpec) crypt() bool {
	return s.family == ctFamUDPCrypt || s.family == ctFamStealth ||
		(s.family == ctFamGaming && s.id != 49)
}

// ctMethods — the full 49-method table. Their catalog is the truth for
// ids/overheads/flags; the Quantum-visible method name = their KIND string.
var ctMethods = map[string]ctMethodSpec{
	// kernel-l3 (16)
	"6to4":       {1, ctFamKernelL3, 60, false, true, false, false, false, true},
	"6to4-gre":   {2, ctFamKernelL3, 64, false, true, false, false, false, false},
	"sit":        {3, ctFamKernelL3, 20, false, true, false, false, false, false},
	"ipip":       {4, ctFamKernelL3, 20, false, true, false, false, false, true},
	"gre":        {5, ctFamKernelL3, 24, false, true, true, false, false, true},
	"ip6gre":     {6, ctFamKernelL3, 44, false, false, true, true, false, false},
	"ipip6":      {7, ctFamKernelL3, 40, false, false, false, true, false, false},
	"ip6ip6":     {8, ctFamKernelL3, 40, false, false, false, true, false, false},
	"wireguard":  {9, ctFamKernelL3, 60, true, false, false, false, false, true},
	"xfrm-ipsec": {10, ctFamKernelL3, 62, false, false, false, false, false, false},
	"fou-gre":    {11, ctFamKernelL3, 32, true, false, false, false, false, false},
	"gue-ipip":   {12, ctFamKernelL3, 32, true, false, false, false, false, false},
	"ecmp-lanes": {13, ctFamKernelL3, 28, false, true, true, false, false, false},
	"bareudp":    {41, ctFamKernelL3, 28, true, false, false, false, false, false},
	"xgre":       {44, ctFamKernelL3, 28, false, true, true, false, false, true},
	"xgre-ip":    {45, ctFamKernelL3, 48, false, true, true, false, false, false},
	// kernel-l2 (7)
	"eoip":      {14, ctFamKernelL2, 42, false, false, false, false, true, true},
	"gretap":    {15, ctFamKernelL2, 38, false, true, false, false, false, false},
	"ip6gretap": {16, ctFamKernelL2, 58, false, false, false, true, false, false},
	"vxlan":     {17, ctFamKernelL2, 50, true, false, false, false, false, true},
	"geneve":    {18, ctFamKernelL2, 50, true, false, false, false, false, false},
	"l2tpv3":    {19, ctFamKernelL2, 50, false, true, false, false, false, false},
	"etherip":   {20, ctFamKernelL2, 36, false, false, false, false, true, false},
	// udp-crypt (11)
	"dtls-1.3":     {21, ctFamUDPCrypt, 66, true, false, false, false, true, false},
	"quic-v1":      {22, ctFamUDPCrypt, 64, true, false, false, false, true, false},
	"srtp-direct":  {23, ctFamUDPCrypt, 65, true, false, false, false, true, false},
	"wg-stealth":   {24, ctFamUDPCrypt, 61, true, false, false, false, true, false},
	"rudp-fec":     {25, ctFamUDPCrypt, 65, true, false, false, false, true, false},
	"dnscrypt-udp": {26, ctFamUDPCrypt, 65, true, false, false, false, true, false},
	"ntp-direct":   {27, ctFamUDPCrypt, 61, true, false, false, false, true, false},
	"openvpn-dco":  {28, ctFamUDPCrypt, 61, true, false, false, false, true, false},
	"stun-turn":    {36, ctFamUDPCrypt, 57, true, false, false, false, true, false},
	"gtp-u":        {39, ctFamUDPCrypt, 61, true, false, false, false, true, false},
	"esp-udp":      {40, ctFamUDPCrypt, 61, true, false, false, false, true, false},
	// stealth (2)
	"faketcp": {37, ctFamStealth, 82, true, false, false, false, true, false},
	"icmp":    {38, ctFamStealth, 53, false, false, false, false, true, false},
	// reverse-l4 (9)
	"tcp":    {29, ctFamRevL4, 0, true, false, false, false, true, false},
	"tcpmux": {30, ctFamRevL4, 0, true, false, false, false, true, false},
	"pck":    {31, ctFamRevL4, 0, true, false, false, false, true, false},
	"ws":     {32, ctFamRevL4, 0, true, false, false, false, true, false},
	"wsmux":  {33, ctFamRevL4, 0, true, false, false, false, true, false},
	"wss":    {34, ctFamRevL4, 0, true, false, false, false, true, false},
	"wssmux": {35, ctFamRevL4, 0, true, false, false, false, true, false},
	"udp":    {42, ctFamRevL4, 0, true, false, false, false, true, false},
	"udpmux": {43, ctFamRevL4, 0, true, false, false, false, true, false},
	// gaming (4)
	"game-udp": {46, ctFamGaming, 48, true, false, false, false, true, false},
	"game-fec": {47, ctFamGaming, 56, true, false, false, false, true, false},
	"game-dup": {48, ctFamGaming, 52, true, false, false, false, true, false},
	"game-kcp": {49, ctFamGaming, 0, true, false, false, false, true, false},
}

// ctMethodList is the deterministic method ordering (by their id) for
// schema/docs rendering.
func ctMethodList() []string {
	out := make([]string, 0, len(ctMethods))
	for name := range ctMethods {
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool {
		return ctMethods[out[i]].id < ctMethods[out[j]].id
	})
	return out
}

// ctEngineNeeded reports whether the instance runs the ctunnel-engine
// binary: every userspace kind always does; kernel kinds do only in
// REVERSE (the engine is the reverse TCP carrier). wireguard never does.
func ctEngineNeeded(spec ctMethodSpec, direction string) bool {
	if spec.id == 9 { // wireguard: kernel-only, endpoint flips by direction
		return false
	}
	if spec.userspace {
		return true
	}
	return direction == "reverse"
}

// ctKernelKind reports whether the driver performs kernel device setup
// (kernel families; both directions — in reverse the kernel device rides
// the carrier TUN).
func (s ctMethodSpec) kernelKind() bool {
	return s.family == ctFamKernelL3 || s.family == ctFamKernelL2
}

// ---- params (v2) --------------------------------------------------------

type ctunnelParams struct {
	ServerSide  string `json:"server_side"`  // the end holding the PUBLIC port (ctunnel ROLE=iran; foreign for the default reverse shape)
	Version     string `json:"version"`      // artifact version (cache key), e.g. "2.0.0"
	Artifact    string `json:"artifact"`     // name template with {arch}
	SHA256Amd   string `json:"sha256_amd64"` // pinned fallback
	SHA256Arm   string `json:"sha256_arm64"`
	SigAmd      string `json:"signature_amd64"`
	SigArm      string `json:"signature_arm64"`
	Method      string `json:"method"`       // any of the 49 ctMethods
	Direction   string `json:"direction"`    // "reverse" (default) | "direct" (L4 methods: reverse only)
	ForeignAddr string `json:"foreign_addr"` // the PEER's carrier address "host:port" (the dialing end dials it)
	CarrierPort int    `json:"carrier_port"` // carrier port, panel-allocated (0 for icmp; FOU wrap port for FOU-capable kernel methods when > 0)
	PublicPort  int    `json:"public_port"`  // PUBLIC forwarded port on the server_side end, panel-allocated
	LocalAddr   string `json:"local_addr"`   // target service "host:port" on the non-server_side end (relay/engine dials it; loopback-only for L4)
	Proto       string `json:"proto"`        // "tcp" (default) | "udp" | "both"
	Secret      string `json:"secret"`       // tunnel secret, 64 hex chars (32 bytes) — 0600 env file only, never logged
	Padding     int    `json:"padding"`      // 0-255 (upstream per-packet padding; UDP-Crypt/Gaming-L3 families)
	MTU         int    `json:"mtu"`          // 0 → per-method default (1500 - overhead [-8 FOU] - padding)
	// v2 per-family desired-state params (all optional; deterministic
	// defaults derived from the TunnelID when absent so BOTH ends agree):
	Lanes    int    `json:"lanes"`     // 1-8 ECMP lanes (SupportsLanes methods)
	GREKey   uint32 `json:"gre_key"`   // keyed GRE/xGRE (0 → derived)
	VNI      uint32 `json:"vni"`       // vxlan/geneve (0 → derived)
	TunnelID uint16 `json:"tunnel_id"` // l2tpv3/eoip (0 → derived)
	RateMbps int    `json:"rate_mbps"` // 0 = off; else tc tbf cap on the driver's OWN devices
	SNI      string `json:"sni"`       // ws/wss TLS server name + WS Host (empty = the carrier IP)
	// PeerAddr is the SERVER_SIDE end's carrier address ("host:port").
	// REQUIRED for the kernel-direct families: both ends build a kernel
	// device against a CONCRETE carrier (no roaming — the kernel cannot
	// learn the peer like the engine's passive end does), so the panel
	// sends both ends' addresses: foreign_addr (the dialing end's peer —
	// the kharej end in direct mode) + peer_addr (this server_side end).
	// The iran end's device remote = foreign_addr; the kharej end's device
	// remote = peer_addr. Engine families ignore it (their passive end
	// roams). wireguard reverse is exempt (its listening end has no
	// endpoint).
	PeerAddr string `json:"peer_addr"`
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

// ctValidateParams — per-family desired-state validation (fail-closed).
func ctValidateParams(p ctunnelParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("ctunnel: server_side required")
	}
	spec, ok := ctMethods[strings.ToLower(strings.TrimSpace(p.Method))]
	if !ok {
		return fmt.Errorf("ctunnel: unknown method %q (must be one of the 49 v2 methods)", p.Method)
	}
	d := ctDefaultDirection(p.Direction)
	if d != "reverse" && d != "direct" {
		return fmt.Errorf("ctunnel: direction must be reverse or direct")
	}
	if spec.l4() && d == "direct" {
		// Their direct-L4 puts the public forwards on the LISTENING end
		// (kharej), which breaks the Quantum server_side contract.
		return fmt.Errorf("ctunnel: method %s supports the reverse direction only (direct L4 binds the public port on the wrong end)", p.Method)
	}
	if pr := ctDefaultProto(p.Proto); pr != "tcp" && pr != "udp" && pr != "both" {
		return fmt.Errorf("ctunnel: proto must be tcp, udp or both")
	}
	if spec.ipv6Underlay {
		host, _, err := net.SplitHostPort(strings.TrimSpace(p.ForeignAddr))
		if err != nil || net.ParseIP(host) == nil || net.ParseIP(host).To4() != nil {
			return fmt.Errorf("ctunnel: %s requires an IPv6 foreign_addr", p.Method)
		}
	} else if _, port, err := net.SplitHostPort(strings.TrimSpace(p.ForeignAddr)); err != nil || port == "" {
		return fmt.Errorf("ctunnel: foreign_addr must be host:port")
	}
	if p.ForeignAddr != strings.TrimSpace(p.ForeignAddr) || strings.ContainsAny(p.ForeignAddr, "\"'\\\n\r") {
		return fmt.Errorf("ctunnel: foreign_addr not config-safe")
	}
	// peer_addr: the server_side end's carrier — required exactly for the
	// kernel-direct families (both ends build concrete kernel devices;
	// wireguard reverse is exempt — its listening end has no endpoint).
	kernelDirect := spec.kernelKind() && !spec.userspace && spec.id != 9 && d == "direct"
	if kernelDirect {
		host, _, err := net.SplitHostPort(strings.TrimSpace(p.PeerAddr))
		if err != nil || net.ParseIP(host) == nil {
			return fmt.Errorf("ctunnel: %s (direct kernel device) requires peer_addr host:port (the server_side end's carrier address)", p.Method)
		}
		if net.ParseIP(host).To4() == nil && !spec.ipv6Underlay {
			return fmt.Errorf("ctunnel: %s expects an IPv4 peer_addr", p.Method)
		}
		if hostOf(strings.TrimSpace(p.PeerAddr)) == hostOf(strings.TrimSpace(p.ForeignAddr)) {
			return fmt.Errorf("ctunnel: peer_addr and foreign_addr must name different ends")
		}
	} else if strings.TrimSpace(p.PeerAddr) != "" {
		host, _, err := net.SplitHostPort(strings.TrimSpace(p.PeerAddr))
		if err != nil || net.ParseIP(host) == nil || strings.ContainsAny(p.PeerAddr, "\"'\\\n\r") {
			return fmt.Errorf("ctunnel: peer_addr must be a config-safe host:port when set")
		}
	}
	if spec.id == 38 { // icmp: no carrier port (the engine derives the id from the secret)
		if p.CarrierPort != 0 {
			return fmt.Errorf("ctunnel: icmp takes no carrier_port (the engine derives the identifier from the secret)")
		}
	} else if spec.needsPort {
		if p.CarrierPort <= 0 || p.CarrierPort > 65535 {
			return fmt.Errorf("ctunnel: carrier_port out of range (required for %s)", p.Method)
		}
	} else if p.CarrierPort < 0 || p.CarrierPort > 65535 {
		return fmt.Errorf("ctunnel: carrier_port out of range")
	}
	if !spec.l4() && spec.id != 38 {
		// Forwarding composition (DNAT/relay) — carrier must not collide
		// with the public port on the same end.
		if p.PublicPort == p.CarrierPort && p.CarrierPort != 0 {
			return fmt.Errorf("ctunnel: public_port must differ from carrier_port")
		}
	}
	if p.PublicPort <= 0 || p.PublicPort > 65535 {
		return fmt.Errorf("ctunnel: public_port out of range")
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(p.LocalAddr)); err != nil ||
		p.LocalAddr != strings.TrimSpace(p.LocalAddr) || strings.ContainsAny(p.LocalAddr, "\"'\\\n\r") {
		return fmt.Errorf("ctunnel: local_addr must be a config-safe host:port")
	}
	if spec.l4() {
		// The engine hard-dials 127.0.0.1:<target> (pkg/l4/client.go).
		host, _, _ := net.SplitHostPort(strings.TrimSpace(p.LocalAddr))
		if host != "127.0.0.1" {
			return fmt.Errorf("ctunnel: %s delivers to 127.0.0.1 only (the engine's own dialer); local_addr host must be 127.0.0.1", p.Method)
		}
	}
	if p.Lanes < 0 || p.Lanes > 8 {
		return fmt.Errorf("ctunnel: lanes must be 0 (default 1) or 1-8")
	}
	if p.Lanes > 1 && !spec.supportsLanes {
		return fmt.Errorf("ctunnel: method %s does not support lanes", p.Method)
	}
	if p.SNI != "" && spec.id != 32 && spec.id != 34 && spec.id != 35 {
		// ws / wss / wssmux only (their SNI = TLS server name + WS Host).
		return fmt.Errorf("ctunnel: sni applies to the ws/wss/wssmux methods only")
	}
	if len(p.SNI) > 255 || strings.ContainsAny(p.SNI, "\"'\\\n\r") {
		return fmt.Errorf("ctunnel: sni not config-safe")
	}
	if p.RateMbps < 0 || p.RateMbps > 100000 {
		return fmt.Errorf("ctunnel: rate_mbps must be 0 (off) or 1-100000")
	}
	if spec.crypt() || spec.id == 9 || spec.id == 10 {
		// Secret: 64 hex chars (32 bytes) — the upstream key-derivation
		// consumes it from the env file / derives the WG+IPsec keys from
		// it; shape-guarded for the file format.
		if len(p.Secret) != 64 {
			return fmt.Errorf("ctunnel: secret must be 64 hex chars (32 bytes)")
		}
		if _, err := hex.DecodeString(p.Secret); err != nil {
			return fmt.Errorf("ctunnel: secret must be hex")
		}
		if p.Padding < 0 || p.Padding > 255 {
			return fmt.Errorf("ctunnel: padding must be 0-255 (0 = upstream default 16)")
		}
	} else {
		if p.Secret != "" {
			if len(p.Secret) != 64 {
				return fmt.Errorf("ctunnel: secret must be 64 hex chars (32 bytes) when set")
			}
			if _, err := hex.DecodeString(p.Secret); err != nil {
				return fmt.Errorf("ctunnel: secret must be hex")
			}
		}
		if p.Padding != 0 {
			return fmt.Errorf("ctunnel: padding applies to the encrypted L3 families only")
		}
	}
	if p.MTU < 0 || p.MTU > 1500 || (p.MTU > 0 && p.MTU < 1280) {
		return fmt.Errorf("ctunnel: mtu must be 1280-1500 (0 = per-method default)")
	}
	// Artifact pins: required exactly when this instance needs the engine.
	if ctEngineNeeded(spec, d) {
		if err := backhaulValidateArtifactPins2(p.Version, p.Artifact, p.SHA256Amd, p.SigAmd, p.SHA256Arm, p.SigArm, ctunnelID); err != nil {
			return err
		}
	} else if p.Version != "" || strings.TrimSpace(p.Artifact) != "" || p.SHA256Amd != "" || p.SHA256Arm != "" || p.SigAmd != "" || p.SigArm != "" {
		// Supplied anyway → they must be WELL-FORMED (never store garbage).
		if err := backhaulValidateArtifactPins2(p.Version, p.Artifact, p.SHA256Amd, p.SigAmd, p.SHA256Arm, p.SigArm, ctunnelID); err != nil {
			return err
		}
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
// reaches both agents): iface name, upstream INDEX, the point-to-point
// 10.77.<index>.0/30 pair, the deterministic ULA inner-v6 pair, and the
// 172.31.<index>.x reverse-carrier pair (the engine's <dev>-r TUN
// addressing, upstream's REVERSE branch). The iran-role end takes .1, the
// kharej end .2. Index 128-227: disjoint from an operator's sequential
// ctunnel indexes (1-49) and from the intermediate-network collisions.
type ctDerive struct {
	iface    string
	index    int
	selfTun  string
	peerTun  string
	selfTun6 string
	peerTun6 string
	// carrier v6 pair for the 6to4 / ipip6 / ip6ip6 families (fd00:78 —
	// distinct from the inner ULA fd00:77) and the reverse-carrier v4 pair
	// (172.31.<index>.x — distinct from upstream's operator space which
	// starts at 172.31.1.x only when an operator runs THEIR reverse tooling
	// alongside ours; disjoint for our index range).
	selfCar6 string
	peerCar6 string
	selfRev4 string
	peerRev4 string
}

func ctDeriveFor(tunnelID, role string) ctDerive {
	sum := sha256.Sum256([]byte("quantum-ctunnel:" + tunnelID))
	iface := "ctq" + hex.EncodeToString(sum[0:4]) // 12 chars ≤ IFNAMSIZ 15 (+"-r" = 14)
	index := 128 + int(sum[4])%100                // 128-227
	d := ctDerive{iface: iface, index: index}
	d.selfTun = fmt.Sprintf("10.77.%d.2", index)
	d.peerTun = fmt.Sprintf("10.77.%d.1", index)
	d.selfTun6 = fmt.Sprintf("fd00:77:%x::2", index)
	d.peerTun6 = fmt.Sprintf("fd00:77:%x::1", index)
	d.selfCar6 = fmt.Sprintf("fd00:78:%x::1", index)
	d.peerCar6 = fmt.Sprintf("fd00:78:%x::2", index)
	d.selfRev4 = fmt.Sprintf("172.31.%d.1", index)
	d.peerRev4 = fmt.Sprintf("172.31.%d.2", index)
	if role == "iran" {
		d.selfTun, d.peerTun = fmt.Sprintf("10.77.%d.1", index), fmt.Sprintf("10.77.%d.2", index)
		d.selfTun6, d.peerTun6 = fmt.Sprintf("fd00:77:%x::1", index), fmt.Sprintf("fd00:77:%x::2", index)
	}
	// The reverse-carrier pair flips with the role the same way (upstream:
	// rev_local=.1 for iran, .2 for kharej).
	if role != "iran" {
		d.selfRev4, d.peerRev4 = fmt.Sprintf("172.31.%d.2", index), fmt.Sprintf("172.31.%d.1", index)
	}
	return d
}

// ctDerivedKey returns the uint32 derived parameter for the tunnel
// (GRE key / VNI / tunnel-id) — deterministic, both ends agree.
func ctDerivedKey(tunnelID, what string) uint32 {
	sum := sha256.Sum256([]byte("quantum-ctunnel-key:" + what + ":" + tunnelID))
	v := binary.BigEndian.Uint32(sum[0:4])
	switch what {
	case "tunnel-id":
		return v%60000 + 1 // uint16 range, never 0
	default:
		return v%100000 + 1 // non-zero, well below the vni/gre-key spaces
	}
}

// ctEnvText renders the per-instance env file (the upstream v2 env contract,
// pkg/tunnel/env.go key set — exactly the keys their ctunnel-kernel.sh and
// ctunnel-engine read). Written 0600: SECRET rides here and nowhere else.
//
// REMOTE_IP semantics (cmd/ctunnel-engine loadConfig): required unless
// passive; "0.0.0.0" means roam-only — the end learns its peer from the
// first authenticated packet (NAT roaming). reverse → the kharej end dials
// the foreign address, the iran end roams; direct → the iran end dials the
// foreign address, the kharej end roams. REVERSE kernel kinds use the
// intermediate 172.31.<index>.x carrier pair on BOTH ends (the engine's
// carrier TUN addressing; the engine opens <DEV>-r itself).
func ctEnvText(p ctunnelParams, role, direction string, d ctDerive, tunnelID string) []byte {
	spec := ctMethods[strings.ToLower(strings.TrimSpace(p.Method))]
	reverse := "0"
	if direction == "reverse" {
		reverse = "1"
	}
	remoteIP := "0.0.0.0"
	localIP := "0.0.0.0"
	dev := d.iface
	port := p.CarrierPort
	if spec.kernelKind() && !spec.userspace && direction == "reverse" && spec.id != 9 {
		// The engine's reverse carrier TUN (upstream's <DEV>-r shape): the
		// kernel device rides it; the engine carries the TUN over its TCP
		// carrier (iran listens, kharej dials).
		dev = d.iface + "-r"
		localIP = d.selfRev4
		remoteIP = d.peerRev4
		if !spec.needsPort {
			port = 0 // FOU wrapping is meaningless over the carrier TUN
		}
	} else if (role == "kharej") == (direction == "reverse") {
		remoteIP = hostOf(strings.TrimSpace(p.ForeignAddr))
	}
	lines := []string{
		"NAME=qc-" + d.iface,
		fmt.Sprintf("INDEX=%d", d.index),
		"DEV=" + dev,
		"ROLE=" + role,
		"KIND=" + strings.ToLower(strings.TrimSpace(p.Method)),
		"LOCAL_IP=" + localIP,
		"REMOTE_IP=" + remoteIP,
		"TUN_LOCAL4=" + d.selfTun,
		"TUN_REMOTE4=" + d.peerTun,
		"CARRIER_LOCAL6=" + d.selfCar6,
		"CARRIER_REMOTE6=" + d.peerCar6,
		fmt.Sprintf("PORT=%d", port),
		fmt.Sprintf("MTU=%d", ctDefaultMTU(p, spec)),
		"REVERSE=" + reverse,
	}
	if spec.crypt() {
		lines = append(lines,
			"SECRET="+p.Secret,
			fmt.Sprintf("PADDING=%d", ctDefaultPadding(p.Padding)))
	} else if p.Secret != "" {
		// Kernel families consume the secret only via the DERIVED keys
		// (wireguard/ipsec below); the raw secret never reaches the env
		// file for them.
		_ = p.Secret
	}
	greKey := p.GREKey
	if greKey == 0 {
		greKey = ctDerivedKey(tunnelID, "gre-key")
	}
	vni := p.VNI
	if vni == 0 {
		vni = ctDerivedKey(tunnelID, "vni")
	}
	tid := uint32(p.TunnelID)
	if tid == 0 {
		tid = ctDerivedKey(tunnelID, "tunnel-id")
	}
	switch spec.id {
	case 5, 13, 44, 45: // gre / ecmp-lanes / xgre / xgre-ip
		lines = append(lines, fmt.Sprintf("GRE_KEY=%d", greKey))
	case 17, 18: // vxlan / geneve
		lines = append(lines, fmt.Sprintf("VNI=%d", vni))
	case 14, 19: // eoip / l2tpv3
		lines = append(lines, fmt.Sprintf("TUNNEL_ID=%d", tid))
	case 9: // wireguard: derived key pair, per role (their WireGuardKeys)
		priv, pub := ctWireGuardKeys(p.Secret, role)
		_, peerPub := ctWireGuardKeys(p.Secret, ctPeerRole(role))
		lines = append(lines, "WG_PRIVATE="+priv, "WG_PEER_PUBLIC="+peerPub)
		_ = pub
	case 10: // xfrm-ipsec: derived SPI/keys, per role (their ipsecSA)
		spiOut, keyOut := ctIPsecSA(p.Secret, role)
		spiIn, keyIn := ctIPsecSA(p.Secret, ctPeerRole(role))
		lines = append(lines,
			"IPSEC_SPI_OUT="+spiOut, "IPSEC_KEY_OUT="+keyOut,
			"IPSEC_SPI_IN="+spiIn, "IPSEC_KEY_IN="+keyIn)
	}
	if p.Lanes > 1 {
		lines = append(lines, fmt.Sprintf("LANES=%d", p.Lanes))
	} else {
		lines = append(lines, "LANES=1")
	}
	lines = append(lines, fmt.Sprintf("RATE_MBIT=%d", p.RateMbps))
	// FORWARDS: the upstream kernel script's DNAT is NOT used — this driver
	// owns the equivalent rules via arg-list exec (ctForwardRulesAdd) for
	// the interface-carrying families; for the L4 families the ENGINE
	// binds the forwards itself, so the env carries them.
	if spec.l4() {
		lines = append(lines, fmt.Sprintf("FORWARDS=%d=%d", p.PublicPort, ctTargetPort(p)))
		if p.SNI != "" {
			lines = append(lines, "SNI="+p.SNI)
		}
	} else {
		// Interface-carrying families: FORWARDS stays EMPTY — the driver
		// owns the public-port rules (comment-tagged, removed on Stop).
		lines = append(lines, "FORWARDS=")
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func ctPeerRole(role string) string {
	if role == "iran" {
		return "kharej"
	}
	return "iran"
}

// ctDeriveSubkey reimplements their interop key derivation
// (pkg/crypto DeriveSubkey — the published wire contract both ends must
// agree on; our own implementation, no upstream source copied):
// HMAC-SHA256(key = raw secret bytes, msg = "ctunnel-v1|" + label).
func ctDeriveSubkey(secretHex, label string) [32]byte {
	raw, err := hex.DecodeString(secretHex)
	if err != nil || len(raw) < 16 {
		raw = []byte(secretHex)
	}
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte("ctunnel-v1|" + label))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// ctWireGuardKeys derives the per-role X25519 key pair from the shared
// secret (their pkg/tunnel WireGuardKeys shape — deterministic, both ends
// + a MikroTik peer derive the same pair).
func ctWireGuardKeys(secret, role string) (private, public string) {
	k := ctDeriveSubkey(secret, "wg-key|"+role)
	priv, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return "", ""
	}
	pub := priv.PublicKey()
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(pub.Bytes())
}

// ctIPsecSA derives the per-role SPI + AES-GCM key+salt (36 bytes) — their
// pkg/tunnel ipsecSA shape.
func ctIPsecSA(secret, role string) (spi, key string) {
	a := ctDeriveSubkey(secret, "ipsec-key|"+role)
	b := ctDeriveSubkey(secret, "ipsec-salt|"+role)
	s := ctDeriveSubkey(secret, "ipsec-spi|"+role)
	v := binary.BigEndian.Uint32(s[:4]) | 0x1000 // clear of reserved SPIs 0-255
	return fmt.Sprintf("0x%08x", v), "0x" + hex.EncodeToString(append(a[:], b[:4]...))
}

// ctTargetPort is the target port the DNAT/engine-forward uses (the port
// part of local_addr; decimal-only, bounded).
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
// flag is -config <env file> (cmd/ctunnel-engine/main.go).
func ctEngineArgs(envPath string) []string {
	return []string{"-config", envPath}
}

// ctIPCmd executes the interface-admin commands the upstream kernel
// script would run (arg-list exec, never a shell). The engine opens the
// TUN/TAP by name via TUNSETIFF and expects the interface to already
// exist with its address and MTU set (upstream error text: "is the
// interface created by ctunnel-kernel?") — the driver replicates exactly
// the script's setup commands and deletes the interface on Stop.
var ctIPCmd = func(args ...string) error {
	_, err := infra.RunCmdTimeout(10*time.Second, "ip", args...)
	return err
}

// ctTCCmd is the traffic-control seam (rate_mbps caps on the driver's OWN
// devices only).
var ctTCCmd = func(args ...string) error {
	_, err := infra.RunCmdTimeout(10*time.Second, "tc", args...)
	return err
}

// ctWgCmd is the wireguard-tools seam (arg-list exec; the key rides a
// 0600 temp file, never argv).
var ctWgCmd = func(args ...string) error {
	_, err := infra.RunCmdTimeout(10*time.Second, "wg", args...)
	return err
}

// ctIP6Tables is the v6 firewall seam (the IPv6-inner-only methods use the
// same tagged-rule composition over ip6tables).
var ctIP6Tables = func(args ...string) ([]byte, error) {
	return infra.RunCmdTimeout(10*time.Second, "ip6tables", args...)
}

// ctIfaceUp replicates ctunnel-kernel.sh's TUN/TAP setup for the
// engine-driven interface kinds (the engine does NOT create or address
// the interface itself):
//
//	ip tuntap add dev "$DEV" mode tun|tap multi_queue   (fallback: without)
//	ip link set dev "$DEV" mtu "$MTU" txqueuelen 10000 up
//	ip addr add "$TUN_LOCAL4" peer "$TUN_REMOTE4/32" dev "$DEV"
//
// plus the deterministic ULA v6 pair so inner IPv6 works. tap = the L2
// bridge kinds (eoip/etherip — the engine's raw bridge is a TAP consumer).
func ctIfaceUp(iface string, mtu int, tap bool, selfTun, peerTun, selfTun6, peerTun6 string) error {
	mode := "tun"
	if tap {
		mode = "tap"
	}
	if err := ctIPCmd("tuntap", "add", "dev", iface, "mode", mode, "multi_queue"); err != nil {
		if err2 := ctIPCmd("tuntap", "add", "dev", iface, "mode", mode); err2 != nil {
			// An existing interface from a previous run is fine — the
			// engine re-attaches via TUNSETIFF.
			if !strings.Contains(err2.Error(), "already exists") {
				return fmt.Errorf("ctunnel: tuntap add: %v / %v", err, err2)
			}
		}
	}
	cmds := [][]string{
		{"link", "set", "dev", iface, "mtu", fmt.Sprint(mtu), "txqueuelen", "10000", "up"},
		{"addr", "add", selfTun, "peer", peerTun + "/32", "dev", iface},
		{"-6", "addr", "add", selfTun6 + "/128", "peer", peerTun6 + "/128", "dev", iface},
	}
	// The L2 bridge kinds (TAP) take the same p2v4 pair + ULA (their
	// script addr4()s the TAP too).
	for _, cmd := range cmds {
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

// ctIfaceDel removes the TUN/TAP (Stop/Uninstall; absence tolerated).
func ctIfaceDel(iface string) error {
	return ctIPCmd("link", "del", "dev", iface)
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

// ctDefaultMTU is the upstream DefaultMTU formula: 1500 - overhead
// [- 8 when a FOU wrap is on] - padding, floored at 1280.
func ctDefaultMTU(p ctunnelParams, spec ctMethodSpec) int {
	if p.MTU > 0 {
		return p.MTU
	}
	mtu := 1500 - spec.overhead - ctDefaultPadding(p.Padding)
	if p.CarrierPort > 0 && spec.supportsFOU {
		mtu -= 8
	}
	if mtu < 1280 {
		mtu = 1280
	}
	return mtu
}

// ctRuleCheck renders the iptables EXISTENCE check for a rendered rule:
// the table prefix (-t <t>) is preserved and the action (-A/-I) is swapped
// for -C, keeping the rule spec intact — the exact-once discipline for
// real iptables, not just the hermetic seam.
func ctRuleCheck(add []string) []string {
	if len(add) >= 3 && add[0] == "-t" {
		out := []string{"-t", add[1], "-C"}
		return append(out, add[3:]...)
	}
	return append([]string{"-C"}, add[1:]...)
}

// ctRuleDelete renders the rule REMOVAL (action swapped for -D).
func ctRuleDelete(add []string) []string {
	if len(add) >= 3 && add[0] == "-t" {
		out := []string{"-t", add[1], "-D"}
		return append(out, add[3:]...)
	}
	return append([]string{"-D"}, add[1:]...)
}

// ctComment is the per-instance iptables comment tag.
func ctComment(tunnelID string) string { return "ctdrv-" + tunnelID }

// ctSysctl executes host sysctls (seam-able). Scope: ONLY keys the tunnel
// needs — net.ipv4.ip_forward=1 (the DNAT delivery) and the per-device
// rp_filter on the driver's OWN interfaces. Never global tuning beyond
// that (their `optimize` sysctl file is NOT replicated — non-additive).
var ctSysctl = func(args ...string) error {
	_, err := infra.RunCmdTimeout(10*time.Second, "sysctl", args...)
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

// ---- the public-port rule set (interface-carrying families) -------------

// ctForwardRulesAdd installs the PUBLIC-PORT rule set on the iran-role end
// (arg-list exec only — the upstream kernel script is never run),
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
// v6 inner (sit/ip6ip6) runs the same composition over ip6tables.
func ctForwardRulesAdd(tunnelID, proto string, publicPort, targetPort int, selfTun, peerTun string) error {
	if err := ctSysctl("-qw", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("ctunnel: ip_forward sysctl: %w", err)
	}
	for _, add := range ctForwardRuleArgs(tunnelID, proto, publicPort, targetPort, selfTun, peerTun) {
		chk := ctRuleCheck(add)
		if _, err := acctIptables(chk...); err != nil {
			if _, err := acctIptables(add...); err != nil {
				return fmt.Errorf("ctunnel: forward rule (%s %s): %w", add[2], add[3], err)
			}
		}
	}
	return nil
}

// ctForwardRuleV6Args renders the v6-inner variant (sit/ip6ip6): the same
// four rules with the v6 tunnel pair and the v6 target port. SNAT uses the
// deterministic ULA source.
func ctForwardRuleV6Args(tunnelID, proto string, publicPort, targetPort int, selfTun6, peerTun6 string) [][]string {
	cmt := ctComment(tunnelID)
	out := make([][]string, 0, len(ctProtosFor(proto))*4)
	for _, pr := range ctProtosFor(proto) {
		out = append(out,
			[]string{"-t", "nat", "-A", "PREROUTING", "-p", pr, "--dport", fmt.Sprint(publicPort),
				"-m", "addrtype", "--dst-type", "LOCAL",
				"-m", "comment", "--comment", cmt, "-j", "DNAT",
				"--to-destination", net.JoinHostPort(peerTun6, fmt.Sprint(targetPort))},
			[]string{"-t", "nat", "-A", "POSTROUTING", "-d", peerTun6 + "/128",
				"-m", "comment", "--comment", cmt, "-j", "SNAT", "--to-source", selfTun6},
			[]string{"-I", "FORWARD", "-d", peerTun6 + "/128",
				"-m", "comment", "--comment", cmt, "-j", "ACCEPT"},
			[]string{"-I", "FORWARD", "-s", peerTun6 + "/128",
				"-m", "comment", "--comment", cmt, "-j", "ACCEPT"})
	}
	return out
}

func ctForwardRulesV6Add(tunnelID, proto string, publicPort, targetPort int, selfTun6, peerTun6 string) error {
	if err := ctSysctl("-qw", "net.ipv6.conf.all.forwarding=1"); err != nil {
		return fmt.Errorf("ctunnel: v6 forwarding sysctl: %w", err)
	}
	for _, add := range ctForwardRuleV6Args(tunnelID, proto, publicPort, targetPort, selfTun6, peerTun6) {
		chk := ctRuleCheck(add)
		if _, err := ctIP6Tables(chk...); err != nil {
			if _, err := ctIP6Tables(add...); err != nil {
				return fmt.Errorf("ctunnel: v6 forward rule: %w", err)
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
func ctForwardRulesDel(tunnelID, proto string, publicPort, targetPort int, selfTun, peerTun string) {
	for _, add := range ctForwardRuleArgs(tunnelID, proto, publicPort, targetPort, selfTun, peerTun) {
		del := ctRuleDelete(add)
		_, _ = acctIptables(del...)
	}
}

func ctForwardRulesV6Del(tunnelID, proto string, publicPort, targetPort int, selfTun6, peerTun6 string) {
	for _, add := range ctForwardRuleV6Args(tunnelID, proto, publicPort, targetPort, selfTun6, peerTun6) {
		del := ctRuleDelete(add)
		_, _ = ctIP6Tables(del...)
	}
}

// ctRelayInputRuleArgs manage the kharej-role end's INPUT accepts for the
// relay delivery: packets arriving ON the tunnel interface addressed to
// the end's own tunnel IP:target must reach the in-agent relay even on
// hardened (drop-all INPUT) hosts — inserted FIRST, comment-tagged.
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
		chk := ctRuleCheck(add)
		if _, err := acctIptables(chk...); err != nil {
			if _, err := acctIptables(add...); err != nil {
				return fmt.Errorf("ctunnel: relay INPUT rule: %w", err)
			}
		}
	}
	return nil
}

func ctRelayInputRulesDel(tunnelID, iface, proto string, targetPort int) {
	for _, add := range ctRelayInputRuleArgs(tunnelID, iface, proto, targetPort) {
		del := ctRuleDelete(add)
		_, _ = acctIptables(del...)
	}
}

// ctMSSClampArgs replicates the kernel script's mangle TCPMSS clamp for
// ONE tunnel (both directions of the tunnel interface), comment-tagged.
// Scoped to the driver's OWN interface: traffic through any other device
// is untouched.
func ctMSSClampArgs(tunnelID, iface string) [][]string {
	cmt := ctComment(tunnelID)
	return [][]string{
		{"-t", "mangle", "-A", "FORWARD", "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-m", "comment", "--comment", cmt, "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
		{"-t", "mangle", "-A", "FORWARD", "-i", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
			"-m", "comment", "--comment", cmt, "-j", "TCPMSS", "--clamp-mss-to-pmtu"},
	}
}

func ctMSSClampAdd(tunnelID, iface string) error {
	for _, add := range ctMSSClampArgs(tunnelID, iface) {
		chk := ctRuleCheck(add)
		if _, err := acctIptables(chk...); err != nil {
			if _, err := acctIptables(add...); err != nil {
				return err
			}
		}
	}
	return nil
}

func ctMSSClampDel(tunnelID, iface string) {
	for _, add := range ctMSSClampArgs(tunnelID, iface) {
		del := ctRuleDelete(add)
		_, _ = acctIptables(del...)
	}
}

// ctNotrackArgs replicates the kernel script's raw-table conntrack skip
// for the raw tunnel protocols (their loop over protos 4/41/47/50/97/115,
// scoped to the peer host), comment-tagged. Untracking ONLY the peer's
// raw-protocol packets is what keeps stateful firewalls from dropping
// decapsulated return traffic.
var ctNotrackProtos = []string{"4", "41", "47", "50", "97", "115"}

func ctNotrackArgs(tunnelID, peerIP string) [][]string {
	cmt := ctComment(tunnelID)
	out := make([][]string, 0, len(ctNotrackProtos)*2)
	for _, pr := range ctNotrackProtos {
		out = append(out,
			[]string{"-t", "raw", "-A", "PREROUTING", "-s", peerIP + "/32", "-p", pr,
				"-m", "comment", "--comment", cmt, "-j", "CT", "--notrack"},
			[]string{"-t", "raw", "-A", "OUTPUT", "-d", peerIP + "/32", "-p", pr,
				"-m", "comment", "--comment", cmt, "-j", "CT", "--notrack"})
	}
	return out
}

func ctNotrackAdd(tunnelID, peerIP string) error {
	for _, add := range ctNotrackArgs(tunnelID, peerIP) {
		chk := ctRuleCheck(add)
		if _, err := acctIptables(chk...); err != nil {
			if _, err := acctIptables(add...); err != nil {
				return err
			}
		}
	}
	return nil
}

func ctNotrackDel(tunnelID, peerIP string) {
	for _, add := range ctNotrackArgs(tunnelID, peerIP) {
		del := ctRuleDelete(add)
		_, _ = acctIptables(del...)
	}
}

// ---- the kernel families (DIRECT direction): per-method device setup ----
// Every function here builds devices/routes/rules on the driver's OWN
// behalf via arg-list exec, records what it created in ctKernelState, and
// ctKernelDown removes EXACTLY that. The upstream ctunnel-kernel.sh is
// never executed (it sweeps unrelated rules and writes global sysctls).

// ctKernelState records every kernel object an instance created so the
// teardown is exact (per-tunnel isolation).
type ctKernelState struct {
	ifaces   []string // all devices to delete (main + lanes + -6 + -x + -r)
	fouPorts []int    // ip fou entries to delete
	routes   [][]string
	l2tpID   int // l2tp session+tunnel id to delete (0 = none)
	// xfrm objects, recorded with their EXACT specs (policies first on
	// teardown, then the states).
	xfrmPolicies [][]string
	xfrmStates   [][]string
	wgKeyFile    string
}

// ctLocalIPFor resolves the host's outbound source address toward the
// peer (their LOCAL_IP semantic; `ip -4 route get <peer>` → src). Empty on
// failure — callers fall back to local-less devices.
var ctLocalIPFor = func(peerIP string) (string, error) {
	out, err := infra.RunCmdTimeout(10*time.Second, "ip", "-4", "route", "get", peerIP)
	if err != nil {
		return "", err
	}
	for _, f := range strings.Fields(string(out)) {
		if f == "src" {
			continue
		}
	}
	i := strings.Index(string(out), " src ")
	if i < 0 {
		return "", fmt.Errorf("no src in route get output")
	}
	return strings.Fields(string(out)[i+5:])[0], nil
}

func ctDevsFor(base string, lanes int) []string {
	out := []string{base}
	for i := 1; i < lanes; i++ {
		out = append(out, fmt.Sprintf("%s.%d", base, i))
	}
	return out
}

// ctKernelUp brings ONE kernel-method instance up (direct direction):
// devices, addresses, routes, FOU, xfrm, wg, MSS clamp, notrack — all
// arg-list, all additive. The engine is NOT spawned (no env needed).
func ctKernelUp(tunnelID string, p ctunnelParams, spec ctMethodSpec, d ctDerive, peerIP string, proto string, st *ctKernelState) error {
	mtu := ctDefaultMTU(p, spec)
	lanes := p.Lanes
	if lanes < 1 {
		lanes = 1
	}
	iface := d.iface
	addrs := func(dev string) error {
		return ctIPCmd("addr", "add", d.selfTun, "peer", d.peerTun+"/32", "dev", dev)
	}
	tune := func(dev string) error {
		if err := ctIPCmd("link", "set", "dev", dev, "mtu", fmt.Sprint(mtu), "txqueuelen", "10000", "up"); err != nil {
			return err
		}
		// Per-device rp_filter loose mode (upstream parity) — scoped to
		// the device this driver created.
		_ = ctSysctl("-qw", "net.ipv4.conf."+strings.ReplaceAll(dev, ".", "/")+".rp_filter=2")
		if p.RateMbps > 0 {
			rate := p.RateMbps
			if lanes > 1 {
				rate = (p.RateMbps + lanes - 1) / lanes
			}
			burst := 1024
			if rate > 64 {
				burst = rate * 16
			}
			if err := ctTCCmd("qdisc", "replace", "dev", dev, "root", "tbf",
				"rate", fmt.Sprintf("%dmbit", rate), "burst", fmt.Sprintf("%dkbit", burst), "latency", "50ms"); err != nil {
				return err
			}
		}
		return nil
	}
	// FOU/GUE UDP wrap for the FOU-capable raw carriers (port>0 only —
	// the panel opts in by allocating a carrier port).
	fou := ""
	if p.CarrierPort > 0 && spec.supportsFOU {
		ipproto := "47"
		gue := false
		switch spec.id {
		case 4:
			ipproto = "4" // ipip
		case 1, 2, 3:
			ipproto = "41" // sit carrier
		case 12:
			gue = true // gue-ipip
		}
		if gue {
			if err := ctIPCmd("fou", "add", "port", fmt.Sprint(p.CarrierPort), "gue"); err != nil {
				return fmt.Errorf("ctunnel: fou add gue: %w", err)
			}
			fou = fmt.Sprintf("encap gue encap-sport auto encap-dport %d", p.CarrierPort)
		} else {
			if err := ctIPCmd("fou", "add", "port", fmt.Sprint(p.CarrierPort), "ipproto", ipproto); err != nil {
				return fmt.Errorf("ctunnel: fou add: %w", err)
			}
			fou = fmt.Sprintf("encap fou encap-sport auto encap-dport %d", p.CarrierPort)
		}
		st.fouPorts = append(st.fouPorts, p.CarrierPort)
	}
	fouArgs := func() []string {
		if fou == "" {
			return nil
		}
		return strings.Split(fou, " ")
	}
	greKey := p.GREKey
	if greKey == 0 {
		greKey = ctDerivedKey(tunnelID, "gre-key")
	}
	fail := func(step string, err error) error {
		ctKernelDown(tunnelID, st)
		return fmt.Errorf("ctunnel: %s: %w", step, err)
	}

	// The GRE-family outer local address: resolved from the host's route
	// toward the peer (their LOCAL_IP is the host's own carrier IP; the
	// lookup is the honest dynamic-IP equivalent). Empty = local-less
	// device args (kernel binds any).
	localIP, _ := ctLocalIPFor(peerIP)
	localArgs := func() []string {
		if localIP == "" {
			return nil
		}
		return []string{"local", localIP}
	}

	switch spec.id {
	case 5, 44, 15, 13, 11: // gre / xgre / gretap / ecmp-lanes / fou-gre
		ktype := map[int]string{5: "gre", 44: "gre", 15: "gretap", 11: "gre"}[spec.id]
		if ktype == "" { // ecmp-lanes
			ktype = "gre"
		}
		extra := []string{}
		if spec.id == 44 { // xgre: their extra args
			extra = []string{"ignore-df", "nopmtudisc"}
		}
		if err := ctKernelGreFamily(tunnelID, iface, ktype, lanes, peerIP, greKey,
			extra, fouArgs(), localArgs(), d.selfTun, d.peerTun, tune, st); err != nil {
			return err
		}
		// The raw carriers get the conntrack skip (parity with the script).
		if err := ctNotrackAdd(tunnelID, peerIP); err != nil {
			return fail("notrack", err)
		}
	case 10: // xfrm-ipsec: GRE device here; the ESP states ride ctKernelUpRole
		if err := ctKernelGreFamily(tunnelID, iface, "gre", lanes, peerIP, greKey,
			nil, fouArgs(), localArgs(), d.selfTun, d.peerTun, tune, st); err != nil {
			return err
		}
		if err := ctNotrackAdd(tunnelID, peerIP); err != nil {
			return fail("notrack", err)
		}
	case 45: // xgre-ip: keyed xGRE carrier + IPIP inside (their xgre_ip_up)
		if err := ctKernelXgreIP(tunnelID, iface, p, d, lanes, peerIP, localArgs(), fouArgs(), tune, st); err != nil {
			return err
		}
		if err := ctNotrackAdd(tunnelID, peerIP); err != nil {
			return fail("notrack", err)
		}
	case 4, 12: // ipip / gue-ipip
		args := []string{"link", "add", "name", iface, "type", "ipip"}
		args = append(args, localArgs()...)
		args = append(args, "remote", peerIP, "ttl", "255")
		args = append(args, fouArgs()...)
		if err := ctIPCmd(args...); err != nil {
			return fail("ip link add ipip", err)
		}
		st.ifaces = append(st.ifaces, iface)
		if err := tune(iface); err != nil {
			return fail("tune ipip", err)
		}
		if err := addrs(iface); err != nil {
			return fail("addr ipip", err)
		}
		if err := ctNotrackAdd(tunnelID, peerIP); err != nil {
			return fail("notrack", err)
		}
	case 3: // sit (IPv6 inside only): the sit device IS the inner carrier
		args := []string{"link", "add", "name", iface, "type", "sit"}
		args = append(args, localArgs()...)
		args = append(args, "remote", peerIP, "ttl", "255")
		args = append(args, fouArgs()...)
		if err := ctIPCmd(args...); err != nil {
			return fail("ip link add sit", err)
		}
		st.ifaces = append(st.ifaces, iface)
		if err := tune(iface); err != nil {
			return fail("tune sit", err)
		}
		if err := ctIPCmd("-6", "addr", "add", d.selfTun6+"/128", "peer", d.peerTun6+"/128", "dev", iface); err != nil {
			return fail("addr sit", err)
		}
		if err := ctNotrackAdd(tunnelID, peerIP); err != nil {
			return fail("notrack", err)
		}
	case 1, 2: // 6to4 / 6to4-gre: SIT carrier + IPIP6/IP6GRE inside
		sitDev := iface + "-6"
		args := []string{"link", "add", "name", sitDev, "type", "sit"}
		args = append(args, localArgs()...)
		args = append(args, "remote", peerIP, "ttl", "255")
		args = append(args, fouArgs()...)
		if err := ctIPCmd(args...); err != nil {
			return fail("ip link add sit carrier", err)
		}
		st.ifaces = append(st.ifaces, sitDev)
		if err := ctIPCmd("link", "set", "dev", sitDev, "mtu", fmt.Sprint(mtu+40), "up"); err != nil {
			return fail("tune sit carrier", err)
		}
		if err := ctIPCmd("-6", "addr", "add", d.selfCar6+"/64", "dev", sitDev); err != nil {
			return fail("addr sit carrier", err)
		}
		if spec.id == 1 {
			if err := ctIPCmd("-6", "tunnel", "add", iface, "mode", "ipip6", "local", d.selfCar6,
				"remote", d.peerCar6, "dev", sitDev, "encaplimit", "none"); err != nil {
				return fail("ip -6 tunnel add ipip6", err)
			}
		} else {
			if err := ctIPCmd("link", "add", "name", iface, "type", "ip6gre",
				"local", d.selfCar6, "remote", d.peerCar6); err != nil {
				return fail("ip link add ip6gre", err)
			}
		}
		st.ifaces = append(st.ifaces, iface)
		if err := tune(iface); err != nil {
			return fail("tune inner", err)
		}
		if err := addrs(iface); err != nil {
			return fail("addr inner", err)
		}
		if err := ctNotrackAdd(tunnelID, peerIP); err != nil {
			return fail("notrack", err)
		}
	case 7: // ipip6 (IPv4 inside, IPv6 carrier)
		if err := ctIPCmd("-6", "tunnel", "add", iface, "mode", "ipip6",
			"local", d.selfCar6, "remote", d.peerCar6, "encaplimit", "none"); err != nil {
			return fail("ip -6 tunnel add ipip6", err)
		}
		st.ifaces = append(st.ifaces, iface)
		if err := tune(iface); err != nil {
			return fail("tune ipip6", err)
		}
		if err := addrs(iface); err != nil {
			return fail("addr ipip6", err)
		}
	case 8: // ip6ip6 (IPv6 inside, IPv6 carrier)
		if err := ctIPCmd("-6", "tunnel", "add", iface, "mode", "ip6ip6",
			"local", d.selfCar6, "remote", d.peerCar6, "encaplimit", "none"); err != nil {
			return fail("ip -6 tunnel add ip6ip6", err)
		}
		st.ifaces = append(st.ifaces, iface)
		if err := tune(iface); err != nil {
			return fail("tune ip6ip6", err)
		}
		if err := ctIPCmd("-6", "addr", "add", d.selfTun6+"/128", "peer", d.peerTun6+"/128", "dev", iface); err != nil {
			return fail("addr ip6ip6", err)
		}
	case 6, 16: // ip6gre / ip6gretap (v6 underlay)
		ktype := "ip6gre"
		if spec.id == 16 {
			ktype = "ip6gretap"
		}
		if err := ctKernelGreFamily(tunnelID, iface, ktype, lanes, peerIP, greKey,
			nil, nil, nil, d.selfTun, d.peerTun, tune, st); err != nil {
			return err
		}
	case 17: // vxlan
		vni := p.VNI
		if vni == 0 {
			vni = ctDerivedKey(tunnelID, "vni")
		}
		if err := ctIPCmd("link", "add", iface, "type", "vxlan", "id", fmt.Sprint(vni),
			"remote", peerIP, "dstport", fmt.Sprint(p.CarrierPort), "nolearning"); err != nil {
			return fail("ip link add vxlan", err)
		}
		st.ifaces = append(st.ifaces, iface)
		if err := tune(iface); err != nil {
			return fail("tune vxlan", err)
		}
		if err := addrs(iface); err != nil {
			return fail("addr vxlan", err)
		}
	case 18: // geneve
		vni := p.VNI
		if vni == 0 {
			vni = ctDerivedKey(tunnelID, "vni")
		}
		if err := ctIPCmd("link", "add", iface, "type", "geneve", "id", fmt.Sprint(vni),
			"remote", peerIP, "dstport", fmt.Sprint(p.CarrierPort)); err != nil {
			return fail("ip link add geneve", err)
		}
		st.ifaces = append(st.ifaces, iface)
		if err := tune(iface); err != nil {
			return fail("tune geneve", err)
		}
		if err := addrs(iface); err != nil {
			return fail("addr geneve", err)
		}
	case 41: // bareudp (kernel 5.7+; peer-locked INPUT — their security rule)
		if err := ctIPCmd("link", "add", iface, "type", "bareudp",
			"dstport", fmt.Sprint(p.CarrierPort), "ethertype", "ipv4"); err != nil {
			return fail("ip link add bareudp", err)
		}
		st.ifaces = append(st.ifaces, iface)
		if err := tune(iface); err != nil {
			return fail("tune bareudp", err)
		}
		if err := addrs(iface); err != nil {
			return fail("addr bareudp", err)
		}
		// bareudp has no peer of its own: the route to the far tunnel
		// address names the outer destination (lightweight encap).
		if err := ctIPCmd("route", "replace", d.peerTun+"/32", "dev", iface, "proto", "77",
			"src", d.selfTun, "encap", "ip", "id", "0", "dst", peerIP, "src", "0.0.0.0", "ttl", "64"); err != nil {
			return fail("route bareudp", err)
		}
		// Unlike GRE, bareudp takes UDP from any address and hands what is
		// inside to the stack. Only the peer may feed it, or anyone could
		// inject packets. This is the ONE deny-shaped rule the driver adds,
		// scoped to OUR tunnel's own dport and tagged for exact teardown —
		// without it the method is unusable (upstream dies without it).
		drop := []string{"-I", "INPUT", "-p", "udp", "--dport", fmt.Sprint(p.CarrierPort),
			"!", "-s", peerIP + "/32", "-m", "comment", "--comment", ctComment(tunnelID), "-j", "DROP"}
		if _, err := acctIptables(ctRuleCheck(drop)...); err != nil {
			if _, err := acctIptables(drop...); err != nil {
				return fail("bareudp peer-lock", err)
			}
		}
		st.routes = append(st.routes, drop)
	case 19: // l2tpv3 static pseudowire (IP 115 or UDP)
		tid := int(p.TunnelID)
		if tid == 0 {
			tid = int(ctDerivedKey(tunnelID, "tunnel-id"))
		}
		if p.CarrierPort > 0 {
			if err := ctIPCmd("l2tp", "add", "tunnel", "tunnel_id", fmt.Sprint(tid),
				"peer_tunnel_id", fmt.Sprint(tid), "encap", "udp",
				"remote", peerIP, "udp_sport", fmt.Sprint(p.CarrierPort), "udp_dport", fmt.Sprint(p.CarrierPort)); err != nil {
				return fail("ip l2tp add tunnel", err)
			}
		} else {
			if err := ctIPCmd("l2tp", "add", "tunnel", "tunnel_id", fmt.Sprint(tid),
				"peer_tunnel_id", fmt.Sprint(tid), "encap", "ip", "remote", peerIP); err != nil {
				return fail("ip l2tp add tunnel", err)
			}
		}
		if err := ctIPCmd("l2tp", "add", "session", "name", iface, "tunnel_id", fmt.Sprint(tid),
			"session_id", fmt.Sprint(tid), "peer_session_id", fmt.Sprint(tid)); err != nil {
			st.l2tpID = tid
			ctKernelDown(tunnelID, st)
			return fmt.Errorf("ctunnel: ip l2tp add session: %w", err)
		}
		st.l2tpID = tid
		st.ifaces = append(st.ifaces, iface)
		if err := tune(iface); err != nil {
			return fail("tune l2tpv3", err)
		}
		if err := addrs(iface); err != nil {
			return fail("addr l2tpv3", err)
		}
		if err := ctNotrackAdd(tunnelID, peerIP); err != nil {
			return fail("notrack", err)
		}
	case 9: // wireguard (kernel; wg set via arg-list, keyfile 0600)
		if err := ctKernelWireguard(tunnelID, p, d, peerIP, st); err != nil {
			return err
		}
		if err := tune(iface); err != nil {
			return fail("tune wg", err)
		}
		if err := addrs(iface); err != nil {
			return fail("addr wg", err)
		}
	default:
		return fmt.Errorf("ctunnel: method %s is not a driver-side kernel kind", p.Method)
	}

	// MSS clamp on OUR devices (parity with fw_apply; harmless for p2p).
	if err := ctMSSClampAdd(tunnelID, iface); err != nil {
		return fail("mss clamp", err)
	}
	_ = proto
	return nil
}

// ctKernelUpRole is ctKernelUp with the resolved role folded in for the
// xfrm/ipsec derivation (kept separate to keep ctKernelUp's signature
// simple; role is only needed for the SPI/key labels).
func ctKernelUpRole(tunnelID, role string, p ctunnelParams, spec ctMethodSpec, d ctDerive, peerIP string, proto string, st *ctKernelState) error {
	if spec.id == 10 {
		// The GRE device + xfrm states/policies (their ipsec_up, arg-list).
		// The ESP states bind the GRE OUTER addresses — a real local is
		// REQUIRED (xfrm cannot key an any-address device).
		localIP, err := ctLocalIPFor(peerIP)
		if err != nil || localIP == "" {
			return fmt.Errorf("ctunnel: xfrm-ipsec needs the host's outbound source address toward the peer (route lookup failed: %v)", err)
		}
		if err := ctKernelUp(tunnelID, p, spec, d, peerIP, proto, st); err != nil {
			return err
		}
		spiOut, keyOut := ctIPsecSA(p.Secret, role)
		spiIn, keyIn := ctIPsecSA(p.Secret, ctPeerRole(role))
		addState := func(src, dst, spi, key string) error {
			args := []string{"xfrm", "state", "add", "src", src, "dst", dst,
				"proto", "esp", "spi", spi, "reqid", spi, "mode", "transport",
				"aead", "rfc4106(gcm(aes))", key, "128", "replay-window", "1024"}
			if err := ctIPCmd(args...); err != nil {
				return err
			}
			st.xfrmStates = append(st.xfrmStates, args)
			return nil
		}
		addPolicy := func(src, dst, dir, spi string) error {
			args := []string{"xfrm", "policy", "add", "src", src, "dst", dst,
				"proto", "gre", "dir", dir, "tmpl", "src", src, "dst", dst,
				"proto", "esp", "reqid", spi, "mode", "transport"}
			if err := ctIPCmd(args...); err != nil {
				return err
			}
			st.xfrmPolicies = append(st.xfrmPolicies, args)
			return nil
		}
		if err := addState(localIP, peerIP, spiOut, keyOut); err != nil {
			ctKernelDown(tunnelID, st)
			return fmt.Errorf("ctunnel: xfrm state add out: %w", err)
		}
		if err := addState(peerIP, localIP, spiIn, keyIn); err != nil {
			ctKernelDown(tunnelID, st)
			return fmt.Errorf("ctunnel: xfrm state add in: %w", err)
		}
		if err := addPolicy(localIP+"/32", peerIP+"/32", "out", spiOut); err != nil {
			ctKernelDown(tunnelID, st)
			return fmt.Errorf("ctunnel: xfrm policy add out: %w", err)
		}
		if err := addPolicy(peerIP+"/32", localIP+"/32", "in", spiIn); err != nil {
			ctKernelDown(tunnelID, st)
			return fmt.Errorf("ctunnel: xfrm policy add in: %w", err)
		}
		return nil
	}
	return ctKernelUp(tunnelID, p, spec, d, peerIP, proto, st)
}

// ctKernelGreFamily creates the gre/gretap/ip6gre/ip6gretap/xgre devices
// (with optional FOU + ECMP lanes; their gre_up shape — the key increments
// per lane, the tunnel address rides every lane dev).
func ctKernelGreFamily(tunnelID, iface, ktype string, lanes int, peerIP string, greKey uint32, extra, fouArgs, localArgs []string,
	selfTun, peerTun string, tune func(string) error, st *ctKernelState) error {
	for i := 0; i < lanes; i++ {
		dev := iface
		if i > 0 {
			dev = fmt.Sprintf("%s.%d", iface, i)
		}
		args := []string{"link", "add", "name", dev, "type", ktype}
		args = append(args, localArgs...)
		args = append(args, "remote", peerIP, "ttl", "255")
		args = append(args, extra...)
		if greKey > 0 {
			args = append(args, "key", fmt.Sprint(uint64(greKey)+uint64(i)))
		}
		args = append(args, fouArgs...)
		if err := ctIPCmd(args...); err != nil {
			ctKernelDown(tunnelID, st)
			return fmt.Errorf("ctunnel: ip link add %s: %w", ktype, err)
		}
		st.ifaces = append(st.ifaces, dev)
		if err := tune(dev); err != nil {
			ctKernelDown(tunnelID, st)
			return fmt.Errorf("ctunnel: tune %s: %w", ktype, err)
		}
		if lanes > 1 {
			if err := ctIPCmd("addr", "add", selfTun+"/32", "dev", dev); err != nil {
				ctKernelDown(tunnelID, st)
				return fmt.Errorf("ctunnel: lane addr: %w", err)
			}
		} else if err := ctIPCmd("addr", "add", selfTun, "peer", peerTun+"/32", "dev", dev); err != nil {
			ctKernelDown(tunnelID, st)
			return fmt.Errorf("ctunnel: addr %s: %w", ktype, err)
		}
	}
	if lanes > 1 {
		// ECMP multipath route (proto 77 = the script's marker protocol).
		nexthops := []string{}
		for i := 0; i < lanes; i++ {
			dev := iface
			if i > 0 {
				dev = fmt.Sprintf("%s.%d", iface, i)
			}
			if i > 0 {
				nexthops = append(nexthops, "nexthop")
			}
			nexthops = append(nexthops, "dev", dev, "weight", "1")
		}
		args := append([]string{"route", "replace", peerTun + "/32", "proto", "77"}, nexthops...)
		if err := ctIPCmd(args...); err != nil {
			ctKernelDown(tunnelID, st)
			return fmt.Errorf("ctunnel: ecmp route: %w", err)
		}
		st.routes = append(st.routes, args)
	}
	return nil
}

// ctKernelXgreIP creates the xGRE carrier + IPIP inside (their
// xgre_ip_up shape: 172.30.<index>.x carrier addrs on the xGRE, IPIP on top).
func ctKernelXgreIP(tunnelID, iface string, p ctunnelParams, d ctDerive, lanes int, peerIP string,
	localArgs, fouArgs []string, tune func(string) error, st *ctKernelState) error {
	greKey := p.GREKey
	if greKey == 0 {
		greKey = ctDerivedKey(tunnelID, "gre-key")
	}
	for i := 0; i < lanes; i++ {
		xd := iface + "-x"
		if i > 0 {
			xd = fmt.Sprintf("%s-x.%d", iface, i)
		}
		args := []string{"link", "add", "name", xd, "type", "gre"}
		args = append(args, localArgs...)
		args = append(args, "remote", peerIP, "ttl", "255",
			"ignore-df", "nopmtudisc", "key", fmt.Sprint(uint64(greKey)+uint64(i)))
		args = append(args, fouArgs...)
		if err := ctIPCmd(args...); err != nil {
			ctKernelDown(tunnelID, st)
			return fmt.Errorf("ctunnel: ip link add xgre carrier: %w", err)
		}
		st.ifaces = append(st.ifaces, xd)
		if err := ctIPCmd("link", "set", "dev", xd, "mtu", fmt.Sprint(ctDefaultMTU(p, ctMethods["xgre-ip"])+20), "txqueuelen", "10000", "up"); err != nil {
			ctKernelDown(tunnelID, st)
			return fmt.Errorf("ctunnel: tune xgre carrier: %w", err)
		}
		// The xGRE carries the IPIP underlay pair: deterministic 172.30 space
		// (upstream's carrier addressing for this method).
		xLocal := fmt.Sprintf("172.30.%d.1", d.index)
		xPeer := fmt.Sprintf("172.30.%d.2", d.index)
		if err := ctIPCmd("addr", "add", xLocal, "peer", xPeer+"/32", "dev", xd); err != nil {
			ctKernelDown(tunnelID, st)
			return fmt.Errorf("ctunnel: xgre carrier addr: %w", err)
		}
	}
	if err := ctIPCmd("link", "add", "name", iface, "type", "ipip",
		"local", fmt.Sprintf("172.30.%d.1", d.index), "remote", fmt.Sprintf("172.30.%d.2", d.index), "ttl", "255"); err != nil {
		ctKernelDown(tunnelID, st)
		return fmt.Errorf("ctunnel: ip link add xgre-ip inner: %w", err)
	}
	st.ifaces = append(st.ifaces, iface)
	if err := tune(iface); err != nil {
		ctKernelDown(tunnelID, st)
		return fmt.Errorf("ctunnel: tune xgre-ip inner: %w", err)
	}
	return nil
}

// ctKernelWireguard brings the kernel WG device up (their wireguard case:
// ip link + wg set via a 0600 keyfile; endpoint only when this end dials).
func ctKernelWireguard(tunnelID string, p ctunnelParams, d ctDerive, peerIP string, st *ctKernelState) error {
	if err := ctIPCmd("link", "add", "dev", d.iface, "type", "wireguard"); err != nil {
		return fmt.Errorf("ctunnel: ip link add wireguard: %w", err)
	}
	st.ifaces = append(st.ifaces, d.iface)
	priv, pub := ctWireGuardKeys(p.Secret, "kharej")
	_, peerPub := ctWireGuardKeys(p.Secret, "iran")
	_ = pub
	keyfile, err := ctWriteKeyFile(priv)
	if err != nil {
		ctKernelDown(tunnelID, st)
		return err
	}
	st.wgKeyFile = keyfile
	args := []string{"set", d.iface, "listen-port", fmt.Sprint(p.CarrierPort),
		"private-key", keyfile, "peer", peerPub, "allowed-ips", "0.0.0.0/0"}
	// The endpoint goes on the DIALING end only (upstream: skip endpoint
	// when REVERSE=1 && ROLE=iran — that end only listens).
	role, rerr := ctResolveRole(p)
	dials := true
	if rerr == nil && role == "iran" && ctDefaultDirection(p.Direction) == "reverse" {
		dials = false
	}
	if dials {
		args = append(args, "endpoint", net.JoinHostPort(peerIP, fmt.Sprint(p.CarrierPort)),
			"persistent-keepalive", "15")
	}
	if err := ctWgCmd(args...); err != nil {
		_ = os.Remove(keyfile)
		ctKernelDown(tunnelID, st)
		return fmt.Errorf("ctunnel: wg set: %w", err)
	}
	_ = os.Remove(keyfile)
	st.wgKeyFile = ""
	return nil
}

// ctWriteKeyFile writes the WG private key to a 0600 temp file (their
// umask 077 mktemp shape; argv never carries the key).
func ctWriteKeyFile(private string) (string, error) {
	f, err := os.CreateTemp("", "ctdrv-wg-*.key")
	if err != nil {
		return "", fmt.Errorf("ctunnel: wg keyfile: %w", err)
	}
	path := f.Name()
	if err := os.Chmod(path, 0o600); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if _, err := f.WriteString(private + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// ctKernelDown removes EXACTLY what ctKernelUp created (per-tunnel
// isolation; absence tolerated — Stop must always succeed). Every object
// is deleted from its RECORDED spec, never re-derived.
func ctKernelDown(tunnelID string, st *ctKernelState) {
	for _, args := range st.xfrmPolicies {
		// policies: swap "add" → "delete", drop the tmpl tail
		del := make([]string, 0, len(args))
		for _, a := range args {
			if a == "add" {
				del = append(del, "delete")
			} else if a == "tmpl" {
				break
			} else {
				del = append(del, a)
			}
		}
		_ = ctIPCmd(del...)
	}
	st.xfrmPolicies = nil
	for _, args := range st.xfrmStates {
		del := make([]string, 0, len(args))
		for _, a := range args {
			if a == "add" {
				del = append(del, "delete")
			} else {
				del = append(del, a)
			}
		}
		_ = ctIPCmd(del...)
	}
	st.xfrmStates = nil
	for _, r := range st.routes {
		switch {
		case len(r) > 1 && r[1] == "route":
			del := append([]string{"route", "del"}, r[2:]...)
			_ = ctIPCmd(del...)
		default: // iptables rules rendered with the real action
			del := ctRuleDelete(r)
			_, _ = acctIptables(del...)
		}
	}
	st.routes = nil
	if st.l2tpID != 0 {
		tid := fmt.Sprint(st.l2tpID)
		_ = ctIPCmd("l2tp", "del", "session", "tunnel_id", tid, "session_id", tid)
		_ = ctIPCmd("l2tp", "del", "tunnel", "tunnel_id", tid)
		st.l2tpID = 0
	}
	for _, dev := range st.ifaces {
		_ = ctIPCmd("link", "del", "dev", dev)
	}
	st.ifaces = nil
	for _, port := range st.fouPorts {
		_ = ctIPCmd("fou", "del", "port", fmt.Sprint(port))
	}
	st.fouPorts = nil
	if st.wgKeyFile != "" {
		_ = os.Remove(st.wgKeyFile)
		st.wgKeyFile = ""
	}
}

// ---- the in-agent relay (TUN + kernel families; unchanged from v1) ------

// ctRelay is the in-agent TCP+UDP relay on the kharej-role end: listens on
// the end's own tunnel IP:<target port>, dials params.local_addr. The
// bind retries with capped backoff (the TUN address exists only after the
// tunnel is up). Zero goroutines after Close.
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
// or the relay closes (the TUN address exists only once the tunnel is up).
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
		// retry until the tunnel interface comes up.
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

// ---- wire accounting (kernel-socket carriers + L4 public ports) ---------

const (
	ctAcctIn  = "CTDRV_ACCT_IN"
	ctAcctOut = "CTDRV_ACCT_OUT"
)

func ctWireRulesEnsure() error {
	if _, err := acctIptables("-N", ctAcctIn); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return err
	}
	if _, err := acctIptables("-N", ctAcctOut); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return err
	}
	if _, err := acctIptables("-C", "INPUT", "-j", ctAcctIn); err != nil {
		if _, err := acctIptables("-A", "INPUT", "-j", ctAcctIn); err != nil {
			return err
		}
	}
	if _, err := acctIptables("-C", "OUTPUT", "-j", ctAcctOut); err != nil {
		if _, err := acctIptables("-A", "OUTPUT", "-j", ctAcctOut); err != nil {
			return err
		}
	}
	return nil
}

// ctWireRulesAdd wires accounting for ONE instance. proto "udp" = the
// UDP-carried TUN families (carrier port); "tcp"/"both" on the L4 methods
// = the engine's own public listeners (normal kernel sockets).
func ctWireRulesAdd(tunnelID, proto string, port int) error {
	if err := ctWireRulesEnsure(); err != nil {
		return err
	}
	cmt := ctComment(tunnelID)
	p := fmt.Sprint(port)
	for _, pr := range ctProtosFor(proto) {
		if _, err := acctIptables("-A", ctAcctIn, "-p", pr, "--dport", p,
			"-m", "comment", "--comment", cmt); err != nil {
			return err
		}
		if _, err := acctIptables("-A", ctAcctOut, "-p", pr, "--sport", p,
			"-m", "comment", "--comment", cmt); err != nil {
			return err
		}
	}
	return nil
}

func ctWireRulesDel(tunnelID, proto string, port int) {
	cmt := ctComment(tunnelID)
	p := fmt.Sprint(port)
	for _, pr := range ctProtosFor(proto) {
		_, _ = acctIptables("-D", ctAcctIn, "-p", pr, "--dport", p, "-m", "comment", "--comment", cmt)
		_, _ = acctIptables("-D", ctAcctOut, "-p", pr, "--sport", p, "-m", "comment", "--comment", cmt)
	}
}

// ctWireBytes reads the instance's carrier counters (iptables-save -c,
// exact bytes; same parse shape as acctWireBytes). matchDport selects
// --dport (rx) vs --sport (tx) lines for the given port.
func ctWireBytes(tunnelID, proto string, port int) (rx, tx uint64, ok bool) {
	out, err := acctIptablesSave()
	if err != nil {
		return 0, 0, false
	}
	cmt := ctComment(tunnelID)
	rng := fmt.Sprint(port)
	protos := map[string]bool{}
	for _, pr := range ctProtosFor(proto) {
		protos[pr] = true
	}
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
		if !lineProtocolMatch(line, protos) {
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

// lineProtocolMatch greps the protocol token out of an iptables-save line
// ("-p tcp"/"-p udp" or "-p 47"-style) and reports whether it belongs to
// this accounting row's protocol set.
func lineProtocolMatch(line string, protos map[string]bool) bool {
	for _, f := range strings.Fields(line) {
		if f != "-p" {
			continue
		}
		i := strings.Index(line, "-p ")
		if i < 0 {
			return false
		}
		rest := strings.Fields(line[i+3:])
		if len(rest) == 0 {
			return false
		}
		val := strings.ToLower(strings.Trim(rest[0], "\""))
		if val == "icmp" || val == "ipv4" || val == "ipv6" {
			return false
		}
		return protos[val]
	}
	return false
}

// ---- instance state + driver --------------------------------------------

// ctInstState is one RUNNING instance's state. proc/stop/binPath ride the
// shared engineInst; the family-specific pieces ride here so Stop's
// teardown removes exactly what Start created (rules BEFORE the env file —
// it holds the SECRET — then the interfaces/kernel objects).
type ctInstState struct {
	engineInst
	params    ctunnelParams
	spec      ctMethodSpec
	role      string // ctunnel role: "iran" (server_side end) | "kharej"
	dir       string
	iface     string // the device the ENGINE opens (or "" for L4)
	selfTun   string
	peerTun   string
	envPath   string
	relay     *ctRelay       // kharej end, interface families with forwards
	kernel    *ctKernelState // kernel families (both directions)
	hasKernel bool
}

// CtunnelDriver implements engine.Driver for C-Tunnel v2.
type CtunnelDriver struct {
	runs *instTable[ctInstState]
}

func NewCtunnelDriver() *CtunnelDriver { return &CtunnelDriver{runs: newInstTable[ctInstState]()} }

func (d *CtunnelDriver) ID() string { return ctunnelID }

// ctInstalledVersion reports the installed ctunnel version for Describe()
// (§2.22 display): the newest cached artifact dir's ctunnel-engine is
// probed with `-version` (bounded; seam-able; 60s cache). Without a cache
// the build-time pin is reported honestly.
var ctVersionProbe = func(binPath string) (string, error) {
	out, err := infra.RunCmdTimeout(10*time.Second, binPath, "-version")
	if err != nil {
		return "", err
	}
	f := strings.Fields(strings.TrimSpace(string(out)))
	if len(f) >= 2 && f[0] == "ctunnel-engine" {
		return f[1], nil
	}
	return "", fmt.Errorf("ctunnel: unexpected -version output")
}

func ctInstalledVersion() string {
	base := filepath.Join(engineEngineDir(ctunnelID), "bin")
	entries, err := os.ReadDir(base)
	if err != nil {
		return ctPinnedVersion
	}
	// Deterministic newest: highest version whose cache marker exists.
	best := ""
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		v := e.Name()
		if !engineCacheHit(filepath.Join(base, v), strings.Repeat("0", 64), []string{"ctunnel-engine"}) {
			// marker mismatch is fine here — we only need the binary to
			// exist and to report; still prefer dirs that look like versions
			if !infra.FileExists(filepath.Join(base, v, "ctunnel-engine")) {
				continue
			}
		}
		if ctVersionLess(best, v) {
			best = v
		}
	}
	if best == "" {
		return ctPinnedVersion
	}
	if v, err := ctVersionProbe(filepath.Join(base, best, "ctunnel-engine")); err == nil && v != "" {
		return v
	}
	return best
}

// ctVersionLess is a minimal numeric-dotted comparison (no semver deps).
func ctVersionLess(a, b string) bool {
	if a == "" {
		return true
	}
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, e1 := strconv.Atoi(pa[i])
		y, e2 := strconv.Atoi(pb[i])
		if e1 != nil || e2 != nil {
			return a < b
		}
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

var (
	ctVerMu      sync.Mutex
	ctVerCached  string
	ctVerCacheAt time.Time
)

// cachedInstalledVersion throttles the -version probe (Describe() is on
// the catalog path — once per panel poll at most, cache 60s).
func cachedInstalledVersion() string {
	ctVerMu.Lock()
	defer ctVerMu.Unlock()
	if ctVerCached != "" && time.Since(ctVerCacheAt) < 60*time.Second {
		return ctVerCached
	}
	v := ctInstalledVersion()
	ctVerCached = v
	ctVerCacheAt = time.Now()
	return v
}

func (d *CtunnelDriver) Describe() engine.EngineInfo {
	methods := ctMethodList()
	schema := map[string]any{
		"server_side": "", "version": ctPinnedVersion,
		"artifact": "..{arch}..", "method": methods,
		"direction":    []string{"reverse", "direct"},
		"foreign_addr": "host:port", "carrier_port": 0, "public_port": 0,
		"local_addr": "127.0.0.1:5201", "proto": []string{"tcp", "udp", "both"},
		"secret": "64-hex", "padding": 0, "mtu": 1400,
		"lanes": 0, "gre_key": 0, "vni": 0, "tunnel_id": 0,
		"rate_mbps": 0, "sni": "", "peer_addr": "host:port",
		"_families": map[string]int{
			"kernel-l3": 16, "kernel-l2": 7, "udp-crypt": 11,
			"stealth": 2, "reverse-l4": 9, "gaming": 4,
		},
	}
	raw, _ := json.Marshal(schema)
	return engine.EngineInfo{ID: ctunnelID, Version: cachedInstalledVersion(), ParamsSchema: raw}
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
// the wstunnel shape. The artifact carries the THREE v2 binaries; the
// agent extracts only ctunnel-engine.
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
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, ctunnelID,
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

// Start implements engine.Driver: validate → role → derive → (engine
// families) verified binary → 0600 env file → iface/kernel setup → spawn →
// supervise → (iran end) DNAT/SNAT + accounting; (kharej end) in-agent
// relay. Kernel-direct families skip the engine entirely.
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
		if engineParamsEqual[ctunnelParams](prev.params, p) && prev.current() != nil {
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
	spec := ctMethods[strings.ToLower(strings.TrimSpace(p.Method))]
	dir := ctDeriveFor(inst.TunnelID, role)
	direction := ctDefaultDirection(p.Direction)
	proto := ctDefaultProto(p.Proto)
	st := &ctInstState{params: p, spec: spec, role: role, dir: direction}
	st.stop = make(chan struct{})

	// Interface-carrying families: the device the ENGINE opens ("" = L4).
	switch {
	case spec.l4():
		// Engine-only: the engine binds the public forwards itself.
	case spec.kernelKind() && !ctEngineNeeded(spec, direction):
		// Kernel-direct: driver-side kernel ops, NO engine, NO env file.
		// Each end points its device at the OTHER end's carrier: the iran
		// end dials foreign_addr (direct mode: the kharej end); the kharej
		// end points at peer_addr (the server_side end's carrier).
		peerIP := hostOf(strings.TrimSpace(p.ForeignAddr))
		if role == "kharej" {
			peerIP = hostOf(strings.TrimSpace(p.PeerAddr))
		}
		ks := &ctKernelState{}
		st.kernel, st.hasKernel = ks, true
		st.iface = dir.iface
		st.selfTun, st.peerTun = dir.selfTun, dir.peerTun
		if err := ctKernelUpRole(inst.TunnelID, role, p, spec, dir, peerIP, proto, ks); err != nil {
			return err
		}
		d.runs.put(inst.TunnelID, st)
		// Public-port rules + relay composition (same as the engine families).
		if role == "iran" {
			if spec.id == 3 || spec.id == 8 { // IPv6-inner-only methods
				if err := ctForwardRulesV6Add(inst.TunnelID, proto, p.PublicPort, ctTargetPort(p), dir.selfTun6, dir.peerTun6); err != nil {
					fmt.Fprintf(os.Stderr, "ctunnel: v6 forward rules unavailable: %v\n", err)
				}
			} else if err := ctForwardRulesAdd(inst.TunnelID, proto, p.PublicPort, ctTargetPort(p), dir.selfTun, dir.peerTun); err != nil {
				fmt.Fprintf(os.Stderr, "ctunnel: forward rules unavailable: %v\n", err)
			}
			if p.CarrierPort > 0 && spec.supportsFOU {
				// FOU-wrapped raw carriers ride kernel UDP on this port.
				if err := ctWireRulesAdd(inst.TunnelID, "udp", p.CarrierPort); err != nil {
					fmt.Fprintf(os.Stderr, "ctunnel: wire accounting unavailable: %v\n", err)
				}
			}
		} else {
			if spec.id == 3 || spec.id == 8 {
				if err := ctRelayInputRulesV6Add(inst.TunnelID, dir.iface, proto, ctTargetPort(p)); err != nil {
					fmt.Fprintf(os.Stderr, "ctunnel: relay INPUT rule unavailable: %v\n", err)
				}
			} else if err := ctRelayInputRulesAdd(inst.TunnelID, dir.iface, proto, ctTargetPort(p)); err != nil {
				fmt.Fprintf(os.Stderr, "ctunnel: relay INPUT rule unavailable: %v\n", err)
			}
			st.relay = ctStartRelay(st.stop, net.JoinHostPort(bindHostFor(spec, dir), fmt.Sprint(ctTargetPort(p))),
				strings.TrimSpace(p.LocalAddr), proto)
		}
		return nil
	default:
		// TUN/TAP + engine (userspace kinds) or kernel-reverse (engine
		// carrier + kernel device riding it).
	}

	binDir, err := ctEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "ctunnel-engine")
	if err := os.MkdirAll(filepath.Dir(ctEnvPath(inst.TunnelID)), 0o700); err != nil {
		return fmt.Errorf("ctunnel: instance dir: %w", err)
	}
	envPath := ctEnvPath(inst.TunnelID)
	// 0600: the env file carries SECRET.
	if err := os.WriteFile(envPath, ctEnvText(p, role, direction, dir, inst.TunnelID), 0o600); err != nil {
		return fmt.Errorf("ctunnel: write env: %w", err)
	}
	st.envPath = envPath

	// Interface setup (the engine attaches to an EXISTING TUN/TAP via
	// TUNSETIFF; kernel-reverse additionally rides the <dev>-r carrier
	// TUN — the env names it in DEV and the driver creates exactly that).
	tap := spec.id == 14 || spec.id == 20 // eoip / etherip
	engineDev := dir.iface
	if spec.l4() {
		engineDev = "" // no tunnel interface: the engine binds the forwards
	}
	if spec.kernelKind() && !spec.userspace && direction == "reverse" && spec.id != 9 {
		engineDev = dir.iface + "-r"
	}
	st.iface = dir.iface
	st.selfTun, st.peerTun = dir.selfTun, dir.peerTun
	if engineDev != "" {
		if err := ctIfaceUp(engineDev, ctDefaultMTU(p, spec), tap,
			revSelfTun(spec, direction, dir), revPeerTun(spec, direction, dir),
			dir.selfTun6, dir.peerTun6); err != nil {
			_ = os.Remove(envPath)
			return err
		}
		st.iface = engineDev
	}

	// Kernel-reverse: the kernel device rides the carrier TUN (their
	// REVERSE branch: the device's local/remote = the 172.31 pair).
	if spec.kernelKind() && !spec.userspace && direction == "reverse" && spec.id != 9 {
		ks := &ctKernelState{}
		st.kernel, st.hasKernel = ks, true
		kp := p
		// The kernel device's underlay = the carrier TUN addresses.
		kp.ForeignAddr = net.JoinHostPort(dir.peerRev4, "0")
		ks.ifaces = append(ks.ifaces, dir.iface)
		if err := ctKernelDeviceReverse(inst.TunnelID, kp, spec, dir, ks); err != nil {
			_ = os.Remove(envPath)
			_ = ctIfaceDel(engineDev)
			return err
		}
	}

	proc, err := ctSpawn(binPath, ctEngineArgs(envPath))
	if err != nil {
		_ = os.Remove(envPath)
		_ = ctIfaceDel(engineDev)
		if st.hasKernel {
			ctKernelDown(inst.TunnelID, st.kernel)
		}
		return err
	}
	st.proc = proc
	st.binPath = binPath
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, binPath, "", func(b, _ string) (frpProcess, error) {
		return ctSpawn(b, ctEngineArgs(envPath))
	})

	target := strings.TrimSpace(p.LocalAddr)
	targetPort := ctTargetPort(p)
	if role == "iran" {
		// The iran end: forwards (L4: the engine binds them itself — no
		// iptables; interface families: the DNAT/SNAT set) + accounting.
		if spec.l4() {
			if err := ctWireRulesAdd(inst.TunnelID, proto, p.PublicPort); err != nil {
				fmt.Fprintf(os.Stderr, "ctunnel: wire accounting unavailable: %v\n", err)
			}
		} else {
			if spec.id == 3 || spec.id == 8 {
				if err := ctForwardRulesV6Add(inst.TunnelID, proto, p.PublicPort, targetPort, dir.selfTun6, dir.peerTun6); err != nil {
					fmt.Fprintf(os.Stderr, "ctunnel: v6 forward rules unavailable: %v\n", err)
				}
			} else if err := ctForwardRulesAdd(inst.TunnelID, proto, p.PublicPort, targetPort, dir.selfTun, dir.peerTun); err != nil {
				fmt.Fprintf(os.Stderr, "ctunnel: forward rules unavailable: %v\n", err)
			}
			if spec.crypt() && spec.id != 37 && spec.id != 38 {
				// UDP-carried TUN families: carrier-port accounting.
				if err := ctWireRulesAdd(inst.TunnelID, "udp", p.CarrierPort); err != nil {
					fmt.Fprintf(os.Stderr, "ctunnel: wire accounting unavailable: %v\n", err)
				}
			}
		}
	} else if spec.kernelKind() && !spec.userspace && direction == "reverse" && spec.id != 9 {
		// Reverse kernel: the kharej end still delivers via the relay on
		// its own INNER tunnel address (the DNAT targets it from the iran
		// end through the kernel device).
		if err := ctRelayInputRulesAdd(inst.TunnelID, dir.iface, proto, targetPort); err != nil {
			fmt.Fprintf(os.Stderr, "ctunnel: relay INPUT rule unavailable: %v\n", err)
		}
		st.relay = ctStartRelay(st.stop, net.JoinHostPort(dir.selfTun, fmt.Sprint(targetPort)), target, proto)
	} else if !spec.l4() {
		// The relay's delivery: packets arriving on the tunnel interface
		// for the end's own tunnel IP:target must reach the in-agent relay.
		if spec.id == 3 || spec.id == 8 {
			if err := ctRelayInputRulesV6Add(inst.TunnelID, dir.iface, proto, targetPort); err != nil {
				fmt.Fprintf(os.Stderr, "ctunnel: relay INPUT rule unavailable: %v\n", err)
			}
		} else if err := ctRelayInputRulesAdd(inst.TunnelID, dir.iface, proto, targetPort); err != nil {
			fmt.Fprintf(os.Stderr, "ctunnel: relay INPUT rule unavailable: %v\n", err)
		}
		if spec.id != 3 && spec.id != 8 { // v6-only methods bind the ULA pair
			st.relay = ctStartRelay(st.stop, net.JoinHostPort(dir.selfTun, fmt.Sprint(targetPort)), target, proto)
		} else {
			st.relay = ctStartRelay(st.stop, net.JoinHostPort(dir.selfTun6, fmt.Sprint(targetPort)), target, proto)
		}
	}
	return nil
}

func bindHostFor(spec ctMethodSpec, d ctDerive) string {
	if spec.id == 3 || spec.id == 8 {
		return d.selfTun6
	}
	return d.selfTun
}

func revSelfTun(spec ctMethodSpec, direction string, d ctDerive) string {
	if spec.kernelKind() && !spec.userspace && direction == "reverse" && spec.id != 9 {
		return d.selfRev4
	}
	if spec.id == 3 || spec.id == 8 {
		return d.selfTun6
	}
	return d.selfTun
}

func revPeerTun(spec ctMethodSpec, direction string, d ctDerive) string {
	if spec.kernelKind() && !spec.userspace && direction == "reverse" && spec.id != 9 {
		return d.peerRev4
	}
	if spec.id == 3 || spec.id == 8 {
		return d.peerTun6
	}
	return d.peerTun
}

// ctRelayInputRulesV6Add/Del — the v6 variant of the relay INPUT accepts.
func ctRelayInputRulesV6Args(tunnelID, iface, proto string, targetPort int) [][]string {
	cmt := ctComment(tunnelID)
	out := make([][]string, 0, len(ctProtosFor(proto)))
	for _, pr := range ctProtosFor(proto) {
		out = append(out, []string{"-I", "INPUT", "-i", iface, "-p", pr,
			"--dport", fmt.Sprint(targetPort), "-j", "ACCEPT",
			"-m", "comment", "--comment", cmt})
	}
	return out
}

func ctRelayInputRulesV6Add(tunnelID, iface, proto string, targetPort int) error {
	for _, add := range ctRelayInputRulesV6Args(tunnelID, iface, proto, targetPort) {
		chk := ctRuleCheck(add)
		if _, err := ctIP6Tables(chk...); err != nil {
			if _, err := ctIP6Tables(add...); err != nil {
				return fmt.Errorf("ctunnel: relay INPUT rule: %w", err)
			}
		}
	}
	return nil
}

func ctRelayInputRulesV6Del(tunnelID, iface, proto string, targetPort int) {
	for _, add := range ctRelayInputRulesV6Args(tunnelID, iface, proto, targetPort) {
		del := ctRuleDelete(add)
		_, _ = ctIP6Tables(del...)
	}
}

// ctKernelDeviceReverse brings the kernel device up riding the reverse
// carrier TUN (their REVERSE branch shape: the device's underlay is the
// 172.31.<index>.x pair; family inner ports at their defaults).
func ctKernelDeviceReverse(tunnelID string, p ctunnelParams, spec ctMethodSpec, d ctDerive, ks *ctKernelState) error {
	peer := d.peerRev4
	mtu := ctDefaultMTU(p, spec)
	tune := func(dev string) error {
		return ctIPCmd("link", "set", "dev", dev, "mtu", fmt.Sprint(mtu), "txqueuelen", "10000", "up")
	}
	addr := func(dev string) error {
		return ctIPCmd("addr", "add", d.selfTun, "peer", d.peerTun+"/32", "dev", dev)
	}
	switch spec.id {
	case 17: // vxlan over the carrier TUN (inner dstport = the family default)
		vni := p.VNI
		if vni == 0 {
			vni = ctDerivedKey(tunnelID, "vni")
		}
		if err := ctIPCmd("link", "add", d.iface, "type", "vxlan", "id", fmt.Sprint(vni),
			"local", d.selfRev4, "remote", peer, "dstport", "4789", "nolearning"); err != nil {
			return fmt.Errorf("ctunnel: vxlan reverse: %w", err)
		}
	case 18: // geneve
		vni := p.VNI
		if vni == 0 {
			vni = ctDerivedKey(tunnelID, "vni")
		}
		if err := ctIPCmd("link", "add", d.iface, "type", "geneve", "id", fmt.Sprint(vni),
			"remote", peer, "dstport", "6081"); err != nil {
			return fmt.Errorf("ctunnel: geneve reverse: %w", err)
		}
	case 11: // fou-gre
		if err := ctIPCmd("link", "add", "name", d.iface, "type", "gre",
			"local", d.selfRev4, "remote", peer, "ttl", "255"); err != nil {
			return fmt.Errorf("ctunnel: fou-gre reverse: %w", err)
		}
	case 12: // gue-ipip
		if err := ctIPCmd("link", "add", "name", d.iface, "type", "ipip",
			"local", d.selfRev4, "remote", peer, "ttl", "255"); err != nil {
			return fmt.Errorf("ctunnel: gue-ipip reverse: %w", err)
		}
	case 41: // bareudp
		if err := ctIPCmd("link", "add", d.iface, "type", "bareudp",
			"dstport", "6635", "ethertype", "ipv4"); err != nil {
			return fmt.Errorf("ctunnel: bareudp reverse: %w", err)
		}
	case 19: // l2tpv3
		tid := int(ctDerivedKey(tunnelID, "tunnel-id"))
		if err := ctIPCmd("l2tp", "add", "tunnel", "tunnel_id", fmt.Sprint(tid),
			"peer_tunnel_id", fmt.Sprint(tid), "encap", "udp",
			"local", d.selfRev4, "remote", peer, "udp_sport", "1701", "udp_dport", "1701"); err != nil {
			return fmt.Errorf("ctunnel: l2tpv3 reverse tunnel: %w", err)
		}
		if err := ctIPCmd("l2tp", "add", "session", "name", d.iface, "tunnel_id", fmt.Sprint(tid),
			"session_id", fmt.Sprint(tid), "peer_session_id", fmt.Sprint(tid)); err != nil {
			return fmt.Errorf("ctunnel: l2tpv3 reverse session: %w", err)
		}
		ks.l2tpID = tid
	case 3: // sit
		if err := ctIPCmd("link", "add", "name", d.iface, "type", "sit",
			"local", d.selfRev4, "remote", peer, "ttl", "255"); err != nil {
			return fmt.Errorf("ctunnel: sit reverse: %w", err)
		}
	case 4: // ipip
		if err := ctIPCmd("link", "add", "name", d.iface, "type", "ipip",
			"local", d.selfRev4, "remote", peer, "ttl", "255"); err != nil {
			return fmt.Errorf("ctunnel: ipip reverse: %w", err)
		}
	case 1, 2: // 6to4 / 6to4-gre over the carrier (inner sits on the rev pair)
		sitDev := d.iface + "-6"
		if err := ctIPCmd("link", "add", "name", sitDev, "type", "sit",
			"local", d.selfRev4, "remote", peer, "ttl", "255"); err != nil {
			return fmt.Errorf("ctunnel: 6to4 reverse sit: %w", err)
		}
		ks.ifaces = append(ks.ifaces, sitDev)
		if err := ctIPCmd("link", "set", "dev", sitDev, "mtu", fmt.Sprint(mtu+40), "up"); err != nil {
			return fmt.Errorf("ctunnel: 6to4 reverse sit tune: %w", err)
		}
		if spec.id == 1 {
			if err := ctIPCmd("-6", "tunnel", "add", d.iface, "mode", "ipip6",
				"local", d.selfCar6, "remote", d.peerCar6, "dev", sitDev, "encaplimit", "none"); err != nil {
				return fmt.Errorf("ctunnel: 6to4 reverse inner: %w", err)
			}
		} else {
			if err := ctIPCmd("link", "add", "name", d.iface, "type", "ip6gre",
				"local", d.selfCar6, "remote", d.peerCar6); err != nil {
				return fmt.Errorf("ctunnel: 6to4-gre reverse inner: %w", err)
			}
		}
	case 5, 44, 13, 15: // gre/xgre/ecmp/gretap
		ktype := "gre"
		if spec.id == 15 {
			ktype = "gretap"
		}
		extra := []string{}
		if spec.id == 44 {
			extra = []string{"ignore-df", "nopmtudisc"}
		}
		lanes := p.Lanes
		if lanes < 1 {
			lanes = 1
		}
		for i := 0; i < lanes; i++ {
			dev := d.iface
			if i > 0 {
				dev = fmt.Sprintf("%s.%d", d.iface, i)
			}
			args := []string{"link", "add", "name", dev, "type", ktype,
				"local", d.selfRev4, "remote", peer, "ttl", "255"}
			args = append(args, extra...)
			if err := ctIPCmd(args...); err != nil {
				return fmt.Errorf("ctunnel: %s reverse: %w", ktype, err)
			}
			if i > 0 {
				ks.ifaces = append(ks.ifaces, dev)
			}
		}
	case 10: // xfrm-ipsec reverse: GRE only (ESP over the carrier is redundant)
		if err := ctIPCmd("link", "add", "name", d.iface, "type", "gre",
			"local", d.selfRev4, "remote", peer, "ttl", "255"); err != nil {
			return fmt.Errorf("ctunnel: xfrm reverse gre: %w", err)
		}
	case 7: // ipip6
		if err := ctIPCmd("-6", "tunnel", "add", d.iface, "mode", "ipip6",
			"local", d.selfCar6, "remote", d.peerCar6, "encaplimit", "none"); err != nil {
			return fmt.Errorf("ctunnel: ipip6 reverse: %w", err)
		}
	case 8: // ip6ip6
		if err := ctIPCmd("-6", "tunnel", "add", d.iface, "mode", "ip6ip6",
			"local", d.selfCar6, "remote", d.peerCar6, "encaplimit", "none"); err != nil {
			return fmt.Errorf("ctunnel: ip6ip6 reverse: %w", err)
		}
	case 6, 16: // ip6gre/ip6gretap
		ktype := "ip6gre"
		if spec.id == 16 {
			ktype = "ip6gretap"
		}
		if err := ctIPCmd("link", "add", "name", d.iface, "type", ktype,
			"local", d.selfRev4, "remote", peer, "ttl", "255"); err != nil {
			return fmt.Errorf("ctunnel: %s reverse: %w", ktype, err)
		}
	case 45: // xgre-ip reverse
		xd := d.iface + "-x"
		greKey := p.GREKey
		if greKey == 0 {
			greKey = ctDerivedKey(tunnelID, "gre-key")
		}
		if err := ctIPCmd("link", "add", "name", xd, "type", "gre",
			"local", d.selfRev4, "remote", peer, "ttl", "255", "ignore-df", "nopmtudisc",
			"key", fmt.Sprint(greKey)); err != nil {
			return fmt.Errorf("ctunnel: xgre-ip reverse carrier: %w", err)
		}
		ks.ifaces = append(ks.ifaces, xd)
		if err := ctIPCmd("link", "add", "name", d.iface, "type", "ipip",
			"local", fmt.Sprintf("172.30.%d.1", d.index), "remote", fmt.Sprintf("172.30.%d.2", d.index), "ttl", "255"); err != nil {
			return fmt.Errorf("ctunnel: xgre-ip reverse inner: %w", err)
		}
	default:
		return fmt.Errorf("ctunnel: method %s has no reverse kernel shape", p.Method)
	}
	if err := tune(d.iface); err != nil {
		return fmt.Errorf("ctunnel: reverse tune: %w", err)
	}
	if err := addr(d.iface); err != nil {
		return fmt.Errorf("ctunnel: reverse addr: %w", err)
	}
	return nil
}

// Stop implements engine.Driver: the shared teardown order with the
// ctunnel-specific hooks — relay closed, the role's rules dropped, the
// kernel objects deleted, THEN the env file removed (it holds the
// SECRET), then the interface(s) deleted.
func (d *CtunnelDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.relay != nil {
			st.relay.Close()
		}
		proto := ctDefaultProto(st.params.Proto)
		targetPort := ctTargetPort(st.params)
		spec := st.spec
		iface := st.iface
		dir := ctDeriveFor(inst.TunnelID, st.role)
		ifaceV4 := dir.iface
		if st.role == "iran" {
			if spec.l4() {
				ctWireRulesDel(inst.TunnelID, proto, st.params.PublicPort)
			} else {
				if spec.id == 3 || spec.id == 8 {
					ctForwardRulesV6Del(inst.TunnelID, proto, st.params.PublicPort, targetPort, dir.selfTun6, dir.peerTun6)
				} else {
					ctForwardRulesDel(inst.TunnelID, proto, st.params.PublicPort, targetPort, st.selfTun, st.peerTun)
				}
				if spec.crypt() && spec.id != 37 && spec.id != 38 {
					ctWireRulesDel(inst.TunnelID, "udp", st.params.CarrierPort)
				} else if spec.kernelKind() {
					ctWireRulesDel(inst.TunnelID, "udp", st.params.CarrierPort)
				}
			}
		} else if spec.l4() {
			// nothing beyond the process
		} else if spec.id == 3 || spec.id == 8 {
			ctRelayInputRulesV6Del(inst.TunnelID, ifaceV4, proto, targetPort)
		} else {
			ctRelayInputRulesDel(inst.TunnelID, ifaceV4, proto, targetPort)
		}
		// Kernel objects (their devices/routes/FOU/xfrm/l2tp) first, then
		// the interface the engine held, then the env file (SECRET last on
		// disk is WRONG — it must go BEFORE the interface delete per the
		// original order; kept: rules → env → interfaces).
		if st.hasKernel {
			ctKernelDown(inst.TunnelID, st.kernel)
		}
		_ = os.Remove(st.envPath)
		if iface != "" {
			_ = ctIfaceDel(iface)
		}
	})
	return nil
}

// Reload implements engine.Driver: equal params are a no-op, anything
// else is a restart (C-Tunnel has no live reload).
func (d *CtunnelDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, ctunnelID, inst.TunnelID, inst.Params,
		func(st *ctInstState) ctunnelParams { return st.params }, engineParamsEqual[ctunnelParams])
}

// ctProbeThrough performs the through-tunnel probe: dial the kharej end's
// tunnel IP:target port (traverses the carrier → TUN → relay → target
// accept) and hold: EOF/RST within the window = dead path (the relay
// closes instantly when the target dial fails); hold-open = healthy.
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
// through the server namespace; hermetic tests stub it).
var ctProbeDial = ctProbeThrough

// Health implements engine.Driver. iran end: the through-tunnel probe
// (warmup gate) — TUN/kernel families dial the peer tunnel IP; L4 families
// dial their own 127.0.0.1:public (the engine listener rides the full
// path to the kharej target). kharej end: process alive + relay bound
// (interface families) or process alive (L4/kernel-no-forward ends).
func (d *CtunnelDriver) Health(inst engine.Instance) engine.Health {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Health{OK: false, Detail: "not running", LatencyMs: -1}
	}
	spec := st.spec
	// Kernel-direct instances have NO process: health = the tunnel device
	// is still up (the engine's process-exit gate does not apply).
	if proc := st.current(); proc != nil {
		select {
		case <-proc.Done():
			return engine.Health{OK: false, Detail: "process exited", LatencyMs: -1}
		default:
		}
	} else if !spec.kernelKind() {
		return engine.Health{OK: false, Detail: "not started", LatencyMs: -1}
	}
	// Kernel-direct instances have no process — health = the interface
	// is up + the through-probe on the iran end.
	proto := ctDefaultProto(st.params.Proto)
	if st.role != "iran" {
		detail := "ctunnel running"
		if spec.kernelKind() && !ctEngineNeeded(spec, st.dir) {
			detail = "ctunnel kernel tunnel up"
		}
		if st.relay != nil {
			wantTCP := proto == "tcp" || proto == "both"
			wantUDP := proto == "udp" || proto == "both"
			if !st.relay.Ready(wantTCP, wantUDP) {
				return engine.Health{OK: false, Detail: "relay not bound yet (waiting for the tunnel interface)", LatencyMs: -1}
			}
			detail += "; relay bound"
		}
		return engine.Health{OK: true, Detail: detail, LatencyMs: -1}
	}
	targetPort := ctTargetPort(st.params)
	start := time.Now()
	probeAddr := ""
	switch {
	case spec.l4():
		// The engine's own public listener: a dial rides the stream to the
		// kharej end's 127.0.0.1:<target>.
		probeAddr = net.JoinHostPort("127.0.0.1", fmt.Sprint(st.params.PublicPort))
	case spec.id == 3 || spec.id == 8:
		probeAddr = net.JoinHostPort(ctDeriveFor(inst.TunnelID, st.role).peerTun6, fmt.Sprint(targetPort))
	default:
		probeAddr = net.JoinHostPort(ctDeriveFor(inst.TunnelID, st.role).peerTun, fmt.Sprint(targetPort))
	}
	if err := ctProbeDial(probeAddr, 3*time.Second); err != nil {
		return engine.Health{OK: false, Detail: "through-tunnel probe failed: " + err.Error(),
			LatencyMs: float64(time.Since(start).Milliseconds())}
	}
	return engine.Health{OK: true, Detail: "through-tunnel probe ok", LatencyMs: float64(time.Since(start).Milliseconds())}
}

// Counters implements engine.Driver: wire = the kernel-socket carrier
// counters (UDP-carried TUN families + L4 public ports) on the iran end;
// payload = the tunnel interface's netdev counters on BOTH ends (each
// agent reports its own view honestly). L4 has no interface → payload
// unknown; faketcp/icmp carriers bypass the normal chains → wire unknown.
func (d *CtunnelDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Counters{}
	}
	out := engine.Counters{}
	spec := st.spec
	if st.role == "iran" {
		switch {
		case spec.l4():
			if rx, tx, ok := ctWireBytes(inst.TunnelID, ctDefaultProto(st.params.Proto), st.params.PublicPort); ok {
				out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
			}
		case spec.crypt() && spec.id != 37 && spec.id != 38 && st.params.CarrierPort > 0:
			if rx, tx, ok := ctWireBytes(inst.TunnelID, "udp", st.params.CarrierPort); ok {
				out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
			}
		}
	}
	if st.iface != "" {
		if data, err := infra.AgentReadNetDev(); err == nil {
			if c, ok := infra.AgentParseNetDev(data)[st.iface]; ok {
				out.PayloadRx, out.PayloadTx, out.PayloadKnown = c.Rx, c.Tx, true
			}
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
// kharej tunnel IP (through the tunnel; v6 pair for the v6-inner methods);
// kharej end → the loopback target. L4: the engine serves the public port
// locally on the iran end; the kharej end dials its own loopback target.
func (d *CtunnelDriver) ForwardAddress(inst engine.Instance) (string, int, bool) {
	var p ctunnelParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return "", 0, false
	}
	role, err := ctResolveRole(p)
	if err != nil {
		return "", 0, false
	}
	spec, ok := ctMethods[strings.ToLower(strings.TrimSpace(p.Method))]
	if !ok {
		return "", 0, false
	}
	targetPort := ctTargetPort(p)
	if targetPort == 0 {
		return "", 0, false
	}
	dir := ctDeriveFor(inst.TunnelID, role)
	if role == "iran" {
		if spec.l4() {
			return "127.0.0.1", p.PublicPort, true
		}
		if spec.id == 3 || spec.id == 8 {
			return dir.peerTun6, targetPort, true
		}
		return dir.peerTun, targetPort, true
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
