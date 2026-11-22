package agent

// easytier_driver.go — the EasyTier engine (EasyTier/EasyTier v2.7.1,
// LGPL-3.0 — binaries-only external core per the cores separation, released
// dual-arch in quantum-cores easytier/) as an engine.Driver per
// 00-ADMIN/ENGINE-GUIDE.md. OVERNIGHT-A7 (the last implementable method —
// the morning human order's "add ALL" finale).
//
// Mesh shape (the D2 wiring spec + the v2.7.1 --help surface, both ends run
// `easytier-core` and join the SAME network by name+secret):
//
//	server (foreign): easytier-core --network-name N --network-secret S
//	    -l <proto>://0.0.0.0:<port> [-i <cidr> | -d] [--proxy-networks ...]
//	    [--mtu ...]
//	client (iran):    easytier-core --network-name N --network-secret S
//	    -p <proto>://foreign:<port> [-i <cidr> | -d] [--proxy-networks ...]
//
// The mesh is an L3 TUN overlay (the binary creates the TUN device — a
// kernel op; the driver checks /dev/net/tun presence first and fails with
// the honest pointer). Node addressing: -d/--dhcp (the 10.126.126.0/24
// default pool) or a static -i CIDR; an empty -i with no dhcp runs the node
// FORWARD-ONLY (no TUN — the relay/exit shape). --proxy-networks exports
// the node's LAN subnets into the mesh. The listener carrier protocols are
// the upstream registry set: tcp|udp|wg|ws|wss|quic|faketcp|ring.
//
// Strictly typed args (no shell, no config file): every value below is
// charset-validated upstream of the argv build. Secrets (network-secret)
// ride argv only — never logged.
//
// Health: process-alive; on the foreign end a TCP-listener dial proves the
// mesh entry is bound (udp/wg/quic listeners — process-alive, honestly).
// Counters: iptables on the foreign listener port (proto-aware).
// Version: `easytier-core --version` (bounded; the C2 smoke shape).

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-agent/internal/infra"
)

const easytierID = "easytier"

// easytierCarriers is the listener/peer URL scheme allowlist (the upstream
// listener registry: tcp|udp|wg|ws|wss|quic|faketcp|ring).
var easytierCarriers = map[string]bool{
	"tcp": true, "udp": true, "wg": true, "ws": true, "wss": true,
	"quic": true, "faketcp": true, "ring": true,
}

// easytierUDPProto reports the carriers whose listener socket is UDP
// (accounting proto mapping; everything else rides tcp).
func easytierUDPProto(proto string) bool {
	switch proto {
	case "udp", "wg", "quic":
		return true
	}
	return false
}

type easytierParams struct {
	ServerSide    string `json:"server_side"`  // the end hosting the mesh LISTENER (foreign)
	Version       string `json:"version"`      // artifact version (cache key)
	Artifact      string `json:"artifact"`     // name template with {arch}
	SHA256Amd     string `json:"sha256_amd64"` // pinned fallback
	SHA256Arm     string `json:"sha256_arm64"`
	SigAmd        string `json:"signature_amd64"`
	SigArm        string `json:"signature_arm64"`
	NetworkName   string `json:"network_name"`   // the mesh network name (both ends must match)
	NetworkSecret string `json:"network_secret"` // the mesh secret (REQUIRED — an open mesh is refused)
	RemoteAddr    string `json:"remote_addr"`    // foreign public host (the client's peer dial)
	ListenerPort  int    `json:"listener_port"`  // the foreign mesh listener port
	// the listener carrier scheme (tcp|udp|wg|ws|wss|quic|faketcp|ring).
	Carrier string `json:"carrier,omitempty"` // default tcp
	// node addressing: -d/--dhcp (the upstream default pool or the given
	// CIDR) XOR a static -i CIDR. Neither = FORWARD-ONLY (no TUN, honest
	// relay shape — the driver renders it but flags it in Health).
	Dhcp     bool   `json:"dhcp,omitempty"`
	DhcpCIDR string `json:"dhcp_cidr,omitempty"` // with dhcp: the initial subnet (optional)
	NodeIPv4 string `json:"node_ipv4,omitempty"` // static -i CIDR (optional)
	// --proxy-networks: the comma-separated LAN subnets this node exports
	// into the mesh.
	ProxyNetworks string `json:"proxy_networks,omitempty"`
	// --mtu (0 = upstream default).
	Mtu int `json:"mtu,omitempty"`
}

func (p easytierParams) easytierArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	return enginePinForArch(EnginePin{Version: p.Version, Artifact: p.Artifact,
		SHA256Amd: p.SHA256Amd, SHA256Arm: p.SHA256Arm, SigAmd: p.SigAmd, SigArm: p.SigArm})
}

// easytierSafe is the charset gate for argv-bound strings.
func easytierSafe(label, v string, max int) error {
	if len(v) > max || strings.ContainsAny(v, "\"'\\\n\r\t `$;&|<>@/:") {
		return fmt.Errorf("easytier: %s must be a ≤%d-char string without quotes/backslashes/control characters", label, max)
	}
	return nil
}

func easytierValidateParams(p easytierParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("easytier: server_side required")
	}
	if err := backhaulValidateArtifactPins2(p.Version, p.Artifact, p.SHA256Amd, p.SigAmd,
		p.SHA256Arm, p.SigArm, easytierID); err != nil {
		return err
	}
	if err := engineVerifySecretShape("easytier network_name", p.NetworkName, 1, 64); err != nil {
		return err
	}
	// the dead-secret discipline: an OPEN mesh (no secret) is refused.
	if err := engineVerifySecretShape("easytier network_secret", p.NetworkSecret, 8, 128); err != nil {
		return err
	}
	carrier := strings.ToLower(strings.TrimSpace(p.Carrier))
	if carrier == "" {
		carrier = "tcp"
	}
	if !easytierCarriers[carrier] {
		return fmt.Errorf("easytier: carrier %q not supported (tcp|udp|wg|ws|wss|quic|faketcp|ring)", p.Carrier)
	}
	if p.ListenerPort <= 0 || p.ListenerPort > 65535 {
		return fmt.Errorf("easytier: listener_port out of range")
	}
	if strings.TrimSpace(p.RemoteAddr) == "" || len(p.RemoteAddr) > 253 ||
		strings.ContainsAny(p.RemoteAddr, "\"'\n\r\\ :") {
		return fmt.Errorf("easytier: remote_addr must be a bare host/IP (the foreign mesh entry)")
	}
	// node addressing: dhcp XOR static (both = ambiguous, refused); the
	// forward-only shape (neither) is legal and flagged in Health.
	if p.Dhcp && p.NodeIPv4 != "" {
		return fmt.Errorf("easytier: dhcp and node_ipv4 are mutually exclusive (both set = ambiguous addressing)")
	}
	if p.Dhcp && p.DhcpCIDR != "" {
		if _, _, err := net.ParseCIDR(p.DhcpCIDR); err != nil {
			return fmt.Errorf("easytier: dhcp_cidr must be a CIDR (the initial pool, e.g. 10.126.126.0/24)")
		}
		if len(p.DhcpCIDR) > 18 || strings.ContainsAny(p.DhcpCIDR, "\"' \n\r") {
			return fmt.Errorf("easytier: dhcp_cidr must be a ≤18-char CIDR without quotes/whitespace")
		}
	}
	if p.NodeIPv4 != "" {
		if _, _, err := net.ParseCIDR(p.NodeIPv4); err != nil {
			return fmt.Errorf("easytier: node_ipv4 must be a CIDR (the static node address, e.g. 10.126.126.1/24)")
		}
		if len(p.NodeIPv4) > 18 || strings.ContainsAny(p.NodeIPv4, "\"' \n\r") {
			return fmt.Errorf("easytier: node_ipv4 must be a ≤18-char CIDR without quotes/whitespace")
		}
	}
	if p.ProxyNetworks != "" {
		if len(p.ProxyNetworks) > 256 || strings.ContainsAny(p.ProxyNetworks, "\"'\\\n\r ") {
			return fmt.Errorf("easytier: proxy_networks must be ≤256 chars of comma-separated CIDRs without quotes/whitespace")
		}
		for _, part := range strings.Split(p.ProxyNetworks, ",") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(strings.TrimSpace(part)); err != nil {
				return fmt.Errorf("easytier: proxy_networks entry %q must be a CIDR", strings.TrimSpace(part))
			}
		}
	}
	if p.Mtu != 0 && (p.Mtu < 576 || p.Mtu > 9000) {
		return fmt.Errorf("easytier: mtu out of range (576-9000; 0 = upstream default)")
	}
	return nil
}

func easytierResolveRole(p easytierParams) (string, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("easytier: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return "server", nil
	}
	return "client", nil
}

type easytierInstState struct {
	engineInst
	params easytierParams
	role   string
}

// EasytierDriver implements engine.Driver for the vendored EasyTier core.
type EasytierDriver struct {
	runs *instTable[easytierInstState]
}

func NewEasytierDriver() *EasytierDriver {
	return &EasytierDriver{runs: newInstTable[easytierInstState]()}
}

func (d *EasytierDriver) ID() string { return easytierID }

func (d *EasytierDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: easytierID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","network_name":"","network_secret":"","remote_addr":"","listener_port":11010,"carrier":"tcp|udp|wg|ws|wss|quic|faketcp|ring","dhcp":false,"dhcp_cidr":"","node_ipv4":"10.126.126.1/24","proxy_networks":"","mtu":0}`)}
}

func (d *EasytierDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *EasytierDriver) Validate(params json.RawMessage) error {
	var p easytierParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("easytier: engine_params: %w", err)
	}
	return easytierValidateParams(p)
}

func easytierEngineDir() string { return engineEngineDir(easytierID) }

func easytierBinDir(version string) string {
	return filepath.Join(easytierEngineDir(), "bin", version)
}

// easytierArgs renders the end's strictly-typed CLI (the v2.7.1 flag
// surface verified from `easytier-core --help`).
func easytierArgs(role string, p easytierParams) []string {
	carrier := strings.ToLower(strings.TrimSpace(p.Carrier))
	if carrier == "" {
		carrier = "tcp"
	}
	args := []string{
		"--network-name", p.NetworkName,
		"--network-secret", p.NetworkSecret,
	}
	if role == "server" {
		args = append(args, "-l", fmt.Sprintf("%s://0.0.0.0:%d", carrier, p.ListenerPort))
	} else {
		args = append(args, "-p", fmt.Sprintf("%s://%s:%d", carrier,
			strings.TrimSpace(p.RemoteAddr), p.ListenerPort))
	}
	// node addressing: dhcp XOR static; neither = forward-only.
	if p.Dhcp {
		if p.DhcpCIDR != "" {
			args = append(args, "--dhcp", p.DhcpCIDR)
		} else {
			args = append(args, "--dhcp")
		}
	} else if p.NodeIPv4 != "" {
		args = append(args, "-i", p.NodeIPv4)
	}
	if p.ProxyNetworks != "" {
		args = append(args, "--proxy-networks", p.ProxyNetworks)
	}
	if p.Mtu > 0 {
		args = append(args, "--mtu", fmt.Sprint(p.Mtu))
	}
	return args
}

// easytierTunAvailable checks /dev/net/tun (the TUN creation is a kernel op
// — the honest fail-closed pointer per the D2 installer-safety note). A
// forward-only node (no dhcp, no -i) skips the check.
var easytierTunAvailable = func() bool {
	return infra.FileExists("/dev/net/tun")
}

// easytierEnsureBinary: manifest-first (engine "easytier"), pinned fallback.
func easytierEnsureBinary(ctx context.Context, p easytierParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("easytier: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.easytierArtifactPin(); pinErr == nil &&
		engineCacheHit(easytierBinDir(p.Version), pinnedSHA, []string{"easytier-core"}) {
		return easytierBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("easytier: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, easytierID,
		func() (string, string, string, error) { return p.easytierArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := easytierBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"easytier-core"}) {
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
		return "", fmt.Errorf("easytier: cache dir: %w", err)
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"easytier-core": true}); err != nil {
		return "", fmt.Errorf("easytier: %w", err)
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("easytier: cache marker: %w", err)
	}
	return dir, nil
}

// easytierSpawn runs `easytier-core <args>` (argv-only).
var easytierSpawn = func(binPath string, args []string) (frpProcess, error) {
	cmd := exec.Command(binPath, args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("easytier: start: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

func (d *EasytierDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p easytierParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("easytier: engine_params: %w", err)
	}
	if err := easytierValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("easytier: invalid tunnel id %q", inst.TunnelID)
	}
	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual[easytierParams](prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}
	// the TUN presence check (installer-safety) runs FIRST: a mesh node that
	// addresses itself (dhcp or static) creates a TUN device; a forward-only
	// node does not. Fail closed with the honest pointer.
	needsTun := p.Dhcp || p.NodeIPv4 != ""
	if needsTun && !easytierTunAvailable() {
		return fmt.Errorf("easytier: /dev/net/tun is not available on this host — the mesh node needs it for the TUN device (load the tun module or run a forward-only node: drop dhcp/node_ipv4)")
	}
	role, err := easytierResolveRole(p)
	if err != nil {
		return err
	}
	binDir, err := easytierEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "easytier-core")
	args := easytierArgs(role, p)
	proc, err := easytierSpawn(binPath, args)
	if err != nil {
		return err
	}
	st := &easytierInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		binPath: binPath}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, st.binPath, "", func(b, _ string) (frpProcess, error) {
		return easytierSpawn(b, easytierArgs(st.role, st.params))
	})
	// wire accounting on the foreign listener port (proto-aware).
	if role == "server" {
		proto := "tcp"
		if easytierUDPProto(p.Carrier) {
			proto = "udp"
		}
		if err := acctWireRulesAddProto(acctChainsDriver, inst.TunnelID, p.ListenerPort, p.ListenerPort, proto); err != nil {
			fmt.Fprintf(os.Stderr, "easytier: wire accounting unavailable: %v\n", err)
		}
	}
	return nil
}

func (d *EasytierDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.role == "server" {
			proto := "tcp"
			if easytierUDPProto(st.params.Carrier) {
				proto = "udp"
			}
			_ = acctWireRulesDelProto(acctChainsDriver, inst.TunnelID, st.params.ListenerPort, st.params.ListenerPort, proto)
		}
	})
	return nil
}

func (d *EasytierDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, easytierID, inst.TunnelID, inst.Params,
		func(st *easytierInstState) easytierParams { return st.params }, engineParamsEqual[easytierParams])
}

// easytierHealthDial seams the listener dial (tcp listeners only — udp/wg/
// quic listeners cannot prove liveness with a TCP dial; process-alive it is).
var easytierHealthDial = gostHealthDial

// Health: process-alive; on the foreign end a TCP-carrier listener dial
// proves the mesh entry is bound. A forward-only node is flagged honestly.
func (d *EasytierDriver) Health(inst engine.Instance) engine.Health {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Health{OK: false, Detail: "not running", LatencyMs: -1}
	}
	select {
	case <-st.current().Done():
		return engine.Health{OK: false, Detail: "process exited", LatencyMs: -1}
	default:
	}
	if st.role == "server" && strings.EqualFold(strings.TrimSpace(st.params.Carrier), "tcp") {
		start := time.Now()
		if err := easytierHealthDial(st.params.ListenerPort); err == nil {
			return engine.Health{OK: true, Detail: "easytier mesh registered (listener answering)",
				LatencyMs: float64(time.Since(start).Milliseconds())}
		}
		return engine.Health{OK: false, Detail: "mesh listener not answering", LatencyMs: -1}
	}
	detail := "easytier " + st.role + " running"
	if !st.params.Dhcp && st.params.NodeIPv4 == "" {
		detail += " (forward-only: no TUN)"
	}
	return engine.Health{OK: true, Detail: detail, LatencyMs: -1}
}

// Counters: the foreign end's wire view on the listener port (proto-aware).
func (d *EasytierDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil || st.role != "server" {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if port := st.params.ListenerPort; port > 0 {
		if rx, tx, ok := acctWireBytes(inst.TunnelID, port, port); ok {
			out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
		}
	}
	return out
}

func (d *EasytierDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, easytierEngineDir())
	return nil
}

// easytierVersionProbe: `easytier-core --version` (the C2 smoke shape).
var easytierVersionProbe = func(binPath string) (string, error) {
	out, err := infra.RunCmdTimeout(10*time.Second, binPath, "--version")
	if err != nil {
		return "", err
	}
	f := strings.Fields(strings.TrimSpace(string(out)))
	if len(f) >= 2 && strings.Contains(string(out), "easytier") {
		return strings.TrimLeft(f[len(f)-1], "v"), nil
	}
	return "", fmt.Errorf("easytier: unexpected version output")
}

// easytierInstalledVersion reports the INSTALLED core version for
// Describe() (the §2.22 pattern): the newest cached artifact probed; the
// build-pin version reported honestly without.
func easytierInstalledVersion() string {
	base := filepath.Join(easytierEngineDir(), "bin")
	entries, err := os.ReadDir(base)
	if err != nil {
		return easytierPinnedVersion
	}
	best := ""
	for _, e := range entries {
		if !e.IsDir() || !infra.FileExists(filepath.Join(base, e.Name(), "easytier-core")) {
			continue
		}
		if ctVersionLess(best, e.Name()) {
			best = e.Name()
		}
	}
	if best == "" {
		return easytierPinnedVersion
	}
	if v, err := easytierVersionProbe(filepath.Join(base, best, "easytier-core")); err == nil && v != "" {
		return v
	}
	return best
}

const easytierPinnedVersion = "2.7.1"
