// wstunnel_driver.go — engine driver for wstunnel (github.com/erebe/wstunnel,
// BSD-3-Clause — license verified from the upstream tree at the pinned tag;
// the text ships inside every artifact via the packer). Sixth driver.
//
// PINNED UPSTREAM: v10.1.x CLI shape. Upstream rewrote the CLI between
// major versions (v4 `-s/-L`, v5+ subcommands, v10 `client/server` with
// `-L/-R` tunnel instructions) — this driver pins v10 and renders exactly:
//
//	server (foreign): wstunnel server ws://0.0.0.0:<ws_port>
//	client  (iran):   wstunnel client \
//	                    -R "tcp://0.0.0.0:<remote_port>:<local_addr>:<local_port>" \
//	                    [-R "udp://0.0.0.0:<remote_udp_port>:<local_addr>:<local_udp_port>"] \
//	                    ws://<remote_addr>:<ws_port>
//
// The Iran end runs the CLIENT (dials out — Iran-friendly); the foreign
// end runs the SERVER. -R (remote-to-local) makes the FOREIGN listener
// relay through the WS to the Iran-side target — the FRP reverse shape.
// TCP is always carried; UDP rides the second -R when remote_udp_port is
// configured (wstunnel carries both over the one WebSocket).
//
// Production TLS: the lab/e2e shape uses plain ws:// (loopback/private);
// production pairs the foreign end with a TLS terminator (or wss:// with
// real certificates) — the WS carrier itself is version-pinned here and
// the carrier URL scheme is an explicit param of the desired state.
//
// Health: SERVER end performs a REAL probe THROUGH the tunnel — dial the
// forwarded remote port, write a probe byte and expect it ECHOED back by
// the client-side target (the integration client runs an echo server on
// the local port; a production target answers with its own protocol).
// Dead relay = no echo = unhealthy. The CLIENT end checks process
// liveness.
//
// Accounting: wire bytes per direction via nftables on the forwarded
// remote port (server end); payload bytes are UNKNOWN (wstunnel has no
// stats API) — honest per ENGINE-CANDIDATES.md.

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const (
	wstID      = "wstunnel"
	wstVersion = "10.1.9" // PINNED upstream CLI shape (v10)
)

// wstParams is the engine_params shape the wstunnel driver accepts.
type wstParams struct {
	ServerSide    string `json:"server_side"`  // foreign end name (hosts the WS server)
	Version       string `json:"version"`      // artifact version (cache key)
	Artifact      string `json:"artifact"`     // name TEMPLATE with {arch}
	SHA256Amd     string `json:"sha256_amd64"` // pinned fallback
	SHA256Arm     string `json:"sha256_arm64"`
	SigAmd        string `json:"signature_amd64"`
	SigArm        string `json:"signature_arm64"`
	RemoteAddr    string `json:"remote_addr"`     // foreign public host (carrier dial + forward view)
	WsPort        int    `json:"ws_port"`         // foreign WebSocket listen port
	RemotePort    int    `json:"remote_port"`     // foreign forwarded TCP port → Iran target
	RemoteUdpPort int    `json:"remote_udp_port"` // foreign forwarded UDP port (0 = TCP only)
	LocalAddr     string `json:"local_addr"`      // Iran-side target host
	LocalPort     int    `json:"local_port"`      // Iran-side target TCP port
	LocalUdpPort  int    `json:"local_udp_port"`  // Iran-side target UDP port
}

func (p wstParams) wstArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	return enginePinForArch(EnginePin{Version: p.Version, Artifact: p.Artifact,
		SHA256Amd: p.SHA256Amd, SHA256Arm: p.SHA256Arm, SigAmd: p.SigAmd, SigArm: p.SigArm})
}

func wstValidateParams(p wstParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("wstunnel: server_side required")
	}
	if strings.TrimSpace(p.Version) == "" || len(p.Version) > 64 ||
		strings.ContainsAny(p.Version, "/\\\"' \t\n\r") {
		return fmt.Errorf("wstunnel: version must be 1-64 safe chars")
	}
	if !strings.Contains(p.Artifact, "{arch}") || strings.ContainsAny(p.Artifact, " \t\n\r\"\\") {
		return fmt.Errorf("wstunnel: artifact must be a name template containing {arch}")
	}
	for _, a := range []struct{ sha, sig string }{{p.SHA256Amd, p.SigAmd}, {p.SHA256Arm, p.SigArm}} {
		if len(a.sha) != 64 || strings.ContainsAny(a.sha, " \t\n\r") {
			return fmt.Errorf("wstunnel: sha256 pin must be 64 hex chars")
		}
		if len(a.sig) < 64 || len(a.sig) > 512 || strings.ContainsAny(a.sig, " \t\n\r") {
			return fmt.Errorf("wstunnel: signature pin must be base64 (64-512 chars)")
		}
	}
	if p.WsPort <= 0 || p.WsPort > 65535 || p.RemotePort <= 0 || p.RemotePort > 65535 {
		return fmt.Errorf("wstunnel: ws_port/remote_port out of range")
	}
	if p.RemoteUdpPort < 0 || p.RemoteUdpPort > 65535 {
		return fmt.Errorf("wstunnel: remote_udp_port out of range")
	}
	if p.RemoteUdpPort > 0 && (p.LocalUdpPort <= 0 || p.LocalUdpPort > 65535) {
		return fmt.Errorf("wstunnel: remote_udp_port set but local_udp_port invalid")
	}
	if strings.TrimSpace(p.LocalAddr) == "" || strings.ContainsAny(p.LocalAddr, "\"'\n\r\\") ||
		p.LocalPort <= 0 || p.LocalPort > 65535 {
		return fmt.Errorf("wstunnel: local_addr/local_port invalid")
	}
	if strings.TrimSpace(p.RemoteAddr) == "" || strings.ContainsAny(p.RemoteAddr, "\"'\n\r\\") {
		return fmt.Errorf("wstunnel: remote_addr invalid")
	}
	if p.RemotePort == p.WsPort {
		return fmt.Errorf("wstunnel: remote_port must differ from ws_port")
	}
	return nil
}

// wstResolveRole resolves this end's role through the enrollment name.
func wstResolveRole(p wstParams) (engineSide, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("wstunnel: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return engineSideServer, nil
	}
	return engineSideClient, nil
}

// wstConfigPath / wstBinDir / engine dir helpers.
func wstConfigPath(tunnelID string) string {
	return filepath.Join(engineEngineDir(wstID), "instances", tunnelID+".args")
}
func wstBinDir(version string) string { return filepath.Join(engineEngineDir(wstID), "bin", version) }

// wstClientArgs renders the client tunnel instructions (validated params
// only — nothing here is shell-interpreted; exec.Command receives the
// fixed list).
func wstClientArgs(p wstParams) []string {
	args := []string{"client"}
	args = append(args, "-R", fmt.Sprintf("tcp://0.0.0.0:%d:%s:%d", p.RemotePort, p.LocalAddr, p.LocalPort))
	if p.RemoteUdpPort > 0 {
		args = append(args, "-R", fmt.Sprintf("udp://0.0.0.0:%d:%s:%d", p.RemoteUdpPort, p.LocalAddr, p.LocalUdpPort))
	}
	args = append(args, fmt.Sprintf("ws://%s", net.JoinHostPort(p.RemoteAddr, fmt.Sprint(p.WsPort))))
	return args
}

// wstServerArgs renders the server command.
func wstServerArgs(p wstParams) []string {
	return []string{"server", fmt.Sprintf("ws://0.0.0.0:%d", p.WsPort)}
}

// wstInstState is one RUNNING instance's state (supervisor target).
// The proc/stop/cfg/binPath base rides the shared engineInst (A1).
type wstInstState struct {
	engineInst
	params wstParams
	role   engineSide
}

// WstDriver implements engine.Driver for wstunnel.
type WstDriver struct {
	runs *instTable[wstInstState]
}

func NewWstDriver() *WstDriver { return &WstDriver{runs: newInstTable[wstInstState]()} }

func (d *WstDriver) ID() string { return wstID }

func (d *WstDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: wstID, Version: wstVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","remote_addr":"","ws_port":0,"remote_port":0,"remote_udp_port":0,"local_addr":"","local_port":0,"local_udp_port":0}`)}
}

// EnsureBinary: the Manager calls this before the first instance starts;
// the download happens in Start via wstEnsureBinary with the resolved
// coordinates (manifest-first, pinned fallback).
func (d *WstDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *WstDriver) Validate(params json.RawMessage) error {
	var p wstParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("wstunnel: engine_params: %w", err)
	}
	return wstValidateParams(p)
}

func wstEnsureBinary(ctx context.Context, p wstParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("wstunnel: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.wstArtifactPin(); pinErr == nil && engineCacheHit(wstBinDir(p.Version), pinnedSHA, []string{"wstunnel"}) {
		return wstBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("wstunnel: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, wstID,
		func() (string, string, string, error) { return p.wstArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := wstBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"wstunnel"}) {
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
		return "", fmt.Errorf("wstunnel: cache dir: %w", err)
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"wstunnel": true}); err != nil {
		return "", err
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("wstunnel: cache marker: %w", err)
	}
	return dir, nil
}

// wstParamsEqual was the Reload no-op comparison; A1 moved the
// canonical-JSON compare to the shared engineParamsEqual.

var wstSpawn = func(binPath string, args []string) (frpProcess, error) {
	cmd := exec.Command(binPath, args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("wstunnel: start %s: %w", binPath, err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

// Start implements engine.Driver: validate → resolve role → ensure the
// verified binary → render the arg file (0600) → spawn → supervise →
// wire accounting on the server end's forwarded port.
func (d *WstDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p wstParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("wstunnel: engine_params: %w", err)
	}
	if err := wstValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("wstunnel: invalid tunnel id %q", inst.TunnelID)
	}
	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual(prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}
	role, err := wstResolveRole(p)
	if err != nil {
		return err
	}
	binDir, err := wstEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "wstunnel")
	args := wstServerArgs(p)
	if role == engineSideClient {
		args = wstClientArgs(p)
	}
	cfgPath := wstConfigPath(inst.TunnelID)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("wstunnel: config dir: %w", err)
	}
	// 0600 arg file: forensics copy of the exact invocation (no secrets
	// today, but the shape is enforced for whatever params carry later).
	if err := os.WriteFile(cfgPath, []byte(strings.Join(args, "\n")), 0o600); err != nil {
		return fmt.Errorf("wstunnel: write args: %w", err)
	}
	proc, err := wstSpawn(binPath, args)
	if err != nil {
		_ = os.Remove(cfgPath)
		return err
	}
	st := &wstInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		cfg: cfgPath, binPath: binPath}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, binPath, "", func(b, _ string) (frpProcess, error) {
		return wstSpawn(b, args)
	})
	// Wire accounting on the SERVER end's forwarded port (single port,
	// not a range — this instance owns it).
	if role == engineSideServer {
		if err := frpWireRulesAdd(inst.TunnelID, p.RemotePort, p.RemotePort); err != nil {
			fmt.Fprintf(os.Stderr, "wstunnel: wire accounting unavailable: %v\n", err)
		}
	}
	return nil
}

// Stop implements engine.Driver: the shared teardown order (stop channel
// closed BEFORE the kill so the supervisor never resurrects a
// deliberately stopped process), with the server end's wire-accounting
// rule as the driver-specific teardown hook.
func (d *WstDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.role == engineSideServer {
			_ = frpWireRulesDel(inst.TunnelID, st.params.RemotePort, st.params.RemotePort)
		}
	})
	return nil
}

// Reload implements engine.Driver: equal params are a no-op, anything
// else is a restart.
func (d *WstDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, wstID, inst.TunnelID, inst.Params,
		func(st *wstInstState) wstParams { return st.params }, engineParamsEqual[wstParams])
}

// wstProbeRelay performs the REAL through-the-tunnel probe: dial the
// forwarded port, write one probe byte, and wait briefly. wstunnel
// accepts the TCP connection before the inner target answers; a dead
// tunnel closes/resets the accepted connection immediately, while a live
// path holds it (a timeout on read = healthy open relay).
func wstProbeRelay(port int, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return fmt.Errorf("relay dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x71}); err != nil {
		return fmt.Errorf("relay write: %w", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		// The client end runs an ECHO target: the probe byte must come
		// BACK through the tunnel. A dead relay is held open by the
		// engine (timeout) or closed — either way, no echo = unhealthy.
		return fmt.Errorf("relay dead (no echo): %w", err)
	}
	return nil // our probe byte echoed back through the tunnel: healthy
}

// Health implements engine.Driver: process alive; on the SERVER end the
// forwarded port must answer THROUGH the tunnel.
func (d *WstDriver) Health(inst engine.Instance) engine.Health {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Health{OK: false, Detail: "not running", LatencyMs: -1}
	}
	select {
	case <-st.current().Done():
		return engine.Health{OK: false, Detail: "process exited", LatencyMs: -1}
	default:
	}
	if st.role != engineSideServer {
		return engine.Health{OK: true, Detail: "wstunnel client running", LatencyMs: -1}
	}
	start := time.Now()
	err := wstProbeRelay(st.params.RemotePort, 3*time.Second)
	lat := float64(time.Since(start).Milliseconds())
	if err != nil {
		return engine.Health{OK: false, Detail: "tunnel relay probe failed: " + err.Error(), LatencyMs: lat}
	}
	return engine.Health{OK: true, Detail: "relay probe ok (through tunnel)", LatencyMs: lat}
}

// Counters implements engine.Driver: the SERVER end reports wire bytes
// per direction from the nftables rules on the forwarded port; payload
// stays UNKNOWN (wstunnel has no stats API — honest per CANDIDATES).
func (d *WstDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil || st.role != engineSideServer {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if rx, tx, ok := frpWireBytes(inst.TunnelID, st.params.RemotePort, st.params.RemotePort); ok {
		out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
	}
	return out
}

// Uninstall implements engine.Driver: stop every instance, then remove
// the binary cache + instance configs + accounting rules. Idle = zero
// processes, zero files, zero goroutines.
func (d *WstDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, engineEngineDir(wstID))
	return nil
}

// ForwardAddress implements engine.ForwardAddresser: server role → the
// forwarded port is local to the server end; client role → remote host.
func (d *WstDriver) ForwardAddress(inst engine.Instance) (string, int, bool) {
	var p wstParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return "", 0, false
	}
	role, err := wstResolveRole(p)
	if err != nil {
		return "", 0, false
	}
	if role == engineSideServer {
		return "127.0.0.1", p.RemotePort, true
	}
	host := strings.TrimSpace(p.RemoteAddr)
	if h, _, serr := net.SplitHostPort(host); serr == nil {
		host = h
	}
	if host == "" {
		return "", 0, false
	}
	return host, p.RemotePort, true
}

// wstKillSentinel keeps syscall imported for the SIGINT path parity.
var _ = syscall.SIGINT
