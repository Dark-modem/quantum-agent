// chisel_driver.go — engine driver for chisel (github.com/jpillora/chisel,
// MIT — license verified from the upstream tree at the pinned tag; the
// text ships inside every artifact via the packer). Seventh driver.
//
// PINNED UPSTREAM: v1.10.x CLI shape:
//
//	server (foreign): chisel server --port <server_port> --reverse [--auth user:pass]
//	client  (iran):   chisel client [--auth user:pass] http://<remote_addr>:<server_port> \
//	                    R:0.0.0.0:<remote_port>:<local_addr>:<local_port>
//
// The Iran end runs the CLIENT (dials out); the R (reverse) remote makes
// the FOREIGN listener relay TCP through the tunnel to the Iran-side
// target — the FRP reverse shape. chisel is TCP-only (CANDIDATES #5).
// Auth rides --auth user:pass on both ends when configured (shape-checked;
// never logged).
//
// Health: SERVER end performs a REAL probe THROUGH the tunnel — dial the
// reverse-listened port, write a probe byte and wait: chisel binds the
// listener on the server as soon as the client declares it, but the inner
// relay to the Iran target only completes when the client is alive; a
// dead path is closed immediately, a live path holds the connection.
// The CLIENT end checks process liveness.
//
// Accounting: wire bytes per direction via nftables on the reverse port
// (server end); payload UNKNOWN (no stats API) — honest.

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
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const (
	chiselID      = "chisel"
	chiselVersion = "1.10.1" // PINNED upstream CLI shape (v1.10)
)

// chiselParams is the engine_params shape the chisel driver accepts.
type chiselParams struct {
	ServerSide string `json:"server_side"`  // foreign end name (hosts the chisel server)
	Version    string `json:"version"`      // artifact version (cache key)
	Artifact   string `json:"artifact"`     // name TEMPLATE with {arch}
	SHA256Amd  string `json:"sha256_amd64"` // pinned fallback
	SHA256Arm  string `json:"sha256_arm64"`
	SigAmd     string `json:"signature_amd64"`
	SigArm     string `json:"signature_arm64"`
	RemoteAddr string `json:"remote_addr"`    // foreign public host
	ServerPort int    `json:"server_port"`    // foreign chisel HTTP/WS port
	RemotePort int    `json:"remote_port"`    // foreign reverse-listened TCP port → Iran target
	LocalAddr  string `json:"local_addr"`     // Iran-side target host
	LocalPort  int    `json:"local_port"`     // Iran-side target TCP port
	Auth       string `json:"auth,omitempty"` // optional user:pass (--auth both ends)
}

func (p chiselParams) chiselArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	return enginePinForArch(EnginePin{Version: p.Version, Artifact: p.Artifact,
		SHA256Amd: p.SHA256Amd, SHA256Arm: p.SHA256Arm, SigAmd: p.SigAmd, SigArm: p.SigArm})
}

func chiselValidateParams(p chiselParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("chisel: server_side required")
	}
	if strings.TrimSpace(p.Version) == "" || len(p.Version) > 64 ||
		strings.ContainsAny(p.Version, "/\\\"' \t\n\r") {
		return fmt.Errorf("chisel: version must be 1-64 safe chars")
	}
	if !strings.Contains(p.Artifact, "{arch}") || strings.ContainsAny(p.Artifact, " \t\n\r\"\\") {
		return fmt.Errorf("chisel: artifact must be a name template containing {arch}")
	}
	for _, a := range []struct{ sha, sig string }{{p.SHA256Amd, p.SigAmd}, {p.SHA256Arm, p.SigArm}} {
		if len(a.sha) != 64 || strings.ContainsAny(a.sha, " \t\n\r") {
			return fmt.Errorf("chisel: sha256 pin must be 64 hex chars")
		}
		if len(a.sig) < 64 || len(a.sig) > 512 || strings.ContainsAny(a.sig, " \t\n\r") {
			return fmt.Errorf("chisel: signature pin must be base64 (64-512 chars)")
		}
	}
	if p.ServerPort <= 0 || p.ServerPort > 65535 || p.RemotePort <= 0 || p.RemotePort > 65535 {
		return fmt.Errorf("chisel: server_port/remote_port out of range")
	}
	if p.RemotePort == p.ServerPort {
		return fmt.Errorf("chisel: remote_port must differ from server_port")
	}
	if strings.TrimSpace(p.LocalAddr) == "" || strings.ContainsAny(p.LocalAddr, "\"'\n\r\\") ||
		p.LocalPort <= 0 || p.LocalPort > 65535 {
		return fmt.Errorf("chisel: local_addr/local_port invalid")
	}
	if strings.TrimSpace(p.RemoteAddr) == "" || strings.ContainsAny(p.RemoteAddr, "\"'\n\r\\") {
		return fmt.Errorf("chisel: remote_addr invalid")
	}
	if p.Auth != "" {
		if err := engineVerifySecretShape("chisel auth", p.Auth, 3, 128); err != nil {
			return err
		}
		if !strings.Contains(p.Auth, ":") {
			return fmt.Errorf("chisel: auth must be user:pass")
		}
	}
	return nil
}

// chiselResolveRole resolves this end's role through the enrollment name.
func chiselResolveRole(p chiselParams) (engineSide, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("chisel: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return engineSideServer, nil
	}
	return engineSideClient, nil
}

func chiselConfigPath(tunnelID string) string {
	return filepath.Join(engineEngineDir(chiselID), "instances", tunnelID+".args")
}
func chiselBinDir(version string) string {
	return filepath.Join(engineEngineDir(chiselID), "bin", version)
}

// chiselClientArgs renders the client command (validated params only).
func chiselClientArgs(p chiselParams) []string {
	args := []string{"client"}
	if p.Auth != "" {
		args = append(args, "--auth", p.Auth)
	}
	args = append(args, fmt.Sprintf("http://%s", net.JoinHostPort(p.RemoteAddr, fmt.Sprint(p.ServerPort))),
		fmt.Sprintf("R:0.0.0.0:%d:%s:%d", p.RemotePort, p.LocalAddr, p.LocalPort))
	return args
}

// chiselServerArgs renders the server command (--reverse is REQUIRED for
// the R remote to be accepted).
func chiselServerArgs(p chiselParams) []string {
	args := []string{"server", "--port", fmt.Sprintf("%d", p.ServerPort), "--reverse"}
	if p.Auth != "" {
		args = append(args, "--auth", p.Auth)
	}
	return args
}

// chiselInstState is one RUNNING instance's state (supervisor target).
// The proc/stop/cfg/binPath base rides the shared engineInst (A1).
type chiselInstState struct {
	engineInst
	params chiselParams
	role   engineSide
}

// ChiselDriver implements engine.Driver for chisel.
type ChiselDriver struct {
	runs *instTable[chiselInstState]
}

func NewChiselDriver() *ChiselDriver { return &ChiselDriver{runs: newInstTable[chiselInstState]()} }

func (d *ChiselDriver) ID() string { return chiselID }

func (d *ChiselDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: chiselID, Version: chiselVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","remote_addr":"","server_port":0,"remote_port":0,"local_addr":"","local_port":0,"auth":"user:pass"}`)}
}

// EnsureBinary: the Manager calls this before the first instance starts;
// the download happens in Start via chiselEnsureBinary.
func (d *ChiselDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *ChiselDriver) Validate(params json.RawMessage) error {
	var p chiselParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("chisel: engine_params: %w", err)
	}
	return chiselValidateParams(p)
}

func chiselEnsureBinary(ctx context.Context, p chiselParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("chisel: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.chiselArtifactPin(); pinErr == nil && engineCacheHit(chiselBinDir(p.Version), pinnedSHA, []string{"chisel"}) {
		return chiselBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("chisel: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, chiselID,
		func() (string, string, string, error) { return p.chiselArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := chiselBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"chisel"}) {
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
		return "", fmt.Errorf("chisel: cache dir: %w", err)
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"chisel": true}); err != nil {
		return "", err
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("chisel: cache marker: %w", err)
	}
	return dir, nil
}

// chiselParamsEqual was the Reload no-op comparison; A1 moved the
// canonical-JSON compare to the shared engineParamsEqual.

var chiselSpawn = func(binPath string, args []string) (frpProcess, error) {
	cmd := exec.Command(binPath, args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("chisel: start %s: %w", binPath, err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

// Start implements engine.Driver.
func (d *ChiselDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p chiselParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("chisel: engine_params: %w", err)
	}
	if err := chiselValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("chisel: invalid tunnel id %q", inst.TunnelID)
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
	role, err := chiselResolveRole(p)
	if err != nil {
		return err
	}
	binDir, err := chiselEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "chisel")
	args := chiselServerArgs(p)
	if role == engineSideClient {
		args = chiselClientArgs(p)
	}
	cfgPath := chiselConfigPath(inst.TunnelID)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("chisel: config dir: %w", err)
	}
	// 0600: --auth may ride these args.
	if err := os.WriteFile(cfgPath, []byte(strings.Join(args, "\n")), 0o600); err != nil {
		return fmt.Errorf("chisel: write args: %w", err)
	}
	proc, err := chiselSpawn(binPath, args)
	if err != nil {
		_ = os.Remove(cfgPath)
		return err
	}
	st := &chiselInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		cfg: cfgPath, binPath: binPath}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, binPath, "", func(b, _ string) (frpProcess, error) {
		return chiselSpawn(b, args)
	})
	if role == engineSideServer {
		if err := frpWireRulesAdd(inst.TunnelID, p.RemotePort, p.RemotePort); err != nil {
			fmt.Fprintf(os.Stderr, "chisel: wire accounting unavailable: %v\n", err)
		}
	}
	return nil
}

// Stop implements engine.Driver: the shared teardown order, with the
// server end's wire-accounting rule as the driver-specific hook.
func (d *ChiselDriver) Stop(inst engine.Instance) error {
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
func (d *ChiselDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, chiselID, inst.TunnelID, inst.Params,
		func(st *chiselInstState) chiselParams { return st.params }, engineParamsEqual[chiselParams])
}

// chiselProbeRelay performs the REAL through-the-tunnel probe (same
// contract as wstProbeRelay).
func chiselProbeRelay(port int, timeout time.Duration) error {
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
		// Echo target: no echo = dead relay (chisel closes fast when the
		// client is gone).
		return fmt.Errorf("relay dead (no echo): %w", err)
	}
	return nil
}

// Health implements engine.Driver: process alive; on the SERVER end the
// reverse port must answer THROUGH the tunnel.
func (d *ChiselDriver) Health(inst engine.Instance) engine.Health {
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
		return engine.Health{OK: true, Detail: "chisel client running", LatencyMs: -1}
	}
	start := time.Now()
	err := chiselProbeRelay(st.params.RemotePort, 3*time.Second)
	lat := float64(time.Since(start).Milliseconds())
	if err != nil {
		return engine.Health{OK: false, Detail: "tunnel relay probe failed: " + err.Error(), LatencyMs: lat}
	}
	return engine.Health{OK: true, Detail: "relay probe ok (through tunnel)", LatencyMs: lat}
}

// Counters implements engine.Driver: the SERVER end reports wire bytes
// per direction from the nftables rules on the reverse port; payload
// UNKNOWN (chisel has no stats API — honest per CANDIDATES).
func (d *ChiselDriver) Counters(inst engine.Instance) engine.Counters {
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

// Uninstall implements engine.Driver.
func (d *ChiselDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, engineEngineDir(chiselID))
	return nil
}

// ForwardAddress implements engine.ForwardAddresser.
func (d *ChiselDriver) ForwardAddress(inst engine.Instance) (string, int, bool) {
	var p chiselParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return "", 0, false
	}
	role, err := chiselResolveRole(p)
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
