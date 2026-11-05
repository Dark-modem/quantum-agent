package agent

// frp_driver.go — the FRP engine (frps on the foreign side, frpc on the
// Iran side) wrapped as an engine.Driver per 00-ADMIN/ENGINE-GUIDE.md.
//
// Tunnel shape: an instance on the foreign host runs one frps bound to
// frp_server_port; the matching instance on the Iran host runs one frpc
// that forwards local_addr:local_port to frps:remote_port (plain TCP
// proxy — the "FRP over the existing carrier" shape). Each tunnel gets
// its own frps/frpc process pair, config file, dashboard port and remote
// port, so instances are independent and stop/uninstall leave nothing.
//
// Binary policy (documented per the phase-3 contract):
//   - EnsureBinary downloads the pinned frp artifact from the controller's
//     artifact endpoint (frp_artifact.go), verifies sha256 + ed25519
//     (fail-closed without a pinned key) and extracts frps/frpc into
//     <configDir>/engines/frp/<version>/. The cache exists only while the
//     engine has instances: Uninstall (called by the Manager after the
//     last instance stopped) removes it.
//   - While an instance runs, the only files are that cache plus one
//     per-tunnel config at <configDir>/engines/frp/<tunnelID>.toml
//     (0600, removed on Stop). No processes or goroutines exist while
//     the engine has zero instances.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// frpID is the engine id used in desired state.
const frpID = "frp"

// frpParams is the engine_params shape the FRP driver accepts. One
// tunnel description is delivered to BOTH ends (the compiler sends the
// same params to each agent); each end resolves its own side by naming
// which end hosts frps (frp_server_side must equal that end's server
// name — the compiler fills Instance.LocalServer with the receiving
// agent's own server name, so a match means "I am the frps side").
type frpParams struct {
	ServerSide string `json:"server_side"`           // server name hosting frps
	Version    string `json:"version"`               // frp artifact version (cache key)
	Artifact   string `json:"artifact"`              // artifact file name on the controller
	SHA256     string `json:"sha256"`                // pin: sha256 hex of the artifact
	Signature  string `json:"signature"`             // pin: base64 ed25519 signature over the artifact
	ServerAddr string `json:"server_addr,omitempty"` // frps host as seen from the frpc side
	ServerPort int    `json:"server_port"`           // frps bind/control port
	Token      string `json:"token"`                 // shared frp auth token
	RemotePort int    `json:"remote_port"`           // public data port on frps
	LocalAddr  string `json:"local_addr"`            // Iran-side target host for frpc
	LocalPort  int    `json:"local_port"`            // Iran-side target port
	DashPort   int    `json:"dashboard_port"`        // frps 127.0.0.1 webServer port (payload counters)
	AllowMin   int    `json:"allow_port_min"`        // frps smallest allowed remote port
	AllowMax   int    `json:"allow_port_max"`        // frps largest allowed remote port
}

// frpValidateParams checks the union shape (no side effects, no binary
// access). The side is not known until Start (it comes from the
// Instance), so Validate conservatively requires the fields both sides
// consume.
func frpValidateParams(p frpParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("frp: server_side (name of the end hosting frps) required")
	}
	if err := frpValidateArtifactPins(p); err != nil {
		return err
	}
	if p.ServerPort < 1 || p.ServerPort > 65535 {
		return fmt.Errorf("frp: server_port must be 1-65535")
	}
	if p.Token == "" || len(p.Token) > 128 || strings.ContainsAny(p.Token, "\"\\ \t\n\r") {
		return fmt.Errorf("frp: token must be 1-128 chars without quotes, backslash or whitespace")
	}
	if p.RemotePort < 1 || p.RemotePort > 65535 {
		return fmt.Errorf("frp: remote_port must be 1-65535")
	}
	if strings.TrimSpace(p.ServerAddr) == "" {
		return fmt.Errorf("frp: server_addr required (frps host as seen from the frpc side)")
	}
	if strings.TrimSpace(p.LocalAddr) == "" {
		return fmt.Errorf("frp: local_addr required (Iran-side target host)")
	}
	if p.LocalPort < 1 || p.LocalPort > 65535 {
		return fmt.Errorf("frp: local_port must be 1-65535")
	}
	if p.DashPort < 1 || p.DashPort > 65535 {
		return fmt.Errorf("frp: dashboard_port must be 1-65535 (localhost payload counters)")
	}
	if p.AllowMin < 1 || p.AllowMax > 65535 || p.AllowMin > p.AllowMax {
		return fmt.Errorf("frp: allow_port_min <= allow_port_max within 1-65535 required")
	}
	return nil
}

// frpResolveRole decides this end's role from the instance context:
// the compiler sets Instance.LocalServer to the receiving agent's own
// server name, so a match with server_side means "I host frps".
func frpResolveRole(inst engine.Instance, p frpParams) (string, error) {
	if inst.LocalServer == p.ServerSide {
		return "server", nil
	}
	if inst.RemoteServer == p.ServerSide {
		return "client", nil
	}
	return "", fmt.Errorf("frp: server_side %q matches neither this instance's local (%q) nor remote (%q) server",
		p.ServerSide, inst.LocalServer, inst.RemoteServer)
}

// frpValidateArtifactPins checks the artifact coordinates every role
// carries: without them the driver refuses to run (fail closed).
func frpValidateArtifactPins(p frpParams) error {
	if strings.TrimSpace(p.Version) == "" || len(p.Version) > 64 ||
		strings.ContainsAny(p.Version, "/\\\"' \t\n\r") {
		return fmt.Errorf("frp: version must be 1-64 safe chars")
	}
	if !frpArtifactNameOK(p.Artifact) {
		return fmt.Errorf("frp: artifact name invalid")
	}
	if len(p.SHA256) != 64 {
		return fmt.Errorf("frp: sha256 must be 64 hex chars")
	}
	if _, err := hex.DecodeString(p.SHA256); err != nil {
		return fmt.Errorf("frp: sha256 must be hex")
	}
	if p.Signature == "" || len(p.Signature) > 256 {
		return fmt.Errorf("frp: signature required (base64 ed25519 over the artifact)")
	}
	return nil
}

// frpTunnelIDOK mirrors the panel artifact-name charset: the tunnel id
// becomes a TOML string and an iptables comment.
func frpTunnelIDOK(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.'
		if !ok {
			return false
		}
	}
	return true
}

// frpProcess is one running frps/frpc process (seam-able for tests).
type frpProcess interface {
	Pid() int
	Signal(sig os.Signal) error
	Done() <-chan error
}

type frpExecProcess struct {
	cmd  *exec.Cmd
	done chan error
}

func (p *frpExecProcess) Pid() int                   { return p.cmd.Process.Pid }
func (p *frpExecProcess) Signal(sig os.Signal) error { return p.cmd.Process.Signal(sig) }
func (p *frpExecProcess) Done() <-chan error         { return p.done }

// frpSpawn is the process-start seam (tests capture, never exec).
var frpSpawn = func(binPath, cfgPath string) (frpProcess, error) {
	cmd := exec.Command(binPath, "-c", cfgPath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("frp: start %s: %w", binPath, err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

// frpProcStop terminates a process: SIGINT (frp's graceful stop), then
// SIGKILL after a short grace period.
func frpProcStop(p frpProcess) {
	if p == nil {
		return
	}
	_ = p.Signal(syscall.SIGINT)
	select {
	case <-p.Done():
		return
	case <-time.After(3 * time.Second):
		_ = p.Signal(os.Kill)
		<-p.Done()
	}
}

// frpInstState is the runtime state of one instance.
type frpInstState struct {
	params frpParams
	role   string
	cfg    string
	proc   frpProcess
}

// FRPDriver implements engine.Driver over frps/frpc.
type FRPDriver struct {
	mu   sync.Mutex
	runs map[string]*frpInstState // tunnelID -> state
}

// NewFRPDriver returns the FRP engine driver.
func NewFRPDriver() *FRPDriver {
	return &FRPDriver{runs: map[string]*frpInstState{}}
}

var (
	_ engine.Driver    = (*FRPDriver)(nil)
	_ engine.Describer = (*FRPDriver)(nil)
)

// ID implements engine.Driver.
func (d *FRPDriver) ID() string { return frpID }

// Describe implements engine.Describer (PROTOCOL-REQUESTS R3).
func (d *FRPDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: frpID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"role":"server|client","version":"","artifact":"","sha256":"","signature":"","server_addr":"","server_port":0,"token":"","remote_port":0,"local_addr":"","local_port":0,"dashboard_port":0,"allow_port_min":0,"allow_port_max":0}`)}
}

// EnsureBinary implements engine.Driver: downloads and verifies the
// pinned frp artifact via the controller (frp_artifact.go) and returns
// the cache directory holding frps/frpc.
func (d *FRPDriver) EnsureBinary(ctx context.Context) (string, error) {
	// The Manager calls this before the first instance starts; the
	// per-instance pins ride engine_params, so the download itself
	// happens in Start via frpEnsureBinary with the pinned coordinates.
	return "", nil
}

// Validate implements engine.Driver.
func (d *FRPDriver) Validate(params json.RawMessage) error {
	var p frpParams
	if len(params) == 0 {
		return errors.New("frp: engine_params required")
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("frp: engine_params: %w", err)
	}
	return frpValidateParams(p)
}

// frpParseParams unmarshals already-validated params.
func frpParseParams(raw json.RawMessage) (frpParams, error) {
	var p frpParams
	err := json.Unmarshal(raw, &p)
	return p, err
}

// frpConfigPath is the per-tunnel config file (exists only while running).
func frpConfigPath(tunnelID string) string {
	return filepath.Join(configDir, "engines", "frp", tunnelID+".toml")
}

// frpBinDir is the per-version binary cache (exists only while installed).
func frpBinDir(version string) string {
	return filepath.Join(configDir, "engines", "frp", version)
}

// frpEngineDir is the whole-engine state dir (removed by Uninstall).
func frpEngineDir() string {
	return filepath.Join(configDir, "engines", "frp")
}

// frpRenderConfig renders the frps/frpc TOML for one instance. The token
// charset was validated, so plain quoting is safe.
func frpRenderConfig(tunnelID, role string, p frpParams) string {
	var b strings.Builder
	switch role {
	case "server":
		fmt.Fprintf(&b, "bindAddr = \"0.0.0.0\"\n")
		fmt.Fprintf(&b, "bindPort = %d\n", p.ServerPort)
		fmt.Fprintf(&b, "auth.token = \"%s\"\n", p.Token)
		fmt.Fprintf(&b, "webServer.addr = \"127.0.0.1\"\n")
		fmt.Fprintf(&b, "webServer.port = %d\n", p.DashPort)
		fmt.Fprintf(&b, "webServer.user = \"quantum\"\n")
		fmt.Fprintf(&b, "webServer.password = \"%s\"\n", frpDashSecret(tunnelID, p))
		fmt.Fprintf(&b, "allowPorts = [{ start = %d, end = %d }]\n", p.AllowMin, p.AllowMax)
	case "client":
		fmt.Fprintf(&b, "serverAddr = \"%s\"\n", p.ServerAddr)
		fmt.Fprintf(&b, "serverPort = %d\n", p.ServerPort)
		fmt.Fprintf(&b, "auth.token = \"%s\"\n", p.Token)
		fmt.Fprintf(&b, "[[proxies]]\n")
		fmt.Fprintf(&b, "name = \"%s\"\n", tunnelID)
		fmt.Fprintf(&b, "type = \"tcp\"\n")
		fmt.Fprintf(&b, "localIP = \"%s\"\n", p.LocalAddr)
		fmt.Fprintf(&b, "localPort = %d\n", p.LocalPort)
		fmt.Fprintf(&b, "remotePort = %d\n", p.RemotePort)
	}
	return b.String()
}

// frpDashSecret derives the localhost-only dashboard password (never
// logged, never leaves the host).
func frpDashSecret(tunnelID string, p frpParams) string {
	sum := sha256.Sum256([]byte("frpdrv:" + tunnelID + ":" + p.Token))
	return hex.EncodeToString(sum[:])[:16]
}

// Start implements engine.Driver: idempotent per TunnelID. Starting an
// already-running instance whose params did not change is a no-op;
// changed params restart the process (frp has no live-reload API the
// driver relies on).
func (d *FRPDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p frpParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("frp: engine_params: %w", err)
	}
	if err := frpValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("frp: invalid tunnel id %q", inst.TunnelID)
	}

	d.mu.Lock()
	prev := d.runs[inst.TunnelID]
	d.mu.Unlock()
	if prev != nil {
		if frpParamsEqual(prev.params, p) && prev.proc != nil {
			select {
			case <-prev.proc.Done(): // process exited: fall through to restart
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst) // params changed or dead process: clean restart
	}

	role, err := frpResolveRole(inst, p)
	if err != nil {
		return err
	}
	binDir, err := frpEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	bin := "frps"
	if role == "client" {
		bin = "frpc"
	}
	binPath := binDir + "/" + bin
	cfg := frpRenderConfig(inst.TunnelID, role, p)
	cfgPath := frpConfigPath(inst.TunnelID)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("frp: config dir: %w", err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("frp: write config: %w", err)
	}
	proc, err := frpSpawn(binPath, cfgPath)
	if err != nil {
		_ = os.Remove(cfgPath)
		return err
	}
	d.mu.Lock()
	d.runs[inst.TunnelID] = &frpInstState{params: p, role: role, cfg: cfgPath, proc: proc}
	d.mu.Unlock()
	// Wire accounting is installed on the server side only (the client's
	// control port is shared across instances and cannot be attributed).
	if role == "server" {
		if err := frpWireRulesAdd(inst.TunnelID, p.AllowMin, p.AllowMax); err != nil {
			// Data plane still runs; counters become Unknown honestly.
			fmt.Fprintf(os.Stderr, "frp: wire accounting unavailable: %v\n", err)
		}
	}
	return nil
}

// Stop implements engine.Driver: terminate the process, drop the config
// and the wire-accounting rule. Stopping a non-running instance is a
// no-op.
func (d *FRPDriver) Stop(inst engine.Instance) error {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	delete(d.runs, inst.TunnelID)
	d.mu.Unlock()
	if st == nil {
		return nil
	}
	frpProcStop(st.proc)
	_ = os.Remove(st.cfg)
	if st.role == "server" {
		_ = frpWireRulesDel(inst.TunnelID, st.params.AllowMin, st.params.AllowMax)
	}
	return nil
}

// Reload implements engine.Driver: frp applies nothing live through this
// driver — equal params are a no-op, anything else is a restart.
func (d *FRPDriver) Reload(inst engine.Instance) error {
	var p frpParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("frp: engine_params: %w", err)
	}
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
	if st == nil {
		return fmt.Errorf("frp: reload on stopped instance %q", inst.TunnelID)
	}
	if frpParamsEqual(st.params, p) {
		return nil
	}
	return engine.ErrRestartRequired
}

// Health implements engine.Driver.
func (d *FRPDriver) Health(inst engine.Instance) engine.Health {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
	if st == nil {
		return engine.Health{OK: false, Detail: "not running", LatencyMs: -1}
	}
	alive := true
	select {
	case <-st.proc.Done():
		alive = false
	default:
	}
	if !alive {
		return engine.Health{OK: false, Detail: "process exited", LatencyMs: -1}
	}
	if st.role == "server" {
		// Real handshake: the localhost dashboard API answers with auth.
		start := time.Now()
		code, err := frpDashStatus(st.params.DashPort, frpDashSecret(inst.TunnelID, st.params))
		lat := float64(time.Since(start).Milliseconds())
		if err != nil || code != 200 {
			return engine.Health{OK: false, Detail: "dashboard API not answering", LatencyMs: lat}
		}
		return engine.Health{OK: true, Detail: "frps running, api ok", LatencyMs: lat}
	}
	return engine.Health{OK: true, Detail: "frpc process running", LatencyMs: -1}
}

// Counters implements engine.Driver. Server side: wire bytes from
// per-port iptables accounting on the carrier (data port only — the
// control port is shared), payload bytes from the frps web API (its
// counters reset daily; documented, never multiplied). Client side:
// neither view is attributable per instance — Unknown, honestly.
func (d *FRPDriver) Counters(inst engine.Instance) engine.Counters {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
	if st == nil {
		return engine.Counters{}
	}
	if st.role != "server" {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if rx, tx, ok := frpWireBytes(inst.TunnelID, st.params.AllowMin, st.params.AllowMax); ok {
		out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
	}
	if in, outB, ok := frpPayloadBytes(inst.TunnelID, st.params.DashPort, frpDashSecret(inst.TunnelID, st.params)); ok {
		out.PayloadRx, out.PayloadTx, out.PayloadKnown = in, outB, true
	}
	return out
}

// Uninstall implements engine.Driver: stop everything and remove the
// binary cache + config dir. The Manager calls it after the last
// instance stopped, so idle engines leave zero processes and zero files.
func (d *FRPDriver) Uninstall(ctx context.Context) error {
	d.mu.Lock()
	ids := make([]string, 0, len(d.runs))
	for id := range d.runs {
		ids = append(ids, id)
	}
	d.mu.Unlock()
	for _, id := range ids {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}
	_ = os.RemoveAll(frpEngineDir())
	return nil
}

// frpParamsEqual compares parsed params (key-order independent).
func frpParamsEqual(a, b frpParams) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return subtle.ConstantTimeCompare(ab, bb) == 1
}
