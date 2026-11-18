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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	ServerSide string `json:"server_side"`     // server name hosting frps
	Version    string `json:"version"`         // frp artifact version (cache key)
	Artifact   string `json:"artifact"`        // artifact name TEMPLATE; "{arch}" -> runtime GOARCH
	SHA256Amd  string `json:"sha256_amd64"`    // pin: sha256 hex of the amd64 artifact
	SHA256Arm  string `json:"sha256_arm64"`    // pin: sha256 hex of the arm64 artifact
	SigAmd     string `json:"signature_amd64"` // pin: base64 ed25519 signature (amd64)
	SigArm     string `json:"signature_arm64"` // pin: base64 ed25519 signature (arm64)
	ServerAddr string `json:"server_addr"`     // frps host as seen from the frpc side
	ServerPort int    `json:"server_port"`     // frps bind/control port
	Token      string `json:"token"`           // shared frp auth token
	RemotePort int    `json:"remote_port"`     // public data port on frps
	LocalAddr  string `json:"local_addr"`      // Iran-side target host for frpc
	LocalPort  int    `json:"local_port"`      // Iran-side target port
	DashPort   int    `json:"dashboard_port"`  // frps 127.0.0.1 webServer port (payload counters)
	AllowMin   int    `json:"allow_port_min"`  // frps smallest allowed remote port
	AllowMax   int    `json:"allow_port_max"`  // frps largest allowed remote port
}

// frpArtifactPin resolves this host's artifact coordinates by GOARCH.
// Both architectures' pins ride the tunnel description (one tunnel row
// reaches an amd64 Iran agent and an arm64 foreign agent), and each end
// verifies only its own artifact.
func (p frpParams) frpArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	arch := strings.ToLower(runtime.GOARCH)
	if !strings.Contains(p.Artifact, "{arch}") {
		return "", "", "", fmt.Errorf("frp: artifact template must contain {arch}")
	}
	name = strings.ReplaceAll(p.Artifact, "{arch}", arch)
	switch arch {
	case "amd64":
		return name, p.SHA256Amd, p.SigAmd, nil
	case "arm64":
		return name, p.SHA256Arm, p.SigArm, nil
	}
	return "", "", "", fmt.Errorf("frp: no artifact pin for GOARCH %q", arch)
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
	// server_addr/local_addr are rendered into the TOML config with plain
	// quoting: a quote, backslash or newline would inject configuration
	// structure beyond the schema the panel is allowed to deliver (extra
	// proxies/visitors, transport overrides). Both must be 1-128 TOML-safe
	// chars — the same discipline the other TOML-rendering drivers apply
	// (phase-21 ingest audit).
	for _, a := range []struct{ label, v string }{
		{"server_addr", p.ServerAddr}, {"local_addr", p.LocalAddr},
	} {
		if strings.TrimSpace(a.v) == "" || len(a.v) > 128 || strings.ContainsAny(a.v, "\"'\n\r\\ \t") {
			return fmt.Errorf("frp: %s must be 1-128 TOML-safe chars (no quotes, backslash or whitespace)", a.label)
		}
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

// frpResolveRole decides this end's role. The tunnel's two end names
// arrive in Instance.LocalServer/RemoteServer — but both ends see the
// SAME two names (swapped between fields), so they cannot identify self.
//
// Self resolution order (R6, phase 17):
//  1. selfName — DesiredV2.Self.Name, panel-stamped for the RECEIVING
//     agent (the linked mesh server's name). Authoritative: it removes
//     the enrollment-name == server-name alignment assumption, since the
//     panel knows the link even when the names diverge.
//  2. the agent's own enrollment name (pre-R6 panels omit Self; the
//     operator links agents to mesh servers whose names match the
//     enrollment names — the panel's link step controls that alignment).
//
// name == server_side → this agent hosts frps; anything else → frpc.
func frpResolveRole(p frpParams, selfName string) (string, error) {
	selfName = strings.TrimSpace(selfName)
	if selfName == "" {
		ident, ok := frpLoadIdentity()
		if !ok {
			return "", fmt.Errorf("frp: no controller identity — cannot resolve this end's role (fail closed)")
		}
		selfName = ident.Name
	}
	if strings.TrimSpace(p.ServerSide) == selfName {
		return "server", nil
	}
	return "client", nil
}

// frpValidateArtifactPins checks the artifact coordinates every role
// carries: without them the driver refuses to run (fail closed).
func frpValidateArtifactPins(p frpParams) error {
	if strings.TrimSpace(p.Version) == "" || len(p.Version) > 64 ||
		strings.ContainsAny(p.Version, "/\\\"' \t\n\r") {
		return fmt.Errorf("frp: version must be 1-64 safe chars")
	}
	if !strings.Contains(p.Artifact, "{arch}") || strings.ContainsAny(p.Artifact, " \t\n\r\"\\") {
		return fmt.Errorf("frp: artifact must be a name template containing {arch}")
	}
	for _, a := range []struct {
		arch string
		sha  string
		sig  string
	}{{"amd64", p.SHA256Amd, p.SigAmd}, {"arm64", p.SHA256Arm, p.SigArm}} {
		if len(a.sha) != 64 {
			return fmt.Errorf("frp: sha256 (%s) must be 64 hex chars", a.arch)
		}
		if _, err := hex.DecodeString(a.sha); err != nil {
			return fmt.Errorf("frp: sha256 (%s) must be hex", a.arch)
		}
		if a.sig == "" || len(a.sig) > 256 {
			return fmt.Errorf("frp: signature (%s) required (base64 ed25519 over the artifact)", a.arch)
		}
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
// SIGKILL after a short grace period. Every wait is capped: a process
// wedged in graceful drain (open client connections) must never block
// Stop — worst case the exit is leaked to the OS reaper instead.
func frpProcStop(p frpProcess) {
	if p == nil {
		return
	}
	_ = p.Signal(syscall.SIGINT)
	select {
	case <-p.Done():
		return
	case <-time.After(3 * time.Second):
	}
	_ = p.Signal(os.Kill)
	select {
	case <-p.Done():
	case <-time.After(5 * time.Second):
	}
}

// frpInstState is the runtime state of one instance. The supervisor
// goroutine (one per RUNNING instance; none when idle) restarts the
// process if it dies unexpectedly — the engine Manager only reconciles
// on desired-state changes and boot, so without it a killed frp process
// would stay dead until the next panel push. The proc/stop/cfg/binPath
// base rides the shared engineInst (A1).
type frpInstState struct {
	engineInst
	params frpParams
	role   string
}

// FRPDriver implements engine.Driver over frps/frpc.
type FRPDriver struct {
	runs *instTable[frpInstState] // tunnelID -> state
}

// NewFRPDriver returns the FRP engine driver.
func NewFRPDriver() *FRPDriver {
	return &FRPDriver{runs: newInstTable[frpInstState]()}
}

var (
	_ engine.Driver           = (*FRPDriver)(nil)
	_ engine.Describer        = (*FRPDriver)(nil)
	_ engine.ForwardAddresser = (*FRPDriver)(nil)
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
	return filepath.Join(engineEngineDir(frpID), version)
}

// frpEngineDir is the whole-engine state dir (removed by Uninstall).
func frpEngineDir() string {
	return engineEngineDir(frpID)
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

// ForwardAddress implements the optional engine.ForwardAddresser
// capability: the delivery target new connections are DNATed to when
// this tunnel is part of a balancing group. The target loops back into
// the tunnel toward the Iran-side service (frps data listener on the
// frps end, the frps address as seen from the frpc end): server role →
// 127.0.0.1:remote_port; client role → server_addr:remote_port. The
// explicit remote_port always wins over the rule's listen port (the
// frps listener is bound to it).
func (d *FRPDriver) ForwardAddress(inst engine.Instance) (string, int, bool) {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return "", 0, false
	}
	if st.role == "server" {
		return "127.0.0.1", st.params.RemotePort, true
	}
	return st.params.ServerAddr, st.params.RemotePort, true
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

	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual[frpParams](prev.params, p) && prev.proc != nil {
			select {
			case <-prev.proc.Done(): // process exited: fall through to restart
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst) // params changed or dead process: clean restart
	}

	role, err := frpResolveRole(p, inst.SelfName)
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
	st := &frpInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		cfg: cfgPath, binPath: binPath}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, st.binPath, st.cfg, frpSpawn) // one goroutine per RUNNING instance
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

// supervise was the per-driver wrapper over the shared engineSupervise;
// A1 deleted it — Start calls engineSupervise directly (same contract:
// Stop closes the stop channel before killing the process, so a killed
// process is never resurrected).

// Stop implements engine.Driver: terminate the process, drop the config
// and the wire-accounting rule (the shared teardown order; the server
// end's allow-range rule is the driver-specific hook). Stopping a
// non-running instance is a no-op.
func (d *FRPDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.role == "server" {
			_ = frpWireRulesDel(inst.TunnelID, st.params.AllowMin, st.params.AllowMax)
		}
	})
	return nil
}

// Reload implements engine.Driver: frp applies nothing live through this
// driver — equal params are a no-op, anything else is a restart.
func (d *FRPDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, frpID, inst.TunnelID, inst.Params,
		func(st *frpInstState) frpParams { return st.params }, engineParamsEqual[frpParams])
}

// Health implements engine.Driver.
func (d *FRPDriver) Health(inst engine.Instance) engine.Health {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Health{OK: false, Detail: "not running", LatencyMs: -1}
	}
	alive := true
	select {
	case <-st.current().Done():
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
	st := d.runs.peek(inst.TunnelID)
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
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, frpEngineDir())
	return nil
}
