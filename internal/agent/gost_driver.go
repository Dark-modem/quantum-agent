package agent

// gost_driver.go — the gost engine (go-gost/gost v3, MIT — license
// verified from the upstream tree at the pinned release; the release
// tarball itself ships LICENSE) as an engine.Driver per
// 00-ADMIN/ENGINE-GUIDE.md's production checklist. Exec-a-binary.
//
// Tunnel shape (reverse port forwarding, verified against the upstream
// port-forwarding docs — gost.run/en/tutorials/port-forwarding):
//
//	server (foreign): gost -L "relay+ws://:<carrier>?bind=true"
//	    a Relay service over the ONE carrier (websocket) with the BIND
//	    capability: it accepts the client's registration and opens the
//	    remote-forward listener ON the foreign host.
//	client (Iran):    gost -L "rtcp://:<public>/<localAddr>" -F "relay+ws://<carrier>"
//	    remote-TCP forward: the rtcp listener binds <public> on the
//	    CHAIN END (the foreign host); connections there tunnel back to
//	    localAddr on the Iran machine.
//
// ONE carrier family by design (task scope): ws. wss is rejected at
// Validate with a clear message (TLS cert management is a separate
// slice; fail closed rather than ship an unencrypted-shaped surprise).
//
// Strictly typed args (no shell, no config file): the CLI form above is
// fully specified by four typed fields, built with fmt.Sprintf and passed
// as separate exec args — nothing free-form reaches a shell.
//
// Health (the warmup gate, checklist item 11): the rtcp listener on the
// foreign host binds the public port only while the client's relay
// connection is live — a successful dial to 127.0.0.1:<public> on the
// SERVER end proves the tunnel is registered end to end (the same gate
// shape as the rathole driver), retried 0/300/800ms.
//
// Counters: wire = iptables on the carrier port (server end); payload
// stays Unknown (gost v3's trafficStats surface requires the operator's
// API service setup — no per-instance machine-readable stats in the OSS
// binary; verified against the config reference).

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"strings"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const gostID = "gost"

type gostParams struct {
	ServerSide  string `json:"server_side"`  // the end hosting the gost RELAY (foreign)
	Version     string `json:"version"`      // artifact version (cache key)
	Artifact    string `json:"artifact"`     // name template with {arch}
	SHA256Amd   string `json:"sha256_amd64"` // pinned fallback
	SHA256Arm   string `json:"sha256_arm64"`
	SigAmd      string `json:"signature_amd64"`
	SigArm      string `json:"signature_arm64"`
	CarrierAddr string `json:"carrier_addr"` // server: relay+ws listen "0.0.0.0:port"; client: dial "host:port"
	PublicPort  int    `json:"public_port"`  // the PUBLIC data port opened on the foreign host (rtcp)
	LocalAddr   string `json:"local_addr"`   // client-side target "127.0.0.1:port"
	Transport   string `json:"transport"`    // "ws" (wss: see the header note — rejected for now)
}

func (p gostParams) gostArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	arch := strings.ToLower(runtime.GOARCH)
	if !strings.Contains(p.Artifact, "{arch}") {
		return "", "", "", fmt.Errorf("gost: artifact template must contain {arch}")
	}
	name = strings.ReplaceAll(p.Artifact, "{arch}", arch)
	switch arch {
	case "amd64":
		return name, p.SHA256Amd, p.SigAmd, nil
	case "arm64":
		return name, p.SHA256Arm, p.SigArm, nil
	}
	return "", "", "", fmt.Errorf("gost: no artifact pin for GOARCH %q", arch)
}

func gostValidateParams(p gostParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("gost: server_side required")
	}
	if err := backhaulValidateArtifactPins2(p.Version, p.Artifact, p.SHA256Amd, p.SigAmd, p.SHA256Arm, p.SigArm, gostID); err != nil {
		return err
	}
	t := strings.ToLower(strings.TrimSpace(p.Transport))
	if t != "ws" {
		if t == "wss" {
			return fmt.Errorf("gost: transport wss is not implemented yet (TLS cert management is a separate slice) — use ws")
		}
		return fmt.Errorf("gost: transport must be ws (one carrier family by design; wss pending TLS cert management)")
	}
	if _, port, err := net.SplitHostPort(strings.TrimSpace(p.CarrierAddr)); err != nil || port == "" {
		return fmt.Errorf("gost: carrier_addr must be host:port")
	}
	if p.CarrierAddr != strings.TrimSpace(p.CarrierAddr) || strings.ContainsAny(p.CarrierAddr, "\"'\\\n\r") {
		return fmt.Errorf("gost: carrier_addr not CLI-safe")
	}
	if p.PublicPort <= 0 || p.PublicPort > 65535 {
		return fmt.Errorf("gost: public_port out of range")
	}
	if _, _, err := net.SplitHostPort(strings.TrimSpace(p.LocalAddr)); err != nil ||
		p.LocalAddr != strings.TrimSpace(p.LocalAddr) || strings.ContainsAny(p.LocalAddr, "\"'\\\n\r") {
		return fmt.Errorf("gost: local_addr must be a CLI-safe host:port")
	}
	return nil
}

func gostResolveRole(p gostParams) (string, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("gost: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return "server", nil
	}
	return "client", nil
}

// gostInstState is one RUNNING instance's state. The proc/stop/binPath
// base rides the shared engineInst (A1); cfg stays empty (args-form —
// no config file is written or removed).
type gostInstState struct {
	engineInst
	params gostParams
	role   string
}

// GostDriver implements engine.Driver for gost v3.
type GostDriver struct {
	runs *instTable[gostInstState]
}

func NewGostDriver() *GostDriver {
	return &GostDriver{runs: newInstTable[gostInstState]()}
}

func (d *GostDriver) ID() string { return gostID }

func (d *GostDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: gostID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","carrier_addr":"0.0.0.0:23344","public_port":0,"local_addr":"127.0.0.1:5201","transport":"ws"}`)}
}

func (d *GostDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *GostDriver) Validate(params json.RawMessage) error {
	var p gostParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("gost: engine_params: %w", err)
	}
	return gostValidateParams(p)
}

func gostEngineDir() string {
	return engineEngineDir(gostID)
}

// gostEnsureBinary: manifest-first (engine "gost"), pinned fallback.
func gostEnsureBinary(ctx context.Context, p gostParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("gost: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.gostArtifactPin(); pinErr == nil && engineCacheHit(gostBinDir(p.Version), pinnedSHA, []string{"gost"}) {
		return gostBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("gost: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, gostID,
		func() (string, string, string, error) { return p.gostArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := gostBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"gost"}) {
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
		return "", fmt.Errorf("gost: cache dir: %w", err)
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"gost": true}); err != nil {
		return "", err
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("gost: cache marker: %w", err)
	}
	return dir, nil
}

func gostBinDir(version string) string {
	return filepath.Join(gostEngineDir(), "bin", version)
}

// gostSpawn runs gost with its typed args (the config is the ARG LIST —
// no shell, no free-form file).
var gostSpawn = func(binPath string, args []string) (frpProcess, error) {
	cmd := exec.Command(binPath, args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("gost: start: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

// gostArgs renders the end's strictly-typed CLI (see the header for the
// verified upstream forms).
func gostArgs(role, transport string, p gostParams) []string {
	if role == "server" {
		return []string{"-L", fmt.Sprintf("relay+%s://:%d?bind=true",
			transport, enginePortOf(p.CarrierAddr))}
	}
	return []string{
		"-L", fmt.Sprintf("rtcp://:%d/%s", p.PublicPort, strings.TrimSpace(p.LocalAddr)),
		"-F", fmt.Sprintf("relay+%s://%s", transport, strings.TrimSpace(p.CarrierAddr)),
	}
}

// Start implements engine.Driver.
func (d *GostDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p gostParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("gost: engine_params: %w", err)
	}
	if err := gostValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("gost: invalid tunnel id %q", inst.TunnelID)
	}
	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual[gostParams](prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}

	role, err := gostResolveRole(p)
	if err != nil {
		return err
	}
	binDir, err := gostEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "gost")
	proc, err := gostSpawn(binPath, gostArgs(role, strings.ToLower(strings.TrimSpace(p.Transport)), p))
	if err != nil {
		return err
	}
	st := &gostInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		binPath: binPath}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, st.binPath, "", func(b, _ string) (frpProcess, error) {
		return gostSpawn(b, gostArgs(st.role, strings.ToLower(strings.TrimSpace(st.params.Transport)), st.params))
	})
	if role == "server" {
		if port := enginePortOf(p.CarrierAddr); port > 0 {
			if err := acctWireRulesAdd(acctChainsDriver, inst.TunnelID, port, port); err != nil {
				fmt.Fprintf(os.Stderr, "gost: wire accounting unavailable: %v\n", err)
			}
		}
	}
	return nil
}

// supervise was the local copy of the capped-backoff supervisor; A1
// deleted it — Start calls the shared engineSupervise directly (same
// 2s→15s backoff, same re-rendered args on respawn, Stop closes the
// stop channel first).

// Stop implements engine.Driver: the shared teardown order (cfg stays
// empty for the args-form driver — nothing to remove), with the server
// end's carrier-port accounting rule as the driver-specific hook.
func (d *GostDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.role == "server" {
			if port := enginePortOf(st.params.CarrierAddr); port > 0 {
				_ = acctWireRulesDel(acctChainsDriver, inst.TunnelID, port, port)
			}
		}
	})
	return nil
}

// gostHealthDial seams the public-port health dial (the integration test
// routes it through the server namespace).
var gostHealthDial = func(port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

// Health implements engine.Driver: process alive; on the SERVER end the
// rtcp listener binds the public port only while the client's relay
// connection is live — the dial is the end-to-end signal (warmup gate,
// item 11), retried 0/300/800ms.
func (d *GostDriver) Health(inst engine.Instance) engine.Health {
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
	if st.role != "server" {
		return engine.Health{OK: true, Detail: "gost client running", LatencyMs: -1}
	}
	start := time.Now()
	delays := []time.Duration{0, 300 * time.Millisecond, 800 * time.Millisecond}
	var lastErr error
	for _, dl := range delays {
		if dl > 0 {
			time.Sleep(dl)
		}
		if err := gostHealthDial(st.params.PublicPort); err == nil {
			return engine.Health{OK: true, Detail: "gost tunnel registered (public port answering)",
				LatencyMs: float64(time.Since(start).Milliseconds())}
		} else {
			lastErr = err
		}
	}
	return engine.Health{OK: false, Detail: "public port not answering (client not registered): " + lastErr.Error(),
		LatencyMs: float64(time.Since(start).Milliseconds())}
}

// Counters: the SERVER end's wire view (iptables on the carrier port);
// payload stays Unknown (no per-instance machine-readable stats in the
// OSS v3 binary).
func (d *GostDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil || st.role != "server" {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if port := enginePortOf(st.params.CarrierAddr); port > 0 {
		if rx, tx, ok := acctWireBytes(inst.TunnelID, port, port); ok {
			out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
		}
	}
	return out
}

// Uninstall implements engine.Driver.
func (d *GostDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, gostEngineDir())
	return nil
}

// Reload implements engine.Driver: equal params are a no-op, anything
// else is a restart (gost has no live reload).
func (d *GostDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, gostID, inst.TunnelID, inst.Params,
		func(st *gostInstState) gostParams { return st.params }, engineParamsEqual[gostParams])
}
