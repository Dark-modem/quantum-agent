package agent

// naive_driver.go — the NaiveProxy CLIENT driver (CORES-6 core
// naive-v154.0.8037.49-5, BSD — binaries-only external core): the HTTP/2
// CONNECT forward proxy riding Chromium's net stack. OVERNIGHT-A9 (the
// BackPack managed shape — the D2 wiring spec's client half).
//
// Shape: the naive CLIENT listens SOCKS locally and h2-CONNECTs to the
// remote naive SERVER over TLS. The server half in Quantum = the sing-box
// driver's naive INBOUND (exposed since A3 — protocol/naive/inbound.go,
// registered unconditionally in v1.14.4; email/pass users) — the two
// engines COMPOSE: sing-box (the foreign naive inbound) + naive (the iran
// naive client). This driver is CLIENT-ONLY by upstream design (the
// naiveproxy server mode is the Caddy forwardproxy fork, not this binary).
//
// Config: the USAGE.txt contract — config.json {"listen": "...",
// "proxy": "..."} rendered as JSON (charset-validated values; the proxy URL
// carries the credentials in its userinfo), exec `naive <config.json>`
// (argv-only). The listen form: socks://0.0.0.0:<port> (the local SOCKS
// entry); the proxy form: https://<user>:<pass>@<host>:<port> (TLS to a
// valid-cert server — self-signed pairs need the cert in the system store;
// honest note in Validate).
//
// Version: `naive --version` (the USAGE contract; prints the build id).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-agent/internal/infra"
)

const naiveID = "naive"

type naiveParams struct {
	Version   string `json:"version"`      // artifact version (cache key)
	Artifact  string `json:"artifact"`     // name template with {arch}
	SHA256Amd string `json:"sha256_amd64"` // pinned fallback
	SHA256Arm string `json:"sha256_arm64"`
	SigAmd    string `json:"signature_amd64"`
	SigArm    string `json:"signature_arm64"`
	// the local SOCKS entry (the iran end listens; the traffic h2-CONNECTs
	// out to the remote naive server).
	ListenPort int `json:"listen_port"`
	// the remote naive server (the sing-box naive inbound on the foreign
	// end): the URL components rendered as https://user:pass@host:port.
	RemoteHost string `json:"remote_host"`
	RemotePort int    `json:"remote_port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	// the h2 connection multiplexing (BackPack's measured fix: 1-16 — the
	// naiveproxy config "concurrency" key).
	Concurrency int    `json:"concurrency,omitempty"`
	// the end hosting the naive SERVER half (the sing-box naive inbound —
	// a different engine). The naive driver runs CLIENT-ONLY on the
	// non-server end.
	ServerSide  string `json:"server_side,omitempty"`
}

func (p naiveParams) naiveArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	return enginePinForArch(EnginePin{Version: p.Version, Artifact: p.Artifact,
		SHA256Amd: p.SHA256Amd, SHA256Arm: p.SHA256Arm, SigAmd: p.SigAmd, SigArm: p.SigArm})
}

func naiveValidateParams(p naiveParams) error {
	if err := backhaulValidateArtifactPins2(p.Version, p.Artifact, p.SHA256Amd, p.SigAmd,
		p.SHA256Arm, p.SigArm, naiveID); err != nil {
		return err
	}
	if p.ListenPort <= 0 || p.ListenPort > 65535 {
		return fmt.Errorf("naive: listen_port out of range")
	}
	if strings.TrimSpace(p.RemoteHost) == "" || len(p.RemoteHost) > 253 ||
		strings.ContainsAny(p.RemoteHost, "\"'\n\r\\ :") {
		return fmt.Errorf("naive: remote_host must be a bare host/IP without port or metacharacters")
	}
	if p.RemotePort <= 0 || p.RemotePort > 65535 {
		return fmt.Errorf("naive: remote_port out of range")
	}
	// the credentials ride the proxy URL's userinfo — RFC-safe charsets.
	if err := engineVerifySecretShape("naive username", p.Username, 1, 64); err != nil {
		return err
	}
	if err := engineVerifySecretShape("naive password", p.Password, 8, 128); err != nil {
		return err
	}
	if strings.ContainsAny(p.Username, "@:/") || strings.ContainsAny(p.Password, "@:/") {
		return fmt.Errorf("naive: username/password must not contain @ : / (the proxy URL's userinfo delimiters)")
	}
	// BackPack's measured fix: 1-16 h2 connections (their 20x number).
	if p.Concurrency != 0 && (p.Concurrency < 1 || p.Concurrency > 16) {
		return fmt.Errorf("naive: concurrency out of range (0 = unset, 1-16 — the BackPack measured band)")
	}
	return nil
}

func naiveResolveRole(p naiveParams) (string, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("naive: no controller identity — cannot resolve this end's role (fail closed)")
	}
	// the naive CLIENT runs on the NON-server end (the iran end dials OUT
	// to the foreign naive server). The foreign end runs the sing-box
	// naive inbound (a different engine) — the naive driver on the server
	// end is a no-op with the honest detail.
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return "server", nil
	}
	return "client", nil
}

// naiveRenderConfig builds the config.json (the USAGE.txt contract:
// {"listen": "...", "proxy": "..."} — charset-validated values, json.Marshal
// handles quoting).
func naiveRenderConfig(p naiveParams) []byte {
	listen := fmt.Sprintf("socks://0.0.0.0:%d", p.ListenPort)
	proxy := fmt.Sprintf("https://%s:%s@%s:%d", p.Username, p.Password,
		p.RemoteHost, p.RemotePort)
	obj := map[string]any{"listen": listen, "proxy": proxy}
	if p.Concurrency > 0 {
		obj["concurrency"] = p.Concurrency
	}
	out, _ := json.MarshalIndent(obj, "", " ")
	return out
}

type naiveInstState struct {
	engineInst
	params naiveParams
	role   string
}

// NaiveDriver implements engine.Driver for the vendored NaiveProxy client.
type NaiveDriver struct {
	runs *instTable[naiveInstState]
}

func NewNaiveDriver() *NaiveDriver {
	return &NaiveDriver{runs: newInstTable[naiveInstState]()}
}

func (d *NaiveDriver) ID() string { return naiveID }

func (d *NaiveDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: naiveID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"version":"","artifact":"..{arch}..","listen_port":0,"remote_host":"","remote_port":0,"username":"","password":"","concurrency":0} — CLIENT-ONLY (the naiveproxy server mode is the Caddy forwardproxy fork, not this binary); the server half = engine:singbox protocol=naive inbound (the engines compose)}`)}
}

func (d *NaiveDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *NaiveDriver) Validate(params json.RawMessage) error {
	var p naiveParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("naive: engine_params: %w", err)
	}
	return naiveValidateParams(p)
}

func naiveEngineDir() string { return engineEngineDir(naiveID) }

func naiveBinDir(version string) string {
	return filepath.Join(naiveEngineDir(), "bin", version)
}

// naiveEnsureBinary: manifest-first (engine "naive"), pinned fallback.
func naiveEnsureBinary(ctx context.Context, p naiveParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("naive: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.naiveArtifactPin(); pinErr == nil &&
		engineCacheHit(naiveBinDir(p.Version), pinnedSHA, []string{"naive"}) {
		return naiveBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("naive: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, naiveID,
		func() (string, string, string, error) { return p.naiveArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := naiveBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"naive"}) {
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
		return "", fmt.Errorf("naive: cache dir: %w", err)
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"naive": true}); err != nil {
		return "", fmt.Errorf("naive: %w", err)
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("naive: cache marker: %w", err)
	}
	return dir, nil
}

// naiveSpawn runs `naive <config.json>` (the USAGE.txt CLI; argv-only).
var naiveSpawn = func(binPath, cfgPath string) (frpProcess, error) {
	cmd := exec.Command(binPath, cfgPath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("naive: start: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

func (d *NaiveDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p naiveParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("naive: engine_params: %w", err)
	}
	if err := naiveValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("naive: invalid tunnel id %q", inst.TunnelID)
	}
	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual[naiveParams](prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}
	role, err := naiveResolveRole(p)
	if err != nil {
		return err
	}
	// CLIENT-ONLY by upstream design: on the server end (the foreign side)
	// the naive driver is a no-op with the honest detail — the naive
	// server half is the sing-box naive inbound (a different engine).
	if role == "server" {
		return fmt.Errorf("naive: the naiveproxy binary is CLIENT-ONLY (the server mode is the Caddy forwardproxy fork, not this binary) — host the server half with engine:singbox protocol=naive (the naive inbound, exposed since A3) and place the naive driver on the dialing end")
	}
	binDir, err := naiveEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "naive")
	cfgPath := filepath.Join(naiveEngineDir(), "instances", inst.TunnelID+".json")
	cfg := naiveRenderConfig(p)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("naive: config dir: %w", err)
	}
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		return fmt.Errorf("naive: write config: %w", err)
	}
	proc, err := naiveSpawn(binPath, cfgPath)
	if err != nil {
		_ = os.Remove(cfgPath)
		return err
	}
	st := &naiveInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		cfg: cfgPath, binPath: binPath}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, st.binPath, st.cfg, naiveSpawn)
	// the local SOCKS entry dial gate (tcp) — the accounting rides it.
	if err := acctWireRulesAddProto(acctChainsDriver, inst.TunnelID, p.ListenPort, p.ListenPort, "tcp"); err != nil {
		fmt.Fprintf(os.Stderr, "naive: wire accounting unavailable: %v\n", err)
	}
	return nil
}

func (d *NaiveDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		_ = acctWireRulesDelProto(acctChainsDriver, inst.TunnelID, st.params.ListenPort, st.params.ListenPort, "tcp")
		if st.cfg != "" {
			_ = os.Remove(st.cfg)
		}
	})
	return nil
}

func (d *NaiveDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, naiveID, inst.TunnelID, inst.Params,
		func(st *naiveInstState) naiveParams { return st.params }, engineParamsEqual[naiveParams])
}

// Health: process-alive + the local SOCKS entry dial (the naive client is
// up when the listen port answers).
func (d *NaiveDriver) Health(inst engine.Instance) engine.Health {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Health{OK: false, Detail: "not running", LatencyMs: -1}
	}
	select {
	case <-st.current().Done():
		return engine.Health{OK: false, Detail: "process exited", LatencyMs: -1}
	default:
	}
	start := time.Now()
	if err := gostHealthDial(st.params.ListenPort); err == nil {
		return engine.Health{OK: true, Detail: "naive client running (socks entry answering)",
			LatencyMs: float64(time.Since(start).Milliseconds())}
	}
	return engine.Health{OK: false, Detail: "socks entry not answering", LatencyMs: -1}
}

// Counters: the local entry dial-side iptables (tcp on the listen port).
func (d *NaiveDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if port := st.params.ListenPort; port > 0 {
		if rx, tx, ok := acctWireBytes(inst.TunnelID, port, port); ok {
			out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
		}
	}
	return out
}

func (d *NaiveDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, naiveEngineDir())
	return nil
}

// naiveVersionProbe: `naive --version` (the USAGE contract).
var naiveVersionProbe = func(binPath string) (string, error) {
	out, err := infra.RunCmdTimeout(10*time.Second, binPath, "--version")
	if err != nil {
		return "", err
	}
	f := strings.Fields(strings.TrimSpace(string(out)))
	if len(f) >= 2 {
		return strings.TrimLeft(f[len(f)-1], "v"), nil
	}
	return "", fmt.Errorf("naive: unexpected version output")
}

func naiveInstalledVersion() string {
	base := filepath.Join(naiveEngineDir(), "bin")
	entries, err := os.ReadDir(base)
	if err != nil {
		return naivePinnedVersion
	}
	best := ""
	for _, e := range entries {
		if !e.IsDir() || !infra.FileExists(filepath.Join(base, e.Name(), "naive")) {
			continue
		}
		if ctVersionLess(best, e.Name()) {
			best = e.Name()
		}
	}
	if best == "" {
		return naivePinnedVersion
	}
	if v, err := naiveVersionProbe(filepath.Join(base, best, "naive")); err == nil && v != "" {
		return v
	}
	return best
}

const naivePinnedVersion = "154.0.8037.49-5"
