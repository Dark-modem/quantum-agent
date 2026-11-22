package agent

// rathole_driver.go — the rathole engine (rapiz1/rathole, Apache-2.0
// verified from the upstream LICENSE at the pinned tag v0.5.0) wrapped as
// an engine.Driver per 00-ADMIN/ENGINE-GUIDE.md's production checklist.
// Exec-a-binary: the Apache license rides the artifact (packaged by
// quantum-release), no code linkage.
//
// Tunnel shape (one instance per end, reverse topology — the CLIENT dials
// OUT, the direction that survives Iran NAT/filtering):
//
//	server (foreign): [server] bind_addr (carrier) + [server.services.<svc>]
//	                  token + bind_addr (the PUBLIC data port) + the noise
//	                  transport with its private key.
//	client (Iran):    [client] remote_addr (dial the carrier) +
//	                  [client.services.<svc>] token + local_addr (the
//	                  Iran-local target) + noise remote_public_key.
//
// Health signal WITHOUT any upstream API: rathole's server binds the
// service port only once the client with the matching token has
// registered — a successful TCP dial to the service port on the server
// end proves the tunnel is registered end to end.
//
// Counters: wire = iptables accounting on the carrier port (all of a
// tunnel's data multiplexes over it); payload stays Unknown (v0.5.0
// exposes no machine-readable stats — verified from the upstream
// releases, none of v0.5.0's notes mention an API).

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

	"github.com/Dark-modem/quantum-agent/internal/infra"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const ratholeID = "rathole"

type ratholeParams struct {
	ServerSide  string `json:"server_side"`  // the end hosting the rathole SERVER (foreign)
	Version     string `json:"version"`      // artifact version (cache key)
	Artifact    string `json:"artifact"`     // name template with {arch}
	SHA256Amd   string `json:"sha256_amd64"` // pinned fallback
	SHA256Arm   string `json:"sha256_arm64"`
	SigAmd      string `json:"signature_amd64"`
	SigArm      string `json:"signature_arm64"`
	ServerAddr  string `json:"server_addr"`  // carrier "host:port" (server bind / client dial)
	ServiceAddr string `json:"service_addr"` // server-side PUBLIC data bind "0.0.0.0:port"
	LocalAddr   string `json:"local_addr"`   // client-side target "127.0.0.1:port"
	Token       string `json:"token"`        // per-tunnel shared token
	// NoiseServerPublic is the SERVER's noise X25519 public key (base64,
	// 44 chars): generated on the server agent, acked, pushed back to the
	// client in a later desired revision (same dance as WG peer_public).
	// The private key NEVER leaves the server agent.
	NoiseServerPublic string `json:"noise_server_public,omitempty"`
	// Transport picks the carrier (OVERNIGHT-A gap-close): upstream
	// src/config.rs TransportType = tcp|tls|noise|websocket. "" and
	// "noise" keep the historical encrypted shape (backward compatible);
	// "tcp" is the plain carrier; "websocket" is plain ws (upstream
	// websocket.tls=false — no operator certs). "tls" needs operator
	// cert/key files on both ends — rejected fail-closed (next wave).
	Transport string `json:"transport,omitempty"`
	// ServiceType picks the per-service forwarding protocol: upstream
	// ServiceType = tcp|udp. "" = tcp (historical shape). udp renders
	// `type = "udp"` into BOTH ends' service blocks.
	ServiceType string `json:"service_type,omitempty"`
	// PreferIPv6 renders upstream's per-service prefer_ipv6 (client side).
	PreferIPv6 bool `json:"prefer_ipv6,omitempty"`
	// OVERNIGHT-A2: the tls carrier rides upstream's PKCS12 store
	// (src/config.rs TlsConfig: pkcs12 + pkcs12_password are BOTH
	// required — Option::and). The path lands in TOML (charset-checked);
	// the password is a secret like any token field.
	PKCS12Path     string `json:"pkcs12_path,omitempty"`
	PKCS12Password string `json:"pkcs12_password,omitempty"`
}

// ratholeAllowedTransports mirrors upstream TransportType (config.rs).
// tls is deliberately absent: it requires cert/key files the panel does
// not deliver yet — fail closed with a clear message instead of an
// upstream startup error.
// "tls" became reachable in OVERNIGHT-A2 — but ONLY with the operator's
// PKCS12 pair (pkcs12_path + pkcs12_password); validate enforces that
// pair, so a bare tls still fails closed with a clear message instead
// of an upstream startup error.
var ratholeAllowedTransports = map[string]bool{
	"": true, "noise": true, "tcp": true, "websocket": true, "tls": true,
}

// ratholeServiceTypes mirrors upstream ServiceType (config.rs).
var ratholeServiceTypes = map[string]bool{
	"": true, "tcp": true, "udp": true,
}

func (p ratholeParams) ratholeArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	arch := strings.ToLower(runtime.GOARCH)
	if !strings.Contains(p.Artifact, "{arch}") {
		return "", "", "", fmt.Errorf("rathole: artifact template must contain {arch}")
	}
	name = strings.ReplaceAll(p.Artifact, "{arch}", arch)
	switch arch {
	case "amd64":
		return name, p.SHA256Amd, p.SigAmd, nil
	case "arm64":
		return name, p.SHA256Arm, p.SigArm, nil
	}
	return "", "", "", fmt.Errorf("rathole: no artifact pin for GOARCH %q", arch)
}

// ratholeValidateParams: strict union shape, every TOML-bound string
// checked for quote/newline injection.
func ratholeValidateParams(p ratholeParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("rathole: server_side required")
	}
	if err := backhaulValidateArtifactPins2(p.Version, p.Artifact, p.SHA256Amd, p.SigAmd, p.SHA256Arm, p.SigArm, "rathole"); err != nil {
		return err
	}
	for _, a := range []struct{ label, v string }{
		{"server_addr", p.ServerAddr}, {"service_addr", p.ServiceAddr}, {"local_addr", p.LocalAddr},
	} {
		if strings.TrimSpace(a.v) == "" || len(a.v) > 128 || strings.ContainsAny(a.v, "\"'\n\r") {
			return fmt.Errorf("rathole: %s must be 1-128 TOML-safe chars", a.label)
		}
	}
	if _, _, err := net.SplitHostPort(p.ServerAddr); err != nil {
		return fmt.Errorf("rathole: server_addr must be host:port")
	}
	if _, _, err := net.SplitHostPort(p.ServiceAddr); err != nil {
		return fmt.Errorf("rathole: service_addr must be host:port")
	}
	if _, _, err := net.SplitHostPort(p.LocalAddr); err != nil {
		return fmt.Errorf("rathole: local_addr must be host:port")
	}
	if len(p.Token) < 8 || len(p.Token) > 256 || strings.ContainsAny(p.Token, "\"'\n\r") {
		return fmt.Errorf("rathole: token must be 8-256 chars without quotes/newlines")
	}
	if p.NoiseServerPublic != "" {
		if len(p.NoiseServerPublic) != 44 || !strings.HasSuffix(p.NoiseServerPublic, "=") {
			return fmt.Errorf("rathole: noise_server_public must be a 44-char base64 key")
		}
		if strings.ContainsAny(p.NoiseServerPublic, "\"'\n\r\\") {
			return fmt.Errorf("rathole: noise_server_public not TOML-safe")
		}
	}
	transport := strings.ToLower(strings.TrimSpace(p.Transport))
	if !ratholeAllowedTransports[transport] {
		return fmt.Errorf("rathole: transport %q not supported (noise|tcp|websocket|tls)", p.Transport)
	}
	if transport == "tls" {
		// upstream TlsConfig: pkcs12 AND pkcs12_password are both
		// required (config.rs Option::and — one without the other is an
		// upstream startup error; fail closed here instead).
		if strings.TrimSpace(p.PKCS12Path) == "" || strings.TrimSpace(p.PKCS12Password) == "" {
			return fmt.Errorf("rathole: transport tls needs pkcs12_path and pkcs12_password (upstream rides a PKCS12 store on BOTH ends)")
		}
	}
	if p.PKCS12Path != "" && (len(p.PKCS12Path) > 256 || strings.ContainsAny(p.PKCS12Path, "\"'\n\r")) {
		return fmt.Errorf("rathole: pkcs12_path must be a ≤256-char TOML-safe path")
	}
	if p.PKCS12Password != "" && (len(p.PKCS12Password) > 256 || strings.ContainsAny(p.PKCS12Password, "\"'\n\r")) {
		return fmt.Errorf("rathole: pkcs12_password must be ≤256 TOML-safe chars")
	}
	// The noise key dance is noise-only ("" IS noise — the historical
	// default): a noise_server_public on a non-noise carrier would never
	// be read upstream — reject it rather than silently carry a dead
	// secret.
	if transport != "" && transport != "noise" && p.NoiseServerPublic != "" {
		return fmt.Errorf("rathole: noise_server_public is only valid with transport=noise (got %q)", p.Transport)
	}
	if !ratholeServiceTypes[strings.ToLower(strings.TrimSpace(p.ServiceType))] {
		return fmt.Errorf("rathole: service_type %q not supported (tcp|udp)", p.ServiceType)
	}
	return nil
}

// backhaulValidateArtifactPins2 is the arch-pins check parameterized (the
// backhaul original is bound to its params struct).
func backhaulValidateArtifactPins2(version, artifact, shaA, sigA, shaB, sigB, engine string) error {
	if strings.TrimSpace(version) == "" || len(version) > 64 ||
		strings.ContainsAny(version, "/\\\"' \t\n\r") {
		return fmt.Errorf("%s: version must be 1-64 safe chars", engine)
	}
	if !strings.Contains(artifact, "{arch}") || strings.ContainsAny(artifact, " \t\n\r\"\\") {
		return fmt.Errorf("%s: artifact must be a name template containing {arch}", engine)
	}
	for _, a := range []struct {
		arch, sha, sig string
	}{
		{"amd64", shaA, sigA},
		{"arm64", shaB, sigB},
	} {
		if len(a.sha) != 64 || strings.ContainsAny(a.sha, " \t\n\r") {
			return fmt.Errorf("%s: %s sha256 pin must be 64 hex chars", engine, a.arch)
		}
		if len(a.sig) < 64 || len(a.sig) > 512 || strings.ContainsAny(a.sig, " \t\n\r") {
			return fmt.Errorf("%s: %s signature pin must be base64 (64-512 chars)", engine, a.arch)
		}
	}
	return nil
}

func ratholeResolveRole(p ratholeParams) (string, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("rathole: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return "server", nil
	}
	return "client", nil
}

// ratholeInstState is one RUNNING instance's state. The proc/stop/cfg/
// binPath base rides the shared engineInst (A1).
type ratholeInstState struct {
	engineInst
	params ratholeParams
	role   string
	iface  string // TOML service name (shared by both ends)
}

// RatholeDriver implements engine.Driver for rathole.
type RatholeDriver struct {
	runs *instTable[ratholeInstState]
}

func NewRatholeDriver() *RatholeDriver {
	return &RatholeDriver{runs: newInstTable[ratholeInstState]()}
}

func (d *RatholeDriver) ID() string { return ratholeID }

func (d *RatholeDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: ratholeID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","server_addr":"0.0.0.0:2333","service_addr":"0.0.0.0:5202","local_addr":"127.0.0.1:5201","token":"","noise_server_public":"","transport":"noise|tcp|websocket|tls","service_type":"tcp|udp","prefer_ipv6":false,"pkcs12_path":"","pkcs12_password":""}`)}
}

func (d *RatholeDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *RatholeDriver) Validate(params json.RawMessage) error {
	var p ratholeParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("rathole: engine_params: %w", err)
	}
	return ratholeValidateParams(p)
}

func ratholeEngineDir() string {
	return filepath.Join(infra.ConfigDir, "engines", ratholeID)
}

func ratholeConfigPath(tunnelID string) string {
	return filepath.Join(ratholeEngineDir(), "instances", tunnelID+".toml")
}

func ratholeBinDir(version string) string {
	return filepath.Join(ratholeEngineDir(), "bin", version)
}

// ratholeServiceName derives the TOML service name from the tunnel id:
// shared by both ends (the token+name pair binds them), TOML-safe
// (frpTunnelIDOK ids are [a-z0-9-]).
func ratholeServiceName(tunnelID string) string {
	return "q" + tunnelID
}

// ratholeRenderConfig renders the end's TOML. OVERNIGHT-A: the transport
// block follows the chosen carrier — noise keeps the historical NK blocks;
// tcp is upstream's default (no block at all); websocket renders the plain
// ws pair (tls=false, no operator certs). The per-service type follows
// service_type (tcp default / udp), and prefer_ipv6 rides the client
// service block. The server holds the noise PRIVATE key (generated on that
// agent, 0600 state) only on the noise carrier; the client is pushed the
// server's PUBLIC key via the desired revision.
func ratholeRenderConfig(role, svc string, p ratholeParams, noisePrivB64 string) string {
	var b strings.Builder
	transport := strings.ToLower(strings.TrimSpace(p.Transport))
	svcType := strings.ToLower(strings.TrimSpace(p.ServiceType))
	if role == "server" {
		b.WriteString("[server]\n")
		fmt.Fprintf(&b, "bind_addr = %q\n", p.ServerAddr)
		b.WriteString("heartbeat_interval = 30\n")
		switch transport {
		case "", "noise":
			b.WriteString("[server.transport]\ntype = \"noise\"\n")
			fmt.Fprintf(&b, "[server.transport.noise]\nlocal_private_key = %q\n", noisePrivB64)
		case "websocket":
			b.WriteString("[server.transport]\ntype = \"websocket\"\n")
			b.WriteString("[server.transport.websocket]\ntls = false\n")
		case "tls":
			b.WriteString("[server.transport]\ntype = \"tls\"\n")
			fmt.Fprintf(&b, "[server.transport.tls]\npkcs12 = %q\npkcs12_password = %q\n", p.PKCS12Path, p.PKCS12Password)
		case "tcp":
			// upstream default — no transport block
		}
		fmt.Fprintf(&b, "\n[server.services.%s]\n", svc)
		if svcType == "udp" {
			b.WriteString("type = \"udp\"\n")
		}
		fmt.Fprintf(&b, "token = %q\nbind_addr = %q\n", p.Token, p.ServiceAddr)
		return b.String()
	}
	b.WriteString("[client]\n")
	fmt.Fprintf(&b, "remote_addr = %q\n", p.ServerAddr)
	b.WriteString("heartbeat_timeout = 40\nretry_interval = 3\n")
	switch transport {
	case "", "noise":
		b.WriteString("[client.transport]\ntype = \"noise\"\n")
		fmt.Fprintf(&b, "[client.transport.noise]\nremote_public_key = %q\n", p.NoiseServerPublic)
	case "websocket":
		b.WriteString("[client.transport]\ntype = \"websocket\"\n")
		b.WriteString("[client.transport.websocket]\ntls = false\n")
	case "tls":
		b.WriteString("[client.transport]\ntype = \"tls\"\n")
		fmt.Fprintf(&b, "[client.transport.tls]\npkcs12 = %q\npkcs12_password = %q\n", p.PKCS12Path, p.PKCS12Password)
	case "tcp":
		// upstream default — no transport block
	}
	fmt.Fprintf(&b, "\n[client.services.%s]\n", svc)
	if svcType == "udp" {
		b.WriteString("type = \"udp\"\n")
	}
	if p.PreferIPv6 {
		b.WriteString("prefer_ipv6 = true\n")
	}
	fmt.Fprintf(&b, "token = %q\nlocal_addr = %q\n", p.Token, p.LocalAddr)
	return b.String()
}

// ratholeEnsureBinary: manifest-first (engine "rathole"), pinned
// fallback; identical trust model to the FRP/Backhaul drivers.
func ratholeEnsureBinary(ctx context.Context, p ratholeParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("rathole: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.ratholeArtifactPin(); pinErr == nil && engineCacheHit(ratholeBinDir(p.Version), pinnedSHA, []string{"rathole"}) {
		return ratholeBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("rathole: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, ratholeID,
		func() (string, string, string, error) { return p.ratholeArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := ratholeBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"rathole"}) {
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
		return "", fmt.Errorf("rathole: cache dir: %w", err)
	}
	if err := ratholeExtract(body, dir); err != nil {
		return "", err
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("rathole: cache marker: %w", err)
	}
	return dir, nil
}

// ratholeCacheHit was the local cache-marker check; A1 replaced it with
// the identical engineCacheHit (want = the single rathole binary).

// ratholeExtract unpacks the release tar.gz (the packer repackages the
// upstream zip into this shape, LICENSE+SOURCE inside): only the regular
// `rathole` binary installs (0755); directory entries skipped, anything
// else refused. A1: the local tar-copy is deleted — delegates to the
// shared engineExtractTarball with the driver error prefix kept (the one
// textual delta: the missing-binary error now reads
// `rathole: engine: artifact missing "rathole"` instead of
// `rathole: artifact missing the rathole binary`; no caller or test
// matches that string).
func ratholeExtract(body []byte, dir string) error {
	if err := engineExtractTarball(body, dir, map[string]bool{"rathole": true}); err != nil {
		return fmt.Errorf("rathole: %w", err)
	}
	return nil
}

// ratholeSpawn runs the rathole binary with the config as a POSITIONAL
// argument: rathole's `-c` means forced-client mode (the server config in
// forced-client mode panics "Try to run as a client"), and the role is
// auto-detected from the config file anyway.
var ratholeSpawn = func(binPath, cfgPath string) (frpProcess, error) {
	cmd := exec.Command(binPath, cfgPath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("rathole: start %s: %w", binPath, err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

// ratholeNoiseKeypair: the server's noise X25519 keypair — the same
// 32-byte curve25519 keys WG uses; the private key stays on the server
// agent (0600 state), the public rides the ack.
func ratholeNoiseKeypair() (pubB64, privB64 string, err error) {
	pub, priv, err := wgX25519Keypair() // generic X25519; the wg* name is historical
	if err != nil {
		return "", "", err
	}
	return wgB64Encode(pub), wgB64Encode(priv), nil
}

// Start implements engine.Driver. The SERVER end generates the noise
// keypair (persisted 0600 per tunnel under infra.ConfigDir/wg — the same store
// the WG driver uses, keys are the same format); the CLIENT end requires
// noise_server_public in its params (fail closed: without it the noise
// handshake cannot authenticate).
func (d *RatholeDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p ratholeParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("rathole: engine_params: %w", err)
	}
	if err := ratholeValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("rathole: invalid tunnel id %q", inst.TunnelID)
	}

	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual[ratholeParams](prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}

	role, err := ratholeResolveRole(p)
	if err != nil {
		return err
	}
	transport := strings.ToLower(strings.TrimSpace(p.Transport))
	noiseMode := transport == "" || transport == "noise"
	var noisePrivB64 string
	if role == "server" && noiseMode {
		noisePrivB64, err = ratholeNoisePrivateKey(inst.TunnelID)
		if err != nil {
			return fmt.Errorf("rathole: noise key: %w", err)
		}
	} else if role == "client" && noiseMode {
		if strings.TrimSpace(p.NoiseServerPublic) == "" {
			return fmt.Errorf("rathole: client end needs noise_server_public (the server's acked key) — fail closed")
		}
	}
	binDir, err := ratholeEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "rathole")
	svc := ratholeServiceName(inst.TunnelID)
	cfg := ratholeRenderConfig(role, svc, p, noisePrivB64)
	cfgPath := ratholeConfigPath(inst.TunnelID)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("rathole: config dir: %w", err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("rathole: write config: %w", err)
	}
	proc, err := ratholeSpawn(binPath, cfgPath)
	if err != nil {
		_ = os.Remove(cfgPath)
		return err
	}
	st := &ratholeInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		cfg: cfgPath, binPath: binPath}, params: p, role: role, iface: svc}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, st.binPath, st.cfg, ratholeSpawn)
	// Wire accounting on the SERVER end: the carrier port multiplexes the
	// tunnel's control AND data bytes.
	if role == "server" {
		if port := enginePortOf(p.ServerAddr); port > 0 {
			if err := acctWireRulesAdd(acctChainsDriver, inst.TunnelID, port, port); err != nil {
				fmt.Fprintf(os.Stderr, "rathole: wire accounting unavailable: %v\n", err)
			}
		}
	}
	return nil
}

// ratholeNoisePrivateKey loads or generates the server's persisted noise
// private key (0600, same store/format family as the WG keys).
func ratholeNoisePrivateKey(tunnelID string) (string, error) {
	dir := filepath.Join(infra.ConfigDir, "wg")
	path := filepath.Join(dir, "rathole-"+tunnelID+".noise")
	if b, rerr := os.ReadFile(path); rerr == nil {
		var ks wgKeyState
		if json.Unmarshal(b, &ks) == nil && ks.PrivateKey != "" {
			return ks.PrivateKey, nil
		}
	}
	pubB64, privB64, err := ratholeNoiseKeypair()
	if err != nil {
		return "", err
	}
	if merr := os.MkdirAll(dir, 0o700); merr != nil {
		return "", merr
	}
	b, _ := json.Marshal(wgKeyState{PrivateKey: privB64, PublicKey: pubB64})
	if werr := os.WriteFile(path, b, 0o600); werr != nil {
		return "", werr
	}
	return privB64, nil
}

// supervise was the local copy of the capped-backoff supervisor; A1
// deleted it — Start calls the shared engineSupervise directly (same
// 2s→15s backoff, same respawn via ratholeSpawn(bin, cfg), Stop closes
// the stop channel before killing the process — no resurrection).

// Stop implements engine.Driver: the shared teardown order, with the
// server end's carrier-port accounting rule as the driver-specific hook.
func (d *RatholeDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.role == "server" {
			if port := enginePortOf(st.params.ServerAddr); port > 0 {
				_ = acctWireRulesDel(acctChainsDriver, inst.TunnelID, port, port)
			}
		}
	})
	return nil
}

// Reload implements engine.Driver: equal params are a no-op, anything
// else (including the noise_server_public revision) is a restart —
// rathole has no config reload; the persisted server noise key makes the
// restart key-stable.
func (d *RatholeDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, ratholeID, inst.TunnelID, inst.Params,
		func(st *ratholeInstState) ratholeParams { return st.params }, engineParamsEqual[ratholeParams])
}

// ratholeHealthDial seams the service-port health dial (the integration
// test routes it through the server namespace — the port is bound there,
// not in the test process's namespace).
var ratholeHealthDial = func(port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

// Health implements engine.Driver: the process alive, and on the server
// end a successful dial to the SERVICE port — rathole binds it only once
// the client with the matching token registered, so the dial is a real
// end-to-end signal (the warmup gate, checklist item 11), retried with
// backoff.
func (d *RatholeDriver) Health(inst engine.Instance) engine.Health {
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
		return engine.Health{OK: true, Detail: "rathole client running", LatencyMs: -1}
	}
	port := enginePortOf(st.params.ServiceAddr)
	if port <= 0 {
		return engine.Health{OK: true, Detail: "rathole server running (no service port)", LatencyMs: -1}
	}
	// UDP services bind a UDP socket — a TCP dial can never prove
	// registration there; the process-alive check above stays the honest
	// signal (OVERNIGHT-A service_type=udp gap-close).
	if strings.EqualFold(strings.TrimSpace(st.params.ServiceType), "udp") {
		return engine.Health{OK: true, Detail: "rathole server running (udp service; dial gate N/A)", LatencyMs: -1}
	}
	start := time.Now()
	delays := []time.Duration{0, 300 * time.Millisecond, 800 * time.Millisecond}
	var lastErr error
	for _, d := range delays {
		if d > 0 {
			time.Sleep(d)
		}
		if err := ratholeHealthDial(port); err == nil {
			return engine.Health{OK: true, Detail: "rathole tunnel registered (service port answering)",
				LatencyMs: float64(time.Since(start).Milliseconds())}
		} else {
			lastErr = err
		}
	}
	return engine.Health{OK: false, Detail: "service port not answering (client not registered): " + lastErr.Error(),
		LatencyMs: float64(time.Since(start).Milliseconds())}
}

// Counters: the SERVER end's wire view (iptables on the carrier port —
// the tunnel's control AND data bytes); payload stays Unknown (v0.5.0 has
// no machine-readable stats — verified from the upstream releases).
func (d *RatholeDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil || st.role != "server" {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if port := enginePortOf(st.params.ServerAddr); port > 0 {
		if rx, tx, ok := acctWireBytes(inst.TunnelID, port, port); ok {
			out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
		}
	}
	return out
}

// Uninstall implements engine.Driver: stop everything, remove the binary
// cache + config dir; idle engines leave zero processes and zero files.
func (d *RatholeDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, ratholeEngineDir())
	return nil
}
