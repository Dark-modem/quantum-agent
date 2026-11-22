package agent

// hysteria_driver.go — the hysteria (v2) engine driver over the VENDORED
// core (quantum-cores hysteria-v2.14.0, MIT — AGENT-31). Exec-a-binary:
// the driver renders the upstream YAML config through typed structs and
// runs `hysteria server|client -c <cfg>` (upstream cobra CLI verified:
// app/cmd/root.go persistent -c flag; server.go/client.go subcommands).
//
// Tunnel shape (AGENT-31 scope — what fits our desired-state model):
// the FOREIGN end runs the hysteria SERVER (QUIC carrier, TLS mandatory
// upstream); the IRAN end runs the CLIENT dialing OUT, offering:
//   - ingress proxies: socks5 (socks5.listen) and/or http (http.listen)
//     — the classic Iran proxy-exit shape;
//   - port forwarding: tcpForwarding/udpForwarding entries
//     (listen local_port → remote forward_addr dialed by the SERVER end
//     from ITS network — a directed Iran→foreign port-forward).
// TUN / tproxy / redirect modes are OUT of scope (node-level L3 shapes —
// see the AGENT-31 report; gost/frp/backhaul cover reverse-port-forward).
//
// The upstream shape every field below cites lives in app/cmd/server.go
// (serverConfig) and app/cmd/client.go (clientConfig): listen, auth
// {type,password}, obfs {type:salamander, salamander:{password}}, tls
// {cert,key} server-side / {sni,insecure,pinSHA256} client-side,
// bandwidth {up,down} (ConvBandwidth strings), socks5 {listen,username,
// password,disableUDP}, http {listen,...}, tcpForwarding/udpForwarding
// [{listen,remote}]. hysteria2 is QUIC — the carrier socket is UDP, so
// the server-end wire accounting rides the -p udp rules (acct.go
// proto-parameterized helpers, OVERNIGHT-A).

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-agent/internal/infra"
)

const hysteriaID = "hysteria"

// hysteriaVersionCmd is the version probe command (upstream cobra:
// `hysteria version`, root.go's versionCmd).
var hysteriaVersionCmd = []string{"version"}

type hysteriaParams struct {
	ServerSide string `json:"server_side"`  // the end hosting the hysteria SERVER (foreign)
	Version    string `json:"version"`      // artifact version (cache key)
	Artifact   string `json:"artifact"`     // name template with {arch}
	SHA256Amd  string `json:"sha256_amd64"` // pinned fallback
	SHA256Arm  string `json:"sha256_arm64"`
	SigAmd     string `json:"signature_amd64"`
	SigArm     string `json:"signature_arm64"`
	ServerAddr string `json:"server_addr"` // carrier "host:port" — server listen / client dial
	// AuthPassword is the shared hysteria2 password (server auth.password;
	// client auth). 8-128 CLI/TOML-safe chars.
	AuthPassword string `json:"auth_password"`
	// ObfsPassword enables the salamander obfuscation layer when set
	// (obfs.type=salamander, obfs.salamander.password). Optional.
	ObfsPassword string `json:"obfs_password,omitempty"`
	// TLS: hysteria2 is ALWAYS TLS — the server needs cert/key paths
	// (self-signed ok); the client verifies unless insecure/pinSHA256.
	TLSCert   string `json:"tls_cert,omitempty"`   // server certFile (PEM path)
	TLSKey    string `json:"tls_key,omitempty"`    // server keyFile (PEM path)
	SNI       string `json:"sni,omitempty"`        // client sni (default = server host)
	Insecure  bool   `json:"insecure,omitempty"`   // client tls.insecure (self-signed labs)
	PinSHA256 string `json:"pin_sha256,omitempty"` // client tls.pinSHA256 (hex, alternative to insecure)
	// Bandwidth (ConvBandwidth strings, e.g. "100 mbps"; empty = built-in
	// congestion control per upstream client.go fillBandwidthConfig).
	UpMbps   string `json:"up_mbps,omitempty"`
	DownMbps string `json:"down_mbps,omitempty"`
	// Ingress (client end): socks5 and/or http local proxies.
	SocksPort int `json:"socks_port,omitempty"` // 0 = off
	HTTPPort  int `json:"http_port,omitempty"`  // 0 = off
	// Forwarding (client end): directed port-forwards through the tunnel
	// (listen local → remote dialed by the server end). 1-16 entries.
	TCPForwards []hysteriaForward `json:"tcp_forwards,omitempty"`
	UDPForwards []hysteriaForward `json:"udp_forwards,omitempty"`
}

type hysteriaForward struct {
	Listen int    `json:"listen"` // local listen port (client end)
	Remote string `json:"remote"` // "host:port" dialed by the server end
}

// hysteriaArtifactPin mirrors backhaulArtifactPin (both arches ride the
// tunnel params; each end verifies its own artifact).
func (p hysteriaParams) hysteriaArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	return enginePinForArch(EnginePin{Version: p.Version, Artifact: p.Artifact,
		SHA256Amd: p.SHA256Amd, SHA256Arm: p.SHA256Arm, SigAmd: p.SigAmd, SigArm: p.SigArm})
}

// hysteriaValidateParams checks the union shape (no side effects). Every
// string that lands in the YAML is charset-checked; ports are bounded;
// the TLS pair is REQUIRED server-side (upstream is TLS-only).
func hysteriaValidateParams(p hysteriaParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("hysteria: server_side required")
	}
	if err := backhaulValidateArtifactPins2(p.Version, p.Artifact, p.SHA256Amd, p.SigAmd,
		p.SHA256Arm, p.SigArm, hysteriaID); err != nil {
		return err
	}
	if _, _, e := net.SplitHostPort(p.ServerAddr); e != nil {
		return fmt.Errorf("hysteria: server_addr must be host:port")
	}
	if err := engineVerifySecretShape("hysteria auth_password", p.AuthPassword, 8, 128); err != nil {
		return err
	}
	if p.ObfsPassword != "" {
		if err := engineVerifySecretShape("hysteria obfs_password", p.ObfsPassword, 4, 128); err != nil {
			return err
		}
	}
	// hysteria2 is TLS-only upstream: the server end cannot start without
	// a certificate. Fail closed here rather than shipping a config the
	// binary refuses.
	if strings.TrimSpace(p.TLSCert) == "" || strings.TrimSpace(p.TLSKey) == "" {
		return fmt.Errorf("hysteria: tls_cert and tls_key are required (hysteria2 is always TLS — self-signed pairs are fine with client insecure/pin_sha256)")
	}
	for _, a := range []struct{ label, v string }{{"tls_cert", p.TLSCert}, {"tls_key", p.TLSKey}} {
		if len(a.v) > 256 || strings.ContainsAny(a.v, "\"'`\n\r$;&|<>") {
			return fmt.Errorf("hysteria: %s must be a ≤256-char path without quotes/shell metacharacters", a.label)
		}
	}
	if p.SNI != "" && (len(p.SNI) > 253 || strings.ContainsAny(p.SNI, "\"'\n\r\\ ")) {
		return fmt.Errorf("hysteria: sni must be a hostname-shaped ≤253-char string")
	}
	if len(p.PinSHA256) > 64 || strings.ContainsAny(p.PinSHA256, "\"'\n\r ") {
		return fmt.Errorf("hysteria: pin_sha256 must be ≤64 chars without quotes/whitespace")
	}
	if err := hysteriaValidateBandwidth("up_mbps", p.UpMbps); err != nil {
		return err
	}
	if err := hysteriaValidateBandwidth("down_mbps", p.DownMbps); err != nil {
		return err
	}
	if p.SocksPort < 0 || p.SocksPort > 65535 || p.HTTPPort < 0 || p.HTTPPort > 65535 {
		return fmt.Errorf("hysteria: socks_port/http_port out of range")
	}
	if p.SocksPort == 0 && p.HTTPPort == 0 && len(p.TCPForwards) == 0 && len(p.UDPForwards) == 0 {
		return fmt.Errorf("hysteria: the client end needs an ingress (socks_port/http_port) or forwards (tcp_forwards/udp_forwards)")
	}
	if len(p.TCPForwards) > 16 || len(p.UDPForwards) > 16 {
		return fmt.Errorf("hysteria: at most 16 tcp/udp forwards per tunnel")
	}
	for _, fam := range []struct {
		label string
		list  []hysteriaForward
	}{{"tcp_forwards", p.TCPForwards}, {"udp_forwards", p.UDPForwards}} {
		for _, f := range fam.list {
			if f.Listen <= 0 || f.Listen > 65535 {
				return fmt.Errorf("hysteria: %s listen out of range", fam.label)
			}
			if strings.TrimSpace(f.Remote) == "" || len(f.Remote) > 128 ||
				strings.ContainsAny(f.Remote, "\"'\n\r") {
				return fmt.Errorf("hysteria: %s remote must be a 1-128 host:port string", fam.label)
			}
			if _, _, e := net.SplitHostPort(f.Remote); e != nil {
				return fmt.Errorf("hysteria: %s remote must be host:port", fam.label)
			}
		}
	}
	return nil
}

// hysteriaValidateBandwidth bounds the ConvBandwidth strings to the
// "N mbps" shape (upstream utils.ConvBandwidth accepts unit strings).
func hysteriaValidateBandwidth(label, v string) error {
	if v == "" {
		return nil
	}
	if len(v) > 16 || strings.ContainsAny(v, "\"'\n\r") {
		return fmt.Errorf("hysteria: %s must be a ≤16-char bandwidth string", label)
	}
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), "mbps")
	n = strings.TrimSpace(n)
	if n == "" {
		return fmt.Errorf("hysteria: %s needs a numeric mbps value (e.g. \"100 mbps\")", label)
	}
	for i := 0; i < len(n); i++ {
		if n[i] < '0' || n[i] > '9' {
			return fmt.Errorf("hysteria: %s must be numeric mbps (e.g. \"100 mbps\")", label)
		}
	}
	return nil
}

func hysteriaResolveRole(p hysteriaParams) (string, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("hysteria: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return "server", nil
	}
	return "client", nil
}

type hysteriaInstState struct {
	engineInst
	params hysteriaParams
	role   string
}

// HysteriaDriver implements engine.Driver for the vendored hysteria core.
type HysteriaDriver struct {
	runs *instTable[hysteriaInstState]
}

func NewHysteriaDriver() *HysteriaDriver {
	return &HysteriaDriver{runs: newInstTable[hysteriaInstState]()}
}

func (d *HysteriaDriver) ID() string { return hysteriaID }

func (d *HysteriaDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: hysteriaID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","server_addr":"0.0.0.0:36712","auth_password":"","obfs_password":"","tls_cert":"","tls_key":"","sni":"","insecure":false,"pin_sha256":"","up_mbps":"100 mbps","down_mbps":"","socks_port":0,"http_port":0,"tcp_forwards":[{"listen":0,"remote":"host:port"}],"udp_forwards":[{"listen":0,"remote":"host:port"}]}`)}
}

func (d *HysteriaDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *HysteriaDriver) Validate(params json.RawMessage) error {
	var p hysteriaParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("hysteria: engine_params: %w", err)
	}
	return hysteriaValidateParams(p)
}

func hysteriaEngineDir() string { return engineEngineDir(hysteriaID) }

func hysteriaBinDir(version string) string {
	return filepath.Join(hysteriaEngineDir(), "bin", version)
}

func hysteriaConfigPath(tunnelID string) string {
	return filepath.Join(hysteriaEngineDir(), "instances", tunnelID+".yaml")
}

// hysteriaRenderConfig renders the end's YAML (typed fields — no
// free-form interpolation beyond the charset-validated values; the YAML
// quoting uses %q which is safe for the validated charsets).
func hysteriaRenderConfig(role string, p hysteriaParams) string {
	var b strings.Builder
	if role == "server" {
		b.WriteString("listen: ")
		_, port, _ := net.SplitHostPort(p.ServerAddr)
		fmt.Fprintf(&b, "%q\n", ":"+port)
		fmt.Fprintf(&b, "auth:\n  type: password\n  password: %q\n", p.AuthPassword)
		if p.ObfsPassword != "" {
			b.WriteString("obfs:\n  type: salamander\n  salamander:\n")
			fmt.Fprintf(&b, "    password: %q\n", p.ObfsPassword)
		}
		fmt.Fprintf(&b, "tls:\n  cert: %q\n  key: %q\n", p.TLSCert, p.TLSKey)
		if p.UpMbps != "" || p.DownMbps != "" {
			b.WriteString("bandwidth:\n")
			if p.UpMbps != "" {
				fmt.Fprintf(&b, "  up: %q\n", p.UpMbps)
			}
			if p.DownMbps != "" {
				fmt.Fprintf(&b, "  down: %q\n", p.DownMbps)
			}
		}
		return b.String()
	}
	fmt.Fprintf(&b, "server: %q\n", p.ServerAddr)
	fmt.Fprintf(&b, "auth: %q\n", p.AuthPassword)
	if p.ObfsPassword != "" {
		b.WriteString("obfs:\n  type: salamander\n  salamander:\n")
		fmt.Fprintf(&b, "    password: %q\n", p.ObfsPassword)
	}
	b.WriteString("tls:\n")
	if p.SNI != "" {
		fmt.Fprintf(&b, "  sni: %q\n", p.SNI)
	}
	if p.Insecure {
		b.WriteString("  insecure: true\n")
	}
	if p.PinSHA256 != "" {
		fmt.Fprintf(&b, "  pinSHA256: %q\n", p.PinSHA256)
	}
	if p.UpMbps != "" || p.DownMbps != "" {
		b.WriteString("bandwidth:\n")
		if p.UpMbps != "" {
			fmt.Fprintf(&b, "  up: %q\n", p.UpMbps)
		}
		if p.DownMbps != "" {
			fmt.Fprintf(&b, "  down: %q\n", p.DownMbps)
		}
	}
	if p.SocksPort > 0 {
		b.WriteString("socks5:\n")
		fmt.Fprintf(&b, "  listen: %q\n", "127.0.0.1:"+strconv.Itoa(p.SocksPort))
		b.WriteString("  disableUDP: true\n")
	}
	if p.HTTPPort > 0 {
		b.WriteString("http:\n")
		fmt.Fprintf(&b, "  listen: %q\n", "127.0.0.1:"+strconv.Itoa(p.HTTPPort))
	}
	for _, fam := range []struct {
		key  string
		list []hysteriaForward
	}{{"tcpForwarding", p.TCPForwards}, {"udpForwarding", p.UDPForwards}} {
		for _, f := range fam.list {
			fmt.Fprintf(&b, "%s:\n  - listen: %q\n    remote: %q\n",
				fam.key, "127.0.0.1:"+strconv.Itoa(f.Listen), f.Remote)
		}
	}
	return b.String()
}

// hysteriaEnsureBinary: manifest-first (engine "hysteria"), pinned
// fallback — the identical trust model to the other drivers.
func hysteriaEnsureBinary(ctx context.Context, p hysteriaParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("hysteria: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.hysteriaArtifactPin(); pinErr == nil &&
		engineCacheHit(hysteriaBinDir(p.Version), pinnedSHA, []string{"hysteria"}) {
		return hysteriaBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("hysteria: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, hysteriaID,
		func() (string, string, string, error) { return p.hysteriaArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := hysteriaBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"hysteria"}) {
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
		return "", fmt.Errorf("hysteria: cache dir: %w", err)
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"hysteria": true}); err != nil {
		return "", fmt.Errorf("hysteria: %w", err)
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("hysteria: cache marker: %w", err)
	}
	return dir, nil
}

// hysteriaSpawn runs `hysteria <role> -c <cfg>` (upstream cobra CLI:
// root.go's persistent -c flag + the server/client subcommands). Strictly
// typed args — no shell.
var hysteriaSpawn = func(role, binPath, cfgPath string) (frpProcess, error) {
	cmd := exec.Command(binPath, role, "-c", cfgPath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("hysteria: start: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

func (d *HysteriaDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p hysteriaParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("hysteria: engine_params: %w", err)
	}
	if err := hysteriaValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("hysteria: invalid tunnel id %q", inst.TunnelID)
	}
	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual[hysteriaParams](prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}
	role, err := hysteriaResolveRole(p)
	if err != nil {
		return err
	}
	binDir, err := hysteriaEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "hysteria")
	cfg := hysteriaRenderConfig(role, p)
	cfgPath := hysteriaConfigPath(inst.TunnelID)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("hysteria: config dir: %w", err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("hysteria: write config: %w", err)
	}
	proc, err := hysteriaSpawn(role, binPath, cfgPath)
	if err != nil {
		_ = os.Remove(cfgPath)
		return err
	}
	st := &hysteriaInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		cfg: cfgPath, binPath: binPath}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, st.binPath, st.cfg,
		func(b, c string) (frpProcess, error) { return hysteriaSpawn(role, b, c) })
	// Wire accounting on the SERVER end: hysteria2's carrier is QUIC =
	// UDP — the -p udp rule family (OVERNIGHT-A proto-parameterized).
	if role == "server" {
		if port := enginePortOf(p.ServerAddr); port > 0 {
			if err := acctWireRulesAddProto(acctChainsDriver, inst.TunnelID, port, port, "udp"); err != nil {
				fmt.Fprintf(os.Stderr, "hysteria: wire accounting unavailable: %v\n", err)
			}
		}
	}
	return nil
}

func (d *HysteriaDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.role == "server" {
			if port := enginePortOf(st.params.ServerAddr); port > 0 {
				_ = acctWireRulesDelProto(acctChainsDriver, inst.TunnelID, port, port, "udp")
			}
		}
	})
	return nil
}

func (d *HysteriaDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, hysteriaID, inst.TunnelID, inst.Params,
		func(st *hysteriaInstState) hysteriaParams { return st.params }, engineParamsEqual[hysteriaParams])
}

func (d *HysteriaDriver) Health(inst engine.Instance) engine.Health {
	st := d.runs.peek(inst.TunnelID)
	if st == nil {
		return engine.Health{OK: false, Detail: "not running", LatencyMs: -1}
	}
	select {
	case <-st.current().Done():
		return engine.Health{OK: false, Detail: "process exited", LatencyMs: -1}
	default:
	}
	detail := "hysteria server running (QUIC carrier)"
	if st.role != "server" {
		detail = "hysteria client running"
	}
	return engine.Health{OK: true, Detail: detail, LatencyMs: -1}
}

// Counters: the SERVER end's wire view (-p udp on the carrier port);
// hysteria2 has no machine-readable per-connection stats in the OSS
// binary's config surface we drive — payload stays Unknown, honestly.
func (d *HysteriaDriver) Counters(inst engine.Instance) engine.Counters {
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

func (d *HysteriaDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, hysteriaEngineDir())
	return nil
}

// hysteriaVersionProbe runs `hysteria version` (bounded; seam-able) and
// parses the "Version:\tX" line (upstream app/cmd/version.go output).
var hysteriaVersionProbe = func(binPath string) (string, error) {
	out, err := infra.RunCmdTimeout(10*time.Second, binPath, hysteriaVersionCmd...)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Version:")), nil
		}
	}
	return "", fmt.Errorf("hysteria: unexpected version output")
}

// hysteriaInstalledVersion reports the INSTALLED core version for
// Describe() (the §2.22 pattern the ctunnel driver established): newest
// cached artifact probed with `hysteria version`; the build-pin version
// reported honestly without a cache.
func hysteriaInstalledVersion() string {
	base := filepath.Join(hysteriaEngineDir(), "bin")
	entries, err := os.ReadDir(base)
	if err != nil {
		return hysteriaPinnedVersion
	}
	best := ""
	for _, e := range entries {
		if !e.IsDir() || !infra.FileExists(filepath.Join(base, e.Name(), "hysteria")) {
			continue
		}
		if ctVersionLess(best, e.Name()) {
			best = e.Name()
		}
	}
	if best == "" {
		return hysteriaPinnedVersion
	}
	if v, err := hysteriaVersionProbe(filepath.Join(base, best, "hysteria")); err == nil && v != "" {
		return v
	}
	return best
}

// hysteriaPinnedVersion is the build-time core pin (the OVERNIGHT-C
// release; §2.22 fallback when no artifact is cached yet).
const hysteriaPinnedVersion = "2.14.0"
