package agent

// backhaul_driver.go — the Backhaul engine (Musixal/backhaul v0.7.2,
// AGPL-3.0, exec-a-binary so the license never touches Quantum's code)
// wrapped as an engine.Driver per 00-ADMIN/ENGINE-GUIDE.md, following the
// production shape the FRP driver established: release-style tarball with
// directory entries, role resolution through the agent's enrollment name,
// a supervisor with capped backoff, wire accounting on the transport
// port, Uninstall on idle, and artifact delivery through the R5 manifest
// (pinned engine_params triple as the fallback). GRE is deliberately NOT
// supported (the legacy Modified Backhaul's GRE transport is out of
// scope; see 00-ADMIN/ENGINE-CANDIDATES.md).
//
// Tunnel shape: one instance per end. The SERVER end (foreign side)
// binds the public carrier and the mapped data ports; the CLIENT end
// (Iran side — dials OUT, the direction that survives Iran NAT/filtering)
// connects to remote_addr and pipes the mapped ports to its local
// targets. Port mappings live on the SERVER config verbatim
// ("port=host:port" per upstream parsePortMappings); the driver treats
// them as opaque strings and only guards TOML safety.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const backhaulID = "backhaul"

// backhaulTransports is the allowlist, mirrored from upstream v0.7.2's
// config.TransportType const block (config/config.go): tcp, tcpmux, ws,
// wss, wsmux, wssmux, udp. OVERNIGHT-A audit deltas: (a) tcpmux + udp
// were MISSING from this driver — both are first-class upstream carriers
// and are now exposed; (b) the old allowlist advertised "tls", but
// upstream v0.7.2 has NO plain tls transport (no constant, no switch
// case, no transport file — TLS exists only inside wss/wssmux via
// tls_cert/tls_key), so a transport="tls" config made upstream fatal on
// startup. That phantom entry is now rejected with a clear message.
var backhaulAllowedTransports = map[string]bool{
	"tcp": true, "tcpmux": true, "udp": true,
	"ws": true, "wss": true, "wsmux": true, "wssmux": true,
}

// backhaulUDPCarrier reports whether the transport binds a UDP socket as
// the carrier (the wire accounting rules must then be -p udp).
func backhaulUDPCarrier(transport string) bool {
	return strings.ToLower(strings.TrimSpace(transport)) == "udp"
}

type backhaulParams struct {
	ServerSide string   `json:"server_side"`     // server name hosting the backhaul SERVER (foreign end)
	Version    string   `json:"version"`         // artifact version (cache key)
	Artifact   string   `json:"artifact"`        // artifact name TEMPLATE; "{arch}" -> runtime GOARCH
	SHA256Amd  string   `json:"sha256_amd64"`    // pinned fallback: sha256 hex (amd64)
	SHA256Arm  string   `json:"sha256_arm64"`    // pinned fallback (arm64)
	SigAmd     string   `json:"signature_amd64"` // pinned fallback: base64 ed25519 (amd64)
	SigArm     string   `json:"signature_arm64"` // pinned fallback (arm64)
	Transport  string   `json:"transport"`       // tcp|tcpmux|udp|ws|wss|wsmux|wssmux (no GRE; no plain "tls" upstream)
	Token      string   `json:"token"`           // shared auth token
	BindAddr   string   `json:"bind_addr"`       // server end: carrier listen addr:port
	RemoteAddr string   `json:"remote_addr"`     // client end: carrier dial addr:port
	Ports      []string `json:"ports"`           // server-side port mappings (opaque, upstream-parsed)
	WebPort    int      `json:"web_port"`        // per-instance stats/web port (0 = disabled)
	// AcceptUDP renders upstream server accept_udp=true (OVERNIGHT-A):
	// UDP sessions encapsulated over the TCP-family carrier. Server-side
	// only upstream (the ClientConfig struct has no accept_udp field).
	AcceptUDP bool `json:"accept_udp,omitempty"`
}

// backhaulArtifactPin mirrors frpArtifactPin (one tunnel row reaches both
// arches; each end verifies only its own artifact).
func (p backhaulParams) backhaulArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	arch := strings.ToLower(runtime.GOARCH)
	if !strings.Contains(p.Artifact, "{arch}") {
		return "", "", "", fmt.Errorf("backhaul: artifact template must contain {arch}")
	}
	name = strings.ReplaceAll(p.Artifact, "{arch}", arch)
	switch arch {
	case "amd64":
		return name, p.SHA256Amd, p.SigAmd, nil
	case "arm64":
		return name, p.SHA256Arm, p.SigArm, nil
	}
	return "", "", "", fmt.Errorf("backhaul: no artifact pin for GOARCH %q", arch)
}

// backhaulValidateParams checks the union shape (no side effects).
func backhaulValidateParams(p backhaulParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("backhaul: server_side (name of the end hosting the server) required")
	}
	if err := backhaulValidateArtifactPins(p); err != nil {
		return err
	}
	if !backhaulAllowedTransports[strings.ToLower(strings.TrimSpace(p.Transport))] {
		if strings.EqualFold(strings.TrimSpace(p.Transport), "tls") {
			return fmt.Errorf("backhaul: transport \"tls\" does not exist upstream (v0.7.2 has tcp|tcpmux|ws|wss|wsmux|wssmux|udp — TLS only rides wss/wssmux); use wss with tls_cert/tls_key")
		}
		return fmt.Errorf("backhaul: transport %q not supported (tcp|tcpmux|udp|ws|wss|wsmux|wssmux; GRE is out of scope)", p.Transport)
	}
	if len(p.Token) < 8 || len(p.Token) > 256 || strings.ContainsAny(p.Token, "\"'\n\r") {
		return fmt.Errorf("backhaul: token must be 8-256 chars without quotes/newlines")
	}
	if strings.TrimSpace(p.BindAddr) == "" || strings.TrimSpace(p.RemoteAddr) == "" ||
		strings.ContainsAny(p.BindAddr+p.RemoteAddr, "\"'\n\r") {
		return fmt.Errorf("backhaul: bind_addr and remote_addr required (TOML-safe)")
	}
	if len(p.Ports) == 0 || len(p.Ports) > 256 {
		return fmt.Errorf("backhaul: 1-256 port mappings required")
	}
	for _, m := range p.Ports {
		if len(m) == 0 || len(m) > 128 || strings.ContainsAny(m, "\"'\n\r") {
			return fmt.Errorf("backhaul: port mapping %q not TOML-safe", m)
		}
	}
	if p.WebPort < 0 || p.WebPort > 65535 {
		return fmt.Errorf("backhaul: web_port out of range")
	}
	return nil
}

func backhaulValidateArtifactPins(p backhaulParams) error {
	if strings.TrimSpace(p.Version) == "" || len(p.Version) > 64 ||
		strings.ContainsAny(p.Version, "/\\\"' \t\n\r") {
		return fmt.Errorf("backhaul: version must be 1-64 safe chars")
	}
	if !strings.Contains(p.Artifact, "{arch}") || strings.ContainsAny(p.Artifact, " \t\n\r\"\\") {
		return fmt.Errorf("backhaul: artifact must be a name template containing {arch}")
	}
	for _, a := range []struct {
		arch string
		sha  string
		sig  string
	}{
		{"amd64", p.SHA256Amd, p.SigAmd},
		{"arm64", p.SHA256Arm, p.SigArm},
	} {
		if len(a.sha) != 64 || strings.ContainsAny(a.sha, " \t\n\r") {
			return fmt.Errorf("backhaul: %s sha256 pin must be 64 hex chars", a.arch)
		}
		if len(a.sig) < 64 || len(a.sig) > 512 || strings.ContainsAny(a.sig, " \t\n\r") {
			return fmt.Errorf("backhaul: %s signature pin must be base64 (64-512 chars)", a.arch)
		}
	}
	return nil
}

// backhaulResolveRole resolves this end's role through the agent's own
// enrollment name (same seam the FRP driver uses).
func backhaulResolveRole(p backhaulParams) (string, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("backhaul: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return "server", nil
	}
	return "client", nil
}

type backhaulInstState struct {
	engineInst
	params backhaulParams
	role   string
}

// BackhaulDriver implements engine.Driver for Backhaul.
type BackhaulDriver struct {
	runs *instTable[backhaulInstState]
}

func NewBackhaulDriver() *BackhaulDriver {
	return &BackhaulDriver{runs: newInstTable[backhaulInstState]()}
}

func (d *BackhaulDriver) ID() string { return backhaulID }

func (d *BackhaulDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: backhaulID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"<name of the end hosting the server>","version":"","artifact":"..{arch}..","transport":"tcp|tcpmux|udp|ws|wss|wsmux|wssmux","token":"","bind_addr":"","remote_addr":"","ports":["5201=127.0.0.1:5201"],"web_port":0,"accept_udp":false}`)}
}

// EnsureBinary: the Manager calls this before the first instance starts;
// the artifact download itself happens in Start via backhaulEnsureBinary
// with the resolved coordinates (manifest-first, pinned fallback).
func (d *BackhaulDriver) EnsureBinary(ctx context.Context) (string, error) {
	return "", nil
}

func (d *BackhaulDriver) Validate(params json.RawMessage) error {
	var p backhaulParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("backhaul: engine_params: %w", err)
	}
	return backhaulValidateParams(p)
}

func backhaulConfigPath(tunnelID string) string {
	return filepath.Join(backhaulEngineDir(), "instances", tunnelID+".toml")
}

func backhaulBinDir(version string) string {
	return filepath.Join(engineEngineDir(backhaulID), "bin", version)
}

func backhaulEngineDir() string {
	return engineEngineDir(backhaulID)
}

// backhaulRenderConfig renders the end's TOML. Server: [server] with the
// carrier bind + the port mappings; client: [client] dialing remote_addr.
// Both share the token and transport; conservative pool/keepalive
// defaults keep the carrier alive behind Iran NAT.
func backhaulRenderConfig(role string, p backhaulParams) string {
	transport := strings.ToLower(strings.TrimSpace(p.Transport))
	var b strings.Builder
	if role == "server" {
		b.WriteString("[server]\n")
		fmt.Fprintf(&b, "bind_addr = %q\n", p.BindAddr)
		fmt.Fprintf(&b, "transport = %q\n", transport)
		fmt.Fprintf(&b, "token = %q\n", p.Token)
		b.WriteString("nodelay = true\nkeepalive_period = 15\n")
		if p.AcceptUDP {
			b.WriteString("accept_udp = true\n")
		}
		if len(p.Ports) > 0 {
			b.WriteString("ports = [")
			for i, m := range p.Ports {
				if i > 0 {
					b.WriteString(", ")
				}
				fmt.Fprintf(&b, "%q", m)
			}
			b.WriteString("]\n")
		}
		if p.WebPort > 0 {
			fmt.Fprintf(&b, "web_port = %d\nsniffer = true\n", p.WebPort)
		}
		b.WriteString("log_level = \"info\"\n")
		return b.String()
	}
	b.WriteString("[client]\n")
	fmt.Fprintf(&b, "remote_addr = %q\n", p.RemoteAddr)
	fmt.Fprintf(&b, "transport = %q\n", transport)
	fmt.Fprintf(&b, "token = %q\n", p.Token)
	b.WriteString("connection_pool = 8\nretry_interval = 5\nnodelay = true\nkeepalive_period = 15\n")
	if p.WebPort > 0 {
		fmt.Fprintf(&b, "web_port = %d\n", p.WebPort)
	}
	b.WriteString("log_level = \"info\"\n")
	return b.String()
}

// backhaulEnsureBinary makes the backhaul binary available and returns
// the cache dir. Manifest-first (engine "backhaul"), pinned fallback —
// identical trust model to the FRP driver.
func backhaulEnsureBinary(ctx context.Context, p backhaulParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("backhaul: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.backhaulArtifactPin(); pinErr == nil && frpCacheHit(backhaulBinDir(p.Version), pinnedSHA) {
		return backhaulBinDir(p.Version), nil
	}
	identFn := frpLoadIdentity
	ident, ok := identFn()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("backhaul: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, backhaulID,
		func() (string, string, string, error) { return p.backhaulArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := backhaulBinDir(p.Version)
	if frpCacheHitBackhaul(dir, sha256Hex) {
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
		return "", fmt.Errorf("backhaul: cache dir: %w", err)
	}
	if err := backhaulExtract(body, dir); err != nil {
		return "", err
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("backhaul: cache marker: %w", err)
	}
	return dir, nil
}

// frpCacheHit checks frps/frpc; backhaul needs its own marker check for
// the single `backhaul` binary.
func frpCacheHitBackhaul(dir, sha256Hex string) bool {
	return engineCacheHit(dir, sha256Hex, []string{"backhaul"})
}

// backhaulExtract unpacks the release tar.gz: only the regular
// `backhaul` binary installs (0755); directory entries skipped, anything
// else refused. Delegates to the shared engineExtractTarball (same
// semantics; errors keep the backhaul prefix).
func backhaulExtract(body []byte, dir string) error {
	if err := engineExtractTarball(body, dir, map[string]bool{"backhaul": true}); err != nil {
		return fmt.Errorf("backhaul: %w", err)
	}
	return nil
}

// Start implements engine.Driver.
func (d *BackhaulDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p backhaulParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("backhaul: engine_params: %w", err)
	}
	if err := backhaulValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("backhaul: invalid tunnel id %q", inst.TunnelID)
	}

	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual[backhaulParams](prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}

	role, err := backhaulResolveRole(p)
	if err != nil {
		return err
	}
	binDir, err := backhaulEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "backhaul")
	cfg := backhaulRenderConfig(role, p)
	cfgPath := backhaulConfigPath(inst.TunnelID)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("backhaul: config dir: %w", err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("backhaul: write config: %w", err)
	}
	proc, err := frpSpawn(binPath, cfgPath)
	if err != nil {
		_ = os.Remove(cfgPath)
		return err
	}
	st := &backhaulInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		cfg: cfgPath, binPath: binPath}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, st.binPath, st.cfg, frpSpawn)
	// Wire accounting on the SERVER end only: the carrier port's bytes
	// are this tunnel's wire view (the client's dial port is shared and
	// cannot be attributed per instance). transport=udp is a UDP carrier
	// — its rules ride the -p udp accounting variant (OVERNIGHT-A).
	if role == "server" {
		if port := enginePortOf(p.BindAddr); port > 0 {
			proto := "tcp"
			if backhaulUDPCarrier(p.Transport) {
				proto = "udp"
			}
			if err := acctWireRulesAddProto(acctChainsDriver, inst.TunnelID, port, port, proto); err != nil {
				fmt.Fprintf(os.Stderr, "backhaul: wire accounting unavailable: %v\n", err)
			}
		}
	}
	return nil
}

// Stop implements engine.Driver: the shared teardown order, with the
// server end's carrier-port accounting rule as the driver-specific hook.
func (d *BackhaulDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.role == "server" {
			if port := enginePortOf(st.params.BindAddr); port > 0 {
				proto := "tcp"
				if backhaulUDPCarrier(st.params.Transport) {
					proto = "udp"
				}
				_ = acctWireRulesDelProto(acctChainsDriver, inst.TunnelID, port, port, proto)
			}
		}
	})
	return nil
}

// Reload implements engine.Driver: equal params are a no-op, anything
// else is a restart.
func (d *BackhaulDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, backhaulID, inst.TunnelID, inst.Params,
		func(st *backhaulInstState) backhaulParams { return st.params }, engineParamsEqual[backhaulParams])
}

// Health implements engine.Driver: the process alive, and on the server
// end (when a web_port is configured) the upstream /stats JSON's
// tunnelStatus must say the tunnel is connected.
func (d *BackhaulDriver) Health(inst engine.Instance) engine.Health {
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
	if st.role == "client" || st.params.WebPort <= 0 {
		return engine.Health{OK: true, Detail: "backhaul process running", LatencyMs: -1}
	}
	start := time.Now()
	status, err := backhaulTunnelStatus(st.params.WebPort)
	lat := float64(time.Since(start).Milliseconds())
	if err != nil {
		return engine.Health{OK: false, Detail: "stats API not answering", LatencyMs: lat}
	}
	if !strings.EqualFold(strings.TrimSpace(status), "connected") {
		return engine.Health{OK: false, Detail: "tunnel " + status, LatencyMs: lat}
	}
	return engine.Health{OK: true, Detail: "backhaul tunnel connected", LatencyMs: lat}
}

// backhaulTunnelStatus reads the upstream web API's /stats JSON
// (internal/web/sniffer.go SystemStats.TunnelStatus).
func backhaulTunnelStatus(webPort int) (string, error) {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/stats", webPort))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var stats struct {
		TunnelStatus string `json:"tunnelStatus"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return "", err
	}
	return stats.TunnelStatus, nil
}

// Counters implements engine.Driver: the SERVER end reports the wire
// view (iptables accounting on the carrier port); per-port payload bytes
// exist only as upstream's humanized dashboard strings — not
// machine-parseable, so payload stays Unknown, honestly (the balancer
// treats Unknown-payload tunnels as wire-only per the design note).
// PHASE8 1c re-check (2026-11-08): v0.7.2 is still the latest upstream
// release (v0.5.1…v0.7.2 line); NO release (up to v0.7.2, Sep 2025)
// exposes machine-readable stats — no API, no Prometheus, no usage
// endpoint in any release note. Keep Unknown; re-check on the next
// upstream release.
func (d *BackhaulDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil || st.role != "server" {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if port := enginePortOf(st.params.BindAddr); port > 0 {
		if rx, tx, ok := acctWireBytes(inst.TunnelID, port, port); ok {
			out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
		}
	}
	return out
}

// Uninstall implements engine.Driver: stop everything, remove the binary
// cache + config dir (idle engines leave zero processes and zero files).
func (d *BackhaulDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, backhaulEngineDir())
	return nil
}
