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
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const backhaulID = "backhaul"

// backhaulTransports is the allowlist: the legacy-supported carriers
// minus GRE. Plain "tcp" is the lab baseline; the TLS/WS carriers are
// the Iran-path shapes.
var backhaulAllowedTransports = map[string]bool{
	"tcp": true, "tls": true, "ws": true, "wss": true, "wsmux": true, "wssmux": true,
}

type backhaulParams struct {
	ServerSide string   `json:"server_side"`     // server name hosting the backhaul SERVER (foreign end)
	Version    string   `json:"version"`         // artifact version (cache key)
	Artifact   string   `json:"artifact"`        // artifact name TEMPLATE; "{arch}" -> runtime GOARCH
	SHA256Amd  string   `json:"sha256_amd64"`    // pinned fallback: sha256 hex (amd64)
	SHA256Arm  string   `json:"sha256_arm64"`    // pinned fallback (arm64)
	SigAmd     string   `json:"signature_amd64"` // pinned fallback: base64 ed25519 (amd64)
	SigArm     string   `json:"signature_arm64"` // pinned fallback (arm64)
	Transport  string   `json:"transport"`       // tcp | tls | ws | wss | wsmux | wssmux (no GRE)
	Token      string   `json:"token"`           // shared auth token
	BindAddr   string   `json:"bind_addr"`       // server end: carrier listen addr:port
	RemoteAddr string   `json:"remote_addr"`     // client end: carrier dial addr:port
	Ports      []string `json:"ports"`           // server-side port mappings (opaque, upstream-parsed)
	WebPort    int      `json:"web_port"`        // per-instance stats/web port (0 = disabled)
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
		return fmt.Errorf("backhaul: transport %q not supported (tcp|tls|ws|wss|wsmux|wssmux; GRE is out of scope)", p.Transport)
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
	params  backhaulParams
	role    string
	cfg     string
	binPath string
	proc    frpProcess
	stop    chan struct{}
	mu      sync.Mutex
}

func (st *backhaulInstState) setProc(p frpProcess) { st.mu.Lock(); st.proc = p; st.mu.Unlock() }
func (st *backhaulInstState) current() frpProcess {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.proc
}

// BackhaulDriver implements engine.Driver for Backhaul.
type BackhaulDriver struct {
	mu   sync.Mutex
	runs map[string]*backhaulInstState
}

func NewBackhaulDriver() *BackhaulDriver {
	return &BackhaulDriver{runs: map[string]*backhaulInstState{}}
}

func (d *BackhaulDriver) ID() string { return backhaulID }

func (d *BackhaulDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: backhaulID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"<name of the end hosting the server>","version":"","artifact":"..{arch}..","transport":"tcp|tls|ws|wss|wsmux|wssmux","token":"","bind_addr":"","remote_addr":"","ports":["5201=127.0.0.1:5201"],"web_port":0}`)}
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
	return filepath.Join(backhaulEngineDir(), "bin", version)
}

func backhaulEngineDir() string {
	return filepath.Join(configDir, "engines", backhaulID)
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

// backhaulParamsEqual compares parsed params (key-order independent).
func backhaulParamsEqual(a, b backhaulParams) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return subtle.ConstantTimeCompare(ab, bb) == 1
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
	if err := os.WriteFile(filepath.Join(dir, "artifact.sha256"), []byte(sha256Hex), 0o600); err != nil {
		return "", fmt.Errorf("backhaul: cache marker: %w", err)
	}
	return dir, nil
}

// frpCacheHit checks frps/frpc; backhaul needs its own marker check for
// the single `backhaul` binary.
func frpCacheHitBackhaul(dir, sha256Hex string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "artifact.sha256"))
	if err != nil || !strings.EqualFold(strings.TrimSpace(string(data)), sha256Hex) {
		return false
	}
	return fileExists(filepath.Join(dir, "backhaul"))
}

// backhaulExtract unpacks the release tar.gz: only the regular `backhaul`
// binary is installed (0755); directory entries (the release wraps
// binaries in a version directory) are skipped, anything else refused.
func backhaulExtract(body []byte, dir string) error {
	gz, err := gzip.NewReader(strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("backhaul: artifact is not gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("backhaul: artifact tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue // the release wraps the binary in a version directory
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("backhaul: artifact contains non-regular entry %q", hdr.Name)
		}
		if hdr.Size > 256<<20 {
			return fmt.Errorf("backhaul: artifact entry %q too large", hdr.Name)
		}
		if filepath.Base(hdr.Name) != "backhaul" {
			continue // docs, LICENSE, completions, …
		}
		if found {
			return fmt.Errorf("backhaul: artifact has duplicate %q", hdr.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, 256<<20))
		if err != nil {
			return fmt.Errorf("backhaul: artifact read %q: %w", hdr.Name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "backhaul"), data, 0o755); err != nil {
			return fmt.Errorf("backhaul: install: %w", err)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("backhaul: artifact missing the backhaul binary")
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

	d.mu.Lock()
	prev := d.runs[inst.TunnelID]
	d.mu.Unlock()
	if prev != nil {
		if backhaulParamsEqual(prev.params, p) && prev.current() != nil {
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
	st := &backhaulInstState{params: p, role: role, cfg: cfgPath, binPath: binPath,
		proc: proc, stop: make(chan struct{})}
	d.mu.Lock()
	d.runs[inst.TunnelID] = st
	d.mu.Unlock()
	go d.supervise(st)
	// Wire accounting on the SERVER end only: the carrier port's bytes
	// are this tunnel's wire view (the client's dial port is shared and
	// cannot be attributed per instance).
	if role == "server" {
		if port := backhaulPortOf(p.BindAddr); port > 0 {
			if err := frpWireRulesAdd(inst.TunnelID, port, port); err != nil {
				fmt.Fprintf(os.Stderr, "backhaul: wire accounting unavailable: %v\n", err)
			}
		}
	}
	return nil
}

// backhaulPortOf extracts the port from "host:port" (0 when absent).
func backhaulPortOf(addr string) int {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return 0
	}
	n := 0
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return 0
		}
		n = n*10 + int(port[i]-'0')
		if n > 65535 {
			return 0
		}
	}
	return n
}

// supervise keeps the instance's process alive until Stop: an unexpected
// exit restarts with a capped backoff (mirrors the FRP supervisor).
func (d *BackhaulDriver) supervise(st *backhaulInstState) {
	backoff := 2 * time.Second
	for {
		select {
		case <-st.stop:
			return
		case <-st.current().Done():
			select {
			case <-st.stop:
				return
			case <-time.After(backoff):
			}
			if backoff < 15*time.Second {
				backoff *= 2
			}
			if proc, err := frpSpawn(st.binPath, st.cfg); err == nil {
				st.setProc(proc)
			}
		}
	}
}

// Stop implements engine.Driver.
func (d *BackhaulDriver) Stop(inst engine.Instance) error {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	delete(d.runs, inst.TunnelID)
	d.mu.Unlock()
	if st == nil {
		return nil
	}
	close(st.stop)
	frpProcStop(st.current())
	_ = os.Remove(st.cfg)
	if st.role == "server" {
		if port := backhaulPortOf(st.params.BindAddr); port > 0 {
			_ = frpWireRulesDel(inst.TunnelID, port, port)
		}
	}
	return nil
}

// Reload implements engine.Driver: equal params are a no-op, anything
// else is a restart.
func (d *BackhaulDriver) Reload(inst engine.Instance) error {
	var p backhaulParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("backhaul: engine_params: %w", err)
	}
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
	if st == nil {
		return fmt.Errorf("backhaul: reload on stopped instance %q", inst.TunnelID)
	}
	if backhaulParamsEqual(st.params, p) {
		return nil
	}
	return engine.ErrRestartRequired
}

// Health implements engine.Driver: the process alive, and on the server
// end (when a web_port is configured) the upstream /stats JSON's
// tunnelStatus must say the tunnel is connected.
func (d *BackhaulDriver) Health(inst engine.Instance) engine.Health {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
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
// exist only as upstream's humanized dashboard strings (v0.7.2) — not
// machine-parseable, so payload stays Unknown, honestly (the balancer
// treats Unknown-payload tunnels as wire-only per the design note).
func (d *BackhaulDriver) Counters(inst engine.Instance) engine.Counters {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
	if st == nil || st.role != "server" {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if port := backhaulPortOf(st.params.BindAddr); port > 0 {
		if rx, tx, ok := frpWireBytes(inst.TunnelID, port, port); ok {
			out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
		}
	}
	return out
}

// Uninstall implements engine.Driver: stop everything, remove the binary
// cache + config dir (idle engines leave zero processes and zero files).
func (d *BackhaulDriver) Uninstall(ctx context.Context) error {
	d.mu.Lock()
	ids := make([]string, 0, len(d.runs))
	for id := range d.runs {
		ids = append(ids, id)
	}
	d.mu.Unlock()
	for _, id := range ids {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}
	_ = os.RemoveAll(backhaulEngineDir())
	return nil
}
