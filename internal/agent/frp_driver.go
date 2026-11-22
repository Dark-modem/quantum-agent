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
//     <infra.ConfigDir>/engines/frp/<version>/. The cache exists only while the
//     engine has instances: Uninstall (called by the Manager after the
//     last instance stopped) removes it.
//   - While an instance runs, the only files are that cache plus one
//     per-tunnel config at <infra.ConfigDir>/engines/frp/<tunnelID>.toml
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

	"github.com/Dark-modem/quantum-agent/internal/infra"

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
	// OVERNIGHT-A gap-close additions (all optional, defaults preserve the
	// historical shape):
	ProxyType string `json:"proxy_type,omitempty"` // tcp (default) | udp — the client proxy block's type
	// Transport is the frpc↔frps carrier: upstream
	// SupportedTransportProtocols = tcp|kcp|quic|websocket|wss. wss needs
	// the server's TLS cert — rejected fail-closed (next wave).
	Transport string `json:"transport,omitempty"`
	// UseEncryption/UseCompression render the per-proxy upstream flags.
	UseEncryption  bool `json:"use_encryption,omitempty"`
	UseCompression bool `json:"use_compression,omitempty"`
	// OVERNIGHT-A2 secret-proxy family (proxy_type stcp|sudp|xtcp): the
	// shared secretKey of the proxy AND the foreign-end visitor (upstream
	// STCPProxyConfig/XTCPProxyConfig secretKey + VisitorBaseConfig).
	SecretKey string `json:"secret_key,omitempty"`
	// OVERNIGHT-A3 vhost family (proxy_type http|https|tcpmux — the
	// morning human order lifted the vhost "next wave" hold). Server-side
	// frps config (pkg/config/v1/server.go): VhostHTTPPort /
	// VhostHTTPSPort / TCPMuxHTTPConnectPort / TCPMuxPassthrough /
	// SubDomainHost. Client-side proxy blocks (pkg/config/v1/proxy.go):
	// HTTPProxyConfig (DomainConfig + Locations + HTTPUser/HTTPPassword +
	// HostHeaderRewrite), HTTPSProxyConfig (DomainConfig — TLS passthrough
	// routed by SNI), TCPMuxProxyConfig (DomainConfig + Multiplexer
	// "httpconnect" + HTTPUser/HTTPPassword). The vhost proxies carry NO
	// remotePort — frps routes by domain on the vhost ports.
	VhostHTTPPort     int    `json:"vhost_http_port,omitempty"`  // frps vhostHTTPPort (0 = off)
	VhostHTTPSPort    int    `json:"vhost_https_port,omitempty"` // frps vhostHTTPSPort
	TCPMuxPort        int    `json:"tcpmux_http_connect_port,omitempty"`
	TCPMuxPassthrough bool   `json:"tcpmux_passthrough,omitempty"`
	SubDomainHost     string `json:"sub_domain_host,omitempty"` // frps subDomainHost
	// DomainConfig (customDomains[] + subdomain) — at least one is
	// required for the vhost family.
	CustomDomains []string `json:"custom_domains,omitempty"`
	SubDomain     string   `json:"subdomain,omitempty"`
	// http-only knobs.
	Locations         []string `json:"locations,omitempty"`
	HostHeaderRewrite string   `json:"host_header_rewrite,omitempty"`
	// http + tcpmux basic auth.
	HTTPUser     string `json:"http_user,omitempty"`
	HTTPPassword string `json:"http_password,omitempty"`
}

// frpSecretProxy reports the proxy types that need the foreign-end
// visitor frpc (the visitor binds the public port; the proxy side sits
// on the Iran end).
func frpSecretProxy(pt string) bool {
	switch strings.ToLower(strings.TrimSpace(pt)) {
	case "stcp", "sudp", "xtcp":
		return true
	}
	return false
}

// frpAllowedProxyTypes mirrors upstream ProxyType entries the two-end
// tunnel shape can drive. OVERNIGHT-A3 adds the vhost family (http/
// https/tcpmux — frps vhost ports + domain routing, verified against
// pkg/config/v1/proxy.go; the A2-era "next wave" hold is lifted by the
// morning human order).
var frpAllowedProxyTypes = map[string]bool{
	"": true, "tcp": true, "udp": true,
	"stcp": true, "sudp": true, "xtcp": true,
	"http": true, "https": true, "tcpmux": true,
}

// frpVhostProxy reports the vhost-routed proxy types (no remotePort —
// frps routes by domain on the vhost ports).
func frpVhostProxy(pt string) bool {
	switch strings.ToLower(strings.TrimSpace(pt)) {
	case "http", "https", "tcpmux":
		return true
	}
	return false
}

// frpHostnameSafe is the domain/hostname charset (renders into TOML).
func frpHostnameSafe(s string) bool {
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.'
		if !ok {
			return false
		}
	}
	return true
}

// frpAllowedTransports mirrors upstream SupportedTransportProtocols
// minus wss (cert-bound).
var frpAllowedTransports = map[string]bool{
	"": true, "tcp": true, "kcp": true, "quic": true, "websocket": true,
}

// frpUDPCarrier reports the transports whose control+data socket is UDP.
func frpUDPCarrier(transport string) bool {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "kcp", "quic":
		return true
	}
	return false
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
	pt := strings.ToLower(strings.TrimSpace(p.ProxyType))
	if !frpAllowedProxyTypes[pt] {
		return fmt.Errorf("frp: proxy_type %q not supported (tcp|udp|stcp|sudp|xtcp|http|https|tcpmux)", p.ProxyType)
	}
	// OVERNIGHT-A3 vhost family: the frps side must open the matching
	// vhost port and the proxy needs a routing domain.
	if frpVhostProxy(pt) {
		switch pt {
		case "http":
			if p.VhostHTTPPort <= 0 || p.VhostHTTPPort > 65535 {
				return fmt.Errorf("frp: proxy_type http needs vhost_http_port 1-65535 (frps vhostHTTPPort)")
			}
		case "https":
			if p.VhostHTTPSPort <= 0 || p.VhostHTTPSPort > 65535 {
				return fmt.Errorf("frp: proxy_type https needs vhost_https_port 1-65535 (frps vhostHTTPSPort)")
			}
		case "tcpmux":
			if p.TCPMuxPort <= 0 || p.TCPMuxPort > 65535 {
				return fmt.Errorf("frp: proxy_type tcpmux needs tcpmux_http_connect_port 1-65535 (frps TCPMuxHTTPConnectPort)")
			}
		}
		if len(p.CustomDomains) == 0 && strings.TrimSpace(p.SubDomain) == "" {
			return fmt.Errorf("frp: proxy_type %s needs custom_domains or subdomain (frps routes by domain — DomainConfig)", p.ProxyType)
		}
		if len(p.CustomDomains) > 16 {
			return fmt.Errorf("frp: custom_domains accepts at most 16 entries")
		}
		for _, d := range p.CustomDomains {
			if strings.TrimSpace(d) == "" || len(d) > 253 || !frpHostnameSafe(d) {
				return fmt.Errorf("frp: custom_domains entries must be hostname-safe ≤253-char strings (got %q)", d)
			}
		}
		if p.SubDomain != "" && (len(p.SubDomain) > 63 || !frpHostnameSafe(p.SubDomain)) {
			return fmt.Errorf("frp: subdomain must be a hostname-safe ≤63-char label (joined with frps subDomainHost)")
		}
		if p.SubDomainHost != "" && (len(p.SubDomainHost) > 253 || !frpHostnameSafe(p.SubDomainHost)) {
			return fmt.Errorf("frp: sub_domain_host must be a hostname-safe ≤253-char string")
		}
		for _, loc := range p.Locations {
			if len(loc) > 128 || !strings.HasPrefix(loc, "/") || strings.ContainsAny(loc, "\"'\\\n\r ") {
				return fmt.Errorf("frp: locations entries must be /-rooted ≤128-char paths without quotes/whitespace")
			}
		}
		if p.HostHeaderRewrite != "" && (len(p.HostHeaderRewrite) > 253 || !frpHostnameSafe(p.HostHeaderRewrite)) {
			return fmt.Errorf("frp: host_header_rewrite must be a hostname-safe ≤253-char string")
		}
		for _, a := range []struct{ label, v string }{{"http_user", p.HTTPUser}, {"http_password", p.HTTPPassword}} {
			if a.v != "" && (len(a.v) > 128 || strings.ContainsAny(a.v, "\"\\ \t\n\r")) {
				return fmt.Errorf("frp: %s must be 1-128 chars without quotes, backslash or whitespace", a.label)
			}
		}
	}
	if frpSecretProxy(pt) {
		if len(p.SecretKey) < 8 || len(p.SecretKey) > 128 || strings.ContainsAny(p.SecretKey, "\"\\ \t\n\r") {
			return fmt.Errorf("frp: proxy_type %s needs secret_key (8-128 chars without quotes/backslash/whitespace — the proxy and the visitor share it)", p.ProxyType)
		}
	} else if p.SecretKey != "" {
		return fmt.Errorf("frp: secret_key is only valid with proxy_type stcp|sudp|xtcp (got %q)", p.ProxyType)
	}
	t := strings.ToLower(strings.TrimSpace(p.Transport))
	if !frpAllowedTransports[t] {
		if t == "wss" {
			return fmt.Errorf("frp: transport wss needs the server's TLS cert — not supported yet (use tcp|kcp|quic|websocket)")
		}
		return fmt.Errorf("frp: transport %q not supported (tcp|kcp|quic|websocket)", p.Transport)
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
	// OVERNIGHT-A2 secret-proxy family: the FOREIGN end additionally runs
	// one frpc WITH A VISITOR config (it binds the public port locally).
	// The visitor owns its OWN engineInst — sharing the main one would
	// let the visitor's supervisor overwrite the main proc handle
	// (engineSupervise calls setProc on respawn).
	visitorState *engineInst
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
		ParamsSchema: json.RawMessage(`{"role":"server|client","version":"","artifact":"","sha256":"","signature":"","server_addr":"","server_port":0,"token":"","remote_port":0,"local_addr":"","local_port":0,"dashboard_port":0,"allow_port_min":0,"allow_port_max":0,"proxy_type":"tcp|udp|stcp|sudp|xtcp|http|https|tcpmux","transport":"tcp|kcp|quic|websocket","use_encryption":false,"use_compression":false,"secret_key":"","vhost_http_port":0,"vhost_https_port":0,"tcpmux_http_connect_port":0,"tcpmux_passthrough":false,"sub_domain_host":"","custom_domains":["app.example.com"],"subdomain":"app","locations":["/api"],"host_header_rewrite":"","http_user":"","http_password":""}`)}
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
	return filepath.Join(infra.ConfigDir, "engines", "frp", tunnelID+".toml")
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
// charset was validated, so plain quoting is safe. OVERNIGHT-A: the proxy
// block gains type/useEncryption/useCompression (defaults keep the
// historical tcp shape), and the transport.protocol block rides both ends
// when a non-tcp carrier is chosen (kcp/quic/websocket — upstream
// SupportedTransportProtocols; the control AND data carrier port stays
// server_port).
func frpRenderConfig(tunnelID, role string, p frpParams) string {
	var b strings.Builder
	proxyType := strings.ToLower(strings.TrimSpace(p.ProxyType))
	if proxyType == "" {
		proxyType = "tcp"
	}
	transport := strings.ToLower(strings.TrimSpace(p.Transport))
	switch role {
	case "server":
		fmt.Fprintf(&b, "bindAddr = \"0.0.0.0\"\n")
		fmt.Fprintf(&b, "bindPort = %d\n", p.ServerPort)
		fmt.Fprintf(&b, "auth.token = \"%s\"\n", p.Token)
		if transport != "" && transport != "tcp" {
			fmt.Fprintf(&b, "transport.protocol = \"%s\"\n", transport)
		}
		fmt.Fprintf(&b, "webServer.addr = \"127.0.0.1\"\n")
		fmt.Fprintf(&b, "webServer.port = %d\n", p.DashPort)
		fmt.Fprintf(&b, "webServer.user = \"quantum\"\n")
		fmt.Fprintf(&b, "webServer.password = \"%s\"\n", frpDashSecret(tunnelID, p))
		fmt.Fprintf(&b, "allowPorts = [{ start = %d, end = %d }]\n", p.AllowMin, p.AllowMax)
		// OVERNIGHT-A3 vhost family: frps opens the vhost ports the
		// client's http/https/tcpmux proxies ride (pkg/config/v1/
		// server.go field names verbatim).
		if p.VhostHTTPPort > 0 {
			fmt.Fprintf(&b, "vhostHTTPPort = %d\n", p.VhostHTTPPort)
		}
		if p.VhostHTTPSPort > 0 {
			fmt.Fprintf(&b, "vhostHTTPSPort = %d\n", p.VhostHTTPSPort)
		}
		if p.TCPMuxPort > 0 {
			fmt.Fprintf(&b, "tcpmuxHTTPConnectPort = %d\n", p.TCPMuxPort)
		}
		if p.TCPMuxPassthrough {
			b.WriteString("tcpmuxPassthrough = true\n")
		}
		if p.SubDomainHost != "" {
			fmt.Fprintf(&b, "subDomainHost = \"%s\"\n", p.SubDomainHost)
		}
	case "client":
		fmt.Fprintf(&b, "serverAddr = \"%s\"\n", p.ServerAddr)
		fmt.Fprintf(&b, "serverPort = %d\n", p.ServerPort)
		fmt.Fprintf(&b, "auth.token = \"%s\"\n", p.Token)
		if transport != "" && transport != "tcp" {
			fmt.Fprintf(&b, "transport.protocol = \"%s\"\n", transport)
		}
		fmt.Fprintf(&b, "[[proxies]]\n")
		fmt.Fprintf(&b, "name = \"%s\"\n", tunnelID)
		fmt.Fprintf(&b, "type = \"%s\"\n", proxyType)
		fmt.Fprintf(&b, "localIP = \"%s\"\n", p.LocalAddr)
		fmt.Fprintf(&b, "localPort = %d\n", p.LocalPort)
		if frpVhostProxy(proxyType) {
			// vhost family: frps routes by domain — the proxy carries
			// DomainConfig, NOT remotePort (upstream HTTPProxyConfig/
			// HTTPSProxyConfig/TCPMuxProxyConfig).
			if len(p.CustomDomains) > 0 {
				quoted := make([]string, 0, len(p.CustomDomains))
				for _, d := range p.CustomDomains {
					quoted = append(quoted, fmt.Sprintf("%q", d))
				}
				fmt.Fprintf(&b, "customDomains = [%s]\n", strings.Join(quoted, ", "))
			}
			if p.SubDomain != "" {
				fmt.Fprintf(&b, "subdomain = \"%s\"\n", p.SubDomain)
			}
			if proxyType == "http" {
				if len(p.Locations) > 0 {
					quoted := make([]string, 0, len(p.Locations))
					for _, l := range p.Locations {
						quoted = append(quoted, fmt.Sprintf("%q", l))
					}
					fmt.Fprintf(&b, "locations = [%s]\n", strings.Join(quoted, ", "))
				}
				if p.HostHeaderRewrite != "" {
					fmt.Fprintf(&b, "hostHeaderRewrite = \"%s\"\n", p.HostHeaderRewrite)
				}
			}
			if proxyType == "http" || proxyType == "tcpmux" {
				if p.HTTPUser != "" {
					fmt.Fprintf(&b, "httpUser = \"%s\"\n", p.HTTPUser)
					fmt.Fprintf(&b, "httpPassword = \"%s\"\n", p.HTTPPassword)
				}
			}
			if proxyType == "tcpmux" {
				fmt.Fprintf(&b, "multiplexer = \"httpconnect\"\n")
			}
		} else {
			fmt.Fprintf(&b, "remotePort = %d\n", p.RemotePort)
		}
		if frpSecretProxy(proxyType) {
			// the proxy name IS the visitor's serverName (upstream
			// naming.BuildTargetServerProxyName resolves it user-less).
			fmt.Fprintf(&b, "secretKey = \"%s\"\n", p.SecretKey)
		}
		if p.UseEncryption {
			b.WriteString("useEncryption = true\n")
		}
		if p.UseCompression {
			b.WriteString("useCompression = true\n")
		}
	}
	return b.String()
}

// frpVisitorConfig renders the FOREIGN-end visitor frpc TOML for the
// secret-proxy family (OVERNIGHT-A2): the visitor connects to the local
// frps (same host) and binds the PUBLIC port locally; public users hit
// foreign:remote_port → through frps → the Iran-end proxy → local_addr.
// Verified shapes: VisitorBaseConfig (secretKey/serverName/bindAddr/
// bindPort) + client/visitor/visitor.go dialRawVisitorConn.
func frpVisitorConfig(tunnelID string, p frpParams) string {
	var b strings.Builder
	fmt.Fprintf(&b, "serverAddr = \"127.0.0.1\"\n")
	fmt.Fprintf(&b, "serverPort = %d\n", p.ServerPort)
	fmt.Fprintf(&b, "auth.token = \"%s\"\n", p.Token)
	fmt.Fprintf(&b, "[[visitors]]\n")
	fmt.Fprintf(&b, "name = \"%s-visitor\"\n", tunnelID)
	fmt.Fprintf(&b, "type = \"%s\"\n", strings.ToLower(strings.TrimSpace(p.ProxyType)))
	fmt.Fprintf(&b, "serverName = \"%s\"\n", tunnelID)
	fmt.Fprintf(&b, "secretKey = \"%s\"\n", p.SecretKey)
	fmt.Fprintf(&b, "bindAddr = \"0.0.0.0\"\n")
	fmt.Fprintf(&b, "bindPort = %d\n", p.RemotePort)
	if p.UseEncryption {
		b.WriteString("useEncryption = true\n")
	}
	if p.UseCompression {
		b.WriteString("useCompression = true\n")
	}
	return b.String()
}

// frpVisitorConfigPath is the visitor frpc's own config file.
func frpVisitorConfigPath(tunnelID string) string {
	return filepath.Join(infra.ConfigDir, "engines", "frp", tunnelID+"-visitor.toml")
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
	// OVERNIGHT-A3 vhost family: the data port is the matching frps vhost
	// port (remotePort is not bound for http/https/tcpmux).
	if frpVhostProxy(st.params.ProxyType) {
		if ports := frpVhostPorts(st.params); len(ports) == 1 {
			if st.role == "server" {
				return "127.0.0.1", ports[0], true
			}
			return st.params.ServerAddr, ports[0], true
		}
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
	// OVERNIGHT-A2 secret-proxy family: on the FOREIGN (frps) end spawn
	// the visitor frpc — it connects to the local frps and binds the
	// PUBLIC port locally. Its supervisor mirrors the main one; a spawn
	// failure tears the whole instance down (fail closed, no half state).
	if role == "server" && frpSecretProxy(p.ProxyType) {
		visitorCfg := frpVisitorConfig(inst.TunnelID, p)
		vCfgPath := frpVisitorConfigPath(inst.TunnelID)
		if err := os.WriteFile(vCfgPath, []byte(visitorCfg), 0o600); err != nil {
			_ = d.Stop(inst)
			return fmt.Errorf("frp: write visitor config: %w", err)
		}
		visitorProc, err := frpSpawn(filepath.Join(binDir, "frpc"), vCfgPath)
		if err != nil {
			_ = os.Remove(vCfgPath)
			_ = d.Stop(inst)
			return fmt.Errorf("frp: visitor frpc: %w", err)
		}
		st.visitorState = &engineInst{proc: visitorProc, stop: make(chan struct{}),
			cfg: vCfgPath, binPath: filepath.Join(binDir, "frpc")}
		go engineSupervise(st.visitorState.stop, st.visitorState, st.visitorState.binPath, st.visitorState.cfg, frpSpawn)
	}
	// Wire accounting is installed on the server side only (the client's
	// control port is shared across instances and cannot be attributed).
	// kcp/quic carriers are UDP sockets — their rules ride the -p udp
	// accounting variant (OVERNIGHT-A). The secret family's DATA port is
	// the visitor bind (stcp=tcp, sudp/xtcp=udp) — both protos get rules
	// with the same comment so acctWireBytes aggregates honestly.
	if role == "server" {
		proto := "tcp"
		if frpUDPCarrier(p.Transport) {
			proto = "udp"
		}
		if err := acctWireRulesAddProto(acctChainsDriver, inst.TunnelID, p.AllowMin, p.AllowMax, proto); err != nil {
			// Data plane still runs; counters become Unknown honestly.
			fmt.Fprintf(os.Stderr, "frp: wire accounting unavailable: %v\n", err)
		}
		if frpSecretProxy(p.ProxyType) {
			udpProto := "udp"
			if strings.EqualFold(strings.TrimSpace(p.ProxyType), "stcp") {
				udpProto = "tcp"
			}
			if err := acctWireRulesAddProto(acctChainsDriver, inst.TunnelID, p.RemotePort, p.RemotePort, udpProto); err != nil {
				fmt.Fprintf(os.Stderr, "frp: visitor accounting unavailable: %v\n", err)
			}
		}
		// OVERNIGHT-A3 vhost family: the vhost ports ARE the data ports
		// (the client's proxy rides them; frps routes by domain).
		if frpVhostProxy(p.ProxyType) {
			for _, vp := range frpVhostPorts(p) {
				if err := acctWireRulesAddProto(acctChainsDriver, inst.TunnelID, vp, vp, "tcp"); err != nil {
					fmt.Fprintf(os.Stderr, "frp: vhost accounting unavailable: %v\n", err)
				}
			}
		}
	}
	return nil
}

// frpVhostPorts lists the vhost ports this tunnel's proxy type rides.
func frpVhostPorts(p frpParams) []int {
	switch strings.ToLower(strings.TrimSpace(p.ProxyType)) {
	case "http":
		if p.VhostHTTPPort > 0 {
			return []int{p.VhostHTTPPort}
		}
	case "https":
		if p.VhostHTTPSPort > 0 {
			return []int{p.VhostHTTPSPort}
		}
	case "tcpmux":
		if p.TCPMuxPort > 0 {
			return []int{p.TCPMuxPort}
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
		// OVERNIGHT-A2: the visitor frpc dies BEFORE its rules are torn
		// down (stop channel first — same no-resurrection discipline).
		if vs := st.visitorState; vs != nil {
			close(vs.stop)
			frpProcStop(vs.current())
			if vs.cfg != "" {
				_ = os.Remove(vs.cfg)
			}
		}
		if st.role == "server" {
			proto := "tcp"
			if frpUDPCarrier(st.params.Transport) {
				proto = "udp"
			}
			_ = acctWireRulesDelProto(acctChainsDriver, inst.TunnelID, st.params.AllowMin, st.params.AllowMax, proto)
			if frpSecretProxy(st.params.ProxyType) {
				udpProto := "udp"
				if strings.EqualFold(strings.TrimSpace(st.params.ProxyType), "stcp") {
					udpProto = "tcp"
				}
				_ = acctWireRulesDelProto(acctChainsDriver, inst.TunnelID, st.params.RemotePort, st.params.RemotePort, udpProto)
			}
			if frpVhostProxy(st.params.ProxyType) {
				for _, vp := range frpVhostPorts(st.params) {
					_ = acctWireRulesDelProto(acctChainsDriver, inst.TunnelID, vp, vp, "tcp")
				}
			}
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
		// OVERNIGHT-A2: the visitor frpc is part of the instance — dead
		// visitor = unhealthy (the public port disappears with it).
		if vs := st.visitorState; vs != nil {
			select {
			case <-vs.current().Done():
				return engine.Health{OK: false, Detail: "visitor frpc exited", LatencyMs: -1}
			default:
			}
		}
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
	if rx, tx, ok := acctWireBytes(inst.TunnelID, st.params.AllowMin, st.params.AllowMax); ok {
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
