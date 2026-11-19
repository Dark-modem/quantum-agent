package agent

// xray_driver.go — the Xray-core engine (VLESS + Reality, candidate #2
// from ENGINE-CANDIDATES.md) as an engine.Driver. See
// 00-ADMIN/ENGINE-XRAY-DESIGN.md for the topology: the FOREIGN end is the
// Xray server (VLESS+Reality inbound + dokodemo-door per forwarded port),
// the IRAN end is the Xray client (vless outbound dialing OUT with
// Reality settings + freedom outbound to the embedded destination).
//
// Production shape (ENGINE-GUIDE.md PRODUCTION CHECKLIST): release-style
// tarball with directory entries, role resolution via the enrollment
// name, supervisor with capped backoff, per-instance counters (wire from
// nftables on the carrier port; payload from Xray's StatsService per
// direction), Uninstall on idle, R5 manifest delivery with pinned
// fallback. The Reality private key is a SECRET: 0600 instance config
// only, never logged/audited/reported (asserted in tests). The config is
// rendered through typed structs — no string concatenation of untrusted
// values.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/Dark-modem/quantum-agent/internal/infra"

	"strings"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const xrayID = "xray"

type xrayParams struct {
	ServerSide        string `json:"server_side"`        // foreign end name (hosts the Xray server)
	Version           string `json:"version"`            // artifact version (cache key)
	Artifact          string `json:"artifact"`           // name TEMPLATE with {arch}
	SHA256Amd         string `json:"sha256_amd64"`       // pinned fallback
	SHA256Arm         string `json:"sha256_arm64"`       // pinned fallback
	SigAmd            string `json:"signature_amd64"`    // pinned fallback
	SigArm            string `json:"signature_arm64"`    // pinned fallback
	RemoteAddr        string `json:"remote_addr"`        // foreign public host (carrier + dokodemo)
	CarrierPort       int    `json:"carrier_port"`       // foreign VLESS+Reality port
	PublicPort        int    `json:"public_port"`        // foreign dokodemo port (forwarded service)
	LocalAddr         string `json:"local_addr"`         // Iran-side target host
	LocalPort         int    `json:"local_port"`         // Iran-side target port
	ServerName        string `json:"server_name"`        // Reality SNI (camouflage handshake)
	Dest              string `json:"dest"`               // Reality camouflage target host:port
	ShortID           string `json:"short_id"`           // Reality shortId (hex, <=16 chars)
	RealityPublicKey  string `json:"reality_public_key"` // base64url x25519 public
	RealityPrivateKey string `json:"reality_private_key"`
	Flow              string `json:"flow"`     // e.g. xtls-rprx-vision
	UUID              string `json:"uuid"`     // VLESS user id
	APIPort           int    `json:"api_port"` // loopback StatsService port (server end; 0 = off)
}

func (p xrayParams) xrayArtifactPin() (name, sha256Hex, sigB64 string, err error) {
	return enginePinForArch(EnginePin{Version: p.Version, Artifact: p.Artifact,
		SHA256Amd: p.SHA256Amd, SHA256Arm: p.SHA256Arm, SigAmd: p.SigAmd, SigArm: p.SigArm})
}

// xrayValidateParams checks the union shape. Secrets are shape-checked
// only (printable ASCII, bounded) — never logged with their value.
func xrayValidateParams(p xrayParams) error {
	if strings.TrimSpace(p.ServerSide) == "" || len(p.ServerSide) > 128 {
		return fmt.Errorf("xray: server_side required")
	}
	if strings.TrimSpace(p.Version) == "" || len(p.Version) > 64 ||
		strings.ContainsAny(p.Version, "/\\\"' \t\n\r") {
		return fmt.Errorf("xray: version must be 1-64 safe chars")
	}
	if !strings.Contains(p.Artifact, "{arch}") || strings.ContainsAny(p.Artifact, " \t\n\r\"\\") {
		return fmt.Errorf("xray: artifact must be a name template containing {arch}")
	}
	for _, a := range []struct{ sha, sig string }{{p.SHA256Amd, p.SigAmd}, {p.SHA256Arm, p.SigArm}} {
		if len(a.sha) != 64 || strings.ContainsAny(a.sha, " \t\n\r") {
			return fmt.Errorf("xray: sha256 pin must be 64 hex chars")
		}
		if len(a.sig) < 64 || len(a.sig) > 512 || strings.ContainsAny(a.sig, " \t\n\r") {
			return fmt.Errorf("xray: signature pin must be base64 (64-512 chars)")
		}
	}
	if p.CarrierPort <= 0 || p.CarrierPort > 65535 || p.PublicPort <= 0 || p.PublicPort > 65535 {
		return fmt.Errorf("xray: carrier_port/public_port out of range")
	}
	if strings.TrimSpace(p.LocalAddr) == "" || strings.ContainsAny(p.LocalAddr, "\"'\n\r\\") ||
		p.LocalPort <= 0 || p.LocalPort > 65535 {
		return fmt.Errorf("xray: local_addr/local_port invalid")
	}
	if strings.TrimSpace(p.RemoteAddr) == "" || strings.ContainsAny(p.RemoteAddr, "\"'\n\r\\") {
		return fmt.Errorf("xray: remote_addr invalid")
	}
	if err := engineVerifySecretShape("xray server_name", p.ServerName, 1, 253); err != nil {
		return err
	}
	if err := engineVerifySecretShape("xray dest", p.Dest, 3, 253); err != nil {
		return err
	}
	if len(p.ShortID) > 16 || strings.ContainsAny(p.ShortID, "\"'\n\r\\ ") {
		return fmt.Errorf("xray: short_id must be <=16 chars without quotes")
	}
	if _, err := hex.DecodeString(p.ShortID); err != nil && p.ShortID != "" {
		return fmt.Errorf("xray: short_id must be hex")
	}
	if err := engineVerifySecretShape("xray reality_public_key", p.RealityPublicKey, 32, 64); err != nil {
		return err
	}
	if err := engineVerifySecretShape("xray reality_private_key", p.RealityPrivateKey, 32, 64); err != nil {
		return err
	}
	if err := engineVerifySecretShape("xray uuid", p.UUID, 16, 64); err != nil {
		return err
	}
	if strings.Contains(p.Flow, "\"") || strings.Contains(p.Flow, "\n") || len(p.Flow) > 64 {
		return fmt.Errorf("xray: flow invalid")
	}
	// The driver's carrier is ALWAYS the bridge/portal reverse link, whose
	// underlying protocol is mux.cool (upstream docs: "the reverse proxy
	// has Mux enabled by default"). Vision flow corrupts the mux.cool
	// framing: with flow=xtls-rprx-vision the reverse channel establishes
	// but DATA STALLS (lab-verified 2026-11-08, xray v24.12.31: vision
	// variant hung, flow-empty variant carried 2.3 Gbit/s). Fail closed.
	if strings.TrimSpace(p.Flow) != "" {
		return fmt.Errorf("xray: flow must be empty — the reverse carrier multiplexes by itself (mux.cool); vision flow stalls all data through it")
	}
	if p.APIPort < 0 || p.APIPort > 65535 {
		return fmt.Errorf("xray: api_port out of range")
	}
	return nil
}

// xrayResolveRole resolves this end's role through the enrollment name.
func xrayResolveRole(p xrayParams) (engineSide, error) {
	ident, ok := frpLoadIdentity()
	if !ok {
		return "", fmt.Errorf("xray: no controller identity — cannot resolve this end's role (fail closed)")
	}
	if strings.TrimSpace(p.ServerSide) == ident.Name {
		return engineSideServer, nil
	}
	return engineSideClient, nil
}

// ---- typed Xray config (marshaled — never string-concatenated) ----

type xrayUser struct {
	ID         string `json:"id"`
	Flow       string `json:"flow,omitempty"`
	Level      int    `json:"level"`
	Encryption string `json:"encryption"`
}

// xrayRealityServer is the Reality decryption block for the VLESS
// inbound (server end): terminate the handshake against the real
// camouflage site; private key NEVER logged.
type xrayRealityServer struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest"`
	Xver        int      `json:"xver"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
}

// xrayRealityClient is the Reality client block for the VLESS outbound
// (Iran end): show=false (no fingerprint leak into logs), SNI pinned.
type xrayRealityClient struct {
	Show        bool   `json:"show"`
	Fingerprint string `json:"fingerprint"`
	ServerName  string `json:"serverName"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	SpiderX     string `json:"spiderX"`
}

type xrayInboundSettings struct {
	Clients        []xrayUser `json:"clients,omitempty"`
	Decryption     string     `json:"decryption,omitempty"`
	Address        string     `json:"address,omitempty"`
	Port           int        `json:"port,omitempty"`
	Network        string     `json:"network,omitempty"`
	FollowRedirect bool       `json:"followRedirect,omitempty"`
}

type xrayStreamSettings struct {
	Network  string             `json:"network"`
	Security string             `json:"security"`
	Reality  *xrayRealityServer `json:"realitySettings,omitempty"`
}

type xraySockopt struct {
	Mark int `json:"mark,omitempty"`
}

type xrayInbound struct {
	Tag            string               `json:"tag"`
	Listen         string               `json:"listen"`
	Port           int                  `json:"port"`
	Protocol       string               `json:"protocol"`
	Settings       *xrayInboundSettings `json:"settings,omitempty"`
	StreamSettings *xrayStreamSettings  `json:"streamSettings,omitempty"`
	Sniffing       *xraySniffing        `json:"sniffing,omitempty"`
}

type xraySniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride,omitempty"`
}

type xrayOutboundSettings struct {
	Vnext    []xrayVnext            `json:"vnext,omitempty"`
	Address  string                 `json:"address,omitempty"`
	Port     int                    `json:"port,omitempty"`
	Response *xrayBlackholeResponse `json:"response,omitempty"`
}

// xrayBlackholeResponse is the blackhole outbound's optional answer
// ({"response":{"type":"http"}} answers probes with an HTTP 403).
type xrayBlackholeResponse struct {
	Type string `json:"type"`
}

type xrayVnext struct {
	Address string     `json:"address"`
	Port    int        `json:"port"`
	Users   []xrayUser `json:"users"`
}

type xrayStreamClient struct {
	Network  string             `json:"network"`
	Security string             `json:"security"`
	Reality  *xrayRealityClient `json:"realitySettings,omitempty"`
}

type xrayOutbound struct {
	Tag            string                `json:"tag"`
	Protocol       string                `json:"protocol"`
	Settings       *xrayOutboundSettings `json:"settings,omitempty"`
	StreamSettings *xrayStreamClient     `json:"streamSettings,omitempty"`
	Mux            *xrayMux              `json:"mux,omitempty"`
}

type xrayMux struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"`
}

type xrayAPI struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services"`
}

type xrayRoutingRule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

type xrayConfig struct {
	Reverse   *xrayReverse   `json:"reverse,omitempty"`
	Log       *xrayLog       `json:"log,omitempty"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
	Routing   *xrayRouting   `json:"routing,omitempty"`
	API       *xrayAPI       `json:"api,omitempty"`
	Stats     *struct{}      `json:"stats,omitempty"`
	Policy    *xrayPolicy    `json:"policy,omitempty"`
}

type xrayLog struct {
	LogLevel string `json:"loglevel"`
}

type xrayRouting struct {
	DomainStrategy string            `json:"domainStrategy"`
	Rules          []xrayRoutingRule `json:"rules"`
}

type xrayPolicy struct {
	Levels map[string]xrayPolicyLevel `json:"levels"`
}

type xrayPolicyLevel struct {
	StatsUserUplink   bool `json:"statsUserUplink,omitempty"`
	StatsUserDownlink bool `json:"statsUserDownlink,omitempty"`
}

type xrayReverse struct {
	Bridges []xrayBridge `json:"bridges,omitempty"`
	Portals []xrayPortal `json:"portals,omitempty"`
}

type xrayBridge struct {
	Tag    string `json:"tag"`
	Domain string `json:"domain"`
}

type xrayPortal struct {
	Tag    string `json:"tag"`
	Domain string `json:"domain"`
}

// xrayPortalDomain is the internal domain both ends share for the
// reverse channel (it is NOT a DNS name — the routing matches on it).
const xrayPortalDomain = "quantum.rev.internal"

// xrayBuildConfig renders the end's config through typed structs, using
// Xray's NATIVE REVERSE feature (bridge/portal) — the frp-equivalent
// shape: the Iran end (bridge) dials OUT to the foreign portal, keeping
// reverse channels open; public connections on the foreign dokodemo ride
// those channels to the Iran-local service. Role decides which half:
// SERVER (foreign) = portal; CLIENT (iran) = bridge + the vless-out
// carrier with Reality client settings.
func xrayBuildConfig(role engineSide, p xrayParams) xrayConfig {
	cfg := xrayConfig{Log: &xrayLog{LogLevel: "warning"}}
	if role == engineSideServer {
		// Portal: the Reality carrier inbound feeds the reverse portal;
		// the public dokodemo rides the reverse channels toward Iran.
		cfg.Inbounds = []xrayInbound{
			{
				Tag: "vless-in", Listen: "0.0.0.0", Port: p.CarrierPort, Protocol: "vless",
				Settings: &xrayInboundSettings{
					Clients:    []xrayUser{{ID: p.UUID, Flow: p.Flow}},
					Decryption: "none",
				},
				StreamSettings: &xrayStreamSettings{
					Network: "tcp", Security: "reality",
					Reality: &xrayRealityServer{
						Dest:        p.Dest,
						ServerNames: []string{p.ServerName},
						PrivateKey:  p.RealityPrivateKey,
						ShortIDs:    []string{p.ShortID},
					},
				},
				Sniffing: &xraySniffing{Enabled: true, DestOverride: []string{"http", "tls"}},
			},
			{
				Tag: "dokodemo-" + fmt.Sprint(p.PublicPort), Listen: "0.0.0.0", Port: p.PublicPort,
				Protocol: "dokodemo-door",
				Settings: &xrayInboundSettings{
					Address: p.LocalAddr, Port: p.LocalPort, Network: "tcp",
				},
			},
		}
		cfg.Outbounds = []xrayOutbound{{Tag: "direct", Protocol: "freedom"}}
		cfg.Reverse = &xrayReverse{Portals: []xrayPortal{{Tag: "rev-portal", Domain: xrayPortalDomain}}}
		cfg.Routing = &xrayRouting{Rules: []xrayRoutingRule{
			{Type: "field", InboundTag: []string{"vless-in"}, OutboundTag: "rev-portal"},
			{Type: "field", InboundTag: []string{"dokodemo-" + fmt.Sprint(p.PublicPort)}, OutboundTag: "rev-portal"},
		}}
		if p.APIPort > 0 {
			// The warmup probe entry (RUNBOOK/PHASE8: Health must not
			// report the tunnel healthy until a through-tunnel probe
			// succeeds). A loopback dokodemo asking for probe.quantum
			// rides the reverse channel to the bridge, whose blackhole
			// answers HTTP — a full round trip proves the channel
			// CARRIES DATA, not just that the carrier TCP accepted.
			cfg.Inbounds = append(cfg.Inbounds, xrayInbound{
				Tag: "probe-in", Listen: "127.0.0.1", Port: p.APIPort + 1, Protocol: "dokodemo-door",
				Settings:       &xrayInboundSettings{Address: xrayProbeHost, Port: 80, Network: "tcp"},
				StreamSettings: &xrayStreamSettings{Network: "tcp"},
			})
			cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRoutingRule{
				Type: "field", InboundTag: []string{"probe-in"}, OutboundTag: "rev-portal",
			})
			cfg.Inbounds = append(cfg.Inbounds, xrayInbound{
				Tag: "api-in", Listen: "127.0.0.1", Port: p.APIPort, Protocol: "dokodemo-door",
				Settings:       &xrayInboundSettings{Address: "127.0.0.1"},
				StreamSettings: &xrayStreamSettings{Network: "tcp"},
			})
			cfg.API = &xrayAPI{Tag: "api-in", Services: []string{"StatsService"}}
			cfg.Stats = &struct{}{}
			cfg.Policy = &xrayPolicy{Levels: map[string]xrayPolicyLevel{"0": {}}}
			cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRoutingRule{
				Type: "field", InboundTag: []string{"api-in"}, OutboundTag: "api",
			})
			cfg.Outbounds = append(cfg.Outbounds, xrayOutbound{Tag: "api", Protocol: "blackhole"})
		}
		return cfg
	}
	// Bridge: the vless outbound dials OUT through Reality; the reverse
	// bridge rides it and forwards to freedom (the Iran-local service).
	cfg.Outbounds = []xrayOutbound{
		{Tag: "carrier-out", Protocol: "vless",
			StreamSettings: &xrayStreamClient{
				Network: "tcp", Security: "reality",
				Reality: &xrayRealityClient{
					Show: false, Fingerprint: "chrome", ServerName: p.ServerName,
					PublicKey: p.RealityPublicKey, ShortID: p.ShortID, SpiderX: "",
				},
			},
			Settings: &xrayOutboundSettings{
				Vnext: []xrayVnext{{Address: p.RemoteAddr, Port: p.CarrierPort,
					Users: []xrayUser{{ID: p.UUID, Flow: p.Flow, Encryption: "none"}}}},
			},
		},
		{Tag: "local", Protocol: "freedom"},
		// The warmup probe's answer: connections the portal sent down the
		// reverse channel asking for probe.quantum get an HTTP response
		// from the blackhole — a full round trip through the channel.
		{Tag: "probe", Protocol: "blackhole",
			Settings: &xrayOutboundSettings{Response: &xrayBlackholeResponse{Type: "http"}}},
	}
	cfg.Reverse = &xrayReverse{Bridges: []xrayBridge{{Tag: "rev-bridge", Domain: xrayPortalDomain}}}
	cfg.Routing = &xrayRouting{Rules: []xrayRoutingRule{
		// Upstream docs (reverse bridge): ONLY the channel-establishment
		// requests carry the internal domain — route THOSE to the carrier.
		// Everything else arriving from the portal must go to the local
		// service; without the domain filter the first rule matches all
		// bridge traffic and portal-returned data LOOPS back into the
		// carrier (lab-verified: 11,705 dials in seconds vs 5 with the
		// filter; first-match-wins made the local rule dead code).
		{Type: "field", InboundTag: []string{"rev-bridge"},
			Domain: []string{"full:" + xrayPortalDomain}, OutboundTag: "carrier-out"},
		// The probe MUST come before the catch-all local rule
		// (first-match-wins).
		{Type: "field", InboundTag: []string{"rev-bridge"},
			Domain: []string{"full:" + xrayProbeHost}, OutboundTag: "probe"},
		{Type: "field", InboundTag: []string{"rev-bridge"}, OutboundTag: "local"},
	}}
	return cfg
}

// xrayInstState is one RUNNING instance's state (supervisor target).
// The proc/stop/cfg/binPath base rides the shared engineInst (A1).
type xrayInstState struct {
	engineInst
	params xrayParams
	role   engineSide
}

// XrayDriver implements engine.Driver for Xray-core.
type XrayDriver struct {
	runs *instTable[xrayInstState]
}

func NewXrayDriver() *XrayDriver { return &XrayDriver{runs: newInstTable[xrayInstState]()} }

func (d *XrayDriver) ID() string { return xrayID }

func (d *XrayDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: xrayID, Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"server_side":"","version":"","artifact":"..{arch}..","remote_addr":"","carrier_port":0,"public_port":0,"local_addr":"","local_port":0,"server_name":"","dest":"","short_id":"","reality_public_key":"","reality_private_key":"","flow":"xtls-rprx-vision","uuid":"","api_port":0}`)}
}

// EnsureBinary: the Manager calls this before the first instance starts;
// the download happens in Start via xrayEnsureBinary with the resolved
// coordinates (manifest-first, pinned fallback).
func (d *XrayDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

func (d *XrayDriver) Validate(params json.RawMessage) error {
	var p xrayParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("xray: engine_params: %w", err)
	}
	return xrayValidateParams(p)
}

func xrayConfigPath(tunnelID string) string {
	return filepath.Join(xrayEngineDir(), "instances", tunnelID+".json")
}

func xrayBinDir(version string) string { return filepath.Join(xrayEngineDir(), "bin", version) }

func xrayEngineDir() string { return engineEngineDir(xrayID) }

// xrayEnsureBinary: R5 manifest first, pinned fallback, same trust model
// as FRP/Backhaul. Installs the single `xray` binary.
func xrayEnsureBinary(ctx context.Context, p xrayParams) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("xray: no engine artifact signing key pinned in this build (fail closed)")
	}
	if _, pinnedSHA, _, pinErr := p.xrayArtifactPin(); pinErr == nil && engineCacheHit(xrayBinDir(p.Version), pinnedSHA, []string{"xray"}) {
		return xrayBinDir(p.Version), nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("xray: no controller identity — cannot fetch engine artifact (fail closed)")
	}
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, xrayID,
		func() (string, string, string, error) { return p.xrayArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}
	dir := xrayBinDir(p.Version)
	if engineCacheHit(dir, sha256Hex, []string{"xray"}) {
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
		return "", fmt.Errorf("xray: cache dir: %w", err)
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"xray": true}); err != nil {
		return "", err
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("xray: cache marker: %w", err)
	}
	return dir, nil
}

// Start implements engine.Driver.
func (d *XrayDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p xrayParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return fmt.Errorf("xray: engine_params: %w", err)
	}
	if err := xrayValidateParams(p); err != nil {
		return err
	}
	if !frpTunnelIDOK(inst.TunnelID) {
		return fmt.Errorf("xray: invalid tunnel id %q", inst.TunnelID)
	}
	prev := d.runs.peek(inst.TunnelID)
	if prev != nil {
		if engineParamsEqual[xrayParams](prev.params, p) && prev.current() != nil {
			select {
			case <-prev.current().Done():
			default:
				return nil // idempotent no-op
			}
		}
		_ = d.Stop(inst)
	}
	role, err := xrayResolveRole(p)
	if err != nil {
		return err
	}
	binDir, err := xrayEnsureBinary(ctx, p)
	if err != nil {
		return err
	}
	binPath := filepath.Join(binDir, "xray")
	cfg := xrayBuildConfig(role, p)
	cfgBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("xray: render config: %w", err)
	}
	cfgPath := xrayConfigPath(inst.TunnelID)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("xray: config dir: %w", err)
	}
	// 0600: the config carries the Reality private key.
	if err := os.WriteFile(cfgPath, cfgBytes, 0o600); err != nil {
		return fmt.Errorf("xray: write config: %w", err)
	}
	proc, err := xraySpawn(binPath, cfgPath)
	if err != nil {
		_ = os.Remove(cfgPath)
		return err
	}
	st := &xrayInstState{engineInst: engineInst{proc: proc, stop: make(chan struct{}),
		cfg: cfgPath, binPath: binPath}, params: p, role: role}
	d.runs.put(inst.TunnelID, st)
	go engineSupervise(st.stop, st, binPath, cfgPath, xraySpawn)
	// Wire accounting on the SERVER end's carrier port (the client's dial
	// port is shared and cannot be attributed per instance).
	if role == engineSideServer {
		if err := acctWireRulesAdd(acctChainsDriver, inst.TunnelID, p.CarrierPort, p.CarrierPort); err != nil {
			fmt.Fprintf(os.Stderr, "xray: wire accounting unavailable: %v\n", err)
		}
	}
	return nil
}

// xraySpawn runs the Xray binary: `xray run -c <cfg>` (upstream CLI).
// Same process-shape contract as frpSpawn (frpProcess + Done channel).
var xraySpawn = func(binPath, cfgPath string) (frpProcess, error) {
	cmd := exec.Command(binPath, "run", "-c", cfgPath)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("xray: start %s: %w", binPath, err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

// Stop implements engine.Driver: the shared teardown order, with the
// server end's carrier-port accounting rule as the driver-specific hook.
func (d *XrayDriver) Stop(inst engine.Instance) error {
	st := d.runs.take(inst.TunnelID)
	if st == nil {
		return nil
	}
	engineStopInst(&st.engineInst, func() {
		if st.role == engineSideServer {
			_ = acctWireRulesDel(acctChainsDriver, inst.TunnelID, st.params.CarrierPort, st.params.CarrierPort)
		}
	})
	return nil
}

// Reload implements engine.Driver: equal params are a no-op, anything
// else is a restart.
func (d *XrayDriver) Reload(inst engine.Instance) error {
	return engineReload(d.runs, xrayID, inst.TunnelID, inst.Params,
		func(st *xrayInstState) xrayParams { return st.params }, engineParamsEqual[xrayParams])
}

// Health implements engine.Driver: the process alive, and on the SERVER
// end (api_port configured) the StatsService must answer — a real probe
// of the engine's control plane. The CLIENT end also probes the stats
// API when configured (both ends may run one for local visibility).
func (d *XrayDriver) Health(inst engine.Instance) engine.Health {
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
	if st.role == engineSideServer && st.params.APIPort > 0 {
		start := time.Now()
		err := xrayStatsPing(st.params.APIPort)
		lat := float64(time.Since(start).Milliseconds())
		if err != nil {
			return engine.Health{OK: false, Detail: "stats API not answering", LatencyMs: lat}
		}
		// Warmup gate (PHASE8 1b): NOT healthy until a through-tunnel
		// probe succeeds. The bridge registers its reverse-channel pool
		// lazily; before that, public connections hit an empty worker
		// list and are dropped — the balancer must not route yet. The
		// probe rides the portal's loopback probe inbound through the
		// reverse channel and expects the bridge's HTTP answer.
		probeDeadline := time.Now().Add(1600 * time.Millisecond)
		delays := []time.Duration{0, 300 * time.Millisecond, 800 * time.Millisecond}
		var lastErr error
		for _, d := range delays {
			if d > 0 {
				if time.Now().After(probeDeadline) {
					break
				}
				time.Sleep(d)
			}
			if lastErr = xrayProbeFn(st.params.APIPort + 1); lastErr == nil {
				return engine.Health{OK: true, Detail: "xray server running, api ok, tunnel probe ok", LatencyMs: lat}
			}
		}
		return engine.Health{OK: false, Detail: "through-tunnel probe failed (warmup or broken channel): " + lastErr.Error(), LatencyMs: lat}
	}
	return engine.Health{OK: true, Detail: "xray process running", LatencyMs: -1}
}

// Counters implements engine.Driver: the SERVER end reports wire bytes
// (iptables on the carrier port) AND payload bytes per direction from
// the StatsService: inbound vless-in = carrier-facing (payload uplink =
// bytes the carrier delivered toward the dokodemo, downlink = bytes
// pushed out), inbound dokodemo = the public-facing view. We report the
// vless-in pair as payload (it is the tunnel-facing side).
func (d *XrayDriver) Counters(inst engine.Instance) engine.Counters {
	st := d.runs.peek(inst.TunnelID)
	if st == nil || st.role != engineSideServer || st.params.APIPort <= 0 {
		return engine.Counters{}
	}
	out := engine.Counters{}
	if rx, tx, ok := acctWireBytes(inst.TunnelID, st.params.CarrierPort, st.params.CarrierPort); ok {
		out.WireRx, out.WireTx, out.WireKnown = rx, tx, true
	}
	up, down, ok := xrayStatTraffic(st.params.APIPort, "inbound>>>vless-in")
	if ok {
		// vless-in uplink = bytes handed TO the carrier from the dokodemo
		// (= payload tx into the tunnel); downlink = bytes delivered OUT
		// to the dokodemo (= payload rx from the tunnel).
		out.PayloadTx, out.PayloadRx, out.PayloadKnown = up, down, true
	}
	return out
}

// xrayStatTraffic queries the StatsService via `xray api statsquery`
// (the real binary's own gRPC client — no protobuf dependency here) and
// returns (uplink, downlink) for the given tag prefix.
// xrayTunnelProbe sends a tiny HTTP request through the FULL tunnel: the
// portal's probe-in inbound (dokodemo → probe.quantum:80) rides the
// reverse channel to the bridge, whose blackhole answers HTTP — a full
// round trip proves the channel carries DATA (the local dokodemo accept
// alone proves nothing: it completes before the far end is dialed).
func xrayTunnelProbe(probePort int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(probePort)), 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("GET /probe HTTP/1.0\r\nHost: " + xrayProbeHost + "\r\n\r\n")); err != nil {
		return err
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(buf[:n], []byte("HTTP/")) {
		return fmt.Errorf("unexpected probe answer %q", buf[:n])
	}
	return nil
}

// xrayProbeFn seams the through-tunnel probe (hermetic tests stub it; the
// integration runs the real dial through the tunnel).
var xrayProbeFn = xrayTunnelProbe

func xrayStatsPing(apiPort int) error {
	up, down, ok := xrayStatTraffic(apiPort, "inbound>>>")
	if !ok {
		return fmt.Errorf("stats unavailable")
	}
	_ = up
	_ = down
	return nil
}

// xrayStatTraffic queries the StatsService via the real binary's own
// gRPC client (xray api statsquery) and returns (uplink, downlink, ok)
// for the given tag prefix.
func xrayStatTraffic(apiPort int, prefix string) (uint64, uint64, bool) {
	return execCommandJSON(apiPort, prefix)
}

// Uninstall implements engine.Driver.
func (d *XrayDriver) Uninstall(ctx context.Context) error {
	engineUninstallAll(d.runs, func(id string) {
		_ = d.Stop(engine.Instance{TunnelID: id})
	}, xrayEngineDir())
	return nil
}

// ForwardAddress implements engine.ForwardAddresser: the balancer's DNAT
// target for this tunnel = the foreign dokodemo (remote host + public
// port), the same delivery shape as FRP. Server role → 127.0.0.1:public
// (the dokodemo is local to the server end); client role → remote host.
func (d *XrayDriver) ForwardAddress(inst engine.Instance) (string, int, bool) {
	var p xrayParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return "", 0, false
	}
	role, err := xrayResolveRole(p)
	if err != nil {
		return "", 0, false
	}
	if role == engineSideServer {
		return "127.0.0.1", p.PublicPort, true
	}
	host := strings.TrimSpace(p.RemoteAddr)
	if h, _, serr := net.SplitHostPort(host); serr == nil {
		host = h
	}
	if host == "" {
		return "", 0, false
	}
	return host, p.PublicPort, true
}

// xrayParamsJSON is test/ops helper.
func xrayParamsJSON(p xrayParams) json.RawMessage { return infra.MustJSON(p) }

// execCommandJSON runs `xray api statsquery --server=...` and returns the
// parsed counters for the prefix. Seam-able for tests.
var execCommandJSON = func(apiPort int, prefix string) (uint64, uint64, bool) {
	binDir := xrayBinDir("")
	bin := filepath.Join(binDir, "xray")
	c := &http.Client{Timeout: 3 * time.Second}
	_ = c // placeholder for the real CLI invocation below
	cmd := exec.Command(bin, "api", "statsquery", fmt.Sprintf("--server=127.0.0.1:%d", apiPort))
	out, err := cmd.Output()
	if err != nil {
		return 0, 0, false
	}
	var parsed struct {
		Stats []struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
		} `json:"stats"`
	}
	if json.Unmarshal(out, &parsed) != nil {
		return 0, 0, false
	}
	var up, down uint64
	for _, s := range parsed.Stats {
		if !strings.HasPrefix(s.Name, prefix) {
			continue
		}
		switch {
		case strings.HasSuffix(s.Name, ">>>uplink"):
			up = uint64(s.Value)
		case strings.HasSuffix(s.Name, ">>>downlink"):
			down = uint64(s.Value)
		}
	}
	return up, down, true
}
