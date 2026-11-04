package agent

// Peer-link configuration for the standalone agent, ported from the
// controller monolith (panel/peer.go @ a1e999c). The agent keeps its own
// peer_link.json under its config dir: when it enrolls against a peer
// (setup.go, master/worker flows) the role and shared secret persist
// here, and the legacy peer-API client paths (carrier_swap.go,
// tunnel.go) read them back.
//
// Deliberate deviation from the monolith: there is no defaultPeerConfig
// with a freshly generated secret. An unset field stays empty so every
// peer-API path fails closed until the operator (or controller) enrolls
// the link; the monolith's default path was panel-host specific
// (currentLocal(), cfg.Port) and has no meaning on a standalone agent.

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// peerRoutePrefix serves the peer API at a fixed path, independent of each
// panel's random base path, which the other side cannot know. Requests there
// must carry the peer secret; anything else gets a plain 404 so the prefix
// does not reveal the panel.
const peerRoutePrefix = "/_hp"

// PeerConfig is one peer-link record (ported verbatim from the monolith).
type PeerConfig struct {
	Role               string  `json:"role"`          // "master" (Iran) or "worker" (Kharej)
	PeerSecret         string  `json:"peer_secret"`   // Shared secret token for inter-panel authentication
	PeerURL            string  `json:"peer_url"`      // Public URL of peer, e.g. "http://5.6.7.8:8080"
	InternalIP         string  `json:"internal_ip"`   // Tunnel internal IP, e.g. "10.10.10.1"
	InternalPort       int     `json:"internal_port"` // Panel port on internal IP (default 8080)
	LastSync           string  `json:"last_sync"`     // Timestamp of last successful handshake/sync
	IsConnected        bool    `json:"is_connected"`
	LatencyMs          float64 `json:"latency_ms"`
	AutoPilotEnabled   bool    `json:"autopilot_enabled"`
	AutoPilotExplicit  bool    `json:"autopilot_explicit,omitempty"`
	AutoPilotThreshold float64 `json:"autopilot_threshold"`       // Packet loss percentage threshold (e.g. 20.0)
	TLSFingerprint     string  `json:"tls_fingerprint,omitempty"` // Pinned SHA-256 (hex) of the peer's leaf TLS cert (TOFU)
	// PeerBasePath is the peer panel's own random base path (each panel has a
	// different one), learned from the handshake or from a pasted panel URL.
	// Only needed to reach peers that predate the fixed peerRoutePrefix.
	PeerBasePath string `json:"peer_base_path,omitempty"`
}

var (
	peerMu sync.RWMutex
)

func peerConfigFile() string {
	return filepath.Join(configDir, "peer_link.json")
}

func loadPeerConfig() PeerConfig {
	peerMu.RLock()
	c, needsSave := readPeerConfig()
	peerMu.RUnlock()

	if needsSave {
		_ = savePeerConfig(c)
	}
	return c
}

// readPeerConfig reads peer_link.json. Caller holds peerMu.
func readPeerConfig() (PeerConfig, bool) {
	data, err := os.ReadFile(peerConfigFile())
	if err != nil {
		return PeerConfig{}, false
	}
	var c PeerConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return PeerConfig{}, false
	}

	needsSave := false
	// Migration: disable AutoPilot on existing configs so tunnels do not
	// switch automatically. AutoPilot was previously true by default,
	// causing unwanted tunnel flap/switching.
	if !c.AutoPilotExplicit {
		c.AutoPilotEnabled = false
		c.AutoPilotExplicit = true
		needsSave = true
	}
	return c, needsSave
}

func savePeerConfig(c PeerConfig) error {
	peerMu.Lock()
	defer peerMu.Unlock()
	return writePeerConfig(c)
}

// updatePeerConfig applies fn to the current peer_link.json under one lock.
// Background status updates use it so they only touch their own fields: a
// copy loaded before a multi-second peer call would otherwise overwrite a
// secret or URL the admin saved in the meantime.
func updatePeerConfig(fn func(c *PeerConfig)) error {
	peerMu.Lock()
	defer peerMu.Unlock()
	c, _ := readPeerConfig()
	fn(&c)
	return writePeerConfig(c)
}

// writePeerConfig persists c atomically. Caller holds peerMu.
func writePeerConfig(c PeerConfig) error {
	_ = os.MkdirAll(configDir, 0700)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := peerConfigFile() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, peerConfigFile())
}

// markPeerSeen records that the peer just reached us.
func markPeerSeen() {
	_ = updatePeerConfig(func(c *PeerConfig) {
		c.IsConnected = true
		c.LastSync = time.Now().Format("2006-01-02 15:04:05")
	})
}

// PeerApplyEngineRequest asks the peer host to switch its tunnel engine
// (ported verbatim from the controller monolith peer.go).
type PeerApplyEngineRequest struct {
	Engine    string `json:"engine"`    // "frp", "backhaul", "gre-backhaul"
	Transport string `json:"transport"` // "tcpmux", "tcp", "ws", "wss"
}

// peerPinMu serializes TOFU pin updates (ported verbatim).
var peerPinMu sync.Mutex

// peerTLSConfig builds the peer TLS configuration with TOFU pinning of
// the peer's leaf certificate (ported verbatim from the monolith
// peer.go: verify by sha256 fingerprint, first-seen pins, mismatch
// fails closed).
func peerTLSConfig(c *PeerConfig) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // verification is done by VerifyPeerCertificate below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("peer presented no TLS certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])

			peerPinMu.Lock()
			defer peerPinMu.Unlock()
			pinned := strings.ToLower(strings.TrimSpace(c.TLSFingerprint))
			if pinned == "" {
				c.TLSFingerprint = got
				if err := updatePeerConfig(func(p *PeerConfig) { p.TLSFingerprint = got }); err != nil {
					log.Printf("peer TLS pin: cannot persist fingerprint: %v", err)
				}
				return nil
			}
			if subtle.ConstantTimeCompare([]byte(pinned), []byte(got)) != 1 {
				return fmt.Errorf("peer TLS certificate fingerprint mismatch: pinned %s, got %s (possible MITM or peer cert changed; clear tls_fingerprint to re-pin)", pinned, got)
			}
			return nil
		},
	}
}

// peerTargetURLs lists the URLs to try for a peer API path, best first:
// the fixed peer prefix (works without knowing the peer's base path), then
// the peer's own base path when known, on the tunnel IP and then the public URL.
// (Ported verbatim from the monolith peer.go; effectiveTLSPort is the
// agent-side stub below.)
func peerTargetURLs(c PeerConfig, path string) []string {
	cleanPath := "/" + strings.TrimLeft(path, "/")
	prefixes := []string{peerRoutePrefix}
	if bp := strings.Trim(c.PeerBasePath, "/"); bp != "" {
		prefixes = append(prefixes, "/"+bp)
	} else if bp := strings.Trim(cfg.BasePath, "/"); bp != "" {
		// Legacy fallback for old peers installed with the same base path.
		prefixes = append(prefixes, "/"+bp)
	}

	var bases []string
	if c.InternalIP != "" {
		ports := []int{}
		if c.InternalPort > 0 {
			ports = append(ports, c.InternalPort)
		}
		if cfg.Port > 0 && cfg.Port != c.InternalPort {
			ports = append(ports, cfg.Port)
		}
		for _, p := range ports {
			bases = append(bases, "http://"+hostPort(c.InternalIP, p))
		}
	}
	if c.PeerURL != "" {
		u := strings.TrimRight(c.PeerURL, "/")
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			u = "http://" + u
		}
		if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
			host := parsed.Hostname()
			if parsed.Port() != "" {
				bases = append(bases, parsed.Scheme+"://"+parsed.Host)
			} else {
				seen := map[int]bool{}
				for _, p := range []int{c.InternalPort, cfg.Port, effectiveTLSPort(), 7443, 7777, 8080} {
					if p > 0 && !seen[p] {
						seen[p] = true
						bases = append(bases, parsed.Scheme+"://"+hostPort(host, p))
					}
				}
			}
		}
	}

	var out []string
	for _, b := range bases {
		for _, pre := range prefixes {
			out = append(out, b+pre+cleanPath)
		}
	}
	return out
}

// peerHandshake announces this host to its peer and records the peer's
// base path and panel port (ported verbatim from the monolith peer.go;
// it goes through sendToPeer, which is a no-op shim on the agent until a
// real peer link is configured).
func peerHandshake(role, internalIP string) error {
	resp, err := sendToPeer("/api/peer/handshake", "POST", PeerHandshakeRequest{
		Role:       role,
		PublicIP:   detectPublicIP(),
		PanelPort:  cfg.Port,
		InternalIP: internalIP,
		BasePath:   strings.Trim(cfg.BasePath, "/"),
	})
	if err != nil {
		return err
	}
	var hs struct {
		BasePath  string `json:"base_path"`
		PanelPort int    `json:"panel_port"`
	}
	if json.Unmarshal(resp, &hs) == nil {
		_ = updatePeerConfig(func(c *PeerConfig) {
			if bp := strings.Trim(hs.BasePath, "/"); bp != "" {
				c.PeerBasePath = bp
			}
			if hs.PanelPort > 0 && hs.PanelPort <= 65535 {
				c.InternalPort = hs.PanelPort
			}
		})
	}
	return nil
}

// requirePeerAuth authenticates peer API requests with the shared peer
// link secret (agent adaptation of the monolith peer.go middleware: no
// admin sessions exist on the agent, so the cookie path is gone).
func requirePeerAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := loadPeerConfig()
		if c.PeerSecret == "" {
			writeAPIError(w, r, "E-AUTH-01", "peer link secret unconfigured")
			return
		}
		clientSecret := strings.TrimSpace(r.Header.Get("X-Peer-Secret"))
		if clientSecret == "" {
			authHdr := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(authHdr), "bearer ") {
				clientSecret = strings.TrimSpace(authHdr[7:])
			}
		}
		if clientSecret == "" || !ConstantTimeCompare(c.PeerSecret, clientSecret) {
			LogSecurityAudit("peer_auth_rejected", "peer", ClientIP(r), "path="+r.URL.Path)
			writeAPIError(w, r, "E-AUTH-01", "invalid peer secret")
			return
		}
		next(w, r)
	}
}

// requirePeerSecretHidden guards the fixed peerRoutePrefix routes: only the
// peer secret is accepted, and every failure is a bare 404 so scanners
// cannot tell the prefix belongs to a panel (ported verbatim from the
// monolith peer.go).
func requirePeerSecretHidden(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := loadPeerConfig()
		got := strings.TrimSpace(r.Header.Get("X-Peer-Secret"))
		if got == "" {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
				got = strings.TrimSpace(h[7:])
			}
		}
		if c.PeerSecret == "" || got == "" || !ConstantTimeCompare(c.PeerSecret, got) {
			if got != "" {
				LogSecurityAudit("peer_auth_rejected", "peer", ClientIP(r), "path="+r.URL.Path)
			}
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

// mountPeerRoutes registers the peer API the agent serves, under base
// (the panel's base path) and under the fixed peerRoutePrefix. Agent
// adaptation of the monolith peer.go version: it mounts only the
// handlers this tree carries (no handshake/apply-carrier/engine/ping/
// status/wrap surface — those flows are controller-driven via the WSS
// protocol now).
func mountPeerRoutes(mux *http.ServeMux, base string) {
	routes := []struct {
		method, path string
		h            http.HandlerFunc
	}{
		{"POST", "/api/peer/revpath-probe", handlePeerRevPathProbe},
		{"POST", "/api/peer/sshfwd-install-key", handlePeerSSHFwdInstallKey},
		{"POST", "/api/peer/swap-carrier", handlePeerSwapCarrier},
		{"GET", "/api/peer/swap-status", handlePeerSwapStatus},
		{"GET", "/api/peer/swap-request", handlePeerSwapRequestGet},
		{"POST", "/api/peer/swap-request", handlePeerSwapRequest},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.method+" "+base+rt.path, requirePeerAuth(rt.h))
		guard := requirePeerSecretHidden
		switch rt.path {
		case "/api/peer/swap-request":
			// A peer's foreign server knows its own tunnel token, not the
			// Peer Link secret: it may still ask for a swap of its tunnel.
			guard = requireTunnelSecretHidden
		}
		mux.HandleFunc(rt.method+" "+peerRoutePrefix+rt.path, guard(rt.h))
	}
	mux.HandleFunc("GET "+peerRoutePrefix+"/api/peer/rescue-offer", requireRescuePeerHidden(handlePeerRescueOffer))
	mux.HandleFunc("POST "+peerRoutePrefix+"/api/peer/rescue-ack", requireRescuePeerHidden(handlePeerRescueAck))
	// Anything else under the prefix (other paths, wrong methods) is a plain
	// 404 rather than the catch-all redirect or a 405 that would reveal routes.
	mux.HandleFunc(peerRoutePrefix+"/", http.NotFound)
}
