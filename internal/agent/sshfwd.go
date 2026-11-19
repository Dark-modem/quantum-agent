package agent

// SSHFwdConfig / Bagher engine: configuration, the portable foreign-setup
// bundle and the live status views.
//
// REFACTOR-PLAN-AGENT §6.A3: the APPLY layer is deleted (deadcode RTA from
// main, 24 funcs: the authorized_keys installers, the systemd unit builders,
// ParseBagherBundle/applyBagherBundle, enable/disable/cleanSSHFwd, the nft
// DNAT conflict cleaner, the legacy HTTP handlers and the full status
// builder — every entry point lived in the purged legacy handler layer).
// What survives is what the reachable graph uses: the config store the
// carrier discovery (acct.go / carrier_traffic.go) reads, MakeBagherBundle
// (the zero-terminal foreign setup), getBagherLiveMetrics and
// getSSHFwdSnapshotStatus (the 5s snapshot), plus the bagher_links.go view
// layer. The x/crypto/ssh import went with the deleted key/unit builders.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// handlePeerSSHFwdInstallKey served the peer-API authorized_keys install.
// §6.A3: the install machinery is deleted; this no-op keeps peerconfig.go's
// dead mountPeerRoutes (out of this stage's named scope) compiling — the
// route was unreachable (mountPeerRoutes has zero callers), so the stub is
// behavior-identical.
func handlePeerSSHFwdInstallKey(w http.ResponseWriter, r *http.Request) {}

// SSHFwdConfig stores configuration for the Bagher Engine / SSH carrier.
type SSHFwdConfig struct {
	Role          string `json:"role"` // "client" (Iran entry) or "server" (Foreign origin)
	Mode          string `json:"mode"` // "bagher" (default stealth hybrid) or "direct" (pure ssh)
	RemoteHost    string `json:"remote_host"`
	RemoteUser    string `json:"remote_user"`
	RemoteSSHPort int    `json:"remote_ssh_port"`
	KeyPath       string `json:"key_path"`
	Ports         []int  `json:"ports"`
	BindAddr      string `json:"bind_addr"`
	FRPBindPort   int    `json:"frp_bind_port"`
	PoolCount     int    `json:"pool_count"`
	UDP           bool   `json:"udp,omitempty"` // Bagher mode: also forward UDP (frp udp proxies); direct SSH cannot
	// Links are the foreign servers after the first (link 1, the fields
	// above). They share the Iran server's frps and SSH key; each has its own
	// carrier unit and its own ports.
	Links               []BagherLink `json:"links,omitempty"`
	Enabled             bool         `json:"enabled"`
	ServerAliveInterval int          `json:"server_alive_interval"`
	ServerAliveCountMax int          `json:"server_alive_count_max"`
	LastStatus          string       `json:"last_status"`
	LastError           string       `json:"last_error"`
	UpdatedAt           string       `json:"updated_at"`
}

var (
	sshFwdMu sync.Mutex
)

func defaultSSHFwdKeyPath() string {
	if os.Geteuid() != 0 || strings.Contains(configDir, "gre-panel-test-") {
		return filepath.Join(configDir, "quantum-fwd")
	}
	return "/root/.ssh/quantum-fwd"
}

func defaultSSHFwdConfig() SSHFwdConfig {
	return SSHFwdConfig{
		Role:                "iran",
		Mode:                "bagher",
		RemoteHost:          "",
		RemoteUser:          "root",
		RemoteSSHPort:       22,
		KeyPath:             defaultSSHFwdKeyPath(),
		Ports:               []int{},
		BindAddr:            "0.0.0.0",
		FRPBindPort:         55400,
		PoolCount:           5,
		Enabled:             false,
		ServerAliveInterval: 15,
		ServerAliveCountMax: 3,
		LastStatus:          "inactive",
		LastError:           "",
		UpdatedAt:           "",
	}
}

func sshFwdConfigFile() string {
	return filepath.Join(configDir, "sshfwd.json")
}

func loadSSHFwdConfigLocked() SSHFwdConfig {
	cfg := defaultSSHFwdConfig()
	b, err := os.ReadFile(sshFwdConfigFile())
	if err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	cfg.Mode = "bagher"
	if cfg.RemoteUser == "" {
		cfg.RemoteUser = "root"
	}
	if cfg.RemoteSSHPort <= 0 {
		cfg.RemoteSSHPort = 22
	}
	if cfg.KeyPath == "" || (os.Geteuid() != 0 && strings.HasPrefix(cfg.KeyPath, "/root")) {
		cfg.KeyPath = defaultSSHFwdKeyPath()
	}
	if cfg.Ports == nil {
		cfg.Ports = []int{}
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0"
	}
	if cfg.FRPBindPort <= 0 {
		cfg.FRPBindPort = 55400
	}
	if cfg.PoolCount <= 0 {
		cfg.PoolCount = 25
	}
	if cfg.ServerAliveInterval <= 0 {
		cfg.ServerAliveInterval = 10
	}
	if cfg.ServerAliveCountMax <= 0 {
		cfg.ServerAliveCountMax = 3
	}
	return cfg
}

// saveSSHFwdConfigLocked writes the sshfwd.json config. §6.A3 note:
// prod-unreachable (the legacy handlers that saved it are deleted);
// traffic_accuracy_test.go uses it to write the fixture config.
func saveSSHFwdConfigLocked(cfg SSHFwdConfig) error {
	cfg.UpdatedAt = time.Now().Format("2006-01-02 15:04:05")
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(sshFwdConfigFile(), b, 0600)
}

type BagherBundle struct {
	Version      int    `json:"v"`
	Role         string `json:"role"`
	IranPub      string `json:"iran_pub"`
	RemoteHost   string `json:"remote_host,omitempty"`
	FRPPort      int    `json:"frp_port"`
	Ports        []int  `json:"ports"`
	Token        string `json:"token"`
	PoolCount    int    `json:"pool_count"`
	UDP          bool   `json:"udp,omitempty"`
	SSHPublicKey string `json:"ssh_pub_key"`
	SSHPort      int    `json:"ssh_port"`
	Timestamp    int64  `json:"ts"`
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ip.IsPrivate() || ip.IsMulticast() // fc00::/7 unique local
	}
	if ip4[0] == 10 {
		return true
	}
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	if ip4[0] == 100 && ip4[1]&0xC0 == 64 { // 100.64.0.0/10 carrier-grade NAT
		return true
	}
	return false
}

// resolvePublicIP is detectPublicIP, which now skips private addresses and
// caches its external lookup itself.
func resolvePublicIP() string {
	return detectPublicIP()
}

// MakeBagherBundle builds a portable encrypted/base64 string for zero-terminal Foreign setup.
// It requires both remote host IP and forwarded ports to be set before generating a bundle.
func MakeBagherBundle(cfg SSHFwdConfig, pubKey string) (string, error) {
	if len(cfg.Ports) == 0 {
		return "", fmt.Errorf("forwarded ports are required before generating bundle")
	}
	if strings.TrimSpace(cfg.RemoteHost) == "" {
		return "", fmt.Errorf("remote host IP is required before generating bundle")
	}
	iranIP := resolvePublicIP()
	if isV6(cfg.RemoteHost) { // the link runs over IPv6: the foreign server sees this one's IPv6
		if v6 := detectPublicIP6(); v6 != "" {
			iranIP = v6
		}
	}
	if iranIP == "" || iranIP == "0.0.0.0" {
		iranIP = cfg.BindAddr
	}
	b := BagherBundle{
		Version:      1,
		Role:         "foreign",
		IranPub:      iranIP,
		RemoteHost:   strings.TrimSpace(cfg.RemoteHost),
		FRPPort:      cfg.FRPBindPort,
		Ports:        cfg.Ports,
		Token:        frpAuthToken(),
		PoolCount:    cfg.PoolCount,
		UDP:          cfg.UDP,
		SSHPublicKey: strings.TrimSpace(pubKey),
		SSHPort:      cfg.RemoteSSHPort,
		Timestamp:    time.Now().Unix(),
	}
	data, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return "BAGHER:" + base64.StdEncoding.EncodeToString(data), nil
}

func formatByteSize(b int64) string {
	if b <= 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

type BagherLiveMetrics struct {
	Connected      bool    `json:"connected"`
	StatusText     string  `json:"status_text"`
	LatencyMs      float64 `json:"latency_ms"`
	RxBytes        int64   `json:"rx_bytes"`
	TxBytes        int64   `json:"tx_bytes"`
	TotalBytes     int64   `json:"total_bytes"`
	RxFormatted    string  `json:"rx_formatted"`
	TxFormatted    string  `json:"tx_formatted"`
	TotalFormatted string  `json:"total_formatted"`
	CurConns       int     `json:"cur_conns"`
	ClientCounts   int     `json:"client_counts"`
}

func getBagherLiveMetrics(cfg SSHFwdConfig) BagherLiveMetrics {
	isForeign := cfg.Role == "foreign" || cfg.Role == "server"
	if !isForeign {
		outFrpc, _ := runCmd("systemctl", "is-active", "quantum-bagher-frpc.service")
		if strings.TrimSpace(outFrpc) == "active" {
			isForeign = true
		}
	}

	if isForeign {
		outFrpc, _ := runCmd("systemctl", "is-active", "quantum-bagher-frpc.service")
		if strings.TrimSpace(outFrpc) != "active" {
			return BagherLiveMetrics{Connected: false, StatusText: "inactive", RxFormatted: "0 B", TxFormatted: "0 B", TotalFormatted: "0 B"}
		}

		// Dial 127.0.0.1:FRPBindPort (SSH reverse forward to Iran)
		t0 := time.Now()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.FRPBindPort), 600*time.Millisecond)
		var lat float64
		connected := false
		statusText := "waiting_for_iran"
		if err == nil {
			lat = float64(time.Since(t0).Microseconds()) / 1000.0
			_ = conn.Close()
			connected = true
			statusText = "connected"
		}

		return BagherLiveMetrics{
			Connected:      connected,
			StatusText:     statusText,
			LatencyMs:      lat,
			RxFormatted:    "0 B",
			TxFormatted:    "0 B",
			TotalFormatted: "0 B",
			ClientCounts:   1,
		}
	}

	// Iran side
	outBagher, _ := runCmd("systemctl", "is-active", "quantum-bagher.service")
	outFrps, _ := runCmd("systemctl", "is-active", "quantum-bagher-frps.service")
	bagherActive := strings.TrimSpace(outBagher) == "active"
	frpsActive := strings.TrimSpace(outFrps) == "active"

	if !bagherActive && !frpsActive {
		return BagherLiveMetrics{Connected: false, StatusText: "inactive", RxFormatted: "0 B", TxFormatted: "0 B", TotalFormatted: "0 B"}
	}

	// The carrier's keepalive round trip is the tunnel's own ping; a TCP
	// connect to the SSH port is only the path's, used until it reports.
	lat, _ := bagherCarrierRTT(cfg, 1)
	if lat <= 0 && cfg.RemoteHost != "" {
		remoteSSHPort := cfg.RemoteSSHPort
		if remoteSSHPort <= 0 {
			remoteSSHPort = 22
		}
		tRemote := time.Now()
		rConn, rErr := net.DialTimeout("tcp", hostPort(cfg.RemoteHost, remoteSSHPort), 600*time.Millisecond)
		if rErr == nil {
			lat = float64(time.Since(tRemote).Microseconds()) / 1000.0
			_ = rConn.Close()
		}
	}
	if lat <= 0 {
		t0 := time.Now()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.FRPBindPort), 400*time.Millisecond)
		if err == nil {
			lat = float64(time.Since(t0).Microseconds()) / 1000.0
			_ = conn.Close()
		}
	}

	dashPort := cfg.FRPBindPort + 1
	dashURL := fmt.Sprintf("http://127.0.0.1:%d/api/serverinfo", dashPort)
	client := &http.Client{Timeout: 400 * time.Millisecond}
	req, err := http.NewRequest("GET", dashURL, nil)
	var rx, tx int64
	var clientCount, curConns int
	gotDashboard := false
	if err == nil {
		req.SetBasicAuth(frpDashboardUser, frpDashboardPass())
		resp, rErr := client.Do(req)
		if rErr == nil && resp.StatusCode == 200 {
			var info struct {
				TotalTrafficIn  int64 `json:"totalTrafficIn"`
				TotalTrafficOut int64 `json:"totalTrafficOut"`
				CurConns        int   `json:"curConns"`
				ClientCounts    int   `json:"clientCounts"`
			}
			if json.NewDecoder(resp.Body).Decode(&info) == nil {
				rx = info.TotalTrafficIn
				tx = info.TotalTrafficOut
				curConns = info.CurConns
				clientCount = info.ClientCounts
				gotDashboard = true
			}
			_ = resp.Body.Close()
		}
	}

	connected := false
	statusText := "waiting_for_peer"
	if online, ok := bagherProxiesOnline(cfg); ok && len(cfg.Links) > 0 {
		// several foreign servers share this frps: link 1 is up when its own
		// ports are registered, not when any frpc is connected
		if bagherLinkUp(online, cfg.Ports) {
			connected = true
			statusText = "connected"
		}
	} else if gotDashboard {
		if clientCount > 0 {
			connected = true
			statusText = "connected"
		}
	} else {
		outSS, _ := runCmd("ss", "-tn", "state", "established", fmt.Sprintf("sport = :%d or dport = :%d", cfg.FRPBindPort, cfg.FRPBindPort))
		lines := strings.Split(strings.TrimSpace(outSS), "\n")
		if len(lines) > 1 {
			connected = true
			statusText = "connected"
			clientCount = 1
		}
	}

	tot := rx + tx
	return BagherLiveMetrics{
		Connected:      connected,
		StatusText:     statusText,
		LatencyMs:      lat,
		RxBytes:        rx,
		TxBytes:        tx,
		TotalBytes:     tot,
		RxFormatted:    formatByteSize(rx),
		TxFormatted:    formatByteSize(tx),
		TotalFormatted: formatByteSize(tot),
		CurConns:       curConns,
		ClientCounts:   clientCount,
	}
}

// bagherUnitNames are every unit name Bagher (or its predecessors) used.
var bagherUnitNames = []string{"quantum-bagher", "quantum-bagher-frpc", "quantum-bagher-frps", "quantum-ssh-fwd", "quantum-frp-ssh-tunnel"}

// bagherUnitInstalled reports whether any Bagher unit file exists (no fork).
func bagherUnitInstalled() bool {
	// Adopt legacy hashem-bagher* units from a pre-rebrand install so status
	// and control keep working after an in-place update. Once per unit.
	for _, n := range bagherUnitNames {
		legacyUnitMigration(n + ".service")
	}
	for _, n := range bagherUnitNames {
		if _, err := os.Stat(filepath.Join("/etc/systemd/system", n+".service")); err == nil {
			return true
		}
	}
	return len(staleBagherLinkUnits(nil)) > 0
}

// getSSHFwdSnapshotStatus is the cheap status the 5s snapshot collects (M9).
// The legacy full status also created the SSH key (ssh-keygen on every
// server, Bagher or not) and built the bundle, which looks up the public IP
// over HTTP; neither belongs in a 5-second loop. Without any Bagher config or
// unit nothing is run at all.
func getSSHFwdSnapshotStatus() map[string]any {
	sshFwdMu.Lock()
	defer sshFwdMu.Unlock()
	cfg := loadSSHFwdConfigLocked()
	configured := cfg.Enabled || (strings.TrimSpace(cfg.RemoteHost) != "" && len(cfg.Ports) > 0) || bagherUnitInstalled()
	if !configured {
		return map[string]any{"has_config": false, "enabled": false, "is_active": false, "connected": false}
	}
	isActive := false
	for _, n := range bagherUnitNames {
		if out, _ := runCmd("systemctl", "is-active", n+".service"); strings.TrimSpace(out) == "active" {
			isActive = true
			break
		}
	}
	metrics := getBagherLiveMetrics(cfg)
	return map[string]any{
		"links":           bagherLinksStatus(cfg, "", false),
		"name":            linkLabel("bagher-1"),
		"has_config":      true,
		"enabled":         cfg.Enabled || isActive,
		"is_active":       isActive,
		"mode":            cfg.Mode,
		"role":            cfg.Role,
		"remote_host":     cfg.RemoteHost,
		"ports":           cfg.Ports,
		"udp":             cfg.UDP,
		"frp_bind_port":   cfg.FRPBindPort,
		"last_error":      cfg.LastError,
		"connected":       metrics.Connected,
		"status_text":     metrics.StatusText,
		"latency_ms":      metrics.LatencyMs,
		"rx_bytes":        metrics.RxBytes,
		"tx_bytes":        metrics.TxBytes,
		"total_bytes":     metrics.TotalBytes,
		"rx_formatted":    metrics.RxFormatted,
		"tx_formatted":    metrics.TxFormatted,
		"total_formatted": metrics.TotalFormatted,
		"cur_conns":       metrics.CurConns,
		"client_counts":   metrics.ClientCounts,
	}
}
