package agent

// More than one foreign server on one Iran server with Bagher. Link 1 is the
// foreign server of the original setup (SSHFwdConfig's own fields); links 2+
// are SSHFwdConfig.Links. Every link has its own carrier unit and SSH session
// to its foreign server, and all of them reach the same frps on Iran. Each
// foreign server's frpc registers its own ports there, so the ports of two
// links must not overlap (frp proxy names are p<port>/u<port>).
//
// REFACTOR-PLAN-AGENT §6.A3: the INTERACTIVE layer (add/remove links, port
// clash checks, unit install/stop, the unit migrations — 13 funcs,
// deadcode-RTA-unreachable from main; their HTTP entry points lived in the
// purged legacy handler layer) is deleted. The STATUS/VIEW layer below stays:
// sshfwd.go's live snapshot/bundle paths call bagherLinksStatus,
// bagherProxiesOnline, bagherLinkUp, bagherCarrierRTT, staleBagherLinkUnits,
// bagherLinkCfg and bagherLinkUnit.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// BagherLink is one foreign server after the first.
type BagherLink struct {
	ID            int    `json:"id"`
	RemoteHost    string `json:"remote_host"`
	RemoteUser    string `json:"remote_user,omitempty"`
	RemoteSSHPort int    `json:"remote_ssh_port,omitempty"`
	Ports         []int  `json:"ports"`
	UDP           bool   `json:"udp,omitempty"`
}

// bagherLinkUnit is the carrier unit name of link id.
func bagherLinkUnit(id int) string {
	if id <= 1 {
		return "quantum-bagher"
	}
	return fmt.Sprintf("quantum-bagher-%d", id)
}

// bagherLinkCfg is cfg as seen by link id: its host, SSH port, user, ports
// and UDP in the top-level fields, for the bundle and the setup commands.
func bagherLinkCfg(cfg SSHFwdConfig, l BagherLink) SSHFwdConfig {
	c := cfg
	c.RemoteHost, c.Ports, c.UDP = l.RemoteHost, l.Ports, l.UDP
	if l.RemoteSSHPort > 0 {
		c.RemoteSSHPort = l.RemoteSSHPort
	}
	if l.RemoteUser != "" {
		c.RemoteUser = l.RemoteUser
	}
	c.Links = nil
	return c
}

// staleBagherLinkUnits lists carrier units beyond the currently configured
// links (left over from removed links).
func staleBagherLinkUnits(keep map[string]bool) []string {
	matches, _ := filepath.Glob("/etc/systemd/system/quantum-bagher-*.service")
	var out []string
	for _, m := range matches {
		b := filepath.Base(m)
		var n int
		if _, err := fmt.Sscanf(b, "quantum-bagher-%d.service", &n); err == nil && n > 1 && !keep[b] {
			out = append(out, b)
		}
	}
	sort.Strings(out)
	return out
}

// bagherHostRe accepts an IP address or a DNS name, nothing that could break
// out of a unit file or a command line.
var bagherHostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// validBagherHost accepts an IP address or a DNS name. §6.A3 note: kept —
// carrier.go's handleCarrierPost set_wss validation (driven by the live
// TestCarrierSetWSSPortAndSNI) uses it; the dead link-add path went.
func validBagherHost(h string) bool {
	return net.ParseIP(h) != nil || bagherHostRe.MatchString(h)
}

// bagherPortOwner reports which link (or link 1) claims port p. §6.A3 note:
// xray.go's dead xrayClaimedPorts — that file being purged next in this
// stage — still compiles against it.
func bagherPortOwner(cfg SSHFwdConfig, p, skip int) int {
	if skip != 1 {
		for _, q := range cfg.Ports {
			if q == p {
				return 1
			}
		}
	}
	for _, l := range cfg.Links {
		if l.ID == skip {
			continue
		}
		for _, q := range l.Ports {
			if q == p {
				return l.ID
			}
		}
	}
	return 0
}

// bagherProxiesOnline asks the Iran frps which proxies are online
// (name -> online); ok is false when its dashboard does not answer.
func bagherProxiesOnline(cfg SSHFwdConfig) (map[string]bool, bool) {
	out := map[string]bool{}
	client := &http.Client{Timeout: 400 * time.Millisecond}
	got := false
	for _, typ := range []string{"tcp", "udp"} {
		req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/api/proxy/%s", cfg.FRPBindPort+1, typ), nil)
		if err != nil {
			continue
		}
		req.SetBasicAuth(frpDashboardUser, frpDashboardPass())
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		var body struct {
			Proxies []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"proxies"`
		}
		if resp.StatusCode == 200 && json.NewDecoder(resp.Body).Decode(&body) == nil {
			got = true
			for _, p := range body.Proxies {
				out[p.Name] = p.Status == "online"
			}
		}
		_ = resp.Body.Close()
	}
	return out, got
}

// bagherLinkUp reports whether any of the link's ports is registered online.
func bagherLinkUp(online map[string]bool, ports []int) bool {
	for _, p := range ports {
		if online[fmt.Sprintf("p%d", p)] {
			return true
		}
	}
	return false
}

// bagherCarrierRTT is the carrier's last measured tunnel ping, if fresh.
func bagherCarrierRTT(cfg SSHFwdConfig, id int) (float64, bool) {
	alive := time.Duration(cfg.ServerAliveInterval) * time.Second
	if alive <= 0 {
		alive = 10 * time.Second
	}
	st, ok := readBagherCarrierStatus(id, 3*alive+5*time.Second)
	if !ok || !st.Connected || st.RTTMs <= 0 {
		return 0, false
	}
	return st.RTTMs, true
}

// bagherLinksStatus is the per-link view for the Tunnel tab; withBundle adds
// each link's bundle (the full status only: it looks up the public IP).
func bagherLinksStatus(cfg SSHFwdConfig, pubKey string, withBundle bool) []map[string]any {
	if len(cfg.Links) == 0 {
		return []map[string]any{}
	}
	online, gotProxies := bagherProxiesOnline(cfg)
	res := make([]map[string]any, 0, len(cfg.Links))
	for _, l := range cfg.Links {
		out, _ := runCmd("systemctl", "is-active", bagherLinkUnit(l.ID)+".service")
		active := strings.TrimSpace(out) == "active"
		rtt, _ := bagherCarrierRTT(cfg, l.ID)
		connected := active && gotProxies && bagherLinkUp(online, l.Ports)
		m := map[string]any{
			"id": l.ID, "remote_host": l.RemoteHost, "ports": l.Ports, "udp": l.UDP,
			"remote_ssh_port": l.RemoteSSHPort, "remote_user": l.RemoteUser,
			"is_active": active, "connected": connected, "latency_ms": rtt,
			"unit": bagherLinkUnit(l.ID), "name": fmt.Sprintf("bagher-%d", l.ID),
		}
		if st, ok := readBagherCarrierStatus(l.ID, 24*time.Hour); ok && st.Error != "" && !st.Connected {
			m["last_error"] = st.Error
		}
		if withBundle && pubKey != "" {
			m["bundle"], _ = MakeBagherBundle(bagherLinkCfg(cfg, l), pubKey)
		}
		res = append(res, m)
	}
	return res
}
