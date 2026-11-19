package agent

// Traffic of tunnels that have no interface of their own: the CARRIER END
// discovery that feeds the iptables accounting layer in acct.go
// (REFACTOR-PLAN-AGENT §6.A2 moved the chain render/load/drop/parse
// machinery — the QUANTUM_ACCT_* namespace — there; this file keeps the
// per-family discovery quirks that are genuinely carrier-specific).
//
// GRE tunnels are counted from /proc/net/dev. Backhaul and Bagher run over the
// public interface, where their bytes are mixed with everything else the
// server does, so the dashboard chart showed nothing (or the whole NIC) for
// them. They are counted with iptables instead: two filter chains,
// QUANTUM_ACCT_IN (jumped to from INPUT) and QUANTUM_ACCT_OUT (from OUTPUT),
// hold one rule without a target per carrier port. Such a rule only counts;
// every packet goes on through the firewall unchanged.
//
// Rules match on the default-route interface only, so a Backhaul that runs
// inside GRE (gre-backhaul) is not counted twice: its packets use the GRE
// interface, which /proc/net/dev already counts. IPv4 only.

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// carrierKey is the pseudo interface the counters are filed under in the
// traffic ledger (no real interface name contains '@').
const carrierKey = "@carrier"

// carrierEnd is one tunnel connection end this server takes part in.
type carrierEnd struct {
	Port   int
	Remote string // the IPv4 this server dials; "" when it listens on Port
	From   string // listening: count only this peer's IPv4 (sshd also serves logins)
	UDP    bool   // also count UDP on the port (Backhaul udp transport, UDP companion)
	// Tag is the tunnel the end belongs to: its Backhaul unit
	// ("backhaul-server-3", the UDP companion files under it too) or
	// "bagher-N" for Bagher link N. Per-link speeds and usage read it.
	Tag string
}

func (e carrierEnd) key() acctKey {
	if e.Remote != "" {
		return acctKey{Port: e.Port, Peer: e.Remote}
	}
	return acctKey{Listen: true, Port: e.Port, Peer: e.From}
}

// backhaulTag is the unit a Backhaul config belongs to: config.toml and
// server.toml are backhaul-server, client.toml backhaul-client, server-3.toml
// backhaul-server-3; a UDP companion's config is udp/<unit>.toml.
func backhaulTag(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), ".toml")
	if filepath.Base(filepath.Dir(path)) == "udp" {
		if rest, ok := strings.CutPrefix(base, "backhaul-udp-"); ok { // named after the companion unit
			return "backhaul-" + rest
		}
		return base
	}
	switch base {
	case "config", "server":
		return "backhaul-server"
	case "client":
		return "backhaul-client"
	}
	return "backhaul-" + base
}

// carrierConfigs lists the Backhaul configs on this server: the main ones, the
// peer and hub ones next to them, and the UDP companions.
func carrierConfigs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] && fileExists(p) {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, c := range staleConfigCandidates() {
		if strings.HasPrefix(c.svc, "backhaul") {
			add(c.path)
		}
	}
	for _, pat := range []string{filepath.Join(backhaulDir, "*.toml"), filepath.Join(backhaulDir, "udp", "*.toml")} {
		m, _ := filepath.Glob(pat)
		for _, p := range m {
			add(p)
		}
	}
	sort.Strings(out)
	return out
}

// carrierLookup resolves a dialled host name; swappable for tests.
var carrierLookup = func(host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

var carrierDNS = struct {
	sync.Mutex
	m map[string]carrierDNSEntry
}{m: map[string]carrierDNSEntry{}}

type carrierDNSEntry struct {
	ip string
	at time.Time
}

// carrierIP is host as an IP address: an IPv6 literal stays IPv6, a name is
// resolved like carrierIPv4.
func carrierIP(host string) string {
	if h := normHost(host); isV6(h) {
		return net.ParseIP(h).String()
	}
	return carrierIPv4(host)
}

// carrierIPv4 is host as an IPv4 address ("" for IPv6 or a name that does not
// resolve). Names are looked up at most every 10 minutes.
func carrierIPv4(host string) string {
	host = normHost(host)
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ""
	}
	if host == "" {
		return ""
	}
	carrierDNS.Lock()
	e, ok := carrierDNS.m[host]
	carrierDNS.Unlock()
	if ok && time.Since(e.at) < 10*time.Minute {
		return e.ip
	}
	ip := carrierLookup(host)
	carrierDNS.Lock()
	carrierDNS.m[host] = carrierDNSEntry{ip, time.Now()}
	carrierDNS.Unlock()
	return ip
}

// carrierEnds reads every Backhaul config, the Bagher config and the Xray links.
func carrierEnds() []carrierEnd {
	var ends []carrierEnd
	for _, p := range carrierConfigs() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		tag := backhaulTag(p)
		for _, e := range backhaulCarrierEnd(parseBackhaulConf(string(data))) {
			e.Tag = tag
			ends = append(ends, e)
		}
	}
	sshFwdMu.Lock()
	cfg := loadSSHFwdConfigLocked()
	sshFwdMu.Unlock()
	ends = append(ends, bagherCarrierEnds(cfg)...)
	ends = append(ends, xrayCarrierEnds()...)
	return dedupeEnds(ends)
}

// bagherCarrierEnds are Bagher's SSH connections: on Iran one per foreign
// server it dials, on the foreign server its sshd port for the Iran server
// only (the same sshd also serves admin logins). The check used to want
// role "client", which Bagher never has, so its traffic was never counted.
func bagherCarrierEnds(cfg SSHFwdConfig) []carrierEnd {
	if !cfg.Enabled || strings.TrimSpace(cfg.RemoteHost) == "" {
		return nil
	}
	port := func(p int) int {
		if p > 0 {
			return p
		}
		return 22
	}
	if cfg.Role == "foreign" || cfg.Role == "server" {
		if ip := carrierIP(cfg.RemoteHost); ip != "" {
			return []carrierEnd{{Port: port(cfg.RemoteSSHPort), From: ip, Tag: "bagher-1"}}
		}
		return nil
	}
	var ends []carrierEnd
	if ip := carrierIP(cfg.RemoteHost); ip != "" {
		ends = append(ends, carrierEnd{Port: port(cfg.RemoteSSHPort), Remote: ip, Tag: "bagher-1"})
	}
	for _, l := range cfg.Links {
		p := l.RemoteSSHPort
		if p <= 0 {
			p = cfg.RemoteSSHPort
		}
		if ip := carrierIP(l.RemoteHost); ip != "" {
			ends = append(ends, carrierEnd{Port: port(p), Remote: ip, Tag: fmt.Sprintf("bagher-%d", l.ID)})
		}
	}
	return ends
}

// backhaulCarrierEnd is the end a Backhaul config makes: it listens on the
// port of bind_addr (server) or dials remote_addr (client).
func backhaulCarrierEnd(c backhaulConf) []carrierEnd {
	if c.BindAddr != "" {
		if _, p, err := net.SplitHostPort(c.BindAddr); err == nil {
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
				return []carrierEnd{{Port: n, UDP: true}}
			}
		}
	}
	if c.RemoteAddr != "" {
		if h, p, err := net.SplitHostPort(c.RemoteAddr); err == nil {
			n, err := strconv.Atoi(p)
			if ip := carrierIP(h); err == nil && n > 0 && n <= 65535 && ip != "" {
				return []carrierEnd{{Port: n, Remote: ip, UDP: true}}
			}
		}
	}
	return nil
}

// dedupeEnds keeps one end per counted connection (the first tag wins: two
// rules for the same packets would count them twice).
func dedupeEnds(ends []carrierEnd) []carrierEnd {
	seen := map[acctKey]int{}
	var out []carrierEnd
	for _, e := range ends {
		if i, ok := seen[e.key()]; ok {
			out[i].UDP = out[i].UDP || e.UDP
			continue
		}
		seen[e.key()] = len(out)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Remote != out[j].Remote {
			return out[i].Remote < out[j].Remote
		}
		return out[i].From < out[j].From
	})
	return out
}
