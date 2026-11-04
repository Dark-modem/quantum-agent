// detect.go — Detect stage. DetectedState is the snapshot every plan diffs
// against and every journal stores for rollback. It is fully JSON-
// serializable so the panel can display it 1:1.

package hardening

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DetectedState is what hardening observed on this host at one point.
type DetectedState struct {
	At int64 `json:"at"`

	Firewall FirewallState `json:"firewall"`
	SSH      SSHState      `json:"ssh"`
	Sysctl   SysctlState   `json:"sysctl"`
	Fail2Ban Fail2BanState `json:"fail2ban"`
	TimeSync TimeSyncState `json:"timesync"`
	Logging  LoggingState  `json:"logging"`
	Keys     SSHKeysState  `json:"keys"`
}

// FirewallState is the ufw view (the only firewall backend hardening
// manages; other backends are reported, never touched).
type FirewallState struct {
	Backend          string   `json:"backend"` // "ufw" | "iptables" | "nftables" | "none"
	UfwActive        bool     `json:"ufw_active"`
	DefaultIncoming  string   `json:"default_incoming,omitempty"` // "deny"|"allow"|"reject"|""
	DefaultOutgoing  string   `json:"default_outgoing,omitempty"` // same
	RawRules         string   `json:"raw_rules,omitempty"`        // ufw status numbered, for the audit trail
	Ours             []string `json:"ours,omitempty"`             // rules tagged quantum:hardening:<owner>
	ReasonNotManaged string   `json:"reason_not_managed,omitempty"`
}

// SSHState is the effective sshd policy: the owned drop-in (if any) plus
// what the host answers with.
type SSHState struct {
	DropInPresent bool   `json:"drop_in_present"`
	DropInContent string `json:"drop_in_content,omitempty"`
	// Effective ports from `ss -tlnp` on sshd listeners (best effort).
	ListeningPorts []int  `json:"listening_ports,omitempty"`
	ServiceActive  bool   `json:"service_active"`
	Reason         string `json:"reason,omitempty"` // detection problems, shown to the operator
}

// SysctlState is the current value of every key a profile might touch.
type SysctlState struct {
	// Values maps sysctl key -> current kernel value ("" = unreadable).
	Values map[string]string `json:"values"`
	// NetoptOwned lists keys already owned by the netopt drop-in.
	NetoptOwned []string `json:"netopt_owned,omitempty"`
}

// Fail2BanState is presence + which jail drop-ins exist.
type Fail2BanState struct {
	Installed   bool `json:"installed"`
	Active      bool `json:"active"`
	OurJailPath bool `json:"our_jail_present"`
}

// TimeSyncState is whether NTP is active (any daemon timedatectl knows).
type TimeSyncState struct {
	NTPActive bool   `json:"ntp_active"`
	Detail    string `json:"detail,omitempty"`
}

// LoggingState is the journald persistence bit.
type LoggingState struct {
	PersistentJournal bool `json:"persistent_journal"`
	DropInPresent     bool `json:"drop_in_present"`
}

// SSHKeysState is the key-only guard input: whether at least one authorized
// public key exists (and for which users), so key-only is never enforced
// blind.
type SSHKeysState struct {
	AnyKeyPresent bool     `json:"any_key_present"`
	Users         []string `json:"users,omitempty"` // users with a parseable key
}

// Detect captures the current state. It is read-only: any failure to read a
// subsystem is recorded in the state (Reason/empty values), never fatal —
// the plan layer decides what is safe given partial information.
func Detect(ctx context.Context) *DetectedState {
	s := &DetectedState{At: nowUnix()}
	s.Firewall = detectFirewall(ctx)
	s.SSH = detectSSH(ctx)
	s.Sysctl = detectSysctl()
	s.Fail2Ban = detectFail2Ban(ctx)
	s.TimeSync = detectTimeSync(ctx)
	s.Logging = detectLogging()
	s.Keys = detectAuthorizedKeys()
	return s
}

// ---- firewall ----

const hardeningCommentTag = "quantum:hardening:"

func detectFirewall(ctx context.Context) FirewallState {
	var f FirewallState
	out, err := run(ctx, "ufw", "status", "verbose")
	if err != nil || strings.TrimSpace(string(out)) == "" {
		f.Backend, f.ReasonNotManaged = firewallBackendFallback(ctx)
		return f
	}
	f.Backend = "ufw"
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "Status:"):
			f.UfwActive = strings.Contains(t, "active") && !strings.Contains(t, "inactive")
		case strings.HasPrefix(t, "Default:"):
			f.DefaultIncoming, f.DefaultOutgoing = parseUfwDefaults(t)
		}
	}
	f.RawRules = ufwNumbered(ctx)
	f.Ours = ufwOurRules(f.RawRules)
	return f
}

// firewallBackendFallback reports what else is installed, purely
// informationally: hardening only manages ufw.
func firewallBackendFallback(ctx context.Context) (backend, reason string) {
	if _, err := run(ctx, "iptables", "-S"); err == nil {
		return "iptables", "ufw not active; iptables present — firewall profile items are not managed by hardening on this host (tunnel/service ports remain the firewall engine's job)"
	}
	if _, err := run(ctx, "nft", "list", "tables"); err == nil {
		return "nftables", "ufw not active; native nftables present — hardening never edits a foreign nftables ruleset"
	}
	return "none", "no firewall tool answered; rule items cannot be applied (install ufw or let the installer enable it)"
}

// parseUfwDefaults reads "Default: deny (incoming), allow (outgoing), disabled (routed)".
func parseUfwDefaults(line string) (in, out string) {
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		fields := strings.Fields(part)
		if len(fields) < 2 {
			continue
		}
		switch {
		case strings.HasSuffix(part, "(incoming)"):
			in = fields[1] // fields[0] is the literal "Default:" on the first part
		case strings.HasSuffix(part, "(outgoing)"):
			out = fields[1]
		}
	}
	return in, out
}

func ufwNumbered(ctx context.Context) string {
	out, err := run(ctx, "ufw", "status", "numbered")
	if err != nil {
		return ""
	}
	return string(out)
}

// ufwOurRules extracts the tagged rules from `ufw status numbered` so the
// plan can diff Quantum-owned state without touching foreign rules.
func ufwOurRules(raw string) []string {
	var ours []string
	for _, line := range strings.Split(raw, "\n") {
		if strings.Contains(line, hardeningCommentTag) {
			ours = append(ours, strings.TrimSpace(line))
		}
	}
	return ours
}

// ---- ssh ----

func detectSSH(ctx context.Context) SSHState {
	var s SSHState
	if b, err := readFile(sshDropInPath); err == nil {
		s.DropInPresent = true
		s.DropInContent = string(b)
	}
	s.ListeningPorts = sshListeningPorts(ctx)
	s.ServiceActive = sshServiceActive(ctx)
	return s
}

// sshListeningPorts parses `ss -tlnp` for sshd listeners. Port 0 entries
// are skipped. Errors are non-fatal (empty list + Detect keeps working).
func sshListeningPorts(ctx context.Context) []int {
	out, err := run(ctx, "ss", "-tlnp")
	if err != nil {
		return nil
	}
	var ports []int
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "sshd") && !strings.Contains(line, "ssh") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Local Address:Port column looks like "0.0.0.0:52587" or "*:22".
		i := strings.LastIndex(fields[3], ":")
		if i < 0 || i+1 >= len(fields[3]) {
			continue
		}
		if p, err := strconv.Atoi(fields[3][i+1:]); err == nil && p > 0 {
			ports = appendUniquePort(ports, p)
		}
	}
	return ports
}

func sshServiceActive(ctx context.Context) bool {
	out, err := run(ctx, "systemctl", "is-active", "ssh")
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		return true
	}
	out, err = run(ctx, "systemctl", "is-active", "sshd")
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// sshServiceName returns the unit name this distro uses ("ssh" on Debian/
// Ubuntu, "sshd" elsewhere).
func sshServiceName(ctx context.Context) string {
	if out, err := run(ctx, "systemctl", "list-unit-files", "ssh.service"); err == nil && strings.Contains(string(out), "ssh.service") {
		return "ssh"
	}
	return "sshd"
}

// ---- sysctl ----

func detectSysctl() SysctlState {
	s := SysctlState{Values: map[string]string{}}
	// Current values are read lazily per key by the planner for keys a
	// profile mentions; here we only capture the netopt-owned key set.
	if b, err := readFile(netoptSysctlPath); err == nil {
		s.NetoptOwned = ownedSysctlKeys(string(b))
	}
	return s
}

// ownedSysctlKeys parses "key = value" lines from a sysctl drop-in.
func ownedSysctlKeys(content string) []string {
	var keys []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			keys = append(keys, strings.TrimSpace(line[:i]))
		}
	}
	return keys
}

// readSysctl reads one key from /proc/sys (no subprocess needed).
func readSysctl(key string) string {
	b, err := readFile(sysctlProcPath(key))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func sysctlProcPath(key string) string {
	return filepath.Join(sysctlProcRoot, strings.ReplaceAll(key, ".", "/"))
}

// ---- fail2ban / timesync / logging / keys ----

func detectFail2Ban(ctx context.Context) Fail2BanState {
	var f Fail2BanState
	if _, err := run(ctx, "fail2ban-client", "version"); err == nil {
		f.Installed = true
	}
	if out, err := run(ctx, "systemctl", "is-active", "fail2ban"); err == nil && strings.TrimSpace(string(out)) == "active" {
		f.Active = true
	}
	_, err := os.Stat(fail2banJailPath)
	f.OurJailPath = err == nil
	return f
}

func detectTimeSync(ctx context.Context) TimeSyncState {
	out, err := run(ctx, "timedatectl", "show", "-p", "NTPActive", "--value")
	if err != nil {
		return TimeSyncState{Detail: "timedatectl unavailable"}
	}
	v := strings.TrimSpace(string(out))
	return TimeSyncState{NTPActive: v == "yes", Detail: v}
}

func detectLogging() LoggingState {
	var l LoggingState
	if _, err := os.Stat(journaldLogDir); err == nil {
		l.PersistentJournal = true
	}
	_, err := os.Stat(journaldDropInPath)
	l.DropInPresent = err == nil
	return l
}

// detectAuthorizedKeys scans the standard authorized_keys locations for at
// least one parseable public key. This is the guard that keeps key-only
// from ever being enforced on a server without a working key path.
func detectAuthorizedKeys() SSHKeysState {
	st := SSHKeysState{}
	seen := map[string]bool{}
	for _, glob := range authorizedKeyGlobs {
		matches, _ := filepath.Glob(glob)
		for _, path := range matches {
			user := authorizedKeysUser(path)
			if user == "" || seen[user] {
				continue
			}
			if hasPublicKey(path) {
				seen[user] = true
				st.Users = append(st.Users, user)
			}
		}
	}
	st.AnyKeyPresent = len(st.Users) > 0
	return st
}

// authorizedKeysUser derives the user from an authorized_keys path of the
// shape .../<user>/.ssh/authorized_keys (works for /root and /home/*).
func authorizedKeysUser(path string) string {
	user := filepath.Base(filepath.Dir(filepath.Dir(path)))
	if user == "" || user == "/" || user == "." {
		return ""
	}
	return user
}

// hasPublicKey reports whether the file contains at least one line that
// looks like an OpenSSH public key (a keytype token we recognize).
func hasPublicKey(path string) bool {
	b, err := readFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			switch fields[0] {
			case "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
				return true
			}
		}
	}
	return false
}

func appendUniquePort(ports []int, p int) []int {
	for _, q := range ports {
		if q == p {
			return ports
		}
	}
	return append(ports, p)
}

func nowUnix() int64 { return timeNow().Unix() }

func planID(prefix string) string {
	return fmt.Sprintf("%s_%d_%s", prefix, nowUnix(), randHex(4))
}
