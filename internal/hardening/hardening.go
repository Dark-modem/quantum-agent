// Package hardening turns server security + network optimization into
// declarative PROFILES (data, not shell scripts) that the Quantum panel can
// push to agent servers as desired state, with safe-apply + automatic
// rollback so an operator can never be locked out of SSH.
//
// Contract (per profile item): Detect -> Plan (diff) -> Apply -> Verify ->
// Revert. Every apply records a journal with per-step undo commands and the
// captured before-state; rollback restores exactly that. Nothing here edits
// another system's files (ufw before.rules, sshd_config itself, resolv.conf)
// and the forbidden operations of the firewall engine (reset, flush, enable/
// disable, foreign ruleset edits) are forbidden here too.
//
// The module owns these drop-ins and no others:
//
//	/etc/ssh/sshd_config.d/00-quantum-hardening.conf   (additive sshd config; 00- prefix wins the first-value-wins race against vendor drop-ins like 01-arvan-*)
//	/etc/sysctl.d/99-quantum-hardening.conf            (does not collide with
//	                                                    netopt's 99-quantum-netopt.conf)
//	/etc/fail2ban/jail.d/quantum-hardening.local
//	/etc/systemd/journald.conf.d/99-quantum-persistent.conf
//
// and this state directory: /var/lib/quantum-agent/hardening (journals,
// rollback scripts). All paths are vars so hermetic tests redirect them.
//
// SAFE-APPLY is mandatory for anything that can cut SSH or remote access:
// both the current and the new SSH port are opened in the firewall BEFORE
// sshd is reloaded, a real SSH banner is dialed on the new port, and a
// systemd-run timer (default 120 s) arms an automatic rollback that fires
// unless the panel confirms the apply. See safeapply.go.
//
// This package is wired into the protocol by the contract session; the
// proposed message shapes are documented in docs/HARDENING.md and the
// entry point is Dispatch (api.go).
package hardening

import (
	"fmt"
	"strings"
)

// ProfileVersion is the schema version of the Profile type.
const ProfileVersion = 1

// Profile is one declarative hardening desired-state document. It is fully
// JSON-serializable (the panel sends it, the agent stores it) and every
// field is optional in effect: a nil/empty field means "leave as-is", so a
// profile can tighten one subsystem without re-stating the others.
type Profile struct {
	Version  int           `json:"version"` // must be ProfileVersion
	Name     string        `json:"name"`    // operator-facing id, e.g. "base-hardened"
	Firewall *FirewallSpec `json:"firewall,omitempty"`
	SSH      *SSHSpec      `json:"ssh,omitempty"`
	Sysctl   []SysctlRule  `json:"sysctl,omitempty"`
	TimeSync *TimeSyncSpec `json:"timesync,omitempty"`
	Logging  *LoggingSpec  `json:"logging,omitempty"`
}

// FirewallSpec manages ufw policies and Quantum-owned allow/limit rules.
// Only ADDITIVE rule management is supported: hardening never resets,
// enables, disables or flushes the firewall (the firewall engine owns the
// enable decision; the installer pre-opens SSH before enabling).
type FirewallSpec struct {
	// DefaultDenyIncoming nil = leave current policy alone; true = "ufw
	// default deny incoming"; false = explicitly allow incoming (rarely
	// wanted; safe-apply refuses it while SSH hardening is in the same plan).
	DefaultDenyIncoming *bool `json:"default_deny_incoming,omitempty"`
	// AllowOutgoing nil = leave; true = "ufw default allow outgoing".
	AllowOutgoing *bool `json:"allow_outgoing,omitempty"`

	// Allows are plain allow rules; Limits are rate-limited allows
	// (ufw limit: >=6 connections in 30 s from one IP are dropped). Limits
	// are intended for SSH. Every rule carries an Owner tag so teardown
	// removes exactly what the profile added.
	Allows []PortRule `json:"allows,omitempty"`
	Limits []PortRule `json:"limits,omitempty"`
}

// PortRule is one firewall allow (or rate-limited allow).
type PortRule struct {
	Port  int    `json:"port"`           // 1-65535
	Proto string `json:"proto"`          // "tcp" | "udp"
	From  string `json:"from,omitempty"` // "" = any source, else one CIDR/IP
	Owner string `json:"owner"`          // no quotes/whitespace, e.g. "profile:base", "service:ssh", "tunnel:at_ab12"
	Note  string `json:"note,omitempty"` // audit description only
}

// SSHSpec is the additive sshd policy written to the owned drop-in.
type SSHSpec struct {
	// Port 0 = leave the current listener(s) alone. Any other value adds a
	// listener on that port (sshd Port directives accumulate, so the old
	// port keeps answering until the base config is edited by hand — the
	// removal is intentionally NOT automated; docs/HARDENING.md explains).
	Port int `json:"port,omitempty"`
	// KeyOnly nil = leave; true = PasswordAuthentication no +
	// KbdInteractiveAuthentication no + PermitEmptyPasswords no. Refused
	// (plan item blocked) unless a public key is verified present for at
	// least one user, or for root when root stays the only admin.
	KeyOnly *bool `json:"key_only,omitempty"`
	// PermitRoot "" = leave; "no" | "prohibit-password" | "yes".
	PermitRoot string `json:"permit_root,omitempty"`
	// MaxAuthTries 0 = leave (1-10 otherwise).
	MaxAuthTries int `json:"max_auth_tries,omitempty"`
	// Fail2Ban nil = leave; Enabled installs the owned jail drop-in.
	Fail2Ban *Fail2BanSpec `json:"fail2ban,omitempty"`
}

// Fail2BanSpec is the sshd jail managed by the owned drop-in.
type Fail2BanSpec struct {
	Enabled     bool `json:"enabled"`
	MaxRetry    int  `json:"maxretry,omitempty"`     // default 5
	FindTimeSec int  `json:"findtime_sec,omitempty"` // default 600
	BanTimeSec  int  `json:"bantime_sec,omitempty"`  // default 3600
}

// SysctlRule is one kernel key with its desired value. Keys owned by the
// netopt engine's drop-in are skipped (delegated), never fought over.
type SysctlRule struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// TimeSyncSpec keeps time sane (tunnel handshakes and cert validation care).
type TimeSyncSpec struct {
	// EnsureActive enables (never installs) systemd-timesyncd.
	EnsureActive bool `json:"ensure_active"`
}

// LoggingSpec is the logging baseline.
type LoggingSpec struct {
	// PersistentJournal stores the journal under /var/log/journal so
	// post-mortems survive reboots.
	PersistentJournal bool `json:"persistent_journal"`
}

// Validate checks a profile before it may reach a plan.
func (p Profile) Validate() error {
	if p.Version != ProfileVersion {
		return fmt.Errorf("profile version %d not supported (want %d)", p.Version, ProfileVersion)
	}
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 64 || strings.ContainsAny(p.Name, "\"'`$\\ \t\n") {
		return fmt.Errorf("profile name must be 1-64 safe characters")
	}
	if p.Firewall != nil {
		for i, r := range append(append([]PortRule{}, p.Firewall.Allows...), p.Firewall.Limits...) {
			if err := r.validate(); err != nil {
				return fmt.Errorf("firewall rule %d: %v", i, err)
			}
		}
	}
	if p.SSH != nil {
		if err := p.SSH.validate(); err != nil {
			return err
		}
	}
	for i, s := range p.Sysctl {
		if !sysctlKeyRe.MatchString(s.Key) {
			return fmt.Errorf("sysctl rule %d: invalid key %q", i, s.Key)
		}
		if len(s.Value) > 256 || strings.ContainsAny(s.Value, "\n\r`") {
			return fmt.Errorf("sysctl rule %d: invalid value for %s", i, s.Key)
		}
	}
	return nil
}

func (r PortRule) validate() error {
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("port %d out of range", r.Port)
	}
	if r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("proto must be tcp or udp, got %q", r.Proto)
	}
	if r.From != "" && !cidrRe.MatchString(r.From) {
		return fmt.Errorf("from must be empty (any) or a CIDR/IP, got %q", r.From)
	}
	if strings.TrimSpace(r.Owner) == "" || strings.ContainsAny(r.Owner, "\"' \t") {
		return fmt.Errorf("owner must be a non-empty string without quotes or whitespace")
	}
	return nil
}

func (s SSHSpec) validate() error {
	if s.Port != 0 && (s.Port < 1 || s.Port > 65535) {
		return fmt.Errorf("ssh port %d out of range", s.Port)
	}
	switch s.PermitRoot {
	case "", "no", "prohibit-password", "yes":
	default:
		return fmt.Errorf("ssh permit_root must be no, prohibit-password or yes, got %q", s.PermitRoot)
	}
	if s.MaxAuthTries != 0 && (s.MaxAuthTries < 1 || s.MaxAuthTries > 10) {
		return fmt.Errorf("ssh max_auth_tries must be 0 (leave) or 1-10")
	}
	if s.Fail2Ban != nil {
		if s.Fail2Ban.MaxRetry != 0 && (s.Fail2Ban.MaxRetry < 1 || s.Fail2Ban.MaxRetry > 100) {
			return fmt.Errorf("fail2ban maxretry out of range")
		}
		if s.Fail2Ban.FindTimeSec != 0 && (s.Fail2Ban.FindTimeSec < 30 || s.Fail2Ban.FindTimeSec > 604800) {
			return fmt.Errorf("fail2ban findtime_sec out of range")
		}
		if s.Fail2Ban.BanTimeSec != 0 && (s.Fail2Ban.BanTimeSec < 30 || s.Fail2Ban.BanTimeSec > 2592000) {
			return fmt.Errorf("fail2ban bantime_sec out of range")
		}
	}
	return nil
}

// Conservative went in §6.A3 (deadcode RTA: unreachable from main — the
// installers' conservative profile is rendered by quantum.sh itself and the
// panel forwards operator hardening JSON opaquely, so no reachable path
// builds it here; the panel's own netProfileConservative is netopt's
// separate surface).
