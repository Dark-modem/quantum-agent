// fail2ban.go — the owned fail2ban sshd jail drop-in. Additive jail.d
// drop-in only; the package's own config is never edited.

package hardening

import (
	"fmt"
	"strconv"
)

// RenderFail2BanJail renders the owned jail drop-in. The port follows the
// profile's SSH port when one is set, so a moved port stays protected.
func RenderFail2BanJail(spec *Fail2BanSpec, sshPort int) string {
	maxretry := spec.MaxRetry
	if maxretry == 0 {
		maxretry = 5
	}
	findtime := spec.FindTimeSec
	if findtime == 0 {
		findtime = 600
	}
	bantime := spec.BanTimeSec
	if bantime == 0 {
		bantime = 3600
	}
	port := sshPort
	if port == 0 {
		port = 22
	}
	return fmt.Sprintf(`# managed by quantum-agent hardening — do not edit
[sshd]
enabled = true
port = %s
backend = systemd
maxretry = %d
findtime = %d
bantime = %d
`, strconv.Itoa(port), maxretry, findtime, bantime)
}
