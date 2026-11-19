package agent

import (
	"github.com/Dark-modem/quantum-agent/internal/infra"
)

// validPublicIP reports whether s is a public address of family fam (4, 6, or
// 0 for either).
func validPublicIP(s string, fam int) bool {
	f := infra.IPFamily(s)
	return f != 0 && (fam == 0 || f == fam) && !isPrivateIP(s)
}
