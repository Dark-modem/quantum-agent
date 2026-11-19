package infra

import (
	"encoding/json"
	"net"
	"os"
	"strings"
)

// MustJSON marshals v indented; marshal errors are swallowed (every caller
// marshals typed structs that always succeed).
func MustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

// FileExists reports whether the path exists (any type).
func FileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// PrimaryInterface is the outbound-facing interface name: a compat stub —
// the agent resolves interfaces through net.Interfaces directly.
func PrimaryInterface() string { return "" }

// NormHost canonicalises an address for comparison: brackets and zone ids are
// dropped and IPv4-mapped IPv6 ("[::ffff:1.2.3.4]") becomes plain IPv4.
func NormHost(h string) string {
	h = strings.TrimSpace(strings.Trim(h, "[]"))
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return h
}
