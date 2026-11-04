package agent

// Port/SNI suggestion helpers ported verbatim from the controller
// monolith (suggest.go): preferred user-port list and SNI candidates
// used by the advisor and setup flows.

import "strings"

// Ports that commonly pass through restrictive networks (HTTPS-like first).
var preferredPorts = []int{443, 8443, 2053, 2083, 2087, 2096, 8080, 8880, 2052, 2082, 2086, 2095, 9443, 4443}

// suggestPorts returns up to n preferred ports that are neither reserved by
// the panel/tunnels (`used`) nor currently bound (`free` false).
func suggestPorts(used map[int]bool, free func(int) bool, n int) []int {
	var out []int
	seen := map[int]bool{}
	for _, p := range preferredPorts {
		if seen[p] || used[p] {
			continue
		}
		seen[p] = true
		if free != nil && !free(p) {
			continue
		}
		out = append(out, p)
		if len(out) == n {
			break
		}
	}
	return out
}

// Popular, widely reachable hostnames for WSS/TLS fronting (SNI).
var preferredSNI = []string{"www.speedtest.net", "www.microsoft.com", "www.cloudflare.com", "www.apple.com", "update.googleapis.com", "www.wikipedia.org"}

func validSNI(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || !strings.Contains(s, ".") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// suggestSNI rotates the preferred list so it starts after `current`
// (never returning the one already in use first).
func suggestSNI(current string, n int) []string {
	var out []string
	start := 0
	for i, s := range preferredSNI {
		if strings.EqualFold(s, current) {
			start = i + 1
		}
	}
	for i := 0; i < len(preferredSNI) && len(out) < n; i++ {
		s := preferredSNI[(start+i)%len(preferredSNI)]
		if !strings.EqualFold(s, current) {
			out = append(out, s)
		}
	}
	return out
}
