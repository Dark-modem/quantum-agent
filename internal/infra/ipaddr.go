package infra

import (
	"net"
	"strconv"
	"strings"
)

// IPFamily is 4 or 6 for an IP literal and 0 for anything else (a name, a
// CIDR, garbage). An IPv4-mapped IPv6 address ("::ffff:1.2.3.4") counts as 4.
func IPFamily(s string) int {
	ip := net.ParseIP(strings.TrimSpace(s))
	switch {
	case ip == nil:
		return 0
	case ip.To4() != nil:
		return 4
	default:
		return 6
	}
}

// IsV6 reports whether s is an IPv6 literal.
func IsV6(s string) bool { return IPFamily(s) == 6 }

// HostPort is net.JoinHostPort with an int port: an IPv6 literal gets its
// brackets ("[2001:db8::1]:443"), an IPv4 address or a name does not.
func HostPort(host string, port int) string {
	return net.JoinHostPort(strings.Trim(strings.TrimSpace(host), "[]"), strconv.Itoa(port))
}

// URLHost is host as it goes into a URL without a port: IPv6 in brackets.
func URLHost(host string) string {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}
