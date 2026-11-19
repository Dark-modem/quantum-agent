package infra

import (
	"context"
	"net"
	"sync"
	"time"
)

// CarrierLookup resolves a dialled host name; swappable for tests.
var CarrierLookup = func(host string) string {
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

// CarrierIP is host as an IP address: an IPv6 literal stays IPv6, a name is
// resolved like CarrierIPv4.
func CarrierIP(host string) string {
	if h := NormHost(host); IsV6(h) {
		return net.ParseIP(h).String()
	}
	return CarrierIPv4(host)
}

// CarrierIPv4 is host as an IPv4 address ("" for IPv6 or a name that does not
// resolve). Names are looked up at most every 10 minutes.
func CarrierIPv4(host string) string {
	host = NormHost(host)
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
	ip := CarrierLookup(host)
	carrierDNS.Lock()
	carrierDNS.m[host] = carrierDNSEntry{ip, time.Now()}
	carrierDNS.Unlock()
	return ip
}
