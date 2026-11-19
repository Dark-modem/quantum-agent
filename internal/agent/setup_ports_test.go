package agent

import (
	"strings"
	"testing"
)

func TestRewriteTomlPorts(t *testing.T) {
	initial := `bindAddr = "0.0.0.0"
bindPort = 7000
auth.token = "secret123"

[[proxies]]
name = "tcp_80"
type = "tcp"
localIP = "127.0.0.1"
localPort = 80
remotePort = 80

[[proxies]]
name = "udp_80"
type = "udp"
localIP = "127.0.0.1"
localPort = 80
remotePort = 80
`

	updated := rewriteTomlPorts(initial, []int{443, 2083})

	if !strings.Contains(updated, "bindPort = 7000") {
		t.Errorf("expected header preserved, got:\n%s", updated)
	}
	if !strings.Contains(updated, "auth.token = \"secret123\"") {
		t.Errorf("expected auth preserved, got:\n%s", updated)
	}
	if strings.Contains(updated, "tcp_80") || strings.Contains(updated, "remotePort = 80") {
		t.Errorf("expected old port 80 removed, got:\n%s", updated)
	}
	if !strings.Contains(updated, "name = \"tcp_443\"") || !strings.Contains(updated, "remotePort = 443") {
		t.Errorf("expected port 443 present, got:\n%s", updated)
	}
	if !strings.Contains(updated, "name = \"udp_443\"") {
		t.Errorf("expected udp_443 present, got:\n%s", updated)
	}
	if !strings.Contains(updated, "name = \"tcp_2083\"") || !strings.Contains(updated, "remotePort = 2083") {
		t.Errorf("expected port 2083 present, got:\n%s", updated)
	}
	if !strings.Contains(updated, "name = \"udp_2083\"") {
		t.Errorf("expected udp_2083 present, got:\n%s", updated)
	}
}

// M14: rewriting the port list keeps per-proxy options such as PROXY
// protocol and encryption instead of dropping them.
func TestRewriteTomlPortsKeepsProxyOptions(t *testing.T) {
	src := `serverAddr = "10.10.10.1"
serverPort = 7000

[[proxies]]
name = "tcp_443"
type = "tcp"
localIP = "127.0.0.1"
localPort = 443
remotePort = 443
transport.proxyProtocolVersion = "v2"
transport.useEncryption = true

[[proxies]]
name = "udp_443"
type = "udp"
localIP = "127.0.0.1"
localPort = 443
remotePort = 443
`
	out := rewriteTomlPorts(src, []int{443, 8443})
	if strings.Count(out, `transport.proxyProtocolVersion = "v2"`) != 2 {
		t.Fatalf("proxy protocol not kept on both tcp proxies:\n%s", out)
	}
	if strings.Count(out, "transport.useEncryption = true") != 2 {
		t.Fatalf("encryption not kept:\n%s", out)
	}
	if strings.Count(out, "[[proxies]]") != 4 || !strings.Contains(out, `name = "udp_8443"`) {
		t.Fatalf("unexpected proxy set:\n%s", out)
	}
	udp := out[strings.Index(out, `name = "udp_443"`):]
	udp = udp[:strings.Index(udp, "[[proxies]]")]
	if strings.Contains(udp, "proxyProtocolVersion") {
		t.Fatalf("tcp-only option copied onto a udp proxy:\n%s", udp)
	}
	if !strings.HasPrefix(out, "serverAddr = \"10.10.10.1\"\nserverPort = 7000\n") {
		t.Fatalf("header not kept:\n%s", out)
	}
}
