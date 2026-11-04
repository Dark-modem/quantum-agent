package agent

import (
	"net/http/httptest"
	"testing"
)

// Test 1: CleanHost helper validates extraction of raw host/IP across formats
func TestCleanHost(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"http://panel.example.com:7443", "panel.example.com"},
		{"https://panel.example.com:7443/dashboard", "panel.example.com"},
		{"https://panel.example.com", "panel.example.com"},
		{"http://1.2.3.4:7777/panel", "1.2.3.4"},
		{"192.168.1.50:8080", "192.168.1.50"},
		{"192.168.1.50", "192.168.1.50"},
		{"[2001:db8::1]:8443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"panel.mydomain.ir", "panel.mydomain.ir"},
		{"http://panel.mydomain.ir:80?token=xyz", "panel.mydomain.ir"},
		{"", ""},
		{"   ", ""},
	}

	for _, tc := range cases {
		actual := CleanHost(tc.input)
		if actual != tc.expected {
			t.Errorf("CleanHost(%q) = %q; want %q", tc.input, actual, tc.expected)
		}
	}
}

// Test 2: loopback is trusted only when TRUSTED_PROXY_IPS lists it (H11):
// tunnels deliver outside clients from 127.0.0.1 too.
func TestTrustedProxyLoopback(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_IPS", "")
	for _, ip := range []string{"127.0.0.1", "::1", "localhost"} {
		if IsTrustedProxy(ip) {
			t.Errorf("%s must not be trusted without TRUSTED_PROXY_IPS", ip)
		}
	}
	spoof := httptest.NewRequest("GET", "/test", nil)
	spoof.RemoteAddr = "127.0.0.1:54321"
	spoof.Header.Set("X-Forwarded-For", "203.0.113.195")
	if got := ClientIP(spoof); got != "127.0.0.1" {
		t.Errorf("X-Forwarded-For via untrusted loopback honoured: %q", got)
	}

	t.Setenv("TRUSTED_PROXY_IPS", "127.0.0.1, ::1")
	for _, ip := range []string{"127.0.0.1", "::1", "localhost"} {
		if !IsTrustedProxy(ip) {
			t.Errorf("%s listed in TRUSTED_PROXY_IPS but not trusted", ip)
		}
	}

	// External untrusted IP should NOT be trusted by default
	if IsTrustedProxy("8.8.8.8") {
		t.Errorf("did not expect 8.8.8.8 to be trusted proxy")
	}

	// When request comes from trusted proxy 127.0.0.1, X-Forwarded-For must be
	// extracted. The repo's proxy configs use $proxy_add_x_forwarded_for, so
	// the trusted proxy APPENDS the real client address: earlier entries were
	// supplied by the client and are spoofable — the LAST hop is the trusted
	// value (Session 4 gate fix).
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 10.0.0.1")
	clientIP := ClientIP(req)
	if clientIP != "10.0.0.1" {
		t.Errorf("ClientIP() = %q; want %q (last hop appended by the trusted proxy)", clientIP, "10.0.0.1")
	}

	// When request comes from untrusted remote IP, X-Forwarded-For must be ignored
	untrustedReq := httptest.NewRequest("GET", "/test", nil)
	untrustedReq.RemoteAddr = "198.51.100.5:12345"
	untrustedReq.Header.Set("X-Forwarded-For", "203.0.113.195")
	untrustedClientIP := ClientIP(untrustedReq)
	if untrustedClientIP != "198.51.100.5" {
		t.Errorf("ClientIP() from untrusted remote = %q; want %q", untrustedClientIP, "198.51.100.5")
	}
}

// Test 3: WebSocket CheckOrigin handles direct domain and reverse proxies
// Test 4: Port conflict checks validate against tunnel ports and panel port
// Test 5: Atomic rollback restores previous certificates on failure
// Test 6: Clean domain removal deletes certs and reverts to HTTP access
// Test 7: Reverse proxy generator outputs valid Nginx and Caddy templates
// Test 8: Preflight check endpoint returns comprehensive status
