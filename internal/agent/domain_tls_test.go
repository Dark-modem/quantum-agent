package agent

import (
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

// TestTrustedProxyLoopback (the H11 loopback-not-trusted gate) went with the
// dead agent-side ClientIP/IsTrustedProxy pair in §6.A3 — the agent has no
// HTTP surface; the live semantics are the panel's, tested there.
