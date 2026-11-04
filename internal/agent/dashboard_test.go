package agent

import (
	"fmt"
	"testing"
	"time"
)

func resetTrafficState(t *testing.T) {
	t.Helper()
	old := configDir
	configDir = t.TempDir()
	trafficStateMu.Lock()
	trafficStateInit, lifetimeUp, lifetimeDown, lastRawUp, lastRawDown, lastRawIf = false, 0, 0, 0, 0, nil
	lastSampleAt, speedDeltaUp, speedDeltaDown, currentSpeedUp, currentSpeedDown = time.Time{}, 0, 0, 0, 0
	trafficStateMu.Unlock()
	t.Cleanup(func() { configDir = old })
}

func TestIsTunnelInterface(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"lo", false},
		{"gre0", false},
		{"gretap0", false},
		{"erspan0", false},
		{"eth0", false},
		{"ens5", false},
		{"enp0s5", false},
		{"docker0", false},
		{"veth1234", false},
		{"br-test", false},
		{"dummy0", false},
		{"gre-tunnel", true},
		{"gre-t2", true},
		{"gre-t3", true},
		{"tun0", true},
		{"tun1", true},
		{"tun-backhaul", true},
	}

	for _, tt := range tests {
		got := isTunnelInterface(tt.name)
		if got != tt.expected {
			t.Errorf("isTunnelInterface(%q) = %v; want %v", tt.name, got, tt.expected)
		}
	}
}

// With no tunnel interface and no carrier the main NIC is not counted: it
// carries the whole server's traffic (the panel used to show it as tunnel
// traffic, and to count it while a GRE interface was being recreated).
// devLines builds /proc/net/dev text: name -> {received, transmitted}.
func devLines(ifs map[string][2]uint64) string {
	s := "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets\n"
	for name, c := range ifs {
		s += fmt.Sprintf("  %s: %d 1 0 0 0 0 0 0 %d 1 0 0 0 0 0 0\n", name, c[0], c[1])
	}
	return s
}

// The throughput chart spiked to tens of GB/s whenever the tunnel interface
// went away (the source switched to the main NIC) or one of several tunnels
// dropped (the smaller sum counted as a counter reset). Only real bytes count.
