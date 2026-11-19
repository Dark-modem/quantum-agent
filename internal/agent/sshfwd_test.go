package agent

import (
	"testing"
)

// §6.A3 removed sshfwd.go's apply layer (authorized_keys installers, systemd
// unit builders, ParseBagherBundle/applyBagherBundle, enable/disable, the
// legacy handlers); the tests that drove those entry points went with them.
// The three tests below cover the surviving pure helpers.

func TestSSHFwdDefaultConfig(t *testing.T) {
	cfg := defaultSSHFwdConfig()
	if cfg.Mode != "bagher" {
		t.Fatalf("expected default mode 'bagher', got: %s", cfg.Mode)
	}
	if cfg.FRPBindPort != 55400 {
		t.Fatalf("expected FRPBindPort 55400, got: %d", cfg.FRPBindPort)
	}
	if cfg.PoolCount != 5 {
		t.Fatalf("expected PoolCount 5, got: %d", cfg.PoolCount)
	}
	if len(cfg.Ports) != 0 {
		t.Fatalf("expected default Ports to be empty for clean installation, got: %v", cfg.Ports)
	}
}

func TestBagherFormatByteSize(t *testing.T) {
	if formatByteSize(0) != "0 B" {
		t.Errorf("expected 0 B, got %s", formatByteSize(0))
	}
	if formatByteSize(500) != "500 B" {
		t.Errorf("expected 500 B, got %s", formatByteSize(500))
	}
	if formatByteSize(1024) != "1.0 KB" {
		t.Errorf("expected 1.0 KB, got %s", formatByteSize(1024))
	}
	if formatByteSize(1048576) != "1.0 MB" {
		t.Errorf("expected 1.0 MB, got %s", formatByteSize(1048576))
	}
	if formatByteSize(1073741824*2) != "2.0 GB" {
		t.Errorf("expected 2.0 GB, got %s", formatByteSize(1073741824*2))
	}
}

func TestIsPrivateIP(t *testing.T) {
	if !isPrivateIP("127.0.0.1") {
		t.Fatalf("expected 127.0.0.1 to be private")
	}
	if !isPrivateIP("10.0.0.5") {
		t.Fatalf("expected 10.0.0.5 to be private")
	}
	if !isPrivateIP("172.16.5.1") {
		t.Fatalf("expected 172.16.5.1 to be private")
	}
	if !isPrivateIP("172.26.32.7") {
		t.Fatalf("expected 172.26.32.7 to be private")
	}
	if !isPrivateIP("192.168.1.100") {
		t.Fatalf("expected 192.168.1.100 to be private")
	}
	if isPrivateIP("1.1.1.1") {
		t.Fatalf("expected 1.1.1.1 to be public")
	}
	if isPrivateIP("8.8.8.8") {
		t.Fatalf("expected 8.8.8.8 to be public")
	}
}
