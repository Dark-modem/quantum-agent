package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentIranBundleExtraction(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "quantum_bundle_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := configDir
	configDir = tmpDir
	defer func() { configDir = oldConfigDir }()

	// 1. Setup mock setup.json with token
	setupData := map[string]any{
		"token":         "test-secret-token-123456",
		"local_public":  "1.2.3.4",
		"remote_public": "5.6.7.8",
		"iran_gre":      "10.10.10.2",
		"foreign_gre":   "10.10.10.1",
		"frp_port":      7000,
		"ports":         "443, 8080",
	}
	raw, _ := json.Marshal(setupData)
	_ = os.WriteFile(filepath.Join(tmpDir, "setup.json"), raw, 0600)

	bStr, tok := currentIranBundle()
	if tok != "test-secret-token-123456" {
		t.Errorf("expected token 'test-secret-token-123456', got %q", tok)
	}
	if bStr == "" {
		t.Fatalf("expected non-empty bundle string")
	}

	// Parse extracted bundle to verify its contents
	bundle, err := ParseBundle(bStr)
	if err != nil {
		t.Fatalf("failed to parse extracted bundle %q: %v", bStr, err)
	}
	if bundle.IranPub != "1.2.3.4" {
		t.Errorf("expected IranPub 1.2.3.4, got %s", bundle.IranPub)
	}
	if bundle.FrpPort != 7000 {
		t.Errorf("expected Port 7000, got %d", bundle.FrpPort)
	}
	if bundle.Token != "test-secret-token-123456" {
		t.Errorf("expected Token 'test-secret-token-123456', got %s", bundle.Token)
	}
}

func TestSwitchTunnelEngineValidation(t *testing.T) {
	engineLab(t, []string{"backhaul", "frpc", "frps"}, []string{"backhaul-server", "backhaul-client"})
	// Invalid engine
	out, err := switchTunnelEngine("invalid_engine", "tcp")
	if err == nil {
		t.Errorf("expected error for invalid engine, got success with output %q", out)
	}

	// Supported engines should proceed
	outFRP, errFRP := switchTunnelEngine("frp", "tcpmux")
	if errFRP != nil {
		t.Errorf("switchTunnelEngine frp failed: %v (%s)", errFRP, outFRP)
	}

	outBH, errBH := switchTunnelEngine("backhaul", "tcpmux")
	if errBH != nil {
		t.Errorf("switchTunnelEngine backhaul failed: %v (%s)", errBH, outBH)
	}
}
