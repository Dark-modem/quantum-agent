package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// TestTrustedProxyAndClientIP (the monolith X-Forwarded-For / trusted-proxy
// gate) went with the dead agent-side ClientIP/IsTrustedProxy pair in
// §6.A3 — the agent has no HTTP surface; the live semantics are the
// panel's, tested there.

func TestChecksumVerification(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "checksum-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := "secure-binary-content-for-testing"
	_, _ = tmpFile.WriteString(content)
	_ = tmpFile.Close()

	expectedHashBytes := sha256.Sum256([]byte(content))
	expectedHashHex := hex.EncodeToString(expectedHashBytes[:])

	// Correct hash should succeed
	if err := VerifyFileSHA256(tmpFile.Name(), expectedHashHex); err != nil {
		t.Fatalf("expected checksum verification to pass, got: %v", err)
	}

	// Corrupted/tampered hash should fail
	if err := VerifyFileSHA256(tmpFile.Name(), "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("expected checksum verification to fail for bad hash, got nil")
	}

	// Test ParseChecksumManifest
	manifestText := `
# Checksum file
` + expectedHashHex + `  test-binary.tar.gz
` + expectedHashHex + ` *another-binary.exe
`
	manifest := ParseChecksumManifest(manifestText)
	if manifest["test-binary.tar.gz"] != expectedHashHex {
		t.Fatalf("manifest parse failed for test-binary.tar.gz: got %s", manifest["test-binary.tar.gz"])
	}
	if manifest["another-binary.exe"] != expectedHashHex {
		t.Fatalf("manifest parse failed for another-binary.exe: got %s", manifest["another-binary.exe"])
	}
}
