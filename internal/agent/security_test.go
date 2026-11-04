package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"testing"
)

func TestTrustedProxyAndClientIP(t *testing.T) {
	orig := os.Getenv("TRUSTED_PROXY_IPS")
	defer os.Setenv("TRUSTED_PROXY_IPS", orig)

	// Case 1: No trusted proxies configured -> Spoofed XFF ignored
	os.Unsetenv("TRUSTED_PROXY_IPS")
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.50:54321"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	if ip := ClientIP(req); ip != "203.0.113.50" {
		t.Fatalf("expected direct IP 203.0.113.50, got %s (spoofing not blocked!)", ip)
	}

	// Case 2: Trusted proxies configured (127.0.0.1 and 10.0.0.0/8)
	os.Setenv("TRUSTED_PROXY_IPS", "127.0.0.1, 10.0.0.0/8")

	// Direct request from untrusted external IP with spoofed XFF
	reqUntrusted := httptest.NewRequest("GET", "/test", nil)
	reqUntrusted.RemoteAddr = "192.0.2.1:12345"
	reqUntrusted.Header.Set("X-Forwarded-For", "198.51.100.1")
	if ip := ClientIP(reqUntrusted); ip != "192.0.2.1" {
		t.Fatalf("expected untrusted host 192.0.2.1, got %s", ip)
	}

	// Request from trusted proxy 127.0.0.1 with XFF. nginx's
	// $proxy_add_x_forwarded_for APPENDS the real client address: earlier
	// entries are client-supplied and spoofable, so the LAST non-empty hop
	// wins (Session 4 gate fix).
	reqTrusted := httptest.NewRequest("GET", "/test", nil)
	reqTrusted.RemoteAddr = "127.0.0.1:40000"
	reqTrusted.Header.Set("X-Forwarded-For", "203.0.113.99, 198.51.100.1")
	if ip := ClientIP(reqTrusted); ip != "198.51.100.1" {
		t.Fatalf("expected last-hop forwarded client IP 198.51.100.1, got %s", ip)
	}

	// A single-entry XFF from a trusted proxy is the proxy-appended value.
	reqSpoof := httptest.NewRequest("GET", "/test", nil)
	reqSpoof.RemoteAddr = "127.0.0.1:40001"
	reqSpoof.Header.Set("X-Forwarded-For", "1.2.3.4")
	if ip := ClientIP(reqSpoof); ip != "1.2.3.4" {
		t.Fatalf("single-entry XFF is the proxy-appended value, got %s", ip)
	}

	// Request from trusted CIDR proxy 10.2.3.4 with X-Real-IP
	reqCIDR := httptest.NewRequest("GET", "/test", nil)
	reqCIDR.RemoteAddr = "10.2.3.4:50000"
	reqCIDR.Header.Set("X-Real-IP", "198.51.100.2")
	if ip := ClientIP(reqCIDR); ip != "198.51.100.2" {
		t.Fatalf("expected forwarded real IP 198.51.100.2, got %s", ip)
	}
}

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
