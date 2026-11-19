package agent

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

func TestPeerAuthMiddleware(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "quantum_peer_auth_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := infra.ConfigDir
	infra.ConfigDir = tmpDir
	defer func() { infra.ConfigDir = oldConfigDir }()

	c := loadPeerConfig()
	c.PeerSecret = "super-secret-peer-key-12345"
	_ = savePeerConfig(c)

	handler := requirePeerAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"authorized"}`))
	})

	// Case 1: Unauthorized (no header)
	req1 := httptest.NewRequest("POST", "/api/peer/ping", nil)
	rr1 := httptest.NewRecorder()
	handler(rr1, req1)
	if rr1.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for missing secret, got %d", rr1.Code)
	}

	// Case 2: Wrong secret
	req2 := httptest.NewRequest("POST", "/api/peer/ping", nil)
	req2.Header.Set("X-Peer-Secret", "wrong-secret")
	rr2 := httptest.NewRecorder()
	handler(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 for wrong secret, got %d", rr2.Code)
	}

	// Case 3: Valid X-Peer-Secret
	req3 := httptest.NewRequest("POST", "/api/peer/ping", nil)
	req3.Header.Set("X-Peer-Secret", "super-secret-peer-key-12345")
	rr3 := httptest.NewRecorder()
	handler(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Errorf("expected status 200 for valid X-Peer-Secret, got %d", rr3.Code)
	}

	// Case 4: Valid Authorization Bearer
	req4 := httptest.NewRequest("POST", "/api/peer/ping", nil)
	req4.Header.Set("Authorization", "Bearer super-secret-peer-key-12345")
	rr4 := httptest.NewRecorder()
	handler(rr4, req4)
	if rr4.Code != http.StatusOK {
		t.Errorf("expected status 200 for valid Bearer token, got %d", rr4.Code)
	}
}

func TestSendToPeerDualPath(t *testing.T) {
	// Start mock peer server
	receivedSecret := ""
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSecret = r.Header.Get("X-Peer-Secret")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pong"}`))
	}))
	defer mockServer.Close()

	tmpDir, err := os.MkdirTemp("", "quantum_peer_send_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldConfigDir := infra.ConfigDir
	infra.ConfigDir = tmpDir
	defer func() { infra.ConfigDir = oldConfigDir }()

	c := loadPeerConfig()
	c.PeerURL = mockServer.URL
	c.InternalIP = "" // force public URL path
	c.PeerSecret = "test-secret-456"
	_ = savePeerConfig(c)

	res, err := sendToPeer("/api/peer/ping", "POST", map[string]string{"ping": "1"})
	if err != nil {
		t.Fatalf("sendToPeer failed: %v", err)
	}
	if !bytes.Contains(res, []byte("pong")) {
		t.Errorf("expected pong response, got: %s", string(res))
	}
	if receivedSecret != "test-secret-456" {
		t.Errorf("expected secret 'test-secret-456', got %q", receivedSecret)
	}
}
