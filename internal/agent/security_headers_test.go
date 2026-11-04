package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func readAllCount(r *http.Request) (int, error) {
	buf := make([]byte, 32*1024)
	total := 0
	for {
		n, err := r.Body.Read(buf)
		total += n
		if err != nil {
			if err.Error() == "EOF" {
				return total, nil
			}
			return total, err
		}
	}
}

func TestPeerTLSPinning(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	}))
	defer srv.Close()
	leaf := srv.Certificate().Raw
	sum := sha256.Sum256(leaf)
	fp := hex.EncodeToString(sum[:])

	dial := func(c *PeerConfig) error {
		tr := &http.Transport{TLSClientConfig: peerTLSConfig(c)}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}

	// First use: pin and persist.
	c := loadPeerConfig()
	c.TLSFingerprint = ""
	if err := dial(&c); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	if c.TLSFingerprint != fp {
		t.Fatalf("fingerprint not stored: %q want %q", c.TLSFingerprint, fp)
	}
	if got := loadPeerConfig().TLSFingerprint; got != fp {
		t.Fatalf("fingerprint not persisted: %q", got)
	}

	// Match.
	c2 := loadPeerConfig()
	if err := dial(&c2); err != nil {
		t.Fatalf("matching pin should succeed: %v", err)
	}

	// Mismatch.
	c3 := loadPeerConfig()
	c3.TLSFingerprint = strings.Repeat("ab", 32)
	err := dial(&c3)
	if err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("expected fingerprint mismatch error, got %v", err)
	}
	if c3.TLSFingerprint != strings.Repeat("ab", 32) {
		t.Error("pin must not be overwritten on mismatch")
	}
}
