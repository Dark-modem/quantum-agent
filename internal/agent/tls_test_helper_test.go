package agent

// tls_test_helper_test.go — an HTTPS test server whose CA the process
// trusts via SSL_CERT_FILE (crypto/x509 honors it on Linux), so the
// agent's own https clients accept the test certificate. NOTE: run this
// test alone (-run filter) so no earlier test in the same binary has
// already built the system cert pool.

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func newTLSTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	caFile := filepath.Join(t.TempDir(), "test-ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", caFile)
	return srv
}
