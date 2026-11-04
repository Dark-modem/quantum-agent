package agent

// Step 2 RED: custom certificate install (paste PEM / upload files / server
// path) with X509KeyPair validation, atomic backup/rollback, in-process HTTPS
// reload. Tunnels never touched.
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"mime/multipart"
	"testing"
	"time"
)

// testCertPEM generates a throwaway self-signed cert+key for tests.
func testCertPEM(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	return certPEM, keyPEM
}

type testMultipart struct {
	buf *bytes.Buffer
	w   *multipart.Writer
}

func newMultipartWriter() *testMultipart {
	buf := &bytes.Buffer{}
	return &testMultipart{buf: buf, w: multipart.NewWriter(buf)}
}

func addMultipartFile(t *testing.T, m *testMultipart, field, name, content string) {
	t.Helper()
	fw, err := m.w.CreateFormFile(field, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
}

func (m *testMultipart) close()              { _ = m.w.Close() }
func (m *testMultipart) contentType() string { return m.w.FormDataContentType() }

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
