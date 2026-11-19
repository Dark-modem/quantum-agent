package agent

// Phase-10 TASK 5: the diag bundle must be SAFE to send to support —
// seeded secrets (enrollment key, tunnel tokens, private keys in the
// state dir) must appear NOWHERE in the bundle; only their SHA-256
// prefixes and file fingerprints survive.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

func TestDiagBundleRedacted(t *testing.T) {
	oldCfg := infra.ConfigDir
	infra.ConfigDir = t.TempDir()
	t.Cleanup(func() { infra.ConfigDir = origCfgForDiag(oldCfg) })

	// Seed secrets: the enrollment (key + pin), a Matrix state file with a
	// token, and a private-key file in the state dir.
	enroll := `{"id":"diag-agent-1","key":"SUPER-SECRET-AGENT-KEY-0123456789","server":"https://panel.example:7443/qbase","name":"diag","tls_pin":"PIN1234567890ABCDEF"}`
	if err := os.WriteFile(agentIdentityPath(), []byte(enroll), 0o600); err != nil {
		t.Fatal(err)
	}
	in := matrixInstance{ID: "matrix2"}
	if err := os.MkdirAll(matrixDirOf(in), 0o700); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(matrixDirOf(in), "token")
	secret := "MATRIX-PSK-SECRET-9876543210"
	if err := os.WriteFile(tokenFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	privKey := filepath.Join(infra.ConfigDir, "some-engine", "private.key")
	if err := os.MkdirAll(filepath.Dir(privKey), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privKey, []byte("PRIVATE-KEY-MATERIAL-abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets := []string{
		"SUPER-SECRET-AGENT-KEY-0123456789", "MATRIX-PSK-SECRET-9876543210",
		"PRIVATE-KEY-MATERIAL-abcdef", "PIN1234567890",
	}

	// The diag payload with a tunnel/balancer section carrying a token-ish
	// field name (the redaction is key-based for maps, value-based for the
	// identity).
	balancer := []balTargetDiag{{
		Forward: "fwd-1", Tunnel: "t-1", Reason: "selected", Health: "up",
		Weight: 30, Addr: "10.189.0.2:5201", NftRange: "0-29", Total: 60,
	}}
	bundle := diagCollect(nil, balancer, false)
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)

	// 1. No secret VALUE anywhere in the bundle.
	for _, s := range secrets {
		if strings.Contains(text, s) {
			t.Fatalf("SECRET %q leaked into the diag bundle", s)
		}
	}
	// 2. The enrollment shape is present with REDACTED values.
	if !strings.Contains(text, `"present": true`) {
		t.Fatalf("identity shape missing:\n%s", text)
	}
	if !strings.Contains(text, "sha256:") {
		t.Fatalf("no redacted fingerprints in the bundle:\n%s", text)
	}
	// 3. The state-dir files are fingerprinted, contents absent.
	if !strings.Contains(text, "private.key") {
		t.Fatalf("the state-dir file list missing:\n%s", text)
	}
	if strings.Contains(text, "PRIVATE") {
		t.Fatal("file contents leaked")
	}
	// 4. The matrix token FILE path may appear, its CONTENT must not.
	if strings.Contains(text, secret) {
		t.Fatalf("matrix token leaked")
	}

}

// origCfgForDiag restores the caller's infra.ConfigDir (named so the cleanup
// reads naturally).
func origCfgForDiag(old string) string { return old }
