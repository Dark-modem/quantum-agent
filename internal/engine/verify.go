package engine

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// VerifyArtifact verifies a downloaded engine artifact before a driver
// installs it: the sha256 hex digest must match, and an ed25519
// signature over the artifact must verify against pubPEM. The public key
// accepts the same two forms as the agent self-update path: PEM
// SubjectPublicKeyInfo, or single-line base64 of the DER form (ldflags
// -X cannot carry newlines). Failing closed: without a pinned key there
// is no signature check, and the artifact is refused.
func VerifyArtifact(artifact []byte, sha256Hex, sigB64, pubPEM string) error {
	sum := sha256.Sum256(artifact)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), strings.ToLower(strings.TrimSpace(sha256Hex))) {
		return errors.New("engine artifact sha256 mismatch")
	}
	key, err := parseEngineKey(pubPEM)
	if err != nil {
		return fmt.Errorf("engine artifact signature unavailable: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("engine artifact signature encoding invalid")
	}
	if !ed25519.Verify(key, artifact, sig) {
		return errors.New("engine artifact signature verification FAILED")
	}
	return nil
}

// parseEngineKey mirrors the agent self-update key parser: PEM or
// base64-DER SubjectPublicKeyInfo, ed25519 only, never empty.
func parseEngineKey(pubPEM string) (ed25519.PublicKey, error) {
	pubPEM = strings.TrimSpace(pubPEM)
	if pubPEM == "" {
		return nil, errors.New("no engine artifact signing key pinned")
	}
	var der []byte
	if block, _ := pem.Decode([]byte(pubPEM)); block != nil && block.Type == "PUBLIC KEY" {
		der = block.Bytes
	} else if b, err := base64.StdEncoding.DecodeString(pubPEM); err == nil {
		der = b
	} else {
		return nil, errors.New("engine signing key is neither PEM nor base64 DER")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("engine signing key not parseable: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("engine signing key is not ed25519")
	}
	return key, nil
}
