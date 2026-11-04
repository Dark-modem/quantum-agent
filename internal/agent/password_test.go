package agent

import (
	"crypto/sha256"
	"encoding/hex"
)

func legacyHash(pw string) string {
	h := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(h[:])
}

// M-03: a legacy SHA-256 panel.json must still log in and be upgraded in place.
// M-03: session cookie must be random, not derivable from panel.json contents.
// C2: the stored hash itself must never be accepted as the password.
// L20: a password with surrounding spaces must verify against its own hash.
