// util.go — small shared helpers (time/rand seams so tests are deterministic).

package hardening

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// timeNow is a seam for deterministic tests.
var timeNow = time.Now

// randHex returns n random bytes hex-encoded (plan/journal ids).
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", timeNow().UnixNano())
	}
	return hex.EncodeToString(b)
}
