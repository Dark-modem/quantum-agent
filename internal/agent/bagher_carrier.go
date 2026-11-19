package agent

// bagher-carrier: the SSH leg of a Bagher tunnel, in place of `ssh -N -R`.
//
// REFACTOR-PLAN-AGENT §6.A3: the carrier itself (the golang.org/x/crypto/ssh
// dialer, the exec-request TCP_NODELAY nudge, the keepalive/ping loop, the
// CLI command and the known-hosts repair — 14 funcs, deadcode-RTA-unreachable
// from main; the legacy handlers that launched it are purged) is deleted.
// What survives is the status SHAPE the live snapshot/links view reads:
// the target/status types, the status-file path and the reader
// (bagher_links.go's bagherCarrierRTT reports the last fresh report).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

// The ssh imports went with the deleted carrier (bagherHostKeyCallback,
// bagherCarrierSession, bagherNudgeNoDelay, bagherPing, bagherKeepalive);
// x/crypto/ssh survives only through sshfwd.go's surviving parts.

// bagherCarrierTarget is everything one carrier needs about its link.
type bagherCarrierTarget struct {
	ID       int
	Host     string
	Port     int
	User     string
	KeyPath  string
	FRPPort  int           // listen port on Foreign and frps port on Iran
	Local    string        // frps address to pipe to; empty: 127.0.0.1:FRPPort
	Alive    time.Duration // keepalive interval
	AliveMax int           // missed keepalives before reconnecting
}

// bagherCarrierStatus is what the carrier reports to the panel.
type bagherCarrierStatus struct {
	Connected bool    `json:"connected"`
	RTTMs     float64 `json:"rtt_ms"`
	Since     int64   `json:"since,omitempty"` // unix time the session came up
	At        int64   `json:"at"`              // unix time of this report
	Error     string  `json:"error,omitempty"`
}

func bagherCarrierStatusPath(id int) string {
	return filepath.Join(infra.ConfigDir, fmt.Sprintf("bagher-carrier-%d.json", id))
}

// readBagherCarrierStatus returns the carrier's last report if it is fresh.
func readBagherCarrierStatus(id int, maxAge time.Duration) (bagherCarrierStatus, bool) {
	var st bagherCarrierStatus
	b, err := os.ReadFile(bagherCarrierStatusPath(id))
	if err != nil || json.Unmarshal(b, &st) != nil {
		return st, false
	}
	if time.Since(time.Unix(st.At, 0)) > maxAge {
		return st, false
	}
	return st, true
}
