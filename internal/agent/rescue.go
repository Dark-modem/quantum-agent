package agent

// Rescue: the one-way-block detection and the emergency carrier-swap flow.
//
// REFACTOR-PLAN-AGENT §6.A3: the rescue ENGINE is deleted (48 of the file's
// funcs — deadcode-RTA-unreachable from main: the code encode/decode, the
// origin/entry frpc+fw+dnat unit builders, the enable/apply/teardown flow,
// the monitor, the legacy HTTP handlers — every entry point lived in the
// purged legacy handler layer, and mountPeerRoutes never routed any of
// them). What survives is what live code uses:
//
//   - runCmd: the package-wide exec seam (acct.go, sshfwd.go,
//     bagher_links.go, matrix.go, firewall.go, …) — DEFINED HERE since the
//     monolith days; relocating it would churn every seam-swap in tests.
//   - randHex: firewall.go/matrix.go token generation.
//   - classifyDial + rescueVerdict: the pure probe-decision rules
//     (unit-tested in isolation; the panel owns the live rescue semantics).
//
// The probe machinery itself (rescueProbeFn/rescueProbeReal/rescueTarget/
// rescueDial) went too: reachable only through the package-var initializer
// and dead callers, and no test swapped or drove it.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// runCmd runs name with a 20s cap and returns the combined output.
// Swappable for tests (several suites replace it to fake systemctl/ssh).
var runCmd = func(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// randHex returns n random bytes hex-encoded.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("rescue: entropy unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func classifyDial(err error) string {
	if err == nil {
		return "open"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	return "timeout"
}

// rescueVerdict is pure so the decision rule is unit-tested in isolation.
//
//	ok               at least one port answers
//	service_down     remote is reachable (it sent RST) but nothing listens
//	one_way_block    ping works, every TCP SYN vanishes -> this is our case
//	host_unreachable neither ping nor TCP work (outage, not a block)
func rescueVerdict(pingOK bool, ports map[int]string) string {
	if len(ports) == 0 {
		return "unknown"
	}
	refused := false
	for _, s := range ports {
		switch s {
		case "open":
			return "ok"
		case "refused":
			refused = true
		}
	}
	if refused {
		return "service_down"
	}
	if pingOK {
		return "one_way_block"
	}
	return "host_unreachable"
}
