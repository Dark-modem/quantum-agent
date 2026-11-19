package agent

// Reverse-path fix machinery (Phase 4) — SHAPES AND SEAMS ONLY since
// REFACTOR-PLAN-AGENT §6.A3. The engine itself (the spoke probes, the fix
// plan/apply/rollback path, the handlers — 20 funcs, deadcode-RTA-unreachable
// from main, its only entry points living in the purged legacy handler layer)
// is deleted together with revpath.go's collector and revfix_test.go; the
// fix state/seam shapes stay because test_main_test.go swaps these seams and
// a future stage may re-arm the engine against the same shapes.

import (
	"net/http"
	"sync"
	"time"
)

type SpokeProbeRequest struct {
	HubInner    string `json:"hub_inner"`
	HubPublic   string `json:"hub_public"`
	ControlPort int    `json:"control_port"`
}

// SpokeProbeReport is the spoke's answer: its local snapshot plus the
// spoke->hub half of the matrix.
type SpokeProbeReport struct {
	OK       bool          `json:"ok"`
	Error    string        `json:"error,omitempty"`
	Matrix   ProbeMatrix   `json:"matrix"`
	Snapshot LocalSnapshot `json:"snapshot"`
	SpokeGre string        `json:"spoke_gre,omitempty"`
	Checked  string        `json:"checked"`
}

// spokeFetcher is the seam the hub used to ask one spoke for its half of the
// matrix. §6.A3: requestSpokeProbe (the real implementation) is deleted with
// the unreachable probe path; the seam var stays for the test swap.
var spokeFetcher = func(p peerRecord) *SpokeProbeReport { return nil }

type FixStep struct {
	At      string  `json:"at"`
	Verdict Verdict `json:"verdict"`
	Action  string  `json:"action"`
	Detail  string  `json:"detail"`
	OK      bool    `json:"ok"`
	Error   string  `json:"error,omitempty"`
}

// FixReport is the per-peer history returned by the API.
type FixReport struct {
	PeerID      int       `json:"peer_id"`
	Auto        bool      `json:"auto"`
	Steps       []FixStep `json:"steps"`
	LastRun     string    `json:"last_run,omitempty"`
	LastVerdict Verdict   `json:"last_verdict,omitempty"`
}

var (
	fixMu      sync.Mutex
	fixReports = map[int]*FixReport{}
	fixLastRun = map[int]time.Time{} // per-peer rate limit
	fixHour    = []time.Time{}       // global rate limit window
)

const (
	fixPeerCooldown = 10 * time.Minute
	fixHourMax      = 3
	revChain        = "QUANTUM-REVPATH"
)

// revpathSysctlConf is the persist file for reverse-path sysctl fixes.
// Tests point it at a throwaway dir (same pattern as frpDir/backhaulDir);
// production keeps /etc/sysctl.d. Overridable with GRE_SYSCTL_CONF.
var revpathSysctlConf = "/etc/sysctl.d/99-quantum-revpath.conf"

// handlePeerRevPathProbe served POST /api/peer/revpath-probe. §6.A3: the
// probe machinery is deleted; this no-op keeps peerconfig.go's dead
// mountPeerRoutes (out of this stage's named scope) compiling — the route
// was unreachable (mountPeerRoutes has zero callers), so the stub is
// behavior-identical.
func handlePeerRevPathProbe(w http.ResponseWriter, r *http.Request) {}
