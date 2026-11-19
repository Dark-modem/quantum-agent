package agent

// tunnel_proc.go — per-tunnel PROCESS metrics for the v2 report
// (Phase 11: tunnel detail CPU/RAM). Samples /proc for each running
// tunnel's supervised process tree via the engine.ProcessInfoer
// capability. Sampling happens ONLY for tunnels whose engine actually
// runs a process: with no process tunnels there are zero /proc reads
// and the sampler resets — the agent's idle footprint is unchanged
// (asserted by TestAgentSampleTunnelProcIdleDoesNoProcReads).
//
// Semantics (mirrored in the protocol TunnelProc type): CPU percent is
// summed over the tree against the sample interval (one busy core =
// 100, two busy workers = 200); RSS is the SUM of the tree's VmRSS
// (shared pages count per process — the honest footprint is <= this);
// the FIRST sample of a new process reports CPU 0 (no baseline yet) but
// its RSS immediately.

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	protocol "github.com/Dark-modem/quantum-protocol"
)

// Seams (tests point these at a fake /proc tree).
var (
	tunnelProcRoot = "/proc"            // seam for tests (revpath.go owns procRoot)
	procClkTck     = 100.0              // _SC_CLK_TCK; the Linux default
	tunnelProcNow  = time.Now           // seam for deterministic deltas
	procStatOf     = procStatOfReal     // pid -> (cumulative jiffies, rss bytes, ok)
	procChildrenOf = procChildrenOfReal // pid -> child pids
)

var (
	tunnelProcMu sync.Mutex
	// Last sample per pid: cumulative jiffies + the wall clock it was
	// taken at. Restarts re-baseline (a vanished pid is forgotten).
	tunnelProcPrev     = map[int]float64{}
	tunnelProcPrevAt   time.Time
	tunnelProcHavePrev bool
)

// procReadCounter counts /proc reads in tests (idle-footprint proof).
var procReadCounter *int64

func procReadTick() {
	if procReadCounter != nil {
		*procReadCounter++
	}
}

// procStatOfReal reads /proc/<pid>/stat (cumulative utime+stime jiffies)
// and /proc/<pid>/status (VmRSS).
func procStatOfReal(pid int) (float64, int64, bool) {
	procReadTick()
	b, err := os.ReadFile(tunnelProcRoot + "/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, false
	}
	// comm may contain spaces/parens: split after the LAST ')'.
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 || i+2 > len(s) {
		return 0, 0, false
	}
	f := strings.Fields(s[i+2:]) // f[0] = state (field 3)
	if len(f) < 13 {
		return 0, 0, false
	}
	utime, err1 := strconv.ParseFloat(f[11], 64) // field 14
	stime, err2 := strconv.ParseFloat(f[12], 64) // field 15
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	rss, _ := procRSSOf(pid)
	return utime + stime, rss, true
}

// procRSSOf reads VmRSS from /proc/<pid>/status (kB -> bytes).
func procRSSOf(pid int) (int64, bool) {
	procReadTick()
	b, err := os.ReadFile(tunnelProcRoot + "/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			f := strings.Fields(line)
			if len(f) < 2 {
				return 0, false
			}
			kb, err := strconv.ParseFloat(f[1], 64)
			if err != nil {
				return 0, false
			}
			return int64(kb * 1024), true
		}
	}
	return 0, false
}

// procChildrenOfReal reads /proc/<pid>/task/<pid>/children (the kernel's
// one-line child list).
func procChildrenOfReal(pid int) []int {
	procReadTick()
	b, err := os.ReadFile(tunnelProcRoot + "/" + strconv.Itoa(pid) + "/task/" + strconv.Itoa(pid) + "/children")
	if err != nil {
		return nil
	}
	var out []int
	for _, f := range strings.Fields(string(b)) {
		if c, err := strconv.Atoi(f); err == nil && c > 0 {
			out = append(out, c)
		}
	}
	return out
}

// procTreeOf walks a process tree from root (BFS, depth-capped,
// deduplicated through seen so one pid never lands in two trees).
func procTreeOf(root int, seen map[int]bool) []int {
	if seen[root] {
		return nil
	}
	out := []int{root}
	seen[root] = true
	frontier := []int{root}
	for depth := 0; depth < 3 && len(frontier) > 0; depth++ {
		var next []int
		for _, pid := range frontier {
			for _, c := range procChildrenOf(pid) {
				if !seen[c] {
					seen[c] = true
					out = append(out, c)
					next = append(next, c)
				}
			}
		}
		frontier = next
	}
	return out
}

// tunnelProcReset drops the CPU baselines (no process tunnels run —
// nothing to sample until the next tunnel start).
func tunnelProcReset() {
	tunnelProcMu.Lock()
	tunnelProcPrev = map[int]float64{}
	tunnelProcHavePrev = false
	tunnelProcMu.Unlock()
}

// agentSampleTunnelProc samples every running tunnel's process tree and
// returns the protocol view. Tunnels without processes (kernel-only
// engines or between restarts) are simply absent — the consumer shows
// known=false. With NO process tunnels at all it resets the baseline
// and reads nothing.
func agentSampleTunnelProc(mgr *engine.Manager) []protocol.TunnelProc {
	pidsByTunnel := mgr.ProcessPIDs()
	if len(pidsByTunnel) == 0 {
		tunnelProcReset()
		return nil
	}
	now := tunnelProcNow()

	// Walk each tunnel's tree (pids shared across tunnels would be a
	// driver bug, but seen keeps the numbers honest anyway).
	seen := map[int]bool{}
	tree := map[string][]int{}
	for id, roots := range pidsByTunnel {
		var t []int
		for _, r := range roots {
			t = append(t, procTreeOf(r, seen)...)
		}
		if len(t) > 0 {
			tree[id] = t
		}
	}
	if len(tree) == 0 {
		tunnelProcReset()
		return nil
	}

	tunnelProcMu.Lock()
	defer tunnelProcMu.Unlock()

	// Wall clock since the previous sample (first sample: CPU 0).
	var dt float64
	if tunnelProcHavePrev {
		dt = now.Sub(tunnelProcPrevAt).Seconds()
	}
	prevAt := now
	havePrev := true

	live := map[int]bool{}
	cur := map[int]float64{} // this sample's cumulative jiffies per pid
	out := make([]protocol.TunnelProc, 0, len(tree))
	for id, pids := range tree {
		tp := protocol.TunnelProc{TunnelID: id}
		var jiffies float64
		var rss int64
		knownAny := false
		for _, pid := range pids {
			j, r, ok := procStatOf(pid)
			if !ok {
				continue // vanished between listing and read
			}
			live[pid] = true
			cur[pid] = j
			knownAny = true
			jiffies += j
			rss += r
			if prev, sampled := tunnelProcPrev[pid]; sampled && dt > 0 {
				tp.CPUPercent += (j - prev) / procClkTck / dt * 100
			}
		}
		if !knownAny {
			continue // every pid of this tree vanished
		}
		tp.Known = true
		tp.RSSBytes = rss
		tp.Processes = len(pids)
		out = append(out, tp)
	}
	// Swap in this sample as the next baseline; forget dead pids.
	tunnelProcPrevAt = prevAt
	tunnelProcHavePrev = havePrev
	tunnelProcPrev = cur
	return out
}
