package agent

// engine_procinfo.go — the Phase-11 driver capabilities the v2 report
// needs, implemented once here for every driver instead of scattered
// through the driver files:
//
//   - ProcessInfoer (per-tunnel PIDs): every PROCESS driver answers from
//     its runs map; kernel-only engines (matrix) and kernel-mode
//     wireguard have no supervised process and don't implement it.
//   - BinaryInfoer (engine-level installed binary): derived from the
//     shared engine-dir layout (<engineDir>/[bin/]<version>/<binary>),
//     so drivers need no extra bookkeeping. matrix/wireguard report the
//     system tooling (tincd / wg) with no version string when unknown.

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-protocol"
)

// engineProcPIDs extracts the supervised PID from any run state (nil =
// no process now — kernel fallback, restarting, gone).
func engineProcPIDs(st engineProcState) []int {
	if st == nil {
		return nil
	}
	p := st.current()
	if p == nil {
		return nil
	}
	if pid := p.Pid(); pid > 0 {
		return []int{pid}
	}
	return nil
}

// ---- ProcessInfoer (one method per process driver) --------------------

func (d *FRPDriver) ProcessPIDs(inst engine.Instance) []int {
	return engineProcPIDs(d.runs.peek(inst.TunnelID))
}

func (d *BackhaulDriver) ProcessPIDs(inst engine.Instance) []int {
	return engineProcPIDs(d.runs.peek(inst.TunnelID))
}

func (d *ChiselDriver) ProcessPIDs(inst engine.Instance) []int {
	return engineProcPIDs(d.runs.peek(inst.TunnelID))
}

func (d *WstDriver) ProcessPIDs(inst engine.Instance) []int {
	return engineProcPIDs(d.runs.peek(inst.TunnelID))
}

func (d *GostDriver) ProcessPIDs(inst engine.Instance) []int {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
	return engineProcPIDs(st)
}

func (d *RatholeDriver) ProcessPIDs(inst engine.Instance) []int {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
	return engineProcPIDs(st)
}

func (d *XrayDriver) ProcessPIDs(inst engine.Instance) []int {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
	return engineProcPIDs(st)
}

// WgDriver: the wireguard-go FALLBACK is a process; kernel-mode has
// none and honestly reports no PIDs.
func (d *WgDriver) ProcessPIDs(inst engine.Instance) []int {
	d.mu.Lock()
	st := d.runs[inst.TunnelID]
	d.mu.Unlock()
	return engineProcPIDs(st)
}

// ---- BinaryInfoer -----------------------------------------------------

// engineBinaryInfoGeneric derives (path, version, bytes) from the shared
// engine-dir layout: the newest versioned directory holding an
// executable regular file wins. Layouts in the wild:
// <engineDir>/bin/<version>/<binary> (new engines) and
// <engineDir>/<version>/<binary> (frp/backhaul).
func engineBinaryInfoGeneric(engineID string) (string, string, int64, bool) {
	dir := engineEngineDir(engineID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", 0, false
	}
	// Candidate version dirs: <dir>/bin/* and <dir>/*.
	cands := []string{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() == "bin" {
			bins, err := os.ReadDir(filepath.Join(dir, "bin"))
			if err != nil {
				continue
			}
			for _, b := range bins {
				if b.IsDir() {
					cands = append(cands, filepath.Join(dir, "bin", b.Name()))
				}
			}
			continue
		}
		cands = append(cands, filepath.Join(dir, e.Name()))
	}
	// Newest install wins (mtime), name as a stable tiebreaker.
	type cand struct {
		path    string
		version string
		mod     time.Time
	}
	var scored []cand
	for _, c := range cands {
		fi, err := os.Stat(c)
		if err != nil {
			continue
		}
		scored = append(scored, cand{path: c, version: filepath.Base(c), mod: fi.ModTime()})
	}
	sort.Slice(scored, func(i, j int) bool {
		if !scored[i].mod.Equal(scored[j].mod) {
			return scored[i].mod.After(scored[j].mod)
		}
		return scored[i].version > scored[j].version
	})
	for _, c := range scored {
		files, err := os.ReadDir(c.path)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			full := filepath.Join(c.path, f.Name())
			fi, err := os.Stat(full)
			if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
				continue // only executables count as the engine binary
			}
			if strings.HasSuffix(f.Name(), ".sha256") || f.Name() == "artifact.sha256" {
				continue
			}
			return full, c.version, fi.Size(), true
		}
	}
	return "", "", 0, false
}

// agentEngineBinaryInfo dispatches per engine: kernel tooling for
// matrix/wireguard, the versioned engine dir for everything else.
func agentEngineBinaryInfo(engineID string) (path, version string, bytes int64, ok bool) {
	base := engine.BaseEngineID(engineID)
	switch base {
	case "matrix":
		if p, err := matrixTincPath(); err == nil {
			if fi, serr := os.Stat(p); serr == nil {
				return p, "", fi.Size(), true
			}
		}
		return "", "", 0, false
	case "wireguard":
		if p, err := exec.LookPath("wg"); err == nil {
			if fi, serr := os.Stat(p); serr == nil {
				return p, "", fi.Size(), true
			}
		}
		return "", "", 0, false
	}
	return engineBinaryInfoGeneric(base)
}

// engineBinaryInfoReport is the manager-facing shape for EnginesStatus
// consumers: (version, bytes, ok).
func engineBinaryInfoReport(engineID string) (string, int64, bool) {
	_, version, bytes, ok := agentEngineBinaryInfo(engineID)
	return version, bytes, ok
}

// compile-time anchors: every process driver satisfies ProcessInfoer.
var (
	_ engine.ProcessInfoer = (*FRPDriver)(nil)
	_ engine.ProcessInfoer = (*BackhaulDriver)(nil)
	_ engine.ProcessInfoer = (*ChiselDriver)(nil)
	_ engine.ProcessInfoer = (*WstDriver)(nil)
	_ engine.ProcessInfoer = (*GostDriver)(nil)
	_ engine.ProcessInfoer = (*RatholeDriver)(nil)
	_ engine.ProcessInfoer = (*XrayDriver)(nil)
	_ engine.ProcessInfoer = (*WgDriver)(nil)
)

var _ sync.Locker = (*sync.Mutex)(nil)

// agentEngineStatusReportV2 maps the manager's per-engine view into the
// protocol's engine_status report (Phase 11): installation state from
// the manager, version/bytes from the BinaryInfoer dispatch.
func agentEngineStatusReportV2(mgr *engine.Manager) []protocol.EngineStatusReport {
	out := make([]protocol.EngineStatusReport, 0, 4)
	for _, es := range mgr.EnginesStatus() {
		r := protocol.EngineStatusReport{
			Engine:    es.Engine,
			Installed: es.Installed,
			Instances: es.Instances,
			LastError: truncateReportDetail(es.LastError),
		}
		r.Enabled = mgr.EngineDesired(es.Engine)
		if version, bytes, ok := engineBinaryInfoReport(es.Engine); ok {
			r.Version = version
			r.BytesOnDisk = bytes
		}
		out = append(out, r)
	}
	return out
}

// truncateReportDetail keeps engine error text short (report bloat and
// log noise); the panel redacts before display anyway.
func truncateReportDetail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
