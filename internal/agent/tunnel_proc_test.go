package agent

// tunnel_proc_test.go — the /proc sampler and the ProcessInfoer path
// (Phase 11): RSS/CPU over a fake process tree, honest known=false when
// the tree is unreadable, and ZERO /proc reads with no process tunnels
// (idle footprint unchanged).

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	protocol "github.com/Dark-modem/quantum-protocol"
)

// stubPIDDriver is a driver whose ProcessPIDs answer is scripted.
type stubPIDDriver struct {
	engine.Driver
	pids atomic.Value // []int
}

func (d *stubPIDDriver) ProcessPIDs(inst engine.Instance) []int {
	if p, ok := d.pids.Load().([]int); ok {
		return p
	}
	return nil
}

func mustJSONRaw2(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newProcTestManager(t *testing.T, drv engine.Driver) (*engine.Manager, *engine.FakeEngine) {
	t.Helper()
	reg := engine.NewRegistry()
	fake := engine.NewFakeEngine("fake")
	if err := reg.Register(fake); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(drv); err != nil {
		t.Fatal(err)
	}
	return engine.NewManager(reg), fake
}

func TestAgentSampleTunnelProcIdleDoesNoProcReads(t *testing.T) {
	mgr, _ := newProcTestManager(t, &stubPIDDriver{Driver: engine.NewFakeEngine("procy")})
	var reads int64
	procReadCounter = &reads
	t.Cleanup(func() { procReadCounter = nil })

	// Nothing reconciled: the sampler must read NOTHING and report nil.
	if got := agentSampleTunnelProc(mgr); got != nil {
		t.Fatalf("idle sampler must return nil, got %+v", got)
	}
	if reads != 0 {
		t.Fatalf("idle sampler did %d /proc reads (must be 0)", reads)
	}
	// And the baseline was reset (no stale CPU jiffies survive).
	tunnelProcMu.Lock()
	n := len(tunnelProcPrev)
	tunnelProcMu.Unlock()
	if n != 0 {
		t.Fatalf("idle sampler left %d stale baselines", n)
	}
}

func TestAgentSampleTunnelProcTreeRSSAndCPU(t *testing.T) {
	drv := &stubPIDDriver{Driver: engine.NewFakeEngine("procy")}
	mgr, _ := newProcTestManager(t, drv)
	var reads int64
	procReadCounter = &reads
	t.Cleanup(func() { procReadCounter = nil })

	// One running tunnel whose tree is pid 100 + child 101.
	if res := mgr.Reconcile(context.Background(),
		[]engine.EngineSpec{{ID: "procy", Enabled: true}},
		[]engine.TunnelSpec{{ID: "t1", Engine: "procy", Enabled: true,
			Params: mustJSONRaw2(t, map[string]string{})}}); len(res.Started) != 1 {
		t.Fatalf("reconcile: %+v", res)
	}
	drv.pids.Store([]int{100})

	// Fake tree: pid 100 has child 101; each process carries jiffies+RSS.
	jiffies := map[int]float64{100: 50, 101: 100} // cumulative
	rss := map[int]int64{100: 10 << 20, 101: 5 << 20}
	okPids := map[int]bool{100: true, 101: true}
	procStatOf = func(pid int) (float64, int64, bool) {
		return jiffies[pid], rss[pid], okPids[pid]
	}
	procChildrenOf = func(pid int) []int {
		if pid == 100 {
			return []int{101}
		}
		return nil
	}
	clock := 1000 // seconds
	tunnelProcNow = func() time.Time { return time.Unix(int64(clock), 0) }
	t.Cleanup(func() {
		procStatOf = procStatOfReal
		procChildrenOf = procChildrenOfReal
		tunnelProcNow = time.Now
		tunnelProcReset()
	})

	// FIRST sample: RSS sums the tree (15 MiB), CPU has no baseline -> 0.
	got := agentSampleTunnelProc(mgr)
	if len(got) != 1 {
		t.Fatalf("samples = %+v", got)
	}
	p := got[0]
	if !p.Known || p.TunnelID != "t1" || p.RSSBytes != 15<<20 || p.Processes != 2 || p.CPUPercent != 0 {
		t.Fatalf("first sample: %+v (want known, rss 15MiB, 2 procs, cpu 0)", p)
	}

	// SECOND sample (+10s): pid 100 gained 50 jiffies, pid 101 gained 150
	// -> 200 jiffies / 100 per second / 10s = 0.2 CPU = 20%.
	jiffies[100], jiffies[101] = 100, 250
	clock += 10
	got = agentSampleTunnelProc(mgr)
	if len(got) != 1 {
		t.Fatalf("samples = %+v", got)
	}
	p = got[0]
	if p.CPUPercent < 19.9999 || p.CPUPercent > 20.0001 {
		t.Fatalf("cpu = %v, want 20", p.CPUPercent)
	}
	if p.RSSBytes != 15<<20 {
		t.Fatalf("rss = %v", p.RSSBytes)
	}

	// A tunnel whose whole tree vanished between listing and read is
	// absent — not zero — so the UI shows "unknown".
	drv.pids.Store([]int{777})
	okPids[777] = false
	got = agentSampleTunnelProc(mgr)
	if len(got) != 0 {
		t.Fatalf("vanished tree must be absent, got %+v", got)
	}
}

func TestAgentSampleTunnelProcUnreadableMeansUnknownNotZero(t *testing.T) {
	drv := &stubPIDDriver{Driver: engine.NewFakeEngine("procy")}
	mgr, _ := newProcTestManager(t, drv)
	if res := mgr.Reconcile(context.Background(),
		[]engine.EngineSpec{{ID: "procy", Enabled: true}},
		[]engine.TunnelSpec{{ID: "t9", Engine: "procy", Enabled: true,
			Params: mustJSONRaw2(t, map[string]string{})}}); len(res.Started) != 1 {
		t.Fatalf("reconcile: %+v", res)
	}
	// The driver reports a PID but /proc says no (kernel-only case, or
	// the process died): Known=false flows to the report honestly.
	drv.pids.Store([]int{424242})
	procStatOf = func(int) (float64, int64, bool) { return 0, 0, false }
	procChildrenOf = func(int) []int { return nil }
	t.Cleanup(func() {
		procStatOf = procStatOfReal
		procChildrenOf = procChildrenOfReal
		tunnelProcReset()
	})
	got := agentSampleTunnelProc(mgr)
	if len(got) != 0 {
		t.Fatalf("unreadable pid must be omitted (known=false upstream), got %+v", got)
	}
	_ = protocol.TunnelProc{} // anchor: the report type carries Known
}
