package agent

// Phase-10 TASK 2: Matrix lifecycle robustness — the real-server defects:
// a FAILED provisioning left its ownership file + QMX_* chains behind, and
// every retry then died on "firewall chain QMX_IN already exists; refusing
// to adopt it" (and the conflicting port stayed bound) until the tunnel
// was deleted and recreated. matrixSetup now rolls its OWN previous
// partial state back best-effort before the resource checks, so retries
// are clean. These hermetic tests pin: retry-after-failure succeeds and
// rolls back, foreign leftovers are still refused, matrix2/matrix3 derived
// resources are collision-free, failed provisioning rolls everything back,
// and a busy mesh port auto-shifts.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

// matrixLifecycleExec is a recording matrixExec: iptables -S reports a
// chain present only when the test seeded it; everything else succeeds
// (systemctl is-active included, so matrixServiceStart completes).
type matrixLifecycleExec struct {
	calls      []string
	chainsUp   map[string]bool // seeded "existing" chains (table|chain)
	failActive bool            // make systemctl is-active fail (service never comes up)
}

func (m *matrixLifecycleExec) run(name string, args ...string) (string, error) {
	s := strings.Join(args, " ")
	m.calls = append(m.calls, name+" "+s)
	switch name {
	case "iptables":
		fields := strings.Fields(s)
		// -X <chain> deletes the chain — the stub's chain table is
		// STATEFUL so a rollback is observable (chainsUp empties). The -X
		// rides mid-args ("iptables -t nat -X CHAIN").
		for i, f := range fields {
			if f == "-X" && i+1 < len(fields) {
				chain := fields[i+1]
				for k := range m.chainsUp {
					if strings.HasSuffix(k, "|"+chain) {
						delete(m.chainsUp, k)
					}
				}
			}
		}
		// -C asks "does this rule exist" — model absent by default so the
		// deletion loops in matrixDNATClear terminate (real iptables -D
		// errors once no rule is left; a stub that always succeeds loops
		// forever).
		if strings.Contains(s, " -C ") {
			return "", fmt.Errorf("rule absent")
		}
		if strings.Contains(s, " -S ") {
			chain := fields[len(fields)-1]
			table := "filter"
			if len(fields) >= 3 && fields[0] == "-t" {
				table = fields[1]
			}
			if m.chainsUp[table+"|"+chain] {
				return "", nil // chain exists
			}
			return "", fmt.Errorf("chain %s absent", chain)
		}
	case "ip":
		if strings.Contains(s, "route") {
			return "[]", nil
		}
		if strings.HasPrefix(s, "link show ") {
			return "", fmt.Errorf("interface does not exist")
		}
	case "systemctl":
		if m.failActive && strings.Contains(s, "is-active") {
			return "", fmt.Errorf("inactive")
		}
	}
	return "", nil
}

func matrixLifecycleLab(t *testing.T) *matrixLifecycleExec {
	t.Helper()
	m := &matrixLifecycleExec{chainsUp: map[string]bool{}}
	oldDir, oldUnit, oldTinc, oldExec := infra.ConfigDir, matrixUnitDir, matrixTincPath, matrixExec
	infra.ConfigDir = t.TempDir()
	matrixUnitDir = t.TempDir()
	matrixTincPath = func() (string, error) { return "/usr/sbin/tincd", nil }
	matrixExec = m.run
	t.Cleanup(func() {
		AgentOpsWait()
		infra.ConfigDir, matrixUnitDir, matrixTincPath, matrixExec = oldDir, oldUnit, oldTinc, oldExec
	})
	return m
}

func (m *matrixLifecycleExec) hasCall(substr string) bool {
	for _, c := range m.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

// TestMatrixRetryAfterFailedSetup: a failed provisioning left the
// ownership file + dir + unit + QMX chains behind; the RETRY (same
// instance, same bundle) must roll the leftovers back and succeed instead
// of refusing with "already exists".
func TestMatrixRetryAfterFailedSetup(t *testing.T) {
	m := matrixLifecycleLab(t)
	in := matrixInstance{ID: "matrix2"}

	// Seed the failed first attempt: ownership saved, unit + dir written,
	// the QMX2 chains left in iptables (the crash point of the incident).
	st := matrixState{Enabled: true, Network: in.network(), Role: "node",
		Family: "ipv4", Port: 2097, Addr: "203.0.113.9", Name: "nodeX",
		IP: in.firstPeer()}
	if err := saveMatrixInstance(in, st); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(matrixDirOf(in), 0o700)
	unit := filepath.Join(matrixUnitDir, in.unit())
	_ = os.WriteFile(unit, []byte("[Unit]\nDescription=stale\n"), 0o644)
	m.chainsUp["nat|"+in.chainPfx()+"_IN"] = true
	m.chainsUp["nat|"+in.chainPfx()+"_OUT"] = true

	// The RETRY: matrixSetup must adopt-and-roll-back, then provision.
	if err := matrixSetup(in, st, "main-host-file"); err != nil {
		t.Fatalf("retry after failed setup must succeed, got: %v", err)
	}
	// The rollback touched the stale unit (stop+disable before rewrite).
	if !m.hasCall("systemctl stop " + in.unit()) {
		t.Fatal("stale unit was not stopped during the rollback")
	}
	// The leftover chains were flushed/deleted by the rollback.
	if !m.hasCall("iptables -t nat -X " + in.chainPfx() + "_IN") {
		t.Fatal("leftover chain was not flushed during the rollback")
	}
	// The fresh provisioning completed: the unit re-written for THIS
	// instance (ExecStart points at this instance's config dir).
	b, rerr := os.ReadFile(unit)
	if rerr != nil {
		t.Fatalf("unit not re-written by the retry: %v", rerr)
	}
	// The regenerated unit is instance-specific: its description carries
	// the suffix and ExecStart points at THIS instance's config dir.
	if !strings.Contains(string(b), "tinc tunnel 2") || !strings.Contains(string(b), "matrix2") {
		t.Fatalf("unit is not the instance's own:\n%s", b)
	}
}

// TestMatrixForeignChainStillRefused: WITHOUT owned state, an existing
// QMX chain is a foreign resource — still refused (the adopt path must
// not turn a genuine conflict into a silent takeover).
func TestMatrixForeignChainStillRefused(t *testing.T) {
	m := matrixLifecycleLab(t)
	in := matrixInstance{ID: "matrix2"}
	m.chainsUp["nat|"+in.chainPfx()+"_IN"] = true // foreign: no ownership file

	err := matrixSetup(in, matrixState{Enabled: true, Network: in.network(),
		Role: "node", Family: "ipv4", Port: 2097, Name: "nodeX", IP: in.firstPeer()},
		"main-host-file")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("foreign chain must still be refused, got: %v", err)
	}
}

// TestMatrixSetupRollsBackOnServiceFailure: when the service never comes
// up, matrixSetup fails AND removes everything it created.
func TestMatrixSetupRollsBackOnServiceFailure(t *testing.T) {
	m := matrixLifecycleLab(t)
	m.failActive = true
	in := matrixInstance{ID: "matrix2"}
	err := matrixSetup(in, matrixState{Enabled: true, Network: in.network(),
		Role: "node", Family: "ipv4", Port: 2097, Name: "nodeX", IP: in.firstPeer()},
		"main-host-file")
	if err == nil {
		t.Fatal("setup must fail when the service never becomes active")
	}
	if _, serr := os.Stat(matrixStatePathOf(in)); serr == nil {
		t.Fatal("state file left behind after the rollback")
	}
	if _, derr := os.Stat(matrixDirOf(in)); derr == nil {
		t.Fatal("config dir left behind after the rollback")
	}
	if _, uerr := os.Stat(filepath.Join(matrixUnitDir, in.unit())); uerr == nil {
		t.Fatal("unit file left behind after the rollback")
	}
}

// TestMatrixInstancesCollisionFree: matrix2 and matrix3 (two instances on
// one pair) derive fully disjoint subnets, interfaces, units, chain
// prefixes, tags, pid files and hub IPs — and the subnets land on
// 10.254.(230+N).0/30 per the design.
func TestMatrixInstancesCollisionFree(t *testing.T) {
	a := matrixInstance{ID: "matrix2"}
	b := matrixInstance{ID: "matrix3"}
	if a.subnet() == b.subnet() || a.iface() == b.iface() || a.unit() == b.unit() ||
		a.chainPfx() == b.chainPfx() || a.tag() == b.tag() || a.pidFile() == b.pidFile() ||
		a.hubIP() == b.hubIP() || a.firstPeer() == b.firstPeer() || a.network() == b.network() {
		t.Fatalf("matrix2/matrix3 resources collide: %+v vs %+v", a, b)
	}
	if a.subnet() != "10.254.232.0/30" {
		t.Fatalf("matrix2 subnet = %q, want 10.254.232.0/30", a.subnet())
	}
	if b.subnet() != "10.254.233.0/30" {
		t.Fatalf("matrix3 subnet = %q, want 10.254.233.0/30", b.subnet())
	}
	if a.iface() != "qmx2" || b.iface() != "qmx3" {
		t.Fatalf("ifaces = %q / %q", a.iface(), b.iface())
	}
}

// TestMatrixBusyMeshPortAutoShifts: when the bundle's mesh port is taken,
// provisioning picks a free one instead of failing (and never collides
// with the forwarded ports).
func TestMatrixBusyMeshPortAutoShifts(t *testing.T) {
	m := matrixLifecycleLab(t)
	in := matrixInstance{ID: "matrix2"}
	// Occupy the classic 2097 and the first scan ports with real listeners.
	l0, _ := net.Listen("tcp", ":2097")
	defer l0.Close()
	l1, _ := net.Listen("tcp", ":21000")
	defer l1.Close()
	l1u, _ := net.ListenPacket("udp", ":21000")
	defer l1u.Close()

	picked, err := matrixAutoMeshPort(in, []int{25210})
	if err != nil {
		t.Fatalf("auto mesh port: %v", err)
	}
	if picked == 2097 || picked == 21000 || picked == 25210 {
		t.Fatalf("picked a busy/forbidden port %d", picked)
	}
	_ = m
}
