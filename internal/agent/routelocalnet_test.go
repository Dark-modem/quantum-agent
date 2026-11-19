package agent

// Phase14 ports TASK 1: route_localnet (RUNBOOK ITEM 35) tests. The
// sysctl read/write seams are swapped; nothing touches the host kernel.

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/balancer"
	protocol "github.com/Dark-modem/quantum-protocol"
)

// rlLoopbackScript renders a script that DNATs to loopback.
func rlLoopbackScript() string {
	return balancer.RenderForwardNFT([]balancer.ForwardRender{{ID: "fw-lb", ListenPort: 8443, Proto: "tcp", TargetPort: 8080,
		Targets: []balancer.BalTarget{{TunnelID: "s1", IP: "127.0.0.1", Port: 8080, Weight: 1}}}})
}

// TestScriptLoopbackDNAT pins the detector against the shapes the
// renderer actually emits.
func TestScriptLoopbackDNAT(t *testing.T) {
	if !balancer.ScriptHasLoopbackDNAT(rlLoopbackScript()) {
		t.Fatalf("loopback target not detected:\n%s", rlLoopbackScript())
	}
	// Address-only map with the single-port suffix.
	uni := balancer.RenderForwardNFT([]balancer.ForwardRender{{ID: "fw-lb", ListenPort: 8443, Proto: "tcp", TargetPort: 8080,
		Targets: []balancer.BalTarget{{TunnelID: "s1", IP: "127.0.0.1", Port: 0, Weight: 1}}}})
	if !balancer.ScriptHasLoopbackDNAT(uni) {
		t.Fatalf("uniform-fallback loopback not detected:\n%s", uni)
	}
	// Mixed map: one loopback element among foreign ones.
	mixed := balancer.RenderForwardNFT([]balancer.ForwardRender{{ID: "fw-mix", ListenPort: 8443, Proto: "tcp", TargetPort: 0,
		Targets: []balancer.BalTarget{
			{TunnelID: "s1", IP: "127.0.0.1", Port: 8080, Weight: 1},
			{TunnelID: "s2", IP: "10.189.0.3", Port: 5201, Weight: 1},
		}}})
	if !balancer.ScriptHasLoopbackDNAT(mixed) {
		t.Fatalf("mixed loopback element not detected:\n%s", mixed)
	}
	// Non-map dnat forms.
	if !balancer.ScriptHasLoopbackDNAT(" chain c {\n  tcp dport 8 dnat to 127.0.0.1\n") {
		t.Fatal("non-map loopback dnat not detected")
	}
	if !balancer.ScriptHasLoopbackDNAT(" chain c {\n  tcp dport 8 dnat to 127.0.0.1:8080\n") {
		t.Fatal("non-map loopback dnat with port not detected")
	}
	// Non-loopback scripts.
	if balancer.ScriptHasLoopbackDNAT(balancer.RenderForwardNFT(nil)) {
		t.Fatal("empty ruleset flagged as loopback")
	}
	plain := balancer.RenderForwardNFT([]balancer.ForwardRender{{ID: "fw-ok", ListenPort: 8443, Proto: "tcp", TargetPort: 8080,
		Targets: []balancer.BalTarget{{TunnelID: "s1", IP: "10.189.0.2", Port: 8080, Weight: 1}}}})
	if balancer.ScriptHasLoopbackDNAT(plain) {
		t.Fatalf("foreign-only targets flagged:\n%s", plain)
	}
}

// TestScriptLoopbackDNATCorrection: 127.0.0.2 IS inside 127.0.0.0/8 —
// the detector must flag it; foreign addresses must not be flagged.
func TestScriptLoopbackDNATCorrection(t *testing.T) {
	if !balancer.ScriptHasLoopbackDNAT(" chain c {\n  tcp dport 8 dnat to 127.0.0.2\n") {
		t.Fatal("127.0.0.2 (inside 127.0.0.0/8) not detected")
	}
	if balancer.ScriptHasLoopbackDNAT(" chain c {\n  tcp dport 8 dnat to 10.189.0.2\n") {
		t.Fatal("foreign address flagged")
	}
}

// TestRouteLocalnetEnsureAndRestore: the first loopback render captures
// the previous value and writes 1; the first loopback-free render
// restores the captured value and forgets it. Only captured values are
// ever written back; re-ensuring an active knob is a no-op.
func TestRouteLocalnetEnsureAndRestore(t *testing.T) {
	bal := balancer.New(nil, nil)
	var writes [][2]string
	readVal := "0"
	oldRead, oldWrite, oldApply := balancer.RlSysctlRead, balancer.RlSysctlWrite, balancer.ApplyNFTScript
	balancer.RlSysctlRead = func(key string) (string, error) { return readVal, nil }
	balancer.RlSysctlWrite = func(key, val string) error { writes = append(writes, [2]string{key, val}); return nil }
	balancer.ApplyNFTScript = func(string) error { return nil }
	t.Cleanup(func() {
		balancer.RlSysctlRead, balancer.RlSysctlWrite, balancer.ApplyNFTScript = oldRead, oldWrite, oldApply
	})

	loopScript := rlLoopbackScript()
	if err := bal.ApplyScriptRL(loopScript); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(writes) != 1 || writes[0][0] != balancer.RlSysctlAll || writes[0][1] != "1" {
		t.Fatalf("ensure writes = %v", writes)
	}
	if !bal.RlActive || bal.RlSaved != "0" {
		t.Fatalf("state after ensure: active=%v saved=%q", bal.RlActive, bal.RlSaved)
	}
	// Idempotent: a loopback re-render must not re-write the knob.
	if err := bal.ApplyScriptRL(loopScript); err != nil {
		t.Fatal(err)
	}
	if len(writes) != 1 {
		t.Fatalf("re-ensure must be a no-op, writes = %v", writes)
	}
	// A loopback-free render restores the CAPTURED value and forgets it.
	if err := bal.ApplyScriptRL(balancer.RenderForwardNFT(nil)); err != nil {
		t.Fatal(err)
	}
	if len(writes) != 2 || writes[1][0] != balancer.RlSysctlAll || writes[1][1] != "0" {
		t.Fatalf("restore write = %v, want [%s=0]", writes[1:], balancer.RlSysctlAll)
	}
	if bal.RlActive || bal.RlSaved != "" || bal.RlIface != "" {
		t.Fatalf("state after restore: active=%v saved=%q iface=%q", bal.RlActive, bal.RlSaved, bal.RlIface)
	}
}

// TestRouteLocalnetAlreadyOne: a knob that already read 1 records
// before="1" — the restore writes the same value it captured (never a
// guess of 0).
func TestRouteLocalnetAlreadyOne(t *testing.T) {
	bal := balancer.New(nil, nil)
	var writes [][2]string
	oldRead, oldWrite, oldApply := balancer.RlSysctlRead, balancer.RlSysctlWrite, balancer.ApplyNFTScript
	balancer.RlSysctlRead = func(string) (string, error) { return "1", nil }
	balancer.RlSysctlWrite = func(key, val string) error { writes = append(writes, [2]string{key, val}); return nil }
	balancer.ApplyNFTScript = func(string) error { return nil }
	t.Cleanup(func() {
		balancer.RlSysctlRead, balancer.RlSysctlWrite, balancer.ApplyNFTScript = oldRead, oldWrite, oldApply
	})

	if err := bal.ApplyScriptRL(rlLoopbackScript()); err != nil {
		t.Fatal(err)
	}
	if bal.RlSaved != "1" {
		t.Fatalf("before value must be captured verbatim, got %q", bal.RlSaved)
	}
	if err := bal.ApplyScriptRL(balancer.RenderForwardNFT(nil)); err != nil {
		t.Fatal(err)
	}
	if len(writes) != 2 || writes[1][1] != "1" {
		t.Fatalf("restore must write the captured 1, writes = %v", writes)
	}
}

// TestRouteLocalnetIfaceKnob: when the listen interface is known the
// per-interface knob is set and captured alongside 'all'; its restore
// mirrors the same captured values.
func TestRouteLocalnetIfaceKnob(t *testing.T) {
	bal := balancer.New(nil, nil)
	const ifaceKey = "net.ipv4.conf.eth0.route_localnet"
	var writes [][2]string
	oldRead, oldWrite, oldApply, oldIface := balancer.RlSysctlRead, balancer.RlSysctlWrite, balancer.ApplyNFTScript, balancer.RlListenIface
	balancer.RlSysctlRead = func(key string) (string, error) {
		if key == ifaceKey {
			return "0", nil
		}
		return "0", nil
	}
	balancer.RlSysctlWrite = func(key, val string) error { writes = append(writes, [2]string{key, val}); return nil }
	balancer.ApplyNFTScript = func(string) error { return nil }
	balancer.RlListenIface = func(int) string { return "eth0" }
	t.Cleanup(func() {
		balancer.RlSysctlRead, balancer.RlSysctlWrite, balancer.ApplyNFTScript, balancer.RlListenIface = oldRead, oldWrite, oldApply, oldIface
	})

	if err := bal.ApplyScriptRL(rlLoopbackScript(), 8443); err != nil {
		t.Fatal(err)
	}
	want := [][2]string{{balancer.RlSysctlAll, "1"}, {ifaceKey, "1"}}
	if len(writes) != 2 || writes[0] != want[0] || writes[1] != want[1] {
		t.Fatalf("ensure writes = %v, want %v", writes, want)
	}
	if bal.RlIface != "eth0" || bal.RlSavedIface != "0" {
		t.Fatalf("iface state: iface=%q saved=%q", bal.RlIface, bal.RlSavedIface)
	}
	if err := bal.ApplyScriptRL(balancer.RenderForwardNFT(nil)); err != nil {
		t.Fatal(err)
	}
	want = [][2]string{{balancer.RlSysctlAll, "1"}, {ifaceKey, "1"}, {balancer.RlSysctlAll, "0"}, {ifaceKey, "0"}}
	if len(writes) != 4 {
		t.Fatalf("restore writes = %v, want %v", writes, want)
	}
	if writes[2] != want[2] || writes[3] != want[3] {
		t.Fatalf("restore order/values wrong: %v", writes[2:])
	}
}

// TestRouteLocalnetIfaceReadFailureIsNonFatal: an unknown per-interface
// key on this kernel must not fail the apply ('all' covers it).
func TestRouteLocalnetIfaceReadFailureIsNonFatal(t *testing.T) {
	bal := balancer.New(nil, nil)
	var writes [][2]string
	oldRead, oldWrite, oldApply, oldIface := balancer.RlSysctlRead, balancer.RlSysctlWrite, balancer.ApplyNFTScript, balancer.RlListenIface
	balancer.RlSysctlRead = func(key string) (string, error) {
		if key != balancer.RlSysctlAll {
			return "", os.ErrNotExist
		}
		return "0", nil
	}
	balancer.RlSysctlWrite = func(key, val string) error { writes = append(writes, [2]string{key, val}); return nil }
	balancer.ApplyNFTScript = func(string) error { return nil }
	balancer.RlListenIface = func(int) string { return "eth0" }
	t.Cleanup(func() {
		balancer.RlSysctlRead, balancer.RlSysctlWrite, balancer.ApplyNFTScript, balancer.RlListenIface = oldRead, oldWrite, oldApply, oldIface
	})

	if err := bal.ApplyScriptRL(rlLoopbackScript(), 8443); err != nil {
		t.Fatalf("iface read failure must be non-fatal: %v", err)
	}
	if len(writes) != 1 || writes[0][0] != balancer.RlSysctlAll {
		t.Fatalf("only the 'all' knob must be written: %v", writes)
	}
	// The 'all' knob IS active with its captured value; the iface part is
	// simply absent (unknown key on this kernel).
	if !bal.RlActive || bal.RlSaved != "0" || bal.RlIface != "" {
		t.Fatalf("state: active=%v saved=%q iface=%q", bal.RlActive, bal.RlSaved, bal.RlIface)
	}
}

// TestBalancerRouteLocalnetLifecycle: end-to-end through the balancer —
// a loopback forward flips the knob on (and the persisted tick report
// says so); removing the forward restores it. The balancer's nft seam is
// the harness's, the sysctl seams are swapped here.
func TestBalancerRouteLocalnetLifecycle(t *testing.T) {
	h := newBalHarness(t)
	var writes [][2]string
	oldRead, oldWrite := balancer.RlSysctlRead, balancer.RlSysctlWrite
	balancer.RlSysctlRead = func(string) (string, error) { return "0", nil }
	balancer.RlSysctlWrite = func(key, val string) error { writes = append(writes, [2]string{key, val}); return nil }
	t.Cleanup(func() { balancer.RlSysctlRead, balancer.RlSysctlWrite = oldRead, oldWrite })

	readReport := func() balancer.TickReport {
		t.Helper()
		b, err := os.ReadFile(balancer.StatusPath())
		if err != nil {
			t.Fatalf("balancer report: %v", err)
		}
		var rep balancer.TickReport
		if json.Unmarshal(b, &rep) != nil {
			t.Fatal("balancer report unreadable")
		}
		return rep
	}

	d := protocol.DesiredV2{
		Revision: "1796470000000000400",
		Balancing: &protocol.BalancingPolicy{
			HealthCheck: protocol.HealthCheckParams{IntervalS: 3600},
		},
		Forwards: []protocol.ForwardRule{{ID: "fw-lb", ListenPort: 18443, Proto: "tcp", Target: "127.0.0.1:18080", TargetPort: 18080}},
	}
	h.bal.Reconcile(&d)
	time.Sleep(50 * time.Millisecond)
	if len(writes) != 1 || writes[0] != [2]string{balancer.RlSysctlAll, "1"} {
		t.Fatalf("ensure writes = %v", writes)
	}
	if rep := readReport(); !rep.RouteLocalnet {
		t.Fatal("persisted tick report must carry route_localnet=true while the loopback forward is enforced")
	}

	// The loopback forward leaves the desired state: restore.
	d2 := d
	d2.Revision = "1796470000000000401"
	d2.Forwards = nil
	h.bal.Reconcile(&d2)
	time.Sleep(50 * time.Millisecond)
	if len(writes) != 2 || writes[1] != [2]string{balancer.RlSysctlAll, "0"} {
		t.Fatalf("restore writes = %v", writes)
	}
	if rep := readReport(); rep.RouteLocalnet {
		t.Fatal("persisted tick report must carry route_localnet=false after the restore")
	}
}

// TestDiagCollectNetSection: the diag bundle surfaces the knob under the
// "net" key (the additive diag route — the protocol is NOT extended).
