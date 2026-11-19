package agent

// Phase14 ports TASK 1: the apply-path preflight tests. All hermetic —
// the ss listing, the ephemeral range and the registry path are seams;
// the "held port" is a real net.Listen socket in the test process whose
// ss line is synthesized (the infra.Runner seam never touches the host).

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/infra"
	protocol "github.com/Dark-modem/quantum-protocol"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// pfPortSeams installs a synthetic ss listing + ephemeral range and
// points the port registry at the test's config dir; restores on cleanup.
func pfPortSeams(t *testing.T, lines string, ephLo, ephHi int) {
	t.Helper()
	oldSS, oldEph, oldReg := portSSRun, portEphemeralRange, portRegPath
	portSSRun = func() (string, error) { return lines, nil }
	portEphemeralRange = func() (int, int) { return ephLo, ephHi }
	portRegPath = filepath.Join(infra.ConfigDir, "port_registry.json")
	t.Cleanup(func() { portSSRun, portEphemeralRange, portRegPath = oldSS, oldEph, oldReg })
}

// pfSSLine renders one ss -Htulnp listener line for proto/port/proc/pid.
func pfSSLine(proto string, port int, proc string, pid int) string {
	return fmt.Sprintf("%s LISTEN 0 128 127.0.0.1:%d 0.0.0.0:* users:((\"%s\",pid=%d,fd=3))\n", proto, port, proc, pid)
}

// pfPortFromListener binds a real loopback listener and returns its port
// (the port the preflight must refuse).
func pfPortFromListener(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a loopback listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// pfDesiredWithTunnel builds a one-tunnel DesiredV2 with engine_params.
func pfDesiredWithTunnel(rev string, params string) protocol.DesiredV2 {
	return protocol.DesiredV2{
		Revision: rev,
		Engines:  []protocol.EngineSpec{{ID: "fake", Enabled: true}},
		Tunnels: []protocol.TunnelSpec{{
			ID: "t1", TopologyID: "topo-pf", LocalServer: "ir", RemoteServer: "hz",
			Engine: "fake", EngineParams: json.RawMessage(params), Enabled: true,
		}},
	}
}

// pfSwapTestDriver replaces the package-level v2 test driver (e.g. with
// one carrying extra capabilities) and rebuilds the runtime; cleanup
// drops the swap.
func pfSwapTestDriver(t *testing.T, d engine.Driver) {
	t.Helper()
	resetV2Runtime()
	agentV2TestDriver = d
	matrixDriverRegOnce = sync.Once{}
	t.Cleanup(func() { resetV2Runtime(); agentV2TestDriver = nil })
}

// TestPreflightPortConflictRefusesTunnel: a tunnel whose engine_params
// listen port is held by a listener is refused with the holder name and
// the next free ports as suggestions; nothing starts.
func TestPreflightPortConflictRefusesTunnel(t *testing.T) {
	withTempConfig(t)
	port := pfPortFromListener(t)
	// The ephemeral-range seam moves OUT of the way so the held port is
	// judged on its listener, not on its range.
	pfPortSeams(t, pfSSLine("tcp", port, "testsink", 4242), 61000, 65535)
	registerV2TestDriver(t)

	d := pfDesiredWithTunnel("1796470000000000300", fmt.Sprintf(`{"listen_port":%d,"instance_hint":"x"}`, port))
	ack := agentApplyDesiredV2(&d)
	if !ack.OK {
		t.Fatalf("partial preflight failure must not fail the ack: %+v", ack)
	}
	errLine, ok := ack.Detail["preflight_error_0"]
	if !ok {
		t.Fatalf("no preflight error in ack detail: %+v", ack.Detail)
	}
	want := fmt.Sprintf("tunnel t1: port %d: in use by \"testsink\" (choose a free port; suggested free: %d, %d, %d)", port, port+1, port+2, port+3)
	if errLine != want {
		t.Fatalf("preflight error =\n  %s\nwant\n  %s", errLine, want)
	}
	mgr, _, err := agentV2RuntimeRef()
	if err != nil {
		t.Fatal(err)
	}
	if mgr.RunningCount() != 0 {
		t.Fatalf("preflight-failed tunnel must not start (running=%d)", mgr.RunningCount())
	}
}

// TestPreflightValidParamsPass: free ports validate and the tunnel starts.
func TestPreflightValidParamsPass(t *testing.T) {
	withTempConfig(t)
	port := pfPortFromListener(t)
	pfPortSeams(t, pfSSLine("tcp", port, "testsink", 4242), 61000, 65535) // port held, tunnel uses port+7
	registerV2TestDriver(t)

	d := pfDesiredWithTunnel("1796470000000000301", fmt.Sprintf(`{"listen_port":%d}`, port+7))
	ack := agentApplyDesiredV2(&d)
	if !ack.OK {
		t.Fatalf("valid params refused: %+v", ack)
	}
	if len(ack.Detail) != 0 {
		t.Fatalf("unexpected ack detail: %+v", ack.Detail)
	}
	mgr, _, err := agentV2RuntimeRef()
	if err != nil {
		t.Fatal(err)
	}
	if mgr.RunningCount() != 1 {
		t.Fatalf("valid tunnel must start (running=%d)", mgr.RunningCount())
	}
}

// TestPreflightValidateRefusal: a driver Validate failure withholds the
// tunnel from Reconcile (Manager never calls Validate itself — the
// preflight does, in the apply path).
func TestPreflightValidateRefusal(t *testing.T) {
	withTempConfig(t)
	pfPortSeams(t, "", 61000, 65535)
	fake := registerV2TestDriver(t)
	fake.FailValidate("bad-params", fmt.Errorf("engine: params rejected"))

	d := pfDesiredWithTunnel("1796470000000000302", `{"note":"bad-params"}`)
	d.Tunnels = append(d.Tunnels, protocol.TunnelSpec{
		ID: "t2", TopologyID: "topo-pf", LocalServer: "ir", RemoteServer: "hz",
		Engine: "fake", EngineParams: json.RawMessage(`{"note":"fine"}`), Enabled: true,
	})
	ack := agentApplyDesiredV2(&d)
	if !ack.OK {
		t.Fatalf("partial failure must not fail the ack: %+v", ack)
	}
	e, ok := ack.Detail["preflight_error_0"]
	if !ok || !strings.Contains(e, "tunnel t1: validate: engine: params rejected") {
		t.Fatalf("validate refusal missing/wrong: %+v", ack.Detail)
	}
	if _, ok := ack.Detail["preflight_error_1"]; ok {
		t.Fatalf("t2 validated cleanly, must not be refused: %+v", ack.Detail)
	}
	mgr, _, err := agentV2RuntimeRef()
	if err != nil {
		t.Fatal(err)
	}
	if mgr.RunningCount() != 1 {
		t.Fatalf("only the valid tunnel must start (running=%d)", mgr.RunningCount())
	}
}

// TestPreflightReapplySameParamsSkipsPortCheck: an identical re-apply of
// a running tunnel (panel re-push, boot replay) must NOT be refused by
// the tunnel's own listener.
func TestPreflightReapplySameParamsSkipsPortCheck(t *testing.T) {
	withTempConfig(t)
	port := pfPortFromListener(t)
	registerV2TestDriver(t)

	d := pfDesiredWithTunnel("1796470000000000303", fmt.Sprintf(`{"listen_port":%d}`, port))
	pfPortSeams(t, "", 61000, 65535) // nothing held yet
	if ack := agentApplyDesiredV2(&d); !ack.OK {
		t.Fatalf("first apply: %+v", ack)
	}
	// Now the tunnel's own engine "listens" (foreign pid: NOT our
	// self-PID allowance — only the identical-params skip may pass this).
	pfPortSeams(t, pfSSLine("tcp", port, "tunnel-engine", 9999), 61000, 65535)
	next := d
	next.Revision = "1796470000000000304"
	ack := agentApplyDesiredV2(&next)
	if !ack.OK {
		t.Fatalf("re-apply refused: %+v", ack)
	}
	for k := range ack.Detail {
		if strings.HasPrefix(k, "preflight_error") {
			t.Fatalf("identical re-apply must skip the port check: %+v", ack.Detail)
		}
	}
	mgr, _, err := agentV2RuntimeRef()
	if err != nil {
		t.Fatal(err)
	}
	if mgr.RunningCount() != 1 {
		t.Fatalf("running tunnel must stay up (running=%d)", mgr.RunningCount())
	}
}

// pfProcDriver wraps FakeEngine with a fixed PID list so the self-PID
// allowance is exercisable without a real process (FakeEngine is not a
// ProcessInfoer).
type pfProcDriver struct {
	*engine.FakeEngine
	pid int
}

func (d *pfProcDriver) ProcessPIDs(inst engine.Instance) []int { return []int{d.pid} }

// TestPreflightSelfHeldPIDAllowed: a CHANGED-params re-apply of a running
// tunnel is allowed to keep a port its own current process holds (the
// driver reload rebinds it deliberately); the same port held by a foreign
// pid is refused and the tunnel keeps its CURRENT params.
func TestPreflightSelfHeldPIDAllowed(t *testing.T) {
	withTempConfig(t)
	const port = 5201 // fixed: the ss listing is synthetic
	pfPortSeams(t, "", 61000, 65535)
	registerV2TestDriver(t)

	d := pfDesiredWithTunnel("1796470000000000305", `{"listen_port":5201}`)
	if ack := agentApplyDesiredV2(&d); !ack.OK {
		t.Fatalf("first apply: %+v", ack)
	}

	// Swap the registered test driver for one whose ProcessPIDs answers
	// 4242 (the tunnel's "own process") and rebuild the runtime. The
	// rebuild wipes the manager (and the in-memory fence floor), so the
	// tunnel is re-established under a newer revision.
	procDriver := &pfProcDriver{FakeEngine: engine.NewFakeEngine("fake"), pid: 4242}
	pfSwapTestDriver(t, procDriver)
	redo := pfDesiredWithTunnel("1796470000000000306", `{"listen_port":5201}`)
	if ack := agentApplyDesiredV2(&redo); !ack.OK {
		t.Fatalf("re-apply after runtime swap: %+v", ack)
	}
	mgr, _, err := agentV2RuntimeRef()
	if err != nil {
		t.Fatal(err)
	}
	if mgr.RunningCount() != 1 {
		t.Fatalf("setup: tunnel must run (running=%d)", mgr.RunningCount())
	}

	// The tunnel's OWN process holds the port: a changed-params re-apply
	// (mtu added) keeps the same port and must be allowed.
	pfPortSeams(t, pfSSLine("tcp", port, "tunnel-engine", 4242), 61000, 65535)
	next := pfDesiredWithTunnel("1796470000000000307", `{"listen_port":5201,"mtu":1400}`)
	ack := agentApplyDesiredV2(&next)
	if !ack.OK {
		t.Fatalf("self-held rebind refused: %+v", ack)
	}
	if len(ack.Detail) != 0 {
		t.Fatalf("self-held port must not be a conflict: %+v", ack.Detail)
	}

	// A FOREIGN process on the same port: refused; the tunnel keeps its
	// CURRENT params (not torn down, not reloaded with the new ones).
	pfPortSeams(t, pfSSLine("tcp", port, "testsink", 4243), 61000, 65535)
	next2 := pfDesiredWithTunnel("1796470000000000308", `{"listen_port":5201,"mtu":1300}`)
	ack = agentApplyDesiredV2(&next2)
	if !ack.OK {
		t.Fatalf("partial failure must not fail the ack: %+v", ack)
	}
	e, ok := ack.Detail["preflight_error_0"]
	if !ok || !strings.Contains(e, "in use by \"testsink\"") {
		t.Fatalf("foreign-holder refusal missing/wrong: %+v", ack.Detail)
	}
	inst, running := mgr.Instance("t1")
	if !running {
		t.Fatal("refused tunnel must keep running")
	}
	// The CURRENT params are the ones from the last SUCCESSFUL apply (the
	// self-held mtu:1400 change) — the refused mtu:1300 change must not
	// have taken.
	if string(inst.Params) != `{"listen_port":5201,"mtu":1400}` {
		t.Fatalf("refused tunnel must keep its CURRENT params, got %s", inst.Params)
	}
}

// TestPreflightEphemeralRefused: a port inside the kernel ephemeral range
// is refused with the range named.
func TestPreflightEphemeralRefused(t *testing.T) {
	withTempConfig(t)
	pfPortSeams(t, "", 40000, 40010)
	registerV2TestDriver(t)
	d := pfDesiredWithTunnel("1796470000000000308", `{"listen_port":40005}`)
	ack := agentApplyDesiredV2(&d)
	e, ok := ack.Detail["preflight_error_0"]
	if !ok || !strings.Contains(e, "ephemeral range 40000-40010") {
		t.Fatalf("ephemeral refusal missing/wrong: %+v", ack.Detail)
	}
}

// TestPreflightForwardListenPort: a forward whose listen port is held is
// dropped from the enforced state with a precise error; a free one passes.
func TestPreflightForwardListenPort(t *testing.T) {
	withTempConfig(t)
	port := pfPortFromListener(t)
	pfPortSeams(t, pfSSLine("udp", port, "testsink", 4242), 61000, 65535)
	registerV2TestDriver(t)

	d := pfDesiredWithTunnel("1796470000000000309", `{"listen_port":22}`)
	d.Forwards = []protocol.ForwardRule{
		{ID: "fw-bad", ListenPort: port, Proto: "udp", Target: "10.189.0.9", TargetPort: 22},
		{ID: "fw-ok", ListenPort: port + 5, Proto: "tcp", Target: "10.189.0.9", TargetPort: 22},
	}
	ack := agentApplyDesiredV2(&d)
	if !ack.OK {
		t.Fatalf("apply: %+v", ack)
	}
	e, ok := ack.Detail["preflight_error_0"]
	if !ok || !strings.Contains(e, fmt.Sprintf("forward fw-bad: port %d: in use by \"testsink\"", port)) {
		t.Fatalf("forward refusal missing/wrong: %+v", ack.Detail)
	}
	_, bal, err := agentV2RuntimeRef()
	if err != nil {
		t.Fatal(err)
	}
	snap := bal.ForwardRuntimeSnapshot()
	if len(snap) != 1 || snap[0].ID != "fw-ok" {
		t.Fatalf("enforced forwards = %+v, want only fw-ok", snap)
	}
}

// TestPreflightParamPortsScan pins the engine_params scan rules: port-ish
// keys (case-insensitive) one level deep + one nested map level, integral
// values 1..65535 only.
func TestPreflightParamPortsScan(t *testing.T) {
	params := json.RawMessage(`{
		"listen_port": 5201,
		"ListenPORT": 5202,
		"passport_id": 7,
		"remote_port": 0,
		"transport": {"server_port": 8443, "ports": "80"},
		"deep": {"deeper": {"port": 1}},
		"web_port": "9090",
		"mtu": 1400
	}`)
	got := preflightParamPorts(params)
	want := []int{7, 5201, 5202, 8443}
	if len(got) != len(want) {
		t.Fatalf("scan = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scan = %v, want %v", got, want)
		}
	}
}

// TestPreflightSnapshotAgreesWithAvailabilityCheck: the batched snapshot
// check mirrors portAvailabilityCheck rule for rule (the suggestion scan
// depends on the two never drifting apart).
func TestPreflightSnapshotAgreesWithAvailabilityCheck(t *testing.T) {
	withTempConfig(t)
	const held = 5201
	pfPortSeams(t, pfSSLine("tcp", held, "testsink", 4242)+pfSSLine("udp", 5202, "other", 43), 50000, 50010)
	snap := preflightSnapshotNow()
	for _, tc := range []struct {
		port  int
		proto string
	}{
		{held, portProtoTCP}, {held, portProtoUDP}, {5202, portProtoUDP},
		{5202, portProtoTCP}, {5203, portProtoTCP}, {50005, portProtoTCP},
		{70000, portProtoTCP},
	} {
		a := portAvailabilityCheck(tc.port, tc.proto)
		b := snap.check(tc.port, tc.proto)
		if a.Available != b.Available || a.Reason != b.Reason || a.ReservedBy != b.ReservedBy {
			t.Fatalf("port %d/%s drift:\n  live check: %+v\n  snapshot:   %+v", tc.port, tc.proto, a, b)
		}
		if (a.Listener == nil) != (b.Listener == nil) {
			t.Fatalf("port %d/%s listener view drift:\n  live: %+v\n  snap: %+v", tc.port, tc.proto, a.Listener, b.Listener)
		}
	}
}

// TestPreflightSuggestFree: suggestions are the next free ports ABOVE the
// conflict, skipping the ephemeral range entirely.
func TestPreflightSuggestFree(t *testing.T) {
	withTempConfig(t)
	const held = 5201
	// 5202, 5204, 5205 held; 5203, 5206+ free; ephemeral 60000-61000.
	pfPortSeams(t, pfSSLine("tcp", 5202, "a", 1)+pfSSLine("tcp", 5204, "b", 2)+pfSSLine("tcp", 5205, "c", 3), 60000, 61000)
	snap := preflightSnapshotNow()
	got := snap.suggestFree(held, 3, portProtoTCP)
	want := []int{5203, 5206, 5207}
	if len(got) != len(want) {
		t.Fatalf("suggestions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("suggestions = %v, want %v", got, want)
		}
	}
	// A conflict just below the ephemeral range must not scan 10k
	// ephemeral candidates: the scan jumps over the range.
	got = snap.suggestFree(59999, 1, portProtoTCP)
	if len(got) != 1 || got[0] != 61001 {
		t.Fatalf("above-range suggestion = %v, want [61001]", got)
	}
}

// TestPreflightSelfRegistryReservationAllowed: a port the registry shows
// as reserved by THIS tunnel is its own reservation, not a conflict.
func TestPreflightSelfRegistryReservationAllowed(t *testing.T) {
	withTempConfig(t)
	const port = 5301
	pfPortSeams(t, "", 61000, 65535)
	registerV2TestDriver(t)

	d := pfDesiredWithTunnel("1796470000000000310", fmt.Sprintf(`{"listen_port":%d}`, port))
	if ack := agentApplyDesiredV2(&d); !ack.OK {
		t.Fatalf("first apply: %+v", ack)
	}
	// The tunnel reserved its port (as the firewall engine's reserve step
	// would): owned by tunnel:t1.
	if err := portReserve(port, portProtoTCP, portOwnerTunnel, "t1", "both", "pf test"); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	next := pfDesiredWithTunnel("1796470000000000311", fmt.Sprintf(`{"listen_port":%d,"note":"changed"}`, port))
	ack := agentApplyDesiredV2(&next)
	if !ack.OK {
		t.Fatalf("self-reserved re-apply refused: %+v", ack)
	}
	if len(ack.Detail) != 0 {
		t.Fatalf("own registry reservation must not be a conflict: %+v", ack.Detail)
	}
}
