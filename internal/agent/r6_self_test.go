package agent

// r6_self_test.go — agent side of R6 (phase 17): the panel stamps
// DesiredV2.Self with the receiving agent's mesh server name; the agent
// threads it into every engine instance (SelfName) for name-based role
// resolution, and surfaces a non-fatal alignment warning when the stamped
// self matches no delivered tunnel end.

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Dark-modem/quantum-protocol"
)

// r6Desired builds a one-tunnel DesiredV2 with an optional Self stamp.
func r6Desired(rev string, self *protocol.SelfInfo, local string) protocol.DesiredV2 {
	d := protocol.DesiredV2{
		Revision: rev,
		Engines:  []protocol.EngineSpec{{ID: "fake", Enabled: true}},
		Tunnels: []protocol.TunnelSpec{{
			ID: "t1", TopologyID: "topo-r6", LocalServer: local, RemoteServer: "hz",
			Engine: "fake", EngineParams: json.RawMessage(`{"listen_port":1}`), Enabled: true,
		}},
	}
	d.Self = self
	return d
}

// TestV2SelfFlowsToInstances (R6): Self.Name reaches every engine
// instance as SelfName, and a doc WITHOUT Self (pre-R6 panel) leaves it
// empty — the drivers' legacy resolution must be untouched.
func TestV2SelfFlowsToInstances(t *testing.T) {
	withTempConfig(t)
	port := pfPortFromListener(t)
	pfPortSeams(t, pfSSLine("tcp", port, "testsink", 4242), 61000, 65535)
	registerV2TestDriver(t)

	d := r6Desired("1796470000000000400",
		&protocol.SelfInfo{Name: "ir-drak-1", Role: "iran"}, "ir-drak-1")
	d.Tunnels[0].EngineParams = json.RawMessage(fmt.Sprintf(`{"listen_port":%d}`, port+7))
	ack := agentApplyDesiredV2(&d)
	if !ack.OK {
		t.Fatalf("self-stamped doc refused: %+v", ack)
	}
	if _, warned := ack.Detail["self_alignment_warning"]; warned {
		t.Fatalf("aligned self must not warn: %+v", ack.Detail)
	}
	mgr, _, err := agentV2RuntimeRef()
	if err != nil {
		t.Fatal(err)
	}
	inst, ok := mgr.Instance("t1")
	if !ok {
		t.Fatal("tunnel t1 not running")
	}
	if inst.SelfName != "ir-drak-1" {
		t.Fatalf("SelfName = %q, want ir-drak-1", inst.SelfName)
	}

	// pre-R6 document: no Self at all — a NEW tunnel (t2) starts with an
	// empty SelfName (t1 keeps running; its instance object is retained
	// when params are unchanged, which is fine — Self is per-doc context).
	d2 := r6Desired("1796470000000000401", nil, "ir-drak-1")
	d2.Tunnels[0] = protocol.TunnelSpec{
		ID: "t2", TopologyID: "topo-r6", LocalServer: "ir-drak-1", RemoteServer: "hz",
		Engine: "fake", EngineParams: json.RawMessage(fmt.Sprintf(`{"listen_port":%d}`, port+8)),
		Enabled: true,
	}
	ack2 := agentApplyDesiredV2(&d2)
	if !ack2.OK {
		t.Fatalf("pre-R6 doc refused: %+v", ack2)
	}
	inst2, ok := mgr.Instance("t2")
	if !ok {
		t.Fatal("tunnel t2 not running after pre-R6 apply")
	}
	if inst2.SelfName != "" {
		t.Fatalf("pre-R6 doc must leave SelfName empty, got %q", inst2.SelfName)
	}
	if _, warned := ack2.Detail["self_alignment_warning"]; warned {
		t.Fatalf("pre-R6 doc must not warn: %+v", ack2.Detail)
	}
}

// TestV2SelfAlignmentWarning (R6): a Self that matches no delivered
// tunnel end is a mis-link signal — non-fatal, riding the ack detail.
func TestV2SelfAlignmentWarning(t *testing.T) {
	withTempConfig(t)
	port := pfPortFromListener(t)
	pfPortSeams(t, pfSSLine("tcp", port, "testsink", 4242), 61000, 65535)
	registerV2TestDriver(t)

	d := r6Desired("1796470000000000402",
		&protocol.SelfInfo{Name: "somewhere-else", Role: "iran"}, "ir-drak-1")
	d.Tunnels[0].EngineParams = json.RawMessage(fmt.Sprintf(`{"listen_port":%d}`, port+7))
	ack := agentApplyDesiredV2(&d)
	if !ack.OK {
		t.Fatalf("mis-aligned self must stay non-fatal: %+v", ack)
	}
	w, ok := ack.Detail["self_alignment_warning"]
	if !ok {
		t.Fatalf("no self_alignment_warning in ack detail: %+v", ack.Detail)
	}
	if want := `self "somewhere-else" matches no tunnel end in revision 1796470000000000402`; w != want {
		t.Fatalf("warning =\n  %s\nwant\n  %s", w, want)
	}
}
