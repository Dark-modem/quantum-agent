package agent

// AGENT-24: the DesiredV2 journal must round-trip the panel-delivered
// bytes BYTE-IDENTICAL, so a boot replay compares the params the running
// instances actually hold and never manufactures a phantom "params
// changed" restart. The pre-AGENT-24 writer (json.MarshalIndent)
// re-indented the nested RawMessage (Go re-indents embedded JSON), so the
// journal held byte-different params than the wire — every reconnect
// restarted every tunnel and reset the engines' in-memory counters.

import (
	"bytes"
	"encoding/json"
	"testing"

	protocol "github.com/Dark-modem/quantum-protocol"
)

func TestJournalV2RoundTripByteIdentical(t *testing.T) {
	agentLab(t)
	// Two tunnels, compact wire bytes exactly as the panel sends them.
	// The second tunnel's params carry <>& deliberately: the writer must
	// not HTML-escape them either (json.Marshal would emit \u0026 etc.).
	doc := protocol.DesiredV2{
		Revision: "1795192572547988463",
		Tunnels: []protocol.TunnelSpec{
			{ID: "tun-drak-hz-ir-drak-1-hz-fra-1-b", Engine: "fake",
				EngineParams: json.RawMessage(`{"lab_addr":"10.200.0.21","lab_port":8443}`)},
			{ID: "tun-drak-hz-ir-drak-1-hz-fra-2-b", Engine: "fake",
				EngineParams: json.RawMessage(`{"lab_addr":"10.200.0.22","lab_port":8444,"note":"A&B<cfg>"}`)},
		},
	}
	wire, err := json.Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte("\n")) {
		t.Fatalf("wire doc must be compact for this test: %s", wire)
	}
	if err := agentMutateState(func(st *agentPersistedState) {
		st.DesiredV2Raw = append([]byte(nil), wire...)
		st.DesiredStatus = "applied"
		st.AppliedRevision = doc.Revision
	}); err != nil {
		t.Fatal(err)
	}
	st := agentLoadState()
	if !bytes.Equal(st.DesiredV2Raw, wire) {
		t.Fatalf("journal round trip NOT byte-identical:\n wire:  %s\n retry: %s", wire, st.DesiredV2Raw)
	}
}
