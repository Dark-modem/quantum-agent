package agent

// Hermetic tests for the Matrix engine driver adapter: shape validation
// and registry composition only — the underlying matrix functions keep
// their own tests (matrix_instances_test.go & co. are unchanged).

import (
	"encoding/json"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

func TestMatrixDriverImplementsEngineDriver(t *testing.T) {
	var d engine.Driver = NewMatrixDriver()
	if d.ID() != "matrix" {
		t.Fatalf("ID = %q", d.ID())
	}
}

func TestMatrixDriverValidate(t *testing.T) {
	d := NewMatrixDriver()
	if err := d.Validate(nil); err == nil {
		t.Fatal("empty params accepted")
	}
	if err := d.Validate(json.RawMessage(`{"instance":"not-matrix!"}`)); err == nil {
		t.Fatal("invalid instance accepted")
	}
	if err := d.Validate(json.RawMessage(`{"instance":"matrix"}`)); err != nil {
		t.Fatalf("legacy instance rejected: %v", err)
	}
	if err := d.Validate(json.RawMessage(`{"instance":"matrix2"}`)); err != nil {
		t.Fatalf("numbered instance rejected: %v", err)
	}
	if err := d.Validate(json.RawMessage(`not json`)); err == nil {
		t.Fatal("non-JSON params accepted")
	}
}

func TestAgentEnginesRegistry(t *testing.T) {
	reg, err := AgentEngines()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Driver("matrix"); !ok {
		t.Fatal("matrix driver not registered")
	}
	if err := reg.Register(NewMatrixDriver()); err == nil {
		t.Fatal("duplicate matrix registration accepted")
	}
}
