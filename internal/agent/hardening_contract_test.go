package agent

// Regression tests for the Phase-7 hardening contract fix: the panel's
// profile/apply endpoint builds the command with params{"payload": …,
// "rollback_timer_s": …} (meshapi2.go meshProfileApply — the exact shape
// below mirrors that builder), while the agent historically read
// params{"profile": …, "rollback_timeout_sec": …}. BOTH spellings are
// accepted now; the tests pin the resolution table.

import (
	"encoding/json"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/hardening"
)

// panelHardeningApplyParams is the EXACT param map the panel builds in
// meshProfileApply (meshapi2.go) for hardening.apply.
func panelHardeningApplyParams(profileJSON string, timer int) map[string]string {
	return map[string]string{
		"confirm":          "yes", // protocol.ParamConfirm
		"rollback_timer_s": "120", // protocol.ParamRollbackTimerS — panel spelling
		"payload":          profileJSON,
	}
}

func TestHardeningContractPanelPayloadSpelling(t *testing.T) {
	profile := hardening.Conservative(22, nil)
	profileJSON, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	req := hardeningRequestFromParams("hardening.apply",
		panelHardeningApplyParams(string(profileJSON), 120))
	if req.Profile != string(profileJSON) {
		t.Fatalf("payload spelling not picked up (panel shape): profile len %d", len(req.Profile))
	}
	if req.RollbackTimeoutSec != 120 {
		t.Fatalf("rollback_timer_s not parsed: %d", req.RollbackTimeoutSec)
	}
	if req.Op != "apply" {
		t.Fatalf("op = %q", req.Op)
	}
}

func TestHardeningContractDocumentedSpelling(t *testing.T) {
	profile := hardening.Conservative(22, nil)
	profileJSON, _ := json.Marshal(profile)
	req := hardeningRequestFromParams("hardening.apply", map[string]string{
		"profile":              string(profileJSON), // documented v2 contract spelling
		"rollback_timeout_sec": "300",
	})
	if req.Profile != string(profileJSON) {
		t.Fatal("profile spelling not picked up")
	}
	if req.RollbackTimeoutSec != 300 {
		t.Fatalf("rollback_timeout_sec not parsed: %d", req.RollbackTimeoutSec)
	}
}

func TestHardeningContractPrecedenceAndInvalidTimer(t *testing.T) {
	// "profile" wins when both spellings are present.
	req := hardeningRequestFromParams("hardening.plan", map[string]string{
		"profile":          `{"name":"documented"}`,
		"payload":          `{"name":"panel"}`,
		"rollback_timer_s": "not-a-number",
	})
	if req.Profile != `{"name":"documented"}` {
		t.Fatalf("profile must win over payload: %q", req.Profile)
	}
	if req.RollbackTimeoutSec != 0 {
		t.Fatalf("invalid timer must parse to 0: %d", req.RollbackTimeoutSec)
	}
	// Payload fallback when only the panel spelling is present.
	req = hardeningRequestFromParams("hardening.plan", map[string]string{
		"payload": `{"name":"panel-only"}`,
	})
	if req.Profile != `{"name":"panel-only"}` {
		t.Fatalf("payload fallback: %q", req.Profile)
	}
}
