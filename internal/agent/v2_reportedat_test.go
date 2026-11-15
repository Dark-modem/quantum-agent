package agent

// v2_reportedat_test.go — R7 agent side (PROTOCOL-REQUESTS.md "WHAT
// DEV-AGENT MUST DO"): every v2 state report carries ReportedAt (the
// AGENT's own clock at report time), the clock is injectable for tests
// (no sleeps), and pre-R7 payloads still decode (0 = legacy-skip signal).

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-protocol"
)

// TestAgentReportV2ReportedAtPresent: the builder stamps ReportedAt from
// the (injectable) agent clock on EVERY v2 report — the healthy path and
// the runtime-error path alike. Clock-injected: no sleeps, no flakiness.
// The lazy runtime the builder builds must be torn down (resetV2Runtime
// cleanup), like every other runtime-touching test: leaving it alive
// pinned a registry built WITHOUT the next test's fake driver (found by
// the WSL full suite — TestApplyDesiredV2StartsTunnelsAndAcks then saw
// `unknown engine: "fake"`).
func TestAgentReportV2ReportedAtPresent(t *testing.T) {
	t.Cleanup(resetV2Runtime)
	fixed := time.Unix(1796479255, 0)
	old := agentReportClock
	agentReportClock = func() time.Time { return fixed }
	t.Cleanup(func() { agentReportClock = old })

	rep := agentBuildStateReportV2()
	if rep.ReportedAt != fixed.Unix() {
		t.Fatalf("healthy report ReportedAt = %d, want %d (agent's own clock at report time)", rep.ReportedAt, fixed.Unix())
	}

	// The runtime-error path still carries the stamp (never a 0 for a
	// real report — the panel would skip the clock_drift rule).
	resetV2Runtime()
	rep2 := agentBuildStateReportV2()
	if rep2.ReportedAt != fixed.Unix() {
		t.Fatalf("error-path report ReportedAt = %d, want %d", rep2.ReportedAt, fixed.Unix())
	}
}

// TestAgentReportV2ReportedAtFixture: the protocol's R7 golden fixture
// (copied verbatim to testdata — protocol fixtures are never edited)
// decodes with ReportedAt == ts-5, and the agent's marshal path
// (decode → re-encode) preserves reported_at.
func TestAgentReportV2ReportedAtFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/heartbeat-v2-reported-at.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	ver, typ, data, err := protocol.DecodeAny(raw)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if typ != "heartbeat" || ver != 2 {
		t.Fatalf("fixture type = %q, want heartbeat", typ)
	}
	var hb agentHeartbeatV2
	if err := json.Unmarshal(data, &hb); err != nil {
		t.Fatalf("unmarshal heartbeat: %v", err)
	}
	want := int64(1796479250) // ts(1796479255) - 5, per the fixture
	if hb.State == nil || hb.State.ReportedAt != want {
		got := int64(0)
		if hb.State != nil {
			got = hb.State.ReportedAt
		}
		t.Fatalf("fixture ReportedAt = %d, want %d", got, want)
	}

	// The agent's marshal path keeps the field: encode the decoded
	// heartbeat back and re-decode — reported_at must survive verbatim.
	out, err := agentEncodeV2("heartbeat", hb)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	ver2, typ2, data2, err := protocol.DecodeAny(out)
	if err != nil {
		t.Fatalf("decode re-encoded: %v", err)
	}
	if typ2 != "heartbeat" || ver2 != 2 {
		t.Fatalf("re-encoded type = %q", typ2)
	}
	var hb2 agentHeartbeatV2
	if err := json.Unmarshal(data2, &hb2); err != nil {
		t.Fatalf("unmarshal re-encoded: %v", err)
	}
	if hb2.State == nil || hb2.State.ReportedAt != want {
		t.Fatalf("re-encoded ReportedAt lost (got %+v) — the agent's marshal path must preserve reported_at", hb2.State)
	}
}

// TestAgentReportV2PreR7DecodeCompat: a pre-R7 payload (no reported_at
// key at all) decodes with ReportedAt == 0 — the legacy-skip signal —
// and the additive field does not disturb the rest of the report.
func TestAgentReportV2PreR7DecodeCompat(t *testing.T) {
	legacy := `{"v":2,"type":"heartbeat","data":{"ts":1796470000,"uptime_s":60,
		"state":{"applied_revision":"r1","tunnels":[]}}}`
	ver, typ, data, err := protocol.DecodeAny([]byte(legacy))
	if err != nil {
		t.Fatalf("decode legacy: %v", err)
	}
	if typ != "heartbeat" || ver != 2 {
		t.Fatalf("legacy type = %q", typ)
	}
	var hb agentHeartbeatV2
	if err := json.Unmarshal(data, &hb); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if hb.State == nil {
		t.Fatal("legacy state missing")
	}
	if hb.State.ReportedAt != 0 {
		t.Fatalf("pre-R7 payload must decode as ReportedAt=0 (legacy-skip), got %d", hb.State.ReportedAt)
	}
	if hb.State.AppliedRevision != "r1" {
		t.Fatalf("legacy fields disturbed: %+v", hb.State)
	}
}
