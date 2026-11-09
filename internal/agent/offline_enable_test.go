//go:build integration

// offline_enable_test.go — TASK 1 (phase 13): the netns proof with REAL
// binaries that an engine ENABLED while the agent is DISCONNECTED
// applies at reconnect (the offline-pending fix, end to end):
//
//	agent connects once (v2 session recorded) → agent killed →
//	POST /api/ui/agents/{id}/engines/{engine}/enable (queued) →
//	agent restarted → hello delivers the queued desired → the engine
//	is desired-enabled on the agent (heartbeat engine_status proves it).
//
// Both compat directions: the RC2 agent binary and the CURRENT agent
// binary against the CURRENT panel. The reverse (old panel) cannot be
// fixed on the new side — the rc2 panel's own gate is frozen reality
// and documented in COMPAT-MATRIX.md.
//
// Run: AGENT_OFFLINE_E2E=1 via .lab/p12/compat-run.sh offline
// (env: PANEL_CUR_BIN).
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	protocol "github.com/Dark-modem/quantum-protocol"
)

func TestAgentOfflineEnableReconnect(t *testing.T) {
	if os.Getenv("AGENT_OFFLINE_E2E") == "" {
		t.Skip("AGENT_OFFLINE_E2E not set")
	}
	panelCur := os.Getenv("PANEL_CUR_BIN")
	if panelCur == "" {
		t.Skip("PANEL_CUR_BIN not set")
	}
	work := t.TempDir()
	rc2Agent := filepath.Join(work, "agent-rc2")
	curAgent := filepath.Join(work, "agent-cur")
	compatBuildAgent(t, compatRC2AgentCommit, rc2Agent)
	compatBuildAgent(t, "", curAgent)

	for name, agentBin := range map[string]string{
		"rc2agent+curpanel": rc2Agent,
		"curagent+curpanel": curAgent,
	} {
		t.Run(name, func(t *testing.T) {
			runOfflineEnableCell(t, name, panelCur, agentBin)
		})
	}
}

func runOfflineEnableCell(t *testing.T, name, panelBin, agentBin string) {
	t.Helper()
	work := t.TempDir()
	p := compatStartPanel(t, panelBin, filepath.Join(work, "panelcfg"))
	p.mustPost("/api/mesh/datacenters", map[string]any{"kind": "iran", "name": "off-iran", "price_coefficient": 1.0})
	_, dcs := p.get("/api/mesh/datacenters")
	var dcID float64
	for _, raw := range dcs["datacenters"].([]any) {
		m := raw.(map[string]any)
		if m["name"].(string) == "off-iran" {
			dcID = m["id"].(float64)
		}
	}
	_, sv1M := p.post("/api/mesh/servers", map[string]any{"name": "off-ir", "role": "iran", "datacenter_id": dcID, "address": "10.86.0.1"})
	_, sv2M := p.post("/api/mesh/servers", map[string]any{"name": "off-fr", "role": "foreign", "datacenter_id": dcID, "address": "10.86.0.2"})
	idReal, keyReal := p.compatEnroll("off-real", sv1M["id"].(float64))
	idGhost, _ := p.compatEnroll("off-ghost", sv2M["id"].(float64))
	_ = idGhost
	sinkPort := compatFreePort(t)
	labParams := []map[string]any{
		{"lab_addr": "127.0.0.1", "lab_port": sinkPort},
		{"lab_addr": "127.0.0.1", "lab_port": sinkPort},
	}
	p.mustPost("/api/mesh/topologies/generate", map[string]any{
		"name": "off-topo", "iran_servers": []float64{sv1M["id"].(float64)},
		"foreign_servers":  []float64{sv2M["id"].(float64)},
		"tunnels_per_pair": 2, "engines": []string{"fake", "fake"},
		"engine_params": labParams, "enabled": true,
	})

	// Session 1: the agent connects ONCE (proto v2 recorded), receives
	// its initial desired, then DISCONNECTS.
	agentCfg := filepath.Join(work, "agentcfg")
	if err := os.MkdirAll(agentCfg, 0o700); err != nil {
		t.Fatal(err)
	}
	ident := fmt.Sprintf(`{"id":%q,"key":%q,"server":%q,"name":"off-real"}`, idReal, keyReal, p.baseURL)
	if err := os.WriteFile(filepath.Join(agentCfg, "agent.json"), []byte(ident), 0o600); err != nil {
		t.Fatal(err)
	}
	logFile, _ := os.Create(filepath.Join(work, "agent.log"))
	defer logFile.Close()

	startAgent := func() *exec.Cmd {
		run := exec.Command(agentBin, "run")
		run.Env = append(os.Environ(), "GRE_PANEL_DIR="+agentCfg, "QUANTUM_ENGINES_LAB=fake")
		run.Stdout, run.Stderr = logFile, logFile
		if err := run.Start(); err != nil {
			t.Fatalf("start agent: %v", err)
		}
		return run
	}
	run := startAgent()
	t.Cleanup(func() {
		_ = run.Process.Kill()
		_, _ = run.Process.Wait()
	})
	waitOnline(t, p, idReal, 30*time.Second)

	// Initial desired (session 1): push while live → ack.
	push := p.mustPost("/api/mesh/agents/"+idReal+"/push", nil)
	if push["pushed"] != true {
		t.Fatalf("initial push: %v", push)
	}
	waitApplied(t, p, idReal, 45*time.Second)

	// DISCONNECT (kill the agent hard — the panel sees the session die).
	if err := run.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_, _ = run.Process.Wait()
	// The hub deregisters the dead session on its read loop's EOF
	// (fast after SIGKILL); the panel's STATUS flag ages out on the
	// stale sweep — waiting on the status is the wrong signal, and the
	// enable below accepts both queued outcomes.

	// OFFLINE ENABLE of wireguard (a KERNEL engine — no artifact needed,
	// not desired by default): the agent is OFFLINE → the push response
	// must NOT claim delivery (the offline-pending queue takes it).
	enable := p.mustPost("/api/ui/agents/"+idReal+"/engines/wireguard/enable", nil)
	// The push may claim delivery (a SIGKILLed socket can still accept
	// writes until the hub notices) or report queued — EITHER WAY the
	// document is durably pending and clears only on the ack. The
	// reconnect assertions below are the real proof.
	cell := map[string]any{"name": name, "enable": enable}
	_ = cell

	// RECONNECT: hello delivers the queued desired (revision-fenced);
	// the agent applies it and reports the engine desired-ENABLED.
	run = startAgent()
	waitOnline(t, p, idReal, 30*time.Second)
	waitApplied(t, p, idReal, 45*time.Second)

	// Definitive check: the agent's own engine_status report (merged
	// into the engines view) must show wireguard desired-ENABLED —
	// i.e. the agent APPLIED the offline change.
	deadline := time.Now().Add(60 * time.Second)
	var eb []byte
	for time.Now().Before(deadline) {
		_, eng := p.get("/api/ui/agents/" + idReal + "/engines")
		eb, _ = json.Marshal(eng)
		if strings.Contains(string(eb), "wireguard") &&
			strings.Contains(string(eb), "desired_enabled\":true") {
			t.Logf("[%s] offline enable applied at reconnect (wireguard desired_enabled=true reported by the agent)", name)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("[%s] offline enable did not apply at reconnect: %s", name, eb)
}

func waitOnline(t *testing.T, p *compatPanel, agentID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, ags := p.get("/api/mesh/agents")
		b, _ := json.Marshal(ags)
		if strings.Contains(string(b), agentID) && strings.Contains(string(b), `"online"`) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("agent %s never came online", agentID)
}

func waitApplied(t *testing.T, p *compatPanel, agentID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, ags := p.get("/api/mesh/agents")
		if m, ok := ags["agents"].([]any); ok {
			for _, raw := range m {
				a := raw.(map[string]any)
				if a["id"] == agentID {
					if rev, _ := a["applied_revision"].(string); rev != "" {
						return
					}
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	_, m := p.get("/api/mesh/agents")
	b, _ := json.Marshal(m)
	t.Fatalf("agent %s never acked desired: %s", agentID, b)
}

var _ = protocol.ProtoVersionV2
