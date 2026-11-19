//go:build integration

// proc_e2e_test.go — the Phase-11 numbers travel agent → panel with REAL
// binaries (AGENT_PROC_E2E=1, build tag integration): builds the real
// quantum-agent binary (QUANTUM_ENGINES_LAB=fake), runs it against a
// local HTTPS fake-panel WSS that pushes DesiredV2 (one lab fake tunnel),
// then asserts the agent's v2 heartbeats carry
//
//   - proc[] with the tunnel Known=true and the agent process's REAL
//     RSS from /proc (the lab engine runs in-process — its process tree
//     IS the agent process),
//
//   - engine_status[] with fake installed+enabled,
//
//   - REAL payload counters after bytes are pushed through the sink.
//
//     Run: AGENT_PROC_E2E=1 go test -tags integration -run TestAgentProcE2E \
//     ./internal/agent/ -count=1 -v -timeout 10m
//
// Netns note: the lab engine has no external process to isolate (the
// sink is a goroutine of the agent), and the phase-10 accounting soak
// already proved this same stack (real binary + fake engine + WSS) runs
// inside network namespaces; the panel→API half is covered by the
// panel's uiapi WS-integration test over a real store.
package agent

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	protocol "github.com/Dark-modem/quantum-protocol"
)

func TestAgentProcE2E(t *testing.T) {
	if os.Getenv("AGENT_PROC_E2E") == "" {
		t.Skip("AGENT_PROC_E2E not set (builds and runs the real agent binary)")
	}
	_ = engine.NewFakeEngine("fake") // framework anchor (the lab driver is env-gated)

	dir := t.TempDir()
	bin := filepath.Join(dir, "quantum-agent")
	cmd := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/quantum-agent")
	cmd.Dir = "../.."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build agent: %v: %s", err, out)
	}

	// The fake panel: real WSS, real protocol envelopes.
	upgrader := &websocket.Upgrader{}
	desiredSent := make(chan struct{})
	hbCh := make(chan protocol.StateReportV2, 16)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agent/ws", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		// hello (v2 envelope) → welcome (session v2).
		var env protocol.Envelope
		if err := ws.ReadJSON(&env); err != nil {
			return
		}
		if env.Type != protocol.MsgHello {
			t.Errorf("first message = %s, want hello", env.Type)
			return
		}
		wj, _ := json.Marshal(protocol.Welcome{OK: true, Version: protocol.ProtoVersionV2})
		if err := ws.WriteJSON(protocol.Envelope{V: 2, Type: protocol.MsgWelcome, Data: wj}); err != nil {
			return
		}
		// Push the desired state immediately (the hub delivers pending
		// desired at hello): one lab fake tunnel; the sink binds 127.0.0.1.
		desired := protocol.DesiredV2{
			Revision: "1000000000000000001",
			Engines:  []protocol.EngineSpec{{ID: "fake", Enabled: true}},
			Tunnels: []protocol.TunnelSpec{{
				ID: "tl-proc", TopologyID: "topo-lab",
				LocalServer: "lab-a", RemoteServer: "lab-b",
				Engine: "fake", Enabled: true,
				EngineParams: json.RawMessage(`{"lab_addr":"127.0.0.1","lab_port":18666}`),
			}},
		}
		dj, _ := json.Marshal(desired)
		if err := ws.WriteJSON(protocol.Envelope{V: 2, Type: protocol.MsgDesired, Data: dj}); err != nil {
			return
		}
		close(desiredSent)
		// Read ack + heartbeats.
		for {
			var e protocol.Envelope
			if err := ws.ReadJSON(&e); err != nil {
				return
			}
			switch e.Type {
			case protocol.MsgHeartbeat:
				var hb protocol.HeartbeatV2
				if json.Unmarshal(e.Data, &hb) == nil && hb.State != nil {
					select {
					case hbCh <- *hb.State:
					default:
					}
				}
			case protocol.MsgAck:
				var ack protocol.Ack
				if json.Unmarshal(e.Data, &ack) == nil && !ack.OK {
					t.Errorf("desired refused by the agent: %+v", ack)
				}
			}
		}
	})
	srv := newTLSTestServer(t, mux)
	defer srv.Close()

	// Enrollment on disk (the real agent reads it at boot).
	cfg := filepath.Join(dir, "cfg")
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	ident := `{"id":"agt-proc-e2e","key":"proc-e2e-key","server":"` + srv.URL + `","name":"proc-e2e"}`
	if err := os.WriteFile(filepath.Join(cfg, "agent.json"), []byte(ident), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.Command(bin, "run")
	run.Env = append(os.Environ(),
		"GRE_PANEL_DIR="+cfg,
		"QUANTUM_ENGINES_LAB=fake",
	)
	out, _ := os.Create(filepath.Join(dir, "agent.log"))
	run.Stdout, run.Stderr = out, out
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = run.Process.Kill()
		_, _ = run.Process.Wait()
		_ = out.Close()
	})

	// Wait for the first tunnel-bearing heartbeat (the session's first
	// heartbeat races the desired apply; the next one, ≤30s later, has
	// the tunnel).
	deadline := time.Now().Add(75 * time.Second)
	var withTunnel *protocol.StateReportV2
	for time.Now().Before(deadline) {
		select {
		case st := <-hbCh:
			if len(st.Tunnels) > 0 {
				cp := st
				withTunnel = &cp
			}
		case <-time.After(time.Second):
		}
		if withTunnel != nil {
			break
		}
	}
	if withTunnel == nil {
		b, _ := os.ReadFile(filepath.Join(dir, "agent.log"))
		t.Fatalf("no tunnel-bearing heartbeat within 75s; agent log:\n%s", b)
	}

	// 1. proc[]: Known=true, RSS = the agent process's REAL /proc RSS.
	var proc *protocol.TunnelProc
	for i := range withTunnel.Proc {
		if withTunnel.Proc[i].TunnelID == "tl-proc" {
			proc = &withTunnel.Proc[i]
		}
	}
	if proc == nil || !proc.Known || proc.RSSBytes < 1<<20 {
		t.Fatalf("proc section wrong: %+v (want tl-proc known, RSS >= 1MiB)", withTunnel.Proc)
	}
	t.Logf("proc numbers traveled: cpu=%.2f%% rss=%d bytes processes=%d",
		proc.CPUPercent, proc.RSSBytes, proc.Processes)

	// 2. engine_status[]: the lab fake engine installed+enabled.
	var fake *protocol.EngineStatusReport
	for i := range withTunnel.EngineStatus {
		if withTunnel.EngineStatus[i].Engine == "fake" {
			fake = &withTunnel.EngineStatus[i]
		}
	}
	if fake == nil || !fake.Installed || !fake.Enabled || fake.Instances != 1 {
		t.Fatalf("engine_status wrong: %+v", withTunnel.EngineStatus)
	}

	// 3. REAL counters: push bytes through the sink; the next heartbeat
	// (≤30s) must show them as wire AND payload (the lab contract).
	sink, err := net.Dial("tcp", "127.0.0.1:18666")
	if err != nil {
		t.Fatalf("dial sink: %v", err)
	}
	const wantBytes = 8192
	if _, err := sink.Write(make([]byte, wantBytes)); err != nil {
		t.Fatalf("write sink: %v", err)
	}
	_ = sink.Close()
	deadline = time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case st := <-hbCh:
			for _, tr := range st.Tunnels {
				if tr.TunnelID == "tl-proc" && tr.WireRx >= wantBytes && tr.PayloadRx >= wantBytes {
					t.Logf("counters traveled: wire_rx=%d payload_rx=%d (want >= %d)",
						tr.WireRx, tr.PayloadRx, wantBytes)
					return // all three assertions passed
				}
			}
		case <-time.After(time.Second):
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "agent.log"))
	t.Fatalf("counters never reached the heartbeat (sink wrote %d bytes); log:\n%s", wantBytes, b)
}
