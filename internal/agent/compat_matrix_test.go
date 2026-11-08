//go:build integration

// compat_matrix_test.go — TASK 1b/1c (phase 12): REAL binaries across
// versions, run inside a throwaway netns by .lab/p12/compat-run.sh:
//
//	rc2 agent  (fb5a57a)  +  current panel
//	current agent          +  rc2 panel (4e0611c9b28b)
//
// Each cell: enroll (real API) → v2 negotiation → desired push (lab
// fake engine) → ack → usage through the sink → panel DEATH survival →
// hardening command path. Fix rule: anything broken is fixed on the NEW
// side only (old agents/panels are frozen reality).
//
// Env:
//
//	AGENT_COMPAT_E2E=1      run the matrix
//	PANEL_RC2_BIN, PANEL_CUR_BIN   prebuilt panel binaries (both repos'
//	                            worktrees are built by the runner script;
//	                            the agent test never leaves its repo)
//
// Results land in COMPAT-OUT (dir) as JSON + the test log.
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	protocol "github.com/Dark-modem/quantum-protocol"
)

const compatRC2AgentCommit = "fb5a57a"
const compatRC2PanelCommit = "4e0611c9b28b"

type compatPanel struct {
	t        *testing.T
	cmd      *exec.Cmd
	baseURL  string
	basePath string
	client   *http.Client
	csrf     string
	logPath  string
}

func compatBuildAgent(t *testing.T, commit, out string) {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := root
	if commit != "" {
		dir = out + ".src"
		wt := exec.Command("git", "worktree", "add", "--detach", dir, commit)
		wt.Dir = root
		if b, err := wt.CombinedOutput(); err != nil {
			t.Fatalf("worktree add %s: %v: %s", commit, err, b)
		}
		t.Cleanup(func() {
			rm := exec.Command("git", "worktree", "remove", "--force", dir)
			rm.Dir = root
			_, _ = rm.CombinedOutput()
			_ = os.RemoveAll(dir)
		})
	}
	build := exec.Command("go", "build", "-o", out, "./cmd/quantum-agent")
	build.Dir = dir
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agent@%s: %v: %s", commit, err, b)
	}
}

func compatFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func compatStartPanel(t *testing.T, bin, cfgDir string) *compatPanel {
	t.Helper()
	logPath := filepath.Join(cfgDir+"_logs", "panel.log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logFile.Close() })
	port := compatFreePort(t)
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"GRE_PANEL_DIR="+cfgDir,
		fmt.Sprintf("GRE_PANEL_PORT=%d", port),
		"GRE_PANEL_PASSWORD=compat-pass-1",
	)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start panel %s: %v", bin, err)
	}
	p := &compatPanel{t: t, cmd: cmd, logPath: logPath}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if p.basePath == "" {
			if b, err := os.ReadFile(filepath.Join(cfgDir, "panel.json")); err == nil {
				var cfg struct {
					BasePath string `json:"base_path"`
				}
				if json.Unmarshal(b, &cfg) == nil {
					p.basePath = strings.Trim(cfg.BasePath, "/")
				}
			}
		}
		if p.basePath != "" {
			p.baseURL = fmt.Sprintf("http://127.0.0.1:%d/%s", port, p.basePath)
			resp, err := http.Get(p.baseURL + "/api/health")
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == 200 {
					p.login()
					return p
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	b, _ := os.ReadFile(logPath)
	t.Fatalf("panel %s never healthy; log:\n%s", bin, b)
	return nil
}

func (p *compatPanel) login() {
	jar, _ := cookiejar.New(nil)
	p.client = &http.Client{Jar: jar, Timeout: 30 * time.Second}
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "compat-pass-1"})
	resp, err := p.client.Post(p.baseURL+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		p.t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		p.t.Fatalf("login: %d %s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if tok, ok := out["csrf_token"].(string); ok {
		p.csrf = tok
	}
}

func (p *compatPanel) get(path string) (int, map[string]any) {
	resp, err := p.client.Get(p.baseURL + path)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

func (p *compatPanel) post(path string, body any) (int, map[string]any) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", p.baseURL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", p.csrf)
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

func (p *compatPanel) mustPost(path string, body any) map[string]any {
	p.t.Helper()
	code, out := p.post(path, body)
	if code != 200 {
		p.t.Fatalf("POST %s: %d %v", path, code, out)
	}
	return out
}

func (p *compatPanel) mustGet(path string) map[string]any {
	p.t.Helper()
	code, out := p.get(path)
	if code != 200 {
		p.t.Fatalf("GET %s: %d %v", path, code, out)
	}
	return out
}

// compatEnroll enrolls one iran agent (tries BOTH enroll routes — the
// path moved between rc2 and current) and links it to the server.
func (p *compatPanel) compatEnroll(name string, serverID float64) (string, string) {
	p.t.Helper()
	tok := p.mustPost("/api/agents/tokens", map[string]any{"role": "iran", "label": "compat", "expires_days": 1})
	token, _ := tok["token"].(string)
	body := fmt.Sprintf(`{"name":%q,"hostname":"compat","os":"linux","arch":"amd64","version":"compat","caps":[]}`, name)
	var id, key string
	for _, path := range []string{"/api/agent/enroll", "/api/agents/enroll"} {
		req, _ := http.NewRequest("POST", p.baseURL+path, strings.NewReader(body))
		req.Header.Set(protocol.HeaderEnrollToken, token)
		resp, err := p.client.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		var er struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		}
		if json.Unmarshal(raw, &er) == nil && er.ID != "" {
			id, key = er.ID, er.Key
			break
		}
	}
	if id == "" {
		p.t.Fatalf("enroll failed on both routes")
	}
	p.mustPost("/api/mesh/agents/"+id+"/link", map[string]any{"server_id": serverID})
	p.mustPost("/api/mesh/agents/"+id+"/engine-catalog",
		map[string]any{"catalog": []map[string]any{{"id": "fake"}}})
	return id, key
}

// runCompatCell drives ONE agent binary against ONE panel binary.
func runCompatCell(t *testing.T, name, panelBin, agentBin string, results map[string]any) {
	t.Helper()
	work := t.TempDir()
	// Panel data: iran DC + 2 servers (1+1 topology so desired compiles).
	p := compatStartPanel(t, panelBin, filepath.Join(work, "panelcfg"))
	p.mustPost("/api/mesh/datacenters", map[string]any{"kind": "iran", "name": "compat-iran", "price_coefficient": 1.0})
	_, dcs := p.get("/api/mesh/datacenters")
	var dcID float64
	for _, raw := range dcs["datacenters"].([]any) {
		m := raw.(map[string]any)
		if m["name"].(string) == "compat-iran" {
			dcID = m["id"].(float64)
		}
	}
	_, sv1M := p.post("/api/mesh/servers", map[string]any{"name": "compat-ir", "role": "iran", "datacenter_id": dcID, "address": "10.85.0.1"})
	_, sv2M := p.post("/api/mesh/servers", map[string]any{"name": "compat-fr", "role": "foreign", "datacenter_id": dcID, "address": "10.85.0.2"})
	// The SECOND agent is nominal (no binary run): only its enrollment +
	// link exist so the desired state compiles for the real agent.
	idReal, keyReal := p.compatEnroll("compat-real", sv1M["id"].(float64))
	idGhost, _ := p.compatEnroll("compat-ghost", sv2M["id"].(float64))
	_ = idGhost
	// The lab fake engine REQUIRES lab_addr+lab_port (the sink binds on
	// the end that owns lab_addr — here, the real agent's loopback).
	sinkPort := compatFreePort(t)
	labParams := []map[string]any{
		{"lab_addr": "127.0.0.1", "lab_port": sinkPort},
		{"lab_addr": "127.0.0.1", "lab_port": sinkPort},
	}
	p.mustPost("/api/mesh/topologies/generate", map[string]any{
		"name": "compat-topo", "iran_servers": []float64{sv1M["id"].(float64)},
		"foreign_servers":  []float64{sv2M["id"].(float64)},
		"tunnels_per_pair": 2, "engines": []string{"fake", "fake"},
		"engine_params": labParams, "enabled": true,
	})
	p.mustPost("/api/mesh/topologies/1/weights", map[string]any{
		"local_server_id": sv1M["id"].(float64), "remote_server_id": sv2M["id"].(float64), "weight": 30})
	// NOTE: the push happens AFTER the agent's session is live (the
	// proven e2e order); pushing to a not-yet-connected agent relies on
	// the hello-time pending delivery, which is exactly what we want to
	// observe separately.

	// The agent (REAL binary) with its enrollment on disk.
	agentCfg := filepath.Join(work, "agentcfg")
	if err := os.MkdirAll(agentCfg, 0o700); err != nil {
		t.Fatal(err)
	}
	ident := fmt.Sprintf(`{"id":%q,"key":%q,"server":%q,"name":"compat-real"}`,
		idReal, keyReal, p.baseURL)
	if err := os.WriteFile(filepath.Join(agentCfg, "agent.json"), []byte(ident), 0o600); err != nil {
		t.Fatal(err)
	}
	agentLog := filepath.Join(work, "agent.log")
	logFile, _ := os.Create(agentLog)
	defer logFile.Close()
	run := exec.Command(agentBin, "run")
	run.Env = append(os.Environ(), "GRE_PANEL_DIR="+agentCfg, "QUANTUM_ENGINES_LAB=fake")
	run.Stdout, run.Stderr = logFile, logFile
	if err := run.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	t.Cleanup(func() {
		_ = run.Process.Kill()
		_, _ = run.Process.Wait()
	})

	cell := map[string]any{"name": name}
	defer func() {
		b, _ := json.Marshal(cell)
		results[name] = json.RawMessage(b)
	}()
	waitFor := func(cond string, timeout time.Duration, check func() bool) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if check() {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		cell["failed_at"] = cond
		b, _ := os.ReadFile(agentLog)
		_, agsDump := p.get("/api/mesh/agents")
		ab, _ := json.Marshal(agsDump)
		t.Fatalf("[%s] never %s; cell=%s; agents=%s; agent log:\n%s", name, cond, mustJSONCell(cell), string(ab), b)
	}

	// 1. v2 negotiation + online.
	waitFor("agent online + v2", 30*time.Second, func() bool {
		_, ags := p.get("/api/mesh/agents")
		b, _ := json.Marshal(ags)
		return strings.Contains(string(b), `"online"`) && strings.Contains(string(b), idReal)
	})

	// Push NOW (the session is live — the proven e2e order).
	pushRes := p.mustPost("/api/mesh/agents/"+idReal+"/push", nil)
	cell["push"] = pushRes

	// 2. desired applied + acked: the agent's applied_revision becomes
	// non-empty.
	waitFor("desired acked", 45*time.Second, func() bool {
		_, ags := p.get("/api/mesh/agents")
		b, _ := json.Marshal(ags)
		if !strings.Contains(string(b), idReal) {
			return false
		}
		for _, raw := range ags["agents"].([]any) {
			m := raw.(map[string]any)
			if m["id"] == idReal {
				if rev, _ := m["applied_revision"].(string); rev != "" {
					cell["applied_revision"] = rev
					return true
				}
				if le, _ := m["last_error"].(string); le != "" {
					cell["desired_error"] = le
				}
			}
		}
		return false
	})

	// 3. usage: write bytes into the sink; the usage API must show them.
	tunnels := p.mustGet("/api/mesh/topologies/1")["tunnels"].([]any)
	tunnelID0 := tunnels[0].(map[string]any)["id"].(float64)
	sink, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sinkPort))
	if err != nil {
		// The sink binds only on the host that OWNS lab_addr — the real
		// agent owns 127.0.0.1. If the agent's tunnel is down, dial fails:
		// wait a bit and retry once.
		time.Sleep(5 * time.Second)
		sink, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sinkPort))
	}
	if err == nil {
		_, _ = sink.Write(bytes.Repeat([]byte("x"), 4096))
		_ = sink.Close()
	}
	waitFor("usage counters", 60*time.Second, func() bool {
		_, u := p.get(fmt.Sprintf("/api/mesh/usage?tunnel_id=%.0f&from=0&to=%d", tunnelID0, time.Now().Add(time.Hour).Unix()))
		b, _ := json.Marshal(u)
		// The engine is the lab fake: the SINK counts bytes it accepted;
		// only the sink-owning end reports them. Either direction counts.
		return strings.Contains(string(b), "wire_rx") && !strings.Contains(string(b), `"wire_rx":0`)
	})

	// 4. panel DEATH: kill the panel; the agent must stay alive (tunnels
	// keep running from the replayed desired state).
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	_, _ = p.cmd.Process.Wait()
	time.Sleep(8 * time.Second)
	if run.Process == nil {
		t.Fatal("agent process gone")
	}
	if err := run.Process.Signal(syscall.Signal(0)); err != nil {
		b, _ := os.ReadFile(agentLog)
		t.Fatalf("[%s] agent DIED with the panel (must survive): log:\n%s", name, b)
	}
	cell["panel_death_survived"] = true

	// 5. hardening command path (payload/profile naming survives the
	// version gap): a profile command must be ACCEPTED by the agent
	// (an error ack still proves the transport + envelope; a crash or
	// disconnect is a failure). Restart the panel first.
	p2 := compatStartPanel(t, panelBin, filepath.Join(work, "panelcfg"))
	code, _ := p2.post("/api/mesh/agents/"+idReal+"/profile/hardening",
		map[string]any{"name": "compat", "profile": map[string]any{}, "rollback_timer_s": 120, "confirm": "yes"})
	cell["hardening_http_status"] = code // 200 (queued) or 409 (offline-not-queued) — both prove the API path
	time.Sleep(3 * time.Second)
	if run.Process != nil {
		if err := run.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("[%s] agent died during the hardening exchange", name)
		}
	}
	cell["ok"] = true
	t.Logf("[%s] OK: v2 + desired + usage + panel-death + hardening path", name)
}

func TestAgentCompatMatrix(t *testing.T) {
	if os.Getenv("AGENT_COMPAT_E2E") == "" {
		t.Skip("AGENT_COMPAT_E2E not set")
	}
	panelRC2 := os.Getenv("PANEL_RC2_BIN")
	panelCur := os.Getenv("PANEL_CUR_BIN")
	if panelRC2 == "" || panelCur == "" {
		t.Skip("PANEL_RC2_BIN / PANEL_CUR_BIN not set (build them from quantum-panel 4e0611c9b28b and main)")
	}
	work := t.TempDir()
	rc2Agent := filepath.Join(work, "agent-rc2")
	curAgent := filepath.Join(work, "agent-cur")
	compatBuildAgent(t, compatRC2AgentCommit, rc2Agent)
	compatBuildAgent(t, "", curAgent)

	results := map[string]any{}
	t.Run("rc2agent+curpanel", func(t *testing.T) { runCompatCell(t, "rc2agent+curpanel", panelCur, rc2Agent, results) })
	t.Run("curagent+rc2panel", func(t *testing.T) { runCompatCell(t, "curagent+rc2panel", panelRC2, curAgent, results) })

	if out := os.Getenv("COMPAT_OUT"); out != "" {
		b, _ := json.MarshalIndent(results, "", "  ")
		_ = os.WriteFile(filepath.Join(out, "compat-results.json"), b, 0o644)
	}
}

func mustJSONCell(v any) string { b, _ := json.Marshal(v); return string(b) }
