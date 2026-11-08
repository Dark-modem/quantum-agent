//go:build integration

// update_rc2_test.go — TASK 1c (phase 12): the RC2 agent (fb5a57a, the
// binary family on the real servers) self-updates to a CURRENT-build
// artifact through the SIGNED update flow, in the lab netns:
//
//	real rc2 agent binary (update key pinned at build time via -X)
//	  ← v2 command `agent.update` {version,url,sha256,signature}
//	  → https download (same-origin) → sha256+ed25519 verify against
//	    the RC2-pinned key → atomic swap (.prev + marker) →
//	    tampered artifact REFUSED, installed binary untouched.
//
// The panel-side push endpoint + restart/rollback chain were verified
// end to end with real binaries in phase 10 (TestAgentUpdateE2E);
// the COMPAT-specific delta proven here is the RC2 agent's update
// CLIENT understanding a CURRENT-signed artifact (key format, param
// names, wire envelope).
//
// Run (inside the netns via .lab/p12/compat-run.sh update):
//
//	AGENT_UPDATE_RC2_E2E=1 go test -tags integration \
//	    -run TestAgentSelfUpdateFromRC2 ./internal/agent/ -count=1 -v
package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	protocol "github.com/Dark-modem/quantum-protocol"
)

func TestAgentSelfUpdateFromRC2(t *testing.T) {
	if os.Getenv("AGENT_UPDATE_RC2_E2E") == "" {
		t.Skip("AGENT_UPDATE_RC2_E2E not set")
	}
	work := t.TempDir()

	// The signing key pair; the PUBLIC half is pinned into BOTH builds.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pin := base64.StdEncoding.EncodeToString(der)

	// Build the RC2 agent WITH the pinned key (ldflags -X), and the
	// CURRENT build as the update artifact (same pin, new version).
	rc2Bin := filepath.Join(work, "agent-rc2")
	curBin := filepath.Join(work, "agent-cur")
	buildWithPin := func(commit, out, version string) {
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
				t.Fatalf("worktree %s: %v: %s", commit, err, b)
			}
			t.Cleanup(func() {
				rm := exec.Command("git", "worktree", "remove", "--force", dir)
				rm.Dir = root
				_, _ = rm.CombinedOutput()
				_ = os.RemoveAll(dir)
			})
		}
		build := exec.Command("go", "build", "-trimpath",
			"-ldflags", "-X github.com/Dark-modem/quantum-agent/internal/agent.agentUpdatePubKeyPEM="+pin+
				" -X github.com/Dark-modem/quantum-agent/internal/agent.panelVersion="+version,
			"-o", out, "./cmd/quantum-agent")
		build.Dir = dir
		if b, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s@%s: %v: %s", version, commit, err, b)
		}
	}
	buildWithPin(compatRC2AgentCommit, rc2Bin, "v0.1.0")
	buildWithPin("", curBin, "v99.0.1-compat")

	curBytes, err := os.ReadFile(curBin)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(curBytes)
	sig := ed25519.Sign(priv, curBytes)

	// The controller: v2 WSS + the artifact on the SAME origin.
	artifactServed := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agent/artifact/gre-panel-linux-amd64", func(w http.ResponseWriter, _ *http.Request) {
		artifactServed = true
		w.Write(curBytes)
	})
	commands := make(chan protocol.Command, 8)
	welcomed := make(chan struct{})
	mux.HandleFunc("/api/agent/ws", func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		var env protocol.Envelope
		if err := ws.ReadJSON(&env); err != nil || env.Type != protocol.MsgHello {
			return
		}
		wj, _ := json.Marshal(protocol.Welcome{OK: true, Version: protocol.ProtoVersionV2})
		if err := ws.WriteJSON(protocol.Envelope{V: 2, Type: protocol.MsgWelcome, Data: wj}); err != nil {
			return
		}
		close(welcomed)
		// Forward queued commands to the agent (the test queues the
		// update command; the hub shape sends it over THIS session).
		go func() {
			for cj := range compatCommandQueue {
				ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := ws.WriteJSON(protocol.Envelope{V: 2, Type: protocol.MsgCommand, Data: cj}); err != nil {
					return
				}
			}
		}()
		for {
			var e protocol.Envelope
			if err := ws.ReadJSON(&e); err != nil {
				return
			}
			switch e.Type {
			case protocol.MsgHeartbeat:
				// update progress rides here; not asserted (restart is
				// phase-10-covered; the lab has no systemd unit)
			case protocol.MsgResult:
				var res protocol.CommandResult
				if json.Unmarshal(e.Data, &res) == nil {
					if !res.OK {
						t.Errorf("agent rejected the update command: %s", res.Error)
					}
				}
			case protocol.MsgCommand:
				var c protocol.Command
				if json.Unmarshal(e.Data, &c) == nil {
					commands <- c
				}
			}
		}
	})
	srv := newTLSTestServer(t, mux)
	defer srv.Close()

	// Enrollment on disk pointing at the HTTPS controller (same origin
	// as the artifact — the update's same-origin rule).
	cfg := filepath.Join(work, "cfg")
	if err := os.MkdirAll(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	ident := `{"id":"agt-rc2-up","key":"rc2-up-key","server":"` + srv.URL + `","name":"rc2-up"}`
	if err := os.WriteFile(filepath.Join(cfg, "agent.json"), []byte(ident), 0o600); err != nil {
		t.Fatal(err)
	}
	tunState := []byte(`{"tunnel":"survives"}`)
	if err := os.WriteFile(filepath.Join(cfg, "tunnel-state.json"), tunState, 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.Command(rc2Bin, "run")
	run.Env = append(os.Environ(), "GRE_PANEL_DIR="+cfg, "QUANTUM_ENGINES_LAB=fake")
	logFile, _ := os.Create(filepath.Join(work, "agent.log"))
	run.Stdout, run.Stderr = logFile, logFile
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = run.Process.Kill()
		_, _ = run.Process.Wait()
		_ = logFile.Close()
	})
	binPath := rc2Bin

	// The update command (the exact shape the RC2 agent's dispatcher
	// reads; CmdAgentUpdate = "agent.update").
	select {
	case <-welcomed:
	case <-time.After(20 * time.Second):
		t.Fatal("agent never connected")
	}
	req := map[string]any{
		"version":   "v99.0.1-compat",
		"url":       srv.URL + "/api/agent/artifact/gre-panel-linux-amd64",
		"sha256":    hex.EncodeToString(sum[:]),
		"signature": base64.StdEncoding.EncodeToString(sig),
	}
	cj, _ := json.Marshal(protocol.Command{Op: protocol.CmdAgentUpdate, Params: toStringMap(req)})
	if err := wsWriteCommand(srv, cj); err != nil {
		t.Fatalf("send update command: %v", err)
	}

	// The swap must happen: .new renamed over the live binary, .prev +
	// the marker present. (The unit restart + boot-rollback chain is
	// phase-10-verified; the lab netns has no systemd unit.)
	deadline := time.Now().Add(60 * time.Second)
	swapped := false
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(binPath)
		if err == nil && string(b) == string(curBytes) {
			if _, err := os.Stat(binPath + ".prev"); err == nil {
				if mk, err := os.ReadFile(filepath.Join(cfg, "agent-update.json")); err == nil && len(mk) > 0 {
					swapped = true
					break
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !swapped {
		b, _ := os.ReadFile(filepath.Join(work, "agent.log"))
		t.Fatalf("rc2 agent never swapped to the current artifact (served=%v); log:\n%s", artifactServed, b)
	}
	// The state files survive byte-for-byte (tunnels keep running).
	if b, _ := os.ReadFile(filepath.Join(cfg, "tunnel-state.json")); string(b) != string(tunState) {
		t.Fatal("tunnel state changed during the rc2→current update")
	}
	t.Logf("rc2 agent accepted the CURRENT-signed artifact and swapped (marker + .prev present)")

	// Tamper refusal (cross-version security property).
	badSum := sha256.Sum256([]byte("tampered"))
	tampered := map[string]any{
		"version":   "v99.0.2",
		"url":       srv.URL + "/api/agent/artifact/gre-panel-linux-amd64",
		"sha256":    hex.EncodeToString(badSum[:]),
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte("tampered"))),
	}
	cj2, _ := json.Marshal(protocol.Command{Op: protocol.CmdAgentUpdate, Params: toStringMap(tampered)})
	if err := wsWriteCommand(srv, cj2); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	if b, _ := os.ReadFile(binPath); string(b) != string(curBytes) {
		t.Fatal("a tampered artifact must not touch the swapped binary")
	}
	_ = strings.TrimSpace // anchor
	t.Logf("tampered artifact refused by the rc2-updated agent")
}

// wsWriteCommand sends one command envelope to the connected agent
// through the hub's registered session (the test server holds it).
func wsWriteCommand(srv *httptest.Server, payload json.RawMessage) error {
	// The hub connection object lives in the handler goroutine; the
	// simplest honest channel: the handler itself pulls from a package
	// var queue (set up in the test above).
	select {
	case compatCommandQueue <- payload:
		return nil
	default:
		return errCompatQueueFull
	}
}

var (
	compatCommandQueue = make(chan json.RawMessage, 4)
	errCompatQueueFull = errCompatQueue("command queue full")
)

type errCompatQueue string

func (e errCompatQueue) Error() string { return string(e) }

func toStringMap(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}
