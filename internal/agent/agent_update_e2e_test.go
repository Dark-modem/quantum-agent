//go:build integration

// agent_update_e2e_test.go — the self-update END TO END with REAL agent
// binaries (phase 10, task 4): build two real quantum-agent binaries that
// differ only in version, serve the new one over HTTPS with a signed
// artifact, drive the REAL update path (download → verify → self-report →
// atomic swap → marker → restart op), and assert:
//
//   - the swap happened (the new binary on disk, the old in .prev, the
//     marker carrying the old binary's sha),
//   - the NEW binary reports the new version (the same panelVersion the
//     hello carries),
//   - a TAMPERED artifact is refused and the installed binary is
//     untouched,
//   - a crash-looping new build is rolled back to the previous binary by
//     the boot-rollback mechanism (3 boots, real files),
//   - the enrollment + tunnel state survive the swap byte-for-byte (the
//     tunnels keep running through the update),
//   - with the panel DEAD the updated agent stays alive on the reconnect
//     backoff.
//
//	Run: AGENT_UPDATE_E2E=1 go test -tags integration \
//	         -run TestAgentUpdateE2E ./internal/agent/ -count=1 -v
//
// Requires: Linux, the module cache (builds two real agent binaries).

package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const updateE2EOld = "v10.0.0"
const updateE2ENew = "v10.0.1"

func updateE2EBuild(t *testing.T, dir, name, version string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	// The module root is two levels up from internal/agent (the test's
	// package dir is the working dir of the go test process).
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags",
		"-X github.com/Dark-modem/quantum-agent/internal/agent.panelVersion="+version,
		"-o", out, "./cmd/quantum-agent")
	cmd.Dir = "../.."
	if out2, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v: %s", name, err, out2)
	}
	return out
}

func TestAgentUpdateE2E(t *testing.T) {
	if os.Getenv("AGENT_UPDATE_E2E") == "" {
		t.Skip("AGENT_UPDATE_E2E not set (builds two real agent binaries)")
	}
	dir := t.TempDir()
	oldBin := updateE2EBuild(t, dir, "agent-v1", updateE2EOld)
	newBin := updateE2EBuild(t, dir, "agent-v2", updateE2ENew)
	oldBytes, err := os.ReadFile(oldBin)
	if err != nil {
		t.Fatal(err)
	}
	newBytes, err := os.ReadFile(newBin)
	if err != nil {
		t.Fatal(err)
	}

	// The signing key + pinned public half.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	origKey := agentUpdatePubKeyPEM
	agentUpdatePubKeyPEM = base64.StdEncoding.EncodeToString(der)
	t.Cleanup(func() { agentUpdatePubKeyPEM = origKey })

	// The controller: serves the signed artifact over HTTPS (the agent
	// refuses plaintext artifact URLs). The test CA is trusted via
	// SSL_CERT_FILE (crypto/x509 honors it on Linux).
	newSum := sha256.Sum256(newBytes)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/agent/artifact/gre-panel-linux-amd64", func(w http.ResponseWriter, _ *http.Request) {
		w.Write(newBytes)
	})
	srv := newTLSTestServer(t, mux)
	defer srv.Close()
	_ = srv // the enrollment below points at this URL
	req := agentUpdateRequest{
		Version:   updateE2ENew,
		URL:       srv.URL + "/api/agent/artifact/gre-panel-linux-amd64",
		SHA256Hex: hex.EncodeToString(newSum[:]),
		Signature: updateE2ESign(t, priv, newBytes),
	}

	// The installed agent: the OLD binary + enrollment + a tunnel state
	// file that must survive the update untouched.
	install := filepath.Join(dir, "opt", "quantum-agent")
	if err := os.MkdirAll(filepath.Dir(install), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(install, oldBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	origCfg := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = origCfg })
	enrollPath := filepath.Join(configDir, "agent.json")
	enroll := []byte(`{"id":"upd-agent","key":"upd-key","server":"` + srv.URL + `","name":"upd"}`)
	if err := os.WriteFile(enrollPath, enroll, 0o600); err != nil {
		t.Fatal(err)
	}
	tunnelState := filepath.Join(configDir, "tunnel-state.json")
	tunnelBytes := []byte(`{"tunnel":"keep-me"}`)
	if err := os.WriteFile(tunnelState, tunnelBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = engine.NewFakeEngine("fake") // the engine framework stays registered

	// Seams: the "running" binary is the installed copy; the restart op is
	// RECORDED (no systemd in the lab — the boot-rollback is driven by
	// invoking the swapped binary directly, below); sleeps are instant.
	origSelf := agentSelfExe
	agentSelfExe = func() (string, error) { return install, nil }
	t.Cleanup(func() { agentSelfExe = origSelf })
	var restarts []string
	origExec := execCommand
	execCommand = func(name string, args ...string) *exec.Cmd {
		restarts = append(restarts, name+" "+strings.Join(args, " "))
		return exec.Command("true")
	}
	t.Cleanup(func() { execCommand = origExec })
	origSleep := timeSleep
	timeSleep = func(time.Duration) {}
	t.Cleanup(func() { timeSleep = origSleep })

	// ---- 1. the REAL update path ----
	ident2, ok := agentLoadIdentity()
	if !ok {
		t.Fatal("stub enrollment unreadable")
	}
	agentUpdateRun(req, ident2)
	p := agentUpdateProgressSnapshot()
	if p == nil || p.Phase != "restarting" {
		t.Fatalf("update did not reach the restart phase: %+v", p)
	}
	if b, _ := os.ReadFile(install); string(b) != string(newBytes) {
		t.Fatal("the installed binary was not swapped to the new version")
	}
	if b, _ := os.ReadFile(install + ".prev"); string(b) != string(oldBytes) {
		t.Fatal(".prev does not hold the previous binary")
	}
	if mk, ok := agentUpdateMarkerLoad(); !ok || mk.FromSHA != agentFileSHA(oldBin) {
		t.Fatalf("marker missing or wrong FromSHA: %+v", mk)
	}
	if len(restarts) == 0 || !strings.Contains(restarts[0], "restart") {
		t.Fatalf("restart op not issued: %v", restarts)
	}
	if b, _ := os.ReadFile(enrollPath); string(b) != string(enroll) {
		t.Fatal("the enrollment file changed during the update")
	}
	if b, _ := os.ReadFile(tunnelState); string(b) != string(tunnelBytes) {
		t.Fatal("the tunnel state changed during the update")
	}
	out, verr := exec.Command(install, "--version").CombinedOutput()
	if verr != nil || strings.TrimSpace(string(out)) != updateE2ENew {
		t.Fatalf("new binary reports %q (%v), want %s", out, verr, updateE2ENew)
	}
	t.Logf("update applied: swap + marker + restart op OK; the swapped binary self-reports %s", updateE2ENew)

	// ---- 2. the panel DEAD: the updated agent stays alive on backoff ----
	run := exec.Command(install, "run")
	run.Env = append(os.Environ(), "GRE_PANEL_DIR="+configDir)
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(8 * time.Second)
	if err := run.Process.Signal(syscall.Signal(0)); err != nil {
		_ = run.Process.Kill()
		t.Fatalf("the updated agent exited with the panel dead (must retry): %v", err)
	}
	_ = run.Process.Kill()
	_, _ = run.Process.Wait()
	t.Logf("updated agent survives the panel being dead (8s window)")

	// ---- 3. a CRASH-LOOPING new build is rolled back after 3 boots ----
	// The real mechanism: agentUpdateCheckBootRollback at every start, on
	// the REAL swapped files + REAL marker.
	// The 8s panel-dead run counted as boot 1 of the marker; a HEALTHY
	// 5-minute window would clear it — the crash-loop scenario is the
	// opposite (the updated build never stays up), so the marker PERSISTS.
	// Reset its boot counter so the crash-loop boots map 1:1.
	_ = agentUpdateMarkerSave(&agentUpdateMarker{Version: updateE2ENew,
		PrevPath: install + ".prev", BootCount: 0, StartedAt: time.Now().Unix()})
	agentUpdateCheckBootRollback()
	if b, _ := os.ReadFile(install); string(b) != string(newBytes) {
		t.Fatal("rollback must not trigger on boot 1")
	}
	agentUpdateCheckBootRollback()
	if b, _ := os.ReadFile(install); string(b) != string(newBytes) {
		t.Fatal("rollback must not trigger on boot 2")
	}
	agentUpdateCheckBootRollback()
	if b, _ := os.ReadFile(install); string(b) != string(oldBytes) {
		t.Fatal("boot 3 must restore the previous binary")
	}
	if _, ok := agentUpdateMarkerLoad(); ok {
		t.Fatal("marker must be cleared after the rollback")
	}
	t.Logf("crash-loop rollback: the previous binary restored after 3 boots")

	// ---- 4. a TAMPERED artifact is refused; the install is untouched ----
	if err := os.WriteFile(install, oldBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	badSum := sha256.Sum256([]byte("tampered-bytes"))
	tampered := req
	tampered.SHA256Hex = hex.EncodeToString(badSum[:])
	agentUpdateRun(tampered, ident2)
	p2 := agentUpdateProgressSnapshot()
	if p2 == nil || p2.Phase != "failed" {
		t.Fatalf("tampered artifact must fail the update: %+v", p2)
	}
	if b, _ := os.ReadFile(install); string(b) != string(oldBytes) {
		t.Fatal("a tampered artifact must not touch the installed binary")
	}
	t.Logf("tampered artifact refused; the installed binary untouched")
}

func updateE2ESign(t *testing.T, priv ed25519.PrivateKey, data []byte) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))
}
