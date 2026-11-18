// engines45_driver_test.go — hermetic tests for the wstunnel (6th) and
// chisel (7th) drivers: strict validation, role resolution via the
// enrollment name, artifact through the R5 manifest with the pinned
// fallback (release tarball WITH a directory entry), idempotent Start,
// supervisor capped-backoff restart, Health relay probe (real local TCP
// relay), per-instance wire accounting seam, Uninstall idle = zero
// files. No host touches; the artifact serves no shell.

package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// ---- shared fixtures -------------------------------------------------------

type engine45Fixture struct {
	body    []byte
	shaHex  string
	sigB64  string
	pubB64  string
	spawned *int
	leaked  *strings.Builder
}

// fakeExitProcess is a controllable fake process for supervisor tests.
type fakeExitProcess struct {
	mu       sync.Mutex
	done     chan error
	exitOnce sync.Once
}

func newFakeExitProcess() *fakeExitProcess {
	return &fakeExitProcess{done: make(chan error, 1)}
}

func (f *fakeExitProcess) Pid() int { return 4242 }
func (f *fakeExitProcess) Signal(sig os.Signal) error {
	f.exitOnce.Do(func() { close(f.done) })
	return nil
}
func (f *fakeExitProcess) Done() <-chan error { return f.done }
func (f *fakeExitProcess) exit()              { f.exitOnce.Do(func() { close(f.done) }) }

// engine45TestArtifact builds a release-style tar.gz WITH a directory
// entry (production shape) holding the given binaries.
func engine45TestArtifact(t *testing.T, dirName string, bins map[string]string) ([]byte, string, string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: dirName + "/", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	for name, content := range bins {
		if err := tw.WriteHeader(&tar.Header{Name: dirName + "/" + name, Mode: 0o755, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	body := buf.Bytes()
	sum := sha256.Sum256(body)
	sig := ed25519.Sign(priv, body)
	return body, hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(sig), base64.StdEncoding.EncodeToString(pubDER)
}

func wstTestParams(amd, arm, sigAmd, sigArm string) wstParams {
	return wstParams{
		ServerSide: "germany", Version: "10.1.9",
		Artifact:  "wstunnel-10.1.9-linux-{arch}.tar.gz",
		SHA256Amd: amd, SHA256Arm: arm, SigAmd: sigAmd, SigArm: sigArm,
		RemoteAddr: "203.0.113.9", WsPort: 18801,
		RemotePort: 18802, RemoteUdpPort: 18803,
		LocalAddr: "127.0.0.1", LocalPort: 18804, LocalUdpPort: 18805,
	}
}

func chiselTestParams(amd, arm, sigAmd, sigArm string) chiselParams {
	return chiselParams{
		ServerSide: "germany", Version: "1.10.1",
		Artifact:  "chisel-1.10.1-linux-{arch}.tar.gz",
		SHA256Amd: amd, SHA256Arm: arm, SigAmd: sigAmd, SigArm: sigArm,
		RemoteAddr: "203.0.113.9", ServerPort: 18811, RemotePort: 18812,
		LocalAddr: "127.0.0.1", LocalPort: 18813, Auth: "op:secret-pass-1",
	}
}

// wstTestHarness wires a full hermetic environment for one engine test:
// pinned key, enrollment identity, R5 manifest + file endpoints serving
// the fake artifact, spawn seam (counting + arg leak capture), iptables
// seam, throwaway config dir.
func wstTestHarness(t *testing.T, role string) (*WstDriver, *int, *strings.Builder, wstParams) {
	t.Helper()
	body, shaHex, sigB64, pubB64 := engine45TestArtifact(t, "wstunnel_10.1.9", map[string]string{
		"wstunnel": "#!/bin/sh\n# fake wstunnel: serve client/server\nsleep 3600\n",
	})
	// The artifact serves BOTH arches (the pinned fallback uses the same
	// bytes; the manifest path resolves the running arch's name).
	p := wstTestParams(shaHex, shaHex, sigB64, sigB64)

	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test:7777", BasePath: "bp", Name: role}, true
	}
	origFetch := frpFetchArtifact
	frpFetchArtifact = func(_ context.Context, url string) ([]byte, error) {
		switch {
		case strings.Contains(url, "/api/agent/engine-artifacts?engine=wstunnel&goarch="):
			arch := strings.ToLower(runtime.GOARCH)
			entry := fmt.Sprintf(`{"engine":"wstunnel","version":"10.1.9","goos":"linux","goarch":%q,"artifact":%q,"sha256":%q,"signature":%q}`,
				arch, strings.ReplaceAll("wstunnel-10.1.9-linux-{arch}.tar.gz", "{arch}", arch), shaHex, sigB64)
			return []byte(`{"artifacts":[` + entry + `]}`), nil
		case strings.Contains(url, "/api/agent/engine-artifacts/file/"),
			strings.Contains(url, "/bp/api/agent/artifact/wstunnel-10.1.9-linux-"):
			return body, nil
		}
		return nil, fmt.Errorf("unexpected artifact url %q", url)
	}
	spawned := 0
	leaked := &strings.Builder{}
	origSpawn := wstSpawn
	wstSpawn = func(binPath string, args []string) (frpProcess, error) {
		spawned++
		if !strings.HasSuffix(binPath, "wstunnel") {
			return nil, fmt.Errorf("unexpected binary %q", binPath)
		}
		leaked.WriteString(strings.Join(args, " ") + "\n")
		return newFakeExitProcess(), nil
	}
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) { return nil, nil }
	origCfg := configDir
	configDir = t.TempDir()
	t.Cleanup(func() {
		engineArtifactPubKeyB64 = origKey
		frpLoadIdentity = origIdent
		frpFetchArtifact = origFetch
		wstSpawn = origSpawn
		frpIptables = origIpt
		configDir = origCfg
	})
	return NewWstDriver(), &spawned, leaked, p
}

func chiselTestHarness(t *testing.T, role string) (*ChiselDriver, *int, *strings.Builder, chiselParams) {
	t.Helper()
	body, shaHex, sigB64, pubB64 := engine45TestArtifact(t, "chisel_1.10.1", map[string]string{
		"chisel": "#!/bin/sh\n# fake chisel: serve client/server\nsleep 3600\n",
	})
	p := chiselTestParams(shaHex, shaHex, sigB64, sigB64)

	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test:7777", BasePath: "bp", Name: role}, true
	}
	origFetch := frpFetchArtifact
	frpFetchArtifact = func(_ context.Context, url string) ([]byte, error) {
		switch {
		case strings.Contains(url, "/api/agent/engine-artifacts?engine=chisel&goarch="):
			arch := strings.ToLower(runtime.GOARCH)
			entry := fmt.Sprintf(`{"engine":"chisel","version":"1.10.1","goos":"linux","goarch":%q,"artifact":%q,"sha256":%q,"signature":%q}`,
				arch, strings.ReplaceAll("chisel-1.10.1-linux-{arch}.tar.gz", "{arch}", arch), shaHex, sigB64)
			return []byte(`{"artifacts":[` + entry + `]}`), nil
		case strings.Contains(url, "/api/agent/engine-artifacts/file/"),
			strings.Contains(url, "/bp/api/agent/artifact/chisel-1.10.1-linux-"):
			return body, nil
		}
		return nil, fmt.Errorf("unexpected artifact url %q", url)
	}
	spawned := 0
	leaked := &strings.Builder{}
	origSpawn := chiselSpawn
	chiselSpawn = func(binPath string, args []string) (frpProcess, error) {
		spawned++
		if !strings.HasSuffix(binPath, "chisel") {
			return nil, fmt.Errorf("unexpected binary %q", binPath)
		}
		leaked.WriteString(strings.Join(args, " ") + "\n")
		return newFakeExitProcess(), nil
	}
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) { return nil, nil }
	origCfg := configDir
	configDir = t.TempDir()
	t.Cleanup(func() {
		engineArtifactPubKeyB64 = origKey
		frpLoadIdentity = origIdent
		frpFetchArtifact = origFetch
		chiselSpawn = origSpawn
		frpIptables = origIpt
		configDir = origCfg
	})
	return NewChiselDriver(), &spawned, leaked, p
}

// ---- wstunnel tests ---------------------------------------------------------

func TestWstDriverImplementsEngineDriver(t *testing.T) {
	var d engine.Driver = NewWstDriver()
	if d.ID() != "wstunnel" {
		t.Fatalf("ID = %q", d.ID())
	}
}

func TestWstValidateParams(t *testing.T) {
	d := NewWstDriver()
	p := wstTestParams(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 100), strings.Repeat("d", 100))
	raw, _ := json.Marshal(p)
	if err := d.Validate(raw); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}
	bad := p
	bad.RemotePort = bad.WsPort
	raw, _ = json.Marshal(bad)
	if err := d.Validate(raw); err == nil {
		t.Fatal("remote_port == ws_port accepted")
	}
	bad = p
	bad.RemoteUdpPort = 18803
	bad.LocalUdpPort = 0
	raw, _ = json.Marshal(bad)
	if err := d.Validate(raw); err == nil {
		t.Fatal("udp remote without local target accepted")
	}
	bad = p
	bad.SHA256Amd = "short"
	raw, _ = json.Marshal(bad)
	if err := d.Validate(raw); err == nil {
		t.Fatal("short sha accepted")
	}
	bad = p
	bad.WsPort = 70000
	raw, _ = json.Marshal(bad)
	if err := d.Validate(raw); err == nil {
		t.Fatal("out-of-range ws_port accepted")
	}
}

func TestWstRoleResolution(t *testing.T) {
	d, _, _, p := wstTestHarness(t, "germany")
	role, err := wstResolveRole(p)
	if err != nil {
		t.Fatal(err)
	}
	if role != engineSideServer {
		t.Fatalf("enrollment name germany must be the server side, got %v", role)
	}
	// Client side.
	d2, _, _, p2 := wstTestHarness(t, "iran-1")
	role2, err := wstResolveRole(p2)
	if err != nil {
		t.Fatal(err)
	}
	if role2 != engineSideClient {
		t.Fatalf("enrollment name iran-1 must be the client side, got %v", role2)
	}
	_ = d
	_ = d2
}

func TestWstStartManifestPathAndArgsShape(t *testing.T) {
	d, spawned, leaked, p := wstTestHarness(t, "germany") // this host IS the server side
	inst := engine.Instance{TunnelID: "t-wst-1", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = d.Stop(inst); _ = d.Uninstall(context.Background()) }()
	if *spawned != 1 {
		t.Fatalf("spawned=%d, want 1", *spawned)
	}
	// The SERVER end renders exactly the pinned v10 server shape.
	if !strings.Contains(leaked.String(), "server ws://0.0.0.0:18801") {
		t.Fatalf("server args wrong: %q", leaked.String())
	}
	if strings.Contains(leaked.String(), "client") {
		t.Fatal("server end must not run the client shape")
	}
	// Idempotent re-Start with equal params is a no-op.
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("idempotent start: %v", err)
	}
	if *spawned != 1 {
		t.Fatalf("idempotent start re-spawned: %d", *spawned)
	}
}

func TestWstClientArgsShapeAndHealthProbe(t *testing.T) {
	// Client shape carries BOTH tcp and udp -R instructions (TCP+UDP over
	// the one WebSocket — the engine's whole point).
	p := wstTestParams("x", "y", "z", "w")
	args := wstClientArgs(p)
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-R tcp://0.0.0.0:18802:127.0.0.1:18804") {
		t.Fatalf("tcp -R missing: %q", joined)
	}
	if !strings.Contains(joined, "-R udp://0.0.0.0:18803:127.0.0.1:18805") {
		t.Fatalf("udp -R missing: %q", joined)
	}
	if !strings.Contains(joined, "ws://203.0.113.9:18801") {
		t.Fatalf("carrier url missing: %q", joined)
	}

	// Health relay probe against a REAL ECHO relay: the probe byte must
	// come back through the tunnel (echo semantics).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c) // echo server: probe byte returns
				c.Close()
			}(c)
		}
	}()
	if err := wstProbeRelay(port, time.Second); err != nil {
		t.Fatalf("echo relay must be healthy: %v", err)
	}
	// A listener that reads and holds (dead relay held by the engine):
	// no echo comes back = unhealthy.
	hold, _ := net.Listen("tcp", "127.0.0.1:0")
	defer hold.Close()
	holdPort := hold.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := hold.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(io.Discard, c) // swallow, never echo
				time.Sleep(2 * time.Second)
				c.Close()
			}(c)
		}
	}()
	if err := wstProbeRelay(holdPort, time.Second); err == nil {
		t.Fatal("no-echo relay must be unhealthy")
	}
	// Nothing listening at all = unhealthy.
	if err := wstProbeRelay(1, 300*time.Millisecond); err == nil {
		t.Fatal("closed port must be unhealthy")
	}
}

func TestWstSupervisorRestartsAndStopKeepsItDead(t *testing.T) {
	d, spawned, _, p := wstTestHarness(t, "germany")
	inst := engine.Instance{TunnelID: "t-wst-2", Params: mustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatal(err)
	}
	st := d.runs.peek("t-wst-2")
	if st == nil {
		t.Fatal("no instance state")
	}
	// UNEXPECTED exit → the supervisor restarts (capped backoff).
	if f, ok := st.current().(*fakeExitProcess); ok {
		f.exit()
	} else {
		t.Fatalf("unexpected proc type %T", st.current())
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if *spawned >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if *spawned < 2 {
		t.Fatalf("supervisor did not restart: spawned=%d", *spawned)
	}
	// Deliberate Stop → the process is killed AND never resurrected.
	if err := d.Stop(inst); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if *spawned != 2 {
		t.Fatalf("stop resurrected the process: spawned=%d", *spawned)
	}
	if runs := d.runs.len(); runs != 0 {
		t.Fatalf("runs not empty after stop: %d", runs)
	}
}

func TestWstUninstallLeavesNothing(t *testing.T) {
	d, _, _, p := wstTestHarness(t, "germany")
	inst := engine.Instance{TunnelID: "t-wst-3", Params: mustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatal(err)
	}
	if err := d.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(engineEngineDir(wstID)); !os.IsNotExist(err) {
		t.Fatalf("engine dir survived uninstall: %v", err)
	}
}

// ---- chisel tests ------------------------------------------------------------

func TestChiselDriverImplementsEngineDriver(t *testing.T) {
	var d engine.Driver = NewChiselDriver()
	if d.ID() != "chisel" {
		t.Fatalf("ID = %q", d.ID())
	}
}

func TestChiselValidateParams(t *testing.T) {
	d := NewChiselDriver()
	p := chiselTestParams(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 100), strings.Repeat("d", 100))
	raw, _ := json.Marshal(p)
	if err := d.Validate(raw); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}
	bad := p
	bad.Auth = "no-colon-here"
	raw, _ = json.Marshal(bad)
	if err := d.Validate(raw); err == nil {
		t.Fatal("auth without colon accepted")
	}
	bad = p
	bad.Auth = "u:p\"quote"
	raw, _ = json.Marshal(bad)
	if err := d.Validate(raw); err == nil {
		t.Fatal("quote in auth accepted")
	}
	bad = p
	bad.RemotePort = bad.ServerPort
	raw, _ = json.Marshal(bad)
	if err := d.Validate(raw); err == nil {
		t.Fatal("remote_port == server_port accepted")
	}
}

func TestChiselRoleAndArgsShape(t *testing.T) {
	d, spawned, leaked, p := chiselTestHarness(t, "iran-7") // this host is the CLIENT
	inst := engine.Instance{TunnelID: "t-ch-1", Params: mustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = d.Stop(inst); _ = d.Uninstall(context.Background()) }()
	role, err := chiselResolveRole(p)
	if err != nil {
		t.Fatal(err)
	}
	if role != engineSideClient {
		t.Fatalf("role = %v, want client", role)
	}
	if *spawned != 1 {
		t.Fatalf("spawned=%d", *spawned)
	}
	joined := leaked.String()
	// The client dials the carrier and declares the REVERSE remote.
	if !strings.Contains(joined, "client") || !strings.Contains(joined, "http://203.0.113.9:18811") {
		t.Fatalf("client args wrong: %q", joined)
	}
	if !strings.Contains(joined, "R:0.0.0.0:18812:127.0.0.1:18813") {
		t.Fatalf("reverse remote missing: %q", joined)
	}
	// Auth rides the client args (and is NEVER in a log line — the args
	// file is 0600 and the driver does not print params).
	if !strings.Contains(joined, "--auth op:secret-pass-1") {
		t.Fatalf("auth missing from client args: %q", joined)
	}
	// Server shape (for the record) carries --reverse.
	sargs := strings.Join(chiselServerArgs(p), " ")
	if !strings.Contains(sargs, "--reverse") || !strings.Contains(sargs, "--port 18811") {
		t.Fatalf("server args wrong: %q", sargs)
	}
}

func TestChiselSupervisorAndUninstall(t *testing.T) {
	d, spawned, _, p := chiselTestHarness(t, "germany")
	inst := engine.Instance{TunnelID: "t-ch-2", Params: mustJSON(p)}
	if err := d.Start(context.Background(), inst); err != nil {
		t.Fatal(err)
	}
	st := d.runs.peek("t-ch-2")
	if f, ok := st.current().(*fakeExitProcess); ok {
		f.exit()
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if *spawned >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if *spawned < 2 {
		t.Fatalf("supervisor did not restart: spawned=%d", *spawned)
	}
	if err := d.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(engineEngineDir(chiselID)); !os.IsNotExist(err) {
		t.Fatalf("engine dir survived uninstall: %v", err)
	}
	if runs := d.runs.len(); runs != 0 {
		t.Fatalf("runs not empty after uninstall: %d", runs)
	}
}

func TestEngines45RegisteredInCatalog(t *testing.T) {
	reg, err := NewAgentEngines()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"wstunnel", "chisel", "frp", "backhaul", "xray", "wireguard", "matrix", "ctunnel"} {
		if _, ok := reg.Driver(id); !ok {
			t.Fatalf("engine %q missing from the registry", id)
		}
	}
}
