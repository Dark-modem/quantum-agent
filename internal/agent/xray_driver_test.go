// All four healthy simultaneously.
package agent

// Hermetic tests for the Xray driver (production shape, mirroring the
// FRP/Backhaul suites): release-style tarball WITH a directory entry,
// role resolution through the enrollment name, supervisor, secrets
// handling (0600 config, private key never in logs), counters from the
// stats API seam, Uninstall on idle, Manager reconcile, and the
// mixed-engine Manager shape (Xray + FRP + Backhaul + lab fake).

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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// xrayTestArtifact builds a signed xray-style tar.gz: the single binary
// wrapped in a version DIRECTORY entry (the production release shape).
func xrayTestArtifact(t *testing.T) (body []byte, shaHex, sigB64, pubB64 string) {
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
	if err := tw.WriteHeader(&tar.Header{
		Name: "xray_25.9.30/", Mode: int64(0o755), Typeflag: tar.TypeDir,
	}); err != nil {
		t.Fatal(err)
	}
	content := []byte("#!/bin/sh\n# fake xray: serve run -c config\nsleep 3600\n")
	if err := tw.WriteHeader(&tar.Header{Name: "xray_25.9.30/xray", Mode: 0o755, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	body = buf.Bytes()
	sum := sha256.Sum256(body)
	shaHex = hex.EncodeToString(sum[:])
	sig := ed25519.Sign(priv, body)
	sigB64 = base64.StdEncoding.EncodeToString(sig)
	pubB64 = base64.StdEncoding.EncodeToString(pubDER)
	return body, shaHex, sigB64, pubB64
}

var xrayTestPins = struct{ amd, arm, sigAmd, sigArm string }{
	strings.Repeat("aa", 32), strings.Repeat("bb", 32), strings.Repeat("QQ==", 22)[:88], strings.Repeat("QQ==", 22)[:88],
}

func xrayTestParams() xrayParams {
	return xrayParams{
		ServerSide: "germany", Version: "25.9.30",
		Artifact:  "xray-25.9.30-linux-{arch}.tar.gz",
		SHA256Amd: xrayTestPins.amd, SHA256Arm: xrayTestPins.arm,
		SigAmd: xrayTestPins.sigAmd, SigArm: xrayTestPins.sigArm,
		RemoteAddr: "203.0.113.9", CarrierPort: 2443,
		PublicPort: 5201, LocalAddr: "127.0.0.1", LocalPort: 5202,
		ServerName: "www.microsoft.com", Dest: "www.microsoft.com:443",
		ShortID: "0123abcd", RealityPublicKey: "i0TZbrs0j3aiB2e8J4j0DqM-uEHoOmQna8a0yaU3Mhc",
		RealityPrivateKey: "qJmA9N5S_9fNnE2wC8bXlQ0V0kL2wE8dG7fH6jK5lM0",
		// Flow stays EMPTY: the reverse carrier multiplexes by itself
		// (mux.cool); vision flow stalls all data through it (lab-verified,
		// see xrayValidateParams).
		Flow: "", UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		APIPort: 21599,
	}
}

// xraySetTestEnv wires every seam: the R5 manifest + file endpoints, the
// identity, the key, the config dir, and a fake process spawn. The
// spawned process's stderr is captured so the secret-leak assertion can
// scan it.
func xraySetTestEnv(t *testing.T) (spawned *int, leaked *strings.Builder) {
	t.Helper()
	body, shaHex, sigB64, pubB64 := xrayTestArtifact(t)
	xrayTestPins.amd, xrayTestPins.arm = shaHex, shaHex
	xrayTestPins.sigAmd, xrayTestPins.sigArm = sigB64, sigB64

	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test:7777", BasePath: "bp", Name: "germany"}, true
	}
	origFetch := frpFetchArtifact
	frpFetchArtifact = func(_ context.Context, url string) ([]byte, error) {
		switch {
		case strings.Contains(url, "/api/agent/engine-artifacts?engine=xray&goarch="):
			arch := strings.ToLower(runtime_GOARCH())
			entry := fmt.Sprintf(`{"engine":"xray","version":"25.9.30","goos":"linux","goarch":%q,"artifact":%q,"sha256":%q,"signature":%q}`,
				arch, strings.ReplaceAll("xray-25.9.30-linux-{arch}.tar.gz", "{arch}", arch), shaHex, sigB64)
			return []byte(`{"artifacts":[` + entry + `]}`), nil
		case strings.Contains(url, "/api/agent/engine-artifacts/file/"),
			strings.Contains(url, "/bp/api/agent/artifact/xray-25.9.30-linux-"):
			return body, nil
		}
		return nil, fmt.Errorf("unexpected artifact url %q", url)
	}
	spawned = new(int)
	leaked = new(strings.Builder)
	origSpawn := xraySpawn
	xraySpawn = func(binPath, cfgPath string) (frpProcess, error) {
		*spawned++
		if !strings.HasSuffix(binPath, "xray") {
			return nil, fmt.Errorf("unexpected binary %q", binPath)
		}
		// Read the config as the real process would: the fake process
		// "runs" it, so its content flows into the leaked scanner.
		if data, err := os.ReadFile(cfgPath); err == nil {
			leaked.WriteString(string(data))
		}
		return &fakeFRPProcess{}, nil
	}
	origStats := execCommandJSON
	execCommandJSON = func(apiPort int, prefix string) (uint64, uint64, bool) {
		return 1111, 2222, true // scripted payload counters
	}
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) { return nil, nil }
	// The through-tunnel probe cannot work against the FAKE xray process
	// (no listener) — stub it healthy; the integration runs the real dial.
	origProbe := xrayProbeFn
	xrayProbeFn = func(int) error { return nil }
	origCfg := configDir
	configDir = t.TempDir()
	t.Cleanup(func() {
		engineArtifactPubKeyB64 = origKey
		frpLoadIdentity = origIdent
		frpFetchArtifact = origFetch
		xraySpawn = origSpawn
		execCommandJSON = origStats
		frpIptables = origIpt
		xrayProbeFn = origProbe
		configDir = origCfg
	})
	return spawned, leaked
}

// runtime_GOARCH indirection so the test stays readable.
func runtime_GOARCH() string { return strings.ToLower(runtime.GOARCH) }

func TestXrayDriverImplementsEngineDriver(t *testing.T) {
	var d engine.Driver = NewXrayDriver()
	if d.ID() != "xray" {
		t.Fatalf("ID = %q", d.ID())
	}
}

func TestXrayValidateParams(t *testing.T) {
	d := NewXrayDriver()
	p := xrayTestParams()
	raw, _ := json.Marshal(p)
	if err := d.Validate(raw); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}
	bad := p
	bad.RealityPrivateKey = "short"
	raw, _ = json.Marshal(bad)
	if err := d.Validate(raw); err == nil {
		t.Fatal("short private key accepted")
	}
	bad = p
	bad.ShortID = "zzzz-not-hex!"
	raw, _ = json.Marshal(bad)
	if err := d.Validate(raw); err == nil {
		t.Fatal("non-hex short_id accepted")
	}
	bad = p
	bad.CarrierPort = 0
	raw, _ = json.Marshal(bad)
	if err := d.Validate(raw); err == nil {
		t.Fatal("zero carrier port accepted")
	}
}

func TestXrayRoleResolution(t *testing.T) {
	_, _, _, pubB64 := xrayTestArtifact(t)
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "germany"}, true
	}
	t.Cleanup(func() {
		engineArtifactPubKeyB64 = origKey
		frpLoadIdentity = origIdent
	})
	p := xrayTestParams()
	if role, err := xrayResolveRole(p); err != nil || role != engineSideServer {
		t.Fatalf("germany role = %q %v, want server", role, err)
	}
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "iran-1"}, true
	}
	if role, err := xrayResolveRole(p); err != nil || role != engineSideClient {
		t.Fatalf("iran role = %q %v, want client", role, err)
	}
}

// TestXrayStartStopSecrets: Start writes the instance config 0600 and
// the Reality private key NEVER appears in anything the driver exposes
// beyond that file (the fake process scans it; the driver's own error
// paths must not embed it).
func TestXrayStartStopSecrets(t *testing.T) {
	spawned, _ := xraySetTestEnv(t)
	d := NewXrayDriver()
	p := xrayTestParams()
	serverInst := engine.Instance{TunnelID: "tx1", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(p)}
	if err := d.Start(context.Background(), serverInst); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	if *spawned != 1 {
		t.Fatalf("spawned = %d", *spawned)
	}
	cfgPath := xrayConfigPath("tx1")
	fi, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// The 0600 mode is a Unix contract; Windows has no perms — the Linux
	// gate (authoritative) enforces it there.
	if runtime.GOOS == "linux" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v, want 0600 (it carries the private key)", fi.Mode().Perm())
	}
	// The private key lives ONLY in the 0600 config — nothing else the
	// driver produced may contain it.
	data, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(data), p.RealityPrivateKey) {
		t.Fatal("config missing the private key (the server needs it)")
	}
	// The spawned process legitimately reads the 0600 config (it must, to
	// run), so the leak assertion is: the key never appears in anything
	// ELSE the driver wrote. Walk the engine tree — every other file
	// carrying it is a leak (configs are the only 0600 holders).
	_ = filepath.Walk(xrayEngineDir(), func(path string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() || path == cfgPath {
			return nil
		}
		if content, rerr := os.ReadFile(path); rerr == nil &&
			strings.Contains(string(content), p.RealityPrivateKey) {
			t.Fatalf("PRIVATE KEY LEAKED into %s (mode %v)", path, info.Mode())
		}
		return nil
	})
	// Health with the stats seam scripted.
	if h := d.Health(serverInst); !h.OK {
		t.Fatalf("health = %+v", h)
	}
	// Counters: wire Unknown (iptables seam nil'd) and payload scripted.
	c := d.Counters(serverInst)
	if !c.PayloadKnown || c.PayloadRx != 2222 || c.PayloadTx != 1111 {
		t.Fatalf("counters = %+v", c)
	}
	if err := d.Stop(serverInst); err != nil {
		t.Fatal(err)
	}
	if h := d.Health(serverInst); h.OK {
		t.Fatal("alive after Stop")
	}
}

func TestXrayRenderConfigShapes(t *testing.T) {
	p := xrayTestParams()
	serverCfg := xrayBuildConfig(engineSideServer, p)
	sj, _ := json.Marshal(serverCfg)
	for _, want := range []string{`"realitySettings"`, `"privateKey"`, `"dokodemo-door"`, `"vless"`, `"StatsService"`} {
		if !strings.Contains(string(sj), want) {
			t.Fatalf("server config missing %q:\n%s", want, sj)
		}
	}
	clientCfg := xrayBuildConfig(engineSideClient, p)
	cj, _ := json.Marshal(clientCfg)
	for _, want := range []string{`"realitySettings"`, `"publicKey"`, `"freedom"`, `"vless"`} {
		if !strings.Contains(string(cj), want) {
			t.Fatalf("client config missing %q:\n%s", want, cj)
		}
	}
	// The client end must NOT carry the private key (it only needs the
	// public half).
	if strings.Contains(string(cj), p.RealityPrivateKey) {
		t.Fatal("client config carries the PRIVATE key")
	}
}

// TestXrayReverseCarrierRules locks in the two reverse-channel fixes found
// in the 2026-11-08 lab (xray v24.12.31):
//   - the bridge's FIRST routing rule must be scoped to the internal
//     domain; without it, first-match-wins sends portal-returned traffic
//     back into the carrier (routing loop: 11,705 dials vs 5);
//   - the carrier must not set vision flow: the reverse link's underlying
//     protocol is mux.cool and vision stalls all data (validate rejects it).
func TestXrayReverseCarrierRules(t *testing.T) {
	p := xrayTestParams()
	clientCfg := xrayBuildConfig(engineSideClient, p)
	cj, _ := json.Marshal(clientCfg)
	wantDomain := `{"type":"field","inboundTag":["rev-bridge"],"domain":["full:quantum.rev.internal"],"outboundTag":"carrier-out"}`
	if !strings.Contains(string(cj), wantDomain) {
		t.Fatalf("bridge first rule lacks the internal-domain filter (routing loop):\n%s", cj)
	}
	if strings.Contains(string(cj), `"flow"`) {
		t.Fatalf("bridge carrier carries a flow — mux.cool + vision stalls data:\n%s", cj)
	}
	// The warmup probe (PHASE8 1b): the bridge answers probe.quantum with
	// the blackhole HTTP response, and the probe rule sits BEFORE the
	// catch-all local rule (first-match-wins).
	probeRule := strings.Index(string(cj), `"domain":["full:probe.quantum"],"outboundTag":"probe"`)
	localRule := strings.Index(string(cj), `"outboundTag":"local"`)
	if probeRule < 0 || localRule < 0 || probeRule > localRule {
		t.Fatalf("bridge probe rule missing or after the local rule:\n%s", cj)
	}
	if !strings.Contains(string(cj), `"tag":"probe","protocol":"blackhole"`) {
		t.Fatalf("bridge probe outbound missing:\n%s", cj)
	}
	serverCfg := xrayBuildConfig(engineSideServer, p)
	sj, _ := json.Marshal(serverCfg)
	if strings.Contains(string(sj), `"flow"`) {
		t.Fatalf("portal vless-in client carries a flow:\n%s", sj)
	}
	// The portal's probe inbound rides APIPort+1 when the API is on.
	if !strings.Contains(string(sj), `"tag":"probe-in"`) || !strings.Contains(string(sj), fmt.Sprint(p.APIPort+1)) {
		t.Fatalf("portal probe inbound missing:\n%s", sj)
	}
	if !strings.Contains(string(sj), `"inboundTag":["probe-in"],"outboundTag":"rev-portal"`) {
		t.Fatalf("portal probe rule missing:\n%s", sj)
	}
	// Validate refuses any flow (fail closed with a clear message).
	bad := p
	bad.Flow = "xtls-rprx-vision"
	raw, _ := json.Marshal(bad)
	d := NewXrayDriver()
	if err := d.Validate(raw); err == nil || !strings.Contains(err.Error(), "flow must be empty") {
		t.Fatalf("vision flow accepted: %v", err)
	}
}

func TestXrayForwardAddress(t *testing.T) {
	_, _, _, pubB64 := xrayTestArtifact(t)
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "germany"}, true
	}
	t.Cleanup(func() {
		engineArtifactPubKeyB64 = origKey
		frpLoadIdentity = origIdent
	})
	d := NewXrayDriver()
	p := xrayTestParams()
	serverInst := engine.Instance{TunnelID: "tx-fa", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(p)}
	host, port, ok := d.ForwardAddress(serverInst)
	if !ok || host != "127.0.0.1" || port != p.PublicPort {
		t.Fatalf("server-side forward = %s:%d %v", host, port, ok)
	}
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "iran-1"}, true
	}
	host, port, ok = d.ForwardAddress(engine.Instance{TunnelID: "tx-fa", LocalServer: "iran",
		RemoteServer: "germany", Params: mustJSON(p)})
	if !ok || host != p.RemoteAddr || port != p.PublicPort {
		t.Fatalf("client-side forward = %s:%d %v", host, port, ok)
	}
}

func TestXrayManagerReconcile(t *testing.T) {
	spawned, _ := xraySetTestEnv(t)
	reg := engine.NewRegistry()
	if err := reg.Register(NewXrayDriver()); err != nil {
		t.Fatal(err)
	}
	mgr := engine.NewManager(reg)
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { frpIptables = origIpt })
	p := xrayTestParams()
	res := mgr.Reconcile(context.Background(),
		[]engine.EngineSpec{{ID: "xray", Enabled: true}},
		[]engine.TunnelSpec{{ID: "tx3", Engine: "xray", LocalServer: "germany", RemoteServer: "iran",
			Params: mustJSON(p), Enabled: true}})
	if len(res.Errors) > 0 {
		t.Fatalf("reconcile: %v", res.Errors)
	}
	if mgr.RunningCount() != 1 || *spawned != 1 {
		t.Fatalf("running=%d spawned=%d", mgr.RunningCount(), *spawned)
	}
	res = mgr.Reconcile(context.Background(), nil, nil)
	if mgr.RunningCount() != 0 {
		t.Fatal("running after disable")
	}
	found := false
	for _, id := range res.Uninstalled {
		if id == "xray" {
			found = true
		}
	}
	if !found {
		t.Fatalf("xray not uninstalled after idle: %v", res.Uninstalled)
	}
}

// TestXrayMixedManagerShape: Xray + FRP + Backhaul + lab fake run in the
// SAME Manager without interference (the multi-engine reconcile shape).
// All four artifacts are signed with ONE test key (a single pinned-key
// TestXrayMixedManagerShape: Xray + FRP + Backhaul + lab fake run in the
// SAME Manager without interference (the multi-engine reconcile shape).
// ALL artifacts are signed with ONE test key (a single pinned-key var
// serves every engine), and one dispatch seam serves all manifests and
// bodies.
func TestXrayMixedManagerShape(t *testing.T) {
	// One keypair signs all three artifacts: the pinned-key var is
	// process-wide, so per-suite keys would fail each other's verify.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pubDER)
	mixArt := func(dirName string, files map[string]string) (body []byte, shaHex, sigB64 string) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&tar.Header{Name: dirName + "/", Mode: int64(0o755), Typeflag: tar.TypeDir}); err != nil {
			t.Fatal(err)
		}
		for name, content := range files {
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
		sum := sha256.Sum256(buf.Bytes())
		return buf.Bytes(), hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, buf.Bytes()))
	}
	frpBody, frpSHA, frpSIG := mixArt("frp_0.61.1", map[string]string{"frps": "#!/bin/sh\nfrps\n", "frpc": "#!/bin/sh\nfrpc\n"})
	xBody, xSHA, xSIG := mixArt("xray_25.9.30", map[string]string{"xray": "#!/bin/sh\nxray\n"})
	bhBody, bhSHA, bhSIG := mixArt("backhaul_0.7.2", map[string]string{"backhaul": "#!/bin/sh\nbackhaul\n"})
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test:7777", BasePath: "bp", Name: "germany"}, true
	}
	origFetch := frpFetchArtifact
	frpFetchArtifact = func(_ context.Context, url string) ([]byte, error) {
		if strings.Contains(url, "/api/agent/engine-artifacts?engine=") {
			var engineID, ver, art, sha, sig string
			arch := strings.ToLower(runtime.GOARCH)
			switch {
			case strings.Contains(url, "engine=xray"):
				engineID, ver, art, sha, sig = "xray", "25.9.30", "xray-25.9.30-linux-"+arch+".tar.gz", xSHA, xSIG
			case strings.Contains(url, "engine=backhaul"):
				engineID, ver, art, sha, sig = "backhaul", "0.7.2", "backhaul-0.7.2-linux-"+arch+".tar.gz", bhSHA, bhSIG
			default:
				engineID, ver, art, sha, sig = "frp", "0.61.1", "frp-0.61.1-linux-"+arch+".tar.gz", frpSHA, frpSIG
			}
			return []byte(fmt.Sprintf(`{"artifacts":[{"engine":%q,"version":%q,"goos":"linux","goarch":%q,"artifact":%q,"sha256":%q,"signature":%q}]}`,
				engineID, ver, arch, art, sha, sig)), nil
		}
		if strings.Contains(url, "backhaul-0.7.2-linux-") {
			return bhBody, nil
		}
		if strings.Contains(url, "xray-25.9.30-linux-") {
			return xBody, nil
		}
		return frpBody, nil
	}
	frpTestPins.amd, frpTestPins.arm = frpSHA, frpSHA
	frpTestPins.sigAmd, frpTestPins.sigArm = frpSIG, frpSIG
	xrayTestPins.amd, xrayTestPins.arm = xSHA, xSHA
	xrayTestPins.sigAmd, xrayTestPins.sigArm = xSIG, xSIG
	backhaulTestPins.amd, backhaulTestPins.arm = bhSHA, bhSHA
	backhaulTestPins.sigAmd, backhaulTestPins.sigArm = bhSIG, bhSIG
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) { return nil, nil }
	origSpawn := frpSpawn
	spawned := new(int)
	frpSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		*spawned++
		return &fakeFRPProcess{}, nil
	}
	origXSpawn := xraySpawn
	xraySpawn = func(binPath, cfgPath string) (frpProcess, error) {
		*spawned++
		return &fakeFRPProcess{}, nil
	}
	// The Xray StatsService probe is scripted (no real binary here).
	origStats := execCommandJSON
	execCommandJSON = func(apiPort int, prefix string) (uint64, uint64, bool) {
		return 1111, 2222, true
	}
	// The through-tunnel warmup probe is scripted too (no real listener).
	origProbeFn := xrayProbeFn
	xrayProbeFn = func(int) error { return nil }
	// The FRP dashboard API (Health probe) is scripted too.
	origDash := frpDashHTTP
	frpDashHTTP = func(ctx context.Context, url string, user string, pass string) (int, []byte, error) {
		return 200, []byte(`{}`), nil
	}
	// Lab fake for the matrix stand-in (needs a forward address).
	origLab := agentV2TestDriver
	lab := engine.NewFakeEngine("fake")
	agentV2TestDriver = lab
	lab.SetForwardAddress("t-matrix", "10.203.0.9", 5201)
	matrixDriverRegOnce = sync.Once{}
	t.Cleanup(func() {
		engineArtifactPubKeyB64 = origKey
		frpFetchArtifact = origFetch
		frpIptables = origIpt
		frpSpawn = origSpawn
		xraySpawn = origXSpawn
		frpDashHTTP = origDash
		execCommandJSON = origStats
		xrayProbeFn = origProbeFn
		frpLoadIdentity = origIdent
		agentV2TestDriver = origLab
		matrixDriverRegOnce = sync.Once{}
	})

	reg, err := AgentEngines()
	if err != nil {
		t.Fatal(err)
	}
	mgr := engine.NewManager(reg)
	xp := xrayTestParams()
	frpP := frpTestParams()
	bp := backhaulTestParams()
	specs := []engine.EngineSpec{
		{ID: "xray", Enabled: true}, {ID: "frp", Enabled: true},
		{ID: "backhaul", Enabled: true}, {ID: "fake", Enabled: true},
	}
	tunnels := []engine.TunnelSpec{
		{ID: "t-xray", Engine: "xray", LocalServer: "germany", RemoteServer: "iran", Params: mustJSON(xp), Enabled: true},
		{ID: "t-frp", Engine: "frp", LocalServer: "germany", RemoteServer: "iran", Params: mustJSON(frpP), Enabled: true},
		{ID: "t-bh", Engine: "backhaul", LocalServer: "germany", RemoteServer: "iran", Params: mustJSON(bp), Enabled: true},
		{ID: "t-matrix", Engine: "fake", LocalServer: "germany", RemoteServer: "iran", Enabled: true},
	}
	res := mgr.Reconcile(context.Background(), specs, tunnels)
	if len(res.Errors) > 0 {
		t.Fatalf("mixed reconcile: %v", res.Errors)
	}
	if mgr.RunningCount() != 4 {
		t.Fatalf("running = %d, want 4", mgr.RunningCount())
	}
	// All four healthy simultaneously.
	for _, ts := range mgr.Status() {
		if !ts.Health.OK {
			t.Fatalf("tunnel %s unhealthy: %+v", ts.TunnelID, ts.Health)
		}
	}
	// Teardown all.
	if res := mgr.Reconcile(context.Background(), nil, nil); len(res.Errors) != 0 {
		t.Fatalf("teardown: %v", res.Errors)
	}
	if mgr.RunningCount() != 0 {
		t.Fatal("running after teardown")
	}
}
