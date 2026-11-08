package agent

// Phase-9 TASK 2: uninstall-leak coverage for EVERY registered engine.
// After Uninstall: zero processes (the shared fake spawn counter frozen —
// a live supervisor would respawn), zero files (the engine dir gone), no
// goroutine growth (bounded settle), and Health not OK. Matrix is
// excluded (pairing-driven lifecycle, covered by its own tests); the lab
// fake is excluded (no resources).

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// leakSpawnTotal reads the shared spawn counter (every driver's spawn
// seam feeds it).
func leakSpawnTotal(n *int) int {
	runtime.Gosched()
	return *n
}

func TestUninstallLeakAllEngines(t *testing.T) {
	restore := leakTestEnv(t)
	defer restore()

	type drv struct {
		id   string
		d    engine.Driver
		inst engine.Instance
	}
	drivers := []drv{
		{"frp", NewFRPDriver(), engine.Instance{TunnelID: "leak-frp", Params: mustJSON(frpTestParams())}},
		{"backhaul", NewBackhaulDriver(), engine.Instance{TunnelID: "leak-bh", Params: mustJSON(backhaulTestParams())}},
		{"xray", NewXrayDriver(), engine.Instance{TunnelID: "leak-xr", Params: mustJSON(xrayTestParams())}},
		{"rathole", NewRatholeDriver(), engine.Instance{TunnelID: "leak-rh", Params: mustJSON(ratholeTestParams())}},
		{"gost", NewGostDriver(), engine.Instance{TunnelID: "leak-gst", Params: mustJSON(gostTestParams())}},
		{"wireguard", NewWgDriver(), engine.Instance{TunnelID: "leak-wg", Params: mustJSON(wgTestParams())}},
		{"wstunnel", NewWstDriver(), engine.Instance{TunnelID: "leak-wst", Params: mustJSON(
			wstTestParams(strings.Repeat("aa", 32), strings.Repeat("bb", 32),
				strings.Repeat("QQ==", 22)[:88], strings.Repeat("QQ==", 22)[:88]))}},
		{"chisel", NewChiselDriver(), engine.Instance{TunnelID: "leak-ch", Params: mustJSON(
			chiselTestParams(strings.Repeat("aa", 32), strings.Repeat("bb", 32),
				strings.Repeat("QQ==", 22)[:88], strings.Repeat("QQ==", 22)[:88]))}},
	}
	ctx := context.Background()
	for _, dd := range drivers {
		t.Run(dd.id, func(t *testing.T) {
			before := runtime.NumGoroutine()
			if err := dd.d.Start(ctx, dd.inst); err != nil {
				t.Fatalf("Start: %v", err)
			}
			time.Sleep(300 * time.Millisecond) // let the supervisors spin up
			spawnedMid := leakSpawnTotal(&leakCounter)

			if err := dd.d.Uninstall(ctx); err != nil {
				t.Fatalf("Uninstall: %v", err)
			}
			if h := dd.d.Health(dd.inst); h.OK {
				t.Fatalf("Health OK after Uninstall: %+v", h)
			}
			// Processes: the spawn counter must be FROZEN (a live
			// supervisor would keep respawning the fakes).
			time.Sleep(1500 * time.Millisecond)
			if got := leakSpawnTotal(&leakCounter); got != spawnedMid {
				t.Fatalf("processes still spawning after Uninstall: %d → %d", spawnedMid, got)
			}
			// Files: the engine dir must be gone.
			p := filepath.Join(configDir, "engines", dd.id)
			if _, err := os.Stat(p); err == nil {
				t.Fatalf("engine dir %s left behind", p)
			}
			// Goroutines: after a settle, back to the pre-Start level (±1)
			// and stable.
			time.Sleep(1500 * time.Millisecond)
			after := runtime.NumGoroutine()
			if after > before+1 {
				t.Fatalf("goroutines leaked: before=%d after=%d", before, after)
			}
			time.Sleep(500 * time.Millisecond)
			if now := runtime.NumGoroutine(); now > after+1 {
				t.Fatalf("goroutines still growing: %d → %d", after, now)
			}
		})
	}
}

// leakCounter is the ONE spawn counter every fake spawn seam feeds.
var leakCounter int

// leakTestEnv wires every spawn seam to the counting fake, the iptables
// seam to a no-op, pins the artifact key, and warms every binary cache.
func leakTestEnv(t *testing.T) (restore func()) {
	t.Helper()
	origFRP := frpSpawn
	frpSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		leakCounter++
		return &fakeFRPProcess{}, nil
	}
	origRath := ratholeSpawn
	ratholeSpawn = func(binPath, cfgPath string) (frpProcess, error) {
		leakCounter++
		return &fakeFRPProcess{}, nil
	}
	origGost := gostSpawn
	gostSpawn = func(binPath string, args []string) (frpProcess, error) {
		leakCounter++
		return &fakeFRPProcess{}, nil
	}
	origXSpawn := xraySpawn
	xraySpawn = func(binPath, cfgPath string) (frpProcess, error) {
		leakCounter++
		return &fakeFRPProcess{}, nil
	}
	origWst := wstSpawn
	wstSpawn = func(binPath string, args []string) (frpProcess, error) {
		leakCounter++
		return &fakeFRPProcess{}, nil
	}
	origCh := chiselSpawn
	chiselSpawn = func(binPath string, args []string) (frpProcess, error) {
		leakCounter++
		return &fakeFRPProcess{}, nil
	}
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) { return nil, nil }
	origStats := execCommandJSON
	execCommandJSON = func(apiPort int, prefix string) (uint64, uint64, bool) { return 1, 2, true }
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = "leak-test-key"
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "germany"}, true
	}
	origCfg := configDir
	configDir = t.TempDir()
	// Warm every binary cache the Start paths hit, with the marker set to
	// each params' OWN pinned sha (the drivers compare marker==pin before
	// trusting the cache). The fetch/verify chain has its own integration
	// coverage.
	warm := func(eng, ver, bin, sha string) {
		d := filepath.Join(configDir, "engines", eng, "bin", ver)
		_ = os.MkdirAll(d, 0o700)
		_ = os.WriteFile(filepath.Join(d, bin), []byte("#!/bin/sh\nexit 0\n"), 0o755)
		_ = os.WriteFile(filepath.Join(d, "artifact.sha256"), []byte(sha), 0o600)
	}
	frpP := frpTestParams()
	// NB: frpBinDir has NO "bin" segment (unlike the other engines).
	frpDir := filepath.Join(configDir, "engines", "frp", frpP.Version)
	_ = os.MkdirAll(frpDir, 0o700)
	_ = os.WriteFile(filepath.Join(frpDir, "frps"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	_ = os.WriteFile(filepath.Join(frpDir, "frpc"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	_ = os.WriteFile(filepath.Join(frpDir, "artifact.sha256"), []byte(frpP.SHA256Amd), 0o600)
	bhP := backhaulTestParams()
	warm("backhaul", bhP.Version, "backhaul", bhP.SHA256Amd)
	xrP := xrayTestParams()
	warm("xray", xrP.Version, "xray", xrP.SHA256Amd)
	rhP := ratholeTestParams()
	warm("rathole", rhP.Version, "rathole", rhP.SHA256Amd)
	gP := gostTestParams()
	warm("gost", gP.Version, "gost", gP.SHA256Amd)
	wstP := wstTestParams(strings.Repeat("aa", 32), strings.Repeat("bb", 32),
		strings.Repeat("QQ==", 22)[:88], strings.Repeat("QQ==", 22)[:88])
	warm("wstunnel", wstP.Version, "wstunnel", wstP.SHA256Amd)
	chP := chiselTestParams(strings.Repeat("aa", 32), strings.Repeat("bb", 32),
		strings.Repeat("QQ==", 22)[:88], strings.Repeat("QQ==", 22)[:88])
	warm("chisel", chP.Version, "chisel", chP.SHA256Amd)
	return func() {
		frpSpawn = origFRP
		ratholeSpawn = origRath
		gostSpawn = origGost
		xraySpawn = origXSpawn
		wstSpawn = origWst
		chiselSpawn = origCh
		frpIptables = origIpt
		execCommandJSON = origStats
		engineArtifactPubKeyB64 = origKey
		frpLoadIdentity = origIdent
		configDir = origCfg
	}
}
