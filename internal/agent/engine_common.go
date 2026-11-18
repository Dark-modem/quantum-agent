package agent

// engine_common.go — production-shape helpers for the engine drivers
// (originally Phase 6). These implement the PRODUCTION CHECKLIST items
// from 00-ADMIN/ENGINE-GUIDE.md as seam-able functions so every driver
// gets the FRP/Backhaul lessons for free.
//
// History note (REFACTOR-A1): this file's original header said the FRP
// and Backhaul drivers still carried their own copies of these helpers
// and that new engines only should use them. That debt was paid down in
// two waves: frp/backhaul first delegated their supervise loops here,
// and stage A1 (2026-11-18) moved the remaining per-driver boilerplate —
// the runs table, per-instance stop/proc/cfg state, and the
// Stop/Reload/Uninstall/params-equal/port-of shapes — into
// driver_core.go, converting every process driver onto it (wg keeps its
// live-reload semantics; matrix is stateless by design).

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// engineSide is one end of a two-ended tunnel engine.
type engineSide string

const (
	engineSideServer engineSide = "server" // hosts the public/listening end
	engineSideClient engineSide = "client" // dials OUT (Iran-friendly)
)

// EnginePin is one engine artifact's verification coordinates for one
// GOARCH. A tunnel row reaches both arches; each end verifies only its
// own artifact. The manifest path makes these optional — desired state
// may carry the engine name only.
type EnginePin struct {
	Version   string
	Artifact  string // name TEMPLATE containing {arch}
	SHA256Amd string
	SHA256Arm string
	SigAmd    string
	SigArm    string
}

// enginePinForArch resolves the pinned coordinates for the running
// GOARCH (the FRP/Backhaul shape, shared).
func enginePinForArch(p EnginePin) (name, sha256Hex, sigB64 string, err error) {
	arch := strings.ToLower(runtime.GOARCH)
	if !strings.Contains(p.Artifact, "{arch}") {
		return "", "", "", fmt.Errorf("engine: artifact template must contain {arch}")
	}
	name = strings.ReplaceAll(p.Artifact, "{arch}", arch)
	switch arch {
	case "amd64":
		return name, p.SHA256Amd, p.SigAmd, nil
	case "arm64":
		return name, p.SHA256Arm, p.SigArm, nil
	}
	return "", "", "", fmt.Errorf("engine: no artifact pin for GOARCH %q", arch)
}

// enginePinOrManifest was the engineArtifactPin twin with an unused
// EnginePin parameter; A1 deleted it — callers use engineArtifactPin
// directly (byte-identical semantics).

// engineExtractTarball unpacks a release-style tar.gz into dir: only
// regular files whose base name is in want are installed (0755);
// directory entries (the release wraps binaries in a version directory)
// are skipped; duplicates, symlinks and other entry types are refused;
// per-entry size cap 256 MiB. Exact-shape twin of the FRP/Backhaul
// extractors.
func engineExtractTarball(body []byte, dir string, want map[string]bool) error {
	gz, err := gzip.NewReader(strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("engine: artifact is not gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("engine: artifact tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue // the release wraps binaries in a version directory
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("engine: artifact contains non-regular entry %q", hdr.Name)
		}
		if hdr.Size > 256<<20 {
			return fmt.Errorf("engine: artifact entry %q too large", hdr.Name)
		}
		base := filepath.Base(hdr.Name)
		if !want[base] {
			continue // docs, LICENSE, completions, …
		}
		if found[base] {
			return fmt.Errorf("engine: artifact has duplicate %q", base)
		}
		data, err := io.ReadAll(io.LimitReader(tr, 256<<20))
		if err != nil {
			return fmt.Errorf("engine: artifact read %q: %w", hdr.Name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, base), data, 0o755); err != nil {
			return fmt.Errorf("engine: install %q: %w", base, err)
		}
		found[base] = true
	}
	for b := range want {
		if !found[b] {
			return fmt.Errorf("engine: artifact missing %q", b)
		}
	}
	return nil
}

// engineCacheHit reports whether dir holds a verified extraction whose
// 0600 marker matches sha256Hex and whose wanted binaries all exist.
func engineCacheHit(dir, sha256Hex string, want []string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "artifact.sha256"))
	if err != nil || !strings.EqualFold(strings.TrimSpace(string(data)), sha256Hex) {
		return false
	}
	for _, f := range want {
		if !fileExists(filepath.Join(dir, f)) {
			return false
		}
	}
	return true
}

// engineWriteCacheMarker records the verified sha256 in dir (0600).
func engineWriteCacheMarker(dir, sha256Hex string) error {
	return os.WriteFile(filepath.Join(dir, "artifact.sha256"), []byte(sha256Hex), 0o600)
}

// engineSupervise keeps one instance's process alive until stop: an
// unexpected exit restarts with capped backoff (2s→15s). The caller's
// Stop MUST close stop before killing the process (a killed process is
// never resurrected); respawn uses the re-invocable procState accessor.
type engineProcState interface {
	current() frpProcess
	setProc(frpProcess)
}

func engineSupervise(stop <-chan struct{}, st engineProcState, binPath, cfgPath string, spawn func(string, string) (frpProcess, error)) {
	backoff := 2 * time.Second
	for {
		select {
		case <-stop:
			return
		case <-st.current().Done():
			select {
			case <-stop:
				return
			case <-time.After(backoff):
			}
			if backoff < 15*time.Second {
				backoff *= 2
			}
			if proc, err := spawn(binPath, cfgPath); err == nil {
				st.setProc(proc)
			}
		}
	}
}

// engineEngineDir returns the per-engine state dir under the agent
// config dir (bin cache + instance configs; removed by Uninstall).
func engineEngineDir(engineID string) string {
	return filepath.Join(configDir, "engines", engineID)
}

// engineVerifySecretShape guards TOML/JSON-injection for any secret that
// rides a rendered config: printable, no quotes/newlines/backslashes,
// bounded length.
func engineVerifySecretShape(kind, v string, minLen, maxLen int) error {
	if len(v) < minLen || len(v) > maxLen {
		return fmt.Errorf("%s: length must be %d-%d chars", kind, minLen, maxLen)
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\'' || c == '\\' {
			return fmt.Errorf("%s: illegal byte 0x%02x (printable ASCII, no quotes/backslash)", kind, c)
		}
	}
	return nil
}

// engineVerifyEngineUnknown is a compile-time anchor for the framework
// import (drivers embed engine.Counters/Health shapes in tests).
var _ = engine.ErrRestartRequired
