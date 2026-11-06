package agent

// engine_manifest.go — the agent-side client for the panel's R5 engine
// artifact manifest (GET /api/agent/engine-artifacts?engine=&goarch= and
// /api/agent/engine-artifacts/file/{name}). The manifest lets desired
// state carry ONLY the engine name: the agent asks the manifest for its
// own arch, downloads, and self-verifies sha256 AND the ed25519
// signature against the build-pinned key — the panel is never trusted
// for integrity. Every failure here is fail-closed; the pinned
// engine_params path (name+sha256+signature in desired state) remains
// the fallback when the manifest is unreachable or has no entry.

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
)

// engineManifestEntry mirrors the panel's manifest item
// (internal/panel/engineartifacts.go handleEngineManifest).
type engineManifestEntry struct {
	Engine    string `json:"engine"`
	Version   string `json:"version"`
	Goos      string `json:"goos"`
	Goarch    string `json:"goarch"`
	Artifact  string `json:"artifact"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Signature string `json:"signature"`
}

// engineManifestURL builds the manifest URL from the enrollment identity
// (same base-path rules as frpArtifactURL).
func engineManifestURL(ident agentIdentity, engine, goarch string) string {
	return frpArtifactBaseURL(ident) + "/api/agent/engine-artifacts?engine=" +
		urlQueryEscape(engine) + "&goarch=" + urlQueryEscape(goarch)
}

// engineManifestFileURL builds the bytes URL for one artifact name.
func engineManifestFileURL(ident agentIdentity, name string) string {
	return frpArtifactBaseURL(ident) + "/api/agent/engine-artifacts/file/" + name
}

// urlQueryEscape escapes a query value without importing net/url twice
// in call sites (the manifest URLs are built from validated identifiers).
func urlQueryEscape(v string) string {
	var out strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~':
			out.WriteByte(c)
		default:
			fmt.Fprintf(&out, "%%%02X", c)
		}
	}
	return out.String()
}

// engineManifestGet fetches and parses the manifest for one engine+arch
// via the shared HTTP seam (frpFetchArtifact — same panel, same proxy
// rules, test-stubbed).
func engineManifestGet(ctx context.Context, ident agentIdentity, engine, goarch string) ([]engineManifestEntry, error) {
	if strings.TrimSpace(engine) == "" {
		return nil, fmt.Errorf("engine manifest: empty engine id")
	}
	arch := strings.TrimSpace(goarch)
	if arch == "" {
		arch = runtime.GOARCH
	}
	body, err := frpFetchArtifact(ctx, engineManifestURL(ident, engine, arch))
	if err != nil {
		return nil, fmt.Errorf("engine manifest: fetch: %w", err)
	}
	var parsed struct {
		Artifacts []engineManifestEntry `json:"artifacts"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("engine manifest: parse: %w", err)
	}
	return parsed.Artifacts, nil
}

// engineResolveArtifact picks the newest matching entry for this host's
// arch from the manifest and returns the (name, sha256, signature) pin
// triple. Refuses (ok=false) when the manifest has no entry for the
// engine+arch — the caller falls back to the pinned engine_params path.
func engineResolveArtifact(entries []engineManifestEntry, engine, goarch string) (engineManifestEntry, bool) {
	arch := strings.TrimSpace(goarch)
	if arch == "" {
		arch = runtime.GOARCH
	}
	var best engineManifestEntry
	found := false
	for _, e := range entries {
		if e.Engine != engine || e.Goarch != arch || strings.TrimSpace(e.Goos) == "" {
			continue
		}
		if strings.TrimSpace(e.Artifact) == "" || strings.TrimSpace(e.SHA256) == "" || strings.TrimSpace(e.Signature) == "" {
			continue // an incomplete entry can never verify — skip, never guess
		}
		if !frpArtifactNameOK(e.Artifact) {
			continue
		}
		if !found || e.Version > best.Version { // deterministic: highest version wins
			best, found = e, true
		}
	}
	return best, found
}

// engineArtifactPin resolves the artifact pin for one engine: the R5
// manifest first (desired state stays name-only), the pinned
// engine_params triple as the fallback. Either way the caller verifies
// sha256+ed25519 against the build-pinned key before anything runs.
// manifestOK reports which path produced the pin (for logs/tests).
func engineArtifactPin(ctx context.Context, ident agentIdentity, engine string,
	pinned func() (name, sha256Hex, sigB64 string, err error)) (name, sha256Hex, sigB64 string, manifestOK bool, err error) {
	if entries, merr := engineManifestGet(ctx, ident, engine, runtime.GOARCH); merr == nil {
		if e, ok := engineResolveArtifact(entries, engine, runtime.GOARCH); ok {
			return e.Artifact, e.SHA256, e.Signature, true, nil
		}
		// Manifest reachable but no entry for this engine/arch: fall back
		// to the pinned path (an operator may ship pins without uploading).
	}
	n, s, sig, perr := pinned()
	return n, s, sig, false, perr
}
