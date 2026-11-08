package agent

// frp_artifact.go — engine binary delivery for the FRP driver: the agent
// fetches the pinned frp artifact from the CONTROLLER's artifact endpoint
// (GET <controller>/<base>/api/agent/artifact/<name>), never from GitHub —
// Iran servers must not need outbound GitHub access. Integrity is
// fail-closed end to end:
//
//  1. the desired state pins artifact name + sha256 + ed25519 signature;
//  2. engine.VerifyArtifact checks both, against a build-time pinned key
//     (engineArtifactPubKeyB64 — empty by default: refuse everything);
//  3. the cache is keyed by version and only trusted after verification.
//
// The production contract for the panel side (a manifest endpoint so
// desired state does not carry the signature) is requested in
// 00-ADMIN/PROTOCOL-REQUESTS.md R5; until then the pins ride engine_params.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// engineArtifactPubKeyB64 is the pinned ed25519 public key (single-line
// base64 DER SPKI, same format as update-pub.b64) used to verify engine
// artifacts. Empty by default: builds without a pinned key refuse every
// artifact (fail closed). Release builds inject it via
// -ldflags "-X github.com/Dark-modem/quantum-agent/internal/agent.engineArtifactPubKeyB64=...".
var engineArtifactPubKeyB64 string

// frpArtifactNameRe mirrors the panel's artifact-name validation
// (agent_update_ctrl.go): one path segment, no traversal.
var frpArtifactNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,128}$`)

func frpArtifactNameOK(name string) bool { return frpArtifactNameRe.MatchString(name) }

// frpLoadIdentity is seam-able so tests never touch agent.json.
var frpLoadIdentity = agentLoadIdentity

// frpFetchArtifact downloads an artifact body (seam: tests serve it locally).
var frpFetchArtifact = func(ctx context.Context, url string) ([]byte, error) {
	c := &http.Client{Timeout: 120 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("frp: artifact request: %w", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("frp: artifact fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("frp: artifact fetch: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, fmt.Errorf("frp: artifact read: %w", err)
	}
	return body, nil
}

// frpArtifactBaseURL returns the controller's API base (server URL plus
// the enrollment base path) — shared by the pinned-artifact URL and the
// R5 manifest URLs.
func frpArtifactBaseURL(ident agentIdentity) string {
	base := strings.TrimRight(strings.TrimSpace(ident.Server), "/")
	if bp := strings.Trim(ident.BasePath, "/"); bp != "" {
		if !strings.HasSuffix(strings.ToLower(base), "/"+strings.ToLower(bp)) {
			base += "/" + bp
		}
	}
	return base
}

// frpArtifactURL builds the controller artifact URL from the enrollment
// identity (same base-path rules as the WS URL builder).
func frpArtifactURL(ident agentIdentity, name string) string {
	return frpArtifactBaseURL(ident) + "/api/agent/artifact/" + url.PathEscape(name)
}

// frpCacheHit reports whether dir holds a verified extraction of the
// artifact with the given sha256 (the 0600 marker written after verify).
func frpCacheHit(dir, sha256Hex string) bool {
	return engineCacheHit(dir, sha256Hex, []string{"frps", "frpc"})
}

// frpEnsureBinary makes the frp binaries available and returns the cache
// directory. The pin comes from the panel's R5 engine-artifact manifest
// (engine name only in desired state) with the pinned engine_params
// triple (name+sha256+signature) as the fallback; EITHER way the body is
// verified sha256+ed25519 against the build-pinned key before extraction
// — the panel is never trusted for integrity. Idempotent: a verified
// cache for the same sha256 is reused without downloading.
func frpEnsureBinary(ctx context.Context, p frpParams) (string, error) {
	// Defense in depth: a build without a pinned key refuses the engine
	// entirely, even on a cache hit — only verified downloads may ever
	// populate the cache, and only builds that can verify may serve it.
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("frp: no engine artifact signing key pinned in this build (fail closed)")
	}
	// Fast path: the desired state pinned a triple and the cache already
	// matches it — no network traffic at all.
	if _, pinnedSHA, _, pinErr := p.frpArtifactPin(); pinErr == nil && frpCacheHit(frpBinDir(p.Version), pinnedSHA) {
		return frpBinDir(p.Version), nil
	}

	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("frp: no controller identity — cannot fetch engine artifact (fail closed)")
	}

	// Resolve the pin: the R5 manifest for this host's arch first, the
	// pinned engine_params triple as the fallback (an operator may ship
	// pins without uploading to the store, or the manifest may be
	// unreachable — both fall back, both verify before anything runs).
	name, sha256Hex, sigB64, viaManifest, err := engineArtifactPin(ctx, ident, "frp",
		func() (string, string, string, error) { return p.frpArtifactPin() })
	if err != nil {
		return "", err
	}
	downloadURL := frpArtifactURL(ident, name)
	if viaManifest {
		downloadURL = engineManifestFileURL(ident, name)
	}

	dir := frpBinDir(p.Version)
	if frpCacheHit(dir, sha256Hex) {
		return dir, nil // the manifest pointed at an artifact already cached
	}

	body, err := frpFetchArtifact(ctx, downloadURL)
	if err != nil {
		return "", err
	}
	if err := engine.VerifyArtifact(body, sha256Hex, sigB64, key); err != nil {
		return "", err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("frp: cache dir: %w", err)
	}
	if err := frpExtract(body, dir); err != nil {
		return "", err
	}
	if err := engineWriteCacheMarker(dir, sha256Hex); err != nil {
		return "", fmt.Errorf("frp: cache marker: %w", err)
	}
	return dir, nil
}

// frpExtract unpacks a frp release tar.gz: only regular files whose base
// name is frps/frpc are installed (0755); links and anything else are
// refused — the artifact is pinned by hash, but extraction stays strict.
// Delegates to the shared engineExtractTarball (same semantics; errors
// keep the frp prefix).
func frpExtract(body []byte, dir string) error {
	if err := engineExtractTarball(body, dir, map[string]bool{"frps": true, "frpc": true}); err != nil {
		return fmt.Errorf("frp: %w", err)
	}
	return nil
}
