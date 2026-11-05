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
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

// frpArtifactURL builds the controller artifact URL from the enrollment
// identity (same base-path rules as the WS URL builder).
func frpArtifactURL(ident agentIdentity, name string) string {
	base := strings.TrimRight(strings.TrimSpace(ident.Server), "/")
	if bp := strings.Trim(ident.BasePath, "/"); bp != "" {
		if !strings.HasSuffix(strings.ToLower(base), "/"+strings.ToLower(bp)) {
			base += "/" + bp
		}
	}
	return base + "/api/agent/artifact/" + url.PathEscape(name)
}

// frpEnsureBinary makes the pinned frp binaries available and returns the
// cache directory. Idempotent: a verified cache for the same sha256 is
// reused without any network traffic.
func frpEnsureBinary(ctx context.Context, p frpParams) (string, error) {
	// Defense in depth: a build without a pinned key refuses the engine
	// entirely, even on a cache hit — only verified downloads may ever
	// populate the cache, and only builds that can verify may serve it.
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("frp: no engine artifact signing key pinned in this build (fail closed)")
	}
	name, sha256Hex, sigB64, err := p.frpArtifactPin()
	if err != nil {
		return "", err
	}
	dir := frpBinDir(p.Version)
	marker := filepath.Join(dir, "artifact.sha256")
	if data, err := os.ReadFile(marker); err == nil &&
		strings.EqualFold(strings.TrimSpace(string(data)), sha256Hex) &&
		fileExists(filepath.Join(dir, "frps")) && fileExists(filepath.Join(dir, "frpc")) {
		return dir, nil // cache hit
	}

	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("frp: no controller identity — cannot fetch engine artifact (fail closed)")
	}

	body, err := frpFetchArtifact(ctx, frpArtifactURL(ident, name))
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
	if err := os.WriteFile(marker, []byte(sha256Hex), 0o600); err != nil {
		return "", fmt.Errorf("frp: cache marker: %w", err)
	}
	return dir, nil
}

// frpExtract unpacks a frp release tar.gz: only regular files whose base
// name is frps/frpc are installed (0755); links and anything else are
// refused — the artifact is pinned by hash, but extraction stays strict.
func frpExtract(body []byte, dir string) error {
	gz, err := gzip.NewReader(strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("frp: artifact is not gzip: %w", err)
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
			return fmt.Errorf("frp: artifact tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("frp: artifact contains non-regular entry %q", hdr.Name)
		}
		if hdr.Size > 256<<20 {
			return fmt.Errorf("frp: artifact entry %q too large", hdr.Name)
		}
		base := filepath.Base(hdr.Name)
		if base != "frps" && base != "frpc" {
			continue // docs, LICENSE, …
		}
		if found[base] {
			return fmt.Errorf("frp: artifact has duplicate %q", base)
		}
		data, err := io.ReadAll(io.LimitReader(tr, 256<<20))
		if err != nil {
			return fmt.Errorf("frp: artifact read %q: %w", hdr.Name, err)
		}
		out := filepath.Join(dir, base)
		if err := os.WriteFile(out, data, 0o755); err != nil {
			return fmt.Errorf("frp: install %q: %w", base, err)
		}
		found[base] = true
	}
	if !found["frps"] || !found["frpc"] {
		return fmt.Errorf("frp: artifact missing frps/frpc binaries")
	}
	return nil
}
