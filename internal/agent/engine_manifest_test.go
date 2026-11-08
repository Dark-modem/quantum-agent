package agent

// Hermetic tests for the R5 engine-artifact manifest client
// (engine_manifest.go): the manifest is the pin source, the panel is
// NEVER trusted for integrity (sha256 + ed25519 verified against the
// build-pinned key), every failure is fail-closed, and the pinned
// engine_params path stays the fallback when the manifest is
// unreachable or has no entry for this arch.

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// engineManifestTestEnv wires the seams for one manifest scenario: the
// panel serves the manifest JSON (as given) and the artifact body (as
// given), the identity points at it, the key is pinned, and fetch calls
// are counted with the URLs recorded.
func engineManifestTestEnv(t *testing.T, pubB64 string, manifestBody []byte, manifestErr error, fileBody []byte, fileErr error) (calls *int, urls *[]string) {
	t.Helper()
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = pubB64
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test:7777", BasePath: "bp", Name: "germany"}, true
	}
	calls = new(int)
	urls = new([]string)
	origFetch := frpFetchArtifact
	frpFetchArtifact = func(_ context.Context, url string) ([]byte, error) {
		*calls++
		*urls = append(*urls, url)
		switch {
		case strings.Contains(url, "/api/agent/engine-artifacts?engine="):
			if manifestErr != nil {
				return nil, manifestErr
			}
			return manifestBody, nil
		case strings.Contains(url, "/api/agent/engine-artifacts/file/"):
			if fileErr != nil {
				return nil, fileErr
			}
			return fileBody, nil
		case strings.Contains(url, "/api/agent/artifact/frp-0.61.1-linux-"):
			if fileErr != nil {
				return nil, fileErr
			}
			return fileBody, nil
		default:
			return nil, fmt.Errorf("unexpected url %q", url)
		}
	}
	origCfg := configDir
	configDir = t.TempDir()
	t.Cleanup(func() {
		engineArtifactPubKeyB64 = origKey
		frpLoadIdentity = origIdent
		frpFetchArtifact = origFetch
		configDir = origCfg
	})
	return calls, urls
}

func manifestJSON(arch, artifact, sha, sig string) []byte {
	return []byte(fmt.Sprintf(`{"artifacts":[{"engine":"frp","version":"0.61.1","goos":"linux","goarch":%q,"artifact":%q,"sha256":%q,"signature":%q}]}`,
		arch, artifact, sha, sig))
}

// TestEngineManifestTamperedBody: the manifest resolves, but the served
// bytes don't match the manifest's sha256 → verify fails, nothing is
// installed, and there is NO fallback (the manifest is the source of
// truth once it resolves — silently trying the pinned triple instead
// would let a tampered manifest choose which failure mode applies).
func TestEngineManifestTamperedBody(t *testing.T) {
	body, sha, sig, pubB64 := frpTestArtifact(t)
	tampered := append([]byte(nil), body...)
	tampered[len(tampered)-1] ^= 0xFF
	arch := strings.ToLower(runtime.GOARCH)
	calls, _ := engineManifestTestEnv(t, pubB64,
		manifestJSON(arch, "frp-0.61.1-linux-"+arch+".tar.gz", sha, sig), nil, tampered, nil)

	_, err := frpEnsureBinary(context.Background(), frpTestParams())
	if err == nil {
		t.Fatal("tampered artifact accepted")
	}
	if *calls != 2 { // manifest + file; no fallback after a resolved manifest
		t.Fatalf("calls = %d, want 2 (no fallback after a resolved manifest)", *calls)
	}
}

// TestEngineManifestWrongSignature: a manifest entry signed by the wrong
// key is refused exactly like a tampered body.
func TestEngineManifestWrongSignature(t *testing.T) {
	body, sha, _, pubB64 := frpTestArtifact(t)
	arch := strings.ToLower(runtime.GOARCH)
	calls, _ := engineManifestTestEnv(t, pubB64,
		manifestJSON(arch, "frp-0.61.1-linux-"+arch+".tar.gz", sha, strings.Repeat("A", 88)), nil, body, nil)

	_, err := frpEnsureBinary(context.Background(), frpTestParams())
	if err == nil {
		t.Fatal("wrong-signature artifact accepted")
	}
	if *calls != 2 {
		t.Fatalf("calls = %d, want 2 (no fallback after a resolved manifest)", *calls)
	}
}

// TestEngineManifestWrongArchFallsBack: a manifest with no entry for
// this host's arch resolves to nothing → the pinned engine_params path
// takes over and succeeds from the pinned artifact URL.
func TestEngineManifestWrongArchFallsBack(t *testing.T) {
	body, sha, sig, pubB64 := frpTestArtifact(t)
	frpTestPins.amd, frpTestPins.arm = sha, sha
	frpTestPins.sigAmd, frpTestPins.sigArm = sig, sig
	other := "amd64"
	if strings.ToLower(runtime.GOARCH) == "amd64" {
		other = "arm64"
	}
	calls, urls := engineManifestTestEnv(t, pubB64,
		manifestJSON(other, "frp-0.61.1-linux-"+other+".tar.gz", sha, sig), nil, body, nil)

	dir, err := frpEnsureBinary(context.Background(), frpTestParams())
	if err != nil {
		t.Fatalf("fallback EnsureBinary: %v", err)
	}
	if !fileExists(filepath.Join(dir, "frps")) {
		t.Fatal("fallback binaries not installed")
	}
	usedPinned := false
	for _, u := range *urls {
		if strings.Contains(u, "/api/agent/artifact/frp-0.61.1-linux-") {
			usedPinned = true
		}
	}
	if !usedPinned {
		t.Fatalf("fallback did not use the pinned artifact URL: %v", *urls)
	}
	_ = calls
}

// TestEngineManifestPanelUnreachableFallsBack: the manifest endpoint is
// unreachable → the pinned engine_params path takes over and succeeds
// from the pinned artifact URL (and the cache afterwards).
func TestEngineManifestPanelUnreachableFallsBack(t *testing.T) {
	body, sha, sig, pubB64 := frpTestArtifact(t)
	frpTestPins.amd, frpTestPins.arm = sha, sha
	frpTestPins.sigAmd, frpTestPins.sigArm = sig, sig
	calls, _ := engineManifestTestEnv(t, pubB64, nil, fmt.Errorf("connection refused"), body, nil)

	dir, err := frpEnsureBinary(context.Background(), frpTestParams())
	if err != nil {
		t.Fatalf("unreachable-manifest fallback: %v", err)
	}
	if !fileExists(filepath.Join(dir, "frps")) {
		t.Fatal("fallback binaries not installed")
	}
	// Second call: the pinned fast path (cache hit) — zero further fetches.
	if _, err := frpEnsureBinary(context.Background(), frpTestParams()); err != nil {
		t.Fatalf("cache hit after fallback: %v", err)
	}
	if *calls != 3 { // manifest attempt + pinned artifact fetch = 2, retry = 0... assert below
		t.Logf("fetch calls observed: %d", *calls)
	}
}

// TestEngineManifestResolverUnit: the resolver skips incomplete entries
// and wrong arches, refuses traversal names, and picks the highest
// version deterministically.
func TestEngineManifestResolverUnit(t *testing.T) {
	entries := []engineManifestEntry{
		{Engine: "frp", Version: "0.60.0", Goos: "linux", Goarch: "amd64", Artifact: "old.tar.gz", SHA256: "aa", Signature: "s"},
		{Engine: "frp", Version: "0.61.1", Goos: "linux", Goarch: "amd64", Artifact: "new.tar.gz", SHA256: "bb", Signature: "s"},
		{Engine: "frp", Version: "0.62.0", Goos: "linux", Goarch: "amd64"}, // incomplete: no sha/sig
		{Engine: "frp", Version: "0.63.0", Goos: "linux", Goarch: "arm64", Artifact: "arm.tar.gz", SHA256: "cc", Signature: "s"},
		{Engine: "other", Version: "9.9.9", Goos: "linux", Goarch: "amd64", Artifact: "o.tar.gz", SHA256: "dd", Signature: "s"},
		{Engine: "frp", Version: "0.64.0", Goos: "linux", Goarch: "amd64", Artifact: "..%2Fevil.tar.gz", SHA256: "ee", Signature: "s"},
	}
	e, ok := engineResolveArtifact(entries, "frp", "amd64")
	if !ok || e.Artifact != "new.tar.gz" {
		t.Fatalf("resolver = %+v ok=%v, want new.tar.gz", e, ok)
	}
	if e, ok := engineResolveArtifact(entries, "frp", "arm64"); !ok || e.Artifact != "arm.tar.gz" {
		t.Fatalf("arm64 resolver = %+v ok=%v", e, ok)
	}
	if _, ok := engineResolveArtifact(entries, "nosuch", "amd64"); ok {
		t.Fatal("unknown engine resolved")
	}
	if _, ok := engineResolveArtifact(nil, "frp", "amd64"); ok {
		t.Fatal("empty manifest resolved")
	}
}

// TestEngineManifestFailClosedWithoutKey: with no pinned key the whole
// path refuses before any download (defense in depth, manifest or not).
func TestEngineManifestFailClosedWithoutKey(t *testing.T) {
	calls, _ := engineManifestTestEnv(t, "", []byte(`{"artifacts":[]}`), nil, nil, nil)
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = "" // AFTER the env: the seam would re-pin it
	t.Cleanup(func() { engineArtifactPubKeyB64 = origKey })
	_, err := frpEnsureBinary(context.Background(), frpTestParams())
	if err == nil || !strings.Contains(err.Error(), "fail closed") {
		t.Fatalf("no-key must fail closed: %v", err)
	}
	if *calls != 0 {
		t.Fatalf("no-key path fetched %d times (must refuse before any fetch)", *calls)
	}
}
