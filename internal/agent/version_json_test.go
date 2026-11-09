package agent

// version_json_test.go — the release-integrity stamp (phase 14): the
// version --json output must carry the engine registry ids, and the
// stamp variables must be ldflags-addressable (build-release.sh asserts
// them against MANIFEST.json after every build).

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVersionJSONHasEngines(t *testing.T) {
	out := versionJSONString()
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("version --json is not valid JSON: %v", err)
	}
	engines, ok := v["engines"].([]any)
	if !ok || len(engines) == 0 {
		t.Fatalf("version --json has no engines list: %v", v["engines"])
	}
	ids := []string{}
	for _, e := range engines {
		ids = append(ids, e.(string))
	}
	for _, want := range []string{"matrix", "frp", "backhaul", "rathole", "gost", "xray", "wireguard", "wstunnel", "chisel"} {
		found := false
		for _, id := range ids {
			if id == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("registered engines missing %q: %v", want, ids)
		}
	}
	if !strings.Contains(out, `"version"`) || !strings.Contains(out, `"go_version"`) {
		t.Fatalf("version --json missing provenance fields")
	}
}

func TestVersionStampVarsAreAddressable(t *testing.T) {
	// build-release.sh sets these via -ldflags -X. If the variables are
	// renamed or moved the build's post-build verification fails on an
	// Iran server instead of at build time — keep this test as the tripwire.
	stamps := versionFlagStamps()
	if _, ok := stamps["sha"]; !ok {
		t.Fatal("sha stamp missing")
	}
	if _, ok := stamps["version"]; !ok {
		t.Fatal("version stamp missing")
	}
}
