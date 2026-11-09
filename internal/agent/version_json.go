package agent

// version_json.go — `quantum-agent version --json`: the release-integrity
// stamp (phase 14). The release build pins ALL of these via -ldflags:
//   -X ...internal/agent.panelVersion=<ver>
//   -X ...internal/agent.buildSHA=<commit sha>
//   -X ...internal/agent.buildTime=<RFC3339>
// (goVersion is runtime.Version(), engines is the live registry).
// build-release.sh asserts these values against MANIFEST.json after every
// build — a binary that cannot state its own provenance must never ship.

import (
	"encoding/json"
	"runtime"
)

// buildSHA / buildTime are set at release build time via -ldflags. Empty
// in dev builds.
var (
	buildSHA   string
	buildTime  string
	binaryName = "quantum-agent"
)

func agentRegistryIDs() []string {
	reg, err := AgentEngines()
	if err != nil || reg == nil {
		return []string{}
	}
	return reg.IDs()
}

type versionJSON struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	SHA       string   `json:"sha"`
	BuildTime string   `json:"build_time"`
	GoVersion string   `json:"go_version"`
	GOOS      string   `json:"goos"`
	GOARCH    string   `json:"goarch"`
	Engines   []string `json:"engines"`
}

func versionJSONString() string {
	v := versionJSON{
		Name:      binaryName,
		Version:   panelVersion,
		SHA:       buildSHA,
		BuildTime: buildTime,
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Engines:   agentRegistryIDs(),
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		// never fails in practice; fall back to the flat version
		return panelVersion
	}
	return string(b)
}

// versionFlagStamps mirrors build-release.sh's post-build assertions so a
// drift between the builder and the binary is caught in tests, not on an
// Iran server.
func versionFlagStamps() map[string]string {
	return map[string]string{
		"version":   panelVersion,
		"sha":       buildSHA,
		"buildTime": buildTime,
	}
}
