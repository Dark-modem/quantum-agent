package agent

// CLI bootstrap for one-shot agent commands, adapted from the controller
// monolith (tls_cli.go cliStart, main.go cfgPath/loadOrInit) with the
// agent-only policy from netcli.go: no panel.json requirement and never
// creating one — read-only commands must work on an un-enrolled box.

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
)

// cliMode marks a one-shot command (no listeners); netcli.go sets it too.
var cliMode bool

// cliStart prepares a one-shot agent command. Unlike the controller
// version it does not refuse when panel.json is missing (agent-only
// endpoints are legitimate) and never creates configuration.
func cliStart() bool {
	if v := os.Getenv("GRE_PANEL_DIR"); v != "" {
		configDir = v
	}
	cliMode = true
	log.SetOutput(io.Discard)
	loadOrInit()
	return true
}

// cfgPath is the controller config file location (kept for install-shape
// detection: netops_api.go distinguishes controller vs agent endpoints).
func cfgPath() string { return filepath.Join(configDir, "panel.json") }

// loadOrInit reads the controller config when present; on an agent-only
// endpoint it is a no-op (the monolith's version would create a default
// panel.json, which Session 6's QA explicitly flagged as wrong here).
func loadOrInit() {
	data, err := os.ReadFile(cfgPath())
	if err != nil {
		return
	}
	var c panelConfig
	if json.Unmarshal(data, &c) == nil {
		cfg = c
	}
}

// Fleet status enum (ported from the monolith fleet.go).
const (
	fleetDown = 0
	fleetDeg  = 1
	fleetOK   = 2
)

// round1 rounds to one decimal (ported verbatim from the monolith fleet.go).
func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }
