package agent

// cli_diag.go — `quantum-agent diag --out FILE`: a REDACTED support
// bundle for the operator (phase 10, task 5). Everything sensitive is
// either omitted (private keys, tokens, enrollment identity values) or
// redacted to a SHA-256 prefix (so an operator can compare two machines'
// secrets WITHOUT seeing them). The bundle is written 0600.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// diagRedactValue redacts one secret string: sha256, first 12 hex chars.
func diagRedactValue(v string) string {
	if v == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(sum[:12])
}

// diagCmdOut runs a command and returns its output (or the error text),
// capped so one noisy command cannot bloat the bundle.
func diagCmdOut(name string, args ...string) string {
	out, err := runCmdTimeout(10*time.Second, name, args...)
	if err != nil {
		return "ERROR: " + err.Error()
	}
	s := strings.TrimSpace(string(out))
	if len(s) > 16<<10 {
		s = s[:16<<10] + "\n... (truncated)"
	}
	return s
}

// diagIdentityShape: the enrollment record with every secret VALUE
// redacted — only the field names and fingerprints survive.
func diagIdentityShape() map[string]any {
	var id agentIdentity
	b, err := os.ReadFile(agentIdentityPath())
	if err != nil {
		return map[string]any{"present": false}
	}
	if err := json.Unmarshal(b, &id); err != nil {
		return map[string]any{"present": false, "error": err.Error()}
	}
	return map[string]any{
		"present":     true,
		"id":          diagRedactValue(id.ID),
		"key":         diagRedactValue(id.Key),
		"server":      id.Server, // the panel URL is operationally needed (not a secret)
		"name":        id.Name,
		"tls_pin":     diagRedactValue(id.TLSPin),
		"enrolled_at": id.EnrolledAt,
	}
}

// diagConfigFiles: the names + SHA-256 prefix of every file in the
// agent state dir (contents NEVER included — the state dir holds
// private keys).
func diagConfigFiles() []map[string]any {
	out := []map[string]any{}
	_ = filepath.Walk(configDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			out = append(out, map[string]any{"path": path, "error": rerr.Error()})
			return nil
		}
		out = append(out, map[string]any{
			"path":   strings.TrimPrefix(path, configDir+"/"),
			"bytes":  info.Size(),
			"sha256": "sha256:" + hex.EncodeToString(sha256SumBytes(b)[:12]),
		})
		return nil
	})
	return out
}

func sha256SumBytes(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// diagUnitStates: the systemd states of the units the agent owns.
func diagUnitStates() map[string]string {
	out := map[string]string{}
	out["quantum-agent.service"] = diagCmdOut("systemctl", "is-active", "quantum-agent.service")
	for _, in := range matrixInstances() {
		out[in.unit()] = diagCmdOut("systemctl", "is-active", in.unit())
	}
	return out
}

// diagInterfaces: the interface list (name + state only).
func diagInterfaces() string {
	return diagCmdOut("ip", "-j", "-4", "addr")
}

// diagCollect builds the bundle's top-level map. The tunnels/balancer
// views come from the caller (the persisted balancer snapshot).
func diagCollect(tunnels []map[string]any, balancer []balTargetDiag, routeLocalnet bool) map[string]any {
	return map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"agent": map[string]any{
			"version": panelVersion,
			"goarch":  runtime.GOARCH,
			"goos":    runtime.GOOS,
		},
		"identity_shape": diagIdentityShape(),
		"units":          diagUnitStates(),
		"interfaces":     diagInterfaces(),
		"nft":            diagCmdOut("nft", "-a", "list", "table", "ip", "quantum-fwd"),
		"iptables":       diagCmdOut("iptables-save", "-c"),
		"time_sync":      diagCmdOut("timedatectl", "show", "--property=NTPSynchronized"),
		// "net": dynamic network knobs the agent owns (phase14). The
		// balancer flips route_localnet while any enforced forward DNATs
		// to a loopback target (RUNBOOK ITEM 35).
		"net":          map[string]any{"route_localnet": routeLocalnet},
		"config_files": diagConfigFiles(),
		"tunnels":      tunnels,
		"balancer":     balancer,
	}
}

// cliDiag implements `quantum-agent diag --out FILE`.
func cliDiag(args []string) int {
	out := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--out" || args[i] == "-o" {
			if i+1 < len(args) {
				i++
				out = args[i]
			}
		}
	}
	if out == "" {
		fmt.Fprintln(os.Stderr, "usage: quantum-agent diag --out FILE")
		return 2
	}
	if v := os.Getenv("GRE_PANEL_DIR"); v != "" {
		configDir = v
	}
	// The balancer view comes from the persisted snapshot (the running
	// agent wrote it); a cold agent produces what it can. The snapshot
	// also carries the tunnel summaries and the route_localnet state.
	balancer := []balTargetDiag{}
	var tunnels []map[string]any
	routeLocalnet := false
	if b, err := os.ReadFile(balancerStatusPath()); err == nil {
		var rep balTickReport
		if json.Unmarshal(b, &rep) == nil {
			balancer = rep.Targets
			tunnels = rep.Tunnels
			routeLocalnet = rep.RouteLocalnet
		}
	}
	bundle := diagCollect(tunnels, balancer, routeLocalnet)
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "diag: render:", err)
		return 1
	}
	if err := os.WriteFile(out, data, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "diag: write:", err)
		return 1
	}
	fmt.Printf("diag bundle written: %s (%d bytes, 0600)\n", out, len(data))
	return 0
}
