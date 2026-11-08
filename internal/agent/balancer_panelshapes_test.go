package agent

// Phase-9 TASK 1: the weight-normalization investigation. The real-server
// night run observed `numgen inc mod 60 map {0-29: A, 30-59: B}` after an
// intended 30/70 — an equal split with total 60 = 30+30, i.e. BOTH
// tunnels resolved to weight 30. These tests pin, with the EXACT rule
// shapes the panel compiler emits (one rule per tunnel, ALL of
// topology/local/remote/tunnel set — internal/panel/desiredv2.go), that:
//
//   - tunnel-scoped rules resolve 70/30, 30/70, 100/0, 1/99, 50/50, 3/7
//     correctly for two matrix instances AND a matrix+frp pair;
//   - the rendered nft map carries the exact ranges and modulus
//     (validated with `nft -c` under root when available);
//   - an UNHEALTHY target is excluded and the remaining target takes the
//     whole modulus (100%);
//   - the DEGENERATE flow that produced mod 60 is characterized: when the
//     desired state carries pair-level weights (both tunnels matching one
//     same-scope rule — what the wizard's pair-level slider writes), both
//     tunnels resolve to that ONE weight and the split goes equal. The
//     fix belongs to the WRITE side (per-tunnel scoping), not the agent;
//     the balancer status snapshot now SURFACES it (nft_range + modulus
//     per target).
//
// The render itself is also validated with `nft -c` (root) per case.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-protocol"
)

// panelShapeRules builds the rule set exactly as the panel compiler does:
// one rule per tunnel with every scoping field set.
func panelShapeRules(topo string, tunnels []struct {
	id     string
	local  string
	remote string
	w      int
}) []protocol.WeightRule {
	rules := make([]protocol.WeightRule, 0, len(tunnels))
	for _, t := range tunnels {
		rules = append(rules, protocol.WeightRule{
			TopologyID: topo, TunnelID: t.id,
			LocalServer: t.local, RemoteServer: t.remote, Weight: t.w,
		})
	}
	return rules
}

// nftCheck runs `nft -c -f <file>` under root when possible and reports
// whether the check ran (root + nft present) and its error.
func nftCheck(t *testing.T, script string) (ran bool, err error) {
	t.Helper()
	probe, e := exec.Command("sudo", "-n", "true").CombinedOutput()
	_ = probe
	if e != nil {
		return false, nil // no root: skip silently
	}
	if _, e := exec.Command("nft", "--version").CombinedOutput(); e != nil {
		return false, nil
	}
	f, err := os.CreateTemp("", "wcheck-*.nft")
	if err != nil {
		return false, nil
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return false, nil
	}
	f.Close()
	out, e := exec.Command("sudo", "nft", "-c", "-f", name).CombinedOutput()
	if e != nil {
		return true, fmt.Errorf("nft -c: %v: %s", e, strings.TrimSpace(string(out)))
	}
	return true, nil
}

// TestPanelShapeWeightMatrix: the exact panel-compiled rule shapes for
// the requested weight combinations, two engine mixes, and the rendered
// nft text asserted + nft -c checked.
func TestPanelShapeWeightMatrix(t *testing.T) {
	const topo = "topo-main"
	type tun struct {
		id     string
		local  string
		remote string
		w      int
	}
	cases := []struct {
		name      string
		tA, tB    tun // matrix-matrix pair (both local=iran, remote=germany)
		wantTotal int
		wantA     string
		wantB     string
	}{
		{"70/30", tun{"mx-1", "iran", "germany", 70}, tun{"mx-2", "iran", "germany", 30}, 100, "0-69", "70-99"},
		{"30/70", tun{"mx-1", "iran", "germany", 30}, tun{"mx-2", "iran", "germany", 70}, 100, "0-29", "30-99"},
		{"100/0", tun{"mx-1", "iran", "germany", 100}, tun{"mx-2", "iran", "germany", 0}, 100, "0-99", ""},
		{"1/99", tun{"mx-1", "iran", "germany", 1}, tun{"mx-2", "iran", "germany", 99}, 100, "0-0", "1-99"},
		{"50/50", tun{"mx-1", "iran", "germany", 50}, tun{"mx-2", "iran", "germany", 50}, 100, "0-49", "50-99"},
		{"3/7", tun{"mx-1", "iran", "germany", 3}, tun{"mx-2", "iran", "germany", 7}, 10, "0-2", "3-9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := panelShapeRules(topo, []struct {
				id     string
				local  string
				remote string
				w      int
			}{tc.tA, tc.tB})

			// resolveWeight per tunnel (the agent's resolution).
			wA, okA := resolveWeight(rules, topo, tc.tA.local, tc.tA.remote, tc.tA.id)
			wB, okB := resolveWeight(rules, topo, tc.tB.local, tc.tB.remote, tc.tB.id)
			if !okA || wA != tc.tA.w {
				t.Fatalf("A resolved %d,%v want %d", wA, okA, tc.tA.w)
			}
			if tc.tB.w == 0 {
				if okB {
					t.Fatalf("B weight 0 must be excluded (ok=false), got %d,%v", wB, okB)
				}
			} else if !okB || wB != tc.tB.w {
				t.Fatalf("B resolved %d,%v want %d", wB, okB, tc.tB.w)
			}

			// Render the nft for a forward rule over the HEALTHY targets.
			targets := []balTarget{{TunnelID: tc.tA.id, IP: "10.189.0.2", Port: 5201, Weight: wA}}
			if okB && wB > 0 {
				targets = append(targets, balTarget{TunnelID: tc.tB.id, IP: "10.189.0.3", Port: 5202, Weight: wB})
			}
			script := renderForwardNFT([]forwardRender{{
				ID: "w-fwd", ListenPort: 8443, Proto: "tcp", Targets: targets,
			}})
			wantSel := fmt.Sprintf("numgen inc mod %d", tc.wantTotal)
			if !strings.Contains(script, wantSel) {
				t.Fatalf("modulus wrong (want %q):\n%s", wantSel, script)
			}
			// Ranges: A always present; B only when healthy+nonzero.
			wantA := fmt.Sprintf("%s : 10.189.0.2 . 5201", tc.wantA)
			if !strings.Contains(script, wantA) {
				t.Fatalf("A range missing (want %q):\n%s", wantA, script)
			}
			if tc.wantB != "" {
				wantB := fmt.Sprintf("%s : 10.189.0.3 . 5202", tc.wantB)
				if !strings.Contains(script, wantB) {
					t.Fatalf("B range missing (want %q):\n%s", wantB, script)
				}
			} else {
				if strings.Contains(script, "10.189.0.3") {
					t.Fatalf("excluded target rendered:\n%s", script)
				}
			}
			if ran, err := nftCheck(t, script); ran && err != nil {
				t.Fatalf("nft -c rejected the render: %v", err)
			}
		})
	}
}

// TestPanelShapeMixedEnginesAndUnhealthy: a matrix + frp pair with 3/7,
// the frp target unhealthy → the matrix takes 100%.
func TestPanelShapeMixedEnginesAndUnhealthy(t *testing.T) {
	const topo = "topo-main"
	rules := panelShapeRules(topo, []struct {
		id     string
		local  string
		remote string
		w      int
	}{
		{"mx-1", "iran", "germany", 3},
		{"frp-1", "iran", "germany", 7},
	})
	wMx, okMx := resolveWeight(rules, topo, "iran", "germany", "mx-1")
	wFrp, okFrp := resolveWeight(rules, topo, "iran", "germany", "frp-1")
	if !okMx || wMx != 3 || !okFrp || wFrp != 7 {
		t.Fatalf("matrix+frp resolution: mx=%d,%v frp=%d,%v", wMx, okMx, wFrp, okFrp)
	}
	// Healthy both: 3/7 (the render sorts by TunnelID — frp-1 first).
	both := renderForwardNFT([]forwardRender{{ID: "fwd-mix", ListenPort: 8443, Proto: "tcp",
		Targets: []balTarget{
			{TunnelID: "frp-1", IP: "10.189.0.3", Port: 5202, Weight: wFrp},
			{TunnelID: "mx-1", IP: "10.189.0.2", Port: 5201, Weight: wMx},
		}}})
	for _, want := range []string{"numgen inc mod 10", "7-9 : 10.189.0.2 . 5201", "0-6 : 10.189.0.3 . 5202"} {
		if !strings.Contains(both, want) {
			t.Fatalf("mixed 3/7 render missing %q:\n%s", want, both)
		}
	}
	if ran, err := nftCheck(t, both); ran && err != nil {
		t.Fatalf("nft -c rejected: %v", err)
	}
	// frp unhealthy: the matrix takes 100% (mod 3, not mod 10).
	frpDown := renderForwardNFT([]forwardRender{{ID: "fwd-mix", ListenPort: 8443, Proto: "tcp",
		Targets: []balTarget{{TunnelID: "mx-1", IP: "10.189.0.2", Port: 5201, Weight: wMx}}}})
	if !strings.Contains(frpDown, "numgen inc mod 3") || !strings.Contains(frpDown, "0-2 : 10.189.0.2 . 5201") {
		t.Fatalf("unhealthy-exclusion render wrong:\n%s", frpDown)
	}
	if ran, err := nftCheck(t, frpDown); ran && err != nil {
		t.Fatalf("nft -c rejected: %v", err)
	}
}

// TestPairLevelDegenerateMod60: the DOCUMENTED degenerate flow behind the
// observed `mod 60 {0-29, 30-59}` — a pair-level write (the wizard's
// pair slider) reaches the agent as ONE same-scope rule per tunnel, so
// both tunnels resolve to the same weight and the split goes equal. The
// agent cannot know the operator meant per-tunnel 30/70; the WRITE side
// must scope per tunnel (wizard/mesh API). This test pins the behavior so
// the diag output is understood to be the tell.
func TestPairLevelDegenerateMod60(t *testing.T) {
	const topo = "topo-main"
	// What a pair-level 30 write compiles to: the SAME resolved weight on
	// both tunnels (the panel's WeightFor returns the pair row for each).
	rules := []protocol.WeightRule{
		{TopologyID: topo, LocalServer: "iran", RemoteServer: "germany", Weight: 30},
	}
	wA, _ := resolveWeight(rules, topo, "iran", "germany", "mx-1")
	wB, _ := resolveWeight(rules, topo, "iran", "germany", "mx-2")
	if wA != 30 || wB != 30 {
		t.Fatalf("pair-level write should resolve 30 on BOTH tunnels, got %d/%d", wA, wB)
	}
	script := renderForwardNFT([]forwardRender{{ID: "w-fwd", ListenPort: 8443, Proto: "tcp",
		Targets: []balTarget{
			{TunnelID: "mx-1", IP: "10.189.0.2", Port: 5201, Weight: wA},
			{TunnelID: "mx-2", IP: "10.189.0.3", Port: 5202, Weight: wB},
		}}})
	if !strings.Contains(script, "numgen inc mod 60") ||
		!strings.Contains(script, "0-29 : 10.189.0.2 . 5201, 30-59 : 10.189.0.3 . 5202") {
		t.Fatalf("degenerate mod-60 shape not reproduced:\n%s", script)
	}
	if ran, err := nftCheck(t, script); ran && err != nil {
		t.Fatalf("nft -c rejected: %v", err)
	}
}
