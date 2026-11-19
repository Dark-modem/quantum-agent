//go:build integration

// nft_mixedgroup_integration_test.go — RUNBOOK ITEM 36 acceptance: the
// mixed port-less + ported group render (and the loopback DNAT shape the
// route_localnet work emits) must be accepted by `nft -c` — check mode
// asks the KERNEL to validate the transaction, so a syntax the parser
// alone would miss fails here. Fully OFFLINE: no network is touched, the
// ruleset is only checked, never applied.
//
// Gating: build tag `integration` keeps it out of the default suite; at
// run time it needs the nft binary AND root (netlink validation needs
// CAP_NET_ADMIN — same probe as balancer_panelshapes_test's nftCheck),
// and honors OFFLINE=0 as an explicit opt-out.
//
// UNVERIFIED in this pass: the KERNEL forwarding test (two net.Listen
// sinks as ported targets + a port-less stub target, byte counts matching
// the 30/70 weights through the DNAT in a network namespace). The nft -c
// check plus the hermetic renderer tests (TestMixedGroupPortlessTargets,
// TestBalancerPortlessTargetMirror) are the requirement carried here.

package agent

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestNFTMixedGroupRender(t *testing.T) {
	if v := os.Getenv("OFFLINE"); v == "0" {
		t.Skip("OFFLINE=0: explicitly opted out")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not available on this host")
	}
	if out, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
		t.Skipf("root (sudo -n) unavailable for nft -c netlink validation: %s", strings.TrimSpace(string(out)))
	}

	// 1. The mixed group: matrix-shaped port-less target (falls back to
	//    the rule's target_port) + a ported target with its own port.
	// 2. The pure port-less group: address-only map.
	// 3. A loopback DNAT (route_localnet shape).
	script := RenderForwardNFT([]ForwardRender{
		{ID: "fw-mixed", ListenPort: 8443, Proto: "both", TargetPort: 443, Targets: []BalTarget{
			{TunnelID: "frp-1", IP: "10.189.0.3", Port: 5201, Weight: 7},
			{TunnelID: "mx-1", IP: "10.189.0.2", Port: 0, Weight: 3},
		}},
		{ID: "fw-matrix", ListenPort: 8444, Proto: "tcp", Targets: []BalTarget{
			{TunnelID: "mx-2", IP: "10.189.0.4", Port: 0, Weight: 1},
		}},
		{ID: "fw-loopback", ListenPort: 18443, Proto: "tcp", TargetPort: 18080, Targets: []BalTarget{
			{TunnelID: "static:fw-loopback", IP: "127.0.0.1", Port: 18080, Weight: 1},
		}},
	})
	for _, want := range []string{
		"0-6 : 10.189.0.3 . 5201",
		"7-9 : 10.189.0.2 . 443",
		"numgen inc mod 1 map { 0-0 : 10.189.0.4 }",
		"dnat to numgen inc mod 1 map { 0-0 : 127.0.0.1 } : 18080",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("render lacks %q:\n%s", want, script)
		}
	}

	f, err := os.CreateTemp("", "quantum-fwd-mixed-*.nft")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("sudo", "nft", "-c", "-f", name).CombinedOutput()
	if err != nil {
		t.Fatalf("nft -c rejected the mixed-group render: %v: %s\nscript:\n%s", err, strings.TrimSpace(string(out)), script)
	}
	t.Logf("nft -c accepted the mixed-group render (%d bytes)", len(script))
}
