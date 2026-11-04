package agent

// Real-kernel benchmark (skipped unless root + nft are available): the
// per-tick cost of one balancer pass with a genuine nft -f apply.

import (
	"os"
	"testing"
	"time"
)

func TestBalTickBenchmarkRealNFT(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root + nft (run in the lab as root)")
	}
	h := newBalHarness(t)
	d := testForwardDesired(t)
	engs, tuns := toEngineSpecs(d.Engines, d.Tunnels)
	_ = h.mgr.Reconcile(testCtx(), engs, tuns)
	h.fake.SetForwardAddress("t1", "10.189.0.2", 8443)
	h.fake.SetForwardAddress("t2", "10.189.0.3", 8443)
	nftApplyScript = applyNFTScript // real kernel apply
	start := time.Now()
	rep := h.bal.tick()
	elapsed := time.Since(start)
	if len(rep.Errors) > 0 {
		t.Logf("apply errors (lab may lack the addresses): %v", rep.Errors)
	}
	t.Logf("tick with real nft apply: %v", elapsed)
	if elapsed > 2*time.Second {
		t.Fatalf("tick took %v — too slow for a 15s heartbeat cadence", elapsed)
	}
}
