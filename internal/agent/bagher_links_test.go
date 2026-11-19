package agent

import (
	"testing"
)

// §6.A3 removed the interactive Bagher link layer (add/remove links, the
// legacy /api/sshfwd handlers and the unit migrations); the tests that drove
// those entry points went with them. TestBagherLinkUp covers the surviving
// view helper.

func TestBagherLinkUp(t *testing.T) {
	online := map[string]bool{"p443": true, "p2053": false, "u2053": true}
	if !bagherLinkUp(online, []int{80, 443}) || bagherLinkUp(online, []int{2053}) {
		t.Fatal("a link is up when one of its TCP proxies is online")
	}
}
