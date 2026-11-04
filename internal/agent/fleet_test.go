package agent

import (
	"testing"
)

func mkLive(id int, gre, frp, ping bool, ms string) peerLive {
	return peerLive{peerRecord: peerRecord{ID: id, Name: "n"}, GreUp: gre, FrpUp: frp, PingOK: ping, PingMs: ms}
}

func TestParsePingMs(t *testing.T) {
	cases := map[string]float64{"12ms": 12, " 3.5ms ": 3.5, "": -1, "abc": -1, "-2ms": -1}
	for in, want := range cases {
		if got := parsePingMs(in); got != want {
			t.Errorf("parsePingMs(%q)=%v want %v", in, got, want)
		}
	}
}

func TestFleetHealthLevels(t *testing.T) {
	if fleetHealth(mkLive(1, true, true, true, "5ms")) != fleetOK {
		t.Fatal("all up must be OK")
	}
	if fleetHealth(mkLive(1, true, false, false, "")) != fleetDeg {
		t.Fatal("one leg must be degraded")
	}
	if fleetHealth(mkLive(1, true, true, false, "")) != fleetDeg {
		t.Fatal("legs up but no ping must be degraded")
	}
	if fleetHealth(mkLive(1, false, false, false, "")) != fleetDown {
		t.Fatal("nothing up must be down")
	}
}
