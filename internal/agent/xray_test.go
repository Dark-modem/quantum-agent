package agent

import (
	"fmt"
	"testing"
)

// §6.A3 removed xray.go's legacy tunnel implementation (bundle make/parse/
// import, the apply/rollback engine, unit management, health prober, legacy
// handlers); the tests that drove those entry points went with them —
// xray_driver.go and its own tests cover the LIVE engine. The one surviving
// test covers xrayCarrierEnds, the QUANTUM_ACCT_* accounting leg.

func TestXrayCarrierEnds(t *testing.T) {
	withTempConfig(t)
	st := xrayState{NextID: 4, Links: []XrayLink{
		{ID: 1, Mode: xrayModeDirect, Side: xraySideIran, Remote: "198.51.100.7", TunnelPort: 443, Profile: XrayProfile{Transport: "raw"}},
		{ID: 2, Mode: xrayModeReverse, Side: xraySideIran, Remote: "", TunnelPort: 8443, Profile: XrayProfile{Transport: "xhttp"}},
		{ID: 3, Mode: xrayModeDirect, Side: xraySideForeign, Remote: "203.0.113.9", TunnelPort: 2083, Profile: XrayProfile{Transport: "kcp"}},
		{ID: 5, Mode: xrayModeDirect, Side: xraySideIran, Remote: "198.51.100.8", TunnelPort: 443, Disabled: true},
	}}
	if err := saveXrayState(st); err != nil {
		t.Fatal(err)
	}
	got := xrayCarrierEnds()
	want := []carrierEnd{
		{Port: 443, Remote: "198.51.100.7", Tag: "xray-1"},
		{Port: 8443, Tag: "xray-2"},
		{Port: 2083, From: "203.0.113.9", UDP: true, Tag: "xray-3"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("ends\n got %+v\nwant %+v", got, want)
	}
}
