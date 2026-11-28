package agent

// Hermetic tests for OVERNIGHT-A9: the NaiveProxy CLIENT driver (CORES-6
// v154.0.8037.49-5, BSD). Upstream evidence: the core's USAGE.txt (the
// config.json contract {"listen","proxy"} + `naive <config.json>` +
// `naive --version`) + the D2 wiring spec (the BackPack managed shape).

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/engine"
	"github.com/Dark-modem/quantum-agent/internal/infra"
)

func naiveTestParams() naiveParams {
	return naiveParams{
		Version:   "154.0.8037.49-5",
		Artifact:  "naive-154.0.8037.49-5-linux-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("cc", 32), SHA256Arm: strings.Repeat("dd", 32),
		SigAmd: strings.Repeat("QQ==", 22)[:88], SigArm: strings.Repeat("QQ==", 22)[:88],
		ListenPort: 21150, RemoteHost: "198.51.100.9", RemotePort: 21443,
		Username: "nvuser", Password: "naive-pass-01",
		Concurrency: 4, ServerSide: "germany",
	}
}

func TestNaiveClientRender(t *testing.T) {
	p := naiveTestParams()
	if err := naiveValidateParams(p); err != nil {
		t.Fatalf("params rejected: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(naiveRenderConfig(p), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["listen"] != "socks://0.0.0.0:21150" {
		t.Fatalf("listen wrong: %v", cfg["listen"])
	}
	if cfg["proxy"] != "https://nvuser:naive-pass-01@198.51.100.9:21443" {
		t.Fatalf("proxy wrong: %v", cfg["proxy"])
	}
	if cfg["concurrency"] != float64(4) {
		t.Fatalf("concurrency wrong: %v", cfg["concurrency"])
	}
	// the concurrency omitted when unset (0).
	p2 := naiveTestParams()
	p2.Concurrency = 0
	var cfg2 map[string]any
	json.Unmarshal(naiveRenderConfig(p2), &cfg2)
	if _, ok := cfg2["concurrency"]; ok {
		t.Fatalf("concurrency must be omitted when unset")
	}
}

func TestNaiveHostileMatrix(t *testing.T) {
	for name, mutate := range map[string]func(*naiveParams){
		"port 0":         func(p *naiveParams) { p.ListenPort = 0 },
		"remote port 0":  func(p *naiveParams) { p.RemotePort = 0 },
		"user empty":     func(p *naiveParams) { p.Username = "" },
		"short password": func(p *naiveParams) { p.Password = "abc" },
		"user @":         func(p *naiveParams) { p.Username = "user@name" },
		"pass colon":     func(p *naiveParams) { p.Password = "pa:ss:word-01" },
		"pass slash":     func(p *naiveParams) { p.Password = "pa/ss/word-01" },
		"remote colon":   func(p *naiveParams) { p.RemoteHost = "host:443" },
		"concurrency 17": func(p *naiveParams) { p.Concurrency = 17 },
	} {
		bad := naiveTestParams()
		mutate(&bad)
		if err := naiveValidateParams(bad); err == nil {
			t.Fatalf("naive %s accepted", name)
		}
	}
	// CLIENT-ONLY by upstream design: the server end is refused with the
	// composition pointer (the sing-box naive inbound hosts the server half).
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		return agentIdentity{Server: "http://panel.test", Name: "germany"}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	d := NewNaiveDriver()
	p := naiveTestParams()
	inst := engine.Instance{TunnelID: "nv-tid", LocalServer: "germany", RemoteServer: "iran",
		Params: infra.MustJSON(p)}
	// the naive driver on the SERVER end (germany = server_side) → the
	// typed composition error. The artifact fetch never runs (the check
	// happens before the binary resolution).
	if err := d.Start(context.Background(), inst); err == nil ||
		!strings.Contains(err.Error(), "CLIENT-ONLY") {
		t.Fatalf("naive on the server end must be refused with the composition pointer: %v", err)
	}
}
