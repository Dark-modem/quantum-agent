package agent

// lab_engine.go — the lab fake-driver registration (QUANTUM_ENGINES_LAB).
//
// Integration/e2e runs need the REAL agent binary to drive more than the
// matrix engine without host-coupled daemons: setting
// QUANTUM_ENGINES_LAB=fake registers this file's own labFakeDriver under
// the id "fake" — not internal/engine/faketest.FakeEngine, which is
// test-only. It is env-gated so production agents never carry it.
//
// Behavior (lab contract):
//   - Start() opens a TCP sink listener on lab_port (from engine_params)
//     and counts accepted bytes as REAL payload counters — so heartbeat
//     reports and the panel usage API carry true numbers for fake
//     tunnels.
//   - ForwardAddress() returns lab_addr[:lab_port] from engine_params —
//     the address the iran-side balancer DNATs new connections to (the
//     foreign namespace where a sibling agent's sink listens).
//   - Counters() reports the sink's byte counts (wire == payload: fake
//     tunnels add no encapsulation overhead, ratio 1.0 by construction).
//   - Health() reflects the sink listener state.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

// labSinkPort is the engine_params key for the sink listen port.
const labSinkPort = "lab_port"

type labFakeDriver struct {
	mu      sync.Mutex
	running map[string]engine.Instance
	sinks   map[string]net.Listener // tunnelID -> listener
	payload map[string]*atomic.Uint64
}

type labParams struct {
	LabAddr string `json:"lab_addr"`
	LabPort int    `json:"lab_port"`
}

// NewLabFakeDriver builds the lab driver (id "fake").
func NewLabFakeDriver() *labFakeDriver {
	return &labFakeDriver{
		running: map[string]engine.Instance{},
		sinks:   map[string]net.Listener{},
		payload: map[string]*atomic.Uint64{},
	}
}

// LabEnginesFromEnv returns lab driver ids requested via QUANTUM_ENGINES_LAB.
func LabEnginesFromEnv() []string {
	raw := strings.TrimSpace(os.Getenv("QUANTUM_ENGINES_LAB"))
	if raw == "" {
		return nil
	}
	var out []string
	for _, id := range strings.Split(raw, ",") {
		if id = strings.TrimSpace(id); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// RegisterLabEngines registers the env-requested lab drivers.
func RegisterLabEngines(reg *engine.Registry) error {
	for _, id := range LabEnginesFromEnv() {
		if id == "fake" {
			if err := reg.Register(NewLabFakeDriver()); err != nil {
				return err
			}
		}
	}
	return nil
}

var (
	_ engine.Driver           = (*labFakeDriver)(nil)
	_ engine.ForwardAddresser = (*labFakeDriver)(nil)
	_ engine.Describer        = (*labFakeDriver)(nil)
	_ engine.ProcessInfoer    = (*labFakeDriver)(nil)
)

// ProcessPIDs implements engine.ProcessInfoer: the lab engine runs IN
// the agent process (the sink listener is a goroutine), so the honest
// process tree is the agent's own pid — the /proc sampler then reports
// the agent's REAL CPU/RSS for these tunnels (and the e2e lab proves
// the numbers travel agent → panel → API).
func (l *labFakeDriver) ProcessPIDs(inst engine.Instance) []int {
	return []int{os.Getpid()}
}

func (l *labFakeDriver) ID() string { return "fake" }

func (l *labFakeDriver) Validate(params json.RawMessage) error {
	var p labParams
	if err := json.Unmarshal(params, &p); err != nil {
		return fmt.Errorf("fake: engine_params: %w", err)
	}
	if p.LabAddr == "" || p.LabPort <= 0 {
		return fmt.Errorf("fake: engine_params must carry lab_addr and lab_port")
	}
	return nil
}

// EnsureBinary implements Driver: nothing to download.
func (l *labFakeDriver) EnsureBinary(ctx context.Context) (string, error) { return "", nil }

// labOwnsAddr reports whether this host owns addr (the lab contract:
// engine_params.lab_addr is the REMOTE server's address, so the far end
// binds the sink and the near end probes it). Phase-5 bug fix: the sink
// used to bind on EVERY instance — on the near end it squatted the
// forward listen port (intercepting the very connections the balancer
// must DNAT), and on both ends the second instance per host failed to
// bind ("address already in use"), leaving one lab tunnel per host.
var labOwnsAddr = func(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true // unspecified: this host by definition
	}
	ips := []string{host}
	if net.ParseIP(host) == nil {
		resolved, err := net.LookupHost(host)
		if err != nil {
			return false
		}
		ips = resolved
	}
	own := map[string]bool{"127.0.0.1": true, "::1": true}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				own[ipn.IP.String()] = true
			}
		}
	}
	for _, ip := range ips {
		if own[net.ParseIP(ip).String()] {
			return true
		}
	}
	return false
}

// labProbeTCP is the near end's end-to-end health probe (the far end's
// sink IS the tunnel's far side). Seam for tests.
var labProbeTCP = func(host string, port int, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), timeout)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// Start implements Driver: the FAR end (lab_addr is one of this host's
// addresses) opens the sink listener and counts received bytes; the NEAR
// end binds nothing (it would squat the forward listen port) and its
// health is a real probe to the far end.
func (l *labFakeDriver) Start(ctx context.Context, inst engine.Instance) error {
	var p labParams
	if err := json.Unmarshal(inst.Params, &p); err != nil {
		return err
	}
	if p.LabPort <= 0 {
		return fmt.Errorf("fake: lab_port required")
	}
	l.mu.Lock()
	if _, running := l.running[inst.TunnelID]; running {
		l.mu.Unlock()
		return nil // idempotent
	}
	l.mu.Unlock()

	l.mu.Lock()
	l.running[inst.TunnelID] = inst
	l.mu.Unlock()
	if !labOwnsAddr(p.LabAddr) {
		log.Printf("[lab] sink %s: near end (lab_addr %s not ours) — no listener, no counter", inst.TunnelID, p.LabAddr)
		return nil // near end: no listener; health probes the far end
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p.LabPort))
	if err != nil {
		l.mu.Lock()
		delete(l.running, inst.TunnelID)
		l.mu.Unlock()
		return fmt.Errorf("fake sink on %d: %w", p.LabPort, err)
	}
	counter := &atomic.Uint64{}
	l.mu.Lock()
	// AGENT-23 diagnostics (lab-only): every counter lifecycle transition
	// logs, so an e2e run can tell a counter RESET (fresh Start over an
	// existing entry) from a first bind — the distribution-leg "0 of 0"
	// flake needed exactly this trail (run logs are the only observer of
	// the running agent's sink counters).
	if old, existed := l.payload[inst.TunnelID]; existed {
		log.Printf("[lab] sink %s: RESTART resets the counter (old value %d; params now %s)",
			inst.TunnelID, old.Load(), string(inst.Params))
	} else {
		log.Printf("[lab] sink %s: first bind on :%d (params %s)", inst.TunnelID, p.LabPort, string(inst.Params))
	}
	l.sinks[inst.TunnelID] = ln
	l.payload[inst.TunnelID] = counter
	l.mu.Unlock()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed = instance stopped
			}
			go func(c net.Conn) {
				defer c.Close()
				n, _ := io.Copy(io.Discard, c)
				counter.Add(uint64(n))
			}(conn)
		}
	}()
	return nil
}

// Stop implements Driver: close the sink (far end) and forget the instance.
func (l *labFakeDriver) Stop(inst engine.Instance) error {
	l.mu.Lock()
	if ln, ok := l.sinks[inst.TunnelID]; ok {
		ln.Close()
		delete(l.sinks, inst.TunnelID)
		log.Printf("[lab] sink %s: stopped (listener closed)", inst.TunnelID) // AGENT-23 lab diag
	}
	delete(l.running, inst.TunnelID)
	l.mu.Unlock()
	return nil
}

// Reload implements Driver: params are fixed in the lab (restart path).
func (l *labFakeDriver) Reload(inst engine.Instance) error { return engine.ErrRestartRequired }

// Health implements Driver: the far end reports its listener; the near
// end reports a real end-to-end probe of the far end's sink (the tunnel
// health the balancer's "engine" probe mode consumes).
func (l *labFakeDriver) Health(inst engine.Instance) engine.Health {
	var p labParams
	_ = json.Unmarshal(inst.Params, &p)
	if p.LabAddr != "" && !labOwnsAddr(p.LabAddr) {
		// 2s: matches the real matrix engine's probe-window tolerance — a
		// single tight dial under forwarded-traffic load flapped the
		// health view and churned the ruleset (Phase-5 e2e).
		ok := labProbeTCP(p.LabAddr, p.LabPort, 2*time.Second)
		detail := "lab fake: far end reachable"
		if !ok {
			detail = "lab fake: far end unreachable"
		}
		return engine.Health{OK: ok, Detail: detail, LatencyMs: -1}
	}
	l.mu.Lock()
	_, listening := l.sinks[inst.TunnelID]
	l.mu.Unlock()
	return engine.Health{OK: listening, Detail: "lab fake sink", LatencyMs: -1}
}

// Counters implements Driver: REAL bytes the sink accepted.
func (l *labFakeDriver) Counters(inst engine.Instance) engine.Counters {
	l.mu.Lock()
	c, ok := l.payload[inst.TunnelID]
	l.mu.Unlock()
	if !ok {
		return engine.Counters{}
	}
	n := c.Load()
	// No encapsulation overhead on a fake tunnel: wire == payload, both
	// directions counted as the sink's received bytes for rx and 0 tx
	// (the sink never sends). Real bytes only — never multiplied.
	return engine.Counters{WireRx: n, WireKnown: true, PayloadRx: n, PayloadKnown: true}
}

// Uninstall implements Driver: close every sink (lab keeps no binaries).
func (l *labFakeDriver) Uninstall(ctx context.Context) error {
	l.mu.Lock()
	n := len(l.sinks)
	for id, ln := range l.sinks {
		ln.Close()
		delete(l.sinks, id)
		log.Printf("[lab] sink %s: uninstalled (listener closed)", id) // AGENT-23 lab diag
	}
	l.running = map[string]engine.Instance{}
	l.mu.Unlock()
	if n > 0 {
		log.Printf("[lab] fake driver uninstall: %d sink(s) closed", n) // AGENT-23 lab diag
	}
	return nil
}

// ForwardAddress implements the optional capability from engine_params.
func (l *labFakeDriver) ForwardAddress(inst engine.Instance) (string, int, bool) {
	var p labParams
	if err := json.Unmarshal(inst.Params, &p); err != nil || p.LabAddr == "" {
		return "", 0, false
	}
	return p.LabAddr, p.LabPort, true
}

// Describe implements the optional capability.
func (l *labFakeDriver) Describe() engine.EngineInfo {
	return engine.EngineInfo{ID: "fake", Version: panelVersion,
		ParamsSchema: json.RawMessage(`{"lab_addr":"<foreign ip>","lab_port":0}`)}
}
