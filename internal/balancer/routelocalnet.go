package balancer

// routelocalnet.go — RUNBOOK ITEM 35: a DNAT to a loopback target
// (127.0.0.0/8) is dropped by the kernel's martian filter unless
// net.ipv4.conf.all.route_localnet=1 (and occasionally the per-interface
// knob too). The forward balancer discovers loopback targets only at
// render time — they come from a driver's ForwardAddress (a tunnel that
// lands on the agent's own loopback) or a static forward target — so the
// knob is balancer-owned DYNAMIC state, not a netopt drop-in:
//
//   - before applying a rendered script that contains a loopback DNAT,
//     the previous value is CAPTURED (never restored on a guess) and 1 is
//     written through `sysctl -w`;
//   - when a later render has no loopback targets anymore, the captured
//     value is restored and forgotten;
//   - the state lives on the ForwardBalancer (guarded by its mutex, the
//     same lock the tick holds) and is surfaced in the balancer tick
//     report → `quantum-agent balancer status` and the diag bundle's
//     "net" section.
//
// The apply/restore shape mirrors netapply.go (capture before-values,
// `sysctl -w key=<before>` restore, unquoted value) but is deliberately
// NOT coupled to the netopt journal: the balancer can flip this knob many
// times per process lifetime as groups gain and lose loopback targets.

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

// RlSysctlAll is the kernel key the balancer owns while any rendered
// forward DNATs to loopback.
const RlSysctlAll = "net.ipv4.conf.all.route_localnet"

// Seams (tests swap them; production reads /proc and shells out to
// sysctl through the shared runner).
var (
	// RlSysctlRead reads one sysctl key's current value.
	RlSysctlRead = func(key string) (string, error) {
		b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	// RlSysctlWrite writes one sysctl key (`sysctl -w key=value`, the
	// value UNQUOTED — netapply's live-acceptance lesson).
	RlSysctlWrite = func(key, val string) error {
		_, err := infra.RunCmdTimeout(5*time.Second, "sysctl", "-w", key+"="+val)
		return err
	}
	// RlListenIface resolves the interface a listen port is reached on.
	// Nothing resolves it today ("" = only the 'all' knob, the
	// documented default); the seam exists so the per-interface write is
	// exercisable and a future resolver can plug in.
	RlListenIface = func(listenPort int) string { return "" }
)

// applyScriptRL applies one rendered nft transaction with the
// route_localnet ensure/restore wrapped around it. Caller holds b.mu
// (the tick holds it for its whole pass; Stop takes it).
func (b *ForwardBalancer) ApplyScriptRL(script string, listenPorts ...int) error {
	if err := b.ensureRouteLocalnet(script, listenPorts); err != nil {
		return err
	}
	err := ApplyNFTScript(script)
	// A script without loopback targets no longer needs the knob — even
	// when the apply itself failed (the state converges on the next pass).
	b.settleRouteLocalnet(script)
	return err
}

// ensureRouteLocalnet captures route_localnet's previous value and sets
// it to 1 when the script DNATs to loopback. Idempotent: an active knob
// is left alone; a knob that already read 1 records before="1" so the
// restore is a no-op write of the same value. Caller holds b.mu.
func (b *ForwardBalancer) ensureRouteLocalnet(script string, listenPorts []int) error {
	if !ScriptHasLoopbackDNAT(script) || b.RlActive {
		return nil
	}
	before, err := RlSysctlRead(RlSysctlAll)
	if err != nil {
		return fmt.Errorf("route_localnet: read %s: %w", RlSysctlAll, err)
	}
	if err := RlSysctlWrite(RlSysctlAll, "1"); err != nil {
		return fmt.Errorf("route_localnet: sysctl -w %s=1: %w", RlSysctlAll, err)
	}
	b.RlActive = true
	b.RlSaved = before // the true before value — never a guess
	if len(listenPorts) > 0 {
		b.ensureRouteLocalnetIface(listenPorts[0])
	}
	return nil
}

// ensureRouteLocalnetIface additionally sets the per-interface knob when
// the listen interface is known; its failure is non-fatal (the 'all' knob
// is already set). Caller holds b.mu.
func (b *ForwardBalancer) ensureRouteLocalnetIface(listenPort int) {
	iface := RlListenIface(listenPort)
	if iface == "" {
		return
	}
	key := "net.ipv4.conf." + iface + ".route_localnet"
	before, err := RlSysctlRead(key)
	if err != nil {
		return // unknown key on this kernel: 'all' covers it
	}
	if err := RlSysctlWrite(key, "1"); err != nil {
		log.Printf("[balancer] route_localnet: %s=1 failed (%v); the 'all' knob is set", key, err)
		return
	}
	b.RlIface, b.RlSavedIface = iface, before
}

// settleRouteLocalnet restores the captured route_localnet when the new
// script no longer DNATs to loopback, then forgets the capture. Only
// values this process captured are ever written back. Caller holds b.mu.
func (b *ForwardBalancer) settleRouteLocalnet(script string) {
	if ScriptHasLoopbackDNAT(script) || !b.RlActive {
		return
	}
	if b.RlSaved != "" {
		if err := RlSysctlWrite(RlSysctlAll, b.RlSaved); err != nil {
			log.Printf("[balancer] route_localnet: restore %s=%s failed: %v", RlSysctlAll, b.RlSaved, err)
		}
	}
	if b.RlIface != "" && b.RlSavedIface != "" {
		key := "net.ipv4.conf." + b.RlIface + ".route_localnet"
		if err := RlSysctlWrite(key, b.RlSavedIface); err != nil {
			log.Printf("[balancer] route_localnet: restore %s=%s failed: %v", key, b.RlSavedIface, err)
		}
	}
	b.RlActive, b.RlSaved, b.RlIface, b.RlSavedIface = false, "", "", ""
}
