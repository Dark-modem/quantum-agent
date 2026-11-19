package balancer

// nftables rendering for the local forward balancer. The exact syntax
// was validated empirically against nftables 1.0.9 (nft -c check mode,
// kernel 6.6):
//
//	tcp dport 8443 dnat to numgen inc mod 100 map { 0-69 : 10.189.0.2, 70-99 : 10.189.0.3 }
//	udp dport 8443 dnat to jhash ip saddr mod 100 map { 0-69 : 10.189.0.2, 70-99 : 10.189.0.3 } : 8443
//	  (with a fixed target port: `... map { ... } : 22`)
//
// TCP uses numgen (round robin per NEW connection, weighted through the
// range sizes); UDP uses jhash of the source address so a flow sticks to
// one tunnel (per-packet numgen would shred UDP flows).

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
)

// BalTarget is one healthy tunnel in a forward rotation.
type BalTarget struct {
	TunnelID string
	IP       string
	Port     int // target port on the foreign side
	Weight   int
}

// ForwardRender is one rendered forward rule (proto expanded to chains).
type ForwardRender struct {
	ID         string
	ListenPort int
	TargetPort int    // fixed target port on the foreign side; 0 = unchanged
	Proto      string // tcp | udp | both
	Targets    []BalTarget
}

// RenderForwardNFT renders one atomic nft transaction that replaces the
// quantum-fwd table with one chain per rule. An empty targets list
// renders a pass-through chain (all targets down: new connections reach
// nothing locally and fail fast instead of blackholing).
func RenderForwardNFT(rules []ForwardRender) string {
	var b strings.Builder
	b.WriteString("table ip quantum-fwd\n")
	b.WriteString("delete table ip quantum-fwd\n")
	b.WriteString("table ip quantum-fwd {\n")
	for _, r := range rules {
		if r.Proto == "tcp" || r.Proto == "both" {
			b.WriteString(RenderForwardChain("tcp", r))
		}
		if r.Proto == "udp" || r.Proto == "both" {
			b.WriteString(RenderForwardChain("udp", r))
		}
	}
	b.WriteString("}\n")
	return b.String()
}

func ChainID(forwardID, proto string) string {
	id := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			return r
		default:
			return '_'
		}
	}, forwardID)
	return "fw_" + strings.ToLower(id) + "_" + proto
}

func RenderForwardChain(proto string, r ForwardRender) string {
	var b strings.Builder
	fmt.Fprintf(&b, " chain %s {\n", ChainID(r.ID, proto))
	fmt.Fprintf(&b, "  type nat hook prerouting priority dstnat; policy accept;\n")
	if len(r.Targets) == 0 {
		// All targets down: no NAT statement — new connections are
		// refused locally instead of being sent into a dead tunnel.
		fmt.Fprintf(&b, "  %s dport %d counter return\n", proto, r.ListenPort)
		b.WriteString(" }\n")
		return b.String()
	}
	// Per-target ports: lab sinks get one port per tunnel, so targets to
	// the same foreign host differ by port. The concatenated form
	// `<addr> . <port>` (verified with nft -c against nftables 1.0.9)
	// expresses that. Phase-5 bug: the single-port suffix used the RULE's
	// TargetPort even when the driver's ForwardAddress carried a
	// different (correct) port — a single remaining target was DNATed to
	// a port nothing listened on. The target's own port ALWAYS wins;
	// TargetPort is only the fallback when a driver gave none.
	kept, dropped := forwardUsableTargets(r)
	for _, t := range dropped {
		// RUNBOOK ITEM 36: a port-less target inside a per-target-port
		// map rendered `<addr> . 0` — nft accepted it and the kernel
		// silently no-oped the element, so the tunnel never received its
		// share. A port-less target cannot join a ported map; its weight
		// leaves the modulus with it (surfaced in the balancer diag as
		// reason "portless-target").
		log.Printf("[nft] forward %s: target %s excluded from the %s rotation: no usable port for a per-target-port map (target port 0, rule target_port %d)", r.ID, t.TunnelID, proto, r.TargetPort)
	}
	// Phase-21 ingest guard (defense in depth): the balancer's tick
	// refuses non-IPv4 targets before they reach this renderer, but the
	// transaction is applied as root — the renderer independently refuses
	// to write anything but a parsed IPv4 literal as a DNAT target.
	safeKept := kept[:0]
	for _, t := range kept {
		if !ForwardTargetIPValid(t.IP) {
			log.Printf("[nft] forward %s: target %s excluded from the %s rotation: %q is not an IPv4 address", r.ID, t.TunnelID, proto, t.IP)
			continue
		}
		safeKept = append(safeKept, t)
	}
	kept = safeKept
	if len(kept) == 0 {
		// Every target was dropped (all port-less in what must be a ported
		// map, or none an IPv4 literal): render the fail-fast pass-through
		// (defensive; forwardUsableTargets keeps at least one target
		// whenever Targets is non-empty, and the balancer refuses non-IP
		// targets before they get here).
		fmt.Fprintf(&b, "  %s dport %d counter return\n", proto, r.ListenPort)
		b.WriteString(" }\n")
		return b.String()
	}
	total := 0
	for _, t := range kept {
		total += t.Weight
	}
	if total <= 0 {
		total = len(kept)
	}
	// Deterministic element order (weights keep their assigned ranges).
	sort.Slice(kept, func(i, j int) bool { return kept[i].TunnelID < kept[j].TunnelID })

	sel := fmt.Sprintf("numgen inc mod %d", total)
	if proto == "udp" {
		// Flow-sticky: hash the source address so one UDP flow keeps its
		// tunnel for its whole lifetime.
		sel = fmt.Sprintf("jhash ip saddr mod %d", total)
	}
	// The map must be per-target-port when the effective ports differ
	// across targets, or when the uniform effective port differs from the
	// rule's TargetPort (the single-port suffix would lie).
	uniformPort := forwardTargetPort(kept[0], r.TargetPort)
	perTargetPort := false
	for _, t := range kept[1:] {
		if forwardTargetPort(t, r.TargetPort) != uniformPort {
			perTargetPort = true
			break
		}
	}
	if !perTargetPort && uniformPort > 0 && uniformPort != r.TargetPort {
		perTargetPort = true
	}
	var elems []string
	lo := 0
	for _, t := range kept {
		w := t.Weight
		if w <= 0 {
			w = 1
		}
		hi := lo + w - 1
		if hi >= total {
			hi = total - 1
		}
		if perTargetPort {
			elems = append(elems, fmt.Sprintf("%d-%d : %s . %d", lo, hi, t.IP, forwardTargetPort(t, r.TargetPort)))
		} else {
			// Elements are addresses only; the (fixed) target port rides
			// as a suffix after the map — the form validated against
			// nft 1.0.9 (nft -c): `map { 0-99 : <addr> } : <port>`.
			elems = append(elems, fmt.Sprintf("%d-%d : %s", lo, hi, t.IP))
		}
		lo += w
		if lo >= total {
			break
		}
	}
	fmt.Fprintf(&b, "  %s dport %d dnat to %s map { %s }", proto, r.ListenPort, sel, strings.Join(elems, ", "))
	if !perTargetPort && r.TargetPort > 0 {
		fmt.Fprintf(&b, " : %d", r.TargetPort)
	}
	b.WriteString("\n }\n")
	return b.String()
}

// forwardTargetPort resolves a target's effective port: the target's own
// port ALWAYS wins; the rule's TargetPort is only the fallback when a
// driver gave none (phase-5 rule).
func forwardTargetPort(t BalTarget, targetPort int) int {
	if t.Port > 0 {
		return t.Port
	}
	return targetPort
}

// forwardUsableTargets splits a render's targets into the ones that can
// join the rendered rotation and the port-less ones a per-target-port
// map would strand (`addr . 0`, RUNBOOK ITEM 36). A group with NO usable
// port at all (every target port 0 AND rule TargetPort 0 — a pure
// matrix-shaped group) keeps ALL its targets: it renders the
// address-only map, which is correct for it. The balancer applies the
// same split before reporting, so the diag ranges match the rendered map.
func forwardUsableTargets(r ForwardRender) (kept, dropped []BalTarget) {
	anyPort := r.TargetPort > 0
	for _, t := range r.Targets {
		if t.Port > 0 {
			anyPort = true
			break
		}
	}
	if !anyPort {
		return append([]BalTarget(nil), r.Targets...), nil
	}
	for _, t := range r.Targets {
		if forwardTargetPort(t, r.TargetPort) > 0 {
			kept = append(kept, t)
		} else {
			dropped = append(dropped, t)
		}
	}
	return kept, dropped
}

// scriptHasLoopbackDNAT reports whether the rendered script DNATs any
// traffic to a loopback address (127.0.0.0/8). Those rules need
// net.ipv4.conf.all.route_localnet=1 (RUNBOOK ITEM 35) or the kernel
// drops the martian packets — see routelocalnet.go.
func ScriptHasLoopbackDNAT(script string) bool {
	for _, line := range strings.Split(script, "\n") {
		i := strings.Index(line, " dnat to ")
		if i < 0 {
			continue
		}
		rest := line[i+len(" dnat to "):]
		if j := strings.Index(rest, " map {"); j >= 0 {
			rest = rest[j+len(" map {"):]
			if k := strings.Index(rest, "}"); k >= 0 {
				rest = rest[:k]
			}
			for _, el := range strings.Split(rest, ",") {
				if isLoopbackAddr(dnatElementAddr(el)) {
					return true
				}
			}
			continue
		}
		// Non-map form: `dnat to <addr>` / `dnat to <addr>:<port>`.
		fields := strings.Fields(rest)
		if len(fields) > 0 && isLoopbackAddr(fields[0]) {
			return true
		}
	}
	return false
}

// dnatElementAddr extracts the address from one map element
// ("0-69 : 10.189.0.2 . 443" or "0-99 : 127.0.0.1" → the address).
func dnatElementAddr(el string) string {
	el = strings.TrimSpace(el)
	i := strings.Index(el, ": ")
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(el[i+2:])
	if d := strings.Index(rest, " . "); d >= 0 {
		rest = rest[:d]
	}
	return strings.TrimSpace(rest)
}

func isLoopbackAddr(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.IsLoopback()
	}
	// Tolerate host:port shapes in non-map dnat targets.
	if host, _, err := net.SplitHostPort(s); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.IsLoopback()
		}
	}
	return false
}
