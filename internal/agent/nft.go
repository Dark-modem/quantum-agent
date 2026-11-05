package agent

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
	"sort"
	"strings"
)

// balTarget is one healthy tunnel in a forward rotation.
type balTarget struct {
	TunnelID string
	IP       string
	Port     int // target port on the foreign side
	Weight   int
}

// forwardRender is one rendered forward rule (proto expanded to chains).
type forwardRender struct {
	ID         string
	ListenPort int
	TargetPort int    // fixed target port on the foreign side; 0 = unchanged
	Proto      string // tcp | udp | both
	Targets    []balTarget
}

// renderForwardNFT renders one atomic nft transaction that replaces the
// quantum-fwd table with one chain per rule. An empty targets list
// renders a pass-through chain (all targets down: new connections reach
// nothing locally and fail fast instead of blackholing).
func renderForwardNFT(rules []forwardRender) string {
	var b strings.Builder
	b.WriteString("table ip quantum-fwd\n")
	b.WriteString("delete table ip quantum-fwd\n")
	b.WriteString("table ip quantum-fwd {\n")
	for _, r := range rules {
		if r.Proto == "tcp" || r.Proto == "both" {
			b.WriteString(renderForwardChain("tcp", r))
		}
		if r.Proto == "udp" || r.Proto == "both" {
			b.WriteString(renderForwardChain("udp", r))
		}
	}
	b.WriteString("}\n")
	return b.String()
}

func chainID(forwardID, proto string) string {
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

func renderForwardChain(proto string, r forwardRender) string {
	var b strings.Builder
	fmt.Fprintf(&b, " chain %s {\n", chainID(r.ID, proto))
	fmt.Fprintf(&b, "  type nat hook prerouting priority dstnat; policy accept;\n")
	if len(r.Targets) == 0 {
		// All targets down: no NAT statement — new connections are
		// refused locally instead of being sent into a dead tunnel.
		fmt.Fprintf(&b, "  %s dport %d counter return\n", proto, r.ListenPort)
		b.WriteString(" }\n")
		return b.String()
	}
	total := 0
	for _, t := range r.Targets {
		total += t.Weight
	}
	if total <= 0 {
		total = len(r.Targets)
	}
	// Deterministic element order (weights keep their assigned ranges).
	sorted := append([]balTarget(nil), r.Targets...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].TunnelID < sorted[j].TunnelID })

	sel := fmt.Sprintf("numgen inc mod %d", total)
	if proto == "udp" {
		// Flow-sticky: hash the source address so one UDP flow keeps its
		// tunnel for its whole lifetime.
		sel = fmt.Sprintf("jhash ip saddr mod %d", total)
	}
	// Per-target ports: lab sinks get one port per tunnel, so targets to
	// the same foreign host differ by port. The concatenated form
	// `<addr> . <port>` (verified with nft -c against nftables 1.0.9)
	// expresses that; the legacy single-port suffix stays for the
	// uniform case.
	perTargetPort := false
	for _, t := range sorted {
		if t.Port != sorted[0].Port {
			perTargetPort = true
			break
		}
	}
	var elems []string
	lo := 0
	for _, t := range sorted {
		w := t.Weight
		if w <= 0 {
			w = 1
		}
		hi := lo + w - 1
		if hi >= total {
			hi = total - 1
		}
		if perTargetPort {
			elems = append(elems, fmt.Sprintf("%d-%d : %s . %d", lo, hi, t.IP, t.Port))
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
