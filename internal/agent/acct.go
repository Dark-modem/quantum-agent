package agent

// acct.go — the ONE iptables accounting layer (REFACTOR-PLAN-AGENT §6.A2,
// dedup item D2). Two chain families live here side by side:
//
//	QUANTUM_ACCT_IN/OUT  (acctChainsCarrier) — the legacy carrier ledger
//	  (Backhaul/Bagher/legacy-Xray tunnels): count-only rules without a
//	  target, rendered per discovered carrier end and loaded atomically
//	  with iptables-restore; per-end/tag counters parsed from
//	  `iptables-save -c` in one pass. Machinery: carrierRules*,
//	  parseAcctSave*, carrierLoad*/carrierDrop*, carrierCounters.
//	FRPDRV_ACCT_IN/OUT   (acctChainsDriver) — the engine-driver wire
//	  accounting: one comment-scoped counter rule pair per tunnel
//	  ("frpdrv-<tunnelID>"), ensured/hooked incrementally with plain
//	  iptables, read back per instance by comment + port range.
//	  Machinery: acctWireRulesEnsure/Add/Del, acctWireBytes. Callers:
//	  frp/backhaul/ctunnel/xray/wstunnel/chisel/gost/rathole (A1) and the
//	  CTDRV_ACCT_* + udp2raw RST rules via the shared acctIptables seam.
//
// KERNEL-VISIBLE CONTRACT: the chain names and the "frpdrv-" rule comment
// are byte-identical to what earlier releases installed — the panel's
// counters read them; they must never move.
//
// The families are NOT force-merged beyond co-location + the namespace
// parameter, because their mechanics differ in behavior-relevant ways:
//   - loading: restore-based atomic replace with an -I INPUT 1 hook vs
//     incremental -N/-C/-A ensure (hook POSITION in INPUT differs by design);
//   - rule shape: targetless per-peer count rules (with -i/-o default-route
//     matching, /32-/128 masks, IPv6 family) vs comment-scoped dport/sport
//     port-RANGE rules;
//   - lifecycle: the carrier chains are dropped when the last tunnel goes
//     away; FRPDRV chains persist once created;
//   - parsing: acctWireBytes scans comment+range lines (bracket at line END,
//     summed per instance), parseAcctSaveEnds scans chain-scoped lines
//     (bracket FIRST, keyed per end via acctRuleKey).
// Unifying any of those would change which rules get installed or read —
// left per-family on purpose.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

// The chain names — kernel-visible, byte-identical to the pre-A2 layout
// (panel-visible counters must not move).
const (
	acctCarrierIn  = "QUANTUM_ACCT_IN"
	acctCarrierOut = "QUANTUM_ACCT_OUT"
	acctDriverIn   = "FRPDRV_ACCT_IN"
	acctDriverOut  = "FRPDRV_ACCT_OUT"
)

// acctChains is one accounting namespace: the chain pair the machinery
// installs, hooks and reads. The namespace is a parameter so a future
// family reuses the same shapes with its own names.
type acctChains struct {
	In  string
	Out string
}

var (
	acctChainsCarrier = acctChains{In: acctCarrierIn, Out: acctCarrierOut}
	acctChainsDriver  = acctChains{In: acctDriverIn, Out: acctDriverOut}
)

// acctIPv6 reports whether this server has a global IPv6 address; swappable
// for tests. (The carrier render and the doctor/advisor IPv6 checks share it.)
var acctIPv6 = func() bool {
	data, err := os.ReadFile("/proc/net/if_inet6")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(data), "\n") {
		if f := strings.Fields(l); len(f) >= 4 && f[3] == "00" { // scope global
			return true
		}
	}
	return false
}

// ---- the shared iptables exec seams --------------------------------------

// acctIptables / acctIptablesSave run iptables and iptables-save -c for
// EVERY accounting family (the FRPDRV machinery, the ctunnel CTDRV_ACCT_*
// chains and the udp2raw RST rule). Hermetic tests stub them.
var (
	acctIptables = func(args ...string) ([]byte, error) {
		return infra.RunCmdTimeout(10*time.Second, "iptables", args...)
	}
	acctIptablesSave = func() ([]byte, error) {
		return infra.RunCmdTimeout(15*time.Second, "iptables-save", "-c", "-t", "filter")
	}
)

// ---- the driver-side wire accounting (FRPDRV_ACCT_*) ---------------------

// acctWireRulesEnsure makes the FRPDRV accounting chains exist and hooks
// them. Safe to call repeatedly; failures are reported (counters go
// Unknown).
func acctWireRulesEnsure(ch acctChains) error {
	if _, err := acctIptables("-N", ch.In); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return err
	}
	if _, err := acctIptables("-N", ch.Out); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return err
	}
	if _, err := acctIptables("-C", "INPUT", "-j", ch.In); err != nil {
		if _, err := acctIptables("-A", "INPUT", "-j", ch.In); err != nil {
			return err
		}
	}
	if _, err := acctIptables("-C", "OUTPUT", "-j", ch.Out); err != nil {
		if _, err := acctIptables("-A", "OUTPUT", "-j", ch.Out); err != nil {
			return err
		}
	}
	return nil
}

// acctRuleComment is the per-instance rule marker the driver family scopes
// its rules with. KERNEL-VISIBLE: the "frpdrv-" prefix is byte-identical to
// earlier releases.
func acctRuleComment(tunnelID string) string { return "frpdrv-" + tunnelID }

// acctPortRange renders the iptables port range for an instance's allowed
// data ports ("n" when min==max, "min:max" otherwise).
func acctPortRange(min, max int) string {
	if min == max {
		return strconv.Itoa(min)
	}
	return strconv.Itoa(min) + ":" + strconv.Itoa(max)
}

// acctWireRulesAdd installs one instance's counter rules (server side).
// The range is the instance's allowed data-port window; the panel allocates
// non-overlapping windows per tunnel.
func acctWireRulesAdd(ch acctChains, tunnelID string, allowMin, allowMax int) error {
	if err := acctWireRulesEnsure(ch); err != nil {
		return err
	}
	cmt := acctRuleComment(tunnelID)
	rng := acctPortRange(allowMin, allowMax)
	if _, err := acctIptables("-A", ch.In, "-p", "tcp", "--dport", rng,
		"-m", "comment", "--comment", cmt); err != nil {
		return err
	}
	if _, err := acctIptables("-A", ch.Out, "-p", "tcp", "--sport", rng,
		"-m", "comment", "--comment", cmt); err != nil {
		return err
	}
	return nil
}

// acctWireRulesDel removes exactly one instance's rules (comment-scoped).
func acctWireRulesDel(ch acctChains, tunnelID string, allowMin, allowMax int) error {
	cmt := acctRuleComment(tunnelID)
	rng := acctPortRange(allowMin, allowMax)
	var firstErr error
	if _, err := acctIptables("-D", ch.In, "-p", "tcp", "--dport", rng,
		"-m", "comment", "--comment", cmt); err != nil && firstErr == nil {
		firstErr = err
	}
	if _, err := acctIptables("-D", ch.Out, "-p", "tcp", "--sport", rng,
		"-m", "comment", "--comment", cmt); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// acctWireBytes reads one instance's counters from iptables-save -c
// (exact bytes, one read, no table lock churn). Line shape:
//
//	-A FRPDRV_ACCT_IN -p tcp -m tcp --dport 34001 -m comment
//	  --comment frpdrv-t1 [ 11:2222 ]
//
// where the bracket holds "pkts:bytes". (The carrier family parses the same
// output differently — see parseAcctSaveEnds; the shapes are kept apart on
// purpose, see the file header.)
func acctWireBytes(tunnelID string, allowMin, allowMax int) (rx, tx uint64, ok bool) {
	out, err := acctIptablesSave()
	if err != nil {
		return 0, 0, false
	}
	cmt := acctRuleComment(tunnelID)
	rng := acctPortRange(allowMin, allowMax)
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, cmt) {
			continue
		}
		var isRx bool
		switch {
		case strings.Contains(line, "--dport "+rng+" "):
			isRx = true
		case strings.Contains(line, "--sport "+rng+" "):
			// outbound leg
		default:
			continue
		}
		i := strings.LastIndex(line, "[")
		j := strings.LastIndex(line, "]")
		if i < 0 || j <= i {
			continue
		}
		// iptables-save -c: the bracket holds one "pkts:bytes" token.
		var v uint64
		parsed := false
		for _, tok := range strings.Fields(line[i+1 : j]) {
			parts := strings.SplitN(tok, ":", 2)
			if len(parts) != 2 {
				continue
			}
			n, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				continue
			}
			v, parsed = n, true
			break
		}
		if !parsed {
			continue
		}
		if isRx {
			rx += v
		} else {
			tx += v
		}
		ok = true
	}
	return rx, tx, ok
}

// ---- the carrier-side iptables accounting (QUANTUM_ACCT_*) ---------------
// The machinery below was moved verbatim from carrier_traffic.go (§6.A2):
// names, signatures, rule text and parse behavior are unchanged — the chain
// names now come from the acctChainsCarrier namespace instead of local
// consts, with identical strings.

// acctKey identifies an end in iptables-save output, which has no tags.
type acctKey struct {
	Listen bool
	Port   int
	Peer   string // the -s/-d address, "" for any
}

// carrierRules renders the two chains as iptables-restore input. ifname is the
// default-route interface ("" matches any).
func carrierRules(ends []carrierEnd, ifname string) string {
	return carrierRulesFam(acctChainsCarrier, ends, ifname, 4)
}

// carrierRules6 is the IPv6 table for ip6tables-restore: the ends with an
// IPv6 peer, and the ports this server listens on for anyone (they are
// reached over IPv6 too) when it has an IPv6 address. "" when there is
// nothing to count over IPv6.
func carrierRules6(ends []carrierEnd, ifname string) string {
	return carrierRulesFam(acctChainsCarrier, ends, ifname, 6)
}

func carrierRulesFam(ch acctChains, ends []carrierEnd, ifname string, fam int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*filter\n:%s - [0:0]\n:%s - [0:0]\n-F %s\n-F %s\n", ch.In, ch.Out, ch.In, ch.Out)
	in, out := "", ""
	if ifname != "" {
		in, out = " -i "+ifname, " -o "+ifname
	}
	mask, v6host, n := "/32", fam == 6 && acctIPv6(), 0
	if fam == 6 {
		mask = "/128"
	}
	for _, e := range ends {
		peer := e.Remote
		if peer == "" {
			peer = e.From
		}
		if peer != "" && infra.IPFamily(peer) != fam || peer == "" && fam == 6 && !v6host {
			continue
		}
		n++
		protos := []string{"tcp"}
		if e.UDP {
			protos = append(protos, "udp")
		}
		for _, pr := range protos {
			switch {
			case e.Remote == "" && e.From != "": // listens, for one peer only
				fmt.Fprintf(&b, "-A %s%s -s %s%s -p %s --dport %d\n", ch.In, in, e.From, mask, pr, e.Port)
				fmt.Fprintf(&b, "-A %s%s -d %s%s -p %s --sport %d\n", ch.Out, out, e.From, mask, pr, e.Port)
			case e.Remote == "": // this server listens on the port
				fmt.Fprintf(&b, "-A %s%s -p %s --dport %d\n", ch.In, in, pr, e.Port)
				fmt.Fprintf(&b, "-A %s%s -p %s --sport %d\n", ch.Out, out, pr, e.Port)
			default: // this server dials Remote:Port
				fmt.Fprintf(&b, "-A %s%s -s %s%s -p %s --sport %d\n", ch.In, in, e.Remote, mask, pr, e.Port)
				fmt.Fprintf(&b, "-A %s%s -d %s%s -p %s --dport %d\n", ch.Out, out, e.Remote, mask, pr, e.Port)
			}
		}
	}
	b.WriteString("COMMIT\n")
	if fam == 6 && n == 0 {
		return ""
	}
	return b.String()
}

// parseAcctSave sums the byte counters of our chains in `iptables-save -c`
// output and reports whether both chains and both jumps to them exist.
func parseAcctSave(out string) (rx, tx uint64, ready bool) {
	rx, tx, _, ready = parseAcctSaveEnds(acctChainsCarrier, out)
	return rx, tx, ready
}

// acctRuleKey reads which end a counting rule belongs to from its text, as
// iptables-save prints it ("-A QUANTUM_ACCT_IN -i eth0 -s 1.2.3.4/32 -p tcp
// -m tcp --sport 22"). In the IN chain --dport is a port this server listens
// on and -s the peer; in the OUT chain --sport and -d.
func acctRuleKey(rule string, in bool) (acctKey, bool) {
	f := strings.Fields(rule)
	var k acctKey
	var lport, dport int
	var peer string
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "--dport":
			dport, _ = strconv.Atoi(f[i+1])
		case "--sport":
			lport, _ = strconv.Atoi(f[i+1])
		case "-s", "-d":
			if (f[i] == "-s") == in {
				peer = strings.TrimSuffix(strings.TrimSuffix(f[i+1], "/32"), "/128")
			}
		}
	}
	if !in { // OUT: the local port is the source port
		lport, dport = dport, lport
	}
	// now dport is the local listening port (if any), lport the remote's port
	switch {
	case dport > 0:
		k = acctKey{Listen: true, Port: dport, Peer: peer}
	case lport > 0:
		k = acctKey{Port: lport, Peer: peer}
	default:
		return k, false
	}
	return k, true
}

// parseAcctSaveEnds is parseAcctSave with the bytes of each end as well
// ([0] received, [1] sent).
func parseAcctSaveEnds(ch acctChains, out string) (rx, tx uint64, ends map[acctKey][2]uint64, ready bool) {
	ends = map[acctKey][2]uint64{}
	var chains, hooks int
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ":"+ch.In+" ") || strings.HasPrefix(line, ":"+ch.Out+" ") {
			chains++
			continue
		}
		if !strings.HasPrefix(line, "[") {
			continue
		}
		end := strings.Index(line, "]")
		if end < 0 {
			continue
		}
		rule := strings.TrimSpace(line[end+1:])
		switch rule {
		case "-A INPUT -j " + ch.In, "-A OUTPUT -j " + ch.Out:
			hooks++
			continue
		}
		_, bytesStr, ok := strings.Cut(line[1:end], ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(bytesStr, 10, 64)
		if err != nil {
			continue
		}
		in := strings.HasPrefix(rule, "-A "+ch.In+" ")
		if !in && !strings.HasPrefix(rule, "-A "+ch.Out+" ") {
			continue
		}
		if in {
			rx += n
		} else {
			tx += n
		}
		if k, ok := acctRuleKey(rule, in); ok {
			c := ends[k]
			if in {
				c[0] += n
			} else {
				c[1] += n
			}
			ends[k] = c
		}
	}
	return rx, tx, ends, chains == 2 && hooks == 2
}

var carrierState = struct {
	sync.Mutex
	sig        string // the rules last loaded by this process
	sig6       string // the IPv6 ones
	at         time.Time
	rx, tx     uint64
	tags       map[string][2]uint64 // per tunnel: [0] received, [1] sent
	ok         bool
	lastFailed time.Time
}{}

// carrierTagCounters is the last reading per tunnel (see carrierEnd.Tag);
// call carrierCounters first for a fresh one.
func carrierTagCounters() map[string][2]uint64 {
	carrierState.Lock()
	defer carrierState.Unlock()
	if !carrierState.ok {
		return nil
	}
	out := make(map[string][2]uint64, len(carrierState.tags))
	for k, v := range carrierState.tags {
		out[k] = v
	}
	return out
}

// carrierCounters returns the bytes received (rx) and sent (tx) by this
// server's Backhaul and Bagher carriers since the chains were last built. ok
// is false when there is nothing to count or iptables is unavailable. The
// reading is cached for two seconds (the snapshot and the history recorder
// both ask).
var carrierCounters = readCarrierCounters

func readCarrierCounters() (rx, tx uint64, ok bool) {
	carrierState.Lock()
	defer carrierState.Unlock()
	if time.Since(carrierState.at) < 2*time.Second {
		return carrierState.rx, carrierState.tx, carrierState.ok
	}
	carrierState.at = time.Now()
	carrierState.ok = false

	ends := carrierEnds()
	if len(ends) == 0 {
		if carrierState.sig != "" || carrierState.sig6 != "" { // the tunnels are gone: remove the chains once
			carrierDrop()
			carrierState.sig, carrierState.sig6 = "", ""
		}
		return 0, 0, false
	}
	// A failing iptables is retried once a minute, not on every tick.
	if !carrierState.lastFailed.IsZero() && time.Since(carrierState.lastFailed) < time.Minute {
		return 0, 0, false
	}
	rules := carrierRules(ends, infra.PrimaryInterface())
	out, err := infra.RunCmdTimeoutOut(5*time.Second, "iptables-save", "-c", "-t", "filter")
	if err != nil {
		carrierState.lastFailed = time.Now()
		return 0, 0, false
	}
	rx, tx, byEnd, ready := parseAcctSaveEnds(acctChainsCarrier, string(out))
	if !ready || rules != carrierState.sig {
		// New or changed tunnels, a reboot or a firewall reload: build the
		// chains again (their counters start over, which the ledger treats as
		// a reset).
		if err := carrierLoad(rules); err != nil {
			carrierState.lastFailed = time.Now()
			return 0, 0, false
		}
		carrierState.sig = rules
		rx, tx, byEnd = 0, 0, nil
	}
	// IPv6: a failing ip6tables leaves the IPv4 counts alone
	if rules6 := carrierRules6(ends, infra.PrimaryInterface()); rules6 == "" && carrierState.sig6 != "" {
		carrierDropFam("ip6tables")
		carrierState.sig6 = ""
	} else if rules6 != "" {
		if out6, err := infra.RunCmdTimeoutOut(5*time.Second, "ip6tables-save", "-c", "-t", "filter"); err == nil {
			rx6, tx6, byEnd6, ready6 := parseAcctSaveEnds(acctChainsCarrier, string(out6))
			if !ready6 || rules6 != carrierState.sig6 {
				if carrierLoadFam(acctChainsCarrier, "ip6tables", rules6) == nil {
					carrierState.sig6 = rules6
				}
				rx6, tx6, byEnd6 = 0, 0, nil
			}
			rx, tx = rx+rx6, tx+tx6
			if byEnd == nil {
				byEnd = map[acctKey][2]uint64{}
			}
			for k, v := range byEnd6 {
				c := byEnd[k]
				byEnd[k] = [2]uint64{c[0] + v[0], c[1] + v[1]}
			}
		}
	}
	tags := map[string][2]uint64{}
	for _, e := range ends {
		c, t := byEnd[e.key()], tags[e.Tag]
		tags[e.Tag] = [2]uint64{t[0] + c[0], t[1] + c[1]}
	}
	carrierState.lastFailed = time.Time{}
	carrierState.rx, carrierState.tx, carrierState.tags, carrierState.ok = rx, tx, tags, true
	return rx, tx, true
}

// carrierLoad replaces both chains and makes sure INPUT and OUTPUT jump to them.
func carrierLoad(rules string) error { return carrierLoadFam(acctChainsCarrier, "iptables", rules) }

// carrierLoadFam is carrierLoad with bin ("iptables" or "ip6tables").
func carrierLoadFam(ch acctChains, bin, rules string) error {
	_ = os.MkdirAll(infra.ConfigDir, 0o700)
	f := filepath.Join(infra.ConfigDir, "carrier-acct.v4")
	if bin == "ip6tables" {
		f = filepath.Join(infra.ConfigDir, "carrier-acct.v6")
	}
	if err := os.WriteFile(f, []byte(rules), 0o600); err != nil {
		return err
	}
	if out, err := infra.RunCmdTimeout(10*time.Second, bin+"-restore", "-w", "5", "-n", f); err != nil {
		return fmt.Errorf("%s-restore: %s", bin, strings.TrimSpace(string(out)))
	}
	for _, h := range [][2]string{{"INPUT", ch.In}, {"OUTPUT", ch.Out}} {
		if _, err := infra.RunCmdTimeout(5*time.Second, bin, "-w", "5", "-C", h[0], "-j", h[1]); err != nil {
			if out, err := infra.RunCmdTimeout(5*time.Second, bin, "-w", "5", "-I", h[0], "1", "-j", h[1]); err != nil {
				return fmt.Errorf("%s -I %s: %s", bin, h[0], strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

// carrierDrop removes both chains and the jumps to them, IPv4 and IPv6
// (quantum.sh acct_chains_drop does the same on uninstall).
func carrierDrop() {
	carrierDropFam("iptables")
	carrierDropFam("ip6tables")
}

func carrierDropFam(bin string) {
	// a host that never counted IPv6 has no chains to drop: skip the failing calls
	if out, err := infra.RunCmdTimeoutOut(5*time.Second, bin+"-save", "-t", "filter"); err == nil &&
		strings.Contains(string(out), "*filter") && !strings.Contains(string(out), ":"+acctCarrierIn+" ") {
		return
	}
	for _, h := range [][2]string{{"INPUT", acctCarrierIn}, {"OUTPUT", acctCarrierOut}} {
		_, _ = infra.RunCmdTimeout(5*time.Second, bin, "-w", "5", "-D", h[0], "-j", h[1])
		_, _ = infra.RunCmdTimeout(5*time.Second, bin, "-w", "5", "-F", h[1])
		_, _ = infra.RunCmdTimeout(5*time.Second, bin, "-w", "5", "-X", h[1])
	}
}
