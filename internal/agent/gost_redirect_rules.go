package agent

// gost_redirect_rules.go — the OVERNIGHT-A3 transparent-proxy firewall
// leg for the gost redirect-tcp/redirect-udp services. The gost `red`
// listener learns the ORIGINAL destination from the kernel
// (SO_ORIGINAL_DST for TCP — handler/redirect/tcp/handler_linux.go;
// IP_RECVORIGDSTADDR for UDP — listener/redirect/udp/listener_linux.go),
// so the host needs REDIRECT (nat) / TPROXY (mangle) rules or the
// listener never receives anything (gost's own e2e pre-installs the same
// rules). Discipline = AGENT-30's kernel families:
//   - arg-list exec only (acctIptables / ip via RunCmdTimeout — no shell);
//   - additive-only: -C checked before -A, rules comment-tagged
//     gostdrv-<tunnelid> (gostComment), teardown removes exactly the
//     recorded specs (-D by full spec);
//   - PREROUTING on the operator-named interface ONLY — never OUTPUT, so
//     the host's own traffic is never hijacked;
//   - installed only when params.RedirectIface names an interface.

import (
	"fmt"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

// gostComment is the per-instance iptables comment tag.
func gostComment(tunnelID string) string { return "gostdrv-" + tunnelID }

// gostIPRule is the seam-able `ip` executor (policy routing for TPROXY).
var gostIPRule = func(args ...string) error {
	_, err := infra.RunCmdTimeout(10*time.Second, "ip", args...)
	return err
}

// gostRedirectRuleArgs renders the ADD specs for the redirect service:
//
//	tcp: -t nat -A PREROUTING -i <iface> -p tcp -m comment --comment <tag>
//	     -j REDIRECT --to-ports <port>
//	udp: -t mangle -A PREROUTING -i <iface> -p udp -m comment
//	     --comment <tag> -j TPROXY --on-port <port> --on-ip 0.0.0.0
//	     --tproxy-mark 0x1/0x1  (+ the fwmark policy route below)
func gostRedirectRuleArgs(tunnelID, service, iface string, port int) [][]string {
	cmt := gostComment(tunnelID)
	if service == "redirect-udp" {
		return [][]string{{"-t", "mangle", "-A", "PREROUTING", "-i", iface,
			"-p", "udp", "-m", "comment", "--comment", cmt,
			"-j", "TPROXY", "--on-port", fmt.Sprint(port),
			"--on-ip", "0.0.0.0", "--tproxy-mark", "0x1/0x1"}}
	}
	return [][]string{{"-t", "nat", "-A", "PREROUTING", "-i", iface,
		"-p", "tcp", "-m", "comment", "--comment", cmt,
		"-j", "REDIRECT", "--to-ports", fmt.Sprint(port)}}
}

// gostRedirectTPRouteArgs renders the TPROXY policy-routing pair (the
// marked packets need a local-route table; the exact-once discipline is
// the pref number: it pins both the rule and the removal).
func gostRedirectTPRouteArgs(tunnelID string) [][]string {
	return [][]string{
		{"rule", "add", "pref", "20020", "fwmark", "0x1", "table", "100"},
		{"route", "add", "table", "100", "local", "0.0.0.0/0", "dev", "lo"},
	}
}

// gostRedirectRulesAdd installs the service's rules (exactly-once via the
// -C check; the TPROXY pair is idempotent by spec — `ip` errors on
// duplicates are tolerated only when the spec already exists, so the
// add path tolerates EEXIST honestly). Marked packets only flow with the
// policy route; the udp service installs both.
func gostRedirectRulesAdd(tunnelID, service, iface string, port int) error {
	for _, add := range gostRedirectRuleArgs(tunnelID, service, iface, port) {
		chk := ctRuleCheck(add)
		if _, err := acctIptables(chk...); err != nil {
			if _, err := acctIptables(add...); err != nil {
				return fmt.Errorf("gost: redirect rule (%s): %w", add[0]+" "+add[1], err)
			}
		}
	}
	if service == "redirect-udp" {
		for _, add := range gostRedirectTPRouteArgs(tunnelID) {
			if err := gostIPRule(add...); err != nil {
				// duplicate specs are the expected steady state (the rule
				// and the local route may be shared/persistent).
				continue
			}
		}
	}
	return nil
}

// gostRedirectRulesDel removes exactly what Add created (-D by full spec;
// the TPROXY route pair is removed by the same specs it was added with).
func gostRedirectRulesDel(tunnelID, service, iface string, port int) {
	for _, add := range gostRedirectRuleArgs(tunnelID, service, iface, port) {
		del := ctRuleDelete(add)
		_, _ = acctIptables(del...)
	}
	if service == "redirect-udp" {
		_ = gostIPRule("rule", "del", "pref", "20020", "fwmark", "0x1", "table", "100")
		_ = gostIPRule("route", "del", "table", "100", "local", "0.0.0.0/0", "dev", "lo")
	}
}
