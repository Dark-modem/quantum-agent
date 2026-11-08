package agent

// cli_balancer.go — `quantum-agent balancer status`: the operator-facing
// view of the last balancer pass (phase-9 diagnostic for the weight
// normalization investigation). Prints per target: tunnel key, resolved
// weight, health, exclusion reason, the nft range and the modulus —
// straight from the balancer's persisted snapshot (no nft parsing).

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
)

func cliBalancer(args []string) int {
	if v := os.Getenv("GRE_PANEL_DIR"); v != "" {
		configDir = v // same scoping as the other agent subcommands
	}
	if len(args) == 0 || args[0] != "status" {
		fmt.Fprintln(os.Stderr, "usage: quantum-agent balancer status")
		return 2
	}
	b, err := os.ReadFile(balancerStatusPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "no balancer state yet (the balancer writes it on the first pass with forwards):", err)
		return 1
	}
	var rep balTickReport
	if err := json.Unmarshal(b, &rep); err != nil {
		fmt.Fprintln(os.Stderr, "balancer state unreadable:", err)
		return 1
	}
	if len(rep.Targets) == 0 {
		fmt.Println("no forward targets evaluated (no forwards in the desired state)")
		return 0
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "FORWARD\tTUNNEL\tWEIGHT\tNFT RANGE\tMODULUS\tHEALTH\tREASON\tTARGET ADDR")
	for _, t := range rep.Targets {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%d\t%s\t%s\t%s\n",
			t.Forward, t.Tunnel, t.Weight, orDash(t.NftRange), t.Total,
			orDash(t.Health), t.Reason, orDash(t.Addr))
	}
	w.Flush()
	if len(rep.Errors) > 0 {
		fmt.Println("\nerrors from the last pass:")
		for _, e := range rep.Errors {
			fmt.Println(" -", e)
		}
	}
	return 0
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
