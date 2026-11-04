package agent

// Main is the quantum-agent binary entry point. With no arguments (or
// "run" via agentCmd) it runs the agent daemon: one outbound connection
// to the controller, tunnels under their own systemd units, and the
// command/allowlist loop. The other subcommands are one-shot CLI.

import "fmt"

func Main(args []string) int {
	if len(args) == 0 {
		return agentRun()
	}
	switch args[0] {
	case "doctor":
		return cliDoctor(args[1:])
	case "netopt":
		// Network Optimization CLI: measure, plan, apply/rollback owned
		// tuning. Never touches SSH, firewall or ports.
		return cliNetOpt(args[1:])
	case "firewall", "ports":
		// Firewall & port engine CLI (Session 1): plan is dry-run,
		// apply/teardown are --yes-gated; all output is JSON.
		return firewallCLI(args[0], args[1:])
	case "--version", "-v", "version":
		fmt.Println(panelVersion)
		return 0
	default:
		return agentCmd(args)
	}
}
