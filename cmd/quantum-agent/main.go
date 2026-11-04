// Command quantum-agent is the light agent installed on every tunnel
// server (Iran and foreign). It establishes tunnels, executes panel
// commands over one outbound authenticated WSS, and keeps working
// without the panel. The implementation lives in internal/agent.
package main

import (
	"os"

	"github.com/Dark-modem/quantum-agent/internal/agent"
)

func main() {
	os.Exit(agent.Main(os.Args[1:]))
}
