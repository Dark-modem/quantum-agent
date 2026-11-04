module github.com/Dark-modem/quantum-agent

go 1.23

require (
	github.com/Dark-modem/quantum-protocol v0.0.0
	github.com/gorilla/websocket v1.5.3
	golang.org/x/crypto v0.31.0
)

require golang.org/x/sys v0.28.0 // indirect


replace github.com/Dark-modem/quantum-protocol => ../wt-phase2-protocol
