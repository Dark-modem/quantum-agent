package agent

// Spoof Tunnel (ParsaKSH/spoof-tunnel) was a bidirectional IP-spoofing UDP
// pipe the legacy monolith wrapped in WireGuard. REFACTOR-PLAN-AGENT §6.A3
// (deadcode RTA: all 32 funcs of the old spoof.go unreachable from main, its
// handler layer unrouted since the legacy HTTP surface was dropped) removed
// the machinery; what survives is the ONE symbol live code still reads:
//
//	spoofIface — the historical WireGuard interface name "wg-spoof",
//	compared by agent_compat.go's isTunnelInterface so an interface left
//	over from an old spoof deployment is still classified as a tunnel.
//
// Removing THAT comparison would change interface classification for hosts
// that ever ran spoof — a behavior change, hence out of A3's scope.

// spoofIface is the interface name the legacy spoof tunnel used.
var spoofIface = "wg-spoof"
