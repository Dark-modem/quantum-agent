package agent

import ()

// TestTrafficLab runs in the hub namespace of tests/test_traffic_lab.sh with
// the real kernel: a GRE main tunnel (gre-tunnel), a GRE peer (gre-p2), a
// Backhaul peer without GRE (port 3090, iptables counters) and a Bagher link
// (this server dials the foreign sshd port). The lab's script moves exact
// byte counts over each; the panel's own snapshot, /api/status,
// /api/dashboard and /api/traffic/usage must report them.
//
//	TRAFFIC_LAB_SCRIPT=<script> TRAFFIC_LAB_FOREIGN=<foreign ip> \
//	TRAFFIC_LAB_EXPECT=main=RX:TX,p2=RX:TX,p3=RX:TX,bagher=RX:TX go test -run TestTrafficLab
