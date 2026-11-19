package agent

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

// §6.A3 removed the rescue engine (parsePortList/validRemoteIP, the code
// encode/decode, the unit builders, the handlers); the tests that drove
// those entry points went with it. TestRescueVerdict and TestClassifyDial
// cover the surviving pure decision rules.

func TestRescueVerdict(t *testing.T) {
	cases := []struct {
		ping  bool
		ports map[int]string
		want  string
	}{
		{true, map[int]string{7777: "open"}, "ok"},
		{false, map[int]string{7777: "timeout", 22: "open"}, "ok"},
		{true, map[int]string{7777: "timeout", 22: "timeout"}, "one_way_block"},
		{false, map[int]string{7777: "timeout"}, "host_unreachable"},
		{true, map[int]string{7777: "refused"}, "service_down"},
		{false, map[int]string{7777: "refused", 22: "timeout"}, "service_down"},
		{true, map[int]string{}, "unknown"},
	}
	for i, c := range cases {
		if got := rescueVerdict(c.ping, c.ports); got != c.want {
			t.Fatalf("case %d: got %s want %s", i, got, c.want)
		}
	}
}

func TestClassifyDial(t *testing.T) {
	if classifyDial(nil) != "open" {
		t.Fatal("nil => open")
	}
	if classifyDial(&net.OpError{Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}) != "refused" {
		t.Fatal("ECONNREFUSED => refused")
	}
	if classifyDial(errors.New("i/o timeout")) != "timeout" {
		t.Fatal("other => timeout")
	}
}
