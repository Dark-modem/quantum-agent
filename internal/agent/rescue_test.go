package agent

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestParsePortList(t *testing.T) {
	ok := map[string][]int{
		"1020, 1030 1040": {1020, 1030, 1040},
		"2000-2003":       {2000, 2001, 2002, 2003},
		"443,443,80":      {80, 443},
		"1;2\n3":          {1, 2, 3},
	}
	for in, want := range ok {
		got, err := parsePortList(in)
		if err != nil || len(got) != len(want) {
			t.Fatalf("%q => %v, %v want %v", in, got, err, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%q => %v want %v", in, got, want)
			}
		}
	}
	for _, bad := range []string{"", "  ", "0", "65536", "abc", "10-5", "1-100", "1,2,x", "-5", "80-"} {
		if _, err := parsePortList(bad); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
	var big []string
	for i := 1; i <= 70; i++ {
		big = append(big, strconv.Itoa(2000+i))
	}
	if _, err := parsePortList(strings.Join(big, ",")); err == nil {
		t.Fatal("more than 64 ports must be rejected")
	}
}

func TestValidRemoteIP(t *testing.T) {
	for _, in := range []string{"203.0.113.102", " 198.51.100.22 ", "2001:db8::1"} {
		if _, err := validRemoteIP(in); err != nil {
			t.Fatalf("%q should pass: %v", in, err)
		}
	}
	for _, in := range []string{"", "127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "::1", "fe80::1", "ff02::1", "example.com", "1.2.3", "1.2.3.4; rm -rf /", "1.2.3.4\nfoo"} {
		if _, err := validRemoteIP(in); err == nil {
			t.Fatalf("%q must be rejected", in)
		}
	}
}

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

func goodCode(t *testing.T) (rescueState, string) {
	t.Helper()
	st := rescueState{CtrlPort: 31000, Token: randHex(24), Secret: randHex(16), Ports: []int{1020, 1030, 1040}}
	return st, rescueEncode(st, "198.51.100.22")
}

func TestRescueCodeRoundTripAndHostile(t *testing.T) {
	st, code := goodCode(t)
	c, err := rescueDecode(code)
	if err != nil || c.IP != "198.51.100.22" || c.CPort != 31000 || c.Token != st.Token || len(c.Ports) != 3 {
		t.Fatalf("round trip failed: %+v %v", c, err)
	}
	bad := []string{
		"", "hrc1_", "hrc1_!!!", "nope", strings.Repeat("A", 5000),
		rescueEncode(rescueState{CtrlPort: 0, Token: st.Token, Secret: st.Secret, Ports: []int{1}}, "198.51.100.22"),
		rescueEncode(rescueState{CtrlPort: 99999, Token: st.Token, Secret: st.Secret, Ports: []int{1}}, "198.51.100.22"),
		rescueEncode(rescueState{CtrlPort: 5, Token: "short", Secret: st.Secret, Ports: []int{1}}, "198.51.100.22"),
		rescueEncode(rescueState{CtrlPort: 5, Token: st.Token, Secret: st.Secret, Ports: []int{1}}, "127.0.0.1"),
		rescueEncode(rescueState{CtrlPort: 5, Token: st.Token, Secret: st.Secret, Ports: []int{70000}}, "198.51.100.22"),
		rescueEncode(rescueState{CtrlPort: 5, Token: st.Token, Secret: st.Secret, Ports: nil}, "198.51.100.22"),
		// config injection through the token must never reach a TOML file
		rescueEncode(rescueState{CtrlPort: 5, Token: "aa\"\nbindPort = 22\n#xx", Secret: st.Secret, Ports: []int{1}}, "198.51.100.22"),
	}
	for i, b := range bad {
		if _, err := rescueDecode(b); err == nil {
			t.Fatalf("hostile code %d must be rejected", i)
		}
	}
}

func TestRenderedFilesAreWellFormed(t *testing.T) {
	frps := rescueFrpsToml(31000, "tok")
	for _, w := range []string{"bindPort = 31000", `auth.token = "tok"`} {
		if !strings.Contains(frps, w) {
			t.Fatalf("frps missing %q:\n%s", w, frps)
		}
	}
	o := rescueOriginFrpcToml(31000, "tok", "sec", []int{1020, 1030})
	if strings.Count(o, "[[proxies]]") != 4 || !strings.Contains(o, `type = "sudp"`) || !strings.Contains(o, `localIP = "127.0.0.1"`) {
		t.Fatalf("origin frpc wrong:\n%s", o)
	}
	e := rescueEntryFrpcToml("198.51.100.22", 31000, "tok", "sec", []int{1020})
	if strings.Count(e, "[[visitors]]") != 2 || !strings.Contains(e, `serverAddr = "198.51.100.22"`) || !strings.Contains(e, "bindPort = 1020") {
		t.Fatalf("entry frpc wrong:\n%s", e)
	}
	fw := rescueFwNft(31000, "203.0.113.102")
	if !strings.Contains(fw, "tcp dport 31000 ip saddr != 203.0.113.102") || !strings.Contains(fw, `iifname "lo" accept`) {
		t.Fatalf("firewall wrong:\n%s", fw)
	}
	dn := rescueDnatNft("198.51.100.22", []int{1020, 1030})
	if !strings.Contains(dn, "fib daddr type local meta l4proto { tcp, udp } th dport { 1020, 1030 } dnat ip to 198.51.100.22") || !strings.Contains(dn, "ip daddr 198.51.100.22 meta l4proto { tcp, udp } th dport { 1020, 1030 } masquerade") {
		t.Fatalf("dnat wrong:\n%s", dn)
	}
}

// fakeSystem swaps runCmd/ dirs so enable/disable runs for real on disk
// without touching systemd.
