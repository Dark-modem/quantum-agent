package agent

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

func TestIPFamily(t *testing.T) {
	for in, want := range map[string]int{
		"1.2.3.4": 4, " 1.2.3.4 ": 4, "::ffff:1.2.3.4": 4,
		"2001:db8::1": 6, "::1": 6, "fd00::5": 6,
		"": 0, "example.com": 0, "[2001:db8::1]": 0, "1.2.3.4/32": 0, "1.2.3": 0,
	} {
		if got := infra.IPFamily(in); got != want {
			t.Errorf("infra.IPFamily(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestHostPortAndURLHost(t *testing.T) {
	for _, c := range []struct {
		host string
		port int
		hp   string
		uh   string
	}{
		{"1.2.3.4", 443, "1.2.3.4:443", "1.2.3.4"},
		{"2001:db8::1", 8443, "[2001:db8::1]:8443", "[2001:db8::1]"},
		{"[2001:db8::1]", 22, "[2001:db8::1]:22", "[2001:db8::1]"},
		{"example.com", 80, "example.com:80", "example.com"},
		{"0.0.0.0", 9000, "0.0.0.0:9000", "0.0.0.0"},
		{"::", 9000, "[::]:9000", "[::]"},
	} {
		if got := infra.HostPort(c.host, c.port); got != c.hp {
			t.Errorf("infra.HostPort(%q, %d) = %q, want %q", c.host, c.port, got, c.hp)
		}
		if got := infra.URLHost(c.host); got != c.uh {
			t.Errorf("infra.URLHost(%q) = %q, want %q", c.host, got, c.uh)
		}
	}
}

func TestValidPublicIP(t *testing.T) {
	for _, c := range []struct {
		ip   string
		fam  int
		want bool
	}{
		{"203.0.113.7", 4, true},
		{"203.0.113.7", 6, false},
		{"203.0.113.7", 0, true},
		{"10.0.0.1", 4, false},
		{"2001:db8::1", 6, true},
		{"2001:db8::1", 4, false},
		{"fd12:3456::1", 6, false}, // unique local
		{"fe80::1", 6, false},      // link local
		{"::1", 6, false},
		{"ff02::1", 6, false},
		{"::", 6, false},
		{"example.com", 0, false},
	} {
		if got := validPublicIP(c.ip, c.fam); got != c.want {
			t.Errorf("validPublicIP(%q, %d) = %v, want %v", c.ip, c.fam, got, c.want)
		}
	}
}

// TestNoBareHostPort keeps "%s:%d" host:port builders out of the panel: they
// break with IPv6 literals; hostPort / net.JoinHostPort bracket them.
func TestNoBareHostPort(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	bad := regexp.MustCompile(`Sprintf\("(?:[a-z]+://)?%s:%d`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if bad.MatchString(line) && !strings.Contains(line, "typ, ") {
				t.Errorf("%s:%d builds host:port without brackets: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// TestPeerPatchIPv6 went with peers_edit.go in §6.A3 (its
// handlePeersPatch entry point is deleted dead code).
// TestRescueIPv6 went with the rescue engine in §6.A3 (validRemoteIP and
// the rescue nft builders are deleted dead code).

func TestBundlesAndSetupIPv6(t *testing.T) {
	// Backhaul without GRE carries either family; the GRE bundles stay IPv4
	b, err := ParseBundle(MakeBackhaulBundle("2001:db8::1", 3080, "tcpmux", "tok", []string{"443"}))
	if err != nil || b.IranPub != "2001:db8::1" || b.FrpPort != 3080 {
		t.Fatalf("bh1 over IPv6: %+v %v", b, err)
	}
	if _, err := ParseBundle(MakeGreBackhaulBundle("2001:db8::1", 3080, "10.10.10.2", "10.10.10.1", "tcpmux", "tok", nil)); err == nil {
		t.Fatal("gh1 with an IPv6 Iran address accepted")
	}
	if _, err := ParseBundle(MakeBundle("2001:db8::1", 7000, "10.10.10.2", "10.10.10.1", "tok", nil)); err == nil {
		t.Fatal("hsh1 with an IPv6 Iran address accepted")
	}

	// setup: GRE needs IPv4 at both ends, with a clear message
	withTempConfig(t)
	for _, engine := range []string{"frp", "gre-backhaul"} {
		rr := httptest.NewRecorder()
		handleSetupPost(rr, httptest.NewRequest("POST", "/api/setup", strings.NewReader(
			`{"role":"iran","engine":"`+engine+`","local_public":"2001:db8::1","remote_public":"2001:db8::2","local_gre":"10.10.10.2","peer_gre":"10.10.10.1","frp_port":7000}`)))
		if rr.Code != 400 || !strings.Contains(rr.Body.String(), "IPv4") {
			t.Errorf("%s over IPv6: %d %s", engine, rr.Code, rr.Body.String())
		}
	}
}
