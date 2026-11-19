package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubHost is a fake host behind the infra.Runner seam. It counts every command so
// tests can assert exactly how much forking a tick or a request costs.
type stubHost struct {
	mu       sync.Mutex
	calls    map[string]int
	ss       string
	pingOK   bool
	pingFail map[string]bool
	block    chan struct{} // when set, `ss` blocks until closed
	n        int
}

func (h *stubHost) count(k string) {
	h.mu.Lock()
	h.calls[k]++
	h.mu.Unlock()
}

func (h *stubHost) get(k string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls[k]
}

func (h *stubHost) total() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, v := range h.calls {
		n += v
	}
	return n
}

func (h *stubHost) reset() {
	h.mu.Lock()
	h.calls = map[string]int{}
	h.mu.Unlock()
}

func (h *stubHost) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := name
	if len(args) > 0 {
		key += ":" + args[0]
	}
	if name == "ping" {
		key += ":" + args[len(args)-1]
	}
	h.count(key)
	switch name {
	case "ss":
		if h.block != nil {
			select {
			case <-h.block:
			case <-ctx.Done():
			}
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		return []byte(h.ss), nil
	case "ip":
		switch args[0] {
		case "tunnel":
			return []byte("gre0: gre/ip remote any local any\n"), nil
		case "-o":
			var b strings.Builder
			for i := 1; i <= h.n; i++ {
				fmt.Fprintf(&b, "6: gre-t%d    inet 10.20.%d.1/30 scope global gre-t%d\\       valid_lft forever\n", i, i, i)
			}
			return []byte(b.String()), nil
		}
	case "systemctl":
		if args[0] == "is-active" {
			var b strings.Builder
			bad := false
			for _, u := range args[1:] {
				if strings.HasPrefix(u, "frps-") {
					b.WriteString("active\n")
				} else {
					b.WriteString("inactive\n")
					bad = true
				}
			}
			if bad {
				return []byte(b.String()), fmt.Errorf("exit status 3")
			}
			return []byte(b.String()), nil
		}
	case "ping":
		h.mu.Lock()
		fail := h.pingFail[args[len(args)-1]] || !h.pingOK
		h.mu.Unlock()
		if fail {
			return []byte("100% packet loss"), fmt.Errorf("exit status 1")
		}
		return []byte("64 bytes"), nil
	}
	return nil, fmt.Errorf("stubHost: unexpected %s %v", name, args)
}

func sessionLine(i int) string {
	return fmt.Sprintf("0 0 192.0.2.10:%d 198.51.100.%d:4%04d\n\t cubic rtt:%d.5/1.0\n", 7000+i, i, i, 10+i)
}

// newStubHost installs n peers (peers.json), a stub procRoot and the infra.Runner.
func TestParsers(t *testing.T) {
	m := parseAddrShow("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n" +
		"5: gre-tunnel    inet 10.10.0.1/30 scope global gre-tunnel\\       valid_lft forever\n" +
		"6: gre-t2@NONE    inet 10.20.2.1/30 scope global gre-t2\\       valid_lft forever\n" +
		"7: eth0    inet 192.0.2.1/24 brd 192.0.2.255 scope global eth0\n7: eth0    inet 192.0.2.9/24 scope global secondary eth0\n")
	if m["gre-tunnel"] != "10.10.0.1/30" || m["gre-t2"] != "10.20.2.1/30" || m["eth0"] != "192.0.2.1/24" || len(m) != 4 {
		t.Fatalf("addr parse wrong: %v", m)
	}
	a, ok := parseIsActive([]string{"a", "b", "c"}, "active\ninactive\nactive\n")
	if !ok || !a["a"] || a["b"] || !a["c"] {
		t.Fatalf("is-active parse wrong: %v %v", a, ok)
	}
	if _, ok := parseIsActive([]string{"a", "b"}, "active\n"); ok {
		t.Fatal("line count mismatch must be reported")
	}
	d := parseNetDev("Inter-|\n face |\n  gre-t1: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0\n    lo: 5 1 0 0 0 0 0 0 6 1 0 0 0 0 0 0\n")
	if d["gre-t1"] != (devCounters{100, 200}) || d["lo"] != (devCounters{5, 6}) {
		t.Fatalf("netdev parse wrong: %v", d)
	}
}

func TestWorkPoolBoundsConcurrencyAndDedupes(t *testing.T) {
	p := newWorkPool(3)
	var mu sync.Mutex
	cur, peak := 0, 0
	release := make(chan struct{})
	for i := 0; i < 12; i++ {
		p.submit(fmt.Sprint("k", i), time.Second, func() {
			mu.Lock()
			cur++
			if cur > peak {
				peak = cur
			}
			mu.Unlock()
			<-release
			mu.Lock()
			cur--
			mu.Unlock()
		})
	}
	p.submit("k0", time.Second, func() { t.Error("duplicate key must be dropped while queued") })
	time.Sleep(50 * time.Millisecond)
	close(release)
	p.wait()
	if peak != 3 {
		t.Fatalf("pool of 3 ran %d at once", peak)
	}
}

func TestWorkPoolHardTimeout(t *testing.T) {
	p := newWorkPool(1)
	block := make(chan struct{})
	defer close(block)
	start := time.Now()
	p.submit("slow", 50*time.Millisecond, func() { <-block })
	p.wait()
	if time.Since(start) > time.Second {
		t.Fatal("a stuck task must be abandoned at its timeout")
	}
}

// A tick passes ss the control-port filter, so a busy host's other sockets are
// never dumped; the base tunnel's port is in it alongside the peers'.
