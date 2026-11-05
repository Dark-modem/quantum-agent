package agent

// frp_counters.go — the FRP driver's byte accounting:
//
//   - Wire bytes: per-instance iptables counter chains on the SERVER
//     side only (FRPDRV_ACCT_IN on INPUT matching the instance's data
//     port, FRPDRV_ACCT_OUT on OUTPUT matching its sport). The control
//     port is shared across instances and deliberately not counted —
//     per-instance attribution would be a lie. The client side reports
//     Unknown for the same reason. Same pattern as carrier_traffic.go
//     (QUANTUM_ACCT_*), namespaced so the two never collide.
//   - Payload bytes: the frps web API (webServer in the generated
//     config), proxy-scoped today_traffic_in/out. frp resets those
//     counters daily — documented semantics, never multiplied, never
//     fabricated; any parse failure reports Unknown.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Accounting chain names, namespaced away from the legacy QUANTUM_ACCT_*.
const (
	frpAcctIn  = "FRPDRV_ACCT_IN"
	frpAcctOut = "FRPDRV_ACCT_OUT"
)

// iptables seams (hermetic tests).
var (
	frpIptables = func(args ...string) ([]byte, error) {
		return runCmdTimeout(10*time.Second, "iptables", args...)
	}
	frpIptablesSave = func() ([]byte, error) {
		return runCmdTimeout(15*time.Second, "iptables-save", "-c", "-t", "filter")
	}
)

// frpDashHTTP is the dashboard API client (seam: tests serve httptest).
var frpDashHTTP = func(ctx context.Context, url, user, pass string) (int, []byte, error) {
	c := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.SetBasicAuth(user, pass)
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil || len(body) > (1<<20) {
			break
		}
	}
	return resp.StatusCode, body, nil
}

// frpWireRulesEnsure makes the accounting chains exist and hooks them.
// Safe to call repeatedly; failures are reported (counters go Unknown).
func frpWireRulesEnsure() error {
	if _, err := frpIptables("-N", frpAcctIn); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return err
	}
	if _, err := frpIptables("-N", frpAcctOut); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return err
	}
	if _, err := frpIptables("-C", "INPUT", "-j", frpAcctIn); err != nil {
		if _, err := frpIptables("-A", "INPUT", "-j", frpAcctIn); err != nil {
			return err
		}
	}
	if _, err := frpIptables("-C", "OUTPUT", "-j", frpAcctOut); err != nil {
		if _, err := frpIptables("-A", "OUTPUT", "-j", frpAcctOut); err != nil {
			return err
		}
	}
	return nil
}

func frpAcctComment(tunnelID string) string { return "frpdrv-" + tunnelID }

// frpPortRange renders the iptables port range for the instance's
// allowed data ports ("n" when min==max, "min:max" otherwise).
func frpPortRange(min, max int) string {
	if min == max {
		return strconv.Itoa(min)
	}
	return strconv.Itoa(min) + ":" + strconv.Itoa(max)
}

// frpWireRulesAdd installs the per-instance counter rules (server side).
// The range is the instance's allowed data-port window; the panel
// allocates non-overlapping windows per tunnel.
func frpWireRulesAdd(tunnelID string, allowMin, allowMax int) error {
	if err := frpWireRulesEnsure(); err != nil {
		return err
	}
	cmt := frpAcctComment(tunnelID)
	rng := frpPortRange(allowMin, allowMax)
	if _, err := frpIptables("-A", frpAcctIn, "-p", "tcp", "--dport", rng,
		"-m", "comment", "--comment", cmt); err != nil {
		return err
	}
	if _, err := frpIptables("-A", frpAcctOut, "-p", "tcp", "--sport", rng,
		"-m", "comment", "--comment", cmt); err != nil {
		return err
	}
	return nil
}

// frpWireRulesDel removes exactly this instance's rules (comment-scoped).
func frpWireRulesDel(tunnelID string, allowMin, allowMax int) error {
	cmt := frpAcctComment(tunnelID)
	rng := frpPortRange(allowMin, allowMax)
	var firstErr error
	if _, err := frpIptables("-D", frpAcctIn, "-p", "tcp", "--dport", rng,
		"-m", "comment", "--comment", cmt); err != nil && firstErr == nil {
		firstErr = err
	}
	if _, err := frpIptables("-D", frpAcctOut, "-p", "tcp", "--sport", rng,
		"-m", "comment", "--comment", cmt); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// frpWireBytes reads the instance's counters from iptables-save -c
// (exact bytes, one read, no table lock churn). Line shape:
//
//	-A FRPDRV_ACCT_IN -p tcp -m tcp --dport 34001 -m comment
//	  --comment frpdrv-t1 [ 11:2222 ]
//
// where the bracket holds "pkts:bytes".
func frpWireBytes(tunnelID string, allowMin, allowMax int) (rx, tx uint64, ok bool) {
	out, err := frpIptablesSave()
	if err != nil {
		return 0, 0, false
	}
	cmt := frpAcctComment(tunnelID)
	rng := frpPortRange(allowMin, allowMax)
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, cmt) {
			continue
		}
		var isRx bool
		switch {
		case strings.Contains(line, "--dport "+rng+" "):
			isRx = true
		case strings.Contains(line, "--sport "+rng+" "):
			// outbound leg
		default:
			continue
		}
		i := strings.LastIndex(line, "[")
		j := strings.LastIndex(line, "]")
		if i < 0 || j <= i {
			continue
		}
		// iptables-save -c: the bracket holds one "pkts:bytes" token.
		var v uint64
		parsed := false
		for _, tok := range strings.Fields(line[i+1 : j]) {
			parts := strings.SplitN(tok, ":", 2)
			if len(parts) != 2 {
				continue
			}
			n, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				continue
			}
			v, parsed = n, true
			break
		}
		if !parsed {
			continue
		}
		if isRx {
			rx += v
		} else {
			tx += v
		}
		ok = true
	}
	return rx, tx, ok
}

// frpDashStatus probes the frps web API (used by Health). The endpoint is
// /api/serverinfo on frp >= 0.52 (the legacy /api/status route was removed
// upstream; found by the frp integration test against real frp v0.61).
func frpDashStatus(dashPort int, pass string) (int, error) {
	code, _, err := frpDashHTTP(context.Background(),
		fmt.Sprintf("http://127.0.0.1:%d/api/serverinfo", dashPort), "quantum", pass)
	return code, err
}

// frpPayloadBytes reads proxy-scoped payload counters from the frps web
// API. frp's counters are "today" semantics: they reset daily; the panel
// derives deltas, and a reset looks like a counter restart — documented,
// never multiplied.
func frpPayloadBytes(tunnelID string, dashPort int, pass string) (in, out uint64, ok bool) {
	code, body, err := frpDashHTTP(context.Background(),
		fmt.Sprintf("http://127.0.0.1:%d/api/proxy/tcp", dashPort), "quantum", pass)
	if err != nil || code != 200 {
		return 0, 0, false
	}
	return frpParseProxyTraffic(string(body), tunnelID)
}

// frpParseProxyTraffic finds the tunnel's proxy entry in a frps
// /api/proxy/tcp response and returns its traffic counters.
func frpParseProxyTraffic(body, tunnelID string) (in, out uint64, ok bool) {
	var doc struct {
		Proxies []struct {
			Name            string      `json:"name"`
			TodayTrafficIn  interface{} `json:"today_traffic_in"`
			TodayTrafficOut interface{} `json:"today_traffic_out"`
		} `json:"proxies"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return 0, 0, false
	}
	for _, pr := range doc.Proxies {
		if pr.Name != tunnelID {
			continue
		}
		in, inOK := frpTrafficNumber(pr.TodayTrafficIn)
		out, outOK := frpTrafficNumber(pr.TodayTrafficOut)
		if inOK && outOK {
			return in, out, true
		}
		return 0, 0, false
	}
	return 0, 0, false
}

// frpTrafficNumber accepts number or string JSON forms.
func frpTrafficNumber(v interface{}) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case string:
		v, err := strconv.ParseUint(strings.TrimSpace(n), 10, 64)
		return v, err == nil
	}
	return 0, false
}
