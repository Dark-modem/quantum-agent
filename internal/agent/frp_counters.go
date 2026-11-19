package agent

// frp_counters.go — the FRP driver's PAYLOAD accounting (the frps web API).
//
// The driver's WIRE accounting (the FRPDRV_ACCT_* iptables chains) lives in
// acct.go since §6.A2, together with the QUANTUM_ACCT_* carrier machinery —
// one accounting layer, two namespaces. What remains here is genuinely
// frp-specific:
//
//   - Payload bytes: the frps web API (webServer in the generated
//     config), proxy-scoped today_traffic_in/out. frp resets those
//     counters daily — documented semantics, never multiplied, never
//     fabricated; any parse failure reports Unknown.
//   - The dashboard status probe Health uses.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
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
