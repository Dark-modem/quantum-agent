package main

// Small helpers ported verbatim from the controller monolith
// (@ a1e999c) that the extracted agent tree kept calling. Grouped here
// so each port states its origin; none of these carry controller-only
// behavior.

import (
	"encoding/json"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- main.go: misc helpers ----

// mustJSON marshals indented JSON, ignoring errors (best-effort output).
func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

// portFree reports whether a TCP port is bindable right now.
func portFree(port int) bool {
	ln, err := net.Listen("tcp", panelBindAddr(port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// panelBindAddr builds the listen address for listeners,
// honoring panel.json bind_host (reverse-proxy mode: "127.0.0.1" keeps
// the panel private behind nginx). Empty binds all interfaces.
func panelBindAddr(port int) string {
	host := strings.TrimSpace(cfg.BindHost)
	if host == "" {
		return fmt.Sprintf(":%d", port)
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// ---- fleet.go: cached public IP ----

var (
	pubIPMu   sync.Mutex
	pubIPVal  string
	pubIPTime time.Time
)

// detectPublicIPCached is detectPublicIP at most every 10 minutes (every
// minute while there is none), for callers on a timer like snapshots.
func detectPublicIPCached() string {
	pubIPMu.Lock()
	defer pubIPMu.Unlock()
	if pubIPVal != "" && time.Since(pubIPTime) < 10*time.Minute {
		return pubIPVal
	}
	if pubIPVal == "" && time.Since(pubIPTime) < time.Minute {
		return "" // recent failed lookup: do not retry on every snapshot tick
	}
	pubIPTime = time.Now()
	if v := detectPublicIP(); v != "" {
		pubIPVal = v
	}
	return pubIPVal
}

// ---- dashboard.go: host memory snapshot ----

// memInfo reads /proc/meminfo into the dashboard's memory shape.
func memInfo() map[string]any {
	out := map[string]any{"used": nil, "total": nil, "pct": nil, "cache": nil}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return out
	}
	var total, avail, cached, buffers, sreclaim uint64
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		case "Cached:":
			cached = v * 1024
		case "Buffers:":
			buffers = v * 1024
		case "SReclaimable:":
			sreclaim = v * 1024
		}
	}
	if total > 0 {
		out["total"] = total
		used := total - avail
		out["used"] = used
		out["pct"] = float64(used) / float64(total) * 100.0
		out["cache"] = cached + buffers + sreclaim
	}
	return out
}

// ---- tls.go: certificate presence and expiry (read-only parts) ----

func tlsDir() string      { return filepath.Join(configDir, "tls") }
func tlsCertFile() string { return filepath.Join(tlsDir(), "server.crt") }
func tlsKeyFile() string  { return filepath.Join(tlsDir(), "server.key") }

// tlsHasCert reports whether a TLS certificate and key are installed.
func tlsHasCert() bool {
	if _, err := os.Stat(tlsCertFile()); err != nil {
		return false
	}
	if _, err := os.Stat(tlsKeyFile()); err != nil {
		return false
	}
	return true
}

// tlsCertExpiry parses the leaf certificate's NotAfter and issuer.
func tlsCertExpiry() (time.Time, string, error) {
	data, err := os.ReadFile(tlsCertFile())
	if err != nil {
		return time.Time{}, "", err
	}
	var blk *pem.Block
	for {
		blk, data = pem.Decode(data)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				continue
			}
			return c.NotAfter, c.Issuer.CommonName, nil
		}
	}
	return time.Time{}, "", fmt.Errorf("no certificate found")
}
