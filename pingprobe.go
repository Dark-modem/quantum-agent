package main

// probePing ported VERBATIM from the controller monolith (benchmark.go):
// low-rate ICMP probe helper used by pathtest diagnostics.

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func probePing(ctx context.Context, host string, count int) (avgRTT, minRTT, maxRTT, loss, jitter float64, err error) {
	if host == "" {
		return 0, 0, 0, 100.0, 0, fmt.Errorf("empty host")
	}

	cmd := exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), "-W", "2", host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, 0, 100.0, 0, fmt.Errorf("ping failed: %v", err)
	}

	str := string(out)
	// Parse packet loss
	if idx := strings.Index(str, "% packet loss"); idx != -1 {
		part := str[:idx]
		if lastSpace := strings.LastIndex(part, " "); lastSpace != -1 {
			lossVal, _ := strconv.ParseFloat(strings.TrimSpace(part[lastSpace:]), 64)
			loss = lossVal
		}
	}

	// Parse rtt min/avg/max/mdev
	if idx := strings.Index(str, "rtt min/avg/max/mdev = "); idx != -1 {
		sub := str[idx+23:]
		if end := strings.Index(sub, " "); end != -1 {
			parts := strings.Split(sub[:end], "/")
			if len(parts) >= 4 {
				minRTT, _ = strconv.ParseFloat(parts[0], 64)
				avgRTT, _ = strconv.ParseFloat(parts[1], 64)
				maxRTT, _ = strconv.ParseFloat(parts[2], 64)
				jitter, _ = strconv.ParseFloat(parts[3], 64)
			}
		}
	} else if strings.Contains(str, "time=") {
		// Single or fallback parse
		avgRTT = 15.0
		minRTT = 15.0
		maxRTT = 15.0
	}

	return avgRTT, minRTT, maxRTT, loss, jitter, nil
}
