package infra

import (
	"os"
	"strconv"
	"strings"
)

// AgentDevCounters is one interface's cumulative rx/tx bytes.
type AgentDevCounters struct{ Rx, Tx uint64 }

// AgentReadNetDev reads the kernel interface counters; seam for tests.
var AgentReadNetDev = func() (string, error) {
	b, err := os.ReadFile("/proc/net/dev")
	return string(b), err
}

// AgentParseNetDev parses /proc/net/dev rows into name → rx/tx bytes.
func AgentParseNetDev(data string) map[string]AgentDevCounters {
	m := map[string]AgentDevCounters{}
	for _, line := range strings.Split(data, "\n") {
		name, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		rx, e1 := strconv.ParseUint(f[0], 10, 64)
		tx, e2 := strconv.ParseUint(f[8], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		m[strings.TrimSpace(name)] = AgentDevCounters{rx, tx}
	}
	return m
}
