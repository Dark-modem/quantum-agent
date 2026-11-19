// Package infra is the leaf package of shared host utilities that the agent
// runtime (internal/agent), the balancer (internal/balancer) and the engine
// drivers use: external-command execution, the config directory, IP/host
// helpers, /proc parsing and the public-IP detection family. The drivers
// still live in internal/agent — the planned internal/engines split was
// deferred per the REFACTOR-A4 stop-rule.
//
// REFACTOR-PLAN-AGENT §6.A4: this leaf exists so internal/balancer (and a
// future internal/engines package) never imports internal/agent.
//
// SWAPPABLE SEAMS: Runner (external commands), CarrierLookup (DNS) and the
// ConfigDir variable are package-level so tests still point them at temp
// dirs — same semantics as before the move, one package up.
package infra

import (
	"context"
	"errors"
	"log"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// ConfigDir is the agent's configuration directory.
var ConfigDir = "/etc/quantum-agent"

// EngineUnitDir is the systemd unit directory the engine units install to.
var EngineUnitDir = "/etc/systemd/system"

type cmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

type stdoutOnlyKey struct{}

// Runner is the single seam for external commands that go through
// RunCmdTimeout. Tests swap it to stub the host.
var Runner cmdRunner = ExecRunner

// ExecRunner is the real runner implementation, exported for lab tests.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if ctx.Value(stdoutOnlyKey{}) != nil {
		return cmd.Output()
	}
	return cmd.CombinedOutput()
}

// execStat accumulates per-command counters. buckets is a 60-slot per-second
// ring used for calls_last_60s without storing every call.
type execStat struct {
	calls    uint64
	total    time.Duration
	max      time.Duration
	timeouts uint64
	errors   uint64
	buckets  [60]struct {
		sec int64
		n   uint64
	}
}

var (
	execMu    sync.Mutex
	execStats = map[string]*execStat{}
)

func recordExec(name string, d time.Duration, err error, timedOut bool) {
	now := time.Now().Unix()
	execMu.Lock()
	defer execMu.Unlock()
	s := execStats[name]
	if s == nil {
		s = &execStat{}
		execStats[name] = s
	}
	s.calls++
	s.total += d
	if d > s.max {
		s.max = d
	}
	if timedOut {
		s.timeouts++
	}
	if err != nil {
		s.errors++
	}
	b := &s.buckets[now%60]
	if b.sec != now {
		b.sec, b.n = now, 0
	}
	b.n++
}

func runCmdTimeoutCtx(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	out, err := Runner(ctx, name, args...)
	timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
	var exitErr *exec.ExitError
	answer := errors.As(err, &exitErr) && exitIsAnswer(name, args)
	if answer {
		recordExec(name, time.Since(start), nil, false)
	} else {
		recordExec(name, time.Since(start), err, timedOut)
	}
	if err != nil && !timedOut && !answer {
		var exitCode = -1
		if exitErr != nil {
			exitCode = exitErr.ExitCode()
		}
		trimmed := strings.Join(strings.Fields(string(out)), " ") // one journal line
		if len(trimmed) > 120 {
			trimmed = trimmed[:120] + "..."
		}
		if trimmed != "" {
			log.Printf("[CMD-ERROR] command %q failed (exit %d): %v | output: %s", name, exitCode, err, trimmed)
		} else {
			log.Printf("[CMD-ERROR] command %q failed (exit %d): %v", name, exitCode, err)
		}
	}
	return out, err
}

// exitIsAnswer reports whether a non-zero exit of this command is its answer
// rather than a failure: `systemctl is-active` exits 3 for a stopped unit and
// 4 for one that is not installed, which the status pollers ask every few
// seconds. Logging those filled the activity stream with false errors.
func exitIsAnswer(name string, args []string) bool {
	if name != "systemctl" || len(args) == 0 {
		return false
	}
	switch args[0] {
	case "is-active", "is-enabled", "is-failed":
		return true
	}
	return false
}

// RunCmdTimeout runs name with a hard timeout (combined stdout+stderr), counting the
// call in the exec metrics.
func RunCmdTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	return runCmdTimeoutCtx(context.Background(), timeout, name, args...)
}

// RunCmdTimeoutOut is RunCmdTimeout returning stdout only (stderr is dropped).
func RunCmdTimeoutOut(timeout time.Duration, name string, args ...string) ([]byte, error) {
	return runCmdTimeoutCtx(context.WithValue(context.Background(), stdoutOnlyKey{}, true), timeout, name, args...)
}

type execStatJSON struct {
	Command      string  `json:"command"`
	Calls        uint64  `json:"calls"`
	AvgMs        float64 `json:"avg_ms"`
	MaxMs        float64 `json:"max_ms"`
	Timeouts     uint64  `json:"timeouts"`
	Errors       uint64  `json:"errors"`
	CallsLast60s uint64  `json:"calls_last_60s"`
}

// ExecSnapshot returns the per-command exec counters (the diag view).
func ExecSnapshot() []execStatJSON {
	now := time.Now().Unix()
	execMu.Lock()
	defer execMu.Unlock()
	res := make([]execStatJSON, 0, len(execStats))
	for name, s := range execStats {
		e := execStatJSON{Command: name, Calls: s.calls, MaxMs: ms(s.max), Timeouts: s.timeouts, Errors: s.errors}
		if s.calls > 0 {
			e.AvgMs = ms(s.total) / float64(s.calls)
		}
		for _, b := range s.buckets {
			if now-b.sec < 60 && b.sec <= now {
				e.CallsLast60s += b.n
			}
		}
		res = append(res, e)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Command < res[j].Command })
	return res
}

// ResetExecStats clears the exec counters (test helper).
func ResetExecStats() {
	execMu.Lock()
	execStats = map[string]*execStat{}
	execMu.Unlock()
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
