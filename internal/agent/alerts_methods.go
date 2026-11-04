package agent

// Alert state-change tracker methods ported verbatim from the controller
// monolith (alerts.go). The agent records link state transitions locally;
// delivery stays a no-op (see alertSend).

import "time"

// reset forgets all recorded states; the next observe only primes.
func (t *alertTracker) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.last = map[string]string{}
	t.lastSent = map[string]time.Time{}
	t.primed = false
}

// observe returns the events to send for this tick.
func (t *alertTracker) observe(now time.Time, links []linkSnap, cfg alertConfig) []alertEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []alertEvent
	seen := map[string]bool{}
	for _, l := range links {
		if l.State == "" {
			continue
		}
		seen[l.Name] = true
		prev := t.last[l.Name]
		t.last[l.Name] = l.State
		if !t.primed || prev == l.State || !isAlertWorthy(prev, l.State, cfg.NotifyDegrad) {
			continue
		}
		gap := time.Duration(cfg.MinGapSec) * time.Second
		if now.Sub(t.lastSent[l.Name]) < gap && !t.lastSent[l.Name].IsZero() {
			continue // flapping: suppress, state is still recorded
		}
		t.lastSent[l.Name] = now
		out = append(out, alertEvent{Link: l.Name, From: prev, To: l.State, Why: l.Why, At: now.UTC().Format(time.RFC3339)})
	}
	for k := range t.last {
		if !seen[k] {
			delete(t.last, k)
			delete(t.lastSent, k)
		}
	}
	t.primed = true
	return out
}

func isAlertWorthy(from, to string, degraded bool) bool {
	if from == to || from == "" || to == "" {
		return false
	}
	if degraded {
		return true
	}
	return from == stateDown || to == stateDown
}
