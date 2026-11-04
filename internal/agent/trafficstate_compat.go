package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Traffic-state machinery ported verbatim from the controller monolith
// (dashboard.go @ a1e999c): lifetime totals with per-interface deltas,
// persisted to traffic_state.json. Deliberate deviation: the fallback to
// the dashboard's traffic.json history is omitted — that history file is
// controller-side; a fresh agent starts its lifetime at zero.

var (
	trafficStateMu   sync.Mutex
	lastRawUp        uint64
	lastRawDown      uint64
	lastRawIf        map[string][2]uint64 // per interface: received, transmitted
	lifetimeUp       uint64
	lifetimeDown     uint64
	trafficStateInit bool
	lastSampleAt     time.Time // when the counters of the last speed window were read
	lastStateSave    time.Time
	speedDeltaUp     uint64
	speedDeltaDown   uint64
	currentSpeedUp   float64
	currentSpeedDown float64
)

type persistentTrafficState struct {
	LifetimeUp    uint64 `json:"lifetime_up"`
	LifetimeDown  uint64 `json:"lifetime_down"`
	LifetimeTotal uint64 `json:"lifetime_total"`
	LastRawUp     uint64 `json:"last_raw_up"`
	LastRawDown   uint64 `json:"last_raw_down"`
	// LastIf: each interface's last raw counters, so the traffic it moved
	// while the panel was stopped (an update, a restart) is counted too.
	LastIf  map[string][2]uint64 `json:"last_if,omitempty"`
	SavedAt int64                `json:"saved_at"`
}

func trafficStateFile() string { return filepath.Join(configDir, "traffic_state.json") }

func loadTrafficStateLocked() {
	if trafficStateInit {
		return
	}
	trafficStateInit = true

	// 1. Try dedicated disk database state file
	if data, err := os.ReadFile(trafficStateFile()); err == nil {
		var st persistentTrafficState
		if json.Unmarshal(data, &st) == nil && (st.LifetimeUp > 0 || st.LifetimeDown > 0) {
			lifetimeUp = st.LifetimeUp
			lifetimeDown = st.LifetimeDown
			lastRawUp = st.LastRawUp
			lastRawDown = st.LastRawDown
			// The carrier chains are rebuilt (from 0) when the panel starts:
			// their old reading is no baseline.
			delete(st.LastIf, carrierKey)
			lastRawIf = st.LastIf
			return
		}
	}

	// (The monolith falls back to the dashboard's traffic.json history
	// here; that file does not exist on an agent-only endpoint.)
}

func saveTrafficStateLocked() {
	_ = os.MkdirAll(configDir, 0700)
	st := persistentTrafficState{
		LifetimeUp:    lifetimeUp,
		LifetimeDown:  lifetimeDown,
		LifetimeTotal: lifetimeUp + lifetimeDown,
		LastRawUp:     lastRawUp,
		LastRawDown:   lastRawDown,
		LastIf:        lastRawIf,
		SavedAt:       time.Now().Unix(),
	}
	b := mustJSON(st)
	tmp := trafficStateFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err == nil {
		_ = os.Rename(tmp, trafficStateFile())
	}
	lastStateSave = time.Now()
}

// trafficSample folds one reading of the counters, taken at at, into the
// lifetime totals and the live speed.
//
// Readings must arrive in time order. Two samplers used to share this state
// (the snapshot, with a /proc/net/dev read seconds earlier, and the history
// recorder, reading fresh): a stale reading looked like every counter had
// gone down, was taken for a reset, and each interface's whole counter was
// added to the total again. A reading older than the last one is now ignored.
//
// There is no fallback to the main network interface any more: with no
// tunnel it counted the whole server's traffic as tunnel traffic, and while a
// GRE interface was being recreated it counted the server's traffic for it.
func trafficSample(devData string, carrierRx, carrierTx uint64, carrierOK bool, at time.Time) map[string]any {
	cur := trafficTunnelIfs(devData)
	// Backhaul and Bagher have no interface: their port counters (carrier_traffic.go).
	if carrierOK {
		cur[carrierKey] = [2]uint64{carrierRx, carrierTx}
	}

	trafficStateMu.Lock()
	defer trafficStateMu.Unlock()

	first := !trafficStateInit
	if first {
		loadTrafficStateLocked()
	}
	if !lastSampleAt.IsZero() && at.Before(lastSampleAt) {
		return trafficResultLocked() // out of order: already counted past it
	}

	// Deltas are taken per interface. Comparing one summed counter made the
	// chart spike: when one of several tunnels dropped, the smaller sum was
	// taken for a counter reset and counted again. An interface seen for the
	// first time is only a baseline; one seen before this process started
	// (traffic_state.json) counts what it moved while the panel was down.
	var dU, dD, rawUp, rawDown uint64
	for name, c := range cur {
		rawDown += c[0]
		rawUp += c[1]
		prev, seen := lastRawIf[name]
		if !seen {
			continue
		}
		dD += counterDelta(prev[0], c[0])
		dU += counterDelta(prev[1], c[1])
	}
	lastRawIf = cur

	lifetimeUp += dU
	lifetimeDown += dD
	lastRawUp = rawUp
	lastRawDown = rawDown

	if (dU > 0 || dD > 0 || first) && time.Since(lastStateSave) >= 5*time.Second {
		saveTrafficStateLocked()
	}

	speedDeltaUp += dU
	speedDeltaDown += dD
	if lastSampleAt.IsZero() {
		speedDeltaUp, speedDeltaDown = 0, 0
		lastSampleAt = at
	} else if dt := at.Sub(lastSampleAt).Seconds(); dt >= 1.0 {
		currentSpeedUp = float64(speedDeltaUp) / dt
		currentSpeedDown = float64(speedDeltaDown) / dt
		speedDeltaUp, speedDeltaDown = 0, 0
		lastSampleAt = at
	}
	return trafficResultLocked()
}

func trafficResultLocked() map[string]any {
	return map[string]any{
		"up":         lifetimeUp,
		"down":       lifetimeDown,
		"total":      lifetimeUp + lifetimeDown,
		"speed_up":   currentSpeedUp,
		"speed_down": currentSpeedDown,
	}
}
