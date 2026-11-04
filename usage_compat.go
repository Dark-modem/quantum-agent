package main

// Usage-ledger types ported verbatim from the controller monolith
// (topology_usage.go @ a1e999c). The agent keeps its own ledger
// (traffic_usage.go); these give it the controller's response shapes and
// the server-totals series. Topology ROWS stay empty here — grouping is
// controller-side.

import "time"

type usageAmount struct {
	Rx    uint64 `json:"rx"`
	Tx    uint64 `json:"tx"`
	Total uint64 `json:"total"`
	Known bool   `json:"known"`
}

type topologyUsageRow struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	usageAmount
	TunnelCount int `json:"tunnel_count"`
}

type serverUsageTotal struct {
	usageAmount
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	Available bool   `json:"available"`
	StartedAt int64  `json:"started_at"`
}

type serverUsageWindow struct {
	usageAmount
	Points []usagePoint  `json:"points"`
	Days   []usageDayRow `json:"days"`
}

// snapshotEvery is the snapshot cadence (monolith snapshot.go).
const snapshotEvery = 5 * time.Second

// usageKnown reports whether a link's counters are fresh enough to trust
// (ported verbatim from the monolith topology_usage.go).
func usageKnown(l *usageLink, now time.Time) bool {
	if l == nil || l.Seen == 0 {
		return false
	}
	if l.Known != nil && !*l.Known {
		return false
	}
	// v1 files did not store Measured; existing points prove measurement.
	if !l.Measured && len(l.Points) == 0 && len(l.Days) == 0 {
		return false
	}
	fresh := 2 * time.Minute
	if 3*snapshotEvery > fresh {
		fresh = 3 * snapshotEvery
	}
	return now.Unix()-l.Seen <= int64(fresh.Seconds())
}

// serverTotalsLocked folds the server-physical-traffic series into the
// API shapes (ported verbatim from the monolith topology_usage.go).
func (s *usageStore) serverTotalsLocked(now time.Time, window time.Duration, step int64) (serverUsageTotal, serverUsageWindow) {
	l := s.links[usageServerKey]
	total := serverUsageTotal{}
	out := serverUsageWindow{Points: []usagePoint{}, Days: []usageDayRow{}}
	if l == nil {
		return total, out
	}
	total.usageAmount = usageAmount{Rx: l.CumulativeRx, Tx: l.CumulativeTx, Total: l.CumulativeRx + l.CumulativeTx, Known: usageKnown(l, now)}
	total.RxBytes, total.TxBytes, total.Available, total.StartedAt = total.Rx, total.Tx, total.Known, l.StartedAt
	sr, _ := s.seriesLocked(usageServerKey, now, window, step)
	out.usageAmount = usageAmount{Rx: sr.Rx, Tx: sr.Tx, Total: sr.Rx + sr.Tx, Known: total.Known}
	out.Points, out.Days = sr.Points, sr.Days
	return total, out
}

// The metrics collector calls ONE of these hooks once per snapshot. Never call
// them from an HTTP handler, or feed physical counters into usageOnSnapshot.
// The per-interface hook is preferred: independent resets/new interfaces must
// not turn a smaller aggregate into a reset of every surviving NIC.
func observeServerUsage(at time.Time, rx, tx uint64, known bool) {
	if !known {
		trafficUsage.observe(usageServerKey, "Server physical traffic", at, nil, nil)
		return
	}
	trafficUsage.observe(usageServerKey, "Server physical traffic", at, &rx, &tx)
}

func observeServerInterfaceUsage(at time.Time, counters map[string][2]uint64, known bool) {
	trafficUsage.observeIfsKnown(usageServerKey, "Server physical traffic", at, counters, known)
}
