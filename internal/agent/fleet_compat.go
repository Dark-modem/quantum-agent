package agent

// Fleet health helpers ported verbatim from the controller monolith
// (fleet.go): the sample-level health of a live record, shared by the
// agent's health code (health.go carries LinkSignals/ComputeHealth).
// fleetHealth is the sample level of a live record. Snapshot-built records carry
// the published (debounced) state; others are computed by ComputeHealth, so
// there is one definition of health.
func fleetHealth(l peerLive) int {
	if l.HealthState != "" {
		return healthLevel(l.HealthState)
	}
	return healthLevel(ComputeHealth(signalsOf(l)).State)
}

func healthName(s int) string {
	switch s {
	case fleetOK:
		return "healthy"
	case fleetDeg:
		return "degraded"
	}
	return "down"
}
