package agent

// The new binary clears the pending marker once it listens; the old binary
// (swap not in effect) leaves it for the guard.
// A rollback by the guard shows in /api/version for a day.
// The guard restores the .bak and restarts when the marker is still there,
// and does nothing once the new binary cleared it.
