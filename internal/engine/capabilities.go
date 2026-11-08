package engine

// capabilities.go — optional driver capabilities (Phase 11, UI data).
// Drivers implement these to feed the agent's v2 report: per-tunnel
// process metrics and per-engine installation state. A driver without
// them simply never appears in those report sections (kernel-only
// engines stay honest "unknown").

// ProcessInfoer is implemented by drivers that supervise an OS process
// for an instance. ProcessPIDs returns the PIDs of the instance's
// process tree (the supervised process; descendants are discovered by
// the sampler). An empty result means "no process now" (kernel-only
// engine, kernel fallback active, or the process is between restarts) —
// the report must then say known=false, not 0.
type ProcessInfoer interface {
	ProcessPIDs(inst Instance) []int
}

// BinaryInfoer is implemented by drivers that can describe their
// installed binary without side effects: path (diagnostic), version
// ("" when unknown) and bytes on disk (0 for kernel tooling). ok=false
// means "not installed / cannot say".
type BinaryInfoer interface {
	BinaryInfo() (path, version string, bytes int64, ok bool)
}
