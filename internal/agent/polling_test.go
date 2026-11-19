package agent

// The C2.7 polling policy lives in index.html with no JS harness; this
// string guard keeps its load-bearing pieces from being silently removed.
// Counts are minimums: several loops legitimately repeat the same guard.
