package engine

// params_equal.go — AGENT-24 layer 2 (defense-in-depth): the
// reconcile/preflight no-op decisions compare CANONICALIZED engine_params,
// not raw bytes.
//
// Why: a legacy agent's state file (pre-AGENT-24 MarshalIndent writer)
// re-indents the journaled DesiredV2's nested engine_params, so a boot
// replay can carry byte-different — but semantically identical — params
// against the instances the Manager already runs. Raw-byte comparison
// manufactured phantom "params changed" reloads/restarts on every
// reconnect (service blips + engine counter resets; AGENT-24 report).
// Layer 1 (the compact state writer) stops producing such journals; this
// helper makes the decisions immune to the ones already on disk and to
// any future re-serialization. The restart path itself is untouched —
// only the comparison input changes.

import (
	"bytes"
	"encoding/json"
)

// ParamsEqual reports whether two engine_params documents are the SAME
// params: canonicalized JSON (json.Compact — insignificant whitespace
// elided, everything else verbatim: key order, numbers, escaping), with a
// trimmed-byte fallback when either side is not valid JSON. An empty
// document is not equal to `{}` (the legacy byte semantics, preserved).
func ParamsEqual(a, b []byte) bool {
	ca, aok := canonicalJSON(a)
	cb, bok := canonicalJSON(b)
	if aok && bok {
		return bytes.Equal(ca, cb)
	}
	return bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b))
}

// canonicalJSON compacts one JSON document (whitespace elided, no HTML
// escaping, no re-parsing — bytes otherwise verbatim). ok=false for
// invalid JSON (the caller falls back to a byte comparison).
func canonicalJSON(b []byte) ([]byte, bool) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}
