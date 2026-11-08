package engine

import (
	"sort"
	"strings"
	"sync"
)

// Registry maps engine IDs to drivers. It is safe for concurrent use.
type Registry struct {
	mu      sync.RWMutex
	drivers map[string]Driver
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{drivers: map[string]Driver{}}
}

// Register adds a driver. Registering a nil driver or a duplicate ID is
// an error: engine IDs come from untrusted desired state, so a silent
// overwrite would be an injection vector.
func (r *Registry) Register(d Driver) error {
	if d == nil {
		return ErrUnknownEngine
	}
	id := d.ID()
	if id == "" {
		return ErrUnknownEngine
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.drivers[id]; dup {
		return ErrUnknownEngine
	}
	r.drivers[id] = d
	return nil
}

// Driver returns the driver for id. A "base@companion" suffix form
// (00-ADMIN/ENGINE-COMPANION-DESIGN.md — e.g. "wireguard@udp2raw") maps
// to the BASE driver: the companion is metadata + kernel plumbing the
// base driver reads from its own params, never a second Driver.
func (r *Registry) Driver(id string) (Driver, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if d, ok := r.drivers[id]; ok {
		return d, true
	}
	if i := strings.Index(id, "@"); i > 0 {
		if d, ok := r.drivers[id[:i]]; ok {
			return d, true
		}
	}
	return nil, false
}

// BaseEngineID strips the companion suffix ("wireguard@udp2raw" →
// "wireguard"); plain ids pass through.
func BaseEngineID(id string) string {
	if i := strings.Index(id, "@"); i > 0 {
		return id[:i]
	}
	return id
}

// IDs lists registered engine IDs, sorted for stable output.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.drivers))
	for id := range r.drivers {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
