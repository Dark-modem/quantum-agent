package engine

import (
	"sort"
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

// Driver returns the driver for id.
func (r *Registry) Driver(id string) (Driver, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.drivers[id]
	return d, ok
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
