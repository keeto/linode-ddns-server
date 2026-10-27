package linode

import "time"

// SetNow replaces the resolver's clock in tests.
func (r *Resolver) SetNow(now func() time.Time) { r.now = now }

// Locks returns the number of per-record locks currently held or awaited.
func (r *Resolver) Locks() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.locks)
}
