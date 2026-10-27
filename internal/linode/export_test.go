package linode

import "time"

// SetNow replaces the resolver's clock in tests.
func (r *Resolver) SetNow(now func() time.Time) { r.now = now }
