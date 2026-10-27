package server

import (
	"net/netip"
	"sync"
	"time"
)

// Failed logins are limited per client with a token bucket: a client may fail
// authBurst times in a row and then regains one attempt every authRefill.
const (
	authBurst  = 10
	authRefill = time.Minute
	// limiterPrune is the number of tracked clients at which clients whose
	// buckets have refilled are dropped.
	limiterPrune = 10000
)

type bucket struct {
	tokens float64
	last   time.Time
}

// failLimiter tracks failed authentication attempts per client. It is safe for
// concurrent use.
type failLimiter struct {
	now func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

func newFailLimiter() *failLimiter {
	return &failLimiter{now: time.Now, buckets: make(map[string]*bucket)}
}

// limiterKey groups a client address: IPv6 clients by /64, since a single
// host usually controls the whole prefix.
func limiterKey(client string) string {
	a, err := netip.ParseAddr(client)
	if err != nil || !a.Is6() {
		return client
	}
	p, _ := a.Prefix(64)
	return p.String()
}

// blocked reports whether the client has no attempts left and, if so, how
// long until it has one.
func (l *failLimiter) blocked(client string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[limiterKey(client)]
	if !ok {
		return 0, false
	}
	l.refill(b)
	if b.tokens >= 1 {
		return 0, false
	}
	return time.Duration((1 - b.tokens) * float64(authRefill)), true
}

// fail records a failed attempt by the client.
func (l *failLimiter) fail(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := limiterKey(client)
	b, ok := l.buckets[k]
	if !ok {
		if len(l.buckets) >= limiterPrune {
			l.prune()
		}
		b = &bucket{tokens: authBurst, last: l.now()}
		l.buckets[k] = b
	}
	l.refill(b)
	b.tokens = max(b.tokens-1, 0)
}

func (l *failLimiter) refill(b *bucket) {
	now := l.now()
	b.tokens = min(authBurst, b.tokens+float64(now.Sub(b.last))/float64(authRefill))
	b.last = now
}

// prune drops clients that are back to a full bucket.
func (l *failLimiter) prune() {
	for k, b := range l.buckets {
		if l.refill(b); b.tokens >= authBurst {
			delete(l.buckets, k)
		}
	}
}
