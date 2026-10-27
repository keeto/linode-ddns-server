package linode

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// DefaultCacheTTL bounds how long a resolved record (and its last known target)
// is trusted before it is looked up again.
const DefaultCacheTTL = 5 * time.Minute

var (
	// ErrNoHost means no zone or no record of the requested type exists for the host.
	ErrNoHost = errors.New("no matching domain record")
	// ErrAmbiguous means more than one record of the requested type exists for the host.
	ErrAmbiguous = errors.New("multiple matching domain records")
)

type cacheKey struct {
	token, host, typ string
}

type entry struct {
	domainID, recordID int
	target             string
	fetched            time.Time
}

// Resolver maps hostnames to Linode A/AAAA records and updates them. It is
// safe for concurrent use; operations on the same record are serialized.
type Resolver struct {
	Client *Client
	TTL    time.Duration
	now    func() time.Time

	mu    sync.Mutex
	cache map[cacheKey]entry
	locks map[cacheKey]*sync.Mutex
}

func NewResolver(c *Client) *Resolver {
	return &Resolver{Client: c, TTL: DefaultCacheTTL}
}

// Current returns the live target of host's record of type typ ("A" or "AAAA"),
// bypassing the cache.
func (r *Resolver) Current(ctx context.Context, token, host, typ string) (string, error) {
	k := cacheKey{token, host, typ}
	unlock := r.lock(k)
	defer unlock()

	e, err := r.resolve(ctx, k)
	if err != nil {
		return "", err
	}
	return e.target, nil
}

// Update points host's record of type typ at ip. It reports whether the record
// was changed; false means it already held ip.
func (r *Resolver) Update(ctx context.Context, token, host, typ string, ip netip.Addr) (bool, error) {
	k := cacheKey{token, host, typ}
	unlock := r.lock(k)
	defer unlock()

	e, cached := r.cached(k)
	if !cached {
		var err error
		if e, err = r.resolve(ctx, k); err != nil {
			return false, err
		}
	}
	if sameAddr(e.target, ip) {
		return false, nil
	}

	_, err := r.Client.UpdateRecordTarget(ctx, token, e.domainID, e.recordID, ip.String())
	if errors.Is(err, ErrNotFound) && cached {
		// The record was deleted or recreated since it was cached.
		if e, err = r.resolve(ctx, k); err != nil {
			return false, err
		}
		if sameAddr(e.target, ip) {
			return false, nil
		}
		_, err = r.Client.UpdateRecordTarget(ctx, token, e.domainID, e.recordID, ip.String())
	}
	if err != nil {
		r.forget(k)
		if errors.Is(err, ErrNotFound) {
			return false, ErrNoHost
		}
		return false, err
	}

	e.target = ip.String()
	e.fetched = r.clock()
	r.store(k, e)
	return true, nil
}

// resolve looks the record up via the API and caches the result.
func (r *Resolver) resolve(ctx context.Context, k cacheKey) (entry, error) {
	r.forget(k)

	domains, err := r.Client.ListDomains(ctx, k.token)
	if err != nil {
		return entry{}, err
	}
	zone, ok := matchZone(domains, k.host)
	if !ok {
		return entry{}, ErrNoHost
	}
	rel := strings.TrimSuffix(strings.TrimSuffix(k.host, strings.ToLower(zone.Domain)), ".")

	records, err := r.Client.ListRecords(ctx, k.token, zone.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return entry{}, ErrNoHost
		}
		return entry{}, err
	}
	var found *Record
	for i, rec := range records {
		if rec.Type != k.typ || !nameMatches(rec.Name, rel, k.host) {
			continue
		}
		if found != nil {
			return entry{}, fmt.Errorf("%w: %s %s", ErrAmbiguous, k.typ, k.host)
		}
		found = &records[i]
	}
	if found == nil {
		return entry{}, ErrNoHost
	}

	e := entry{domainID: zone.ID, recordID: found.ID, target: found.Target, fetched: r.clock()}
	r.store(k, e)
	return e, nil
}

// matchZone returns the domain that is the longest suffix of host.
func matchZone(domains []Domain, host string) (Domain, bool) {
	var best Domain
	for _, d := range domains {
		name := strings.TrimSuffix(strings.ToLower(d.Domain), ".")
		if (host == name || strings.HasSuffix(host, "."+name)) && len(name) > len(best.Domain) {
			best = Domain{ID: d.ID, Domain: name}
		}
	}
	return best, best.Domain != ""
}

// nameMatches reports whether a record name refers to the host. Linode stores
// names relative to the zone ("" for the apex), but a fully qualified name is
// accepted as well.
func nameMatches(name, rel, host string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return name == rel || name == host
}

func sameAddr(target string, ip netip.Addr) bool {
	t, err := netip.ParseAddr(target)
	return err == nil && t == ip
}

func (r *Resolver) lock(k cacheKey) func() {
	r.mu.Lock()
	if r.locks == nil {
		r.locks = make(map[cacheKey]*sync.Mutex)
	}
	l, ok := r.locks[k]
	if !ok {
		l = &sync.Mutex{}
		r.locks[k] = l
	}
	r.mu.Unlock()
	l.Lock()
	return l.Unlock
}

func (r *Resolver) cached(k cacheKey) (entry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[k]
	if !ok || r.clock().Sub(e.fetched) >= r.TTL {
		return entry{}, false
	}
	return e, true
}

func (r *Resolver) store(k cacheKey, e entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil {
		r.cache = make(map[cacheKey]entry)
	}
	r.cache[k] = e
}

func (r *Resolver) forget(k cacheKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cache, k)
}

func (r *Resolver) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}
