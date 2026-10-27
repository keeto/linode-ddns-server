package server

import (
	"net/http"
	"testing"
	"time"
)

func TestFailLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := newFailLimiter()
	l.now = func() time.Time { return now }

	for i := 0; i < authBurst; i++ {
		if _, blocked := l.blocked("192.0.2.1"); blocked {
			t.Fatalf("blocked after %d failures", i)
		}
		l.fail("192.0.2.1")
	}
	wait, blocked := l.blocked("192.0.2.1")
	if !blocked || wait != authRefill {
		t.Fatalf("after burst: blocked=%v wait=%v", blocked, wait)
	}
	if _, blocked := l.blocked("192.0.2.2"); blocked {
		t.Error("other client blocked")
	}

	now = now.Add(authRefill)
	if _, blocked := l.blocked("192.0.2.1"); blocked {
		t.Error("still blocked after refill")
	}
	l.fail("192.0.2.1")
	if _, blocked := l.blocked("192.0.2.1"); !blocked {
		t.Error("refill granted more than one attempt")
	}
}

func TestFailLimiterIPv6Prefix(t *testing.T) {
	l := newFailLimiter()
	for i := 0; i < authBurst; i++ {
		l.fail("2001:db8::1")
	}
	if _, blocked := l.blocked("2001:db8::ffff"); !blocked {
		t.Error("same /64 not blocked")
	}
	if _, blocked := l.blocked("2001:db8:0:1::1"); blocked {
		t.Error("different /64 blocked")
	}
}

func TestFailLimiterPrune(t *testing.T) {
	now := time.Unix(0, 0)
	l := newFailLimiter()
	l.now = func() time.Time { return now }
	l.fail("192.0.2.1")
	now = now.Add(authRefill)
	l.prune()
	if len(l.buckets) != 0 {
		t.Errorf("refilled bucket kept: %d", len(l.buckets))
	}
}

func TestLoginLockout(t *testing.T) {
	_, srv := setup(t)
	path := "/v1/update?domain=home.example.com&ip=2.2.2.2"
	for i := 0; i < authBurst; i++ {
		if got := get(t, srv, path, "router:nope", ""); got.status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d %q", i, got.status, got.body)
		}
	}
	got := get(t, srv, path, auth, "")
	if got.status != http.StatusTooManyRequests || got.body != "abuse\n" {
		t.Errorf("after lockout: %d %q", got.status, got.body)
	}
}
