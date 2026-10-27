package linode_test

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"linode-ddns/internal/linode"
	"linode-ddns/internal/linode/linodetest"
)

const token = "tok"

const putPattern = "PUT /domains/{id}/records/{rid}"

func setup(t *testing.T) (*linodetest.Fake, *linode.Resolver) {
	t.Helper()
	f := linodetest.New(token)
	t.Cleanup(f.Close)
	f.AddDomain(1, "example.com")
	f.AddDomain(2, "sub.example.com")
	f.AddDomain(3, "other.org")
	f.AddRecord(1, linode.Record{ID: 10, Type: "A", Name: "home", Target: "1.1.1.1"})
	f.AddRecord(1, linode.Record{ID: 11, Type: "AAAA", Name: "home", Target: "2001:db8::1"})
	f.AddRecord(1, linode.Record{ID: 12, Type: "A", Name: "", Target: "1.1.1.1"})
	f.AddRecord(1, linode.Record{ID: 13, Type: "A", Name: "dup", Target: "1.1.1.1"})
	f.AddRecord(1, linode.Record{ID: 14, Type: "A", Name: "dup", Target: "1.1.1.2"})
	f.AddRecord(1, linode.Record{ID: 15, Type: "CNAME", Name: "alias", Target: "home.example.com"})
	f.AddRecord(2, linode.Record{ID: 20, Type: "A", Name: "deep", Target: "3.3.3.3"})
	f.AddRecord(2, linode.Record{ID: 21, Type: "A", Name: "fq.sub.example.com", Target: "4.4.4.4"})
	return f, linode.NewResolver(f.Client())
}

func TestCurrent(t *testing.T) {
	_, r := setup(t)
	tests := []struct {
		host, typ, want string
		err             error
	}{
		{"home.example.com", "A", "1.1.1.1", nil},
		{"home.example.com", "AAAA", "2001:db8::1", nil},
		{"example.com", "A", "1.1.1.1", nil},
		{"deep.sub.example.com", "A", "3.3.3.3", nil}, // longest zone wins
		{"fq.sub.example.com", "A", "4.4.4.4", nil},   // fully qualified record name
		{"missing.example.com", "A", "", linode.ErrNoHost},
		{"example.com", "AAAA", "", linode.ErrNoHost},
		{"alias.example.com", "A", "", linode.ErrNoHost},
		{"home.nowhere.net", "A", "", linode.ErrNoHost},
		{"notexample.com", "A", "", linode.ErrNoHost}, // suffix must be on a label boundary
		{"dup.example.com", "A", "", linode.ErrAmbiguous},
	}
	for _, tt := range tests {
		got, err := r.Current(context.Background(), token, tt.host, tt.typ)
		if !errors.Is(err, tt.err) || got != tt.want {
			t.Errorf("Current(%s, %s) = %q, %v; want %q, %v", tt.host, tt.typ, got, err, tt.want, tt.err)
		}
	}
}

func TestUpdate(t *testing.T) {
	f, r := setup(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("5.5.5.5")

	changed, err := r.Update(ctx, token, "home.example.com", "A", ip)
	if err != nil || !changed {
		t.Fatalf("first update = %v, %v; want true, nil", changed, err)
	}
	if got := f.Target(1, 10); got != "5.5.5.5" {
		t.Fatalf("target = %q", got)
	}

	// Second update with the same IP is answered from cache without any API call.
	lists := f.Calls("GET /domains")
	changed, err = r.Update(ctx, token, "home.example.com", "A", ip)
	if err != nil || changed {
		t.Fatalf("repeat update = %v, %v; want false, nil", changed, err)
	}
	if f.Calls("GET /domains") != lists || f.Calls(putPattern) != 1 {
		t.Errorf("repeat update made API calls")
	}
}

func TestUpdateNoChangeCompressedIPv6(t *testing.T) {
	f, r := setup(t)
	changed, err := r.Update(context.Background(), token, "home.example.com", "AAAA", netip.MustParseAddr("2001:0db8:0:0::1"))
	if err != nil || changed {
		t.Fatalf("update = %v, %v; want false, nil", changed, err)
	}
	if f.Calls(putPattern) != 0 {
		t.Errorf("unexpected PUT")
	}
}

func TestUpdateRecordDeletedAfterCaching(t *testing.T) {
	f, r := setup(t)
	ctx := context.Background()
	if _, err := r.Update(ctx, token, "home.example.com", "A", netip.MustParseAddr("5.5.5.5")); err != nil {
		t.Fatal(err)
	}

	// Record replaced out of band with a new ID.
	f.DeleteRecord(1, 10)
	f.AddRecord(1, linode.Record{ID: 99, Type: "A", Name: "home", Target: "1.1.1.1"})

	changed, err := r.Update(ctx, token, "home.example.com", "A", netip.MustParseAddr("6.6.6.6"))
	if err != nil || !changed {
		t.Fatalf("update = %v, %v; want true, nil", changed, err)
	}
	if got := f.Target(1, 99); got != "6.6.6.6" {
		t.Errorf("new record target = %q", got)
	}

	// Record removed entirely.
	f.DeleteRecord(1, 99)
	if _, err := r.Update(ctx, token, "home.example.com", "A", netip.MustParseAddr("7.7.7.7")); !errors.Is(err, linode.ErrNoHost) {
		t.Errorf("err = %v; want ErrNoHost", err)
	}
}

func TestCacheExpiry(t *testing.T) {
	f, r := setup(t)
	now := time.Unix(0, 0)
	r.SetNow(func() time.Time { return now })
	ctx := context.Background()
	ip := netip.MustParseAddr("1.1.1.1")

	r.Update(ctx, token, "home.example.com", "A", ip)
	r.Update(ctx, token, "home.example.com", "A", ip)
	if n := f.Calls("GET /domains"); n != 1 {
		t.Fatalf("domain lists = %d; want 1", n)
	}
	now = now.Add(linode.DefaultCacheTTL)
	r.Update(ctx, token, "home.example.com", "A", ip)
	if n := f.Calls("GET /domains"); n != 2 {
		t.Errorf("domain lists after expiry = %d; want 2", n)
	}
}

func TestPagination(t *testing.T) {
	f := linodetest.New(token)
	defer f.Close()
	f.PageSize = 2
	for i := 1; i <= 5; i++ {
		f.AddDomain(i, "d"+string(rune('0'+i))+".com")
	}
	for i := 1; i <= 5; i++ {
		f.AddRecord(5, linode.Record{ID: 100 + i, Type: "A", Name: "h" + string(rune('0'+i)), Target: "9.9.9.9"})
	}
	r := linode.NewResolver(f.Client())
	got, err := r.Current(context.Background(), token, "h5.d5.com", "A")
	if err != nil || got != "9.9.9.9" {
		t.Errorf("Current = %q, %v", got, err)
	}
}

func TestAPIErrors(t *testing.T) {
	f, r := setup(t)
	f.FailWith(http.StatusInternalServerError)
	_, err := r.Current(context.Background(), token, "home.example.com", "A")
	var apiErr *linode.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 {
		t.Errorf("err = %v; want APIError 500", err)
	}

	f.FailWith(0)
	_, err = r.Current(context.Background(), "wrong-token", "home.example.com", "A")
	if !errors.As(err, &apiErr) || apiErr.Status != 401 {
		t.Errorf("err = %v; want APIError 401", err)
	}
}
