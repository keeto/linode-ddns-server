package linode_test

import (
	"context"
	"net/netip"
	"sync"
	"testing"
)

func TestLocksReleased(t *testing.T) {
	_, r := setup(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		host := []string{"home.example.com", "missing.example.com", "deep.sub.example.com"}[i%3]
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Update(context.Background(), token, host, "A", netip.MustParseAddr("5.5.5.5"))
		}()
	}
	wg.Wait()
	if n := r.Locks(); n != 0 {
		t.Errorf("%d locks left after all operations finished", n)
	}
}
