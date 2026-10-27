package config

import (
	"net/netip"
	"testing"
)

func TestTrustedProxies(t *testing.T) {
	c, err := Parse([]byte("trusted_proxies: [127.0.0.1, \"::1\", 10.1.2.3/8, \"fd00::/8\"]\n" + valid))
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]bool{
		"127.0.0.1":        true,
		"::ffff:127.0.0.1": true, // IPv4-mapped peer
		"127.0.0.2":        false,
		"::1":              true,
		"10.200.0.1":       true, // host bits in the CIDR are masked
		"11.0.0.1":         false,
		"fd12::1":          true,
		"2001:db8::1":      false,
	} {
		if got := c.TrustedProxy(netip.MustParseAddr(addr)); got != want {
			t.Errorf("TrustedProxy(%s) = %v", addr, got)
		}
	}

	none, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if none.TrustedProxy(netip.MustParseAddr("127.0.0.1")) {
		t.Error("no proxies configured, but 127.0.0.1 trusted")
	}
}

func TestTrustedProxiesInvalid(t *testing.T) {
	for _, p := range []string{"nope", "10.0.0.0/33", "1.2.3.4:80", ""} {
		if _, err := Parse([]byte("trusted_proxies: [\"" + p + "\"]\n" + valid)); err == nil {
			t.Errorf("expected error for %q", p)
		}
	}
}
