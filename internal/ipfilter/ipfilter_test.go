package ipfilter

import (
	"net/netip"
	"testing"

	"gopkg.in/yaml.v3"
)

func parse(t *testing.T, in string) *Spec {
	t.Helper()
	var s Spec
	if err := yaml.Unmarshal([]byte(in), &s); err != nil {
		t.Fatalf("parse %q: %v", in, err)
	}
	return &s
}

func TestConditions(t *testing.T) {
	src := netip.MustParseAddr("198.51.100.7")
	tests := []struct {
		cond string
		ip   string
		want bool
	}{
		{"any", "10.0.0.1", true},
		{"any", "127.0.0.1", false}, // special addresses need explicit conditions
		{"public", "8.8.8.8", true},
		{"public", "2606:4700::1111", true},
		{"public", "10.0.0.1", false},
		{"public", "100.64.0.1", false},
		{"public", "192.0.2.1", false},
		{"public", "2001:db8::1", false},
		{"public", "fd00::1", false},
		{"public", "4000::1", false}, // outside 2000::/3
		{"private", "172.16.5.5", true},
		{"private", "fd12::1", true},
		{"private", "8.8.8.8", false},
		{"cgnat", "100.127.255.1", true},
		{"reserved", "203.0.113.9", true},
		{"reserved", "255.255.255.255", false}, // special, not reserved
		{"special", "127.0.0.1", true},
		{"special", "8.8.8.8", false},
		{"loopback", "::1", true},
		{"loopback", "169.254.1.1", false},
		{"link-local", "fe80::1", true},
		{"multicast", "224.0.0.1", true},
		{"unspecified", "::", true},
		{"broadcast", "255.255.255.255", true},
		{"10.0.0.0/8", "10.9.9.9", true},
		{"10.0.0.0/8", "11.0.0.1", false},
		{"0.0.0.0/0", "127.0.0.1", false}, // CIDRs never match special addresses
		{"2001:db8::5", "2001:db8::5", true},
		{"source", "198.51.100.7", true},
		{"source", "198.51.100.8", false},
		{"source/24", "198.51.100.200", true},
		{"source/24", "198.51.101.1", false},
		{"source/24,64", "198.51.100.1", true},
	}
	for _, tt := range tests {
		p := parse(t, tt.cond).Policy
		if p == nil {
			t.Fatalf("%s: not a condition", tt.cond)
		}
		if got, _ := p.Allows(netip.MustParseAddr(tt.ip), src); got != tt.want {
			t.Errorf("%s allows %s = %v", tt.cond, tt.ip, got)
		}
	}
}

func TestSourceIPv6(t *testing.T) {
	p := parse(t, "source/32,64").Policy
	src := netip.MustParseAddr("2606:4700:1:2::9")
	for ip, want := range map[string]bool{
		"2606:4700:1:2::1": true,
		"2606:4700:1:3::1": false,
		"198.51.100.7":     false, // other family
	} {
		if got, _ := p.Allows(netip.MustParseAddr(ip), src); got != want {
			t.Errorf("Allows(%s) = %v", ip, got)
		}
	}
	if got, _ := p.Allows(netip.MustParseAddr("2606:4700:1:2::1"), netip.Addr{}); got {
		t.Error("unknown source matched")
	}
}

func TestRules(t *testing.T) {
	p := parse(t, `
- "!192.168.1.1"
- deny: [10.0.0.0/8, cgnat]
- allow: {all: [private, 192.168.0.0/16]}
- allow: [loopback, public]
`).Policy
	for ip, want := range map[string]int{
		"192.168.1.1": 0,
		"10.1.1.1":    1,
		"100.64.0.1":  1,
		"192.168.5.5": 2,
		"127.0.0.1":   3,
		"8.8.8.8":     3,
		"172.16.0.1":  -1,
	} {
		allowed, rule := p.Allows(netip.MustParseAddr(ip), netip.Addr{})
		if rule != want || allowed != (rule >= 2) {
			t.Errorf("Allows(%s) = %v, rule %d; want rule %d", ip, allowed, rule, want)
		}
	}
}

func TestRef(t *testing.T) {
	s := parse(t, "home-lan")
	if s.Ref != "home-lan" || s.Policy != nil {
		t.Errorf("got %+v", s)
	}
}

func TestDefault(t *testing.T) {
	p := Default()
	for ip, want := range map[string]bool{"8.8.8.8": true, "192.168.1.1": false, "127.0.0.1": false} {
		if got, _ := p.Allows(netip.MustParseAddr(ip), netip.Addr{}); got != want {
			t.Errorf("Default allows %s = %v", ip, got)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{
		`"!10.0.0.0/8"`,
		`[]`,
		`{allow: public}`,
		`[nope]`,
		`[10.0.0.0/33]`,
		`[source/33]`,
		`[source/24,129]`,
		`[{permit: public}]`,
		`[{allow: public, deny: private}]`,
		`[{allow: []}]`,
		`[{allow: {all: []}}]`,
		`[{allow: {any: [public]}}]`,
	} {
		var s Spec
		if err := yaml.Unmarshal([]byte(in), &s); err == nil {
			t.Errorf("expected error for %s", in)
		}
	}
}

func TestIsCondition(t *testing.T) {
	for s, want := range map[string]bool{"public": true, "source/24": true, "10.0.0.0/8": true, "home": false, "!public": false} {
		if got := IsCondition(s); got != want {
			t.Errorf("IsCondition(%q) = %v", s, got)
		}
	}
}
