// Package ipfilter decides which addresses a DNS record may point at.
//
// A policy is an ordered list of allow and deny rules. The first rule with a
// matching condition decides; an address no rule matches is denied.
//
// Special addresses (everything that is not global unicast: loopback,
// link-local, multicast, broadcast, unspecified) are matched only by the
// conditions that name them, never by a CIDR, "any" or "source". A policy
// therefore allows them only when it says so explicitly.
package ipfilter

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Policy is a compiled list of rules.
type Policy struct {
	// Name identifies the policy in logs.
	Name  string
	rules []rule
}

type rule struct {
	allow bool
	any   []cond // the rule matches when any condition does
}

// cond is one condition. A special condition matches only special addresses;
// any other condition matches only non-special ones.
type cond struct {
	special bool
	match   func(ip, src netip.Addr) bool
}

func (c cond) matches(ip, src netip.Addr) bool {
	return Special(ip) == c.special && c.match(ip, src)
}

// Default returns the policy used when none is configured: public addresses
// only.
func Default() *Policy {
	return &Policy{Name: "default", rules: []rule{{allow: true, any: []cond{classes["public"]}}}}
}

// Allows reports whether the record may point at ip when the request came
// from src, and the index of the deciding rule, or -1 when no rule matched.
// src is the zero Addr when the requester's address is unknown.
func (p *Policy) Allows(ip, src netip.Addr) (bool, int) {
	ip = ip.Unmap()
	for i, r := range p.rules {
		for _, c := range r.any {
			if c.matches(ip, src) {
				return r.allow, i
			}
		}
	}
	return false, -1
}

// Special reports whether ip is not a global unicast address.
func Special(ip netip.Addr) bool {
	return !ip.IsGlobalUnicast()
}

var (
	privateNets  = prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
	cgnatNets    = prefixes("100.64.0.0/10")
	reservedNets = prefixes(
		// IPv4: this network, IETF protocol assignments, documentation,
		// benchmarking, future use.
		"0.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		// IPv6: discard-only, documentation.
		"100::/64", "2001:db8::/32", "3fff::/20",
	)
	globalV6  = netip.MustParsePrefix("2000::/3")
	broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})
)

func prefixes(ss ...string) []netip.Prefix {
	ps := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		ps[i] = netip.MustParsePrefix(s)
	}
	return ps
}

func in(ps []netip.Prefix) func(netip.Addr) bool {
	return func(ip netip.Addr) bool {
		for _, p := range ps {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
}

func public(ip netip.Addr) bool {
	if in(privateNets)(ip) || in(cgnatNets)(ip) || in(reservedNets)(ip) {
		return false
	}
	return ip.Is4() || globalV6.Contains(ip)
}

// class builds a condition that ignores the requester's address.
func class(special bool, f func(netip.Addr) bool) cond {
	return cond{special: special, match: func(ip, _ netip.Addr) bool { return f(ip) }}
}

var classes = map[string]cond{
	"any":      class(false, func(netip.Addr) bool { return true }),
	"public":   class(false, public),
	"private":  class(false, in(privateNets)),
	"cgnat":    class(false, in(cgnatNets)),
	"reserved": class(false, in(reservedNets)),

	"special":     class(true, func(netip.Addr) bool { return true }),
	"loopback":    class(true, netip.Addr.IsLoopback),
	"link-local":  class(true, netip.Addr.IsLinkLocalUnicast),
	"multicast":   class(true, netip.Addr.IsMulticast),
	"unspecified": class(true, netip.Addr.IsUnspecified),
	"broadcast":   class(true, func(ip netip.Addr) bool { return ip == broadcast }),
}

// IsCondition reports whether s is a valid condition.
func IsCondition(s string) bool {
	_, err := parseCond(s)
	return err == nil
}

// parseCond parses one condition: a class name, source[/N[,M]], an IP or a
// CIDR.
func parseCond(s string) (cond, error) {
	s = strings.TrimSpace(s)
	if c, ok := classes[s]; ok {
		return c, nil
	}
	if s == "source" {
		return source(32, 128), nil
	}
	if bits, ok := strings.CutPrefix(s, "source/"); ok {
		v4s, v6s, both := strings.Cut(bits, ",")
		v4, err4 := strconv.Atoi(v4s)
		v6 := v4
		var err6 error
		if both {
			v6, err6 = strconv.Atoi(v6s)
		}
		if err4 != nil || err6 != nil || v4 < 0 || v4 > 32 || v6 < 0 || v6 > 128 {
			return cond{}, fmt.Errorf("invalid condition %q: use source/N with N up to 32, or source/N,M for IPv4 and IPv6, e.g. source/32,64", s)
		}
		return source(v4, v6), nil
	}
	p, err := ParsePrefix(s)
	if err != nil {
		return cond{}, fmt.Errorf("invalid condition %q", s)
	}
	return class(false, p.Contains), nil
}

// source matches addresses in the same /v4 or /v6 prefix as the requester.
func source(v4, v6 int) cond {
	return cond{match: func(ip, src netip.Addr) bool {
		src = src.Unmap()
		if !src.IsValid() || ip.Is4() != src.Is4() {
			return false
		}
		bits := v6
		if ip.Is4() {
			bits = v4
		}
		p, err := src.Prefix(bits)
		return err == nil && p.Contains(ip)
	}}
}

// allOf matches when every condition does.
func allOf(cs []cond) cond {
	return cond{special: cs[0].special, match: func(ip, src netip.Addr) bool {
		for _, c := range cs {
			if !c.matches(ip, src) {
				return false
			}
		}
		return true
	}}
}

// ParsePrefix accepts a CIDR or a single IP address. IPv4-mapped addresses
// are unmapped and host bits are masked.
func ParsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}
