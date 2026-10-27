package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestIPPolicies(t *testing.T) {
	c, err := Parse([]byte(`
ip_policies:
  lan: [private]
default_ips: [public, cgnat]
users:
  - username: a
    password_hash: "` + hash + `"
    linode_api_token: t
    ips: lan
    domains:
      - user.example.com
      - host: Inline.Example.com.
        ips: 203.0.113.0/24
      - host: named.example.com
        ips: lan
  - username: b
    password_hash: "` + hash + `"
    linode_api_token: t
    domains: [default.example.com]
`))
	if err != nil {
		t.Fatal(err)
	}
	a, b := c.User("a"), c.User("b")
	tests := []struct {
		u          *User
		host, name string
		allow      string // an address the policy allows
		deny       string
	}{
		{a, "user.example.com", "lan", "192.168.1.1", "8.8.8.8"},
		{a, "inline.example.com", "a/inline.example.com", "203.0.113.5", "192.168.1.1"},
		{a, "named.example.com", "lan", "10.0.0.1", "8.8.8.8"},
		{b, "default.example.com", "default_ips", "100.64.0.1", "10.0.0.1"},
	}
	for _, tt := range tests {
		p := tt.u.IPPolicy(tt.host)
		if p == nil {
			t.Fatalf("%s: no policy", tt.host)
		}
		if p.Name != tt.name {
			t.Errorf("%s: policy %q, want %q", tt.host, p.Name, tt.name)
		}
		if ok, _ := p.Allows(netip.MustParseAddr(tt.allow), netip.Addr{}); !ok {
			t.Errorf("%s: %s denied", tt.host, tt.allow)
		}
		if ok, _ := p.Allows(netip.MustParseAddr(tt.deny), netip.Addr{}); ok {
			t.Errorf("%s: %s allowed", tt.host, tt.deny)
		}
	}
	if a.IPPolicy("other.example.com") != nil {
		t.Error("policy for unlisted host")
	}
}

func TestIPPolicyDefaultPublic(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	p := c.User("router").IPPolicy("home.example.com")
	if ok, _ := p.Allows(netip.MustParseAddr("8.8.8.8"), netip.Addr{}); !ok {
		t.Error("public address denied by default")
	}
	if ok, _ := p.Allows(netip.MustParseAddr("192.168.1.1"), netip.Addr{}); ok {
		t.Error("private address allowed by default")
	}
}

func TestIPPolicyErrors(t *testing.T) {
	user := func(extra string) string {
		return "users:\n  - username: u\n    password_hash: \"" + hash + "\"\n    linode_api_token: t\n" + extra
	}
	tests := map[string]string{
		"unknown ref":         user("    ips: nope\n    domains: [a.example.com]\n"),
		"unknown domain ref":  user("    domains:\n      - host: a.example.com\n        ips: nope\n"),
		"unknown default ref": "default_ips: nope\n" + user("    domains: [a.example.com]\n"),
		"keyword name":        "ip_policies:\n  public: [any]\n" + user("    domains: [a.example.com]\n"),
		"cidr name":           "ip_policies:\n  10.0.0.0/8: [any]\n" + user("    domains: [a.example.com]\n"),
		"alias policy":        "ip_policies:\n  x: [any]\n  y: x\n" + user("    domains: [a.example.com]\n"),
		"bad condition":       user("    ips: [10.0.0.0/33]\n    domains: [a.example.com]\n"),
		"unknown domain key":  user("    domains:\n      - host: a.example.com\n        ip: any\n"),
		"duplicate domain":    user("    domains: [a.example.com, A.example.com.]\n"),
	}
	for name, in := range tests {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected error for:\n%s", name, in)
		} else if strings.Contains(in, "nope") && !strings.Contains(err.Error(), `"nope"`) {
			t.Errorf("%s: error does not name the policy: %v", name, err)
		}
	}
}
