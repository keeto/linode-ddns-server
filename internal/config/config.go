// Package config loads and validates the linode-ddns YAML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"linode-ddns/internal/ipfilter"
)

// DefaultListen is used when the config does not set listen.
const DefaultListen = ":8080"

type Config struct {
	Listen string `yaml:"listen"`
	TLS    *TLS   `yaml:"tls"`
	// TrustedProxies lists IPs or CIDRs of reverse proxies whose
	// X-Forwarded-For header is trusted when logging the client address.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// IPPolicies holds named IP policies that users and domains refer to.
	IPPolicies map[string]*ipfilter.Spec `yaml:"ip_policies"`
	// DefaultIPs applies to users and domains without their own policy. When
	// unset, only public addresses are allowed.
	DefaultIPs *ipfilter.Spec `yaml:"default_ips"`
	Users      []User         `yaml:"users"`

	byName  map[string]*User
	proxies []netip.Prefix
}

type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type User struct {
	Username       string         `yaml:"username"`
	PasswordHash   string         `yaml:"password_hash"`
	LinodeAPIToken string         `yaml:"linode_api_token"`
	IPs            *ipfilter.Spec `yaml:"ips"`
	Domains        []Domain       `yaml:"domains"`

	allowed map[string]*ipfilter.Policy
}

// Domain is a hostname a user may update, with an optional IP policy. In YAML
// it is either a plain hostname or {host, ips}.
type Domain struct {
	Host string         `yaml:"host"`
	IPs  *ipfilter.Spec `yaml:"ips"`
}

func (d *Domain) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		d.Host = n.Value
		return nil
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if k := n.Content[i].Value; k != "host" && k != "ips" {
				return fmt.Errorf("line %d: unknown domain field %q", n.Content[i].Line, k)
			}
		}
	}
	type plain Domain
	return n.Decode((*plain)(d))
}

// Load reads and validates the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse decodes and validates config YAML. Unknown fields are rejected.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.TLS != nil && (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return errors.New("tls: cert_file and key_file must both be set")
	}
	if c.TLS != nil && c.TLS.CertFile == "" {
		c.TLS = nil
	}
	for i, p := range c.TrustedProxies {
		prefix, err := ipfilter.ParsePrefix(strings.TrimSpace(p))
		if err != nil {
			return fmt.Errorf("trusted_proxies[%d]: invalid IP or CIDR %q", i, p)
		}
		c.proxies = append(c.proxies, prefix)
	}
	named := make(map[string]*ipfilter.Policy, len(c.IPPolicies))
	for name, s := range c.IPPolicies {
		switch {
		case name == "" || strings.HasPrefix(name, "!") || ipfilter.IsCondition(name):
			return fmt.Errorf("ip_policies: %q cannot be a policy name because it is a condition", name)
		case s == nil || s.Policy == nil:
			return fmt.Errorf("ip_policies.%s: must list conditions or rules, not refer to another policy", name)
		}
		s.Policy.Name = name
		named[name] = s.Policy
	}
	// resolve returns the policy s describes, or fallback when s is unset.
	resolve := func(s *ipfilter.Spec, fallback *ipfilter.Policy, name string) (*ipfilter.Policy, error) {
		switch {
		case s == nil:
			return fallback, nil
		case s.Ref != "":
			p, ok := named[s.Ref]
			if !ok {
				return nil, fmt.Errorf("unknown ip policy or invalid condition %q", s.Ref)
			}
			return p, nil
		default:
			s.Policy.Name = name
			return s.Policy, nil
		}
	}
	def, err := resolve(c.DefaultIPs, ipfilter.Default(), "default_ips")
	if err != nil {
		return fmt.Errorf("default_ips: %w", err)
	}

	if len(c.Users) == 0 {
		return errors.New("no users defined")
	}
	c.byName = make(map[string]*User, len(c.Users))
	for i := range c.Users {
		u := &c.Users[i]
		switch {
		case u.Username == "":
			return fmt.Errorf("users[%d]: username is required", i)
		case strings.Contains(u.Username, ":"):
			return fmt.Errorf("user %q: username must not contain ':'", u.Username)
		case u.PasswordHash == "":
			return fmt.Errorf("user %q: password_hash is required", u.Username)
		case u.LinodeAPIToken == "":
			return fmt.Errorf("user %q: linode_api_token is required", u.Username)
		case len(u.Domains) == 0:
			return fmt.Errorf("user %q: domains is required", u.Username)
		}
		if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
			return fmt.Errorf("user %q: invalid password_hash: %w", u.Username, err)
		}
		if _, dup := c.byName[u.Username]; dup {
			return fmt.Errorf("duplicate username %q", u.Username)
		}
		c.byName[u.Username] = u

		userPolicy, err := resolve(u.IPs, def, u.Username)
		if err != nil {
			return fmt.Errorf("user %q: ips: %w", u.Username, err)
		}
		u.allowed = make(map[string]*ipfilter.Policy, len(u.Domains))
		for j := range u.Domains {
			d := &u.Domains[j]
			n := NormalizeHost(d.Host)
			if !ValidHost(n) {
				return fmt.Errorf("user %q: domains[%d]: invalid hostname %q", u.Username, j, d.Host)
			}
			if _, dup := u.allowed[n]; dup {
				return fmt.Errorf("user %q: duplicate domain %q", u.Username, n)
			}
			d.Host = n
			p, err := resolve(d.IPs, userPolicy, u.Username+"/"+n)
			if err != nil {
				return fmt.Errorf("user %q: domain %q: ips: %w", u.Username, n, err)
			}
			u.allowed[n] = p
		}
	}
	return nil
}

// User returns the user with the given name, or nil.
func (c *Config) User(name string) *User {
	return c.byName[name]
}

// TrustedProxy reports whether addr is one of the configured trusted proxies.
func (c *Config) TrustedProxy(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range c.proxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Allows reports whether host is in the user's domains list.
func (u *User) Allows(host string) bool {
	_, ok := u.allowed[host]
	return ok
}

// IPPolicy returns the IP policy for one of the user's hosts, or nil when the
// host is not in the domains list.
func (u *User) IPPolicy(host string) *ipfilter.Policy {
	return u.allowed[host]
}

// NormalizeHost lowercases host and strips surrounding whitespace and a
// trailing dot.
func NormalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// ValidHost reports whether a normalized host is a plausible FQDN: at least two
// labels of letters, digits, hyphens or underscores.
func ValidHost(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}
