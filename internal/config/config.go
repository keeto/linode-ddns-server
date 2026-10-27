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
)

// DefaultListen is used when the config does not set listen.
const DefaultListen = ":8080"

type Config struct {
	Listen string `yaml:"listen"`
	TLS    *TLS   `yaml:"tls"`
	// TrustedProxies lists IPs or CIDRs of reverse proxies whose
	// X-Forwarded-For header is trusted when logging the client address.
	TrustedProxies []string `yaml:"trusted_proxies"`
	Users          []User   `yaml:"users"`

	byName  map[string]*User
	proxies []netip.Prefix
}

type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type User struct {
	Username       string   `yaml:"username"`
	PasswordHash   string   `yaml:"password_hash"`
	LinodeAPIToken string   `yaml:"linode_api_token"`
	Domains        []string `yaml:"domains"`

	allowed map[string]bool
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
		prefix, err := parsePrefix(strings.TrimSpace(p))
		if err != nil {
			return fmt.Errorf("trusted_proxies[%d]: invalid IP or CIDR %q", i, p)
		}
		c.proxies = append(c.proxies, prefix)
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

		u.allowed = make(map[string]bool, len(u.Domains))
		for j, d := range u.Domains {
			n := NormalizeHost(d)
			if !ValidHost(n) {
				return fmt.Errorf("user %q: domains[%d]: invalid hostname %q", u.Username, j, d)
			}
			u.Domains[j] = n
			u.allowed[n] = true
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

// parsePrefix accepts a CIDR or a single IP address.
func parsePrefix(s string) (netip.Prefix, error) {
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

// Allows reports whether host is in the user's domains list.
func (u *User) Allows(host string) bool {
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
