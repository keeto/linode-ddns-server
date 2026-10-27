package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hash is bcrypt("secret") at cost 4.
const hash = "$2a$04$8LDA2Jiln/ij5hj6db7R7uAMEzP5xyPxbSBnfeV/D42Pb6rIsx1yS"

const valid = `
users:
  - username: router
    password_hash: "` + hash + `"
    linode_api_token: tok
    domains:
      - Home.Example.COM.
      - example.com
  - username: open
    password_hash: "` + hash + `"
    linode_api_token: tok2
`

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != DefaultListen || c.TLS != nil {
		t.Errorf("defaults: listen=%q tls=%v", c.Listen, c.TLS)
	}
	u := c.User("router")
	if u == nil || u.LinodeAPIToken != "tok" {
		t.Fatalf("User(router) = %+v", u)
	}
	if !u.Allows("home.example.com") || !u.Allows("example.com") || u.Allows("other.example.com") {
		t.Errorf("router allow list wrong: %v", u.Domains)
	}
	if open := c.User("open"); open == nil || !open.Allows("anything.example.net") {
		t.Errorf("user without domains should allow any host")
	}
	if c.User("nobody") != nil {
		t.Errorf("unknown user found")
	}
}

func TestParseErrors(t *testing.T) {
	user := func(fields string) string {
		return "users:\n  - " + strings.ReplaceAll(strings.TrimSpace(fields), "\n", "\n    ") + "\n"
	}
	full := "username: u\npassword_hash: \"" + hash + "\"\nlinode_api_token: t"
	tests := map[string]string{
		"malformed":        "users: [",
		"unknown field":    user(full + "\npassword: plain"),
		"no users":         "listen: \":80\"\n",
		"missing username": user("password_hash: \"" + hash + "\"\nlinode_api_token: t"),
		"colon username":   user("username: a:b\npassword_hash: \"" + hash + "\"\nlinode_api_token: t"),
		"missing hash":     user("username: u\nlinode_api_token: t"),
		"bad hash":         user("username: u\npassword_hash: nothash\nlinode_api_token: t"),
		"missing token":    user("username: u\npassword_hash: \"" + hash + "\""),
		"bad domain":       user(full + "\ndomains: [\"not a host\"]"),
		"single label":     user(full + "\ndomains: [localhost]"),
		"duplicate user":   user(full) + "  - " + strings.ReplaceAll(full, "\n", "\n    ") + "\n",
		"half tls":         "tls:\n  cert_file: c.pem\n" + user(full),
	}
	for name, in := range tests {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected error for:\n%s", name, in)
		}
	}
}

func TestParseTLS(t *testing.T) {
	in := "listen: \":8443\"\ntls:\n  cert_file: c.pem\n  key_file: k.pem\n" + valid
	c, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8443" || c.TLS == nil || c.TLS.CertFile != "c.pem" || c.TLS.KeyFile != "k.pem" {
		t.Errorf("got listen=%q tls=%+v", c.Listen, c.TLS)
	}
}

func TestLoad(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Error(err)
	}
}

func TestValidHost(t *testing.T) {
	for host, want := range map[string]bool{
		"example.com":                    true,
		"a.b.example.com":                true,
		"_acme.example.com":              true,
		"x-1.example.com":                true,
		"example":                        false,
		"":                               false,
		"-a.example.com":                 false,
		"a..example.com":                 false,
		"a b.example.com":                false,
		"exa%mple.com":                   false,
		strings.Repeat("a", 64) + ".com": false,
	} {
		if got := ValidHost(host); got != want {
			t.Errorf("ValidHost(%q) = %v", host, got)
		}
	}
}
