package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"linode-ddns/internal/config"
	"linode-ddns/internal/linode"
	"linode-ddns/internal/linode/linodetest"
)

// hash is bcrypt("secret") at cost 4.
const hash = "$2a$04$8LDA2Jiln/ij5hj6db7R7uAMEzP5xyPxbSBnfeV/D42Pb6rIsx1yS"

const cfgYAML = `
ip_policies:
  lan: ["!192.168.1.1", private]
users:
  - username: router
    password_hash: "` + hash + `"
    linode_api_token: tok
    domains: [home.example.com, v4only.example.com, gone.example.com, broken.example.com]
  - username: other
    password_hash: "` + hash + `"
    linode_api_token: tok
    domains: [other.example.com]
  - username: policy
    password_hash: "` + hash + `"
    linode_api_token: tok
    ips: lan
    domains:
      - home.example.com
      - host: v4only.example.com
        ips: [source, loopback]
`

func setup(t *testing.T) (*linodetest.Fake, *httptest.Server) {
	t.Helper()
	return setupWith(t, cfgYAML)
}

func setupWith(t *testing.T, cfgYAML string) (*linodetest.Fake, *httptest.Server) {
	t.Helper()
	f := linodetest.New("tok")
	t.Cleanup(f.Close)
	f.AddDomain(1, "example.com")
	f.AddRecord(1, linode.Record{ID: 10, Type: "A", Name: "home", Target: "1.1.1.1"})
	f.AddRecord(1, linode.Record{ID: 11, Type: "AAAA", Name: "home", Target: "2001:4860::1"})
	f.AddRecord(1, linode.Record{ID: 12, Type: "A", Name: "v4only", Target: "1.1.1.1"})
	f.AddRecord(1, linode.Record{ID: 13, Type: "A", Name: "other", Target: "1.1.1.1"})

	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(New(cfg, linode.NewResolver(f.Client()), log))
	t.Cleanup(srv.Close)
	return f, srv
}

func TestDummyHashCost(t *testing.T) {
	strong, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost+1)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(cfgYAML + `
  - username: strong
    password_hash: "` + string(strong) + `"
    linode_api_token: tok
    domains: [home.example.com]
`))
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if c, _ := bcrypt.Cost(s.dummyHash); c != bcrypt.MinCost+1 {
		t.Errorf("dummy hash cost = %d, want %d", c, bcrypt.MinCost+1)
	}
}

func TestIPPolicy(t *testing.T) {
	f, srv := setup(t)
	const pol = "policy:secret"
	tests := []struct {
		name, path, user string
		status           int
		body             string
	}{
		{"default denies private", "/v1/update?domain=home.example.com&ip=10.0.0.1", auth, 400, "badip 10.0.0.1\n"},
		{"default denies loopback", "/v1/update?domain=home.example.com&ip=127.0.0.1", auth, 400, "badip 127.0.0.1\n"},
		{"split", "/v1/update?domain=home.example.com&ip=2.2.2.2&ipv6=fd00::1", auth, 400, "good 2.2.2.2\nbadip fd00::1\n"},
		{"user policy allows", "/v1/update?domain=home.example.com&ip=192.168.5.5", pol, 200, "good 192.168.5.5\n"},
		{"user policy deny rule", "/v1/update?domain=home.example.com&ip=192.168.1.1", pol, 400, "badip 192.168.1.1\n"},
		{"user policy no match", "/v1/update?domain=home.example.com&ip=8.8.8.8", pol, 400, "badip 8.8.8.8\n"},
		{"domain allows loopback", "/v1/update?domain=v4only.example.com&ip=127.0.0.1", pol, 200, "good 127.0.0.1\n"},
	}
	for _, tt := range tests {
		got := get(t, srv, tt.path, tt.user, "")
		if got.status != tt.status || got.body != tt.body {
			t.Errorf("%s: got %d %q; want %d %q", tt.name, got.status, got.body, tt.status, tt.body)
		}
	}
	if f.Target(1, 10) != "192.168.5.5" || f.Target(1, 12) != "127.0.0.1" {
		t.Errorf("targets: %s %s", f.Target(1, 10), f.Target(1, 12))
	}
}

func TestIPPolicySource(t *testing.T) {
	_, srv := setupWith(t, "trusted_proxies: [127.0.0.1]\n"+cfgYAML)
	update := func(ip string) response {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/update?domain=v4only.example.com&ip="+ip, nil)
		req.SetBasicAuth("policy", "secret")
		req.Header.Set("X-Forwarded-For", "198.51.100.7")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return response{status: resp.StatusCode, body: string(b)}
	}
	if got := update("198.51.100.7"); got.status != 200 || got.body != "good 198.51.100.7\n" {
		t.Errorf("own address: %d %q", got.status, got.body)
	}
	if got := update("198.51.100.8"); got.status != 400 || got.body != "badip 198.51.100.8\n" {
		t.Errorf("other address: %d %q", got.status, got.body)
	}
}

type response struct {
	status  int
	ctype   string
	body    string
	nosniff string
}

func get(t *testing.T, srv *httptest.Server, path, user, accept string) response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if user != "" {
		name, pass, _ := strings.Cut(user, ":")
		req.SetBasicAuth(name, pass)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return response{resp.StatusCode, resp.Header.Get("Content-Type"), string(b), resp.Header.Get("X-Content-Type-Options")}
}

const auth = "router:secret"

func TestUpdateText(t *testing.T) {
	f, srv := setup(t)
	tests := []struct {
		name, path, user string
		status           int
		body             string
	}{
		{"no auth", "/v1/update?domain=home.example.com&ip=2.2.2.2", "", 401, "badauth\n"},
		{"wrong password", "/v1/update?domain=home.example.com&ip=2.2.2.2", "router:nope", 401, "badauth\n"},
		{"unknown user", "/v1/update?domain=home.example.com&ip=2.2.2.2", "ghost:secret", 401, "badauth\n"},
		{"missing domain", "/v1/update?ip=2.2.2.2", auth, 400, "notfqdn\n"},
		{"bad domain", "/v1/update?domain=localhost&ip=2.2.2.2", auth, 400, "notfqdn\n"},
		{"not allowed", "/v1/update?domain=other.example.com&ip=2.2.2.2", auth, 404, "nohost\n"},
		{"no record", "/v1/update?domain=gone.example.com&ip=2.2.2.2", auth, 404, "nohost\n"},
		{"no ip", "/v1/update?domain=home.example.com", auth, 400, "badip\n"},
		{"garbage ip", "/v1/update?domain=home.example.com&ip=nope", auth, 400, "badip\n"},
		{"v6 in ip", "/v1/update?domain=home.example.com&ip=2001:4860::2", auth, 400, "badip\n"},
		{"v4 in ipv6", "/v1/update?domain=home.example.com&ipv6=2.2.2.2", auth, 400, "badip\n"},
		{"4in6 in ipv6", "/v1/update?domain=home.example.com&ipv6=::ffff:2.2.2.2", auth, 400, "badip\n"},
		{"nochg", "/v1/update?domain=home.example.com&ip=1.1.1.1", auth, 200, "nochg 1.1.1.1\n"},
		{"good", "/v1/update?domain=HOME.example.com.&ip=2.2.2.2", auth, 200, "good 2.2.2.2\n"},
		{"good v6", "/v1/update?domain=home.example.com&ipv6=2001:4860::2", auth, 200, "good 2001:4860::2\n"},
		{"both", "/v1/update?domain=home.example.com&ip=3.3.3.3&ipv6=2001:4860::2", auth, 200, "good 3.3.3.3\nnochg 2001:4860::2\n"},
		{"partial", "/v1/update?domain=v4only.example.com&ip=3.3.3.3&ipv6=2001:4860::2", auth, 404, "good 3.3.3.3\nnohost\n"},
		{"other user", "/v1/update?domain=other.example.com&ip=4.4.4.4", "other:secret", 200, "good 4.4.4.4\n"},
		{"other user not allowed", "/v1/update?domain=home.example.com&ip=4.4.4.4", "other:secret", 404, "nohost\n"},
	}
	for _, tt := range tests {
		got := get(t, srv, tt.path, tt.user, "")
		if got.status != tt.status || got.body != tt.body {
			t.Errorf("%s: got %d %q; want %d %q", tt.name, got.status, got.body, tt.status, tt.body)
		}
		if !strings.HasPrefix(got.ctype, "text/plain") {
			t.Errorf("%s: content-type %q", tt.name, got.ctype)
		}
		if got.nosniff != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options %q", tt.name, got.nosniff)
		}
	}
	if f.Target(1, 10) != "3.3.3.3" || f.Target(1, 11) != "2001:4860::2" || f.Target(1, 13) != "4.4.4.4" {
		t.Errorf("records not updated: %s %s %s", f.Target(1, 10), f.Target(1, 11), f.Target(1, 13))
	}
}

func TestUpdateJSON(t *testing.T) {
	_, srv := setup(t)
	got := get(t, srv, "/v1/update?domain=home.example.com&ip=2.2.2.2&ipv6=2001:4860::1", auth, "application/json")
	if got.status != 200 || got.ctype != "application/json" {
		t.Fatalf("got %d %q", got.status, got.ctype)
	}
	var body struct{ Results []Result }
	if err := json.Unmarshal([]byte(got.body), &body); err != nil {
		t.Fatal(err)
	}
	want := []Result{{Type: "A", Code: "good", IP: "2.2.2.2"}, {Type: "AAAA", Code: "nochg", IP: "2001:4860::1"}}
	if len(body.Results) != 2 || body.Results[0] != want[0] || body.Results[1] != want[1] {
		t.Errorf("results = %+v", body.Results)
	}

	got = get(t, srv, "/v1/update?domain=home.example.com&ip=2.2.2.2", "", "application/json")
	if got.status != 401 || !strings.Contains(got.body, `"status":"badauth"`) {
		t.Errorf("badauth json: %d %s", got.status, got.body)
	}
}

func TestUpstreamError(t *testing.T) {
	f, srv := setup(t)
	f.FailWith(http.StatusInternalServerError)
	got := get(t, srv, "/v1/update?domain=home.example.com&ip=2.2.2.2", auth, "")
	if got.status != 502 || got.body != "911\n" {
		t.Errorf("got %d %q", got.status, got.body)
	}
	if strings.Contains(got.body, "tok") {
		t.Errorf("token leaked in body")
	}
}

func TestStatus(t *testing.T) {
	_, srv := setup(t)
	got := get(t, srv, "/v1/status?domain=home.example.com", auth, "")
	if got.status != 200 || got.body != "A 1.1.1.1\nAAAA 2001:4860::1\n" {
		t.Errorf("home: %d %q", got.status, got.body)
	}
	got = get(t, srv, "/v1/status?domain=v4only.example.com", auth, "application/json")
	if got.status != 200 || got.body != `{"results":[{"type":"A","status":"ok","ip":"1.1.1.1"}]}`+"\n" {
		t.Errorf("v4only: %d %q", got.status, got.body)
	}
	got = get(t, srv, "/v1/status?domain=gone.example.com", auth, "")
	if got.status != 404 || got.body != "nohost\n" {
		t.Errorf("gone: %d %q", got.status, got.body)
	}
	got = get(t, srv, "/v1/status?domain=home.example.com", "", "")
	if got.status != 401 {
		t.Errorf("unauthenticated status: %d", got.status)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	_, srv := setup(t)
	resp, err := http.Post(srv.URL+"/v1/update?domain=home.example.com&ip=2.2.2.2", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d", resp.StatusCode)
	}
}

func TestWantsJSON(t *testing.T) {
	for accept, want := range map[string]bool{
		"":                                   false,
		"*/*":                                false,
		"text/plain":                         false,
		"application/json":                   true,
		"application/*":                      true,
		"application/json, text/plain":       false,
		"application/json, text/plain;q=0.5": true,
		"text/plain;q=0.9, application/json": true,
		"application/json;q=0.1, */*":        false,
		"text/html, application/json;q=0.9":  true,
		"bogus":                              false,
	} {
		var h []string
		if accept != "" {
			h = []string{accept}
		}
		if got := wantsJSON(h); got != want {
			t.Errorf("wantsJSON(%q) = %v", accept, got)
		}
	}
}
