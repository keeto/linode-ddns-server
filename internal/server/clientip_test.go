package server

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"linode-ddns/internal/config"
)

func TestClientIP(t *testing.T) {
	cfg, err := config.Parse([]byte("trusted_proxies: [127.0.0.1, 10.0.0.0/8]\n" + cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	tests := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"untrusted peer ignores header", "203.0.113.9:4000", []string{"1.1.1.1"}, "203.0.113.9"},
		{"trusted peer, no header", "127.0.0.1:4000", nil, "127.0.0.1"},
		{"trusted peer, single hop", "127.0.0.1:4000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"spoofed left entry ignored", "127.0.0.1:4000", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"skips trusted hops", "127.0.0.1:4000", []string{"198.51.100.7, 10.0.0.5"}, "198.51.100.7"},
		{"multiple headers", "127.0.0.1:4000", []string{"6.6.6.6", "198.51.100.7"}, "198.51.100.7"},
		{"all trusted", "127.0.0.1:4000", []string{"10.0.0.1, 10.0.0.2"}, "10.0.0.1"},
		{"malformed stops walk", "127.0.0.1:4000", []string{"198.51.100.7, garbage, 10.0.0.5"}, "10.0.0.5"},
		{"ipv6 client", "127.0.0.1:4000", []string{"2001:db8::7"}, "2001:db8::7"},
		{"mapped peer", "[::ffff:127.0.0.1]:4000", []string{"198.51.100.7"}, "198.51.100.7"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/v1/status", nil)
		r.RemoteAddr = tt.remote
		for _, v := range tt.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := s.clientIP(r); got != tt.want {
			t.Errorf("%s: clientIP = %q; want %q", tt.name, got, tt.want)
		}
	}
}
