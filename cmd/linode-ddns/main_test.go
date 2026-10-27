package main

import "testing"

func TestLoopback(t *testing.T) {
	for listen, want := range map[string]bool{
		"127.0.0.1:8080": true,
		"[::1]:8080":     true,
		"localhost:8080": true,
		":8080":          false,
		"0.0.0.0:8080":   false,
		"[::]:8080":      false,
		"10.0.0.1:8080":  false,
		"bogus":          false,
	} {
		if got := loopback(listen); got != want {
			t.Errorf("loopback(%q) = %v", listen, got)
		}
	}
}
