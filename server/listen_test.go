package main

import "testing"

func TestIsLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{
		"": false, "0.0.0.0": false, "::": false, "192.168.1.5": false,
		"127.0.0.1": true, "::1": true, "[::1]": true, "localhost": true, "127.0.0.2": true,
	} {
		if got := isLoopbackHost(h); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", h, got, want)
		}
	}
}
