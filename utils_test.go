package main

import (
	"reflect"
	"testing"
)

func TestExtractHosts(t *testing.T) {
	cases := map[string][]string{
		"example.com":           {"example.com"},
		"example.com:8080":      {"example.com"},
		"http://example.com":    {"example.com"},
		"https://example.com":   {"example.com"},
		"ftp://example.com":     {"example.com"},
		"example.com/10":        {"example.com"},
		"example.com/path":      {"example.com"},
		"sub.example.com":       {"sub.example.com"},
		"sub.example.com:8080":  {"sub.example.com"},
		"ftp://sub.example.com": {"sub.example.com"},
		"x.x.x.com":             {"x.x.x.com"},
		"111.111.111.111":       {"111.111.111.111"},
		"222.222.222.222":       {"222.222.222.222"},
		"10.0.0.0/29":           {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"},
		"http://17.0.0.0/10":    {"17.0.0.0"},
		"17.0.0.0/10/10":        {"17.0.0.0"},
		"http://17.0.0.0/10/10": {"17.0.0.0"},
		"as1111":                {"as1111"},
		"foo":                   {"foo"},
		"x@x":                   {"x"},
		"x@x.com":               {"x.com"},
		"x!x":                   nil,
	}

	for c, want := range cases {
		got := extractHosts(c)
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%q: got %v, want %v", c, got, want)
		}
	}
}
