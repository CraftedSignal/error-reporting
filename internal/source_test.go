package internal

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		forwarded  []string
		remoteAddr string
		want       string
	}{
		{name: "behind load balancer", forwarded: []string{"203.0.113.7, 34.36.1.2"}, want: "203.0.113.7"},
		{name: "client-supplied hops are ignored", forwarded: []string{"198.51.100.9, 203.0.113.7, 34.36.1.2"}, want: "203.0.113.7"},
		{name: "repeated headers", forwarded: []string{"198.51.100.9", "203.0.113.7, 34.36.1.2"}, want: "203.0.113.7"},
		{name: "single hop", forwarded: []string{"203.0.113.7"}, want: "203.0.113.7"},
		{name: "ipv4-mapped", forwarded: []string{"::ffff:203.0.113.7, 34.36.1.2"}, want: "203.0.113.7"},
		{name: "ipv6", forwarded: []string{"2001:db8::7, 34.36.1.2"}, want: "2001:db8::7"},
		{name: "not an address", forwarded: []string{"<!channel>, 34.36.1.2"}, want: ""},
		{name: "no header uses connection", remoteAddr: "198.51.100.2:41234", want: "198.51.100.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), "POST", "/logs", nil)
			if tt.remoteAddr != "" {
				r.RemoteAddr = tt.remoteAddr
			}
			for _, v := range tt.forwarded {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := ClientIP(r); got != tt.want {
				t.Fatalf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveSource(t *testing.T) {
	named := func(context.Context, string) ([]string, error) {
		return []string{"94-224-86-24.access.telenet.be."}, nil
	}
	if got := ResolveSource(context.Background(), "94.224.86.24", named); got != (Source{IP: "94.224.86.24", Host: "94-224-86-24.access.telenet.be"}) {
		t.Fatalf("ResolveSource() = %+v", got)
	}
	failing := func(context.Context, string) ([]string, error) { return nil, errors.New("no PTR") }
	if got := ResolveSource(context.Background(), "192.0.2.1", failing); got != (Source{IP: "192.0.2.1"}) {
		t.Fatalf("ResolveSource() with lookup failure = %+v", got)
	}
	if got := ResolveSource(context.Background(), "", named); got != (Source{}) {
		t.Fatalf("ResolveSource() without an address = %+v", got)
	}
}
