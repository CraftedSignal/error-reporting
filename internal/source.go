package internal

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Source is where a report batch came from as seen by the ingestor. Unlike the
// payload, the reporter cannot choose it.
type Source struct {
	IP   string
	Host string // reverse DNS name of IP; empty when it has none
}

// ClientIP returns the address that connected to the load balancer. The
// external load balancer appends "<client>, <load balancer>" to
// X-Forwarded-For, so entries left of the second-to-last one were supplied by
// the client and are ignored. Without the header (local runs) the connection's
// address is used.
func ClientIP(r *http.Request) string {
	var hops []string
	for _, value := range r.Header.Values("X-Forwarded-For") {
		for _, hop := range strings.Split(value, ",") {
			if hop = strings.TrimSpace(hop); hop != "" {
				hops = append(hops, hop)
			}
		}
	}
	var candidate string
	switch {
	case len(hops) >= 2:
		candidate = hops[len(hops)-2]
	case len(hops) == 1:
		candidate = hops[0]
	default:
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return ""
		}
		candidate = host
	}
	addr, err := netip.ParseAddr(candidate)
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
}

// ResolveSource names ip with reverse DNS, bounded so a slow resolver cannot
// hold the request.
func ResolveSource(ctx context.Context, ip string, lookup func(context.Context, string) ([]string, error)) Source {
	src := Source{IP: ip}
	if ip == "" || lookup == nil {
		return src
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if names, err := lookup(ctx, ip); err == nil && len(names) > 0 {
		src.Host = strings.TrimSuffix(names[0], ".")
	}
	return src
}
