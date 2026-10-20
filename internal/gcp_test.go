package internal

import (
	"net/http"
	"strings"
	"testing"
)

func TestMetadataAccessTokenSourceRejectsUntrustedMetadataHosts(t *testing.T) {
	for _, host := range []string{
		"attacker.example",
		"10.0.0.12:8080",
		"https://metadata.google.internal",
		"127.0.0.1:8080/path",
		"user@127.0.0.1:8080",
		"127.0.0.1:not-a-port",
	} {
		t.Run(host, func(t *testing.T) {
			t.Setenv("GCE_METADATA_HOST", host)
			called := false
			source := NewMetadataAccessTokenSource()
			source.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				called = true
				return nil, nil
			})

			_, err := source.Token(t.Context())
			if err == nil || !strings.Contains(err.Error(), "invalid GCE_METADATA_HOST") {
				t.Fatalf("Token() error = %v, want invalid GCE_METADATA_HOST", err)
			}
			if called {
				t.Fatal("Token() sent a request to an untrusted metadata host")
			}
		})
	}
}
