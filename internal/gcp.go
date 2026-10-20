package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const metadataTokenPath = "/computeMetadata/v1/instance/service-accounts/default/token"

// AccessTokenSource supplies OAuth access tokens for Google Cloud REST APIs.
type AccessTokenSource interface {
	Token(ctx context.Context) (string, error)
}

// MetadataAccessTokenSource reads short-lived tokens from the Cloud Run
// metadata server. Tokens are cached until shortly before expiry.
type MetadataAccessTokenSource struct {
	client *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func NewMetadataAccessTokenSource() *MetadataAccessTokenSource {
	return &MetadataAccessTokenSource{
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (s *MetadataAccessTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	if s.token != "" && time.Until(s.expiry) > 5*time.Minute {
		token := s.token
		s.mu.Unlock()
		return token, nil
	}
	s.mu.Unlock()

	endpoint, err := metadataTokenEndpoint()
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("metadata token request returned %d", resp.StatusCode)
	}

	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode metadata token: %w", err)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("metadata token response missing access token")
	}

	expiry := time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	s.mu.Lock()
	s.token = body.AccessToken
	s.expiry = expiry
	s.mu.Unlock()
	return body.AccessToken, nil
}

func metadataTokenEndpoint() (string, error) {
	host := strings.TrimSpace(os.Getenv("GCE_METADATA_HOST"))
	switch host {
	case "", "metadata.google.internal":
		return "http://metadata.google.internal" + metadataTokenPath, nil
	case "169.254.169.254":
		return "http://169.254.169.254" + metadataTokenPath, nil
	}

	// Permit only an explicit loopback IP with a numeric port for local tests.
	// Hostnames, private-network addresses, paths, credentials, and schemes are
	// rejected so GCE_METADATA_HOST cannot turn the metadata client into an SSRF
	// primitive.
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		return "", fmt.Errorf("invalid GCE_METADATA_HOST %q: %w", host, err)
	}
	ip := net.ParseIP(hostname)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("invalid GCE_METADATA_HOST %q: only the Google metadata endpoint or a loopback IP is allowed", host)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid GCE_METADATA_HOST %q: port must be between 1 and 65535", host)
	}
	endpoint := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(ip.String(), strconv.Itoa(portNumber)),
		Path:   metadataTokenPath,
	}
	return endpoint.String(), nil
}
