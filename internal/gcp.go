package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

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

	host := os.Getenv("GCE_METADATA_HOST")
	if host == "" {
		host = "metadata.google.internal"
	}
	url := fmt.Sprintf("http://%s/computeMetadata/v1/instance/service-accounts/default/token", host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
