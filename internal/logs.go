package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ObservedLogEntry struct {
	Timestamp time.Time         `json:"timestamp"`
	Severity  string            `json:"severity"`
	Message   string            `json:"message"`
	Resource  string            `json:"resource"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type CloudLoggingClient struct {
	projectID  string
	apiBaseURL string
	client     *http.Client
	tokens     AccessTokenSource
}

func NewCloudLoggingClient(projectID string, tokens AccessTokenSource) *CloudLoggingClient {
	return &CloudLoggingClient{
		projectID:  projectID,
		apiBaseURL: "https://logging.googleapis.com/v2",
		client:     &http.Client{Timeout: 15 * time.Second},
		tokens:     tokens,
	}
}

func (c *CloudLoggingClient) RecentEntries(ctx context.Context, incident IncidentEnvelope, limit int) ([]ObservedLogEntry, error) {
	if c == nil || c.projectID == "" {
		return nil, nil
	}
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 60
	}

	triggeredAt := incident.Report.TriggeredAt
	if triggeredAt.IsZero() {
		triggeredAt = time.Now().UTC()
	}
	start := triggeredAt.Add(-10 * time.Minute).Format(time.RFC3339Nano)
	end := triggeredAt.Add(10 * time.Minute).Format(time.RFC3339Nano)
	service := logFilterValue(incident.Service)

	filter := fmt.Sprintf(`timestamp >= "%s" AND timestamp <= "%s" AND (severity >= WARNING OR textPayload:"%s" OR jsonPayload.msg:"%s" OR jsonPayload.message:"%s" OR resource.labels.container_name="%s" OR resource.labels.service_name="%s")`,
		start, end, service, service, service, service, service)

	reqBody, err := json.Marshal(map[string]interface{}{
		"resourceNames": []string{"projects/" + c.projectID},
		"filter":        filter,
		"orderBy":       "timestamp asc",
		"pageSize":      limit,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.apiBaseURL, "/")+"/entries:list", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloud logging entries:list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("cloud logging entries:list returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result struct {
		Entries []cloudLogSinkEntry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode cloud logging entries:list: %w", err)
	}

	entries := make([]ObservedLogEntry, 0, len(result.Entries))
	for _, entry := range result.Entries {
		ts := time.Now().UTC()
		if entry.Timestamp != "" {
			if parsed, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err == nil {
				ts = parsed.UTC()
			}
		}
		entries = append(entries, ObservedLogEntry{
			Timestamp: ts,
			Severity:  entry.Severity,
			Message:   RedactString(cloudLogMessage(entry)),
			Resource:  entry.Resource.Type,
			Labels:    entry.Resource.Labels,
		})
	}
	return entries, nil
}

func logFilterValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	if value == "" {
		return "unknown"
	}
	return value
}
