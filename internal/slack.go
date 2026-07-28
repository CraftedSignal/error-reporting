package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SlackNotifier sends formatted messages to a Slack incoming webhook.
type SlackNotifier struct {
	webhookURL string
	client     *http.Client
}

// NewSlackNotifier creates a notifier for the given webhook URL.
func NewSlackNotifier(webhookURL string) *SlackNotifier {
	return &SlackNotifier{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Notify sends a Slack message for the report.
func (n *SlackNotifier) Notify(ctx context.Context, r ReportPayload) error {
	if n.webhookURL == "" {
		return fmt.Errorf("slack webhook not configured")
	}

	companyID := "unknown"
	correlationID := ""
	userID := ""
	for _, a := range r.Trigger.Attrs {
		switch a.Key {
		case "company_id":
			companyID = fmt.Sprintf("%v", a.Value)
		case "correlation_id":
			correlationID = fmt.Sprintf("%v", a.Value)
		case "user_id":
			userID = fmt.Sprintf("%v", a.Value)
		}
	}

	color := "#ff9900" // warning
	if r.Trigger.Level == "error" {
		color = "#ff0000"
	}

	attachment := map[string]interface{}{
		"color":      color,
		"title":      fmt.Sprintf("[%s] %s", strings.ToUpper(r.Trigger.Level), r.Trigger.Message),
		"fallback":   fmt.Sprintf("%s: %s", r.Trigger.Level, r.Trigger.Message),
		"fields":     slackFields(r, companyID, correlationID, userID),
		"footer":     fmt.Sprintf("CraftedSignal %s (%s)", r.Build.Version, r.Build.Commit),
		"ts":         time.Now().Unix(),
		"mrkdwn_in":  []string{"text", "fields"},
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{attachment},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack webhook request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	return nil
}

func slackFields(r ReportPayload, companyID, correlationID, userID string) []map[string]interface{} {
	fields := []map[string]interface{}{
		{"title": "Company", "value": companyID, "short": true},
		{"title": "Environment", "value": envLabel(r.Runtime), "short": true},
	}
	if correlationID != "" {
		fields = append(fields, map[string]interface{}{"title": "Correlation ID", "value": correlationID, "short": true})
	}
	if userID != "" {
		fields = append(fields, map[string]interface{}{"title": "User ID", "value": userID, "short": true})
	}
	if len(r.Before) > 0 || len(r.After) > 0 {
		fields = append(fields, map[string]interface{}{
			"title": "Context",
			"value": fmt.Sprintf("%d before, %d after", len(r.Before), len(r.After)),
			"short": true,
		})
	}
	return fields
}

func envLabel(rt RuntimeInfo) string {
	if rt.IsSaaS {
		return "SaaS"
	}
	if rt.Airgapped {
		return "airgapped"
	}
	return "on-prem"
}
