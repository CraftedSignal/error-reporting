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

// SlackNotifier sends formatted messages to a Slack incoming webhook or to the
// Slack Web API when configured with a bot token (xoxb-...).
type SlackNotifier struct {
	webhookURL string
	channel    string
	client     *http.Client
}

// NewSlackNotifier creates a notifier for the given webhook URL or bot token.
// When webhookURL starts with "xoxb-" it is treated as a bot token and channel
// must be a channel id or name (e.g. #alerts).
func NewSlackNotifier(webhookURL, channel string) *SlackNotifier {
	return &SlackNotifier{
		webhookURL: webhookURL,
		channel:    channel,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *SlackNotifier) isBotToken() bool {
	return strings.HasPrefix(n.webhookURL, "xoxb-")
}

// Notify sends a Slack message for the report.
func (n *SlackNotifier) Notify(ctx context.Context, r ReportPayload) error {
	if n.webhookURL == "" {
		return fmt.Errorf("slack webhook not configured")
	}
	if n.isBotToken() && n.channel == "" {
		return fmt.Errorf("slack channel not configured for bot token")
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
		"color":     color,
		"title":     fmt.Sprintf("[%s] %s", strings.ToUpper(r.Trigger.Level), r.Trigger.Message),
		"fallback":  fmt.Sprintf("%s: %s", r.Trigger.Level, r.Trigger.Message),
		"fields":    slackFields(r, companyID, correlationID, userID),
		"footer":    fmt.Sprintf("CraftedSignal %s (%s)", r.Build.Version, r.Build.Commit),
		"ts":        time.Now().Unix(),
		"mrkdwn_in": []string{"text", "fields"},
	}

	return n.send(ctx, map[string]interface{}{
		"attachments": []map[string]interface{}{attachment},
	})
}

// NotifyResolution sends the resolver handoff: mention first, then PR/status.
func (n *SlackNotifier) NotifyResolution(ctx context.Context, msg ResolutionNotification) error {
	if n.webhookURL == "" {
		return fmt.Errorf("slack webhook not configured")
	}
	if n.isBotToken() && n.channel == "" {
		return fmt.Errorf("slack channel not configured for bot token")
	}

	heading := "Investigated production error"
	color := "#ffaa00"
	if msg.PRURL != "" {
		heading = "Auto-fix PR opened for production error"
		color = "#2eb67d"
	} else if strings.Contains(strings.ToLower(msg.Status), "needs human") {
		heading = "Production error needs human review"
		color = "#e01e5a"
	}

	text := strings.TrimSpace(strings.Join([]string{msg.Mention, heading + " in " + msg.Service + " " + msg.Environment}, " "))
	fields := []map[string]interface{}{
		{"title": "Status", "value": emptyFallback(msg.Status, "unknown"), "short": true},
		{"title": "Category", "value": emptyFallback(msg.Category, "unknown"), "short": true},
		{"title": "Deployed source", "value": "`" + emptyFallback(msg.DeployedSource, "unknown") + "`", "short": false},
		{"title": "Error", "value": truncateSlack(RedactString(msg.Error), 700), "short": false},
		{"title": "Impact", "value": emptyFallback(truncateSlack(RedactString(msg.Impact), 700), "unknown"), "short": false},
		{"title": "Confidence", "value": emptyFallback(msg.Confidence, "low"), "short": true},
		{"title": "Fingerprint", "value": "`" + emptyFallback(msg.Fingerprint, "unknown") + "`", "short": true},
	}
	if msg.PRURL != "" {
		fields = append([]map[string]interface{}{{"title": "PR", "value": msg.PRURL, "short": false}}, fields...)
	}

	return n.send(ctx, map[string]interface{}{
		"text": text,
		"attachments": []map[string]interface{}{
			{
				"color":     color,
				"title":     heading,
				"fallback":  text,
				"fields":    fields,
				"footer":    "CraftedSignal error resolver",
				"ts":        time.Now().Unix(),
				"mrkdwn_in": []string{"text", "fields"},
			},
		},
	})
}

func (n *SlackNotifier) send(ctx context.Context, payload map[string]interface{}) error {
	var (
		url  = n.webhookURL
		body []byte
		err  error
	)
	if n.isBotToken() {
		url = "https://slack.com/api/chat.postMessage"
		payload["channel"] = n.channel
	}
	body, err = json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.isBotToken() {
		req.Header.Set("Authorization", "Bearer "+n.webhookURL)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	if n.isBotToken() {
		var apiResp struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			return fmt.Errorf("decode slack response: %w", err)
		}
		if !apiResp.OK {
			return fmt.Errorf("slack api error: %s", apiResp.Error)
		}
	}
	return nil
}

func emptyFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func truncateSlack(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	if limit < 20 {
		return value[:limit]
	}
	return value[:limit-15] + "... [truncated]"
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
