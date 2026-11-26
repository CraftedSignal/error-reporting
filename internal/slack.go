package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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

// Notify sends a Slack message for the report. src is where the batch came
// from, as seen by the ingestor.
func (n *SlackNotifier) Notify(ctx context.Context, r ReportPayload, src Source) error {
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
		"fallback":  fmt.Sprintf("%s (%s): %s", r.Trigger.Level, environmentLabel(r.Runtime), r.Trigger.Message),
		"fields":    slackFields(r, src, companyID, correlationID, userID),
		"footer":    fmt.Sprintf("CraftedSignal %s (%s)", r.Build.Version, r.Build.Commit),
		"ts":        time.Now().Unix(),
		"mrkdwn_in": []string{"text", "fields"},
	}

	return n.send(ctx, map[string]interface{}{
		"attachments": []map[string]interface{}{attachment},
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

func truncateSlack(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	if limit < 20 {
		return value[:limit]
	}
	return value[:limit-15] + "... [truncated]"
}

func slackFields(r ReportPayload, src Source, companyID, correlationID, userID string) []map[string]interface{} {
	fields := []map[string]interface{}{
		{"title": "Environment", "value": slackValue(environmentLabel(r.Runtime)), "short": true},
		{"title": "Company", "value": companyID, "short": true},
		{"title": "Version", "value": slackValue(versionLabel(r.Build)), "short": true},
		{"title": "Runtime", "value": slackValue(runtimeLabel(r)), "short": true},
	}
	if r.Runtime.Hostname != "" {
		fields = append(fields, map[string]interface{}{"title": "Host", "value": slackValue(r.Runtime.Hostname), "short": true})
	}
	if label := sourceLabel(src); label != "" {
		fields = append(fields, map[string]interface{}{"title": "Source", "value": slackValue(label), "short": true})
	}
	if correlationID != "" {
		fields = append(fields, map[string]interface{}{"title": "Correlation ID", "value": correlationID, "short": true})
	}
	if userID != "" {
		fields = append(fields, map[string]interface{}{"title": "User ID", "value": userID, "short": true})
	}
	if details := slackDetails(r.Trigger.Attrs); details != "" {
		fields = append(fields, map[string]interface{}{"title": "Details", "value": "```\n" + details + "\n```", "short": false})
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

// slackEscaper neutralizes mrkdwn control characters in report values, which
// can be attacker-influenced (the platform's CSP report endpoint is public):
// &, < and > would otherwise let a value inject mentions or links, and a
// backtick would end the code block.
var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "`", "'")

const (
	slackDetailLineLimit = 700 // bound each diagnostic attribute
	slackDetailsLimit    = 2000
	slackFieldLimit      = 200 // bound each identity field
)

// slackValue bounds and neutralizes a reporter-supplied field value.
func slackValue(value string) string {
	return slackEscaper.Replace(truncateSlack(strings.Join(strings.Fields(value), " "), slackFieldLimit))
}

// slackDetails renders the trigger's attributes as key=value lines, skipping
// those that already have a field of their own. Only scalar values are shown:
// reporters that predate attribute values sent {} for every one.
func slackDetails(attrs []Attr) string {
	lines := make([]string, 0, len(attrs))
	for _, a := range attrs {
		switch a.Key {
		case "company_id", "correlation_id", "user_id":
			continue
		}
		var value string
		switch v := a.Value.(type) {
		case string:
			value = v
		case json.Number:
			value = v.String()
		case bool:
			value = strconv.FormatBool(v)
		default:
			continue
		}
		line := RedactString(a.Key + "=" + strings.Join(strings.Fields(value), " "))
		lines = append(lines, slackEscaper.Replace(truncateSlack(line, slackDetailLineLimit)))
	}
	return truncateSlack(strings.Join(lines, "\n"), slackDetailsLimit)
}

// environmentLabel says which kind of installation reported and whose it is:
// the license type alone made a development box look like a customer site.
func environmentLabel(rt RuntimeInfo) string {
	parts := []string{envLabel(rt)}
	if rt.Licensee != "" {
		parts = append(parts, rt.Licensee)
	}
	if rt.DevMode {
		parts = append(parts, "dev mode")
	}
	return strings.Join(parts, " · ")
}

// versionLabel names the build; git-describe versions already contain the
// short commit, so it is only appended when missing.
func versionLabel(b BuildInfo) string {
	version := b.Version
	if version == "" {
		version = "unknown"
	}
	commit := b.Commit
	if len(commit) > 8 {
		commit = commit[:8]
	}
	if commit != "" && !strings.Contains(version, commit) {
		version += " (" + commit + ")"
	}
	return version
}

// runtimeLabel is the OS/architecture, database and hosting of the reporter.
func runtimeLabel(r ReportPayload) string {
	var parts []string
	if r.Build.GoOS != "" || r.Build.GoArch != "" {
		parts = append(parts, r.Build.GoOS+"/"+r.Build.GoArch)
	}
	for _, v := range []string{r.Runtime.StorageDriver, r.Runtime.Hosting} {
		if v != "" {
			parts = append(parts, v)
		}
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, " · ")
}

func sourceLabel(src Source) string {
	if src.Host == "" {
		return src.IP
	}
	return src.IP + " (" + src.Host + ")"
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
