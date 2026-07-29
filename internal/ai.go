package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var ErrAIUnavailable = errors.New("ai analyzer unavailable")

type Analyzer interface {
	Analyze(ctx context.Context, input AnalysisInput) (ResolutionPlan, error)
}

type AnalysisInput struct {
	Incident IncidentEnvelope
	Repo     ServiceRepoConfig
	Logs     []ObservedLogEntry
	Source   SourceContext
}

type ResolutionPlan struct {
	Category     string     `json:"category"`
	Action       string     `json:"action"`
	Title        string     `json:"title"`
	Summary      string     `json:"summary"`
	RootCause    string     `json:"root_cause"`
	Impact       string     `json:"impact"`
	Confidence   string     `json:"confidence"`
	FileEdits    []FileEdit `json:"file_edits"`
	TestCommands []string   `json:"test_commands"`
}

type FileEdit struct {
	Path    string `json:"path"`
	Find    string `json:"find"`
	Replace string `json:"replace"`
	Reason  string `json:"reason"`
}

type AIClient struct {
	endpoint       string
	apiKey         string
	model          string
	maxPromptBytes int
	client         *http.Client
}

func NewAIClient(endpoint, apiKey, model string, maxPromptBytes int) *AIClient {
	if maxPromptBytes <= 0 {
		maxPromptBytes = 120 * 1024
	}
	return &AIClient{
		endpoint:       strings.TrimRight(endpoint, "/"),
		apiKey:         apiKey,
		model:          model,
		maxPromptBytes: maxPromptBytes,
		client:         &http.Client{Timeout: 90 * time.Second},
	}
}

func (c *AIClient) Analyze(ctx context.Context, input AnalysisInput) (ResolutionPlan, error) {
	if c == nil || c.apiKey == "" || c.model == "" || c.endpoint == "" {
		return ResolutionPlan{}, ErrAIUnavailable
	}

	prompt, err := BuildAnalysisPrompt(input, c.maxPromptBytes)
	if err != nil {
		return ResolutionPlan{}, err
	}

	reqBody, err := json.Marshal(map[string]interface{}{
		"model": c.model,
		"messages": []map[string]string{
			{
				"role": "system",
				"content": strings.Join([]string{
					"You are a senior production incident resolver.",
					"Return only strict JSON.",
					"Prefer no_pr or needs_human unless the source edit is small, directly supported by evidence, and safe.",
					"Never propose direct production mutation, secret changes, or broad rewrites.",
				}, " "),
			},
			{"role": "user", "content": prompt},
		},
		"temperature":     0.1,
		"max_tokens":      4000,
		"response_format": map[string]string{"type": "json_object"},
	})
	if err != nil {
		return ResolutionPlan{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return ResolutionPlan{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return ResolutionPlan{}, fmt.Errorf("ai request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return ResolutionPlan{}, fmt.Errorf("ai request returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return ResolutionPlan{}, fmt.Errorf("decode ai response: %w", err)
	}
	if len(chatResp.Choices) == 0 || strings.TrimSpace(chatResp.Choices[0].Message.Content) == "" {
		return ResolutionPlan{}, fmt.Errorf("ai response missing content")
	}

	plan, err := DecodeResolutionPlan(chatResp.Choices[0].Message.Content)
	if err != nil {
		return ResolutionPlan{}, err
	}
	return NormalizeResolutionPlan(plan, input.Incident), nil
}

func BuildAnalysisPrompt(input AnalysisInput, maxBytes int) (string, error) {
	reportJSON, err := json.MarshalIndent(redactedReport(input.Incident.Report), "", "  ")
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("Investigate this production incident and decide whether to open a PR.\n\n")
	b.WriteString("Return JSON with this exact shape:\n")
	b.WriteString(`{"category":"external_source|runtime_resource|code_bug|unknown","action":"no_pr|open_pr|needs_human","title":"","summary":"","root_cause":"","impact":"","confidence":"low|medium|high","file_edits":[{"path":"","find":"","replace":"","reason":""}],"test_commands":[""]}`)
	b.WriteString("\n\nRules:\n")
	b.WriteString("- Use action=open_pr only when the change is narrow and directly supported by logs/source.\n")
	b.WriteString("- file_edits may only touch files shown below; each find string must match exactly once. Use empty find only to create a new file.\n")
	b.WriteString("- OOMKilled and quota/resource errors are runtime_resource unless code evidence shows a leak or runaway allocation.\n")
	b.WriteString("- 403/404/rate-limit failures from third-party feeds are external_source unless retry/backoff/parsing code is clearly wrong.\n")
	b.WriteString("- Do not edit secrets, generated files, vendored files, lockfiles, or deployment credentials.\n")
	b.WriteString("- Put verification commands in test_commands; prefer the repo's configured commands.\n\n")

	b.WriteString("Incident:\n")
	b.Write(reportJSON)
	b.WriteString("\n\nRecent logs:\n")
	for _, entry := range input.Logs {
		b.WriteString("- ")
		b.WriteString(entry.Timestamp.Format(time.RFC3339))
		b.WriteString(" ")
		b.WriteString(entry.Severity)
		b.WriteString(" ")
		b.WriteString(RedactString(entry.Message))
		b.WriteByte('\n')
	}
	if len(input.Logs) == 0 {
		b.WriteString("- none collected\n")
	}

	b.WriteString("\nRepository:\n")
	b.WriteString(input.Repo.Repo)
	b.WriteString("@")
	b.WriteString(firstNonEmpty(input.Source.Ref, input.Repo.BaseBranch))
	b.WriteString("\nConfigured tests:\n")
	for _, cmd := range input.Repo.TestCommands {
		b.WriteString("- ")
		b.WriteString(cmd)
		b.WriteByte('\n')
	}

	b.WriteString("\nSource files:\n")
	for _, file := range input.Source.Files {
		b.WriteString("\n--- ")
		b.WriteString(file.Path)
		b.WriteString(" ---\n")
		b.WriteString(file.Content)
		if !strings.HasSuffix(file.Content, "\n") {
			b.WriteByte('\n')
		}
	}
	if len(input.Source.Files) == 0 {
		b.WriteString("none\n")
	}

	out := b.String()
	if maxBytes > 0 && len(out) > maxBytes {
		out = out[:maxBytes] + "\n[context truncated]"
	}
	return out, nil
}

func DecodeResolutionPlan(content string) (ResolutionPlan, error) {
	content = strings.TrimSpace(content)
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start < 0 || end < start {
		return ResolutionPlan{}, fmt.Errorf("ai response was not json")
	}
	var plan ResolutionPlan
	body := content[start : end+1]
	if err := json.Unmarshal([]byte(body), &plan); err != nil {
		repaired := escapeJSONControlCharsInStrings(body)
		if repaired == body {
			return ResolutionPlan{}, fmt.Errorf("decode resolution plan: %w", err)
		}
		if repairErr := json.Unmarshal([]byte(repaired), &plan); repairErr != nil {
			return ResolutionPlan{}, fmt.Errorf("decode resolution plan: %w", err)
		}
	}
	return plan, nil
}

func escapeJSONControlCharsInStrings(value string) string {
	var b strings.Builder
	inString := false
	escaped := false
	changed := false
	for _, r := range value {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if !inString {
			if r == '"' {
				inString = true
			}
			b.WriteRune(r)
			continue
		}
		switch r {
		case '\\':
			b.WriteRune(r)
			escaped = true
		case '"':
			b.WriteRune(r)
			inString = false
		case '\n':
			b.WriteString(`\n`)
			changed = true
		case '\r':
			b.WriteString(`\r`)
			changed = true
		case '\t':
			b.WriteString(`\t`)
			changed = true
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
				changed = true
			} else {
				b.WriteRune(r)
			}
		}
	}
	if !changed {
		return value
	}
	return b.String()
}

func NormalizeResolutionPlan(plan ResolutionPlan, incident IncidentEnvelope) ResolutionPlan {
	plan.Category = normalizeChoice(plan.Category, []string{"external_source", "runtime_resource", "code_bug", "unknown"}, HeuristicPlan(incident).Category)
	plan.Action = normalizeChoice(plan.Action, []string{"no_pr", "open_pr", "needs_human"}, "")
	if plan.Action == "" {
		if len(plan.FileEdits) > 0 {
			plan.Action = "open_pr"
		} else {
			plan.Action = "needs_human"
		}
	}
	plan.Confidence = normalizeChoice(plan.Confidence, []string{"low", "medium", "high"}, "low")
	if strings.TrimSpace(plan.Title) == "" {
		plan.Title = defaultResolutionTitle(incident)
	}
	if len(plan.Title) > 120 {
		plan.Title = plan.Title[:120]
	}
	plan.Summary = RedactString(plan.Summary)
	plan.RootCause = RedactString(plan.RootCause)
	plan.Impact = RedactString(plan.Impact)
	return plan
}

func HeuristicPlan(incident IncidentEnvelope) ResolutionPlan {
	text := strings.ToLower(incident.Report.Trigger.Message + " " + AttrString(incident.Report.Trigger.Attrs, "error", "reason", "msg"))
	switch {
	case strings.Contains(text, "oomkill"), strings.Contains(text, "oomkilled"), strings.Contains(text, "exit code 137"), strings.Contains(text, "out of memory"):
		return ResolutionPlan{
			Category:   "runtime_resource",
			Action:     "needs_human",
			Title:      defaultResolutionTitle(incident),
			Summary:    "Runtime resource failure detected.",
			RootCause:  "The container appears to have been killed or restarted because of memory pressure.",
			Impact:     "Service availability or background work may have been interrupted.",
			Confidence: "medium",
		}
	case strings.Contains(text, "bleepingcomputer"), strings.Contains(text, " nvd "), strings.Contains(text, "403"), strings.Contains(text, "404"), strings.Contains(text, "rate limit"):
		return ResolutionPlan{
			Category:   "external_source",
			Action:     "no_pr",
			Title:      defaultResolutionTitle(incident),
			Summary:    "External dependency failure detected.",
			RootCause:  "The failure appears to come from an upstream source response or access restriction.",
			Impact:     "A feed/import job may have skipped or retried work.",
			Confidence: "medium",
		}
	case strings.Contains(text, "panic"), strings.Contains(text, "nil pointer"), strings.Contains(text, "parse"), strings.Contains(text, "yaml"), strings.Contains(text, "index out of range"):
		return ResolutionPlan{
			Category:   "code_bug",
			Action:     "needs_human",
			Title:      defaultResolutionTitle(incident),
			Summary:    "Likely code or input-handling bug detected.",
			RootCause:  "A code change may be required, but no AI patch was produced.",
			Impact:     "The reported operation failed.",
			Confidence: "low",
		}
	default:
		return ResolutionPlan{
			Category:   "unknown",
			Action:     "needs_human",
			Title:      defaultResolutionTitle(incident),
			Summary:    "The incident could not be classified with enough confidence.",
			RootCause:  "Insufficient evidence for an automated change.",
			Impact:     "Review the linked logs and service state.",
			Confidence: "low",
		}
	}
}

func redactedReport(report ReportPayload) ReportPayload {
	report.Trigger.Message = RedactString(report.Trigger.Message)
	for i := range report.Trigger.Attrs {
		report.Trigger.Attrs[i].Value = RedactString(fmt.Sprintf("%v", report.Trigger.Attrs[i].Value))
	}
	for i := range report.Before {
		report.Before[i].Message = RedactString(report.Before[i].Message)
		for j := range report.Before[i].Attrs {
			report.Before[i].Attrs[j].Value = RedactString(fmt.Sprintf("%v", report.Before[i].Attrs[j].Value))
		}
	}
	for i := range report.After {
		report.After[i].Message = RedactString(report.After[i].Message)
		for j := range report.After[i].Attrs {
			report.After[i].Attrs[j].Value = RedactString(fmt.Sprintf("%v", report.After[i].Attrs[j].Value))
		}
	}
	report.ConfigSummary = redactMap(report.ConfigSummary)
	return report
}

func normalizeChoice(value string, allowed []string, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return fallback
}

func defaultResolutionTitle(incident IncidentEnvelope) string {
	msg := strings.TrimSpace(incident.Report.Trigger.Message)
	if msg == "" {
		msg = "production error"
	}
	if len(msg) > 70 {
		msg = msg[:70]
	}
	return fmt.Sprintf("agent: investigate %s error %s", incident.Service, msg)
}
