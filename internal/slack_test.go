package internal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// slackFieldsFor decodes a report batch in the platform's wire format, runs
// Notify against a stub Slack webhook, and returns the posted attachment's
// fields keyed by title.
func slackFieldsFor(t *testing.T, batch string) map[string]string {
	t.Helper()
	reports, err := DecodeReportBatch([]byte(batch))
	if err != nil || len(reports) != 1 {
		t.Fatalf("DecodeReportBatch: %d reports, err = %v", len(reports), err)
	}

	var posted struct {
		Attachments []struct {
			Fields []struct {
				Title string `json:"title"`
				Value string `json:"value"`
			} `json:"fields"`
		} `json:"attachments"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &posted); err != nil {
			t.Errorf("slack payload: %v", err)
		}
	}))
	defer srv.Close()

	if err := NewSlackNotifier(srv.URL, "").Notify(context.Background(), reports[0]); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if len(posted.Attachments) != 1 {
		t.Fatalf("posted %d attachments, want 1", len(posted.Attachments))
	}
	fields := make(map[string]string)
	for _, f := range posted.Attachments[0].Fields {
		fields[f.Title] = f.Value
	}
	return fields
}

// detailLines returns the key=value lines inside the Details code block.
func detailLines(t *testing.T, fields map[string]string) []string {
	t.Helper()
	details, ok := fields["Details"]
	if !ok {
		t.Fatalf("no Details field in %v", fields)
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(details, "```\n"), "\n```")
	return strings.Split(inner, "\n")
}

func reportWithAttrs(attrs string) string {
	return `[{"v":"1","triggered_at":"2026-10-18T08:57:05Z","trigger":{"time":"2026-10-18T08:57:04Z","level":"warning","msg":"boom","attrs":[` +
		attrs + `]},"build":{"version":"dev","commit":"ce1f9464"},"runtime":{"is_saas":true}}]`
}

func TestNotifyShowsTriggerAttributes(t *testing.T) {
	// The CSP violation report as the platform serializes it.
	fields := slackFieldsFor(t, `[{"v":"1","triggered_at":"2026-10-18T08:57:05Z","trigger":{"time":"2026-10-18T08:57:04Z","level":"warning","msg":"CSP violation detected","attrs":[
		{"key":"document_uri","value":"https://app.craftedsignal.io/auth/login"},
		{"key":"effective_directive","value":"script-src"},
		{"key":"blocked_uri","value":"wasm-eval"},
		{"key":"source_uri","value":"chrome-extension"},
		{"key":"line_number","value":2},
		{"key":"column_number","value":34960}]},
		"before":[{"time":"2026-10-18T08:57:03Z","level":"info","msg":"request"}],
		"build":{"version":"dev","commit":"ce1f9464"},"runtime":{"is_saas":true}}]`)

	want := []string{
		"document_uri=https://app.craftedsignal.io/auth/login",
		"effective_directive=script-src",
		"blocked_uri=wasm-eval",
		"source_uri=chrome-extension",
		"line_number=2",
		"column_number=34960",
	}
	if got := detailLines(t, fields); !reflect.DeepEqual(got, want) {
		t.Errorf("details = %q, want %q", got, want)
	}
	if fields["Company"] != "unknown" {
		t.Errorf("Company = %q, want unknown", fields["Company"])
	}
}

func TestNotifyDetailsKeepNumbersExactAndSkipDedicatedFields(t *testing.T) {
	fields := slackFieldsFor(t, reportWithAttrs(`
		{"key":"company_id","value":1234567},
		{"key":"correlation_id","value":"abc"},
		{"key":"bytes","value":1048576},
		{"key":"enforced","value":true}`))

	if got, want := detailLines(t, fields), []string{"bytes=1048576", "enforced=true"}; !reflect.DeepEqual(got, want) {
		t.Errorf("details = %q, want %q", got, want)
	}
	if fields["Company"] != "1234567" {
		t.Errorf("Company = %q, want 1234567", fields["Company"])
	}
	if fields["Correlation ID"] != "abc" {
		t.Errorf("Correlation ID = %q, want abc", fields["Correlation ID"])
	}
}

func TestNotifyDetailsNeutralizeUntrustedValues(t *testing.T) {
	fields := slackFieldsFor(t, reportWithAttrs(`
		{"key":"user_agent","value":"<!channel> `+"```"+`x`+"```"+` <https://evil.example|click> a&b"},
		{"key":"error","value":"dial tcp: token=abc123 refused\nsecond line"}`))

	lines := detailLines(t, fields)
	if len(lines) != 2 {
		t.Fatalf("details = %q, want one line per attribute", lines)
	}
	for _, line := range lines {
		if strings.ContainsAny(line, "<>`") {
			t.Errorf("line %q contains mrkdwn control characters", line)
		}
	}
	if want := "user_agent=&lt;!channel&gt; '''x''' &lt;https://evil.example|click&gt; a&amp;b"; lines[0] != want {
		t.Errorf("user_agent line = %q, want %q", lines[0], want)
	}
	if want := "error=dial tcp: token=[REDACTED] refused second line"; lines[1] != want {
		t.Errorf("error line = %q, want %q", lines[1], want)
	}
}

func TestNotifyOmitsDetailsWithoutScalarValues(t *testing.T) {
	// Reporters that predate attribute values sent {} for every value.
	fields := slackFieldsFor(t, reportWithAttrs(`
		{"key":"blocked_uri","value":{}},
		{"key":"ids","value":[1,2]},
		{"key":"nothing","value":null}`))

	if _, ok := fields["Details"]; ok {
		t.Errorf("Details present for non-scalar attributes: %q", fields["Details"])
	}
}

func TestSlackDetailsAreBounded(t *testing.T) {
	long := strings.Repeat("x", 5000)
	var attrs []Attr
	for i := 0; i < 10; i++ {
		attrs = append(attrs, Attr{Key: "k" + string(rune('a'+i)), Value: long})
	}

	details := slackDetails(attrs)
	if len(details) > slackDetailsLimit {
		t.Errorf("len(details) = %d, want at most %d", len(details), slackDetailsLimit)
	}
	if first := strings.SplitN(details, "\n", 2)[0]; len(first) > slackDetailLineLimit {
		t.Errorf("len(first line) = %d, want at most %d", len(first), slackDetailLineLimit)
	}
}
