package internal

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type cloudLogSinkEntry struct {
	InsertID     string                 `json:"insertId"`
	LogName      string                 `json:"logName"`
	Severity     string                 `json:"severity"`
	Timestamp    string                 `json:"timestamp"`
	TextPayload  string                 `json:"textPayload"`
	JSONPayload  map[string]interface{} `json:"jsonPayload"`
	ProtoPayload map[string]interface{} `json:"protoPayload"`
	Resource     struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
}

// IncidentFromCloudLogEntry converts a raw Cloud Logging sink entry into the
// same incident shape used for encrypted application reports.
func IncidentFromCloudLogEntry(raw []byte, environment string) (IncidentEnvelope, error) {
	var entry cloudLogSinkEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return IncidentEnvelope{}, fmt.Errorf("decode cloud log entry: %w", err)
	}

	ts := time.Now().UTC()
	if entry.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err == nil {
			ts = parsed.UTC()
		}
	}

	message := cloudLogMessage(entry)
	service := NormalizeServiceName(firstNonEmpty(
		entry.Resource.Labels["container_name"],
		entry.Resource.Labels["service_name"],
		entry.Resource.Labels["namespace_name"],
	))

	attrs := []Attr{
		{Key: "log_name", Value: entry.LogName},
		{Key: "insert_id", Value: entry.InsertID},
		{Key: "resource_type", Value: entry.Resource.Type},
	}
	for k, v := range entry.Resource.Labels {
		attrs = append(attrs, Attr{Key: "resource." + k, Value: v})
	}
	for _, key := range []string{"reason", "message", "msg", "error"} {
		if value, ok := entry.JSONPayload[key]; ok {
			attrs = append(attrs, Attr{Key: key, Value: RedactString(fmt.Sprintf("%v", value))})
		}
	}

	report := ReportPayload{
		FormatVersion: "1",
		TriggeredAt:   ts,
		Trigger: LogRecord{
			Time:    ts,
			Level:   strings.ToLower(firstNonEmpty(entry.Severity, "error")),
			Message: RedactString(message),
			Attrs:   attrs,
		},
		Runtime: RuntimeInfo{IsSaaS: true},
		ConfigSummary: map[string]string{
			"log_source": "cloud_logging",
		},
	}
	fingerprint := FingerprintReport(service, report)
	return IncidentEnvelope{
		ID:          fmt.Sprintf("%s-%d", ShortFingerprint(fingerprint), ts.Unix()),
		Source:      "cloud-logging",
		ReceivedAt:  time.Now().UTC(),
		Environment: environment,
		Service:     service,
		Fingerprint: fingerprint,
		Report:      report,
	}, nil
}

func cloudLogMessage(entry cloudLogSinkEntry) string {
	if entry.TextPayload != "" {
		return entry.TextPayload
	}
	for _, key := range []string{"message", "msg", "error", "reason"} {
		if value, ok := entry.JSONPayload[key]; ok && value != nil {
			return fmt.Sprintf("%v", value)
		}
	}
	if method, ok := entry.ProtoPayload["methodName"]; ok && method != nil {
		return fmt.Sprintf("%v", method)
	}
	if entry.Severity != "" {
		return entry.Severity
	}
	return "cloud log entry"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
