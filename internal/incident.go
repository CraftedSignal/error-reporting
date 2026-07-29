package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// IncidentEnvelope is the normalized event handed from the ingestor or a
// Cloud Logging sink to the resolver worker.
type IncidentEnvelope struct {
	ID          string        `json:"id"`
	Source      string        `json:"source"`
	ReceivedAt  time.Time     `json:"received_at"`
	Environment string        `json:"environment"`
	Service     string        `json:"service"`
	Fingerprint string        `json:"fingerprint"`
	Report      ReportPayload `json:"report"`
}

// NewIncidentEnvelope converts a decrypted platform report into a resolver
// incident. Fingerprints are intentionally stable across repeated occurrences.
func NewIncidentEnvelope(report ReportPayload, environment string) IncidentEnvelope {
	if environment == "" {
		environment = envLabel(report.Runtime)
	}
	if report.TriggeredAt.IsZero() {
		report.TriggeredAt = time.Now().UTC()
	}

	service := ServiceFromReport(report)
	fingerprint := FingerprintReport(service, report)
	return IncidentEnvelope{
		ID:          fmt.Sprintf("%s-%d", ShortFingerprint(fingerprint), report.TriggeredAt.Unix()),
		Source:      "error-reporting",
		ReceivedAt:  time.Now().UTC(),
		Environment: environment,
		Service:     service,
		Fingerprint: fingerprint,
		Report:      report,
	}
}

// ServiceFromReport extracts the best available service identity from a report.
func ServiceFromReport(report ReportPayload) string {
	if v := AttrString(report.Trigger.Attrs, "service", "app", "application", "component", "container", "container_name"); v != "" {
		return NormalizeServiceName(v)
	}
	for _, key := range []string{"service", "app", "application", "component", "container", "container_name"} {
		if v := report.ConfigSummary[key]; v != "" {
			return NormalizeServiceName(v)
		}
	}
	msg := strings.ToLower(report.Trigger.Message)
	switch {
	case strings.Contains(msg, "ti-bot"), strings.Contains(msg, "threat intel"), strings.Contains(msg, "auto-publish"):
		return "ti-bot"
	case strings.Contains(msg, "error-reporting"):
		return "error-reporting"
	default:
		return "platform"
	}
}

// FingerprintReport returns a stable fingerprint that suppresses repeated
// incidents while still separating services and high-level error classes.
func FingerprintReport(service string, report ReportPayload) string {
	errText := AttrString(report.Trigger.Attrs, "error", "err", "exception", "panic")
	parts := []string{
		NormalizeServiceName(service),
		strings.ToLower(report.Trigger.Level),
		normalizeFingerprintText(report.Trigger.Message),
		normalizeFingerprintText(errText),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

// ShortFingerprint trims a fingerprint for branch names and Slack messages.
func ShortFingerprint(fingerprint string) string {
	if len(fingerprint) <= 12 {
		return fingerprint
	}
	return fingerprint[:12]
}

// AttrString returns the first string-like value for any requested attr key.
func AttrString(attrs []Attr, keys ...string) string {
	for _, key := range keys {
		for _, attr := range attrs {
			if !strings.EqualFold(attr.Key, key) {
				continue
			}
			if attr.Value == nil {
				return ""
			}
			return strings.TrimSpace(fmt.Sprintf("%v", attr.Value))
		}
	}
	return ""
}

// NormalizeServiceName keeps service keys stable for repository routing.
func NormalizeServiceName(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "craftedsignal-")
	value = strings.TrimPrefix(value, "craftedsignal/")
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.Trim(value, " .:/")
	if value == "" {
		return "platform"
	}
	return value
}

var fingerprintNoise = regexp.MustCompile(`(?i)\b([0-9a-f]{8,}|[0-9]+|[0-9a-f-]{32,})\b`)

func normalizeFingerprintText(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = fingerprintNoise.ReplaceAllString(value, "#")
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 300 {
		return value[:300]
	}
	return value
}
