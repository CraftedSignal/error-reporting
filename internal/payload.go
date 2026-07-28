package internal

import (
	"encoding/json"
	"fmt"
	"time"
)

// LogRecord mirrors the platform LogRecord shape.
type LogRecord struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"msg"`
	Attrs   []Attr    `json:"attrs,omitempty"`
}

// Attr mirrors slog.Attr for JSON unmarshaling.
type Attr struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

// BuildInfo mirrors the platform BuildInfo shape.
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	GoOS    string `json:"goos"`
	GoArch  string `json:"goarch"`
}

// RuntimeInfo mirrors the platform RuntimeInfo shape.
type RuntimeInfo struct {
	StorageDriver string `json:"storage_driver"`
	LogLevel      string `json:"log_level"`
	IsSaaS        bool   `json:"is_saas"`
	DevMode       bool   `json:"dev_mode"`
	Airgapped     bool   `json:"airgapped"`
}

// ReportPayload is one decrypted report.
type ReportPayload struct {
	FormatVersion string            `json:"v"`
	TriggeredAt   time.Time         `json:"triggered_at"`
	Trigger       LogRecord         `json:"trigger"`
	Before        []LogRecord       `json:"before,omitempty"`
	After         []LogRecord       `json:"after,omitempty"`
	Build         BuildInfo         `json:"build"`
	Runtime       RuntimeInfo       `json:"runtime"`
	ConfigSummary map[string]string `json:"config_summary,omitempty"`
}

// DecodeReportBatch parses the decrypted plaintext into a batch of reports.
func DecodeReportBatch(plaintext []byte) ([]ReportPayload, error) {
	var batch []ReportPayload
	if err := json.Unmarshal(plaintext, &batch); err != nil {
		return nil, fmt.Errorf("decode report batch: %w", err)
	}
	return batch, nil
}
