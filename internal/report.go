package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	maxReportBatchSize   = 4 << 20
	maxReportsPerBatch   = 100
	maxLogRecords        = 1000
	maxAttrsPerLogRecord = 128
	maxMessageSize       = 64 << 10
	maxAttrKeySize       = 256
	maxConfigEntries     = 128
	reportFormatVersion  = "1"
)

var (
	ErrEmptyBatch         = errors.New("empty report batch")
	ErrBatchTooLarge      = errors.New("report batch too large")
	ErrInvalidReport      = errors.New("invalid report")
	ErrTrailingData       = errors.New("unexpected trailing JSON data")
	ErrUnsupportedVersion = errors.New("unsupported report format version")
)

type LogRecord struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"msg"`
	Attrs   []Attr    `json:"attrs,omitempty"`
}
type Attr struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	GoOS    string `json:"goos"`
	GoArch  string `json:"goarch"`
}
type RuntimeInfo struct {
	StorageDriver string `json:"storage_driver"`
	LogLevel      string `json:"log_level"`
	IsSaaS        bool   `json:"is_saas"`
	DevMode       bool   `json:"dev_mode"`
	Airgapped     bool   `json:"airgapped"`
}
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

// DecodeReportBatch preserves numeric precision and accepts unknown fields
// for forward compatibility, while enforcing structural and size limits.
func DecodeReportBatch(plaintext []byte) ([]ReportPayload, error) {
	if len(plaintext) > maxReportBatchSize {
		return nil, ErrBatchTooLarge
	}
	if len(bytes.TrimSpace(plaintext)) == 0 {
		return nil, ErrEmptyBatch
	}
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("decode report batch: %w", err)
	}
	if token != json.Delim('[') {
		return nil, fmt.Errorf("%w: expected array", ErrInvalidReport)
	}
	batch := make([]ReportPayload, 0, 8)
	for dec.More() {
		if len(batch) >= maxReportsPerBatch {
			return nil, ErrBatchTooLarge
		}
		var r ReportPayload
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("decode report %d: %w", len(batch), err)
		}
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("report %d: %w", len(batch), err)
		}
		batch = append(batch, r)
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("close batch: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrTrailingData
	}
	if len(batch) == 0 {
		return nil, ErrEmptyBatch
	}
	return batch, nil
}

func (r ReportPayload) Validate() error {
	if r.FormatVersion != reportFormatVersion {
		return ErrUnsupportedVersion
	}
	if r.TriggeredAt.IsZero() {
		return fmt.Errorf("%w: missing triggered_at", ErrInvalidReport)
	}
	if err := r.Trigger.Validate(); err != nil {
		return fmt.Errorf("trigger: %w", err)
	}
	if len(r.Before) > maxLogRecords || len(r.After) > maxLogRecords {
		return fmt.Errorf("%w: too many contextual logs", ErrInvalidReport)
	}
	for i, v := range r.Before {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("before[%d]: %w", i, err)
		}
	}
	for i, v := range r.After {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("after[%d]: %w", i, err)
		}
	}
	if len(r.ConfigSummary) > maxConfigEntries {
		return fmt.Errorf("%w: too many configuration entries", ErrInvalidReport)
	}
	return nil
}
func (r LogRecord) Validate() error {
	if r.Time.IsZero() || strings.TrimSpace(r.Level) == "" {
		return fmt.Errorf("%w: missing timestamp or level", ErrInvalidReport)
	}
	if len(r.Message) > maxMessageSize || len(r.Attrs) > maxAttrsPerLogRecord {
		return fmt.Errorf("%w: log limits exceeded", ErrInvalidReport)
	}
	for i, a := range r.Attrs {
		if len(a.Key) > maxAttrKeySize {
			return fmt.Errorf("%w: attribute %d key too long", ErrInvalidReport, i)
		}
	}
	return nil
}
func (r LogRecord) GetAttr(key string) (any, bool) {
	for _, a := range r.Attrs {
		if a.Key == key {
			return a.Value, true
		}
	}
	return nil, false
}
func (r LogRecord) GetAttrString(key string) (string, bool) {
	v, ok := r.GetAttr(key)
	if !ok || v == nil {
		return "", false
	}
	return fmt.Sprint(v), true
}
func (r ReportPayload) CompanyID() (string, bool) { return r.Trigger.GetAttrString("company_id") }
