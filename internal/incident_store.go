package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

var (
	ErrIncidentRecordExists = errors.New("incident record already exists")
	ErrIncidentRecordGone   = errors.New("incident record not found")
)

// StatusError is returned for non-success GCS responses so callers can
// classify failures by HTTP status code rather than message text.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("gcs incident store returned %d: %s", e.Code, e.Body)
}

// isTransientStoreError reports whether err is a rate-limit or server-side
// failure that is worth retrying.
func isTransientStoreError(err error) bool {
	var se *StatusError
	if !errors.As(err, &se) {
		return false
	}
	return se.Code == http.StatusTooManyRequests || se.Code >= 500
}

const (
	// duplicateWriteInterval bounds how often the duplicate counter of one
	// incident is rewritten. GCS allows about one write per second per object.
	duplicateWriteInterval = 10 * time.Second
	createMaxAttempts      = 4
	createRetryBackoff     = 200 * time.Millisecond
)

type IncidentStore interface {
	Claim(ctx context.Context, incident IncidentEnvelope) (IncidentClaim, error)
	Update(ctx context.Context, incident IncidentEnvelope, update IncidentRecordUpdate) error
}

type IncidentClaim struct {
	New    bool
	Record IncidentRecord
}

type IncidentRecord struct {
	ID               string    `json:"id"`
	Fingerprint      string    `json:"fingerprint"`
	ShortFingerprint string    `json:"short_fingerprint"`
	Service          string    `json:"service"`
	Environment      string    `json:"environment"`
	Source           string    `json:"source"`
	Message          string    `json:"message"`
	Status           string    `json:"status"`
	Action           string    `json:"action,omitempty"`
	Category         string    `json:"category,omitempty"`
	PRURL            string    `json:"pr_url,omitempty"`
	Count            int       `json:"count"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	LastTriggeredAt  time.Time `json:"last_triggered_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type IncidentRecordUpdate struct {
	Status   string
	Action   string
	Category string
	PRURL    string
}

type GCSIncidentStore struct {
	bucket     string
	prefix     string
	ttl        time.Duration
	apiBaseURL string
	uploadURL  string
	client     *http.Client
	tokens     AccessTokenSource

	dupInterval  time.Duration
	retryBackoff time.Duration
}

func NewGCSIncidentStore(bucket, prefix string, ttl time.Duration, tokens AccessTokenSource) *GCSIncidentStore {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	return &GCSIncidentStore{
		bucket:     bucket,
		prefix:     prefix,
		ttl:        ttl,
		apiBaseURL: envOrDefault("GCS_API_BASE_URL", "https://storage.googleapis.com/storage/v1"),
		uploadURL:  envOrDefault("GCS_UPLOAD_BASE_URL", "https://storage.googleapis.com/upload/storage/v1"),
		client:     &http.Client{Timeout: 10 * time.Second},
		tokens:     tokens,

		dupInterval:  duplicateWriteInterval,
		retryBackoff: createRetryBackoff,
	}
}

// createWithRetry attempts the first-time create, retrying transient errors
// (429/5xx) with a short exponential backoff.
func (s *GCSIncidentStore) createWithRetry(ctx context.Context, objectName string, record IncidentRecord) (IncidentRecord, error) {
	backoff := s.retryBackoff
	var err error
	for attempt := 1; ; attempt++ {
		var created IncidentRecord
		created, err = s.writeRecord(ctx, objectName, record, "0")
		if err == nil || !isTransientStoreError(err) || attempt >= createMaxAttempts {
			return created, err
		}
		select {
		case <-ctx.Done():
			return IncidentRecord{}, err
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

func (s *GCSIncidentStore) Claim(ctx context.Context, incident IncidentEnvelope) (IncidentClaim, error) {
	if s == nil || s.bucket == "" {
		return IncidentClaim{New: true}, nil
	}
	now := time.Now().UTC()
	record := NewIncidentRecord(incident, now)
	objectName := s.objectName(record)

	created, err := s.createWithRetry(ctx, objectName, record)
	if err == nil {
		return IncidentClaim{New: true, Record: created}, nil
	}
	if !errors.Is(err, ErrIncidentRecordExists) {
		if !isTransientStoreError(err) {
			return IncidentClaim{}, err
		}
		// Rate limited on create: the object may already exist (a duplicate
		// burst). If a live record is readable, treat as duplicate; otherwise
		// surface the original retryable error.
		existing, _, readErr := s.readRecord(ctx, objectName)
		if readErr != nil || s.expired(existing, now) {
			return IncidentClaim{}, err
		}
		return IncidentClaim{New: false, Record: existing}, nil
	}

	existing, generation, err := s.readRecord(ctx, objectName)
	if err != nil {
		if errors.Is(err, ErrIncidentRecordGone) {
			created, createErr := s.writeRecord(ctx, objectName, record, "0")
			if createErr == nil {
				return IncidentClaim{New: true, Record: created}, nil
			}
			if errors.Is(createErr, ErrIncidentRecordExists) {
				return IncidentClaim{New: false, Record: record}, nil
			}
			return IncidentClaim{}, createErr
		}
		return IncidentClaim{}, err
	}

	if s.expired(existing, now) {
		refreshed := NewIncidentRecord(incident, now)
		updated, updateErr := s.writeRecord(ctx, objectName, refreshed, generation)
		if updateErr == nil {
			return IncidentClaim{New: true, Record: updated}, nil
		}
		if errors.Is(updateErr, ErrIncidentRecordExists) {
			return IncidentClaim{New: false, Record: existing}, nil
		}
		return IncidentClaim{}, updateErr
	}

	// Duplicate: only rewrite the object when the stored record is older than
	// dupInterval, so a burst costs at most one write per interval.
	if !existing.UpdatedAt.IsZero() && now.Sub(existing.UpdatedAt) < s.dupInterval {
		return IncidentClaim{New: false, Record: existing}, nil
	}

	existing.Count++
	existing.LastSeen = now
	existing.LastTriggeredAt = nonZeroTime(incident.Report.TriggeredAt, existing.LastTriggeredAt, now)
	existing.UpdatedAt = now
	if incident.Source != "" {
		existing.Source = incident.Source
	}
	if incident.Report.Trigger.Message != "" {
		existing.Message = RedactString(incident.Report.Trigger.Message)
	}
	if _, updateErr := s.writeRecord(ctx, objectName, existing, generation); updateErr != nil && !errors.Is(updateErr, ErrIncidentRecordExists) {
		// A duplicate must never fail the request: the counter is best effort.
		slog.Info("duplicate incident counter update skipped",
			slog.String("fingerprint", record.Fingerprint),
			slog.String("error", updateErr.Error()))
	}
	return IncidentClaim{New: false, Record: existing}, nil
}

func (s *GCSIncidentStore) Update(ctx context.Context, incident IncidentEnvelope, update IncidentRecordUpdate) error {
	if s == nil || s.bucket == "" {
		return nil
	}
	record := NewIncidentRecord(incident, time.Now().UTC())
	objectName := s.objectName(record)
	existing, generation, err := s.readRecord(ctx, objectName)
	if err != nil {
		if errors.Is(err, ErrIncidentRecordGone) {
			return nil
		}
		return err
	}
	now := time.Now().UTC()
	if update.Status != "" {
		existing.Status = update.Status
	}
	if update.Action != "" {
		existing.Action = update.Action
	}
	if update.Category != "" {
		existing.Category = update.Category
	}
	if update.PRURL != "" {
		existing.PRURL = update.PRURL
	}
	existing.UpdatedAt = now
	_, err = s.writeRecord(ctx, objectName, existing, generation)
	if errors.Is(err, ErrIncidentRecordExists) {
		return nil
	}
	return err
}

func NewIncidentRecord(incident IncidentEnvelope, now time.Time) IncidentRecord {
	triggeredAt := nonZeroTime(incident.Report.TriggeredAt, incident.Report.Trigger.Time, now)
	fingerprint := incident.Fingerprint
	if fingerprint == "" {
		service := firstNonEmpty(incident.Service, ServiceFromReport(incident.Report))
		fingerprint = FingerprintReport(service, incident.Report)
	}
	service := NormalizeServiceName(firstNonEmpty(incident.Service, ServiceFromReport(incident.Report)))
	environment := firstNonEmpty(incident.Environment, "prod")
	return IncidentRecord{
		ID:               firstNonEmpty(incident.ID, fmt.Sprintf("%s-%d", ShortFingerprint(fingerprint), triggeredAt.Unix())),
		Fingerprint:      fingerprint,
		ShortFingerprint: ShortFingerprint(fingerprint),
		Service:          service,
		Environment:      environment,
		Source:           incident.Source,
		Message:          RedactString(incident.Report.Trigger.Message),
		Status:           "processing",
		Count:            1,
		FirstSeen:        now,
		LastSeen:         now,
		LastTriggeredAt:  triggeredAt,
		UpdatedAt:        now,
	}
}

func (s *GCSIncidentStore) expired(record IncidentRecord, now time.Time) bool {
	if s.ttl <= 0 || record.FirstSeen.IsZero() {
		return false
	}
	return now.Sub(record.FirstSeen) > s.ttl
}

func (s *GCSIncidentStore) objectName(record IncidentRecord) string {
	return path.Join(strings.Trim(s.prefix, "/"), record.Environment, record.Service, record.Fingerprint+".json")
}

func (s *GCSIncidentStore) readRecord(ctx context.Context, objectName string) (IncidentRecord, string, error) {
	var metadata struct {
		Generation string `json:"generation"`
	}
	if err := s.doJSON(ctx, http.MethodGet, s.objectURL(objectName, false), nil, &metadata); err != nil {
		return IncidentRecord{}, "", err
	}
	var record IncidentRecord
	if err := s.doJSON(ctx, http.MethodGet, s.objectURL(objectName, true), nil, &record); err != nil {
		return IncidentRecord{}, "", err
	}
	return record, metadata.Generation, nil
}

func (s *GCSIncidentStore) writeRecord(ctx context.Context, objectName string, record IncidentRecord, ifGenerationMatch string) (IncidentRecord, error) {
	body, err := json.Marshal(record)
	if err != nil {
		return IncidentRecord{}, fmt.Errorf("marshal incident record: %w", err)
	}
	params := url.Values{}
	params.Set("uploadType", "media")
	params.Set("name", objectName)
	if ifGenerationMatch != "" {
		params.Set("ifGenerationMatch", ifGenerationMatch)
	}
	u := fmt.Sprintf("%s/b/%s/o?%s", strings.TrimRight(s.uploadURL, "/"), url.PathEscape(s.bucket), params.Encode())
	var stored struct {
		Generation string `json:"generation"`
	}
	if err := s.doJSON(ctx, http.MethodPost, u, body, &stored); err != nil {
		return IncidentRecord{}, err
	}
	return record, nil
}

func (s *GCSIncidentStore) objectURL(objectName string, media bool) string {
	params := url.Values{}
	if media {
		params.Set("alt", "media")
	}
	suffix := ""
	if encoded := params.Encode(); encoded != "" {
		suffix = "?" + encoded
	}
	return fmt.Sprintf("%s/b/%s/o/%s%s", strings.TrimRight(s.apiBaseURL, "/"), url.PathEscape(s.bucket), url.PathEscape(objectName), suffix)
}

func (s *GCSIncidentStore) doJSON(ctx context.Context, method, rawURL string, body []byte, out interface{}) error {
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return err
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrIncidentRecordGone
	}
	if resp.StatusCode == http.StatusPreconditionFailed {
		return ErrIncidentRecordExists
	}
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(respBody))}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode gcs incident store response: %w", err)
	}
	return nil
}

func nonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Now().UTC()
}
