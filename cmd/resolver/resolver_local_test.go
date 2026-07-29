package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/craftedsignal/error-reporting/internal"
)

func TestPubSubHandlerSuppressesDuplicateIncidentWithGCSStore(t *testing.T) {
	var slackCalls int
	slack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("slack method = %s, want POST", r.Method)
		}
		slackCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer slack.Close()

	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"local-token","expires_in":3600,"token_type":"Bearer"}`)
	}))
	defer metadata.Close()

	gcs := newFakeGCS(t, "local-incident-bucket")
	defer gcs.Close()

	t.Setenv("GCE_METADATA_HOST", strings.TrimPrefix(metadata.URL, "http://"))
	t.Setenv("GCS_API_BASE_URL", gcs.URL+"/storage/v1")
	t.Setenv("GCS_UPLOAD_BASE_URL", gcs.URL+"/upload/storage/v1")
	t.Setenv("INCIDENT_STORE_BUCKET", "local-incident-bucket")
	t.Setenv("INCIDENT_STORE_PREFIX", "resolver-incidents")
	t.Setenv("INCIDENT_SUPPRESSION_TTL", "168h")
	t.Setenv("SLACK_WEBHOOK_URL", slack.URL)
	t.Setenv("ENVIRONMENT", "prod")
	t.Setenv("NOTIFY_NON_PR", "true")
	t.Setenv("MAX_LOG_ENTRIES", "0")

	cfg, err := internal.LoadResolverConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadResolverConfigFromEnv() error = %v", err)
	}
	resolver := internal.NewResolver(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handler := newPubSubHandler(resolver, cfg.Environment)

	body := pubSubPushBody(t, internal.IncidentEnvelope{
		ID:          "local-oom",
		Source:      "local-test",
		ReceivedAt:  time.Now().UTC(),
		Environment: "prod",
		Service:     "platform",
		Report: internal.ReportPayload{
			FormatVersion: "1",
			TriggeredAt:   time.Now().UTC(),
			Trigger: internal.LogRecord{
				Time:    time.Now().UTC(),
				Level:   "error",
				Message: "Memory cgroup out of memory: Killed process 12345 (craftedsignal) total-vm:1960876kB anon-rss:521972kB",
			},
			Runtime: internal.RuntimeInfo{IsSaaS: true},
		},
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/pubsub", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("push %d status = %d, body = %q", i+1, rr.Code, rr.Body.String())
		}
	}

	if slackCalls != 1 {
		t.Fatalf("slack calls = %d, want 1", slackCalls)
	}
	record := gcs.onlyRecord()
	if record.Count != 2 {
		t.Fatalf("incident count = %d, want 2", record.Count)
	}
	if record.Status != "needs human review" {
		t.Fatalf("incident status = %q, want needs human review", record.Status)
	}
}

func pubSubPushBody(t *testing.T, incident internal.IncidentEnvelope) []byte {
	t.Helper()
	raw, err := json.Marshal(incident)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]interface{}{
		"message": map[string]interface{}{
			"data":      base64.StdEncoding.EncodeToString(raw),
			"messageId": "local-message",
		},
		"subscription": "local-subscription",
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type fakeGCS struct {
	*httptest.Server
	t      *testing.T
	bucket string
	mu     sync.Mutex
	next   int64
	items  map[string]fakeGCSObject
}

type fakeGCSObject struct {
	generation string
	body       []byte
}

func newFakeGCS(t *testing.T, bucket string) *fakeGCS {
	f := &fakeGCS{
		t:      t,
		bucket: bucket,
		next:   1,
		items:  make(map[string]fakeGCSObject),
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeGCS) handle(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("Authorization"); got != "Bearer local-token" {
		f.t.Fatalf("authorization = %q, want bearer token", got)
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/upload/storage/v1/b/"+f.bucket+"/o":
		f.handleUpload(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.EscapedPath(), "/storage/v1/b/"+f.bucket+"/o/"):
		f.handleGet(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGCS) handleUpload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	current, exists := f.items[name]
	if match := r.URL.Query().Get("ifGenerationMatch"); match != "" {
		switch {
		case match == "0" && exists:
			http.Error(w, "precondition failed", http.StatusPreconditionFailed)
			return
		case match != "0" && (!exists || current.generation != match):
			http.Error(w, "precondition failed", http.StatusPreconditionFailed)
			return
		}
	}
	generation := strconv.FormatInt(f.next, 10)
	f.next++
	f.items[name] = fakeGCSObject{generation: generation, body: body}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"generation":%q}`, generation)
}

func (f *fakeGCS) handleGet(w http.ResponseWriter, r *http.Request) {
	escapedName := strings.TrimPrefix(r.URL.EscapedPath(), "/storage/v1/b/"+f.bucket+"/o/")
	name, err := url.PathUnescape(escapedName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	object, exists := f.items[name]
	f.mu.Unlock()
	if !exists {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if r.URL.Query().Get("alt") == "media" {
		_, _ = w.Write(object.body)
		return
	}
	fmt.Fprintf(w, `{"generation":%q}`, object.generation)
}

func (f *fakeGCS) onlyRecord() internal.IncidentRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.items) != 1 {
		f.t.Fatalf("stored objects = %d, want 1", len(f.items))
	}
	for _, object := range f.items {
		var record internal.IncidentRecord
		if err := json.Unmarshal(object.body, &record); err != nil {
			f.t.Fatal(err)
		}
		return record
	}
	panic("unreachable")
}
