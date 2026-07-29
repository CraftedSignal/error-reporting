package internal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeIncidentStore struct {
	claim   IncidentClaim
	updates int
}

func (s *fakeIncidentStore) Claim(context.Context, IncidentEnvelope) (IncidentClaim, error) {
	return s.claim, nil
}

func (s *fakeIncidentStore) Update(context.Context, IncidentEnvelope, IncidentRecordUpdate) error {
	s.updates++
	return nil
}

type fakeAnalyzer struct {
	called bool
	plan   ResolutionPlan
}

func (a *fakeAnalyzer) Analyze(context.Context, AnalysisInput) (ResolutionPlan, error) {
	a.called = true
	return a.plan, nil
}

func TestResolverSuppressesNeedsHumanNotificationsWhenNotifyNonPRDisabled(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := ResolverConfig{
		Environment:     "prod",
		SlackWebhookURL: server.URL,
		ServiceRepos:    DefaultServiceRepos(),
		NotifyNonPR:     false,
	}
	resolver := NewResolver(cfg, nil)
	incident := IncidentEnvelope{
		Environment: "prod",
		Service:     "platform",
		Report: ReportPayload{
			FormatVersion: "1",
			TriggeredAt:   time.Now().UTC(),
			Trigger: LogRecord{
				Time:    time.Now().UTC(),
				Level:   "error",
				Message: "container OOMKilled with exit code 137",
			},
		},
	}

	if err := resolver.HandleIncident(context.Background(), incident); err != nil {
		t.Fatalf("HandleIncident() error = %v", err)
	}
	if called {
		t.Fatal("Slack webhook was called for suppressed needs-human incident")
	}
}

func TestResolverSuppressesDuplicateIncidentBeforeAnalysisAndSlack(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := &fakeIncidentStore{claim: IncidentClaim{
		New: false,
		Record: IncidentRecord{
			Fingerprint: "abc123",
			Count:       2,
		},
	}}
	analyzer := &fakeAnalyzer{plan: ResolutionPlan{
		Category:   "runtime_resource",
		Action:     "needs_human",
		Confidence: "medium",
	}}
	cfg := ResolverConfig{
		Environment:     "prod",
		SlackWebhookURL: server.URL,
		ServiceRepos:    DefaultServiceRepos(),
		NotifyNonPR:     true,
	}
	resolver := NewResolver(cfg, nil)
	resolver.store = store
	resolver.ai = analyzer

	incident := IncidentEnvelope{
		Environment: "prod",
		Service:     "platform",
		Fingerprint: "abc123",
		Report: ReportPayload{
			FormatVersion: "1",
			TriggeredAt:   time.Now().UTC(),
			Trigger: LogRecord{
				Time:    time.Now().UTC(),
				Level:   "error",
				Message: "container OOMKilled with exit code 137",
			},
		},
	}

	if err := resolver.HandleIncident(context.Background(), incident); err != nil {
		t.Fatalf("HandleIncident() error = %v", err)
	}
	if analyzer.called {
		t.Fatal("analyzer was called for duplicate incident")
	}
	if called {
		t.Fatal("Slack webhook was called for duplicate incident")
	}
	if store.updates != 0 {
		t.Fatalf("store updates = %d, want 0", store.updates)
	}
}
