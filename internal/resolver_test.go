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
		ServiceRepos: map[string]ServiceRepoConfig{
			"application": {Repo: "Example/application", BaseBranch: "main"},
		},
		NotifyNonPR: false,
	}
	resolver := NewResolver(cfg, nil)
	incident := IncidentEnvelope{
		Environment: "prod",
		Service:     "application",
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
		ServiceRepos: map[string]ServiceRepoConfig{
			"application": {Repo: "Example/application", BaseBranch: "main"},
		},
		NotifyNonPR: true,
	}
	resolver := NewResolver(cfg, nil)
	resolver.store = store
	resolver.ai = analyzer

	incident := IncidentEnvelope{
		Environment: "prod",
		Service:     "application",
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

// Investigated-but-no-action outcomes flooded #alerts-prod (scraper blips,
// boot-churn transients — every one an @here). They stay recorded in the
// incident store but must not notify Slack unless explicitly enabled.
func TestResolverDoesNotNotifySlackForNoPRInvestigations(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	analyzer := &fakeAnalyzer{plan: ResolutionPlan{
		Category:   "external_source",
		Action:     "no_pr",
		Confidence: "high",
	}}
	cfg := ResolverConfig{
		Environment:     "prod",
		SlackWebhookURL: server.URL,
		AIAPIKey:        "test-key",
		AIModel:         "test-model",
		ServiceRepos: map[string]ServiceRepoConfig{
			"application": {Repo: "Example/application", BaseBranch: "main"},
		},
		NotifyNonPR: true,
	}
	resolver := NewResolver(cfg, nil)
	store := &fakeIncidentStore{claim: IncidentClaim{New: true}}
	resolver.store = store
	resolver.ai = analyzer

	incident := IncidentEnvelope{
		Environment: "prod",
		Service:     "application",
		Fingerprint: "nopr123",
		Report: ReportPayload{
			FormatVersion: "1",
			TriggeredAt:   time.Now().UTC(),
			Trigger: LogRecord{
				Time:    time.Now().UTC(),
				Level:   "error",
				Message: "scraper error",
			},
		},
	}
	if err := resolver.HandleIncident(context.Background(), incident); err != nil {
		t.Fatalf("HandleIncident() error = %v", err)
	}
	t.Logf("analyzer.called=%v webhook.called=%v store.updates=%d", analyzer.called, called, store.updates)
	if !analyzer.called {
		t.Fatal("analyzer was not called")
	}
	if called {
		t.Fatal("Slack webhook was called for a no_pr investigation")
	}
}
