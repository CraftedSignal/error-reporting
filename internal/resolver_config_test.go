package internal

import "testing"

func TestResolveIncidentRepoUsesConfiguredRoute(t *testing.T) {
	repos := map[string]ServiceRepoConfig{
		"app": {
			Repo:       "Example/app",
			BaseBranch: "main",
		},
		"deploy": {
			Repo:       "Example/deploy",
			BaseBranch: "main",
			Routes: []IncidentRoute{
				{Match: []string{"resource_type=cluster_event", "reason=capacity_exceeded"}},
			},
		},
	}
	incident := IncidentEnvelope{
		Service: "app",
		Report: ReportPayload{
			Trigger: LogRecord{
				Message: "capacity exceeded while scheduling workload",
				Attrs: []Attr{
					{Key: "resource_type", Value: "cluster_event"},
					{Key: "reason", Value: "Capacity_Exceeded"},
				},
			},
		},
	}

	service, cfg, ok := ResolveIncidentRepo(repos, incident)
	if !ok {
		t.Fatal("ResolveIncidentRepo() did not resolve")
	}
	if service != "deploy" || cfg.Repo != "Example/deploy" {
		t.Fatalf("ResolveIncidentRepo() = %q/%q, want deploy/Example/deploy", service, cfg.Repo)
	}
}

func TestParseServiceRepoConfigRejectsInvalidRoutePattern(t *testing.T) {
	raw := `{"app":{"repo":"Example/app","routes":[{"match":["["]}]}}`
	if _, err := ParseServiceRepoConfig(raw); err == nil {
		t.Fatal("expected invalid route pattern error")
	}
}
