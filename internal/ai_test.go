package internal

import "testing"

func TestDecodeResolutionPlan(t *testing.T) {
	plan, err := DecodeResolutionPlan(`{"category":"code_bug","action":"open_pr","confidence":"high","file_edits":[{"path":"main.go","find":"a","replace":"b"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != "open_pr" || len(plan.FileEdits) != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestDecodeResolutionPlanRepairsRawNewlineInString(t *testing.T) {
	plan, err := DecodeResolutionPlan("{\"category\":\"code_bug\",\"action\":\"needs_human\",\"summary\":\"line one\nline two\"}")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary != "line one\nline two" {
		t.Fatalf("summary = %q", plan.Summary)
	}
}

func TestHeuristicPlanOOM(t *testing.T) {
	plan := HeuristicPlan(IncidentEnvelope{
		Report: ReportPayload{
			Trigger: LogRecord{
				Message: "Container killed by OOMKilled",
			},
		},
	})
	if plan.Category != "runtime_resource" || plan.Action != "needs_human" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}
