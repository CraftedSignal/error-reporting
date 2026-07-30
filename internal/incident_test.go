package internal

import "testing"

func TestNewIncidentEnvelopeStableFingerprint(t *testing.T) {
	report := ReportPayload{
		Trigger: LogRecord{
			Level:   "error",
			Message: "failed to parse YAML bundle 12345",
			Attrs: []Attr{
				{Key: "service", Value: "ti-bot"},
				{Key: "error", Value: "line 99: invalid token"},
			},
		},
	}

	a := NewIncidentEnvelope(report, "prod")
	report.Trigger.Message = "failed to parse YAML bundle 67890"
	report.Trigger.Attrs[1].Value = "line 42: invalid token"
	b := NewIncidentEnvelope(report, "prod")

	if a.Service != "ti-bot" {
		t.Fatalf("service = %q, want ti-bot", a.Service)
	}
	if a.Fingerprint != b.Fingerprint {
		t.Fatalf("fingerprint drifted: %s != %s", a.Fingerprint, b.Fingerprint)
	}
}

func TestServiceFromReportFallbacks(t *testing.T) {
	tests := []struct {
		name   string
		report ReportPayload
		want   string
	}{
		{
			name: "attr",
			report: ReportPayload{Trigger: LogRecord{Attrs: []Attr{
				{Key: "container_name", Value: "worker"},
			}}},
			want: "worker",
		},
		{
			name: "config",
			report: ReportPayload{
				ConfigSummary: map[string]string{"service": "api"},
			},
			want: "api",
		},
		{
			name:   "default",
			report: ReportPayload{Trigger: LogRecord{Message: "database failed"}},
			want:   "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ServiceFromReport(tt.report); got != tt.want {
				t.Fatalf("ServiceFromReport() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFingerprintStableAcrossTemporalWorkflowRuns(t *testing.T) {
	// Real prod payloads: the same recurring Temporal failure from two
	// consecutive scheduled cycles. Only workflow/run IDs and the batch
	// offset differ — the fingerprint must not.
	const cycleA = `child workflow execution error (type: ThreatFeedSyncWorkflow, workflowID: 019fb164-cadb-79d9-85ba-457eaf0327ee_5, runID: 019fb164-d607-7099-b027-5c356f30f77b, initiatedEventID: 5, startedEventID: 6): activity error (type: FetchAndSyncBundle, scheduledEventID: 5, startedEventID: 6, identity: 1@craftedsignal-worker-7c58d85cdf-cbpff@): segmented sync failed: failed to insert CVEs (batch 1000-1500): ERROR: duplicate key value violates unique constraint "threat_brief_cves_tbc_brief_id_tbc_cve_id_key" (SQLSTATE 23505)`
	const cycleB = `child workflow execution error (type: ThreatFeedSyncWorkflow, workflowID: 019fb149-51ff-760e-9299-fb9c1341be4a_5, runID: 019fb149-52c2-7562-8095-3575a6dfb002, initiatedEventID: 5, startedEventID: 6): activity error (type: FetchAndSyncBundle, scheduledEventID: 5, startedEventID: 6, identity: 1@craftedsignal-worker-7c58d85cdf-cbpff@): segmented sync failed: failed to insert CVEs (batch 2000-2500): ERROR: duplicate key value violates unique constraint "threat_brief_cves_tbc_brief_id_tbc_cve_id_key" (SQLSTATE 23505)`

	payload := func(errText string) ReportPayload {
		return ReportPayload{
			Trigger: LogRecord{
				Level:   "error",
				Message: "scheduled threat feed sync failed",
				Attrs:   []Attr{{Key: "error", Value: errText}},
			},
		}
	}

	a := FingerprintReport("platform", payload(cycleA))
	b := FingerprintReport("platform", payload(cycleB))
	if a != b {
		t.Fatalf("fingerprint unstable across runs of the same incident:\n  normalized A: %s\n  normalized B: %s",
			normalizeFingerprintText(cycleA), normalizeFingerprintText(cycleB))
	}
}
