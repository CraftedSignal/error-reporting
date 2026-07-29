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
				{Key: "container_name", Value: "craftedsignal-worker"},
			}}},
			want: "worker",
		},
		{
			name:   "message",
			report: ReportPayload{Trigger: LogRecord{Message: "ti-bot auto-publish failed"}},
			want:   "ti-bot",
		},
		{
			name:   "default",
			report: ReportPayload{Trigger: LogRecord{Message: "database failed"}},
			want:   "platform",
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
