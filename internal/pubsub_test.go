package internal

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestDecodeIncidentPubSubPush(t *testing.T) {
	incident := IncidentEnvelope{
		ID:          "abc",
		Source:      "error-reporting",
		Environment: "prod",
		Service:     "platform",
		Fingerprint: "abcdef123456",
		Report: ReportPayload{
			TriggeredAt: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC),
			Trigger:     LogRecord{Level: "error", Message: "boom"},
		},
	}
	raw, err := json.Marshal(incident)
	if err != nil {
		t.Fatal(err)
	}
	push := map[string]interface{}{
		"message": map[string]interface{}{
			"data": base64.StdEncoding.EncodeToString(raw),
		},
	}
	body, err := json.Marshal(push)
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecodeIncidentPubSubPush(body, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != incident.Fingerprint {
		t.Fatalf("fingerprint = %q, want %q", got.Fingerprint, incident.Fingerprint)
	}
}

func TestDecodeCloudLoggingPubSubPush(t *testing.T) {
	entry := map[string]interface{}{
		"insertId":  "1",
		"logName":   "projects/p/logs/events",
		"severity":  "ERROR",
		"timestamp": "2026-07-29T12:00:00Z",
		"resource": map[string]interface{}{
			"type": "k8s_node",
			"labels": map[string]string{
				"container_name": "craftedsignal-worker",
			},
		},
		"jsonPayload": map[string]interface{}{
			"reason":  "OOMKilling",
			"message": "Memory cgroup out of memory",
		},
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	push := map[string]interface{}{
		"message": map[string]interface{}{
			"data": base64.StdEncoding.EncodeToString(raw),
		},
	}
	body, err := json.Marshal(push)
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecodeIncidentPubSubPush(body, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "cloud-logging" {
		t.Fatalf("source = %q, want cloud-logging", got.Source)
	}
	if got.Service != "worker" {
		t.Fatalf("service = %q, want worker", got.Service)
	}
	if got.Report.Trigger.Message != "Memory cgroup out of memory" {
		t.Fatalf("message = %q", got.Report.Trigger.Message)
	}
}
