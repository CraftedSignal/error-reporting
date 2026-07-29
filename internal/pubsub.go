package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PubSubPublisher publishes normalized incidents to a Pub/Sub topic using the
// Cloud Run service account's metadata token.
type PubSubPublisher struct {
	projectID  string
	topic      string
	apiBaseURL string
	client     *http.Client
	tokens     AccessTokenSource
}

func NewPubSubPublisher(projectID, topic string, tokens AccessTokenSource) *PubSubPublisher {
	return &PubSubPublisher{
		projectID:  projectID,
		topic:      topic,
		apiBaseURL: "https://pubsub.googleapis.com/v1",
		client:     &http.Client{Timeout: 5 * time.Second},
		tokens:     tokens,
	}
}

func (p *PubSubPublisher) PublishIncident(ctx context.Context, incident IncidentEnvelope) (string, error) {
	if p == nil || p.topic == "" {
		return "", nil
	}
	if p.projectID == "" && !strings.HasPrefix(p.topic, "projects/") {
		return "", fmt.Errorf("project id required for topic %q", p.topic)
	}
	token, err := p.tokens.Token(ctx)
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(incident)
	if err != nil {
		return "", fmt.Errorf("marshal incident: %w", err)
	}

	reqBody, err := json.Marshal(map[string]interface{}{
		"messages": []map[string]interface{}{
			{
				"data": base64.StdEncoding.EncodeToString(payload),
				"attributes": map[string]string{
					"fingerprint": incident.Fingerprint,
					"service":     incident.Service,
					"environment": incident.Environment,
					"source":      incident.Source,
				},
			},
		},
	})
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/%s:publish", strings.TrimRight(p.apiBaseURL, "/"), p.topicResourceName())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("pubsub publish: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("pubsub publish returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result struct {
		MessageIDs []string `json:"messageIds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode pubsub publish response: %w", err)
	}
	if len(result.MessageIDs) == 0 {
		return "", fmt.Errorf("pubsub publish response missing message id")
	}
	return result.MessageIDs[0], nil
}

func (p *PubSubPublisher) topicResourceName() string {
	if strings.HasPrefix(p.topic, "projects/") {
		return p.topic
	}
	return fmt.Sprintf("projects/%s/topics/%s", p.projectID, p.topic)
}

type PubSubPushEnvelope struct {
	Message struct {
		Data        string            `json:"data"`
		Attributes  map[string]string `json:"attributes"`
		MessageID   string            `json:"messageId"`
		PublishTime string            `json:"publishTime"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// DecodeIncidentPubSubPush decodes a Cloud Run Pub/Sub push request. It accepts
// both normalized IncidentEnvelope messages and raw Cloud Logging sink entries.
func DecodeIncidentPubSubPush(body []byte, environment string) (IncidentEnvelope, error) {
	var envelope PubSubPushEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return IncidentEnvelope{}, fmt.Errorf("decode pubsub push envelope: %w", err)
	}
	if envelope.Message.Data == "" {
		return IncidentEnvelope{}, fmt.Errorf("pubsub push missing message.data")
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.Message.Data)
	if err != nil {
		return IncidentEnvelope{}, fmt.Errorf("decode pubsub message data: %w", err)
	}

	var incident IncidentEnvelope
	if err := json.Unmarshal(raw, &incident); err == nil && (incident.Fingerprint != "" || incident.Report.Trigger.Message != "") {
		if incident.Environment == "" {
			incident.Environment = environment
		}
		if incident.Service == "" {
			incident.Service = ServiceFromReport(incident.Report)
		}
		if incident.Fingerprint == "" {
			incident.Fingerprint = FingerprintReport(incident.Service, incident.Report)
		}
		if incident.ID == "" {
			incident.ID = ShortFingerprint(incident.Fingerprint)
		}
		if incident.ReceivedAt.IsZero() {
			incident.ReceivedAt = time.Now().UTC()
		}
		return incident, nil
	}

	return IncidentFromCloudLogEntry(raw, environment)
}
