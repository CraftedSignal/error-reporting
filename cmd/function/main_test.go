package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/craftedsignal/error-reporting/internal"
)

func TestIngestDeliversEncryptedReportsAndSuppressesDuplicates(t *testing.T) {
	publicKey, keys := ingestKeys(t)
	var notifications []struct {
		Attachments []struct {
			Title  string
			Fields []struct{ Title, Value string }
		}
	}
	slack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var notification struct {
			Attachments []struct {
				Title  string
				Fields []struct{ Title, Value string }
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&notification); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		notifications = append(notifications, notification)
	}))
	defer slack.Close()

	handler := newIngestHandler(keys, internal.NewDeduper(time.Minute), internal.NewSlackNotifier(slack.URL, ""))
	body := sealBatch(t, publicKey, `[{"v":"1","trigger":{"level":"error","msg":"query failed","attrs":[{"key":"error","value":"connection refused"}]},"runtime":{"is_saas":true}}]`)
	for range 2 {
		request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/logs", bytes.NewReader(body))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusAccepted || response.Body.String() != `{"status":"accepted"}` {
			t.Fatalf("ingest response = %d %q", response.Code, response.Body.String())
		}
	}
	if len(notifications) != 1 || len(notifications[0].Attachments) != 1 {
		t.Fatalf("Slack notifications = %+v, want one alert", notifications)
	}
	attachment := notifications[0].Attachments[0]
	if attachment.Title != "[ERROR] query failed" {
		t.Fatalf("Slack alert title = %q", attachment.Title)
	}
	for _, field := range attachment.Fields {
		if field.Title == "Details" && strings.Contains(field.Value, "error=connection refused") {
			return
		}
	}
	t.Fatalf("Slack alert lost the error details: %+v", attachment.Fields)
}

func TestIngestRejectsInvalidRequests(t *testing.T) {
	publicKey, keys := ingestKeys(t)
	for _, test := range []struct {
		name   string
		method string
		body   []byte
		status int
	}{
		{"method", http.MethodGet, nil, http.StatusMethodNotAllowed},
		{"malformed envelope", http.MethodPost, []byte("{"), http.StatusBadRequest},
		{"unknown key", http.MethodPost, []byte(`{"v":"1","kid":"v99","ct":"AA=="}`), http.StatusUnauthorized},
		{"malformed batch", http.MethodPost, sealBatch(t, publicKey, "not json"), http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := newIngestHandler(keys, internal.NewDeduper(time.Minute), internal.NewSlackNotifier("", ""))
			request := httptest.NewRequestWithContext(context.Background(), test.method, "/logs", bytes.NewReader(test.body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("ingest status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func ingestKeys(t *testing.T) (ed25519.PublicKey, *internal.KeyStore) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := internal.NewKeyStore(hex.EncodeToString(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, keys
}

func sealBatch(t *testing.T, publicKey ed25519.PublicKey, batch string) []byte {
	t.Helper()
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	var curvePublicKey [32]byte
	copy(curvePublicKey[:], point.BytesMontgomery())
	ciphertext, err := box.SealAnonymous(nil, []byte(batch), &curvePublicKey, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(internal.EncryptedPayload{
		FormatVersion: "1", KeyID: "v1", CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
