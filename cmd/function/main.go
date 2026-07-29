package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/craftedsignal/error-reporting/internal"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	keysEnv := os.Getenv("ERROR_REPORTING_PRIVATE_KEYS")
	ks, err := internal.NewKeyStore(keysEnv)
	if err != nil {
		logger.Error("failed to initialize key store", slog.String("error", err.Error()))
		os.Exit(1)
	}

	deduper := internal.NewDeduper(5 * time.Minute)
	notifier := internal.NewSlackNotifier(os.Getenv("SLACK_WEBHOOK_URL"), os.Getenv("SLACK_CHANNEL"))
	var publisher *internal.PubSubPublisher
	if topic := os.Getenv("ERROR_RESOLVER_TOPIC"); topic != "" {
		publisher = internal.NewPubSubPublisher(os.Getenv("PROJECT_ID"), topic, internal.NewMetadataAccessTokenSource())
	}

	handler := newIngestHandler(ks, deduper, notifier, publisher, os.Getenv("ENVIRONMENT"))

	mux := http.NewServeMux()
	mux.HandleFunc("/logs", handler)
	// Health/readiness probe used by Cloud Run.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	logger.Info("starting error reporting ingestor", slog.String("addr", server.Addr))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server exited", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func newIngestHandler(ks *internal.KeyStore, deduper *internal.Deduper, notifier *internal.SlackNotifier, publisher *internal.PubSubPublisher, environment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20)) // 2 MiB max
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		payload, err := internal.DecodeEncryptedBody(body)
		if err != nil {
			slog.Warn("failed to decode encrypted body", slog.String("error", err.Error()))
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		plaintext, err := ks.Decrypt(payload)
		if err != nil {
			slog.Warn("failed to decrypt payload", slog.String("error", err.Error()))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		reports, err := internal.DecodeReportBatch(plaintext)
		if err != nil {
			slog.Warn("failed to decode report batch", slog.String("error", err.Error()))
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		for _, report := range reports {
			if deduper.Seen(report) {
				continue
			}
			if err := notifier.Notify(r.Context(), report); err != nil {
				slog.Warn("failed to notify slack", slog.String("error", err.Error()))
				// Continue processing other reports.
			}
			if publisher != nil {
				ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				incident := internal.NewIncidentEnvelope(report, environment)
				if id, err := publisher.PublishIncident(ctx, incident); err != nil {
					slog.Warn("failed to publish resolver incident",
						slog.String("fingerprint", incident.Fingerprint),
						slog.String("error", err.Error()))
				} else {
					slog.Info("published resolver incident",
						slog.String("message_id", id),
						slog.String("service", incident.Service),
						slog.String("fingerprint", incident.Fingerprint))
				}
				cancel()
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"status":"accepted"}`)
	}
}
