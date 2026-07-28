package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/GoogleCloudPlatform/functions-framework-go/funcframework"
	"github.com/craftedsignal/error-reporting/internal"
)

var (
	keyStore *internal.KeyStore
	deduper  *internal.Deduper
	notifier *internal.SlackNotifier
)

func init() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	keysEnv := os.Getenv("ERROR_REPORTING_PRIVATE_KEYS")
	ks, err := internal.NewKeyStore(keysEnv)
	if err != nil {
		logger.Error("failed to initialize key store", slog.String("error", err.Error()))
		os.Exit(1)
	}
	keyStore = ks

	deduper = internal.NewDeduper(5 * time.Minute)
	notifier = internal.NewSlackNotifier(os.Getenv("SLACK_WEBHOOK_URL"), os.Getenv("SLACK_CHANNEL"))

	functions.HTTP("Ingest", ingestHandler)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if err := funcframework.Start(port); err != nil {
		slog.Default().Error("framework exited", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func ingestHandler(w http.ResponseWriter, r *http.Request) {
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

	plaintext, err := keyStore.Decrypt(payload)
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
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprint(w, `{"status":"accepted"}`)
}
