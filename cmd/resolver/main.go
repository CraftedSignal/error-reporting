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

	cfg, err := internal.LoadResolverConfigFromEnv()
	if err != nil {
		logger.Error("failed to load resolver config", slog.String("error", err.Error()))
		os.Exit(1)
	}
	resolver := internal.NewResolver(cfg, logger)

	mux := http.NewServeMux()
	mux.HandleFunc("/pubsub", newPubSubHandler(resolver, cfg.Environment))
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
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	logger.Info("starting error resolver", slog.String("addr", server.Addr))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server exited", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func newPubSubHandler(resolver *internal.Resolver, environment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		incident, err := internal.DecodeIncidentPubSubPush(body, environment)
		if err != nil {
			slog.Warn("failed to decode pubsub incident", slog.String("error", err.Error()))
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 9*time.Minute)
		defer cancel()
		if err := resolver.HandleIncident(ctx, incident); err != nil {
			slog.Warn("failed to resolve incident",
				slog.String("service", incident.Service),
				slog.String("fingerprint", incident.Fingerprint),
				slog.String("error", err.Error()))
			http.Error(w, "resolver failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
