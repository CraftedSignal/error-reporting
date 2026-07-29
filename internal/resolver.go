package internal

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

type Resolver struct {
	cfg      ResolverConfig
	logger   *slog.Logger
	ai       Analyzer
	github   *GitHubClient
	logs     *CloudLoggingClient
	notifier *SlackNotifier
}

type ResolutionNotification struct {
	Mention        string
	Service        string
	Environment    string
	Category       string
	Fingerprint    string
	PRURL          string
	DeployedSource string
	Error          string
	Status         string
	Impact         string
	Confidence     string
}

func NewResolver(cfg ResolverConfig, logger *slog.Logger) *Resolver {
	if logger == nil {
		logger = slog.Default()
	}
	tokens := NewMetadataAccessTokenSource()
	return &Resolver{
		cfg:      cfg,
		logger:   logger,
		ai:       NewAIClient(cfg.AIEndpoint, cfg.AIAPIKey, cfg.AIModel, cfg.MaxPromptBytes),
		github:   NewGitHubClient(cfg.GitHubToken, cfg.GitHubAPIBaseURL),
		logs:     NewCloudLoggingClient(cfg.ProjectID, tokens),
		notifier: NewSlackNotifier(cfg.SlackWebhookURL, cfg.SlackChannel),
	}
}

func (r *Resolver) HandleIncident(ctx context.Context, incident IncidentEnvelope) error {
	if incident.Environment == "" {
		incident.Environment = r.cfg.Environment
	}
	if incident.Service == "" {
		incident.Service = ServiceFromReport(incident.Report)
	}
	if incident.Fingerprint == "" {
		incident.Fingerprint = FingerprintReport(incident.Service, incident.Report)
	}

	serviceKey, repoCfg, ok := ResolveServiceRepo(r.cfg.ServiceRepos, incident.Service)
	if !ok || repoCfg.Repo == "" {
		plan := HeuristicPlan(incident)
		plan.Action = "needs_human"
		plan.Summary = "No repository route is configured for this service."
		return r.notify(ctx, incident, repoCfg, plan, "", "needs human: repository route missing")
	}
	incident.Service = serviceKey
	if repoCfg.Mention == "" {
		repoCfg.Mention = r.cfg.SlackMention
	}

	logEntries := r.collectLogs(ctx, incident)
	source := r.collectSource(ctx, incident, repoCfg)
	plan := r.analyze(ctx, AnalysisInput{
		Incident: incident,
		Repo:     repoCfg,
		Logs:     logEntries,
		Source:   source,
	})

	deployed := deployedSource(repoCfg.Repo, incident.Report.Build.Commit, source.Ref)
	switch plan.Action {
	case "open_pr":
		if r.cfg.DryRun {
			return r.notify(ctx, incident, repoCfg, plan, "", "dry run: PR not opened")
		}
		if r.cfg.GitHubToken == "" {
			return r.notify(ctx, incident, repoCfg, plan, "", "needs human: GitHub token not configured")
		}
		if len(plan.FileEdits) == 0 {
			return r.notify(ctx, incident, repoCfg, plan, "", "needs human: AI requested PR without edits")
		}

		pr, err := r.github.OpenPullRequestWithEdits(ctx, repoCfg.Repo, repoCfg, incident, plan, r.cfg.MaxEdits)
		if err != nil {
			status := "needs human: PR creation failed"
			r.logger.Warn("failed to open resolver pr",
				slog.String("service", incident.Service),
				slog.String("fingerprint", incident.Fingerprint),
				slog.String("error", err.Error()))
			notifyErr := r.notify(ctx, incident, repoCfg, plan, "", status+": "+err.Error())
			if isTransientResolverError(err) {
				if notifyErr != nil {
					return fmt.Errorf("%w; slack: %v", err, notifyErr)
				}
				return err
			}
			return notifyErr
		}
		status := "PR opened"
		if pr.Reused {
			status = "existing PR reused"
		}
		n := resolutionNotification(incident, repoCfg, plan, pr.URL, status)
		n.DeployedSource = deployed
		return r.notifier.NotifyResolution(ctx, n)
	case "no_pr":
		if !r.cfg.NotifyNonPR {
			return nil
		}
		return r.notify(ctx, incident, repoCfg, plan, "", "investigated: no PR opened")
	default:
		return r.notify(ctx, incident, repoCfg, plan, "", "needs human review")
	}
}

func (r *Resolver) collectLogs(ctx context.Context, incident IncidentEnvelope) []ObservedLogEntry {
	if r.cfg.ProjectID == "" || r.cfg.MaxLogEntries <= 0 {
		return nil
	}
	logCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	entries, err := r.logs.RecentEntries(logCtx, incident, r.cfg.MaxLogEntries)
	if err != nil {
		r.logger.Info("log context unavailable",
			slog.String("service", incident.Service),
			slog.String("fingerprint", incident.Fingerprint),
			slog.String("error", err.Error()))
		return nil
	}
	return entries
}

func (r *Resolver) collectSource(ctx context.Context, incident IncidentEnvelope, repoCfg ServiceRepoConfig) SourceContext {
	if r.cfg.GitHubToken == "" {
		return SourceContext{}
	}
	ref := strings.TrimSpace(incident.Report.Build.Commit)
	if ref == "" || ref == "unknown" || ref == "dev" {
		ref = repoCfg.BaseBranch
	}
	sourceCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	source, err := r.github.LoadSourceContext(sourceCtx, repoCfg.Repo, ref, repoCfg, incident, r.cfg.MaxSourceFiles, r.cfg.MaxFileBytes)
	if err != nil {
		r.logger.Info("source context unavailable",
			slog.String("repo", repoCfg.Repo),
			slog.String("ref", ref),
			slog.String("error", err.Error()))
		return SourceContext{Repo: repoCfg.Repo, Ref: ref}
	}
	return source
}

func (r *Resolver) analyze(ctx context.Context, input AnalysisInput) ResolutionPlan {
	plan := HeuristicPlan(input.Incident)
	if r.cfg.AIAPIKey == "" || r.cfg.AIModel == "" {
		return plan
	}
	aiCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	aiPlan, err := r.ai.Analyze(aiCtx, input)
	if err != nil {
		r.logger.Warn("ai analysis failed; using heuristic plan",
			slog.String("service", input.Incident.Service),
			slog.String("fingerprint", input.Incident.Fingerprint),
			slog.String("error", err.Error()))
		return plan
	}
	return aiPlan
}

func (r *Resolver) notify(ctx context.Context, incident IncidentEnvelope, repoCfg ServiceRepoConfig, plan ResolutionPlan, prURL, status string) error {
	n := resolutionNotification(incident, repoCfg, plan, prURL, status)
	n.DeployedSource = deployedSource(repoCfg.Repo, incident.Report.Build.Commit, "")
	return r.notifier.NotifyResolution(ctx, n)
}

func resolutionNotification(incident IncidentEnvelope, repoCfg ServiceRepoConfig, plan ResolutionPlan, prURL, status string) ResolutionNotification {
	return ResolutionNotification{
		Mention:        repoCfg.Mention,
		Service:        incident.Service,
		Environment:    incident.Environment,
		Category:       plan.Category,
		Fingerprint:    ShortFingerprint(incident.Fingerprint),
		PRURL:          prURL,
		DeployedSource: deployedSource(repoCfg.Repo, incident.Report.Build.Commit, ""),
		Error:          incident.Report.Trigger.Message,
		Status:         status,
		Impact:         plan.Impact,
		Confidence:     plan.Confidence,
	}
}

func deployedSource(repo, reportedCommit, sourceRef string) string {
	ref := firstNonEmpty(reportedCommit, sourceRef, "unknown")
	return repo + "@" + ref
}

func isTransientResolverError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "temporarily") ||
		strings.Contains(msg, "rate limit") ||
		strings.Contains(msg, " returned 5")
}
