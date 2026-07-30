package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type IncidentRoute struct {
	Match []string `json:"match"`
}

type ServiceRepoConfig struct {
	Repo         string          `json:"repo"`
	BaseBranch   string          `json:"base_branch"`
	Mention      string          `json:"mention"`
	ContextPaths []string        `json:"context_paths"`
	TestCommands []string        `json:"test_commands"`
	Routes       []IncidentRoute `json:"routes,omitempty"`
	SourceHints  []string        `json:"source_hints,omitempty"`
}

type ResolverConfig struct {
	ProjectID        string
	Environment      string
	GitHubToken      string
	GitHubAPIBaseURL string
	AIAPIKey         string
	AIEndpoint       string
	AIModel          string
	SlackWebhookURL  string
	SlackChannel     string
	SlackMention     string
	ServiceRepos     map[string]ServiceRepoConfig
	MaxSourceFiles   int
	MaxFileBytes     int
	MaxPromptBytes   int
	MaxLogEntries    int
	MaxEdits         int
	DryRun           bool
	NotifyNonPR      bool
	IncidentBucket   string
	IncidentPrefix   string
	IncidentTTL      time.Duration
}

func LoadResolverConfigFromEnv() (ResolverConfig, error) {
	serviceRepos, err := ParseServiceRepoConfig(os.Getenv("SERVICE_REPOSITORIES_JSON"))
	if err != nil {
		return ResolverConfig{}, err
	}
	if len(serviceRepos) == 0 {
		serviceRepos = DefaultServiceRepos()
	}

	cfg := ResolverConfig{
		ProjectID:        os.Getenv("PROJECT_ID"),
		Environment:      os.Getenv("ENVIRONMENT"),
		GitHubToken:      os.Getenv("GITHUB_TOKEN"),
		GitHubAPIBaseURL: envOrDefault("GITHUB_API_BASE_URL", "https://api.github.com"),
		AIAPIKey:         firstNonEmpty(os.Getenv("AI_API_KEY"), os.Getenv("OPENAI_API_KEY")),
		AIEndpoint:       envOrDefault("AI_ENDPOINT", "https://api.openai.com/v1/chat/completions"),
		AIModel:          firstNonEmpty(os.Getenv("AI_MODEL"), os.Getenv("OPENAI_MODEL")),
		SlackWebhookURL:  os.Getenv("SLACK_WEBHOOK_URL"),
		SlackChannel:     os.Getenv("SLACK_CHANNEL"),
		SlackMention:     os.Getenv("SLACK_MENTION"),
		ServiceRepos:     serviceRepos,
		MaxSourceFiles:   envInt("MAX_SOURCE_FILES", 12),
		MaxFileBytes:     envInt("MAX_FILE_BYTES", 24*1024),
		MaxPromptBytes:   envInt("MAX_PROMPT_BYTES", 120*1024),
		MaxLogEntries:    envInt("MAX_LOG_ENTRIES", 60),
		MaxEdits:         envInt("MAX_EDITS", 8),
		DryRun:           envBool("DRY_RUN", false),
		NotifyNonPR:      envBool("NOTIFY_NON_PR", true),
		IncidentBucket:   os.Getenv("INCIDENT_STORE_BUCKET"),
		IncidentPrefix:   envOrDefault("INCIDENT_STORE_PREFIX", "resolver-incidents"),
		IncidentTTL:      envDuration("INCIDENT_SUPPRESSION_TTL", 7*24*time.Hour),
	}
	if cfg.Environment == "" {
		cfg.Environment = "prod"
	}
	return cfg, nil
}

func ParseServiceRepoConfig(raw string) (map[string]ServiceRepoConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var repos map[string]ServiceRepoConfig
	if err := json.Unmarshal([]byte(raw), &repos); err != nil {
		return nil, fmt.Errorf("parse SERVICE_REPOSITORIES_JSON: %w", err)
	}
	for key, cfg := range repos {
		if strings.TrimSpace(cfg.Repo) == "" {
			return nil, fmt.Errorf("service repo %q missing repo", key)
		}
		if cfg.BaseBranch == "" {
			cfg.BaseBranch = "main"
		}
		for i, route := range cfg.Routes {
			for _, pattern := range route.Match {
				if _, err := regexp.Compile("(?is)" + pattern); err != nil {
					return nil, fmt.Errorf("service repo %q route %d has invalid match pattern %q: %w", key, i, pattern, err)
				}
			}
		}
		repos[NormalizeServiceName(key)] = cfg
		if NormalizeServiceName(key) != key {
			delete(repos, key)
		}
	}
	return repos, nil
}

func DefaultServiceRepos() map[string]ServiceRepoConfig {
	return map[string]ServiceRepoConfig{}
}

func ResolveServiceRepo(repos map[string]ServiceRepoConfig, service string) (string, ServiceRepoConfig, bool) {
	service = NormalizeServiceName(service)
	if cfg, ok := repos[service]; ok {
		return service, normalizeRepoConfig(cfg), true
	}
	return "", ServiceRepoConfig{}, false
}

func ResolveIncidentRepo(repos map[string]ServiceRepoConfig, incident IncidentEnvelope) (string, ServiceRepoConfig, bool) {
	if service, cfg, ok := ResolveConfiguredRoute(repos, incident); ok {
		return service, cfg, true
	}
	return ResolveServiceRepo(repos, incident.Service)
}

func ResolveConfiguredRoute(repos map[string]ServiceRepoConfig, incident IncidentEnvelope) (string, ServiceRepoConfig, bool) {
	document := incidentRouteDocument(incident)
	keys := make([]string, 0, len(repos))
	for key := range repos {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		cfg := normalizeRepoConfig(repos[key])
		for _, route := range cfg.Routes {
			if incidentRouteMatches(route, document) {
				return key, cfg, true
			}
		}
	}
	return "", ServiceRepoConfig{}, false
}

func incidentRouteMatches(route IncidentRoute, document string) bool {
	if len(route.Match) == 0 {
		return false
	}
	for _, pattern := range route.Match {
		re, err := regexp.Compile("(?is)" + pattern)
		if err != nil || !re.MatchString(document) {
			return false
		}
	}
	return true
}

func incidentRouteDocument(incident IncidentEnvelope) string {
	var b strings.Builder
	appendRouteField(&b, "environment", incident.Environment)
	appendRouteField(&b, "service", incident.Service)
	appendRouteField(&b, "source", incident.Source)
	appendRouteField(&b, "trigger.level", incident.Report.Trigger.Level)
	appendRouteField(&b, "trigger.message", incident.Report.Trigger.Message)
	for key, value := range incident.Report.ConfigSummary {
		appendRouteField(&b, "config."+key, value)
	}
	for _, attr := range incident.Report.Trigger.Attrs {
		value := fmt.Sprintf("%v", attr.Value)
		appendRouteField(&b, attr.Key, value)
		appendRouteField(&b, "attr."+attr.Key, value)
	}
	return b.String()
}

func appendRouteField(b *strings.Builder, key, value string) {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return
	}
	b.WriteString(key)
	b.WriteByte('=')
	b.WriteString(value)
	b.WriteByte('\n')
}

func normalizeRepoConfig(cfg ServiceRepoConfig) ServiceRepoConfig {
	if cfg.BaseBranch == "" {
		cfg.BaseBranch = "main"
	}
	return cfg
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
