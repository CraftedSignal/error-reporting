package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type ServiceRepoConfig struct {
	Repo         string   `json:"repo"`
	BaseBranch   string   `json:"base_branch"`
	Mention      string   `json:"mention"`
	ContextPaths []string `json:"context_paths"`
	TestCommands []string `json:"test_commands"`
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
		repos[NormalizeServiceName(key)] = cfg
		if NormalizeServiceName(key) != key {
			delete(repos, key)
		}
	}
	return repos, nil
}

func DefaultServiceRepos() map[string]ServiceRepoConfig {
	return map[string]ServiceRepoConfig{
		"platform": {
			Repo:       "CraftedSignal/platform",
			BaseBranch: "main",
			ContextPaths: []string{
				"go.mod",
				"cmd/**",
				"pkg/errorreporting/**",
				"pkg/logger/**",
				"pkg/service/ai/**",
				"pkg/workflows/**",
				"config/**",
				".github/**",
			},
			TestCommands: []string{"go test ./..."},
		},
		"ti-bot": {
			Repo:       "CraftedSignal/ti-bot",
			BaseBranch: "main",
			ContextPaths: []string{
				"go.mod",
				"cmd/ti-bot/**",
				"internal/pipeline/**",
				"internal/publisher/**",
				"internal/sources/**",
				"config.example.yaml",
				"Dockerfile",
				".github/**",
			},
			TestCommands: []string{"go test ./..."},
		},
		"error-reporting": {
			Repo:       "CraftedSignal/error-reporting",
			BaseBranch: "main",
			ContextPaths: []string{
				"go.mod",
				"cmd/**",
				"internal/**",
				"Dockerfile",
				".github/**",
			},
			TestCommands: []string{"go test ./..."},
		},
		"infrastructure": {
			Repo:       "CraftedSignal/infrastructure",
			BaseBranch: "main",
			ContextPaths: []string{
				"terraform/**",
				"k8s/**",
				".github/**",
			},
			TestCommands: []string{"terraform fmt -check -recursive", "terraform validate"},
		},
	}
}

func ResolveServiceRepo(repos map[string]ServiceRepoConfig, service string) (string, ServiceRepoConfig, bool) {
	service = NormalizeServiceName(service)
	if cfg, ok := repos[service]; ok {
		return service, normalizeRepoConfig(cfg), true
	}
	switch {
	case strings.Contains(service, "ti-bot"):
		cfg, ok := repos["ti-bot"]
		return "ti-bot", normalizeRepoConfig(cfg), ok
	case strings.Contains(service, "temporal"), strings.Contains(service, "worker"), strings.Contains(service, "server"), strings.Contains(service, "craftedsignal"):
		cfg, ok := repos["platform"]
		return "platform", normalizeRepoConfig(cfg), ok
	default:
		cfg, ok := repos["platform"]
		return "platform", normalizeRepoConfig(cfg), ok
	}
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
