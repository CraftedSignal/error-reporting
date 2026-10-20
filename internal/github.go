package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrGitHubNotFound = errors.New("github resource not found")

type GitHubClient struct {
	token      string
	apiBaseURL string
	client     *http.Client
}

type RepoID struct {
	Owner string
	Name  string
}

type SourceContext struct {
	Repo      string       `json:"repo"`
	Ref       string       `json:"ref"`
	TreeSHA   string       `json:"tree_sha"`
	Truncated bool         `json:"truncated"`
	Files     []SourceFile `json:"files"`
}

type SourceFile struct {
	Path    string `json:"path"`
	Ref     string `json:"ref"`
	Content string `json:"content"`
}

type PullRequestResult struct {
	URL    string
	Branch string
	Reused bool
}

type gitTreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int    `json:"size"`
}

type gitCommitResponse struct {
	SHA    string `json:"sha"`
	Commit struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	} `json:"commit"`
}

type gitRefResponse struct {
	Ref    string `json:"ref"`
	Object struct {
		SHA  string `json:"sha"`
		Type string `json:"type"`
	} `json:"object"`
}

type gitDataCommitResponse struct {
	SHA  string `json:"sha"`
	Tree struct {
		SHA string `json:"sha"`
	} `json:"tree"`
}

type gitTreeResponse struct {
	SHA       string         `json:"sha"`
	Truncated bool           `json:"truncated"`
	Tree      []gitTreeEntry `json:"tree"`
}

func NewGitHubClient(token, apiBaseURL string) *GitHubClient {
	if apiBaseURL == "" {
		apiBaseURL = "https://api.github.com"
	}
	return &GitHubClient{
		token:      token,
		apiBaseURL: strings.TrimRight(apiBaseURL, "/"),
		client:     &http.Client{Timeout: 30 * time.Second},
	}
}

func ParseGitHubRepo(raw string) (RepoID, error) {
	raw = strings.TrimSpace(strings.TrimSuffix(raw, ".git"))
	raw = strings.TrimPrefix(raw, "git@github.com:")
	raw = strings.TrimPrefix(raw, "https://github.com/")
	raw = strings.TrimPrefix(raw, "http://github.com/")
	parts := strings.Split(raw, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return RepoID{}, fmt.Errorf("invalid github repo %q; expected owner/name", raw)
	}
	return RepoID{Owner: parts[0], Name: parts[1]}, nil
}

func (c *GitHubClient) LoadSourceContext(ctx context.Context, repo string, ref string, cfg ServiceRepoConfig, incident IncidentEnvelope, maxFiles, maxFileBytes int) (SourceContext, error) {
	if c == nil || c.token == "" {
		return SourceContext{}, fmt.Errorf("github token not configured")
	}
	if ref == "" || ref == "unknown" || ref == "dev" {
		ref = cfg.BaseBranch
	}
	if maxFiles <= 0 {
		maxFiles = 12
	}
	if maxFileBytes <= 0 {
		maxFileBytes = 24 * 1024
	}

	commit, err := c.ResolveCommit(ctx, repo, ref)
	if err != nil {
		return SourceContext{}, err
	}
	tree, err := c.GetTree(ctx, repo, commit.Commit.Tree.SHA)
	if err != nil {
		return SourceContext{}, err
	}

	selected := selectSourceFiles(tree.Tree, cfg, incident, maxFiles, maxFileBytes)
	files := make([]SourceFile, 0, len(selected))
	for _, entry := range selected {
		content, err := c.GetBlobText(ctx, repo, entry.SHA, maxFileBytes)
		if err != nil {
			continue
		}
		files = append(files, SourceFile{Path: entry.Path, Ref: commit.SHA, Content: content})
	}

	return SourceContext{
		Repo:      repo,
		Ref:       commit.SHA,
		TreeSHA:   commit.Commit.Tree.SHA,
		Truncated: tree.Truncated,
		Files:     files,
	}, nil
}

func (c *GitHubClient) ResolveCommit(ctx context.Context, repo, ref string) (gitCommitResponse, error) {
	id, err := ParseGitHubRepo(repo)
	if err != nil {
		return gitCommitResponse{}, err
	}
	var out gitCommitResponse
	err = c.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/commits/%s", pathEscape(id.Owner), pathEscape(id.Name), pathEscape(ref)), nil, &out)
	return out, err
}

func (c *GitHubClient) GetTree(ctx context.Context, repo, treeSHA string) (gitTreeResponse, error) {
	id, err := ParseGitHubRepo(repo)
	if err != nil {
		return gitTreeResponse{}, err
	}
	var out gitTreeResponse
	err = c.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/git/trees/%s?recursive=1", pathEscape(id.Owner), pathEscape(id.Name), pathEscape(treeSHA)), nil, &out)
	return out, err
}

func (c *GitHubClient) GetBlobText(ctx context.Context, repo, blobSHA string, maxBytes int) (string, error) {
	id, err := ParseGitHubRepo(repo)
	if err != nil {
		return "", err
	}
	var out struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		Size     int    `json:"size"`
	}
	if err := c.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/git/blobs/%s", pathEscape(id.Owner), pathEscape(id.Name), pathEscape(blobSHA)), nil, &out); err != nil {
		return "", err
	}
	if out.Encoding != "base64" {
		return "", fmt.Errorf("unsupported github blob encoding %q", out.Encoding)
	}
	if maxBytes > 0 && out.Size > maxBytes {
		return "", fmt.Errorf("github blob too large: %d bytes", out.Size)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(out.Content, "\n", ""))
	if err != nil {
		return "", fmt.Errorf("decode github blob: %w", err)
	}
	if maxBytes > 0 && len(decoded) > maxBytes {
		return "", fmt.Errorf("github blob too large: %d bytes", len(decoded))
	}
	if !utf8.Valid(decoded) {
		return "", fmt.Errorf("github blob is not utf-8 text")
	}
	return string(decoded), nil
}

func (c *GitHubClient) OpenPullRequestWithEdits(ctx context.Context, repo string, cfg ServiceRepoConfig, incident IncidentEnvelope, plan ResolutionPlan, maxEdits int) (PullRequestResult, error) {
	if c == nil || c.token == "" {
		return PullRequestResult{}, fmt.Errorf("github token not configured")
	}
	id, err := ParseGitHubRepo(repo)
	if err != nil {
		return PullRequestResult{}, err
	}
	if maxEdits <= 0 {
		maxEdits = 8
	}
	if len(plan.FileEdits) == 0 {
		return PullRequestResult{}, fmt.Errorf("resolution plan contains no file edits")
	}
	if len(plan.FileEdits) > maxEdits {
		return PullRequestResult{}, fmt.Errorf("resolution plan has %d edits; max is %d", len(plan.FileEdits), maxEdits)
	}

	baseBranch := firstNonEmpty(cfg.BaseBranch, "main")
	branch := agentBranchName(incident)
	if existing, err := c.findOpenPullRequest(ctx, id, branch); err == nil && existing != "" {
		return PullRequestResult{URL: existing, Branch: branch, Reused: true}, nil
	}

	baseRef, err := c.getRef(ctx, id, "heads/"+baseBranch)
	if err != nil {
		return PullRequestResult{}, err
	}
	baseCommit, err := c.getGitCommit(ctx, id, baseRef.Object.SHA)
	if err != nil {
		return PullRequestResult{}, err
	}
	baseTree, err := c.GetTree(ctx, repo, baseCommit.Tree.SHA)
	if err != nil {
		return PullRequestResult{}, err
	}
	treeByPath := make(map[string]gitTreeEntry, len(baseTree.Tree))
	for _, entry := range baseTree.Tree {
		if entry.Type == "blob" {
			treeByPath[entry.Path] = entry
		}
	}

	treeUpdates := make([]map[string]string, 0, len(plan.FileEdits))
	changedPaths := make(map[string]struct{}, len(plan.FileEdits))
	for _, edit := range plan.FileEdits {
		edit.Path = strings.TrimSpace(edit.Path)
		if err := validateEditPath(edit.Path); err != nil {
			return PullRequestResult{}, err
		}
		if _, seen := changedPaths[edit.Path]; seen {
			return PullRequestResult{}, fmt.Errorf("duplicate edit for %s", edit.Path)
		}
		changedPaths[edit.Path] = struct{}{}

		var current string
		entry, exists := treeByPath[edit.Path]
		if exists {
			current, err = c.GetBlobText(ctx, repo, entry.SHA, 512*1024)
			if err != nil {
				return PullRequestResult{}, err
			}
		}

		updated, err := ApplyFileEdit(current, exists, edit)
		if err != nil {
			return PullRequestResult{}, fmt.Errorf("%s: %w", edit.Path, err)
		}
		blobSHA, err := c.createBlob(ctx, id, updated)
		if err != nil {
			return PullRequestResult{}, err
		}
		treeUpdates = append(treeUpdates, map[string]string{
			"path": edit.Path,
			"mode": "100644",
			"type": "blob",
			"sha":  blobSHA,
		})
	}
	if len(treeUpdates) == 0 {
		return PullRequestResult{}, fmt.Errorf("no file edits remained after validation")
	}

	newTreeSHA, err := c.createTree(ctx, id, baseCommit.Tree.SHA, treeUpdates)
	if err != nil {
		return PullRequestResult{}, err
	}
	message := fmt.Sprintf("fix(%s): resolve incident %s", NormalizeServiceName(incident.Service), ShortFingerprint(incident.Fingerprint))
	newCommitSHA, err := c.createCommit(ctx, id, message, newTreeSHA, []string{baseRef.Object.SHA})
	if err != nil {
		return PullRequestResult{}, err
	}
	if err := c.createRef(ctx, id, "refs/heads/"+branch, newCommitSHA); err != nil {
		if existing, findErr := c.findOpenPullRequest(ctx, id, branch); findErr == nil && existing != "" {
			return PullRequestResult{URL: existing, Branch: branch, Reused: true}, nil
		}
		return PullRequestResult{}, err
	}

	prURL, err := c.createPullRequest(ctx, id, baseBranch, branch, prTitle(incident, plan), BuildPRBody(incident, plan, cfg))
	if err != nil {
		return PullRequestResult{}, err
	}
	return PullRequestResult{URL: prURL, Branch: branch}, nil
}

func ApplyFileEdit(current string, exists bool, edit FileEdit) (string, error) {
	if strings.TrimSpace(edit.Path) == "" {
		return "", fmt.Errorf("missing path")
	}
	if edit.Find == "" {
		if exists {
			return "", fmt.Errorf("empty find is only allowed for new files")
		}
		if edit.Replace == "" {
			return "", fmt.Errorf("new file content is empty")
		}
		return edit.Replace, nil
	}
	count := strings.Count(current, edit.Find)
	if count != 1 {
		return "", fmt.Errorf("find string matched %d times; expected exactly one", count)
	}
	updated := strings.Replace(current, edit.Find, edit.Replace, 1)
	if updated == current {
		return "", fmt.Errorf("edit is a no-op")
	}
	return updated, nil
}

func BuildPRBody(incident IncidentEnvelope, plan ResolutionPlan, cfg ServiceRepoConfig) string {
	var b strings.Builder
	b.WriteString("## Agent Investigation\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("| --- | --- |\n")
	b.WriteString("| Service | `")
	b.WriteString(incident.Service)
	b.WriteString("` |\n")
	b.WriteString("| Environment | `")
	b.WriteString(incident.Environment)
	b.WriteString("` |\n")
	b.WriteString("| Fingerprint | `")
	b.WriteString(incident.Fingerprint)
	b.WriteString("` |\n")
	b.WriteString("| Deployed source | `")
	b.WriteString(cfg.Repo)
	b.WriteString("@")
	b.WriteString(firstNonEmpty(incident.Report.Build.Commit, "unknown"))
	b.WriteString("` |\n")
	b.WriteString("| Category | `")
	b.WriteString(plan.Category)
	b.WriteString("` |\n")
	b.WriteString("| Confidence | `")
	b.WriteString(plan.Confidence)
	b.WriteString("` |\n\n")

	b.WriteString("## Summary\n\n")
	b.WriteString(firstNonEmpty(plan.Summary, "No summary provided."))
	b.WriteString("\n\n## Root Cause\n\n")
	b.WriteString(firstNonEmpty(plan.RootCause, "No root-cause hypothesis provided."))
	b.WriteString("\n\n## Impact\n\n")
	b.WriteString(firstNonEmpty(plan.Impact, "Impact unknown."))
	b.WriteString("\n\n## Trigger\n\n")
	b.WriteString("```text\n")
	b.WriteString(RedactString(incident.Report.Trigger.Message))
	b.WriteString("\n```\n")

	b.WriteString("\n## Verification\n\n")
	if len(plan.TestCommands) == 0 {
		plan.TestCommands = cfg.TestCommands
	}
	if len(plan.TestCommands) == 0 {
		b.WriteString("- CI should run on this PR.\n")
	} else {
		for _, cmd := range plan.TestCommands {
			b.WriteString("- `")
			b.WriteString(cmd)
			b.WriteString("`\n")
		}
	}
	b.WriteString("\n## Safety\n\n")
	b.WriteString("- Agent opened a PR only; no production mutation was performed.\n")
	b.WriteString("- Secrets and common credential fields were redacted before analysis.\n")
	return b.String()
}

func selectSourceFiles(tree []gitTreeEntry, cfg ServiceRepoConfig, incident IncidentEnvelope, maxFiles, maxFileBytes int) []gitTreeEntry {
	hints := sourceHints(incident, cfg)
	type scored struct {
		entry gitTreeEntry
		score int
	}
	scoredEntries := make([]scored, 0, len(tree))
	for _, entry := range tree {
		if entry.Type != "blob" || entry.Size > maxFileBytes || !isTextSourcePath(entry.Path) {
			continue
		}
		score := 0
		for _, pattern := range cfg.ContextPaths {
			if pathMatchesPattern(entry.Path, pattern) {
				score += 100
			}
		}
		for _, hint := range hints {
			if entry.Path == hint {
				score += 250
			}
			if strings.HasSuffix(entry.Path, "/"+hint) || path.Base(entry.Path) == hint {
				score += 125
			}
			if strings.Contains(entry.Path, hint) {
				score += 40
			}
		}
		if isCommonContextPath(entry.Path) {
			score += 80
		}
		if score > 0 {
			scoredEntries = append(scoredEntries, scored{entry: entry, score: score})
		}
	}
	sort.Slice(scoredEntries, func(i, j int) bool {
		if scoredEntries[i].score == scoredEntries[j].score {
			return scoredEntries[i].entry.Path < scoredEntries[j].entry.Path
		}
		return scoredEntries[i].score > scoredEntries[j].score
	})
	if len(scoredEntries) > maxFiles {
		scoredEntries = scoredEntries[:maxFiles]
	}
	out := make([]gitTreeEntry, 0, len(scoredEntries))
	for _, entry := range scoredEntries {
		out = append(out, entry.entry)
	}
	return out
}

func sourceHints(incident IncidentEnvelope, cfg ServiceRepoConfig) []string {
	values := []string{incident.Report.Trigger.Message}
	for _, attr := range incident.Report.Trigger.Attrs {
		values = append(values, fmt.Sprintf("%v", attr.Value))
	}
	for _, rec := range incident.Report.Before {
		values = append(values, rec.Message)
	}
	for _, rec := range incident.Report.After {
		values = append(values, rec.Message)
	}

	pathRE := regexp.MustCompile(`[A-Za-z0-9_./-]+\.(go|yaml|yml|json|tf|toml|sql|sh|md|js|ts|tsx|jsx)`)
	seen := make(map[string]struct{})
	var hints []string
	addHint := func(value string) {
		value = strings.TrimLeft(strings.TrimSpace(value), "./")
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		hints = append(hints, value)
	}
	for _, hint := range cfg.SourceHints {
		addHint(hint)
	}
	for _, value := range values {
		for _, match := range pathRE.FindAllString(value, -1) {
			match = strings.TrimLeft(match, "./")
			if idx := strings.Index(match, ":"); idx >= 0 {
				match = match[:idx]
			}
			addHint(match)
			base := path.Base(match)
			if base != match {
				addHint(base)
			}
		}
	}
	return hints
}

func pathMatchesPattern(value, pattern string) bool {
	pattern = strings.TrimLeft(strings.TrimSpace(pattern), "/")
	if pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return value == prefix || strings.HasPrefix(value, prefix+"/")
	}
	if strings.Contains(pattern, "*") {
		ok, err := path.Match(pattern, value)
		return err == nil && ok
	}
	return value == pattern
}

func isCommonContextPath(value string) bool {
	switch value {
	case "go.mod", "go.sum", "Dockerfile", "Dockerfile.deploy", "Makefile", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock":
		return true
	default:
		return strings.HasPrefix(value, ".github/workflows/")
	}
}

func isTextSourcePath(value string) bool {
	ext := strings.ToLower(path.Ext(value))
	switch ext {
	case ".go", ".mod", ".sum", ".yaml", ".yml", ".json", ".tf", ".toml", ".sql", ".sh", ".md", ".js", ".ts", ".tsx", ".jsx", ".html", ".css":
		return true
	default:
		return path.Base(value) == "Dockerfile" || path.Base(value) == "Makefile"
	}
}

func validateEditPath(value string) error {
	if value == "" {
		return fmt.Errorf("empty edit path")
	}
	if strings.HasPrefix(value, "/") || strings.Contains(value, "..") || strings.HasPrefix(value, ".git/") {
		return fmt.Errorf("unsafe edit path %q", value)
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "secret") || strings.Contains(lower, "credential") || strings.Contains(lower, "private-key") || strings.Contains(lower, ".env") {
		return fmt.Errorf("refusing to edit sensitive path %q", value)
	}
	if !isTextSourcePath(value) {
		return fmt.Errorf("refusing to edit non-source path %q", value)
	}
	return nil
}

func agentBranchName(incident IncidentEnvelope) string {
	service := NormalizeServiceName(incident.Service)
	short := ShortFingerprint(incident.Fingerprint)
	value := "agent/" + service + "/" + short
	value = strings.ToLower(value)
	allowed := regexp.MustCompile(`[^a-z0-9._/-]+`)
	value = allowed.ReplaceAllString(value, "-")
	value = strings.Trim(value, "/.-")
	if value == "" {
		return "agent/incident/" + short
	}
	return value
}

func prTitle(incident IncidentEnvelope, plan ResolutionPlan) string {
	title := strings.TrimSpace(plan.Title)
	if title == "" {
		title = defaultResolutionTitle(incident)
	}
	short := ShortFingerprint(incident.Fingerprint)
	if !strings.Contains(title, short) {
		title = fmt.Sprintf("%s [%s]", title, short)
	}
	if len(title) > 120 {
		title = title[:120]
	}
	return title
}

func (c *GitHubClient) getRef(ctx context.Context, repo RepoID, ref string) (gitRefResponse, error) {
	var out gitRefResponse
	err := c.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/git/ref/%s", pathEscape(repo.Owner), pathEscape(repo.Name), escapePathSegments(ref)), nil, &out)
	return out, err
}

func (c *GitHubClient) getGitCommit(ctx context.Context, repo RepoID, sha string) (gitDataCommitResponse, error) {
	var out gitDataCommitResponse
	err := c.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/git/commits/%s", pathEscape(repo.Owner), pathEscape(repo.Name), pathEscape(sha)), nil, &out)
	return out, err
}

func (c *GitHubClient) createBlob(ctx context.Context, repo RepoID, content string) (string, error) {
	var out struct {
		SHA string `json:"sha"`
	}
	body := map[string]string{"content": content, "encoding": "utf-8"}
	err := c.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/git/blobs", pathEscape(repo.Owner), pathEscape(repo.Name)), body, &out)
	return out.SHA, err
}

func (c *GitHubClient) createTree(ctx context.Context, repo RepoID, baseTree string, updates []map[string]string) (string, error) {
	var out struct {
		SHA string `json:"sha"`
	}
	body := map[string]interface{}{
		"base_tree": baseTree,
		"tree":      updates,
	}
	err := c.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/git/trees", pathEscape(repo.Owner), pathEscape(repo.Name)), body, &out)
	return out.SHA, err
}

func (c *GitHubClient) createCommit(ctx context.Context, repo RepoID, message, treeSHA string, parents []string) (string, error) {
	var out struct {
		SHA string `json:"sha"`
	}
	body := map[string]interface{}{
		"message": message,
		"tree":    treeSHA,
		"parents": parents,
	}
	err := c.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/git/commits", pathEscape(repo.Owner), pathEscape(repo.Name)), body, &out)
	return out.SHA, err
}

func (c *GitHubClient) createRef(ctx context.Context, repo RepoID, ref, sha string) error {
	body := map[string]string{"ref": ref, "sha": sha}
	return c.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/git/refs", pathEscape(repo.Owner), pathEscape(repo.Name)), body, nil)
}

func (c *GitHubClient) createPullRequest(ctx context.Context, repo RepoID, base, head, title, body string) (string, error) {
	var out struct {
		HTMLURL string `json:"html_url"`
	}
	reqBody := map[string]interface{}{
		"title": title,
		"head":  head,
		"base":  base,
		"body":  body,
	}
	err := c.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/pulls", pathEscape(repo.Owner), pathEscape(repo.Name)), reqBody, &out)
	return out.HTMLURL, err
}

func (c *GitHubClient) findOpenPullRequest(ctx context.Context, repo RepoID, branch string) (string, error) {
	var out []struct {
		HTMLURL string `json:"html_url"`
	}
	query := url.Values{}
	query.Set("state", "open")
	query.Set("head", repo.Owner+":"+branch)
	err := c.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/pulls?%s", pathEscape(repo.Owner), pathEscape(repo.Name), query.Encode()), nil, &out)
	if err != nil {
		return "", err
	}
	if len(out) == 0 {
		return "", nil
	}
	return out[0].HTMLURL, nil
}

func (c *GitHubClient) request(ctx context.Context, method, apiPath string, body interface{}, out interface{}) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiBaseURL+apiPath, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("github %s %s: %w", method, apiPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrGitHubNotFound
	}
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("github %s %s returned %d: %s", method, apiPath, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if out == nil {
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return fmt.Errorf("drain github %s %s response: %w", method, apiPath, err)
		}
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode github response: %w", err)
	}
	return nil
}

func pathEscape(value string) string {
	return url.PathEscape(value)
}

func escapePathSegments(value string) string {
	parts := strings.Split(value, "/")
	for i := range parts {
		parts[i] = pathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
