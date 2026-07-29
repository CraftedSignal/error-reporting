package internal

import "testing"

func TestApplyFileEditExactMatch(t *testing.T) {
	got, err := ApplyFileEdit("a\nb\nc\n", true, FileEdit{Path: "main.go", Find: "b\n", Replace: "bb\n"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "a\nbb\nc\n" {
		t.Fatalf("updated content = %q", got)
	}
}

func TestApplyFileEditRejectsAmbiguousMatch(t *testing.T) {
	_, err := ApplyFileEdit("a\na\n", true, FileEdit{Path: "main.go", Find: "a\n", Replace: "b\n"})
	if err == nil {
		t.Fatal("expected ambiguous match error")
	}
}

func TestValidateEditPath(t *testing.T) {
	for _, path := range []string{"/tmp/x.go", "../x.go", ".git/config", "config/secret.yaml", "image.png"} {
		t.Run(path, func(t *testing.T) {
			if err := validateEditPath(path); err == nil {
				t.Fatal("expected unsafe path error")
			}
		})
	}
	if err := validateEditPath("internal/foo.go"); err != nil {
		t.Fatalf("valid path rejected: %v", err)
	}
}

func TestSelectSourceFiles(t *testing.T) {
	tree := []gitTreeEntry{
		{Path: "go.mod", Type: "blob", Size: 100},
		{Path: "internal/publisher/publisher.go", Type: "blob", Size: 100},
		{Path: "README.md", Type: "blob", Size: 100},
	}
	cfg := ServiceRepoConfig{ContextPaths: []string{"internal/publisher/**"}}
	incident := IncidentEnvelope{Report: ReportPayload{Trigger: LogRecord{Message: "internal/publisher/publisher.go:12 failed"}}}

	got := selectSourceFiles(tree, cfg, incident, 2, 1024)
	if len(got) != 2 {
		t.Fatalf("selected %d files, want 2", len(got))
	}
	if got[0].Path != "internal/publisher/publisher.go" {
		t.Fatalf("first selected path = %q", got[0].Path)
	}
}

func TestSelectSourceFilesUsesConfiguredSourceHints(t *testing.T) {
	tree := []gitTreeEntry{
		{Path: "deploy/service.yaml", Type: "blob", Size: 100},
		{Path: "internal/app.go", Type: "blob", Size: 100},
	}
	cfg := ServiceRepoConfig{
		ContextPaths: []string{"internal/**"},
		SourceHints:  []string{"deploy/service.yaml"},
	}

	got := selectSourceFiles(tree, cfg, IncidentEnvelope{}, 1, 1024)
	if len(got) != 1 {
		t.Fatalf("selected %d files, want 1", len(got))
	}
	if got[0].Path != "deploy/service.yaml" {
		t.Fatalf("selected path = %q, want deploy/service.yaml", got[0].Path)
	}
}
