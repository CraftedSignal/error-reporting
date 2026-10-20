package errorreporting_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestRuntimeImagesContainOnlyTheirOwnBinary(t *testing.T) {
	data, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(data)

	for _, tc := range []struct {
		stage      string
		binary     string
		entrypoint string
		forbidden  string
	}{
		{stage: "runtime-function", binary: "/function", entrypoint: `ENTRYPOINT ["/function"]`, forbidden: "/resolver"},
		{stage: "runtime-resolver", binary: "/resolver", entrypoint: `ENTRYPOINT ["/resolver"]`, forbidden: "/function"},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			section := dockerStage(t, dockerfile, tc.stage)
			if !strings.Contains(section, tc.binary) {
				t.Fatalf("stage %q does not copy %s", tc.stage, tc.binary)
			}
			if !strings.Contains(section, tc.entrypoint) {
				t.Fatalf("stage %q does not declare %s", tc.stage, tc.entrypoint)
			}
			if strings.Contains(section, tc.forbidden) {
				t.Fatalf("stage %q unexpectedly contains %s", tc.stage, tc.forbidden)
			}
		})
	}
}

func dockerStage(t *testing.T, dockerfile, stage string) string {
	t.Helper()
	pattern := regexp.MustCompile(`(?m)^FROM [^\n]+ AS ` + regexp.QuoteMeta(stage) + `$`)
	start := pattern.FindStringIndex(dockerfile)
	if start == nil {
		t.Fatalf("Dockerfile is missing stage %q", stage)
	}
	rest := dockerfile[start[1]:]
	if next := regexp.MustCompile(`(?m)^FROM `).FindStringIndex(rest); next != nil {
		rest = rest[:next[0]]
	}
	return rest
}
