package internal

import (
	"regexp"
	"strings"
)

var secretLineRE = regexp.MustCompile(`(?i)(authorization|bearer|api[_-]?key|token|secret|password|passwd|private[_-]?key|client[_-]?secret)(\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)`)

// RedactString removes common credential shapes before data is sent to Slack,
// GitHub PRs, or an AI model.
func RedactString(value string) string {
	if value == "" {
		return ""
	}
	value = secretLineRE.ReplaceAllString(value, "$1$2[REDACTED]")
	if len(value) > 16*1024 {
		return value[:16*1024] + "\n[truncated]"
	}
	return value
}

func redactMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for k, v := range values {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "token") ||
			strings.Contains(lower, "secret") ||
			strings.Contains(lower, "password") ||
			strings.Contains(lower, "key") ||
			strings.Contains(lower, "authorization") {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = RedactString(v)
	}
	return out
}
