package internal

import (
	"regexp"
)

var secretLineRE = regexp.MustCompile(`(?i)(authorization|bearer|api[_-]?key|token|secret|password|passwd|private[_-]?key|client[_-]?secret)(\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)`)

// RedactString removes common credential shapes before data is sent to Slack.
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
