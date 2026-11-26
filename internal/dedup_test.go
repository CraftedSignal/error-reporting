package internal

import (
	"testing"
	"time"
)

func TestDeduperKeepsInstallationsApart(t *testing.T) {
	report := func(saas bool, licenseID string) ReportPayload {
		return ReportPayload{
			Trigger: LogRecord{Level: "error", Message: "list threat summaries", Attrs: []Attr{{Key: "company_id", Value: "1"}}},
			Runtime: RuntimeInfo{IsSaaS: saas, LicenseID: licenseID},
		}
	}
	d := NewDeduper(time.Minute)
	if d.Seen(report(false, "lic-onprem")) {
		t.Fatal("first on-prem report was treated as a duplicate")
	}
	if d.Seen(report(true, "lic-saas")) {
		t.Fatal("SaaS report was suppressed by an on-prem report for the same company ID")
	}
	if d.Seen(report(false, "lic-other")) {
		t.Fatal("another installation's report was suppressed")
	}
	if !d.Seen(report(false, "lic-onprem")) {
		t.Fatal("repeat from the same installation was not deduplicated")
	}
}
