package internal

import (
	"fmt"
	"sync"
	"time"
)

// Deduper suppresses duplicate notifications within a TTL.
type Deduper struct {
	mu     sync.Mutex
	ttl    time.Duration
	seen   map[string]time.Time
}

// NewDeduper creates a deduplication cache with the given TTL.
func NewDeduper(ttl time.Duration) *Deduper {
	return &Deduper{ttl: ttl, seen: make(map[string]time.Time)}
}

// Seen returns true if a similar report was already notified recently.
func (d *Deduper) Seen(r ReportPayload) bool {
	companyID := ""
	for _, a := range r.Trigger.Attrs {
		if a.Key == "company_id" {
			companyID = fmt.Sprintf("%v", a.Value)
			break
		}
	}
	key := fmt.Sprintf("%s:%s:%s", r.Trigger.Message, r.Trigger.Level, companyID)
	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	// Clean expired entries opportunistically.
	for k, t := range d.seen {
		if now.Sub(t) > d.ttl {
			delete(d.seen, k)
		}
	}

	if last, ok := d.seen[key]; ok && now.Sub(last) <= d.ttl {
		return true
	}
	d.seen[key] = now
	return false
}
