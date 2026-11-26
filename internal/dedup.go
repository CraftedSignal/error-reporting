package internal

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"strconv"
	"sync"
	"time"
)

const defaultMaxEntries = 100_000

type dedupEntry struct {
	key     [sha256.Size]byte
	expires time.Time
}

// Deduper is a concurrency-safe, bounded sliding-TTL cache.
type Deduper struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	seen       map[[sha256.Size]byte]*list.Element
	order      list.List // most recently observed first
}

// NewDeduper creates a cache. Non-positive TTL disables deduplication.
func NewDeduper(ttl time.Duration) *Deduper {
	return &Deduper{ttl: ttl, maxEntries: defaultMaxEntries, seen: make(map[[sha256.Size]byte]*list.Element)}
}

// Seen registers an observation and refreshes its sliding TTL.
// Callers must account for notification delivery failures separately.
func (d *Deduper) Seen(r ReportPayload) bool {
	if d.ttl <= 0 {
		return false
	}
	key := fingerprint(r)
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	d.expire(now)
	if e, ok := d.seen[key]; ok {
		entryOf(e).expires = now.Add(d.ttl)
		d.order.MoveToFront(e)
		return true
	}
	if len(d.seen) >= d.maxEntries {
		d.remove(d.order.Back())
	}
	d.seen[key] = d.order.PushFront(&dedupEntry{key: key, expires: now.Add(d.ttl)})
	return false
}

func (d *Deduper) remove(e *list.Element) {
	if e == nil {
		return
	}
	delete(d.seen, entryOf(e).key)
	d.order.Remove(e)
}

// Expiry order follows recency because every entry has the same TTL.
func (d *Deduper) expire(now time.Time) {
	for e := d.order.Back(); e != nil && !now.Before(entryOf(e).expires); e = d.order.Back() {
		d.remove(e)
	}
}

// entryOf returns the entry an element holds; the list only holds *dedupEntry.
func entryOf(e *list.Element) *dedupEntry {
	entry, _ := e.Value.(*dedupEntry)
	return entry
}

func (d *Deduper) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expire(time.Now())
	return len(d.seen)
}
func (d *Deduper) Reset() { d.mu.Lock(); defer d.mu.Unlock(); clear(d.seen); d.order.Init() }

func fingerprint(r ReportPayload) [sha256.Size]byte {
	h := sha256.New()
	writeField(h, "notification:v1")
	writeField(h, r.Trigger.Message)
	writeField(h, r.Trigger.Level)
	// Company IDs repeat across installations (every one starts at 1), so an
	// on-prem alert must not suppress the same message from SaaS or elsewhere.
	writeField(h, strconv.FormatBool(r.Runtime.IsSaaS))
	writeField(h, r.Runtime.LicenseID)
	if company, ok := r.Trigger.GetAttr("company_id"); ok {
		writeField(h, "present")
		writeField(h, fmt.Sprintf("%T", company))
		writeField(h, fmt.Sprint(company))
	} else {
		writeField(h, "absent")
	}
	var key [sha256.Size]byte
	h.Sum(key[:0])
	return key
}

func writeField(h hash.Hash, s string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(s)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(s))
}
