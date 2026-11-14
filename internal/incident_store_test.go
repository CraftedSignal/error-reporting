package internal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type staticToken struct{}

func (staticToken) Token(context.Context) (string, error) { return "t", nil }

type fakeGCS struct {
	mu           sync.Mutex
	obj          []byte
	gen          int
	createFails  int // number of 429s to return on creates (ifGenerationMatch=0)
	createAlways bool
	writeStatus  int // status for non-create writes, 0 = ok
	creates      int32
	updates      int32
}

func (f *fakeGCS) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == http.MethodPost {
			_, _ = io.Copy(io.Discard, r.Body)
			create := r.URL.Query().Get("ifGenerationMatch") == "0"
			if create {
				atomic.AddInt32(&f.creates, 1)
				if f.createAlways || f.createFails > 0 {
					if !f.createAlways {
						f.createFails--
					}
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{"error":{"code":429}}`))
					return
				}
				if f.obj != nil {
					w.WriteHeader(http.StatusPreconditionFailed)
					return
				}
			} else {
				atomic.AddInt32(&f.updates, 1)
				if f.writeStatus != 0 {
					w.WriteHeader(f.writeStatus)
					return
				}
			}
			body, _ := io.ReadAll(r.Body)
			_ = body
			f.gen++
			_, _ = w.Write([]byte(`{"generation":"1"}`))
			return
		}
		if f.obj == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("alt") == "media" {
			_, _ = w.Write(f.obj)
			return
		}
		_, _ = w.Write([]byte(`{"generation":"1"}`))
	})
}

func (f *fakeGCS) seed(t *testing.T, rec IncidentRecord) {
	t.Helper()
	b, _ := json.Marshal(rec)
	f.obj = b
}

func newTestStore(t *testing.T, f *fakeGCS) *GCSIncidentStore {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	s := NewGCSIncidentStore("b", "p", time.Hour, staticToken{})
	s.apiBaseURL = srv.URL
	s.uploadURL = srv.URL
	s.retryBackoff = time.Millisecond
	return s
}

func testEnvelope() IncidentEnvelope {
	return IncidentEnvelope{Service: "svc", Environment: "prod", Fingerprint: "fp1"}
}

func seededRecord(updated time.Time) IncidentRecord {
	r := NewIncidentRecord(testEnvelope(), updated)
	r.Count = 5
	return r
}

func TestClaimDuplicateSurvivesRateLimitedCounterWrite(t *testing.T) {
	for _, code := range []int{429, 412, 500} {
		f := &fakeGCS{writeStatus: code}
		f.seed(t, seededRecord(time.Now().Add(-time.Minute)))
		s := newTestStore(t, f)
		claim, err := s.Claim(context.Background(), testEnvelope())
		if err != nil {
			t.Fatalf("code %d: duplicate must not fail: %v", code, err)
		}
		if claim.New {
			t.Fatalf("code %d: expected duplicate", code)
		}
		if f.updates != 1 {
			t.Fatalf("code %d: expected single non-retried write, got %d", code, f.updates)
		}
	}
}

func TestClaimDuplicateWhenCreateRateLimited(t *testing.T) {
	f := &fakeGCS{createAlways: true}
	f.seed(t, seededRecord(time.Now()))
	s := newTestStore(t, f)
	claim, err := s.Claim(context.Background(), testEnvelope())
	if err != nil || claim.New {
		t.Fatalf("expected duplicate success, got %+v %v", claim, err)
	}
}

func TestClaimDuplicateCounterWrittenAtMostOncePerInterval(t *testing.T) {
	f := &fakeGCS{}
	f.seed(t, seededRecord(time.Now().Add(-time.Minute)))
	s := newTestStore(t, f)
	// First duplicate writes; simulate the store now holding a fresh UpdatedAt.
	if _, err := s.Claim(context.Background(), testEnvelope()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.seed(t, seededRecord(time.Now()))
	f.mu.Unlock()
	for i := 0; i < 50; i++ {
		claim, err := s.Claim(context.Background(), testEnvelope())
		if err != nil || claim.New {
			t.Fatalf("burst claim %d: %+v %v", i, claim, err)
		}
	}
	if got := atomic.LoadInt32(&f.updates); got != 1 {
		t.Fatalf("expected 1 counter write across burst, got %d", got)
	}
}

func TestClaimCreateRetriesOn429ThenSucceeds(t *testing.T) {
	f := &fakeGCS{createFails: 2}
	s := newTestStore(t, f)
	claim, err := s.Claim(context.Background(), testEnvelope())
	if err != nil || !claim.New {
		t.Fatalf("expected new claim, got %+v %v", claim, err)
	}
	if f.creates != 3 {
		t.Fatalf("expected 3 create attempts, got %d", f.creates)
	}
}

func TestClaimPersistentCreateFailureReturnsError(t *testing.T) {
	f := &fakeGCS{createAlways: true}
	s := newTestStore(t, f)
	_, err := s.Claim(context.Background(), testEnvelope())
	if err == nil || !isTransientStoreError(err) {
		t.Fatalf("expected retryable status error, got %v", err)
	}
	if f.creates != createMaxAttempts {
		t.Fatalf("expected %d attempts, got %d", createMaxAttempts, f.creates)
	}
}
