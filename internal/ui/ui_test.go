package ui

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tasoint/certinv/internal/evaluate"
	"github.com/tasoint/certinv/internal/store"
)

func TestHandlerRendersInventory(t *testing.T) {
	handler, err := New(&fakeStore{snapshot: store.InventorySnapshot{Rows: []store.InventoryRow{
		{
			Hostname:      "www.example.com",
			Port:          443,
			Apex:          "example.com",
			Source:        "manual",
			HostStatus:    "active",
			CertState:     "healthy",
			Fingerprint:   "abcdef1234567890",
			SubjectCN:     "www.example.com",
			IssuerCN:      "Test CA",
			NotAfter:      "2026-11-17T12:44:20Z",
			SANNames:      `["www.example.com","example.com"]`,
			ChainComplete: true,
			HostnameMatch: true,
		},
	}}, events: []store.StoredEvent{{ID: 7, Event: evaluate.Event{Kind: evaluate.EventWarn, Fingerprint: "abcdef1234567890", Detail: "expiring"}}}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	rec := httptest.NewRecorder()
	handler.serveInventory(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"www.example.com", "healthy", "Test CA", "abcdef123456", "example.com", "/ui/export.csv", "Unacknowledged alerts", "expiring", "/ui/events/7/ack"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Fatal("body contains forbidden key material marker")
	}
}

func TestHandlerExportsInventoryCSV(t *testing.T) {
	handler, err := New(&fakeStore{snapshot: store.InventorySnapshot{Rows: []store.InventoryRow{
		{
			Hostname:       "www.example.com",
			Port:           443,
			Apex:           "example.com",
			Source:         "manual",
			HostStatus:     "active",
			CertState:      "healthy",
			Fingerprint:    "abcdef1234567890",
			SubjectCN:      "www.example.com",
			IssuerCN:       "Test CA",
			IssuerOrg:      "Example Org",
			NotBefore:      "2026-08-23T00:00:00Z",
			NotAfter:       "2026-11-17T12:44:20Z",
			SANNames:       `["www.example.com","example.com"]`,
			ChainComplete:  true,
			HostnameMatch:  true,
			FirstSeenAt:    "2026-08-23T00:00:00Z",
			LastResolvedAt: "2026-08-23T00:01:00Z",
			LastProbedAt:   "2026-08-23T00:02:00Z",
			LastSeenAt:     "2026-08-23T00:03:00Z",
			ObservedAt:     "2026-08-23T00:04:00Z",
		},
	}}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/export.csv", nil)
	rec := httptest.NewRecorder()
	handler.serveExportCSV(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/csv; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/csv", got)
	}
	records, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("csv rows = %d, want 2: %#v", len(records), records)
	}
	header := strings.Join(records[0], ",")
	for _, want := range []string{"host", "port", "apex", "issuer_cn", "fingerprint", "san", "observed_at"} {
		if !strings.Contains(header, want) {
			t.Fatalf("header missing %q: %s", want, header)
		}
	}
	row := records[1]
	for _, want := range []string{"www.example.com", "443", "example.com", "Test CA", "Example Org", "abcdef1234567890", "www.example.com;example.com", "true"} {
		if !containsCSVField(row, want) {
			t.Fatalf("row missing %q: %#v", want, row)
		}
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatal("csv contains forbidden key material marker")
	}
}

func TestHandlerRedirectsRoot(t *testing.T) {
	handler, err := New(&fakeStore{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.redirectRoot(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/ui" {
		t.Fatalf("Location = %q, want /ui", got)
	}
}

func TestHandlerAcknowledgesEvent(t *testing.T) {
	fake := &fakeStore{}
	handler, err := New(fake)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/events/7/ack", nil)
	req.SetBasicAuth("operator", "secret")
	rec := httptest.NewRecorder()
	handler.acknowledgeEvent(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if fake.ackID != 7 || fake.ackBy != "operator" {
		t.Fatalf("acknowledgement = id %d by %q, want id 7 by operator", fake.ackID, fake.ackBy)
	}
}

func TestHandlerAcknowledgeMissingEvent(t *testing.T) {
	handler, err := New(&fakeStore{ackErr: store.ErrEventNotFound})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/events/999/ack", nil)
	rec := httptest.NewRecorder()
	handler.acknowledgeEvent(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func containsCSVField(row []string, want string) bool {
	for _, field := range row {
		if field == want {
			return true
		}
	}
	return false
}

type fakeStore struct {
	store.Store
	snapshot store.InventorySnapshot
	events   []store.StoredEvent
	err      error
	ackID    int64
	ackBy    string
	ackErr   error
}

func (s fakeStore) InventorySnapshot(context.Context) (store.InventorySnapshot, error) {
	return s.snapshot, s.err
}

func (s *fakeStore) UnacknowledgedEvents(context.Context) ([]store.StoredEvent, error) {
	return s.events, s.err
}

func (s *fakeStore) AcknowledgeEvent(_ context.Context, eventID int64, by string, _ time.Time) error {
	s.ackID = eventID
	s.ackBy = by
	return s.ackErr
}
