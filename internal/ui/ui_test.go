package ui

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tasoint/certinv/internal/discover"
	"github.com/tasoint/certinv/internal/evaluate"
	"github.com/tasoint/certinv/internal/store"
)

func TestHandlerRendersInventory(t *testing.T) {
	handler, err := New(&fakeStore{
		targets: store.ManagedTargets{
			Apexes: []store.ManagedApex{{Apex: "managed.example.net", Source: "db"}},
			ManualHosts: []store.ManagedManualHost{
				{Hostname: "db.example.com", Port: 8443, Apex: "example.com", Source: "db"},
			},
		},
		snapshot: store.InventorySnapshot{Rows: []store.InventoryRow{
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
		}},
		events: []store.StoredEvent{{ID: 7, Event: evaluate.Event{Kind: evaluate.EventWarn, Fingerprint: "abcdef1234567890", Detail: "expiring"}}},
	}, WithConfigTargets([]string{"example.com"}, nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui?notice=saved&error=problem", nil)
	rec := httptest.NewRecorder()
	handler.serveInventory(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"www.example.com", "healthy", "Test CA", "abcdef123456", "example.com", "/ui/export.csv", "Unacknowledged alerts", "expiring", "/ui/events/7/ack", "/ui/scan", "managed.example.net", "db.example.com:8443", "saved", "problem"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Fatal("body contains forbidden key material marker")
	}
}

func TestHandlerAddsAndDeletesManagedTargets(t *testing.T) {
	store := &fakeStore{}
	handler, err := New(store, WithConfigTargets([]string{"example.com"}, nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ui/apexes", strings.NewReader("apex=example.net"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.serveAddApex(rec, req)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "/ui?notice=") || store.addedApex != "example.net" {
		t.Fatalf("add apex status=%d added=%q", rec.Code, store.addedApex)
	}

	req = httptest.NewRequest(http.MethodPost, "/ui/manual-hosts", strings.NewReader("hostname=www.example.com&port=8443"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	handler.serveAddManualHost(rec, req)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "/ui?notice=") || store.addedHost.Hostname != "www.example.com" || store.addedHost.Port != 8443 {
		t.Fatalf("add host status=%d host=%#v", rec.Code, store.addedHost)
	}

	req = httptest.NewRequest(http.MethodPost, "/ui/manual-hosts/delete", strings.NewReader("hostname=www.example.com&port=8443"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	handler.serveDeleteManualHost(rec, req)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "/ui?notice=") || store.deletedHost != "www.example.com:8443" {
		t.Fatalf("delete host status=%d deleted=%q", rec.Code, store.deletedHost)
	}
}

func TestHandlerRejectsManualHostOutsideApex(t *testing.T) {
	store := &fakeStore{}
	handler, err := New(store, WithConfigTargets([]string{"example.com"}, nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ui/manual-hosts", strings.NewReader("hostname=www.example.net&port=443"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.serveAddManualHost(rec, req)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "/ui?error=") {
		t.Fatalf("status/location = %d/%q, want 303 error redirect", rec.Code, rec.Header().Get("Location"))
	}
}

func TestHandlerAcceptsManualScan(t *testing.T) {
	scanner := &fakeScanner{accepted: true}
	handler, err := New(&fakeStore{}, WithScanTrigger(scanner))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ui/scan", nil)
	rec := httptest.NewRecorder()
	handler.serveScan(rec, req)

	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "/ui?notice=") {
		t.Fatalf("status/location = %d/%q, want 303 notice redirect", rec.Code, rec.Header().Get("Location"))
	}
	if scanner.calls != 1 {
		t.Fatalf("scan calls = %d, want 1", scanner.calls)
	}
}

func TestHandlerRejectsManualScanWhenRunning(t *testing.T) {
	handler, err := New(&fakeStore{}, WithScanTrigger(&fakeScanner{accepted: false}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ui/scan", nil)
	rec := httptest.NewRecorder()
	handler.serveScan(rec, req)

	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "/ui?error=") {
		t.Fatalf("status/location = %d/%q, want 303 error redirect", rec.Code, rec.Header().Get("Location"))
	}
}

func TestHandlerRedirectsActionValidationErrors(t *testing.T) {
	handler, err := New(&fakeStore{}, WithConfigTargets([]string{"example.com"}, nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for name, tc := range map[string]struct {
		req   *http.Request
		serve func(http.ResponseWriter, *http.Request)
	}{
		"add apex": {
			req:   formRequest("/ui/apexes", "apex=www.example.com"),
			serve: handler.serveAddApex,
		},
		"delete apex": {
			req:   formRequest("/ui/apexes/delete", "apex=www.example.com"),
			serve: handler.serveDeleteApex,
		},
		"add manual host": {
			req:   formRequest("/ui/manual-hosts", "hostname=www.example.net&port=443"),
			serve: handler.serveAddManualHost,
		},
		"delete manual host": {
			req:   formRequest("/ui/manual-hosts/delete", "hostname=www.example.com&port=bad"),
			serve: handler.serveDeleteManualHost,
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.serve(rec, tc.req)
			if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "/ui?error=") {
				t.Fatalf("status/location = %d/%q, want 303 error redirect", rec.Code, rec.Header().Get("Location"))
			}
		})
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

func formRequest(path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

type fakeStore struct {
	store.Store
	snapshot    store.InventorySnapshot
	targets     store.ManagedTargets
	events      []store.StoredEvent
	suppressed  []store.SuppressedHost
	err         error
	addedApex   string
	deletedApex string
	addedHost   discover.Host
	deletedHost string
	ackID       int64
	ackBy       string
	ackErr      error
	suppressKey string
}

func (s fakeStore) InventorySnapshot(context.Context) (store.InventorySnapshot, error) {
	return s.snapshot, s.err
}

func (s *fakeStore) ManagedTargets(context.Context) (store.ManagedTargets, error) {
	return s.targets, s.err
}

func (s *fakeStore) AddManagedApex(_ context.Context, apex string, _ time.Time) error {
	s.addedApex = apex
	return nil
}

func (s *fakeStore) DeleteManagedApex(_ context.Context, apex string) error {
	s.deletedApex = apex
	return nil
}

func (s *fakeStore) AddManagedManualHost(_ context.Context, host discover.Host, _ time.Time) error {
	s.addedHost = host
	return nil
}

func (s *fakeStore) DeleteManagedManualHost(_ context.Context, hostname string, port int) error {
	s.deletedHost = hostname + ":" + strconv.Itoa(port)
	return nil
}

func (s *fakeStore) UnacknowledgedEvents(context.Context) ([]store.StoredEvent, error) {
	return s.events, s.err
}

func (s *fakeStore) AcknowledgeEvent(_ context.Context, eventID int64, by string, _ time.Time) error {
	s.ackID = eventID
	s.ackBy = by
	return s.ackErr
}

func (s *fakeStore) SuppressedHosts(context.Context) ([]store.SuppressedHost, error) {
	return s.suppressed, s.err
}

func (s *fakeStore) SuppressHost(_ context.Context, hostname string, port int, _ time.Time) error {
	s.suppressKey = hostname + ":" + strconv.Itoa(port)
	return nil
}

func (s *fakeStore) UnsuppressHost(_ context.Context, hostname string, port int) error {
	s.suppressKey = "unsuppress:" + hostname + ":" + strconv.Itoa(port)
	return nil
}

type fakeScanner struct {
	accepted bool
	calls    int
}

func (s *fakeScanner) TriggerScan() bool {
	s.calls++
	return s.accepted
}

func TestHandlerSuppressesAndUnsuppressesHost(t *testing.T) {
	fake := &fakeStore{}
	handler, err := New(fake)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	rec := httptest.NewRecorder()
	handler.serveSuppressHost(rec, formRequest("/ui/hosts/suppress", "hostname=www.example.com&port=443"))
	if rec.Code != http.StatusSeeOther || fake.suppressKey != "www.example.com:443" {
		t.Fatalf("suppress status/key = %d/%q", rec.Code, fake.suppressKey)
	}
	rec = httptest.NewRecorder()
	handler.serveUnsuppressHost(rec, formRequest("/ui/hosts/unsuppress", "hostname=www.example.com&port=443"))
	if rec.Code != http.StatusSeeOther || fake.suppressKey != "unsuppress:www.example.com:443" {
		t.Fatalf("unsuppress status/key = %d/%q", rec.Code, fake.suppressKey)
	}
}
