package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tasoint/certinv/internal/store"
)

func TestHandlerRendersInventory(t *testing.T) {
	handler, err := New(fakeStore{snapshot: store.InventorySnapshot{Rows: []store.InventoryRow{
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
	}}})
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
	for _, want := range []string{"www.example.com", "healthy", "Test CA", "abcdef123456", "example.com"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Fatal("body contains forbidden key material marker")
	}
}

func TestHandlerRedirectsRoot(t *testing.T) {
	handler, err := New(fakeStore{})
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

type fakeStore struct {
	store.Store
	snapshot store.InventorySnapshot
	err      error
}

func (s fakeStore) InventorySnapshot(context.Context) (store.InventorySnapshot, error) {
	return s.snapshot, s.err
}
