package crtname

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverFiltersOutOfScopeNames(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != UserAgent {
			t.Fatalf("User-Agent = %q, want %q", got, UserAgent)
		}
		if got := r.URL.Query().Get("apex"); got != "example.com" {
			t.Fatalf("apex query = %q, want example.com", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[
			{"sub":"www.example.com","first_seen":"2026-08-23"},
			{"sub":"*.example.com\noutside.example.net"}
		]`))
	}))
	defer server.Close()

	source := New(server.URL, WithHTTPClient(server.Client()))
	hosts, err := source.Discover(context.Background(), []string{"example.com"})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("len(hosts) = %d, want 2", len(hosts))
	}
}

func TestRecordHostnamesKeepsLegacyFields(t *testing.T) {
	names := record{
		Subdomain: "legacy.example.com",
		NameValue: "*.example.com\napi.example.com",
	}.hostnames()
	if len(names) != 3 {
		t.Fatalf("len(names) = %d, want 3: %#v", len(names), names)
	}
}
