package ui

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tasoint/certinv/internal/config"
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
		events:     []store.StoredEvent{{ID: 7, Event: evaluate.Event{Kind: evaluate.EventWarn, Fingerprint: "abcdef1234567890", Detail: "expiring"}}},
		suppressed: []store.SuppressedHost{{Hostname: "old.example.com", Port: 443}},
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
	for _, want := range []string{"www.example.com", "healthy", "Test CA", "abcdef123456", "example.com", "/ui/export.csv", "Unacknowledged alerts", "remaining validity ratio", "expiring", "/ui/events/7/ack", "/ui/scan", "inventory-host-filter", "inventory-status-filter", "data-inventory-host=\"www.example.com\"", "data-cert-state=\"healthy\"", "applyInventoryFilters", "All clear", "/ui/hosts/suppress-all", "Purge all", "/ui/hosts/purge-all", "saved", "problem"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Fatal("body contains forbidden key material marker")
	}
	if strings.Contains(body, `name="include_crtname" value="true" checked`) {
		t.Fatal("include_crtname checkbox is checked by default")
	}
}

func TestHandlerRendersTabs(t *testing.T) {
	handler, err := New(&fakeStore{targets: store.ManagedTargets{ManualHosts: []store.ManagedManualHost{
		{Hostname: "db.example.com", Port: 8443, Apex: "example.com", Source: "db"},
	}}}, WithConfigTargets([]string{"example.com"}, nil), WithSourceConfig(config.Discovery{
		Sources: []string{discover.SourceCrtName},
		CrtName: config.CrtNameSource{Endpoint: "https://crt.name/v1/search"},
	}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui?tab=sources", nil)
	rec := httptest.NewRecorder()
	handler.serveInventory(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sources status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Apexes", "Manual hosts", "crt.name discovery", "Zone files", "Add apex", "Add manual host", "/ui/manual-hosts/edit", "Update port", "Saved setting:", "Saving applies this setting", "CT-log subdomains", "not a filter for apex discovery", "every apex registered above", "example.com", "config.yaml", "Added in UI"} {
		if !strings.Contains(body, want) {
			t.Fatalf("sources tab missing %q:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "<th>Hostname</th><th>Apex</th><th>Origin</th><th>Port</th><th>Action</th>") {
		t.Fatalf("manual hosts header has unexpected order:\n%s", body)
	}
	if strings.Contains(body, "Unacknowledged alerts") {
		t.Fatal("sources tab contains inventory alerts")
	}

	req = httptest.NewRequest(http.MethodGet, "/ui?tab=inventory", nil)
	rec = httptest.NewRecorder()
	handler.serveInventory(rec, req)
	body = rec.Body.String()
	if !strings.Contains(body, "Unacknowledged alerts") || strings.Contains(body, "Add apex") {
		t.Fatalf("inventory tab content mismatch:\n%s", body)
	}
}

func TestHandlerRendersScanPollingAfterAcceptedNotice(t *testing.T) {
	handler, err := New(&fakeStore{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/ui?notice=scan+accepted", nil)
	rec := httptest.NewRecorder()
	handler.serveInventory(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "/ui/scan/status") || !strings.Contains(body, "credentials: 'same-origin'") {
		t.Fatalf("body missing scan polling script:\n%s", body)
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

func TestHandlerEditsManagedManualHostPort(t *testing.T) {
	store := &fakeStore{targets: store.ManagedTargets{ManualHosts: []store.ManagedManualHost{
		{Hostname: "www.example.com", Port: 443, Apex: "example.com", Source: "db"},
	}}}
	handler, err := New(store, WithConfigTargets([]string{"example.com"}, nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.serveEditManualHost(rec, formRequest("/ui/manual-hosts/edit?tab=sources", "hostname=www.example.com&old_port=443&port=8443"))
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "tab=sources") {
		t.Fatalf("status/location = %d/%q", rec.Code, rec.Header().Get("Location"))
	}
	if store.deletedHost != "www.example.com:443" {
		t.Fatalf("deleted host = %q, want www.example.com:443", store.deletedHost)
	}
	if store.addedHost.Hostname != "www.example.com" || store.addedHost.Port != 8443 {
		t.Fatalf("added host = %#v, want www.example.com:8443", store.addedHost)
	}
}

func TestHandlerRejectsEditingConfigManualHost(t *testing.T) {
	store := &fakeStore{}
	handler, err := New(store, WithConfigTargets([]string{"example.com"}, []config.ManualHost{{Hostname: "www.example.com", Port: 443}}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.serveEditManualHost(rec, formRequest("/ui/manual-hosts/edit?tab=sources", "hostname=www.example.com&old_port=443&port=8443"))
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Fatalf("status/location = %d/%q", rec.Code, rec.Header().Get("Location"))
	}
	if store.deletedHost != "" || store.addedHost.Hostname != "" {
		t.Fatalf("store mutated deleted=%q added=%#v", store.deletedHost, store.addedHost)
	}
}

func TestHandlerSavesCrtNameSettings(t *testing.T) {
	store := &fakeStore{}
	handler, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := formRequest("/ui/crtname?tab=sources", "enabled=on&endpoint=https%3A%2F%2Fcrt.example%2Fsearch")
	rec := httptest.NewRecorder()
	handler.serveSaveCrtName(rec, req)
	if rec.Code != http.StatusSeeOther || !store.crtNameEnabled || store.crtNameEndpoint != "https://crt.example/search" {
		t.Fatalf("status=%d enabled=%t endpoint=%q", rec.Code, store.crtNameEnabled, store.crtNameEndpoint)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "tab=sources") || !strings.Contains(got, "notice=") {
		t.Fatalf("Location = %q, want sources notice", got)
	}
}

func TestHandlerLooksUpCrtNameCandidates(t *testing.T) {
	var gotApex string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotApex = r.URL.Query().Get("apex")
		if gotApex != "example.com" {
			t.Fatalf("apex query = %q, want example.com", gotApex)
		}
		if err := json.NewEncoder(w).Encode([]map[string]string{
			{"sub": "www.example.com\napi.example.com\noutside.example.net"},
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	handler, err := New(&fakeStore{},
		WithConfigTargets([]string{"example.com"}, nil),
		WithSourceConfig(config.Discovery{
			Sources: []string{discover.SourceCrtName},
			CrtName: config.CrtNameSource{Endpoint: server.URL},
		}),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := formRequest("/ui/crtname/lookup?tab=sources", "enabled=on&endpoint="+server.URL+"&apex=example.com")
	rec := httptest.NewRecorder()
	handler.serveCrtNameLookup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"crtname lookup completed", "www.example.com", "api.example.com", "Add selected to Targets"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "outside.example.net") {
		t.Fatalf("body contains out-of-scope host:\n%s", body)
	}
	if gotApex == "" {
		t.Fatal("crtname server was not called")
	}
}

func TestHandlerCrtNameLookupUsesSelectedApexAndFormEndpoint(t *testing.T) {
	var gotApex string
	usedFormEndpoint := false
	formServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		usedFormEndpoint = true
		gotApex = r.URL.Query().Get("apex")
		if gotApex != "managed.example.net" {
			t.Fatalf("apex query = %q, want managed.example.net", gotApex)
		}
		if err := json.NewEncoder(w).Encode([]map[string]string{
			{"sub": "app.managed.example.net"},
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer formServer.Close()
	savedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("saved endpoint should not be used for lookup")
	}))
	defer savedServer.Close()

	handler, err := New(&fakeStore{
		targets: store.ManagedTargets{Apexes: []store.ManagedApex{{Apex: "managed.example.net", Source: "db"}}},
		discovery: store.ManagedDiscovery{
			CrtNameSet:      true,
			CrtNameEnabled:  true,
			CrtNameEndpoint: savedServer.URL,
		},
	}, WithConfigTargets([]string{"example.com"}, nil), WithSourceConfig(config.Discovery{Sources: []string{discover.SourceCrtName}, CrtName: config.CrtNameSource{Endpoint: savedServer.URL}}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.serveCrtNameLookup(rec, formRequest("/ui/crtname/lookup?tab=sources", "enabled=on&endpoint="+formServer.URL+"&apex=managed.example.net"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "app.managed.example.net") {
		t.Fatalf("status/body = %d/%s", rec.Code, rec.Body.String())
	}
	if !usedFormEndpoint {
		t.Fatal("form endpoint was not used")
	}
	if strings.Contains(rec.Body.String(), "www.example.com") {
		t.Fatalf("body includes unselected apex candidate:\n%s", rec.Body.String())
	}
}

func TestHandlerCrtNameLookupExcludesExistingManualHosts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode([]map[string]string{
			{"sub": "www.example.com\napi.example.com\ndb.example.com"},
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	handler, err := New(&fakeStore{
		targets: store.ManagedTargets{ManualHosts: []store.ManagedManualHost{
			{Hostname: "db.example.com", Port: 8443, Apex: "example.com", Source: "db"},
		}},
	}, WithConfigTargets([]string{"example.com"}, []config.ManualHost{{Hostname: "www.example.com", Port: 443}}), WithSourceConfig(config.Discovery{
		Sources: []string{discover.SourceCrtName},
		CrtName: config.CrtNameSource{Endpoint: server.URL},
	}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.serveCrtNameLookup(rec, formRequest("/ui/crtname/lookup?tab=sources", "enabled=on&endpoint="+server.URL+"&apex=example.com"))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "api.example.com") {
		t.Fatalf("status/body = %d/%s", rec.Code, body)
	}
	if strings.Contains(body, `data-crtname-host="www.example.com"`) || strings.Contains(body, `data-crtname-host="db.example.com"`) {
		t.Fatalf("body contains already registered host:\n%s", body)
	}
	if !strings.Contains(body, "Filter hostnames") || !strings.Contains(body, "Select all") || !strings.Contains(body, "Clear all") {
		t.Fatalf("body missing candidate controls:\n%s", body)
	}
}

func TestHandlerAddsSelectedCrtNameHosts(t *testing.T) {
	store := &fakeStore{}
	handler, err := New(store, WithConfigTargets([]string{"example.com"}, nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.serveAddCrtNameSelected(rec, formRequest("/ui/crtname/add-selected?tab=sources", "hostname=www.example.com&hostname=api.example.com"))
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "tab=sources") {
		t.Fatalf("status/location = %d/%q", rec.Code, rec.Header().Get("Location"))
	}
	if len(store.addedHosts) != 2 {
		t.Fatalf("added hosts = %d, want 2", len(store.addedHosts))
	}
	for _, host := range store.addedHosts {
		if host.Port != 443 || host.Apex != "example.com" {
			t.Fatalf("added host = %#v, want port 443 apex example.com", host)
		}
	}
}

func TestHandlerRejectsSelectedCrtNameHostOutsideApex(t *testing.T) {
	store := &fakeStore{}
	handler, err := New(store, WithConfigTargets([]string{"example.com"}, nil))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rec := httptest.NewRecorder()
	handler.serveAddCrtNameSelected(rec, formRequest("/ui/crtname/add-selected?tab=sources", "hostname=outside.example.net"))
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Fatalf("status/location = %d/%q", rec.Code, rec.Header().Get("Location"))
	}
	if len(store.addedHosts) != 0 {
		t.Fatalf("added hosts = %d, want 0", len(store.addedHosts))
	}
}

func TestHandlerAddsZoneFileWithinAllowedDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/example.zone", []byte("$ORIGIN example.com."), 0o600); err != nil {
		t.Fatalf("write zone file: %v", err)
	}
	store := &fakeStore{}
	handler, err := New(store, WithSourceConfig(config.Discovery{Zone: config.ZoneSource{AllowedDir: dir}}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := formRequest("/ui/zone-files?tab=sources", "file=example.zone")
	rec := httptest.NewRecorder()
	handler.serveAddZoneFile(rec, req)
	if rec.Code != http.StatusSeeOther || !strings.HasSuffix(store.addedZoneFile, "/example.zone") {
		t.Fatalf("status=%d added zone file=%q", rec.Code, store.addedZoneFile)
	}
}

func TestHandlerRejectsZoneTraversal(t *testing.T) {
	dir := t.TempDir()
	store := &fakeStore{}
	handler, err := New(store, WithSourceConfig(config.Discovery{Zone: config.ZoneSource{AllowedDir: dir}}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := formRequest("/ui/zone-files?tab=sources", "file=../outside.zone")
	rec := httptest.NewRecorder()
	handler.serveAddZoneFile(rec, req)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "error=") {
		t.Fatalf("status/location = %d/%q, want error redirect", rec.Code, rec.Header().Get("Location"))
	}
	if store.addedZoneFile != "" {
		t.Fatalf("added zone file = %q, want empty", store.addedZoneFile)
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

func TestHandlerScanLoadingMarkup(t *testing.T) {
	handler, err := New(&fakeStore{}, WithScanTrigger(&fakeScanner{accepted: true}))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.serveInventory(rec, httptest.NewRequest(http.MethodGet, "/ui?notice=scan+accepted", nil))
	body := rec.Body.String()
	for _, want := range []string{"Scanning...", `id="run-scan"`, "disabled", "Date.now() - started > 60000", "may still be running"} {
		if !strings.Contains(body, want) {
			t.Fatalf("loading markup missing %q", want)
		}
	}
}

func TestHandlerPassesCrtNameScanOverride(t *testing.T) {
	scanner := &fakeScanner{accepted: true}
	handler, err := New(&fakeStore{}, WithScanTrigger(scanner))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/scan", strings.NewReader("include_crtname=true"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.serveScan(httptest.NewRecorder(), req)
	if !scanner.include {
		t.Fatal("include_crtname=false, want true")
	}
	req = httptest.NewRequest(http.MethodPost, "/ui/scan", nil)
	handler.serveScan(httptest.NewRecorder(), req)
	if scanner.include {
		t.Fatal("unchecked include_crtname=true, want false")
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
		"edit manual host": {
			req:   formRequest("/ui/manual-hosts/edit", "hostname=www.example.com&old_port=443&port=bad"),
			serve: handler.serveEditManualHost,
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
	snapshot        store.InventorySnapshot
	targets         store.ManagedTargets
	events          []store.StoredEvent
	suppressed      []store.SuppressedHost
	err             error
	addedApex       string
	deletedApex     string
	addedHost       discover.Host
	addedHosts      []discover.Host
	deletedHost     string
	ackID           int64
	ackBy           string
	ackErr          error
	suppressKey     string
	suppressedKeys  []string
	discovery       store.ManagedDiscovery
	crtNameEnabled  bool
	crtNameEndpoint string
	addedZoneFile   string
	deletedZoneFile string
	purgedHost      string
	purgedHosts     []string
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
	s.addedHosts = append(s.addedHosts, host)
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
	s.suppressedKeys = append(s.suppressedKeys, s.suppressKey)
	return nil
}

func (s *fakeStore) UnsuppressHost(_ context.Context, hostname string, port int) error {
	s.suppressKey = "unsuppress:" + hostname + ":" + strconv.Itoa(port)
	return nil
}

func (s *fakeStore) PurgeHost(_ context.Context, hostname string, port int) error {
	s.purgedHost = hostname + ":" + strconv.Itoa(port)
	s.purgedHosts = append(s.purgedHosts, s.purgedHost)
	return nil
}

func (s *fakeStore) ManagedDiscovery(context.Context) (store.ManagedDiscovery, error) {
	return s.discovery, s.err
}

func (s *fakeStore) SaveManagedCrtName(_ context.Context, enabled bool, endpoint string, _ time.Time) error {
	s.crtNameEnabled = enabled
	s.crtNameEndpoint = endpoint
	return nil
}

func (s *fakeStore) AddManagedZoneFile(_ context.Context, path string, _ time.Time) error {
	s.addedZoneFile = path
	return nil
}

func (s *fakeStore) DeleteManagedZoneFile(_ context.Context, path string) error {
	s.deletedZoneFile = path
	return nil
}

type fakeScanner struct {
	accepted bool
	running  bool
	calls    int
	include  bool
}

func (s *fakeScanner) TriggerScan(include bool) bool {
	s.calls++
	s.include = include
	return s.accepted
}

func (s *fakeScanner) Running() bool {
	return s.running
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

func TestHandlerSuppressesAllInventoryHosts(t *testing.T) {
	fake := &fakeStore{snapshot: store.InventorySnapshot{Rows: []store.InventoryRow{
		{Hostname: "www.example.com", Port: 443},
		{Hostname: "api.example.com", Port: 8443},
	}}}
	handler, err := New(fake)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	rec := httptest.NewRecorder()
	handler.serveSuppressAllHosts(rec, httptest.NewRequest(http.MethodPost, "/ui/hosts/suppress-all", nil))
	if rec.Code != http.StatusSeeOther || len(fake.suppressedKeys) != 2 {
		t.Fatalf("status/suppressed = %d/%#v", rec.Code, fake.suppressedKeys)
	}
	if fake.suppressedKeys[0] != "www.example.com:443" || fake.suppressedKeys[1] != "api.example.com:8443" {
		t.Fatalf("suppressed keys = %#v", fake.suppressedKeys)
	}
}

func TestHandlerPurgesSuppressedHost(t *testing.T) {
	fake := &fakeStore{}
	handler, err := New(fake)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	rec := httptest.NewRecorder()
	handler.servePurgeHost(rec, formRequest("/ui/hosts/purge", "hostname=www.example.com&port=443"))
	if rec.Code != http.StatusSeeOther || fake.purgedHost != "www.example.com:443" {
		t.Fatalf("purge status/host = %d/%q", rec.Code, fake.purgedHost)
	}
}

func TestHandlerPurgesAllSuppressedHosts(t *testing.T) {
	fake := &fakeStore{suppressed: []store.SuppressedHost{
		{Hostname: "old.example.com", Port: 443},
		{Hostname: "gone.example.com", Port: 8443},
	}}
	handler, err := New(fake)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	rec := httptest.NewRecorder()
	handler.servePurgeAllHosts(rec, httptest.NewRequest(http.MethodPost, "/ui/hosts/purge-all", nil))
	if rec.Code != http.StatusSeeOther || len(fake.purgedHosts) != 2 {
		t.Fatalf("status/purged = %d/%#v", rec.Code, fake.purgedHosts)
	}
	if fake.purgedHosts[0] != "old.example.com:443" || fake.purgedHosts[1] != "gone.example.com:8443" {
		t.Fatalf("purged hosts = %#v", fake.purgedHosts)
	}
}

func TestHandlerReportsScanStatus(t *testing.T) {
	handler, err := New(&fakeStore{}, WithScanTrigger(&fakeScanner{running: true}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/ui/scan/status", nil)
	rec := httptest.NewRecorder()
	handler.serveScanStatus(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"running":true`) {
		t.Fatalf("status/body = %d/%s", rec.Code, rec.Body.String())
	}
}
