package exporter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	certmeta "github.com/tasoint/certinv/internal/cert"
	"github.com/tasoint/certinv/internal/core"
	"github.com/tasoint/certinv/internal/discover"
	sqlitestore "github.com/tasoint/certinv/internal/store/sqlite"
)

func TestHandlerExportsStoreAndScanMetrics(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitestore.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer db.Close()

	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	if err := db.UpsertApex(ctx, "example.com", now); err != nil {
		t.Fatalf("UpsertApex() error = %v", err)
	}
	hostID, err := db.UpsertHost(ctx, discover.Host{
		Hostname: "www.example.com",
		Port:     443,
		Apex:     "example.com",
		Source:   discover.SourceManual,
	}, "active", now)
	if err != nil {
		t.Fatalf("UpsertHost() error = %v", err)
	}
	if err := db.UpsertCertificate(ctx, certmeta.Metadata{
		Fingerprint:   "abc123",
		SubjectCN:     "www.example.com",
		IssuerCN:      "Test CA",
		NotBefore:     now.Add(-24 * time.Hour),
		NotAfter:      now.Add(47 * 24 * time.Hour),
		LifetimeDays:  48,
		ChainComplete: true,
		HostnameMatch: true,
	}, now); err != nil {
		t.Fatalf("UpsertCertificate() error = %v", err)
	}
	if err := db.LinkHostCertificate(ctx, hostID, "abc123", true, true, now); err != nil {
		t.Fatalf("LinkHostCertificate() error = %v", err)
	}
	if err := db.SetAutomationClass(ctx, hostID, "abc123", "likely_auto"); err != nil {
		t.Fatalf("SetAutomationClass() error = %v", err)
	}

	exp := New(db)
	exp.RecordScan(core.Summary{Probed: 1}, 1500*time.Millisecond, true, now)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	exp.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`certinv_cert_not_after_timestamp{automation="likely_auto",common_name="www.example.com",fingerprint="abc123",issuer="Test CA"}`,
		`certinv_cert_lifetime_days{automation="likely_auto",common_name="www.example.com",fingerprint="abc123",issuer="Test CA"}`,
		`certinv_cert_remaining_ratio{automation="likely_auto",common_name="www.example.com",fingerprint="abc123",issuer="Test CA"}`,
		"certinv_host_reachable",
		"certinv_scan_duration_seconds 1.5",
		"certinv_scan_last_success_timestamp",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics body missing %q:\n%s", want, body)
		}
	}
}
