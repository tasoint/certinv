package sqlite

import (
	"context"
	"testing"
	"time"

	certmeta "github.com/tasoint/certinv/internal/cert"
	"github.com/tasoint/certinv/internal/discover"
)

func TestStorePersistsHostCertificateLink(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	if err := store.UpsertApex(ctx, "example.com", now); err != nil {
		t.Fatalf("UpsertApex() error = %v", err)
	}
	hostID, err := store.UpsertHost(ctx, discover.Host{
		Hostname: "www.example.com",
		Port:     443,
		Apex:     "example.com",
		Source:   discover.SourceManual,
	}, "active", now)
	if err != nil {
		t.Fatalf("UpsertHost() error = %v", err)
	}
	certificate := certmeta.Metadata{
		Fingerprint:   "abc123",
		NotBefore:     now.Add(-24 * time.Hour),
		NotAfter:      now.Add(47 * 24 * time.Hour),
		LifetimeDays:  48,
		IsSelfSigned:  true,
		SANNames:      []string{"www.example.com"},
		ChainComplete: true,
		HostnameMatch: true,
	}
	if err := store.UpsertCertificate(ctx, certificate, now); err != nil {
		t.Fatalf("UpsertCertificate() error = %v", err)
	}
	if err := store.LinkHostCertificate(ctx, hostID, certificate.Fingerprint, true, true, now); err != nil {
		t.Fatalf("LinkHostCertificate() error = %v", err)
	}

	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_certificates`).Scan(&count); err != nil {
		t.Fatalf("count links: %v", err)
	}
	if count != 1 {
		t.Fatalf("link count = %d, want 1", count)
	}
}
