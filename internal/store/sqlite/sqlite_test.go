package sqlite

import (
	"context"
	"testing"
	"time"

	certmeta "github.com/tasoint/certinv/internal/cert"
	"github.com/tasoint/certinv/internal/discover"
	"github.com/tasoint/certinv/internal/evaluate"
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
	latest, err := store.LatestHostCertificate(ctx, hostID)
	if err != nil {
		t.Fatalf("LatestHostCertificate() error = %v", err)
	}
	if latest.Fingerprint != certificate.Fingerprint {
		t.Fatalf("latest fingerprint = %q, want %q", latest.Fingerprint, certificate.Fingerprint)
	}

	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_certificates`).Scan(&count); err != nil {
		t.Fatalf("count links: %v", err)
	}
	if count != 1 {
		t.Fatalf("link count = %d, want 1", count)
	}
}

func TestStorePersistsStateAndEvent(t *testing.T) {
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
	if err := store.SetCertificateState(ctx, hostID, "abc123", evaluate.StateWarn, now); err != nil {
		t.Fatalf("SetCertificateState() error = %v", err)
	}
	state, err := store.GetCertificateState(ctx, hostID, "abc123")
	if err != nil {
		t.Fatalf("GetCertificateState() error = %v", err)
	}
	if state != evaluate.StateWarn {
		t.Fatalf("state = %q, want %q", state, evaluate.StateWarn)
	}

	eventID, err := store.RecordEvent(ctx, evaluate.Event{
		Kind:        evaluate.EventWarn,
		Fingerprint: "abc123",
		HostID:      hostID,
		Detail:      "certificate crossed warn threshold",
	}, now)
	if err != nil {
		t.Fatalf("RecordEvent() error = %v", err)
	}
	pending, err := store.PendingEvents(ctx)
	if err != nil {
		t.Fatalf("PendingEvents() error = %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending events = %d, want 1", len(pending))
	}
	if pending[0].ID != eventID || pending[0].Kind != evaluate.EventWarn {
		t.Fatalf("pending event = %#v, want id %d kind %s", pending[0], eventID, evaluate.EventWarn)
	}
	unacknowledged, err := store.UnacknowledgedEvents(ctx)
	if err != nil {
		t.Fatalf("UnacknowledgedEvents() error = %v", err)
	}
	if len(unacknowledged) != 1 || unacknowledged[0].ID != eventID {
		t.Fatalf("unacknowledged events = %#v, want event %d", unacknowledged, eventID)
	}
	if err := store.AcknowledgeEvent(ctx, eventID, "operator", now); err != nil {
		t.Fatalf("AcknowledgeEvent() error = %v", err)
	}
	unacknowledged, err = store.UnacknowledgedEvents(ctx)
	if err != nil {
		t.Fatalf("UnacknowledgedEvents() after acknowledge error = %v", err)
	}
	if len(unacknowledged) != 0 {
		t.Fatalf("unacknowledged events after acknowledge = %#v, want none", unacknowledged)
	}
	var acknowledgedAt, acknowledgedBy string
	if err := store.db.QueryRowContext(ctx, `SELECT acknowledged_at, acknowledged_by FROM events WHERE id = ?`, eventID).
		Scan(&acknowledgedAt, &acknowledgedBy); err != nil {
		t.Fatalf("select acknowledgement: %v", err)
	}
	if acknowledgedAt == "" || acknowledgedBy != "operator" {
		t.Fatalf("acknowledgement = %q by %q, want timestamp by operator", acknowledgedAt, acknowledgedBy)
	}
	if err := store.MarkEventNotified(ctx, eventID, now); err != nil {
		t.Fatalf("MarkEventNotified() error = %v", err)
	}
	var notifiedAt string
	if err := store.db.QueryRowContext(ctx, `SELECT notified_at FROM events WHERE id = ?`, eventID).Scan(&notifiedAt); err != nil {
		t.Fatalf("select event: %v", err)
	}
	if notifiedAt == "" {
		t.Fatal("notified_at is empty")
	}
}

func TestMetricsSnapshot(t *testing.T) {
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
	if err := store.UpsertCertificate(ctx, certmeta.Metadata{
		Fingerprint:   "abc123",
		SubjectCN:     "www.example.com",
		IssuerCN:      "Test CA",
		NotBefore:     now.Add(-24 * time.Hour),
		NotAfter:      now.Add(47 * 24 * time.Hour),
		LifetimeDays:  48,
		IsSelfSigned:  true,
		ChainComplete: true,
		HostnameMatch: true,
	}, now); err != nil {
		t.Fatalf("UpsertCertificate() error = %v", err)
	}
	if err := store.LinkHostCertificate(ctx, hostID, "abc123", true, true, now); err != nil {
		t.Fatalf("LinkHostCertificate() error = %v", err)
	}

	snapshot, err := store.MetricsSnapshot(ctx)
	if err != nil {
		t.Fatalf("MetricsSnapshot() error = %v", err)
	}
	if len(snapshot.Certificates) != 1 {
		t.Fatalf("certificates = %d, want 1", len(snapshot.Certificates))
	}
	if len(snapshot.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(snapshot.Hosts))
	}
	if !snapshot.Hosts[0].Reachable {
		t.Fatal("host reachable = false, want true")
	}
}
func TestInventorySnapshot(t *testing.T) {
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
		SubjectCN:     "www.example.com",
		IssuerCN:      "Test CA",
		IssuerOrg:     "Example Org",
		NotBefore:     now.Add(-24 * time.Hour),
		NotAfter:      now.Add(47 * 24 * time.Hour),
		LifetimeDays:  48,
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
	if err := store.SetCertificateState(ctx, hostID, certificate.Fingerprint, evaluate.StateHealthy, now); err != nil {
		t.Fatalf("SetCertificateState() error = %v", err)
	}

	snapshot, err := store.InventorySnapshot(ctx)
	if err != nil {
		t.Fatalf("InventorySnapshot() error = %v", err)
	}
	if len(snapshot.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(snapshot.Rows))
	}
	row := snapshot.Rows[0]
	if row.Hostname != "www.example.com" || row.Fingerprint != "abc123" || row.CertState != evaluate.StateHealthy {
		t.Fatalf("row = %#v", row)
	}
	if row.SANNames == "" || row.SANNames == "[]" {
		t.Fatalf("SANNames = %q, want populated JSON", row.SANNames)
	}
}

func TestManagedTargets(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	if err := store.AddManagedApex(ctx, "example.net", now); err != nil {
		t.Fatalf("AddManagedApex() error = %v", err)
	}
	if err := store.AddManagedManualHost(ctx, discover.Host{
		Hostname: "www.example.net",
		Port:     8443,
		Apex:     "example.net",
		Source:   "managed",
	}, now); err != nil {
		t.Fatalf("AddManagedManualHost() error = %v", err)
	}

	targets, err := store.ManagedTargets(ctx)
	if err != nil {
		t.Fatalf("ManagedTargets() error = %v", err)
	}
	if len(targets.Apexes) != 1 || targets.Apexes[0].Apex != "example.net" {
		t.Fatalf("managed apexes = %#v", targets.Apexes)
	}
	if len(targets.ManualHosts) != 1 || targets.ManualHosts[0].Hostname != "www.example.net" || targets.ManualHosts[0].Port != 8443 {
		t.Fatalf("managed manual hosts = %#v", targets.ManualHosts)
	}

	if err := store.DeleteManagedManualHost(ctx, "www.example.net", 8443); err != nil {
		t.Fatalf("DeleteManagedManualHost() error = %v", err)
	}
	if err := store.DeleteManagedApex(ctx, "example.net"); err != nil {
		t.Fatalf("DeleteManagedApex() error = %v", err)
	}
	targets, err = store.ManagedTargets(ctx)
	if err != nil {
		t.Fatalf("ManagedTargets() after delete error = %v", err)
	}
	if len(targets.Apexes) != 0 || len(targets.ManualHosts) != 0 {
		t.Fatalf("managed targets after delete = %#v", targets)
	}
}
