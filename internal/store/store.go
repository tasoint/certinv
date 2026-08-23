package store

import (
	"context"
	"time"

	certmeta "github.com/tasoint/certinv/internal/cert"
	"github.com/tasoint/certinv/internal/discover"
	"github.com/tasoint/certinv/internal/evaluate"
)

type Store interface {
	UpsertApex(ctx context.Context, apex string, now time.Time) error
	UpsertHost(ctx context.Context, host discover.Host, status string, now time.Time) (int64, error)
	MarkHostResolved(ctx context.Context, hostname string, port int, now time.Time) error
	MarkHostProbed(ctx context.Context, hostname string, port int, now time.Time) error
	LatestHostCertificate(ctx context.Context, hostID int64) (HostCertificate, error)
	UpsertCertificate(ctx context.Context, cert certmeta.Metadata, now time.Time) error
	LinkHostCertificate(ctx context.Context, hostID int64, fingerprint string, chainComplete, hostnameMatch bool, now time.Time) error
	GetCertificateState(ctx context.Context, hostID int64, fingerprint string) (string, error)
	SetCertificateState(ctx context.Context, hostID int64, fingerprint, state string, now time.Time) error
	RecordEvent(ctx context.Context, event evaluate.Event, now time.Time) (int64, error)
	PendingEvents(ctx context.Context) ([]StoredEvent, error)
	MarkEventNotified(ctx context.Context, eventID int64, now time.Time) error
	MetricsSnapshot(ctx context.Context) (MetricsSnapshot, error)
	InventorySnapshot(ctx context.Context) (InventorySnapshot, error)
	ManagedTargets(ctx context.Context) (ManagedTargets, error)
	AddManagedApex(ctx context.Context, apex string, now time.Time) error
	DeleteManagedApex(ctx context.Context, apex string) error
	AddManagedManualHost(ctx context.Context, host discover.Host, now time.Time) error
	DeleteManagedManualHost(ctx context.Context, hostname string, port int) error
	Close() error
}

type StoredEvent struct {
	ID int64
	evaluate.Event
}

type HostCertificate struct {
	Fingerprint string
	NotAfter    time.Time
}

type MetricsSnapshot struct {
	Certificates []CertificateMetric
	Hosts        []HostMetric
}

type CertificateMetric struct {
	Fingerprint  string
	Issuer       string
	CommonName   string
	NotBefore    time.Time
	NotAfter     time.Time
	LifetimeDays int
}

type HostMetric struct {
	Hostname  string
	Port      int
	Reachable bool
}

type InventorySnapshot struct {
	Rows []InventoryRow
}

type ManagedTargets struct {
	Apexes      []ManagedApex
	ManualHosts []ManagedManualHost
}

type ManagedApex struct {
	Apex    string
	Source  string
	AddedAt string
}

type ManagedManualHost struct {
	Hostname string
	Port     int
	Apex     string
	Source   string
	AddedAt  string
}

type InventoryRow struct {
	Hostname       string
	Port           int
	Apex           string
	Source         string
	HostStatus     string
	FirstSeenAt    string
	LastResolvedAt string
	LastProbedAt   string
	Fingerprint    string
	CertState      string
	SubjectCN      string
	IssuerCN       string
	IssuerOrg      string
	NotBefore      string
	NotAfter       string
	LifetimeDays   int
	SANNames       string
	ObservedAt     string
	ChainComplete  bool
	HostnameMatch  bool
	LastSeenAt     string
}
