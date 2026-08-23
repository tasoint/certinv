package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	certmeta "github.com/tasoint/certinv/internal/cert"
	"github.com/tasoint/certinv/internal/discover"
	"github.com/tasoint/certinv/internal/evaluate"
	"github.com/tasoint/certinv/internal/store"
)

type Store struct {
	db *sql.DB
	mu sync.Mutex
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) UpsertApex(ctx context.Context, apex string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
INSERT INTO apexes (apex, enabled, added_at)
VALUES (?, 1, ?)
ON CONFLICT(apex) DO UPDATE SET enabled = 1
`, apex, formatTime(now))
	if err != nil {
		return fmt.Errorf("upsert apex %q: %w", apex, err)
	}
	return nil
}

func (s *Store) UpsertHost(ctx context.Context, host discover.Host, status string, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	firstSeen := now
	if host.FirstSeen != nil {
		firstSeen = *host.FirstSeen
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO hosts (hostname, port, apex, source, first_seen_at, status)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(hostname, port) DO UPDATE SET
  apex = excluded.apex,
  source = excluded.source,
  status = excluded.status
`, host.Hostname, host.Port, host.Apex, host.Source, formatTime(firstSeen), status)
	if err != nil {
		return 0, fmt.Errorf("upsert host %s:%d: %w", host.Hostname, host.Port, err)
	}

	var id int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM hosts WHERE hostname = ? AND port = ?`, host.Hostname, host.Port).Scan(&id); err != nil {
		return 0, fmt.Errorf("select host %s:%d: %w", host.Hostname, host.Port, err)
	}
	return id, nil
}

func (s *Store) MarkHostResolved(ctx context.Context, hostname string, port int, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
UPDATE hosts SET last_resolved_at = ?, status = 'active'
WHERE hostname = ? AND port = ?
`, formatTime(now), hostname, port)
	if err != nil {
		return fmt.Errorf("mark host resolved %s:%d: %w", hostname, port, err)
	}
	return nil
}

func (s *Store) MarkHostProbed(ctx context.Context, hostname string, port int, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
UPDATE hosts SET last_probed_at = ?
WHERE hostname = ? AND port = ?
`, formatTime(now), hostname, port)
	if err != nil {
		return fmt.Errorf("mark host probed %s:%d: %w", hostname, port, err)
	}
	return nil
}

func (s *Store) LatestHostCertificate(ctx context.Context, hostID int64) (store.HostCertificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var cert store.HostCertificate
	var notAfter string
	err := s.db.QueryRowContext(ctx, `
SELECT hc.fingerprint, c.not_after
FROM host_certificates hc
JOIN certificates c ON c.fingerprint = hc.fingerprint
WHERE hc.host_id = ?
ORDER BY hc.observed_at DESC, hc.rowid DESC
LIMIT 1
`, hostID).Scan(&cert.Fingerprint, &notAfter)
	if err == sql.ErrNoRows {
		return store.HostCertificate{}, nil
	}
	if err != nil {
		return store.HostCertificate{}, fmt.Errorf("latest host certificate host=%d: %w", hostID, err)
	}
	parsed, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		return store.HostCertificate{}, fmt.Errorf("parse latest host certificate not_after: %w", err)
	}
	cert.NotAfter = parsed
	return cert, nil
}

func (s *Store) UpsertCertificate(ctx context.Context, cert certmeta.Metadata, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sanNames, err := json.Marshal(cert.SANNames)
	if err != nil {
		return fmt.Errorf("marshal SAN names for %s: %w", cert.Fingerprint, err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO certificates (
  fingerprint, subject_cn, issuer_cn, issuer_org, not_before, not_after,
  lifetime_days, sig_algorithm, key_algorithm, key_bits, is_self_signed,
  san_names, first_seen_at, last_seen_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(fingerprint) DO UPDATE SET
  subject_cn = excluded.subject_cn,
  issuer_cn = excluded.issuer_cn,
  issuer_org = excluded.issuer_org,
  not_before = excluded.not_before,
  not_after = excluded.not_after,
  lifetime_days = excluded.lifetime_days,
  sig_algorithm = excluded.sig_algorithm,
  key_algorithm = excluded.key_algorithm,
  key_bits = excluded.key_bits,
  is_self_signed = excluded.is_self_signed,
  san_names = excluded.san_names,
  last_seen_at = excluded.last_seen_at
`, cert.Fingerprint, cert.SubjectCN, cert.IssuerCN, cert.IssuerOrg, formatTime(cert.NotBefore), formatTime(cert.NotAfter),
		cert.LifetimeDays, cert.SigAlgorithm, cert.KeyAlgorithm, cert.KeyBits, boolInt(cert.IsSelfSigned),
		string(sanNames), formatTime(now), formatTime(now))
	if err != nil {
		return fmt.Errorf("upsert certificate %s: %w", cert.Fingerprint, err)
	}
	return nil
}

func (s *Store) LinkHostCertificate(ctx context.Context, hostID int64, fingerprint string, chainComplete, hostnameMatch bool, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
INSERT INTO host_certificates (host_id, fingerprint, observed_at, chain_complete, hostname_match)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(host_id, fingerprint) DO UPDATE SET
  observed_at = excluded.observed_at,
  chain_complete = excluded.chain_complete,
  hostname_match = excluded.hostname_match
`, hostID, fingerprint, formatTime(now), boolInt(chainComplete), boolInt(hostnameMatch))
	if err != nil {
		return fmt.Errorf("link host %d to certificate %s: %w", hostID, fingerprint, err)
	}
	return nil
}

func (s *Store) GetCertificateState(ctx context.Context, hostID int64, fingerprint string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var state string
	err := s.db.QueryRowContext(ctx, `
SELECT state FROM certificate_states
WHERE host_id = ? AND fingerprint = ?
`, hostID, fingerprint).Scan(&state)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get certificate state host=%d fingerprint=%s: %w", hostID, fingerprint, err)
	}
	return state, nil
}

func (s *Store) SetCertificateState(ctx context.Context, hostID int64, fingerprint, state string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
INSERT INTO certificate_states (host_id, fingerprint, state, updated_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(host_id, fingerprint) DO UPDATE SET
  state = excluded.state,
  updated_at = excluded.updated_at
`, hostID, fingerprint, state, formatTime(now))
	if err != nil {
		return fmt.Errorf("set certificate state host=%d fingerprint=%s: %w", hostID, fingerprint, err)
	}
	return nil
}

func (s *Store) RecordEvent(ctx context.Context, event evaluate.Event, now time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, `
INSERT INTO events (kind, fingerprint, host_id, occurred_at, detail)
VALUES (?, ?, ?, ?, ?)
`, event.Kind, event.Fingerprint, nullableHostID(event.HostID), formatTime(now), event.Detail)
	if err != nil {
		return 0, fmt.Errorf("record event %q for %s: %w", event.Kind, event.Fingerprint, err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get event id: %w", err)
	}
	return id, nil
}

func (s *Store) PendingEvents(ctx context.Context) ([]store.StoredEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx, `
SELECT id, kind, fingerprint, COALESCE(host_id, 0), COALESCE(detail, '')
FROM events
WHERE notified_at IS NULL
ORDER BY id
`)
	if err != nil {
		return nil, fmt.Errorf("select pending events: %w", err)
	}
	defer rows.Close()

	var events []store.StoredEvent
	for rows.Next() {
		var event store.StoredEvent
		if err := rows.Scan(&event.ID, &event.Kind, &event.Fingerprint, &event.HostID, &event.Detail); err != nil {
			return nil, fmt.Errorf("scan pending event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending events: %w", err)
	}
	return events, nil
}

func (s *Store) MarkEventNotified(ctx context.Context, eventID int64, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
UPDATE events SET notified_at = ?
WHERE id = ?
`, formatTime(now), eventID)
	if err != nil {
		return fmt.Errorf("mark event %d notified: %w", eventID, err)
	}
	return nil
}

func (s *Store) MetricsSnapshot(ctx context.Context) (store.MetricsSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	certificates, err := s.certificateMetrics(ctx)
	if err != nil {
		return store.MetricsSnapshot{}, err
	}
	hosts, err := s.hostMetrics(ctx)
	if err != nil {
		return store.MetricsSnapshot{}, err
	}
	return store.MetricsSnapshot{Certificates: certificates, Hosts: hosts}, nil
}

func (s *Store) InventorySnapshot(ctx context.Context) (store.InventorySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx, `
SELECT
  h.hostname,
  h.port,
  h.apex,
  h.source,
  h.status,
  h.first_seen_at,
  COALESCE(h.last_resolved_at, ''),
  COALESCE(h.last_probed_at, ''),
  COALESCE(c.fingerprint, ''),
  COALESCE(cs.state, ''),
  COALESCE(c.subject_cn, ''),
  COALESCE(c.issuer_cn, ''),
  COALESCE(c.issuer_org, ''),
  COALESCE(c.not_before, ''),
  COALESCE(c.not_after, ''),
  COALESCE(c.lifetime_days, 0),
  COALESCE(c.san_names, '[]'),
  COALESCE(hc.observed_at, ''),
  COALESCE(hc.chain_complete, 0),
  COALESCE(hc.hostname_match, 0),
  COALESCE(c.last_seen_at, '')
FROM hosts h
LEFT JOIN host_certificates hc ON hc.host_id = h.id
LEFT JOIN certificates c ON c.fingerprint = hc.fingerprint
LEFT JOIN certificate_states cs ON cs.host_id = h.id AND cs.fingerprint = c.fingerprint
ORDER BY h.hostname, h.port, c.not_after
`)
	if err != nil {
		return store.InventorySnapshot{}, fmt.Errorf("select inventory snapshot: %w", err)
	}
	defer rows.Close()

	var snapshot store.InventorySnapshot
	for rows.Next() {
		var row store.InventoryRow
		var chainComplete int
		var hostnameMatch int
		if err := rows.Scan(
			&row.Hostname,
			&row.Port,
			&row.Apex,
			&row.Source,
			&row.HostStatus,
			&row.FirstSeenAt,
			&row.LastResolvedAt,
			&row.LastProbedAt,
			&row.Fingerprint,
			&row.CertState,
			&row.SubjectCN,
			&row.IssuerCN,
			&row.IssuerOrg,
			&row.NotBefore,
			&row.NotAfter,
			&row.LifetimeDays,
			&row.SANNames,
			&row.ObservedAt,
			&chainComplete,
			&hostnameMatch,
			&row.LastSeenAt,
		); err != nil {
			return store.InventorySnapshot{}, fmt.Errorf("scan inventory snapshot: %w", err)
		}
		row.ChainComplete = chainComplete == 1
		row.HostnameMatch = hostnameMatch == 1
		snapshot.Rows = append(snapshot.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return store.InventorySnapshot{}, fmt.Errorf("iterate inventory snapshot: %w", err)
	}
	return snapshot, nil
}

func (s *Store) ManagedTargets(ctx context.Context) (store.ManagedTargets, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	apexRows, err := s.db.QueryContext(ctx, `
SELECT apex, added_at
FROM managed_apexes
ORDER BY apex
`)
	if err != nil {
		return store.ManagedTargets{}, fmt.Errorf("select managed apexes: %w", err)
	}
	defer apexRows.Close()

	var targets store.ManagedTargets
	for apexRows.Next() {
		var apex store.ManagedApex
		if err := apexRows.Scan(&apex.Apex, &apex.AddedAt); err != nil {
			return store.ManagedTargets{}, fmt.Errorf("scan managed apex: %w", err)
		}
		apex.Source = "db"
		targets.Apexes = append(targets.Apexes, apex)
	}
	if err := apexRows.Err(); err != nil {
		return store.ManagedTargets{}, fmt.Errorf("iterate managed apexes: %w", err)
	}

	hostRows, err := s.db.QueryContext(ctx, `
SELECT hostname, port, apex, added_at
FROM managed_manual_hosts
ORDER BY hostname, port
`)
	if err != nil {
		return store.ManagedTargets{}, fmt.Errorf("select managed manual hosts: %w", err)
	}
	defer hostRows.Close()

	for hostRows.Next() {
		var host store.ManagedManualHost
		if err := hostRows.Scan(&host.Hostname, &host.Port, &host.Apex, &host.AddedAt); err != nil {
			return store.ManagedTargets{}, fmt.Errorf("scan managed manual host: %w", err)
		}
		host.Source = "db"
		targets.ManualHosts = append(targets.ManualHosts, host)
	}
	if err := hostRows.Err(); err != nil {
		return store.ManagedTargets{}, fmt.Errorf("iterate managed manual hosts: %w", err)
	}
	return targets, nil
}

func (s *Store) AddManagedApex(ctx context.Context, apex string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
INSERT INTO managed_apexes (apex, added_at)
VALUES (?, ?)
ON CONFLICT(apex) DO UPDATE SET added_at = excluded.added_at
`, apex, formatTime(now))
	if err != nil {
		return fmt.Errorf("add managed apex %q: %w", apex, err)
	}
	return nil
}

func (s *Store) DeleteManagedApex(ctx context.Context, apex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `DELETE FROM managed_apexes WHERE apex = ?`, apex)
	if err != nil {
		return fmt.Errorf("delete managed apex %q: %w", apex, err)
	}
	return nil
}

func (s *Store) AddManagedManualHost(ctx context.Context, host discover.Host, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `
INSERT INTO managed_manual_hosts (hostname, port, apex, added_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(hostname, port) DO UPDATE SET
  apex = excluded.apex,
  added_at = excluded.added_at
`, host.Hostname, host.Port, host.Apex, formatTime(now))
	if err != nil {
		return fmt.Errorf("add managed manual host %s:%d: %w", host.Hostname, host.Port, err)
	}
	return nil
}

func (s *Store) DeleteManagedManualHost(ctx context.Context, hostname string, port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, `DELETE FROM managed_manual_hosts WHERE hostname = ? AND port = ?`, hostname, port)
	if err != nil {
		return fmt.Errorf("delete managed manual host %s:%d: %w", hostname, port, err)
	}
	return nil
}

func (s *Store) certificateMetrics(ctx context.Context) ([]store.CertificateMetric, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT fingerprint, COALESCE(issuer_cn, ''), COALESCE(subject_cn, ''), not_before, not_after, lifetime_days
FROM certificates
ORDER BY fingerprint
`)
	if err != nil {
		return nil, fmt.Errorf("select certificate metrics: %w", err)
	}
	defer rows.Close()

	var certificates []store.CertificateMetric
	for rows.Next() {
		var cert store.CertificateMetric
		var notBefore string
		var notAfter string
		if err := rows.Scan(&cert.Fingerprint, &cert.Issuer, &cert.CommonName, &notBefore, &notAfter, &cert.LifetimeDays); err != nil {
			return nil, fmt.Errorf("scan certificate metrics: %w", err)
		}
		parsedNotBefore, err := time.Parse(time.RFC3339, notBefore)
		if err != nil {
			return nil, fmt.Errorf("parse certificate not_before: %w", err)
		}
		parsedNotAfter, err := time.Parse(time.RFC3339, notAfter)
		if err != nil {
			return nil, fmt.Errorf("parse certificate not_after: %w", err)
		}
		cert.NotBefore = parsedNotBefore
		cert.NotAfter = parsedNotAfter
		certificates = append(certificates, cert)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate certificate metrics: %w", err)
	}
	return certificates, nil
}

func (s *Store) hostMetrics(ctx context.Context) ([]store.HostMetric, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT hostname, port, status
FROM hosts
ORDER BY hostname, port
`)
	if err != nil {
		return nil, fmt.Errorf("select host metrics: %w", err)
	}
	defer rows.Close()

	var hosts []store.HostMetric
	for rows.Next() {
		var host store.HostMetric
		var status string
		if err := rows.Scan(&host.Hostname, &host.Port, &status); err != nil {
			return nil, fmt.Errorf("scan host metrics: %w", err)
		}
		host.Reachable = status == "active"
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate host metrics: %w", err)
	}
	return hosts, nil
}

func (s *Store) migrate(ctx context.Context) error {
	for _, statement := range schema {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate sqlite: %w", err)
		}
	}
	return nil
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableHostID(hostID int64) any {
	if hostID == 0 {
		return nil
	}
	return hostID
}

var schema = []string{
	`CREATE TABLE IF NOT EXISTS managed_apexes (
  apex           TEXT PRIMARY KEY,
  added_at       TEXT NOT NULL
)`,
	`CREATE TABLE IF NOT EXISTS managed_manual_hosts (
  hostname        TEXT NOT NULL,
  port            INTEGER NOT NULL DEFAULT 443,
  apex            TEXT NOT NULL,
  added_at        TEXT NOT NULL,
  PRIMARY KEY (hostname, port)
)`,
	`CREATE TABLE IF NOT EXISTS apexes (
  apex           TEXT PRIMARY KEY,
  enabled        INTEGER NOT NULL DEFAULT 1,
  added_at       TEXT NOT NULL
)`,
	`CREATE TABLE IF NOT EXISTS hosts (
  id                INTEGER PRIMARY KEY,
  hostname          TEXT NOT NULL,
  port              INTEGER NOT NULL DEFAULT 443,
  apex              TEXT NOT NULL REFERENCES apexes(apex),
  source            TEXT NOT NULL,
  first_seen_at     TEXT NOT NULL,
  last_resolved_at  TEXT,
  last_probed_at    TEXT,
  status            TEXT NOT NULL,
  UNIQUE(hostname, port)
)`,
	`CREATE TABLE IF NOT EXISTS certificates (
  fingerprint       TEXT PRIMARY KEY,
  subject_cn        TEXT,
  issuer_cn         TEXT,
  issuer_org        TEXT,
  not_before        TEXT NOT NULL,
  not_after         TEXT NOT NULL,
  lifetime_days     INTEGER NOT NULL,
  sig_algorithm     TEXT,
  key_algorithm     TEXT,
  key_bits          INTEGER,
  is_self_signed    INTEGER NOT NULL,
  san_names         TEXT,
  first_seen_at     TEXT NOT NULL,
  last_seen_at      TEXT NOT NULL
)`,
	`CREATE TABLE IF NOT EXISTS host_certificates (
  host_id           INTEGER NOT NULL REFERENCES hosts(id),
  fingerprint       TEXT NOT NULL REFERENCES certificates(fingerprint),
  observed_at       TEXT NOT NULL,
  chain_complete    INTEGER,
  hostname_match    INTEGER,
  PRIMARY KEY (host_id, fingerprint)
)`,
	`CREATE TABLE IF NOT EXISTS certificate_states (
  host_id           INTEGER NOT NULL REFERENCES hosts(id),
  fingerprint       TEXT NOT NULL REFERENCES certificates(fingerprint),
  state             TEXT NOT NULL,
  updated_at        TEXT NOT NULL,
  PRIMARY KEY (host_id, fingerprint)
)`,
	`CREATE TABLE IF NOT EXISTS events (
  id                INTEGER PRIMARY KEY,
  kind              TEXT NOT NULL,
  fingerprint       TEXT,
  host_id           INTEGER,
  occurred_at       TEXT NOT NULL,
  notified_at       TEXT,
  detail            TEXT
)`,
	`CREATE INDEX IF NOT EXISTS idx_hosts_apex ON hosts(apex)`,
	`CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status)`,
	`CREATE INDEX IF NOT EXISTS idx_certs_not_after ON certificates(not_after)`,
	`CREATE INDEX IF NOT EXISTS idx_events_notified ON events(notified_at) WHERE notified_at IS NULL`,
}
