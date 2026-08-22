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
