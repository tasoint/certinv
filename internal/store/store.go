package store

import (
	"context"
	"time"

	certmeta "github.com/tasoint/certinv/internal/cert"
	"github.com/tasoint/certinv/internal/discover"
)

type Store interface {
	UpsertApex(ctx context.Context, apex string, now time.Time) error
	UpsertHost(ctx context.Context, host discover.Host, status string, now time.Time) (int64, error)
	MarkHostResolved(ctx context.Context, hostname string, port int, now time.Time) error
	MarkHostProbed(ctx context.Context, hostname string, port int, now time.Time) error
	UpsertCertificate(ctx context.Context, cert certmeta.Metadata, now time.Time) error
	LinkHostCertificate(ctx context.Context, hostID int64, fingerprint string, chainComplete, hostnameMatch bool, now time.Time) error
	Close() error
}
