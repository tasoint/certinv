package core

import (
	"bytes"
	"context"
	"time"

	certmeta "github.com/tasoint/certinv/internal/cert"
	"github.com/tasoint/certinv/internal/config"
	"github.com/tasoint/certinv/internal/discover"
	"github.com/tasoint/certinv/internal/probe"
	"github.com/tasoint/certinv/internal/resolve"
	sqlitestore "github.com/tasoint/certinv/internal/store/sqlite"
	"testing"
)

func TestRunnerRunsPipeline(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitestore.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	runner := Runner{
		Config: &config.Config{
			Apexes: []string{"example.com"},
			Probe:  config.Probe{Concurrency: 2},
		},
		Sources: []discover.Source{fakeSource{hosts: []discover.Host{
			{Hostname: "www.example.com", Port: 443, Apex: "example.com", Source: discover.SourceManual},
		}}},
		Resolver: fakeResolver{},
		Prober: fakeProber{certificate: certmeta.Metadata{
			Fingerprint:   "abc123",
			IssuerCN:      "Test CA",
			NotBefore:     now.Add(-24 * time.Hour),
			NotAfter:      now.Add(47 * 24 * time.Hour),
			LifetimeDays:  48,
			ChainComplete: true,
			HostnameMatch: true,
		}},
		Store: db,
		Now:   func() time.Time { return now },
		Out:   &out,
	}

	summary, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if summary.Probed != 1 {
		t.Fatalf("summary.Probed = %d, want 1", summary.Probed)
	}
	if got := out.String(); got == "" {
		t.Fatal("output is empty")
	}
}

type fakeSource struct {
	hosts []discover.Host
}

func (s fakeSource) Name() string {
	return "fake"
}

func (s fakeSource) Discover(context.Context, []string) ([]discover.Host, error) {
	return s.hosts, nil
}

type fakeResolver struct{}

func (fakeResolver) Resolve(_ context.Context, hostname string) (resolve.Result, error) {
	return resolve.Result{Hostname: hostname, Addresses: []string{"127.0.0.1"}, Resolved: true}, nil
}

type fakeProber struct {
	certificate certmeta.Metadata
}

func (p fakeProber) Probe(_ context.Context, target probe.Target) (probe.Result, error) {
	return probe.Result{Target: target, Certificate: p.certificate, ProbedAt: time.Now()}, nil
}
