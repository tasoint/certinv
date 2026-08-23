package core

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	certmeta "github.com/tasoint/certinv/internal/cert"
	"github.com/tasoint/certinv/internal/config"
	"github.com/tasoint/certinv/internal/discover"
	"github.com/tasoint/certinv/internal/evaluate"
	"github.com/tasoint/certinv/internal/notify"
	"github.com/tasoint/certinv/internal/probe"
	"github.com/tasoint/certinv/internal/resolve"
	sqlitestore "github.com/tasoint/certinv/internal/store/sqlite"
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
			IssuerCN:      "YR1",
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
	if summary.Events != 1 {
		t.Fatalf("summary.Events = %d, want 1", summary.Events)
	}
	if summary.LikelyAuto != 1 {
		t.Fatalf("summary.LikelyAuto = %d, want 1", summary.LikelyAuto)
	}
	if got := out.String(); !strings.Contains(got, "automation=likely_auto") {
		t.Fatalf("output = %q, want automation=likely_auto", got)
	}
}

func TestRunnerNotifiesOnlyOnStateTransition(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitestore.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	notifier := &fakeNotifier{}
	runner := Runner{
		Config: &config.Config{
			Apexes: []string{"example.com"},
			Probe:  config.Probe{Concurrency: 1},
			Thresholds: config.Thresholds{
				Warn:  config.Threshold{Ratio: 0.25, FloorDays: 3},
				Alert: config.Threshold{Ratio: 0.10, FloorDays: 1},
			},
		},
		Sources: []discover.Source{fakeSource{hosts: []discover.Host{
			{Hostname: "www.example.com", Port: 443, Apex: "example.com", Source: discover.SourceManual},
		}}},
		Resolver: fakeResolver{},
		Prober: fakeProber{certificate: certmeta.Metadata{
			Fingerprint:   "abc123",
			IssuerCN:      "Test CA",
			NotBefore:     now.Add(-90 * 24 * time.Hour),
			NotAfter:      now.Add(10 * 24 * time.Hour),
			LifetimeDays:  100,
			ChainComplete: true,
			HostnameMatch: true,
		}},
		Store:     db,
		Notifiers: []notify.Notifier{notifier},
		Now:       func() time.Time { return now },
		Out:       &bytes.Buffer{},
	}

	first, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
	if first.Events != 1 || first.Notified != 1 {
		t.Fatalf("first summary events/notified = %d/%d, want 1/1", first.Events, first.Notified)
	}
	second, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if second.Events != 0 || second.Notified != 0 {
		t.Fatalf("second summary events/notified = %d/%d, want 0/0", second.Events, second.Notified)
	}
	if len(notifier.events) != 1 {
		t.Fatalf("notifications = %d, want 1", len(notifier.events))
	}
}

func TestRunnerEmitsRenewedWhenFingerprintChangesAndExpiryExtends(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitestore.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	notifier := &fakeNotifier{}
	runner := Runner{
		Config: &config.Config{
			Apexes: []string{"example.com"},
			Probe:  config.Probe{Concurrency: 1},
			Thresholds: config.Thresholds{
				Warn:  config.Threshold{Ratio: 0.25, FloorDays: 3},
				Alert: config.Threshold{Ratio: 0.10, FloorDays: 1},
			},
		},
		Sources: []discover.Source{fakeSource{hosts: []discover.Host{
			{Hostname: "www.example.com", Port: 443, Apex: "example.com", Source: discover.SourceManual},
		}}},
		Resolver:  fakeResolver{},
		Prober:    &sequenceProber{certificates: []certmeta.Metadata{testMetadata(now, "old", 20), testMetadata(now, "new", 90)}},
		Store:     db,
		Notifiers: []notify.Notifier{notifier},
		Now:       func() time.Time { return now },
		Out:       &bytes.Buffer{},
	}

	if _, err := runner.Run(ctx); err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
	if _, err := runner.Run(ctx); err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if len(notifier.events) != 2 {
		t.Fatalf("notifications = %d, want 2", len(notifier.events))
	}
	if got := notifier.events[1].Kind; got != evaluate.EventRenewed {
		t.Fatalf("second event kind = %q, want %q", got, evaluate.EventRenewed)
	}
}

func TestRunnerIncludesManagedManualHosts(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitestore.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	if err := db.AddManagedApex(ctx, "example.net", now); err != nil {
		t.Fatalf("AddManagedApex() error = %v", err)
	}
	if err := db.AddManagedManualHost(ctx, discover.Host{
		Hostname: "www.example.net",
		Port:     443,
		Apex:     "example.net",
		Source:   "managed",
	}, now); err != nil {
		t.Fatalf("AddManagedManualHost() error = %v", err)
	}

	runner := Runner{
		Config: &config.Config{
			Apexes: []string{"example.com"},
			Probe:  config.Probe{Concurrency: 1},
		},
		Resolver: fakeResolver{},
		Prober: fakeProber{certificate: certmeta.Metadata{
			Fingerprint:   "managed123",
			IssuerCN:      "Test CA",
			NotBefore:     now.Add(-24 * time.Hour),
			NotAfter:      now.Add(47 * 24 * time.Hour),
			LifetimeDays:  48,
			ChainComplete: true,
			HostnameMatch: true,
		}},
		Store: db,
		Now:   func() time.Time { return now },
		Out:   &bytes.Buffer{},
	}
	summary, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if summary.Probed != 1 {
		t.Fatalf("summary.Probed = %d, want 1", summary.Probed)
	}
}

func TestRunnerAppliesManagedDiscoverySettings(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitestore.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	defer db.Close()

	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	if err := db.SaveManagedCrtName(ctx, false, "https://crt.example/search", now); err != nil {
		t.Fatalf("SaveManagedCrtName() error = %v", err)
	}
	if err := db.AddManagedZoneFile(ctx, "/tmp/example.zone", now); err != nil {
		t.Fatalf("AddManagedZoneFile() error = %v", err)
	}
	runner := Runner{
		Config: &config.Config{
			Discovery: config.Discovery{
				Sources: []string{discover.SourceCrtName},
				CrtName: config.CrtNameSource{
					Endpoint: "https://crt.name/v1/search",
				},
			},
		},
		Store: db,
	}
	sources, err := runner.effectiveSources(ctx)
	if err != nil {
		t.Fatalf("effectiveSources() error = %v", err)
	}
	if len(sources) != 1 || sources[0].Name() != discover.SourceZone {
		t.Fatalf("sources = %#v, want managed zone only", sources)
	}
}

func TestRunnerFiltersCrtNameApexes(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitestore.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	if err := db.SaveManagedCrtName(ctx, true, "https://crt.example/search", now); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveManagedApexCrtName(ctx, "disabled.example.com", false, now); err != nil {
		t.Fatal(err)
	}
	runner := Runner{Config: &config.Config{
		Apexes: []string{"enabled.example.com", "disabled.example.com"},
		Discovery: config.Discovery{
			Sources: []string{discover.SourceCrtName},
			CrtName: config.CrtNameSource{Endpoint: "https://crt.name/v1/search"},
		},
	}, Store: db}
	sources, err := runner.effectiveSources(ctx)
	if err != nil {
		t.Fatalf("effectiveSources() error = %v", err)
	}
	if len(sources) != 1 || sources[0].Name() != discover.SourceCrtName {
		t.Fatalf("sources = %#v, want crtname", sources)
	}
	scoped, ok := sources[0].(scopedSource)
	if !ok {
		t.Fatalf("source type = %T, want scopedSource", sources[0])
	}
	if len(scoped.apexes) != 1 || scoped.apexes[0] != "enabled.example.com" {
		t.Fatalf("scoped apexes = %#v", scoped.apexes)
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

type sequenceProber struct {
	certificates []certmeta.Metadata
	index        int
}

func (p *sequenceProber) Probe(_ context.Context, target probe.Target) (probe.Result, error) {
	certificate := p.certificates[p.index]
	if p.index < len(p.certificates)-1 {
		p.index++
	}
	return probe.Result{Target: target, Certificate: certificate, ProbedAt: time.Now()}, nil
}

type fakeNotifier struct {
	events []evaluate.Event
}

func (n *fakeNotifier) Name() string {
	return "fake"
}

func (n *fakeNotifier) Handles(string) bool {
	return true
}

func (n *fakeNotifier) Notify(_ context.Context, event evaluate.Event) error {
	n.events = append(n.events, event)
	return nil
}

func testMetadata(now time.Time, fingerprint string, remainingDays int) certmeta.Metadata {
	return certmeta.Metadata{
		Fingerprint:   fingerprint,
		IssuerCN:      "Test CA",
		NotBefore:     now.Add(-10 * 24 * time.Hour),
		NotAfter:      now.Add(time.Duration(remainingDays) * 24 * time.Hour),
		LifetimeDays:  100,
		ChainComplete: true,
		HostnameMatch: true,
	}
}

func TestRunnerExcludesSuppressedHostsFromDiscovery(t *testing.T) {
	ctx := context.Background()
	db, err := sqlitestore.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	if err := db.SuppressHost(ctx, "www.example.com", 443, now); err != nil {
		t.Fatalf("SuppressHost() error = %v", err)
	}
	runner := Runner{
		Config:  &config.Config{Apexes: []string{"example.com"}},
		Sources: []discover.Source{fakeSource{hosts: []discover.Host{{Hostname: "www.example.com", Port: 443, Apex: "example.com"}, {Hostname: "api.example.com", Port: 443, Apex: "example.com"}}}},
		Store:   db,
	}
	hosts, err := runner.discover(ctx)
	if err != nil {
		t.Fatalf("discover() error = %v", err)
	}
	if len(hosts) != 1 || hosts[0].Hostname != "api.example.com" {
		t.Fatalf("discovered hosts = %#v, want only api.example.com", hosts)
	}
}
