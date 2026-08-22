package core

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/tasoint/certinv/internal/config"
	"github.com/tasoint/certinv/internal/discover"
	"github.com/tasoint/certinv/internal/discover/crtname"
	"github.com/tasoint/certinv/internal/discover/manual"
	"github.com/tasoint/certinv/internal/probe"
	"github.com/tasoint/certinv/internal/resolve"
	"github.com/tasoint/certinv/internal/store"
	sqlitestore "github.com/tasoint/certinv/internal/store/sqlite"
)

type Summary struct {
	Discovered int
	Resolved   int
	Probed     int
	Failed     int
}

type Runner struct {
	Config   *config.Config
	Sources  []discover.Source
	Resolver resolve.Resolver
	Prober   probe.Prober
	Store    store.Store
	Now      func() time.Time
	Logger   *slog.Logger
	Out      io.Writer
}

func Run(ctx context.Context, cfg *config.Config, out io.Writer) (Summary, error) {
	db, err := sqlitestore.Open(ctx, cfg.Storage.DSN)
	if err != nil {
		return Summary{}, err
	}
	defer db.Close()

	sources := make([]discover.Source, 0, len(cfg.Discovery.Sources))
	if slices.Contains(cfg.Discovery.Sources, discover.SourceCrtName) {
		sources = append(sources, crtname.New(cfg.Discovery.CrtName.Endpoint))
	}
	if slices.Contains(cfg.Discovery.Sources, discover.SourceManual) {
		sources = append(sources, manual.New(cfg.ManualHosts))
	}

	runner := Runner{
		Config:   cfg,
		Sources:  sources,
		Resolver: resolve.NewNetResolver(nil),
		Prober:   probe.NewTLSProber(cfg.Probe.ConnectTimeout, cfg.Probe.HandshakeTimeout),
		Store:    db,
		Now:      time.Now,
		Logger:   slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Out:      out,
	}
	return runner.Run(ctx)
}

func (r Runner) Run(ctx context.Context) (Summary, error) {
	if r.Config == nil {
		return Summary{}, fmt.Errorf("config is required")
	}
	if r.Resolver == nil {
		return Summary{}, fmt.Errorf("resolver is required")
	}
	if r.Prober == nil {
		return Summary{}, fmt.Errorf("prober is required")
	}
	if r.Store == nil {
		return Summary{}, fmt.Errorf("store is required")
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Out == nil {
		r.Out = io.Discard
	}

	now := r.Now()
	for _, apex := range r.Config.Apexes {
		if err := r.Store.UpsertApex(ctx, apex, now); err != nil {
			return Summary{}, err
		}
	}

	hosts, err := r.discover(ctx)
	if err != nil {
		return Summary{}, err
	}
	summary := Summary{Discovered: len(hosts)}

	jobs := make(chan discover.Host)
	results := make(chan hostResult)
	workers := r.Config.Probe.Concurrency
	if workers < 1 {
		workers = 1
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				results <- r.processHost(ctx, host)
			}
		}()
	}
	go func() {
		for _, host := range hosts {
			select {
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				close(results)
				return
			case jobs <- host:
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	for result := range results {
		if result.resolved {
			summary.Resolved++
		}
		if result.probed {
			summary.Probed++
		}
		if result.err != nil {
			summary.Failed++
			if r.Logger != nil {
				r.Logger.WarnContext(ctx, "scan host failed", "host", result.host.Hostname, "port", result.host.Port, "error", result.err)
			}
			continue
		}
	}

	if err := ctx.Err(); err != nil {
		return summary, err
	}
	printSummary(r.Out, summary)
	return summary, nil
}

func (r Runner) discover(ctx context.Context) ([]discover.Host, error) {
	var groups [][]discover.Host
	for _, source := range r.Sources {
		hosts, err := source.Discover(ctx, r.Config.Apexes)
		if err != nil {
			return nil, fmt.Errorf("discover via %s: %w", source.Name(), err)
		}
		groups = append(groups, hosts)
	}
	return discover.Merge(groups...), nil
}

func (r Runner) processHost(ctx context.Context, host discover.Host) hostResult {
	now := r.Now()
	hostID, err := r.Store.UpsertHost(ctx, host, "unresolved", now)
	if err != nil {
		return hostResult{host: host, err: err}
	}

	resolution, err := r.Resolver.Resolve(ctx, host.Hostname)
	if err != nil {
		return hostResult{host: host, err: fmt.Errorf("resolve %s: %w", host.Hostname, err)}
	}
	if !resolution.Resolved {
		return hostResult{host: host}
	}
	if err := r.Store.MarkHostResolved(ctx, host.Hostname, host.Port, now); err != nil {
		return hostResult{host: host, err: err}
	}

	probeResult, err := r.Prober.Probe(ctx, probe.Target{Hostname: host.Hostname, Port: host.Port})
	if err != nil {
		return hostResult{host: host, resolved: true, err: err}
	}
	if err := r.Store.UpsertCertificate(ctx, probeResult.Certificate, now); err != nil {
		return hostResult{host: host, resolved: true, err: err}
	}
	if err := r.Store.LinkHostCertificate(ctx, hostID, probeResult.Certificate.Fingerprint, probeResult.Certificate.ChainComplete, probeResult.Certificate.HostnameMatch, now); err != nil {
		return hostResult{host: host, resolved: true, err: err}
	}
	if err := r.Store.MarkHostProbed(ctx, host.Hostname, host.Port, now); err != nil {
		return hostResult{host: host, resolved: true, err: err}
	}

	fmt.Fprintf(r.Out, "%s:%d %s not_after=%s issuer=%q host_match=%t chain_complete=%t\n",
		host.Hostname,
		host.Port,
		probeResult.Certificate.Fingerprint,
		probeResult.Certificate.NotAfter.Format(time.RFC3339),
		probeResult.Certificate.IssuerCN,
		probeResult.Certificate.HostnameMatch,
		probeResult.Certificate.ChainComplete,
	)
	return hostResult{host: host, resolved: true, probed: true}
}

func printSummary(out io.Writer, summary Summary) {
	fmt.Fprintf(out, "summary discovered=%d resolved=%d probed=%d failed=%d\n",
		summary.Discovered,
		summary.Resolved,
		summary.Probed,
		summary.Failed,
	)
}

type hostResult struct {
	host     discover.Host
	resolved bool
	probed   bool
	err      error
}
