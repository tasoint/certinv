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
	"github.com/tasoint/certinv/internal/evaluate"
	"github.com/tasoint/certinv/internal/notify"
	"github.com/tasoint/certinv/internal/probe"
	"github.com/tasoint/certinv/internal/resolve"
	"github.com/tasoint/certinv/internal/store"
	sqlitestore "github.com/tasoint/certinv/internal/store/sqlite"
)

type Summary struct {
	Discovered   int
	Resolved     int
	Probed       int
	Events       int
	Notified     int
	NotifyFailed int
	Failed       int
}

type Runner struct {
	Config    *config.Config
	Sources   []discover.Source
	Resolver  resolve.Resolver
	Prober    probe.Prober
	Store     store.Store
	Notifiers []notify.Notifier
	Now       func() time.Time
	Logger    *slog.Logger
	Out       io.Writer
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
	notifiers, err := notify.FromConfig(cfg.Notifiers)
	if err != nil {
		return Summary{}, err
	}

	runner := Runner{
		Config:    cfg,
		Sources:   sources,
		Resolver:  resolve.NewNetResolver(nil),
		Prober:    probe.NewTLSProber(cfg.Probe.ConnectTimeout, cfg.Probe.HandshakeTimeout),
		Store:     db,
		Notifiers: notifiers,
		Now:       time.Now,
		Logger:    slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Out:       out,
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
	summary := Summary{}
	notified, notifyFailed, err := r.retryPendingEvents(ctx, now)
	if err != nil {
		return summary, err
	}
	summary.Notified += notified
	summary.NotifyFailed += notifyFailed

	hosts, err := r.discover(ctx)
	if err != nil {
		return Summary{}, err
	}
	summary.Discovered = len(hosts)

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
		if result.evented {
			summary.Events++
		}
		if result.notified {
			summary.Notified++
		}
		if result.notifyFailed {
			summary.NotifyFailed++
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

	previousState, err := r.Store.GetCertificateState(ctx, hostID, probeResult.Certificate.Fingerprint)
	if err != nil {
		return hostResult{host: host, resolved: true, probed: true, err: err}
	}
	evaluation := evaluate.Certificate(probeResult.Certificate, r.Config.Thresholds, now, previousState, hostID)
	if err := r.Store.SetCertificateState(ctx, hostID, probeResult.Certificate.Fingerprint, evaluation.State, now); err != nil {
		return hostResult{host: host, resolved: true, probed: true, err: err}
	}

	result := hostResult{host: host, resolved: true, probed: true}
	if evaluation.Event != nil {
		result.evented = true
		eventID, err := r.Store.RecordEvent(ctx, *evaluation.Event, now)
		if err != nil {
			return hostResult{host: host, resolved: true, probed: true, err: err}
		}
		notified, notifyFailed := r.notifyEvent(ctx, eventID, *evaluation.Event, now)
		result.notified = notified
		result.notifyFailed = notifyFailed
	}

	fmt.Fprintf(r.Out, "%s:%d %s state=%s not_after=%s issuer=%q host_match=%t chain_complete=%t\n",
		host.Hostname,
		host.Port,
		probeResult.Certificate.Fingerprint,
		evaluation.State,
		probeResult.Certificate.NotAfter.Format(time.RFC3339),
		probeResult.Certificate.IssuerCN,
		probeResult.Certificate.HostnameMatch,
		probeResult.Certificate.ChainComplete,
	)
	return result
}

func (r Runner) notifyEvent(ctx context.Context, eventID int64, event evaluate.Event, now time.Time) (bool, bool) {
	handled := false
	for _, notifier := range r.Notifiers {
		if !notifier.Handles(event.Kind) {
			continue
		}
		handled = true
		if err := notifier.Notify(ctx, event); err != nil {
			if r.Logger != nil {
				r.Logger.WarnContext(ctx, "notification failed", "notifier", notifier.Name(), "event", event.Kind, "fingerprint", event.Fingerprint, "error", err)
			}
			return false, true
		}
	}
	if err := r.Store.MarkEventNotified(ctx, eventID, now); err != nil {
		if r.Logger != nil {
			r.Logger.WarnContext(ctx, "mark event notified failed", "event_id", eventID, "error", err)
		}
		return false, true
	}
	return handled, false
}

func (r Runner) retryPendingEvents(ctx context.Context, now time.Time) (int, int, error) {
	pending, err := r.Store.PendingEvents(ctx)
	if err != nil {
		return 0, 0, err
	}
	notified := 0
	failed := 0
	for _, storedEvent := range pending {
		sent, notifyFailed := r.notifyEvent(ctx, storedEvent.ID, storedEvent.Event, now)
		if sent {
			notified++
		}
		if notifyFailed {
			failed++
		}
	}
	return notified, failed, nil
}

func printSummary(out io.Writer, summary Summary) {
	fmt.Fprintf(out, "summary discovered=%d resolved=%d probed=%d events=%d notified=%d notify_failed=%d failed=%d\n",
		summary.Discovered,
		summary.Resolved,
		summary.Probed,
		summary.Events,
		summary.Notified,
		summary.NotifyFailed,
		summary.Failed,
	)
}

type hostResult struct {
	host         discover.Host
	resolved     bool
	probed       bool
	evented      bool
	notified     bool
	notifyFailed bool
	err          error
}
