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
	"github.com/tasoint/certinv/internal/discover/zonefile"
	"github.com/tasoint/certinv/internal/evaluate"
	"github.com/tasoint/certinv/internal/notify"
	"github.com/tasoint/certinv/internal/probe"
	"github.com/tasoint/certinv/internal/report"
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
	LikelyAuto   int
	LikelyManual int
	UnknownAuto  int
}

type Runner struct {
	Config          *config.Config
	Sources         []discover.Source
	Resolver        resolve.Resolver
	Prober          probe.Prober
	Store           store.Store
	Notifiers       []notify.Notifier
	Recorder        ScanRecorder
	Now             func() time.Time
	Logger          *slog.Logger
	Out             io.Writer
	CrtNameOverride *bool
}

type ScanRecorder interface {
	RecordScan(summary Summary, duration time.Duration, success bool, occurredAt time.Time)
}

func Run(ctx context.Context, cfg *config.Config, out io.Writer) (Summary, error) {
	db, err := sqlitestore.Open(ctx, cfg.Storage.DSN)
	if err != nil {
		return Summary{}, err
	}
	defer db.Close()

	runner, err := NewRunner(cfg, db, out, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return Summary{}, err
	}
	return runner.Run(ctx)
}

func NewRunner(cfg *config.Config, st store.Store, out io.Writer, logger *slog.Logger) (Runner, error) {
	notifiers, err := notify.FromConfig(cfg.Notifiers)
	if err != nil {
		return Runner{}, err
	}

	return Runner{
		Config:    cfg,
		Resolver:  resolve.NewNetResolver(nil),
		Prober:    probe.NewTLSProber(cfg.Probe.ConnectTimeout, cfg.Probe.HandshakeTimeout, cfg.Probe.HTTPCheck),
		Store:     st,
		Notifiers: notifiers,
		Now:       time.Now,
		Logger:    logger,
		Out:       out,
	}, nil
}

func (r Runner) Run(ctx context.Context) (summary Summary, err error) {
	return r.run(ctx)
}

type RunOptions struct {
	CrtNameEnabled *bool
}

func (r Runner) RunWithOptions(ctx context.Context, options RunOptions) (Summary, error) {
	r.CrtNameOverride = options.CrtNameEnabled
	return r.run(ctx)
}

func (r Runner) run(ctx context.Context) (summary Summary, err error) {
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
	startedAt := now
	defer func() {
		if r.Recorder != nil {
			r.Recorder.RecordScan(summary, r.Now().Sub(startedAt), err == nil, r.Now())
		}
	}()

	effectiveApexes, err := r.effectiveApexes(ctx)
	if err != nil {
		return Summary{}, err
	}
	for _, apex := range effectiveApexes {
		if err := r.Store.UpsertApex(ctx, apex, now); err != nil {
			return Summary{}, err
		}
	}
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
		if result.likelyAuto {
			summary.LikelyAuto++
		}
		if result.likelyManual {
			summary.LikelyManual++
		}
		if result.unknownAuto {
			summary.UnknownAuto++
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
	apexes, err := r.effectiveApexes(ctx)
	if err != nil {
		return nil, err
	}
	sources, err := r.effectiveSources(ctx)
	if err != nil {
		return nil, err
	}
	for _, source := range sources {
		hosts, err := source.Discover(ctx, apexes)
		if err != nil {
			return nil, fmt.Errorf("discover via %s: %w", source.Name(), err)
		}
		groups = append(groups, hosts)
	}
	for _, source := range r.Sources {
		hosts, err := source.Discover(ctx, apexes)
		if err != nil {
			return nil, fmt.Errorf("discover via %s: %w", source.Name(), err)
		}
		groups = append(groups, hosts)
	}
	manualHosts, err := r.effectiveManualHosts(ctx, apexes)
	if err != nil {
		return nil, err
	}
	if slices.Contains(r.Config.Discovery.Sources, discover.SourceManual) || len(manualHosts) > 0 {
		hosts, err := manual.New(manualHosts).Discover(ctx, apexes)
		if err != nil {
			return nil, fmt.Errorf("discover via %s: %w", discover.SourceManual, err)
		}
		groups = append(groups, hosts)
	}
	hosts := discover.Merge(groups...)
	suppressed, err := r.Store.SuppressedHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("load suppressed hosts: %w", err)
	}
	suppressedKeys := make(map[string]struct{}, len(suppressed))
	for _, host := range suppressed {
		suppressedKeys[fmt.Sprintf("%s:%d", discover.NormalizeHostname(host.Hostname), host.Port)] = struct{}{}
	}
	filtered := hosts[:0]
	for _, host := range hosts {
		key := fmt.Sprintf("%s:%d", discover.NormalizeHostname(host.Hostname), host.Port)
		if _, ok := suppressedKeys[key]; !ok {
			filtered = append(filtered, host)
		}
	}
	return filtered, nil
}

func (r Runner) effectiveSources(ctx context.Context) ([]discover.Source, error) {
	managed, err := r.Store.ManagedDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	var sources []discover.Source
	crtNameEnabled := slices.Contains(r.Config.Discovery.Sources, discover.SourceCrtName)
	crtNameEndpoint := r.Config.Discovery.CrtName.Endpoint
	if managed.CrtNameSet {
		crtNameEnabled = managed.CrtNameEnabled
		if managed.CrtNameEndpoint != "" {
			crtNameEndpoint = managed.CrtNameEndpoint
		}
		if r.CrtNameOverride != nil {
			crtNameEnabled = *r.CrtNameOverride
		}
	}
	if crtNameEnabled {
		sources = append(sources, crtname.New(crtNameEndpoint))
	}
	zoneFiles := append([]string{}, r.Config.Discovery.Zone.Files...)
	for _, file := range managed.ZoneFiles {
		zoneFiles = append(zoneFiles, file.Path)
	}
	if slices.Contains(r.Config.Discovery.Sources, discover.SourceZone) || len(managed.ZoneFiles) > 0 {
		sources = append(sources, zonefile.New(zoneFiles))
	}
	return sources, nil
}

func (r Runner) effectiveApexes(ctx context.Context) ([]string, error) {
	apexes := append([]string{}, r.Config.Apexes...)
	managed, err := r.Store.ManagedTargets(ctx)
	if err != nil {
		return nil, err
	}
	for _, apex := range managed.Apexes {
		apexes = append(apexes, apex.Apex)
	}
	return uniqueStrings(apexes), nil
}

func (r Runner) effectiveManualHosts(ctx context.Context, apexes []string) ([]config.ManualHost, error) {
	hosts := append([]config.ManualHost{}, r.Config.ManualHosts...)
	managed, err := r.Store.ManagedTargets(ctx)
	if err != nil {
		return nil, err
	}
	for _, host := range managed.ManualHosts {
		if _, ok := discover.ApexFor(host.Hostname, apexes); ok {
			hosts = append(hosts, config.ManualHost{Hostname: host.Hostname, Port: host.Port})
		}
	}
	return hosts, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var result []string
	for _, value := range values {
		value = discover.NormalizeHostname(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
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
	previousCertificate, err := r.Store.LatestHostCertificate(ctx, hostID)
	if err != nil {
		return hostResult{host: host, resolved: true, err: err}
	}
	if err := r.Store.UpsertCertificate(ctx, probeResult.Certificate, now); err != nil {
		return hostResult{host: host, resolved: true, err: err}
	}
	if err := r.Store.LinkHostCertificate(ctx, hostID, probeResult.Certificate.Fingerprint, probeResult.Certificate.ChainComplete, probeResult.Certificate.HostnameMatch, now); err != nil {
		return hostResult{host: host, resolved: true, err: err}
	}
	if err := r.Store.SetHTTPStatus(ctx, hostID, probeResult.Certificate.Fingerprint, probeResult.HTTPStatus); err != nil {
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
	automation := report.EstimateAutomation(probeResult.Certificate)
	switch automation.Class {
	case report.AutomationLikelyAuto:
		result.likelyAuto = true
	case report.AutomationLikelyManual:
		result.likelyManual = true
	default:
		result.unknownAuto = true
	}
	event := evaluation.Event
	if previousCertificate.Fingerprint != "" &&
		previousCertificate.Fingerprint != probeResult.Certificate.Fingerprint &&
		probeResult.Certificate.NotAfter.After(previousCertificate.NotAfter) {
		event = &evaluate.Event{
			Kind:        evaluate.EventRenewed,
			Fingerprint: probeResult.Certificate.Fingerprint,
			HostID:      hostID,
			Detail:      "certificate fingerprint changed and not_after increased",
		}
	}
	if event != nil {
		result.evented = true
		eventID, err := r.Store.RecordEvent(ctx, *event, now)
		if err != nil {
			return hostResult{host: host, resolved: true, probed: true, err: err}
		}
		notified, notifyFailed := r.notifyEvent(ctx, eventID, *event, now)
		result.notified = notified
		result.notifyFailed = notifyFailed
	}

	fmt.Fprintf(r.Out, "%s:%d %s state=%s automation=%s not_after=%s issuer=%q host_match=%t chain_complete=%t\n",
		host.Hostname,
		host.Port,
		probeResult.Certificate.Fingerprint,
		evaluation.State,
		automation.Class,
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
	fmt.Fprintf(out, "summary discovered=%d resolved=%d probed=%d events=%d notified=%d notify_failed=%d failed=%d automation_likely_auto=%d automation_likely_manual=%d automation_unknown=%d\n",
		summary.Discovered,
		summary.Resolved,
		summary.Probed,
		summary.Events,
		summary.Notified,
		summary.NotifyFailed,
		summary.Failed,
		summary.LikelyAuto,
		summary.LikelyManual,
		summary.UnknownAuto,
	)
}

type hostResult struct {
	host         discover.Host
	resolved     bool
	probed       bool
	evented      bool
	notified     bool
	notifyFailed bool
	likelyAuto   bool
	likelyManual bool
	unknownAuto  bool
	err          error
}
