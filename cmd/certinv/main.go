package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tasoint/certinv/internal/config"
	"github.com/tasoint/certinv/internal/core"
	"github.com/tasoint/certinv/internal/discover"
	"github.com/tasoint/certinv/internal/exporter"
	"github.com/tasoint/certinv/internal/probe"
	sqlitestore "github.com/tasoint/certinv/internal/store/sqlite"
	"github.com/tasoint/certinv/internal/ui"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "certinv: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "serve":
		return runServe(args[1:])
	case "check":
		return runCheck(args[1:])
	default:
		return usageError()
	}
}

func runScan(args []string) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "config.yaml", "path to config file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("scan does not accept positional arguments")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	_, err = core.Run(ctx, cfg, os.Stdout)
	return err
}

func runServe(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "config.yaml", "path to config file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("serve does not accept positional arguments")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	db, err := sqlitestore.Open(context.Background(), cfg.Storage.DSN)
	if err != nil {
		return err
	}
	defer db.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	exp := exporter.New(db)
	runner, err := core.NewRunner(cfg, db, os.Stdout, logger)
	if err != nil {
		return err
	}
	runner.Recorder = exp

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	scans := newSerialScanRunner(ctx, func(ctx context.Context) error {
		_, err := runner.Run(ctx)
		return err
	}, logger)
	uiHandler, err := ui.New(db, ui.WithScanTrigger(scans), ui.WithConfigTargets(cfg.Apexes, cfg.ManualHosts), ui.WithSourceConfig(cfg.Discovery))
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	uiHandler.Register(mux)
	mux.Handle("/metrics", exp.Handler())
	handler := withOptionalBasicAuth(mux, cfg.Exporter.BasicAuth)
	server := &http.Server{
		Addr:              cfg.Exporter.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errs := make(chan error, 2)
	go func() {
		logger.InfoContext(ctx, "metrics exporter listening", "listen", cfg.Exporter.Listen)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errs <- fmt.Errorf("serve metrics: %w", err)
		}
	}()
	go func() {
		scheduler := core.Scheduler{
			Interval: cfg.Schedule.Interval,
			RunOnce: func(ctx context.Context) error {
				return scans.Run(ctx)
			},
			Logger: logger,
		}
		errs <- scheduler.Run(ctx)
	}()

	select {
	case err := <-errs:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown metrics server: %w", err)
		}
	}
	return nil
}

type serialScanRunner struct {
	mu      sync.Mutex
	running bool
	ctx     context.Context
	run     func(context.Context) error
	logger  *slog.Logger
}

func newSerialScanRunner(ctx context.Context, run func(context.Context) error, logger *slog.Logger) *serialScanRunner {
	return &serialScanRunner{
		ctx:    ctx,
		run:    run,
		logger: logger,
	}
}

func (r *serialScanRunner) Run(ctx context.Context) error {
	if !r.start() {
		if r.logger != nil {
			r.logger.InfoContext(ctx, "scan skipped because another scan is running")
		}
		return nil
	}
	defer r.finish()
	return r.run(ctx)
}

func (r *serialScanRunner) TriggerScan() bool {
	if !r.start() {
		return false
	}
	go func() {
		defer r.finish()
		if err := r.run(r.ctx); err != nil && r.logger != nil {
			r.logger.ErrorContext(r.ctx, "manual scan failed", "error", err)
		}
	}()
	return true
}

func (r *serialScanRunner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

func (r *serialScanRunner) start() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return false
	}
	r.running = true
	return true
}

func (r *serialScanRunner) finish() {
	r.mu.Lock()
	r.running = false
	r.mu.Unlock()
}

func withOptionalBasicAuth(next http.Handler, auth config.ExporterAuth) http.Handler {
	if auth.Username == "" && auth.Password == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		usernameOK := subtle.ConstantTimeCompare([]byte(username), []byte(auth.Username)) == 1
		passwordOK := subtle.ConstantTimeCompare([]byte(password), []byte(auth.Password)) == 1
		if !ok || !usernameOK || !passwordOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="certinv"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func runCheck(args []string) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "config.yaml", "path to config file")
	port := flags.Int("port", 443, "TLS port to check")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("check requires exactly one FQDN")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	hostname, apex, err := scopedCheckTarget(flags.Arg(0), cfg.Apexes)
	if err != nil {
		return err
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	prober := probe.NewTLSProber(cfg.Probe.ConnectTimeout, cfg.Probe.HandshakeTimeout, cfg.Probe.HTTPCheck)
	result, err := prober.Probe(ctx, probe.Target{Hostname: hostname, Port: *port})
	if err != nil {
		return err
	}
	printCheckResult(os.Stdout, apex, result)
	return nil
}

func scopedCheckTarget(rawHostname string, apexes []string) (string, string, error) {
	hostname := discover.NormalizeHostname(rawHostname)
	if hostname == "" {
		return "", "", fmt.Errorf("check target FQDN is required")
	}
	if strings.Contains(hostname, ":") {
		return "", "", fmt.Errorf("check target must be an FQDN without port; use --port for non-443 TLS")
	}
	apex, ok := discover.ApexFor(hostname, apexes)
	if !ok {
		return "", "", fmt.Errorf("check target %q is outside configured apexes", hostname)
	}
	return hostname, apex, nil
}

func printCheckResult(out io.Writer, apex string, result probe.Result) {
	cert := result.Certificate
	fmt.Fprintf(out, "host: %s\n", result.Target.Hostname)
	fmt.Fprintf(out, "port: %d\n", result.Target.Port)
	fmt.Fprintf(out, "apex: %s\n", apex)
	fmt.Fprintf(out, "fingerprint_sha256: %s\n", cert.Fingerprint)
	fmt.Fprintf(out, "subject_cn: %s\n", cert.SubjectCN)
	fmt.Fprintf(out, "issuer_cn: %s\n", cert.IssuerCN)
	fmt.Fprintf(out, "issuer_org: %s\n", cert.IssuerOrg)
	fmt.Fprintf(out, "not_before: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Fprintf(out, "not_after: %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(out, "lifetime_days: %d\n", cert.LifetimeDays)
	fmt.Fprintf(out, "signature_algorithm: %s\n", cert.SigAlgorithm)
	fmt.Fprintf(out, "key_algorithm: %s\n", cert.KeyAlgorithm)
	fmt.Fprintf(out, "key_bits: %d\n", cert.KeyBits)
	fmt.Fprintf(out, "chain_complete: %t\n", cert.ChainComplete)
	fmt.Fprintf(out, "hostname_match: %t\n", cert.HostnameMatch)
	fmt.Fprintf(out, "self_signed: %t\n", cert.IsSelfSigned)
	fmt.Fprintf(out, "san_names:\n")
	for _, name := range cert.SANNames {
		fmt.Fprintf(out, "  - %s\n", name)
	}
	fmt.Fprintf(out, "probed_at: %s\n", result.ProbedAt.Format(time.RFC3339))
}

func usageError() error {
	return fmt.Errorf("usage: certinv scan --config config.yaml | certinv serve --config config.yaml | certinv check --config config.yaml [--port 443] <fqdn>")
}
