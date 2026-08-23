package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tasoint/certinv/internal/config"
	"github.com/tasoint/certinv/internal/core"
	"github.com/tasoint/certinv/internal/exporter"
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
	uiHandler, err := ui.New(db)
	if err != nil {
		return err
	}
	runner, err := core.NewRunner(cfg, db, os.Stdout, logger)
	if err != nil {
		return err
	}
	runner.Recorder = exp

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mux := http.NewServeMux()
	uiHandler.Register(mux)
	mux.Handle("/metrics", exp.Handler())
	server := &http.Server{
		Addr:              cfg.Exporter.Listen,
		Handler:           mux,
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
				_, err := runner.Run(ctx)
				return err
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

func usageError() error {
	return fmt.Errorf("usage: certinv scan --config config.yaml | certinv serve --config config.yaml")
}
