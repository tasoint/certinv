package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/tasoint/certinv/internal/config"
	"github.com/tasoint/certinv/internal/core"
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
	_, err = core.Run(context.Background(), cfg, os.Stdout)
	return err
}

func usageError() error {
	return fmt.Errorf("usage: certinv scan --config config.yaml")
}
