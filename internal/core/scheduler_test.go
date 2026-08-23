package core

import (
	"context"
	"testing"
	"time"
)

func TestSchedulerRunsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan struct{}, 1)
	scheduler := Scheduler{
		Interval: time.Hour,
		RunOnce: func(context.Context) error {
			calls <- struct{}{}
			cancel()
			return nil
		},
	}

	if err := scheduler.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
}

func TestSchedulerRejectsInvalidConfig(t *testing.T) {
	if err := (Scheduler{}).Run(context.Background()); err == nil {
		t.Fatal("Run() error = nil, want error")
	}
}
