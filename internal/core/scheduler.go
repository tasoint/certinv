package core

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

type Scheduler struct {
	Interval time.Duration
	RunOnce  func(context.Context) error
	Logger   *slog.Logger
}

func (s Scheduler) Run(ctx context.Context) error {
	if s.Interval <= 0 {
		return fmt.Errorf("schedule interval must be positive")
	}
	if s.RunOnce == nil {
		return fmt.Errorf("run function is required")
	}

	s.run(ctx)
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.run(ctx)
		}
	}
}

func (s Scheduler) run(ctx context.Context) {
	if err := s.RunOnce(ctx); err != nil && s.Logger != nil {
		s.Logger.WarnContext(ctx, "scheduled scan failed", "error", err)
	}
}
