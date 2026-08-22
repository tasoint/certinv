package evaluate

import (
	"testing"
	"time"

	certmeta "github.com/tasoint/certinv/internal/cert"
	"github.com/tasoint/certinv/internal/config"
)

func TestThresholdWindow(t *testing.T) {
	tests := []struct {
		name         string
		lifetimeDays int
		threshold    config.Threshold
		want         time.Duration
	}{
		{name: "warn 398", lifetimeDays: 398, threshold: config.Threshold{Ratio: 0.25, FloorDays: 3}, want: 99*24*time.Hour + 12*time.Hour},
		{name: "alert 398", lifetimeDays: 398, threshold: config.Threshold{Ratio: 0.10, FloorDays: 1}, want: 39*24*time.Hour + 19*time.Hour + 12*time.Minute},
		{name: "warn 200", lifetimeDays: 200, threshold: config.Threshold{Ratio: 0.25, FloorDays: 3}, want: 50 * 24 * time.Hour},
		{name: "alert 200", lifetimeDays: 200, threshold: config.Threshold{Ratio: 0.10, FloorDays: 1}, want: 20 * 24 * time.Hour},
		{name: "warn 100", lifetimeDays: 100, threshold: config.Threshold{Ratio: 0.25, FloorDays: 3}, want: 25 * 24 * time.Hour},
		{name: "alert 100", lifetimeDays: 100, threshold: config.Threshold{Ratio: 0.10, FloorDays: 1}, want: 10 * 24 * time.Hour},
		{name: "warn 47", lifetimeDays: 47, threshold: config.Threshold{Ratio: 0.25, FloorDays: 3}, want: 11*24*time.Hour + 18*time.Hour},
		{name: "alert 47", lifetimeDays: 47, threshold: config.Threshold{Ratio: 0.10, FloorDays: 1}, want: 4*24*time.Hour + 16*time.Hour + 48*time.Minute},
		{name: "floor", lifetimeDays: 1, threshold: config.Threshold{Ratio: 0.10, FloorDays: 3}, want: 3 * 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ThresholdWindow(tt.lifetimeDays, tt.threshold)
			if got != tt.want {
				t.Fatalf("ThresholdWindow() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertificateThresholdBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	thresholds := config.Thresholds{
		Warn:  config.Threshold{Ratio: 0.25, FloorDays: 3},
		Alert: config.Threshold{Ratio: 0.10, FloorDays: 1},
	}

	tests := []struct {
		name         string
		lifetimeDays int
		remaining    time.Duration
		wantState    string
	}{
		{name: "398 days warns at 99 days", lifetimeDays: 398, remaining: 99 * 24 * time.Hour, wantState: StateWarn},
		{name: "398 days does not warn at 100 days", lifetimeDays: 398, remaining: 100 * 24 * time.Hour, wantState: StateHealthy},
		{name: "47 days warns before 12 days", lifetimeDays: 47, remaining: 11*24*time.Hour + 17*time.Hour, wantState: StateWarn},
		{name: "47 days does not warn at 12 days", lifetimeDays: 47, remaining: 12 * 24 * time.Hour, wantState: StateHealthy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := certificateWithRemaining(now, tt.lifetimeDays, tt.remaining, true, true, false)
			result := Certificate(cert, thresholds, now, StateHealthy, 7)
			if result.State != tt.wantState {
				t.Fatalf("State = %q, want %q", result.State, tt.wantState)
			}
		})
	}
}

func TestCertificateStateAndTransitionEvent(t *testing.T) {
	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	thresholds := config.Thresholds{
		Warn:  config.Threshold{Ratio: 0.25, FloorDays: 3},
		Alert: config.Threshold{Ratio: 0.10, FloorDays: 1},
	}

	tests := []struct {
		name          string
		cert          certmeta.Metadata
		previousState string
		wantState     string
		wantEventKind string
	}{
		{
			name:          "new certificate discovered",
			cert:          certificate(now, 100, 80, true, true, false),
			previousState: "",
			wantState:     StateHealthy,
			wantEventKind: EventDiscovered,
		},
		{
			name:          "warn threshold crossed",
			cert:          certificate(now, 100, 20, true, true, false),
			previousState: StateHealthy,
			wantState:     StateWarn,
			wantEventKind: EventWarn,
		},
		{
			name:          "alert threshold crossed",
			cert:          certificate(now, 100, 5, true, true, false),
			previousState: StateWarn,
			wantState:     StateAlert,
			wantEventKind: EventAlert,
		},
		{
			name:          "expired",
			cert:          certificate(now, 100, -1, true, true, false),
			previousState: StateAlert,
			wantState:     StateExpired,
			wantEventKind: EventExpired,
		},
		{
			name:          "misconfigured before threshold",
			cert:          certificate(now, 100, 80, false, true, false),
			previousState: StateHealthy,
			wantState:     StateMisconfigured,
			wantEventKind: EventMisconfigured,
		},
		{
			name:          "no duplicate event without transition",
			cert:          certificate(now, 100, 20, true, true, false),
			previousState: StateWarn,
			wantState:     StateWarn,
			wantEventKind: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Certificate(tt.cert, thresholds, now, tt.previousState, 7)
			if result.State != tt.wantState {
				t.Fatalf("State = %q, want %q", result.State, tt.wantState)
			}
			if tt.wantEventKind == "" {
				if result.Event != nil {
					t.Fatalf("Event = %#v, want nil", result.Event)
				}
				return
			}
			if result.Event == nil {
				t.Fatalf("Event = nil, want %q", tt.wantEventKind)
			}
			if result.Event.Kind != tt.wantEventKind {
				t.Fatalf("Event.Kind = %q, want %q", result.Event.Kind, tt.wantEventKind)
			}
		})
	}
}

func certificate(now time.Time, lifetimeDays, remainingDays int, chainComplete, hostnameMatch, selfSigned bool) certmeta.Metadata {
	return certificateWithRemaining(now, lifetimeDays, time.Duration(remainingDays)*24*time.Hour, chainComplete, hostnameMatch, selfSigned)
}

func certificateWithRemaining(now time.Time, lifetimeDays int, remaining time.Duration, chainComplete, hostnameMatch, selfSigned bool) certmeta.Metadata {
	return certmeta.Metadata{
		Fingerprint:   "abc123",
		NotBefore:     now.Add(remaining - time.Duration(lifetimeDays)*24*time.Hour),
		NotAfter:      now.Add(remaining),
		LifetimeDays:  lifetimeDays,
		ChainComplete: chainComplete,
		HostnameMatch: hostnameMatch,
		IsSelfSigned:  selfSigned,
	}
}
