package evaluate

import (
	"time"

	certmeta "github.com/tasoint/certinv/internal/cert"
	"github.com/tasoint/certinv/internal/config"
)

const (
	StateHealthy       = "healthy"
	StateWarn          = "warn"
	StateAlert         = "alert"
	StateExpired       = "expired"
	StateMisconfigured = "misconfigured"

	EventDiscovered    = "discovered"
	EventWarn          = "warn"
	EventAlert         = "alert"
	EventExpired       = "expired"
	EventMisconfigured = "misconfigured"
)

type Event struct {
	Kind        string
	Fingerprint string
	HostID      int64
	Detail      string
}

type Result struct {
	State         string
	Remaining     time.Duration
	WarnWindow    time.Duration
	AlertWindow   time.Duration
	Event         *Event
	Misconfigured bool
}

func Certificate(cert certmeta.Metadata, thresholds config.Thresholds, now time.Time, previousState string, hostID int64) Result {
	remaining := cert.NotAfter.Sub(now)
	warnWindow := ThresholdWindow(cert.LifetimeDays, thresholds.Warn)
	alertWindow := ThresholdWindow(cert.LifetimeDays, thresholds.Alert)

	state := StateHealthy
	detail := ""
	switch {
	case remaining <= 0:
		state = StateExpired
		detail = "certificate is expired"
	case !cert.ChainComplete || !cert.HostnameMatch || cert.IsSelfSigned:
		state = StateMisconfigured
		detail = "certificate has TLS configuration issues"
	case remaining <= alertWindow:
		state = StateAlert
		detail = "certificate crossed alert threshold"
	case remaining <= warnWindow:
		state = StateWarn
		detail = "certificate crossed warn threshold"
	}

	result := Result{
		State:         state,
		Remaining:     remaining,
		WarnWindow:    warnWindow,
		AlertWindow:   alertWindow,
		Misconfigured: state == StateMisconfigured,
	}
	if previousState == "" {
		result.Event = &Event{
			Kind:        EventDiscovered,
			Fingerprint: cert.Fingerprint,
			HostID:      hostID,
			Detail:      "certificate discovered",
		}
		return result
	}
	if previousState != state && state != StateHealthy {
		result.Event = &Event{
			Kind:        state,
			Fingerprint: cert.Fingerprint,
			HostID:      hostID,
			Detail:      detail,
		}
	}
	return result
}

func ThresholdWindow(lifetimeDays int, threshold config.Threshold) time.Duration {
	ratioWindow := time.Duration(float64(time.Duration(lifetimeDays)*24*time.Hour) * threshold.Ratio)
	floorWindow := time.Duration(threshold.FloorDays) * 24 * time.Hour
	if ratioWindow < floorWindow {
		return floorWindow
	}
	return ratioWindow
}
