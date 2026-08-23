package exporter

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/tasoint/certinv/internal/core"
	"github.com/tasoint/certinv/internal/store"
)

type Exporter struct {
	store    store.Store
	registry *prometheus.Registry

	mu              sync.Mutex
	lastDuration    float64
	lastSuccessUnix float64
}

func New(store store.Store) *Exporter {
	exporter := &Exporter{
		store:    store,
		registry: prometheus.NewRegistry(),
	}
	exporter.registry.MustRegister(exporter)
	return exporter
}

func (e *Exporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{})
}

func (e *Exporter) RecordScan(_ core.Summary, duration time.Duration, success bool, occurredAt time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.lastDuration = duration.Seconds()
	if success {
		e.lastSuccessUnix = float64(occurredAt.Unix())
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range e.descriptors() {
		ch <- desc
	}
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	snapshot, err := e.store.MetricsSnapshot(ctx)
	if err == nil {
		now := time.Now()
		for _, cert := range snapshot.Certificates {
			labels := []string{cert.Fingerprint, cert.Issuer, cert.CommonName}
			ch <- prometheus.MustNewConstMetric(certNotAfter, prometheus.GaugeValue, float64(cert.NotAfter.Unix()), labels...)
			ch <- prometheus.MustNewConstMetric(certLifetimeDays, prometheus.GaugeValue, float64(cert.LifetimeDays), labels...)
			ch <- prometheus.MustNewConstMetric(certRemainingRatio, prometheus.GaugeValue, remainingRatio(cert, now), labels...)
		}
		for _, host := range snapshot.Hosts {
			value := 0.0
			if host.Reachable {
				value = 1.0
			}
			ch <- prometheus.MustNewConstMetric(hostReachable, prometheus.GaugeValue, value, host.Hostname, strconv.Itoa(host.Port))
		}
	}

	e.mu.Lock()
	lastDuration := e.lastDuration
	lastSuccessUnix := e.lastSuccessUnix
	e.mu.Unlock()
	ch <- prometheus.MustNewConstMetric(scanDuration, prometheus.GaugeValue, lastDuration)
	ch <- prometheus.MustNewConstMetric(scanLastSuccess, prometheus.GaugeValue, lastSuccessUnix)
}

func remainingRatio(cert store.CertificateMetric, now time.Time) float64 {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	if lifetime <= 0 {
		return 0
	}
	remaining := cert.NotAfter.Sub(now)
	if remaining <= 0 {
		return 0
	}
	ratio := remaining.Seconds() / lifetime.Seconds()
	if ratio > 1 {
		return 1
	}
	return ratio
}

func (e *Exporter) descriptors() []*prometheus.Desc {
	return []*prometheus.Desc{
		certNotAfter,
		certLifetimeDays,
		certRemainingRatio,
		hostReachable,
		scanDuration,
		scanLastSuccess,
	}
}

var (
	certNotAfter = prometheus.NewDesc(
		"certinv_cert_not_after_timestamp",
		"TLS certificate notAfter timestamp.",
		[]string{"fingerprint", "issuer", "common_name"},
		nil,
	)
	certLifetimeDays = prometheus.NewDesc(
		"certinv_cert_lifetime_days",
		"TLS certificate lifetime in days.",
		[]string{"fingerprint", "issuer", "common_name"},
		nil,
	)
	certRemainingRatio = prometheus.NewDesc(
		"certinv_cert_remaining_ratio",
		"TLS certificate remaining lifetime ratio.",
		[]string{"fingerprint", "issuer", "common_name"},
		nil,
	)
	hostReachable = prometheus.NewDesc(
		"certinv_host_reachable",
		"Whether a configured host resolved during the latest scan.",
		[]string{"host", "port"},
		nil,
	)
	scanDuration = prometheus.NewDesc(
		"certinv_scan_duration_seconds",
		"Duration of the latest scan.",
		nil,
		nil,
	)
	scanLastSuccess = prometheus.NewDesc(
		"certinv_scan_last_success_timestamp",
		"Unix timestamp of the latest successful scan.",
		nil,
		nil,
	)
)
