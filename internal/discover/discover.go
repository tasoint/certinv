package discover

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	SourceCrtName = "crtname"
	SourceManual  = "manual"
	SourceZone    = "zone"
	DefaultPort   = 443
)

type Host struct {
	Hostname  string
	Port      int
	Apex      string
	Source    string
	FirstSeen *time.Time
}

type Source interface {
	Name() string
	Discover(ctx context.Context, apexes []string) ([]Host, error)
}

func NormalizeHostname(hostname string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
}

func WithinApex(hostname, apex string) bool {
	hostname = NormalizeHostname(hostname)
	apex = NormalizeHostname(apex)
	return hostname == apex || strings.HasSuffix(hostname, "."+apex)
}

func ApexFor(hostname string, apexes []string) (string, bool) {
	for _, apex := range apexes {
		if WithinApex(hostname, apex) {
			return NormalizeHostname(apex), true
		}
	}
	return "", false
}

func Merge(hostSets ...[]Host) []Host {
	seen := map[string]Host{}
	for _, hosts := range hostSets {
		for _, host := range hosts {
			host.Hostname = NormalizeHostname(host.Hostname)
			if host.Port == 0 {
				host.Port = DefaultPort
			}
			key := fmt.Sprintf("%s:%d", host.Hostname, host.Port)
			if _, ok := seen[key]; !ok {
				seen[key] = host
				continue
			}
			existing := seen[key]
			if existing.Source != host.Source {
				existing.Source = existing.Source + "," + host.Source
			}
			seen[key] = existing
		}
	}

	hosts := make([]Host, 0, len(seen))
	for _, host := range seen {
		hosts = append(hosts, host)
	}
	return hosts
}
