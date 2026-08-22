package manual

import (
	"context"
	"fmt"

	"github.com/tasoint/certinv/internal/config"
	"github.com/tasoint/certinv/internal/discover"
)

type Source struct {
	hosts []config.ManualHost
}

func New(hosts []config.ManualHost) *Source {
	return &Source{hosts: hosts}
}

func (s *Source) Name() string {
	return discover.SourceManual
}

func (s *Source) Discover(_ context.Context, apexes []string) ([]discover.Host, error) {
	hosts := make([]discover.Host, 0, len(s.hosts))
	for _, manualHost := range s.hosts {
		hostname := discover.NormalizeHostname(manualHost.Hostname)
		apex, ok := discover.ApexFor(hostname, apexes)
		if !ok {
			return nil, fmt.Errorf("manual host %q is outside configured apexes", hostname)
		}
		port := manualHost.Port
		if port == 0 {
			port = discover.DefaultPort
		}
		hosts = append(hosts, discover.Host{
			Hostname: hostname,
			Port:     port,
			Apex:     apex,
			Source:   discover.SourceManual,
		})
	}
	return hosts, nil
}
