package crtname

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tasoint/certinv/internal/discover"
)

const UserAgent = "certinv/0.1 (+https://github.com/tasoint/certinv)"

type Source struct {
	endpoint string
	client   *http.Client
}

type Option func(*Source)

func WithHTTPClient(client *http.Client) Option {
	return func(s *Source) {
		s.client = client
	}
}

func New(endpoint string, opts ...Option) *Source {
	s := &Source{
		endpoint: strings.TrimRight(endpoint, "/"),
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Source) Name() string {
	return discover.SourceCrtName
}

func (s *Source) Discover(ctx context.Context, apexes []string) ([]discover.Host, error) {
	var all []discover.Host
	for _, apex := range apexes {
		hosts, err := s.discoverApex(ctx, discover.NormalizeHostname(apex))
		if err != nil {
			return nil, err
		}
		all = append(all, hosts...)
	}
	return discover.Merge(all), nil
}

func (s *Source) discoverApex(ctx context.Context, apex string) ([]discover.Host, error) {
	endpointURL, err := url.Parse(s.endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse crtname endpoint: %w", err)
	}
	q := endpointURL.Query()
	q.Set("apex", apex)
	q.Set("format", "json")
	q.Set("dates", "1")
	endpointURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build crtname request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crtname request for %s: %w", apex, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("crtname request for %s returned status %d", apex, resp.StatusCode)
	}

	var rows []record
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("decode crtname response for %s: %w", apex, err)
	}

	hosts := make([]discover.Host, 0, len(rows))
	for _, row := range rows {
		firstSeen := row.firstSeenTime()
		for _, name := range row.hostnames() {
			if !discover.WithinApex(name, apex) {
				continue
			}
			hosts = append(hosts, discover.Host{
				Hostname:  discover.NormalizeHostname(name),
				Port:      discover.DefaultPort,
				Apex:      apex,
				Source:    discover.SourceCrtName,
				FirstSeen: firstSeen,
			})
		}
	}
	return discover.Merge(hosts), nil
}

type record struct {
	Subdomain string `json:"subdomain"`
	NameValue string `json:"name_value"`
	FirstSeen string `json:"first_seen"`
	NotBefore string `json:"not_before"`
}

func (r record) hostnames() []string {
	var names []string
	for _, field := range []string{r.Subdomain, r.NameValue} {
		for _, name := range strings.FieldsFunc(field, func(r rune) bool {
			return r == '\n' || r == ',' || r == ' ' || r == '\t'
		}) {
			name = strings.TrimPrefix(discover.NormalizeHostname(name), "*.")
			if name != "" {
				names = append(names, name)
			}
		}
	}
	return names
}

func (r record) firstSeenTime() *time.Time {
	for _, raw := range []string{r.FirstSeen, r.NotBefore} {
		if raw == "" {
			continue
		}
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
			t, err := time.Parse(layout, raw)
			if err == nil {
				return &t
			}
		}
	}
	return nil
}
