package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadAppliesDefaultsAndNormalizes(t *testing.T) {
	path := writeConfig(t, `
apexes:
  - Example.COM.
manual_hosts:
  - hostname: Mail.Example.COM.
discovery:
  sources: [manual]
storage:
  dsn: ./test.db
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got := cfg.Apexes[0]; got != "example.com" {
		t.Fatalf("apex = %q, want example.com", got)
	}
	if got := cfg.ManualHosts[0].Hostname; got != "mail.example.com" {
		t.Fatalf("manual hostname = %q, want mail.example.com", got)
	}
	if got := cfg.ManualHosts[0].Port; got != 443 {
		t.Fatalf("manual port = %d, want 443", got)
	}
	if got := cfg.Probe.Concurrency; got != DefaultProbeConcurrency {
		t.Fatalf("probe concurrency = %d, want %d", got, DefaultProbeConcurrency)
	}
	if got := cfg.Probe.ConnectTimeout; got != 5*time.Second {
		t.Fatalf("connect timeout = %v, want 5s", got)
	}
}

func TestLoadRejectsNonApexDomain(t *testing.T) {
	path := writeConfig(t, `
apexes:
  - www.example.com
`)

	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil, want error")
	}
}

func TestLoadRejectsManualHostOutsideApex(t *testing.T) {
	path := writeConfig(t, `
apexes:
  - example.com
manual_hosts:
  - hostname: other.example.net
`)

	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil, want error")
	}
}

func TestLoadRejectsUnsupportedSource(t *testing.T) {
	path := writeConfig(t, `
apexes:
  - example.com
discovery:
  sources: [manual, zone]
`)

	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil, want error")
	}
}

func TestLoadAcceptsZoneSource(t *testing.T) {
	path := writeConfig(t, `
apexes:
  - example.com
discovery:
  sources: [zone]
  zone:
    files:
      - ./example.zone
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Discovery.Zone.Files[0]; got != "./example.zone" {
		t.Fatalf("zone file = %q, want ./example.zone", got)
	}
}

func TestLoadAcceptsExporterBasicAuth(t *testing.T) {
	path := writeConfig(t, `
apexes:
  - example.com
exporter:
  listen: :9101
  basic_auth:
    username: operator
    password: secret
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Exporter.BasicAuth.Username; got != "operator" {
		t.Fatalf("basic auth username = %q, want operator", got)
	}
	if got := cfg.Exporter.BasicAuth.Password; got != "secret" {
		t.Fatalf("basic auth password = %q, want secret", got)
	}
}

func TestLoadRejectsPartialExporterBasicAuth(t *testing.T) {
	for name, body := range map[string]string{
		"username only": `
apexes:
  - example.com
exporter:
  basic_auth:
    username: operator
`,
		"password only": `
apexes:
  - example.com
exporter:
  basic_auth:
    password: secret
`,
	} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, body)
			if _, err := Load(path); err == nil {
				t.Fatal("Load() error = nil, want error")
			}
		})
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
