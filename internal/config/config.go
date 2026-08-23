package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"
)

const (
	DefaultCrtNameEndpoint  = "https://crt.name/v1/search"
	DefaultProbeConcurrency = 5
	DefaultConnectTimeout   = 5 * time.Second
	DefaultHandshakeTimeout = 5 * time.Second
	DefaultRetireAfterDays  = 30
	DefaultWarnRatio        = 0.25
	DefaultWarnFloorDays    = 3
	DefaultAlertRatio       = 0.10
	DefaultAlertFloorDays   = 1
	DefaultStorageDriver    = "sqlite"
	DefaultStorageDSN       = "./certinv.db"
	DefaultScheduleInterval = 6 * time.Hour
	DefaultExporterListen   = ":9101"
	DefaultManualHostPort   = 443
	DefaultDiscoveryCrtName = "crtname"
	DefaultDiscoveryManual  = "manual"
	DefaultDiscoveryZone    = "zone"
)

type Config struct {
	Apexes      []string     `yaml:"apexes"`
	ManualHosts []ManualHost `yaml:"manual_hosts"`
	Discovery   Discovery    `yaml:"discovery"`
	Probe       Probe        `yaml:"probe"`
	Thresholds  Thresholds   `yaml:"thresholds"`
	Storage     Storage      `yaml:"storage"`
	Schedule    Schedule     `yaml:"schedule"`
	Notifiers   []Notifier   `yaml:"notifiers"`
	Exporter    Exporter     `yaml:"exporter"`
}

type ManualHost struct {
	Hostname string `yaml:"hostname"`
	Port     int    `yaml:"port"`
}

type Discovery struct {
	Sources []string      `yaml:"sources"`
	CrtName CrtNameSource `yaml:"crtname"`
	Zone    ZoneSource    `yaml:"zone"`
}

type CrtNameSource struct {
	Endpoint string `yaml:"endpoint"`
}

type ZoneSource struct {
	Files []string `yaml:"files"`
}

type Probe struct {
	Concurrency      int           `yaml:"concurrency"`
	ConnectTimeout   time.Duration `yaml:"connect_timeout"`
	HandshakeTimeout time.Duration `yaml:"handshake_timeout"`
	RetireAfterDays  int           `yaml:"retire_after_days"`
}

type Thresholds struct {
	Warn  Threshold `yaml:"warn"`
	Alert Threshold `yaml:"alert"`
}

type Threshold struct {
	Ratio     float64 `yaml:"ratio"`
	FloorDays int     `yaml:"floor_days"`
}

type Storage struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

type Schedule struct {
	Interval time.Duration `yaml:"interval"`
}

type Notifier struct {
	Type          string   `yaml:"type"`
	WebhookURLEnv string   `yaml:"webhook_url_env"`
	URL           string   `yaml:"url"`
	Events        []string `yaml:"events"`
}

type Exporter struct {
	Listen    string       `yaml:"listen"`
	BasicAuth ExporterAuth `yaml:"basic_auth"`
}

type ExporterAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func Load(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("config path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := defaultConfig()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func defaultConfig() Config {
	return Config{
		Discovery: Discovery{
			Sources: []string{DefaultDiscoveryCrtName, DefaultDiscoveryManual},
			CrtName: CrtNameSource{
				Endpoint: DefaultCrtNameEndpoint,
			},
		},
		Probe: Probe{
			Concurrency:      DefaultProbeConcurrency,
			ConnectTimeout:   DefaultConnectTimeout,
			HandshakeTimeout: DefaultHandshakeTimeout,
			RetireAfterDays:  DefaultRetireAfterDays,
		},
		Thresholds: Thresholds{
			Warn: Threshold{
				Ratio:     DefaultWarnRatio,
				FloorDays: DefaultWarnFloorDays,
			},
			Alert: Threshold{
				Ratio:     DefaultAlertRatio,
				FloorDays: DefaultAlertFloorDays,
			},
		},
		Storage: Storage{
			Driver: DefaultStorageDriver,
			DSN:    DefaultStorageDSN,
		},
		Schedule: Schedule{
			Interval: DefaultScheduleInterval,
		},
		Exporter: Exporter{
			Listen: DefaultExporterListen,
		},
	}
}

func (c *Config) normalize() {
	for i := range c.Apexes {
		c.Apexes[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.Apexes[i])), ".")
	}
	for i := range c.ManualHosts {
		c.ManualHosts[i].Hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.ManualHosts[i].Hostname)), ".")
		if c.ManualHosts[i].Port == 0 {
			c.ManualHosts[i].Port = DefaultManualHostPort
		}
	}
}

func (c Config) Validate() error {
	if len(c.Apexes) == 0 {
		return errors.New("at least one apex is required")
	}

	apexSet := make(map[string]struct{}, len(c.Apexes))
	for _, apex := range c.Apexes {
		if err := validateApex(apex); err != nil {
			return err
		}
		if _, ok := apexSet[apex]; ok {
			return fmt.Errorf("duplicate apex %q", apex)
		}
		apexSet[apex] = struct{}{}
	}

	for _, source := range c.Discovery.Sources {
		switch source {
		case DefaultDiscoveryCrtName, DefaultDiscoveryManual, DefaultDiscoveryZone:
		default:
			return fmt.Errorf("unsupported discovery source %q", source)
		}
	}
	if slices.Contains(c.Discovery.Sources, DefaultDiscoveryCrtName) && strings.TrimSpace(c.Discovery.CrtName.Endpoint) == "" {
		return errors.New("discovery.crtname.endpoint is required")
	}
	if slices.Contains(c.Discovery.Sources, DefaultDiscoveryZone) && len(c.Discovery.Zone.Files) == 0 {
		return errors.New("discovery.zone.files is required when zone source is enabled")
	}

	for _, host := range c.ManualHosts {
		if err := validateManualHost(host, apexSet); err != nil {
			return err
		}
	}

	if c.Probe.Concurrency <= 0 {
		return errors.New("probe.concurrency must be positive")
	}
	if c.Probe.ConnectTimeout <= 0 {
		return errors.New("probe.connect_timeout must be positive")
	}
	if c.Probe.HandshakeTimeout <= 0 {
		return errors.New("probe.handshake_timeout must be positive")
	}
	if c.Probe.RetireAfterDays <= 0 {
		return errors.New("probe.retire_after_days must be positive")
	}
	if err := validateThreshold("thresholds.warn", c.Thresholds.Warn); err != nil {
		return err
	}
	if err := validateThreshold("thresholds.alert", c.Thresholds.Alert); err != nil {
		return err
	}
	if c.Storage.Driver != DefaultStorageDriver {
		return fmt.Errorf("unsupported storage driver %q", c.Storage.Driver)
	}
	if strings.TrimSpace(c.Storage.DSN) == "" {
		return errors.New("storage.dsn is required")
	}
	if c.Schedule.Interval <= 0 {
		return errors.New("schedule.interval must be positive")
	}
	if strings.TrimSpace(c.Exporter.Listen) == "" {
		return errors.New("exporter.listen is required")
	}
	if strings.TrimSpace(c.Exporter.BasicAuth.Username) == "" && strings.TrimSpace(c.Exporter.BasicAuth.Password) != "" {
		return errors.New("exporter.basic_auth.username is required when password is set")
	}
	if strings.TrimSpace(c.Exporter.BasicAuth.Username) != "" && strings.TrimSpace(c.Exporter.BasicAuth.Password) == "" {
		return errors.New("exporter.basic_auth.password is required when username is set")
	}

	return nil
}

func validateApex(apex string) error {
	if apex == "" {
		return errors.New("apex must not be empty")
	}
	if net.ParseIP(apex) != nil {
		return fmt.Errorf("apex %q must be a domain name", apex)
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(apex)
	if err != nil {
		return fmt.Errorf("apex %q is not a registrable domain: %w", apex, err)
	}
	if etld1 != apex {
		return fmt.Errorf("apex %q must be eTLD+1, got %q", apex, etld1)
	}
	return nil
}

func validateManualHost(host ManualHost, apexSet map[string]struct{}) error {
	if host.Hostname == "" {
		return errors.New("manual host hostname is required")
	}
	if net.ParseIP(host.Hostname) != nil {
		return fmt.Errorf("manual host %q must be a domain name", host.Hostname)
	}
	if host.Port < 1 || host.Port > 65535 {
		return fmt.Errorf("manual host %q has invalid port %d", host.Hostname, host.Port)
	}
	for apex := range apexSet {
		if host.Hostname == apex || strings.HasSuffix(host.Hostname, "."+apex) {
			return nil
		}
	}
	return fmt.Errorf("manual host %q is outside configured apexes", host.Hostname)
}

func validateThreshold(name string, threshold Threshold) error {
	if threshold.Ratio <= 0 || threshold.Ratio > 1 {
		return fmt.Errorf("%s.ratio must be greater than 0 and at most 1", name)
	}
	if threshold.FloorDays < 0 {
		return fmt.Errorf("%s.floor_days must not be negative", name)
	}
	return nil
}
