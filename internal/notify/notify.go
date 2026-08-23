package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/tasoint/certinv/internal/config"
	"github.com/tasoint/certinv/internal/evaluate"
)

type Notifier interface {
	Name() string
	Notify(ctx context.Context, event evaluate.Event) error
	Handles(kind string) bool
}

type Option func(*httpNotifier)

func WithHTTPClient(client *http.Client) Option {
	return func(n *httpNotifier) {
		n.client = client
	}
}

func FromConfig(configs []config.Notifier, opts ...Option) ([]Notifier, error) {
	notifiers := make([]Notifier, 0, len(configs))
	for _, cfg := range configs {
		switch cfg.Type {
		case "":
			continue
		case "slack":
			webhookURL := strings.TrimSpace(os.Getenv(cfg.WebhookURLEnv))
			if webhookURL == "" {
				return nil, fmt.Errorf("slack notifier requires environment variable %q", cfg.WebhookURLEnv)
			}
			notifiers = append(notifiers, newHTTPNotifier("slack", webhookURL, cfg.Events, slackPayload, opts...))
		case "webhook":
			if strings.TrimSpace(cfg.URL) == "" {
				return nil, fmt.Errorf("webhook notifier requires url")
			}
			notifiers = append(notifiers, newHTTPNotifier("webhook", cfg.URL, cfg.Events, webhookPayload, opts...))
		default:
			return nil, fmt.Errorf("unsupported notifier type %q", cfg.Type)
		}
	}
	return notifiers, nil
}

type payloadFunc func(e evaluate.Event) (any, error)

type httpNotifier struct {
	name   string
	url    string
	events []string
	client *http.Client
	build  payloadFunc
}

func newHTTPNotifier(name, url string, events []string, build payloadFunc, opts ...Option) *httpNotifier {
	notifier := &httpNotifier{
		name:   name,
		url:    url,
		events: events,
		client: &http.Client{Timeout: 10 * time.Second},
		build:  build,
	}
	for _, opt := range opts {
		opt(notifier)
	}
	return notifier
}

func (n *httpNotifier) Name() string {
	return n.name
}

func (n *httpNotifier) Handles(kind string) bool {
	return len(n.events) == 0 || slices.Contains(n.events, kind)
}

func (n *httpNotifier) Notify(ctx context.Context, event evaluate.Event) error {
	if !n.Handles(event.Kind) {
		return nil
	}
	payload, err := n.build(event)
	if err != nil {
		return fmt.Errorf("build %s notification: %w", n.name, err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal %s notification: %w", n.name, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build %s notification request: %w", n.name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "certinv/0.2 (+https://github.com/tasoint/certinv)")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("send %s notification: %w", n.name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("send %s notification returned status %d", n.name, resp.StatusCode)
	}
	return nil
}

func webhookPayload(e evaluate.Event) (any, error) {
	return e, nil
}

func slackPayload(e evaluate.Event) (any, error) {
	return map[string]string{
		"text": fmt.Sprintf("certinv %s: fingerprint=%s host_id=%d %s", e.Kind, e.Fingerprint, e.HostID, e.Detail),
	}, nil
}
