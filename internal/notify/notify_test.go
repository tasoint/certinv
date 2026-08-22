package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tasoint/certinv/internal/config"
	"github.com/tasoint/certinv/internal/evaluate"
)

func TestWebhookNotifierPostsEvent(t *testing.T) {
	var got evaluate.Event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	notifiers, err := FromConfig([]config.Notifier{{
		Type:   "webhook",
		URL:    server.URL,
		Events: []string{evaluate.EventWarn},
	}}, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("FromConfig() error = %v", err)
	}

	event := evaluate.Event{Kind: evaluate.EventWarn, Fingerprint: "abc123", HostID: 7, Detail: "warn"}
	if err := notifiers[0].Notify(context.Background(), event); err != nil {
		t.Fatalf("Notify() error = %v", err)
	}
	if got.Kind != event.Kind || got.Fingerprint != event.Fingerprint || got.HostID != event.HostID {
		t.Fatalf("event = %#v, want %#v", got, event)
	}
}

func TestSlackNotifierReadsWebhookFromEnv(t *testing.T) {
	t.Setenv("SLACK_WEBHOOK_URL_TEST", "https://example.com/slack")

	notifiers, err := FromConfig([]config.Notifier{{
		Type:          "slack",
		WebhookURLEnv: "SLACK_WEBHOOK_URL_TEST",
		Events:        []string{evaluate.EventAlert},
	}})
	if err != nil {
		t.Fatalf("FromConfig() error = %v", err)
	}
	if !notifiers[0].Handles(evaluate.EventAlert) {
		t.Fatal("slack notifier does not handle alert")
	}
	if notifiers[0].Handles(evaluate.EventWarn) {
		t.Fatal("slack notifier handles warn, want false")
	}
}

func TestSlackNotifierRequiresEnv(t *testing.T) {
	if _, err := FromConfig([]config.Notifier{{Type: "slack", WebhookURLEnv: "MISSING_SLACK_URL"}}); err == nil {
		t.Fatal("FromConfig() error = nil, want error")
	}
}
