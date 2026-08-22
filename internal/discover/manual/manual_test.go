package manual

import (
	"context"
	"testing"

	"github.com/tasoint/certinv/internal/config"
)

func TestDiscoverRejectsOutOfScopeHost(t *testing.T) {
	source := New([]config.ManualHost{{Hostname: "mail.example.net"}})

	if _, err := source.Discover(context.Background(), []string{"example.com"}); err == nil {
		t.Fatal("Discover() error = nil, want error")
	}
}
