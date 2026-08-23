package zonefile

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverZoneFileHosts(t *testing.T) {
	path := writeZone(t, `
$ORIGIN example.com.
@ 3600 IN A 192.0.2.10
www IN A 192.0.2.11
api 300 IN AAAA 2001:db8::1
alias IN CNAME www.example.com.
outside.example.net. IN A 192.0.2.12
_acme-challenge IN TXT "ignored"
`)

	source := New([]string{path})
	hosts, err := source.Discover(context.Background(), []string{"example.com"})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	got := map[string]bool{}
	for _, host := range hosts {
		got[host.Hostname] = true
		if host.Apex != "example.com" {
			t.Fatalf("host apex = %q, want example.com", host.Apex)
		}
		if host.Port != 443 {
			t.Fatalf("host port = %d, want 443", host.Port)
		}
	}
	for _, want := range []string{"example.com", "www.example.com", "api.example.com", "alias.example.com"} {
		if !got[want] {
			t.Fatalf("missing host %q in %#v", want, got)
		}
	}
	if got["outside.example.net"] {
		t.Fatal("out-of-scope host was included")
	}
}

func TestDiscoverRejectsInvalidOrigin(t *testing.T) {
	path := writeZone(t, `$ORIGIN`)
	source := New([]string{path})

	if _, err := source.Discover(context.Background(), []string{"example.com"}); err == nil {
		t.Fatal("Discover() error = nil, want error")
	}
}

func writeZone(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "example.zone")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write zone: %v", err)
	}
	return path
}
