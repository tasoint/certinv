package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	certmeta "github.com/tasoint/certinv/internal/cert"
	"github.com/tasoint/certinv/internal/config"
	"github.com/tasoint/certinv/internal/probe"
)

func TestScopedCheckTargetAcceptsApexHost(t *testing.T) {
	hostname, apex, err := scopedCheckTarget("WWW.Example.COM.", []string{"example.com"})
	if err != nil {
		t.Fatalf("scopedCheckTarget() error = %v", err)
	}
	if hostname != "www.example.com" {
		t.Fatalf("hostname = %q, want www.example.com", hostname)
	}
	if apex != "example.com" {
		t.Fatalf("apex = %q, want example.com", apex)
	}
}

func TestScopedCheckTargetRejectsOutOfScopeHost(t *testing.T) {
	if _, _, err := scopedCheckTarget("www.example.net", []string{"example.com"}); err == nil {
		t.Fatal("scopedCheckTarget() error = nil, want error")
	}
}

func TestScopedCheckTargetRejectsHostPort(t *testing.T) {
	if _, _, err := scopedCheckTarget("www.example.com:443", []string{"example.com"}); err == nil {
		t.Fatal("scopedCheckTarget() error = nil, want error")
	}
}

func TestPrintCheckResult(t *testing.T) {
	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	printCheckResult(&out, "example.com", probe.Result{
		Target: probe.Target{Hostname: "www.example.com", Port: 443},
		Certificate: certmeta.Metadata{
			Fingerprint:   "abc123",
			SubjectCN:     "www.example.com",
			IssuerCN:      "Test CA",
			IssuerOrg:     "Example Org",
			NotBefore:     now.Add(-24 * time.Hour),
			NotAfter:      now.Add(47 * 24 * time.Hour),
			LifetimeDays:  48,
			SigAlgorithm:  "ECDSA-SHA256",
			KeyAlgorithm:  "ECDSA",
			KeyBits:       256,
			ChainComplete: true,
			HostnameMatch: true,
			SANNames:      []string{"www.example.com", "example.com"},
		},
		ProbedAt: now,
	})

	got := out.String()
	for _, want := range []string{
		"host: www.example.com",
		"apex: example.com",
		"fingerprint_sha256: abc123",
		"issuer_cn: Test CA",
		"not_after: 2026-10-09T00:00:00Z",
		"  - www.example.com",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "PRIVATE KEY") {
		t.Fatal("output contains forbidden key material marker")
	}
}

func TestOptionalBasicAuthPassesThroughWhenUnset(t *testing.T) {
	handler := withOptionalBasicAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), config.ExporterAuth{})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestOptionalBasicAuthAcceptsValidCredentials(t *testing.T) {
	handler := withOptionalBasicAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), config.ExporterAuth{Username: "operator", Password: "secret"})

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.SetBasicAuth("operator", "secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestOptionalBasicAuthRejectsInvalidCredentials(t *testing.T) {
	handler := withOptionalBasicAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}), config.ExporterAuth{Username: "operator", Password: "secret"})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.SetBasicAuth("operator", "wrong")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="certinv"` {
		t.Fatalf("WWW-Authenticate = %q, want Basic realm", got)
	}
}
