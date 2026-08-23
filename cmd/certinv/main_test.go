package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	certmeta "github.com/tasoint/certinv/internal/cert"
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
