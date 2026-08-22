package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestFromChainExtractsMetadata(t *testing.T) {
	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	leaf := testCertificate(t, "www.example.com", now.Add(-time.Hour), now.Add(47*24*time.Hour))

	metadata, err := FromChain([]*x509.Certificate{leaf}, "www.example.com", now)
	if err != nil {
		t.Fatalf("FromChain() error = %v", err)
	}
	if metadata.Fingerprint == "" {
		t.Fatal("Fingerprint is empty")
	}
	if !metadata.HostnameMatch {
		t.Fatal("HostnameMatch = false, want true")
	}
	if !metadata.IsSelfSigned {
		t.Fatal("IsSelfSigned = false, want true")
	}
	if metadata.LifetimeDays != 47 {
		t.Fatalf("LifetimeDays = %d, want 47", metadata.LifetimeDays)
	}
}

func testCertificate(t *testing.T, dnsName string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		DNSNames:              []string{dnsName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}
