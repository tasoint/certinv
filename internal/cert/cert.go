package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type Metadata struct {
	Fingerprint   string
	SubjectCN     string
	IssuerCN      string
	IssuerOrg     string
	NotBefore     time.Time
	NotAfter      time.Time
	LifetimeDays  int
	SigAlgorithm  string
	KeyAlgorithm  string
	KeyBits       int
	IsSelfSigned  bool
	SANNames      []string
	ChainComplete bool
	HostnameMatch bool
}

func FromChain(chain []*x509.Certificate, hostname string, now time.Time) (Metadata, error) {
	_ = now
	if len(chain) == 0 {
		return Metadata{}, fmt.Errorf("certificate chain is empty")
	}

	leaf := chain[0]
	metadata := Metadata{
		Fingerprint:   FingerprintSHA256(leaf.Raw),
		SubjectCN:     leaf.Subject.CommonName,
		IssuerCN:      leaf.Issuer.CommonName,
		IssuerOrg:     firstString(leaf.Issuer.Organization),
		NotBefore:     leaf.NotBefore,
		NotAfter:      leaf.NotAfter,
		LifetimeDays:  lifetimeDays(leaf.NotBefore, leaf.NotAfter),
		SigAlgorithm:  leaf.SignatureAlgorithm.String(),
		KeyAlgorithm:  publicKeyAlgorithm(leaf),
		KeyBits:       publicKeyBits(leaf),
		IsSelfSigned:  isSelfSigned(leaf),
		SANNames:      append([]string{}, leaf.DNSNames...),
		ChainComplete: chainComplete(chain),
		HostnameMatch: hostnameMatches(leaf, hostname),
	}
	return metadata, nil
}

func FingerprintSHA256(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func lifetimeDays(notBefore, notAfter time.Time) int {
	return int(notAfter.Sub(notBefore).Hours() / 24)
}

func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

func hostnameMatches(cert *x509.Certificate, hostname string) bool {
	hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if hostname == "" {
		return false
	}
	return cert.VerifyHostname(hostname) == nil
}

func chainComplete(chain []*x509.Certificate) bool {
	if len(chain) < 2 {
		return isSelfSigned(chain[0])
	}
	for i := 0; i < len(chain)-1; i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return false
		}
	}
	last := chain[len(chain)-1]
	return isSelfSigned(last) || !sameName(last.Subject.String(), last.Issuer.String())
}

func sameName(a, b string) bool {
	return a == b
}

func publicKeyAlgorithm(cert *x509.Certificate) string {
	return cert.PublicKeyAlgorithm.String()
}

func publicKeyBits(cert *x509.Certificate) int {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return len(key) * 8
	default:
		return 0
	}
}
