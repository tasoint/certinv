package report

import (
	"strings"

	certmeta "github.com/tasoint/certinv/internal/cert"
)

const (
	AutomationLikelyAuto   = "likely_auto"
	AutomationLikelyManual = "likely_manual"
	AutomationUnknown      = "unknown"
)

type AutomationEstimate struct {
	Class  string
	Reason string
}

func EstimateAutomation(cert certmeta.Metadata) AutomationEstimate {
	issuer := strings.ToLower(strings.TrimSpace(cert.IssuerCN + " " + cert.IssuerOrg))
	switch {
	case cert.LifetimeDays <= 100 && knownACMEIssuer(issuer):
		return AutomationEstimate{
			Class:  AutomationLikelyAuto,
			Reason: "short-lived certificate from known ACME-capable issuer",
		}
	case cert.LifetimeDays >= 200 && !knownACMEIssuer(issuer):
		return AutomationEstimate{
			Class:  AutomationLikelyManual,
			Reason: "long-lived certificate from issuer not in ACME shortlist",
		}
	default:
		return AutomationEstimate{
			Class:  AutomationUnknown,
			Reason: "insufficient signal",
		}
	}
}

func knownACMEIssuer(issuer string) bool {
	// TODO: make this list configurable once real-world issuer naming variance is observed.
	for _, name := range []string{
		"let's encrypt",
		"lets encrypt",
		"r10",
		"r11",
		"r12",
		"r13",
		"e5",
		"e6",
		"google trust services",
		"gts",
		"we1",
		"we2",
		"yr1",
		"zerossl",
		"buypass",
	} {
		if strings.Contains(issuer, name) {
			return true
		}
	}
	return false
}
