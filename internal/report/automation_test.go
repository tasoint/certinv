package report

import (
	"testing"

	certmeta "github.com/tasoint/certinv/internal/cert"
)

func TestEstimateAutomation(t *testing.T) {
	tests := []struct {
		name string
		cert certmeta.Metadata
		want string
	}{
		{
			name: "short lived acme issuer",
			cert: certmeta.Metadata{LifetimeDays: 90, IssuerCN: "R11", IssuerOrg: "Let's Encrypt"},
			want: AutomationLikelyAuto,
		},
		{
			name: "long lived non acme issuer",
			cert: certmeta.Metadata{LifetimeDays: 398, IssuerCN: "Example Commercial TLS CA"},
			want: AutomationLikelyManual,
		},
		{
			name: "short lived unknown issuer",
			cert: certmeta.Metadata{LifetimeDays: 90, IssuerCN: "Private CA"},
			want: AutomationUnknown,
		},
		{
			name: "medium lived acme issuer",
			cert: certmeta.Metadata{LifetimeDays: 120, IssuerCN: "YR1"},
			want: AutomationUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EstimateAutomation(tt.cert)
			if got.Class != tt.want {
				t.Fatalf("Class = %q, want %q", got.Class, tt.want)
			}
		})
	}
}
