package common

import (
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestShouldHonorClusterTLSProfile(t *testing.T) {
	tests := []struct {
		name     string
		policy   TLSAdherencePolicy
		expected bool
	}{
		{
			name:     "empty value returns false",
			policy:   TLSAdherencePolicyNoOpinion,
			expected: false,
		},
		{
			name:     "legacy returns false",
			policy:   TLSAdherencePolicyLegacyExternalAPIServerComponentsOnly,
			expected: false,
		},
		{
			name:     "strict returns true",
			policy:   TLSAdherencePolicyStrictAllComponents,
			expected: true,
		},
		{
			name:     "unknown value returns true for forward compatibility",
			policy:   TLSAdherencePolicy("FutureValue"),
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldHonorClusterTLSProfile(tt.policy)
			if got != tt.expected {
				t.Errorf("ShouldHonorClusterTLSProfile(%q) = %v, want %v", tt.policy, got, tt.expected)
			}
		})
	}
}

func TestGetTLSProfileSpec(t *testing.T) {
	tests := []struct {
		name               string
		profile            *configv1.TLSSecurityProfile
		expectedMinVersion configv1.TLSProtocolVersion
	}{
		{
			name:               "nil profile returns Intermediate",
			profile:            nil,
			expectedMinVersion: configv1.VersionTLS12,
		},
		{
			name:               "Old profile",
			profile:            &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
			expectedMinVersion: configv1.VersionTLS10,
		},
		{
			name:               "Intermediate profile",
			profile:            &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
			expectedMinVersion: configv1.VersionTLS12,
		},
		{
			name:               "Modern profile",
			profile:            &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
			expectedMinVersion: configv1.VersionTLS13,
		},
		{
			name: "Custom profile",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
						MinTLSVersion: configv1.VersionTLS12,
					},
				},
			},
			expectedMinVersion: configv1.VersionTLS12,
		},
		{
			name: "Custom profile with nil custom field falls back to Intermediate",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
			},
			expectedMinVersion: configv1.VersionTLS12,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := GetTLSProfileSpec(tt.profile)
			if spec.MinTLSVersion != tt.expectedMinVersion {
				t.Errorf("GetTLSProfileSpec() MinTLSVersion = %v, want %v", spec.MinTLSVersion, tt.expectedMinVersion)
			}
		})
	}
}

func TestTLSConfigFromProfile(t *testing.T) {
	tests := []struct {
		name               string
		profile            *configv1.TLSSecurityProfile
		expectedMinVersion uint16
		expectError        bool
	}{
		{
			name:               "nil profile uses Intermediate defaults",
			profile:            nil,
			expectedMinVersion: tls.VersionTLS12,
		},
		{
			name:               "Intermediate profile",
			profile:            &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
			expectedMinVersion: tls.VersionTLS12,
		},
		{
			name:               "Old profile uses TLS 1.0",
			profile:            &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
			expectedMinVersion: tls.VersionTLS10,
		},
		{
			name:               "Modern profile uses TLS 1.3",
			profile:            &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
			expectedMinVersion: tls.VersionTLS13,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := TLSConfigFromProfile(tt.profile)
			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if cfg.MinVersion != tt.expectedMinVersion {
				t.Errorf("MinVersion = %d, want %d", cfg.MinVersion, tt.expectedMinVersion)
			}
			if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
				t.Errorf("NextProtos = %v, want [http/1.1]", cfg.NextProtos)
			}
		})
	}
}
