package cli

import (
	"testing"

	"github.com/mcp-hub-corp/mcp-cage/internal/config"
	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
)

// TestOriginPolicyIntegration validates that origin policy can be loaded from config
// and properly enforced during package execution
func TestOriginPolicyIntegration(t *testing.T) {
	testCases := []struct {
		name           string
		allowedOrigins []string
		packageOrigin  string
		shouldAllow    bool
	}{
		{
			name:           "allow all origins (empty policy)",
			allowedOrigins: []string{},
			packageOrigin:  "community",
			shouldAllow:    true,
		},
		{
			name:           "official only - allow official",
			allowedOrigins: []string{"official"},
			packageOrigin:  "official",
			shouldAllow:    true,
		},
		{
			name:           "official only - block community",
			allowedOrigins: []string{"official"},
			packageOrigin:  "community",
			shouldAllow:    false,
		},
		{
			name:           "official and verified - allow verified",
			allowedOrigins: []string{"official", "verified"},
			packageOrigin:  "verified",
			shouldAllow:    true,
		},
		{
			name:           "official and verified - block community",
			allowedOrigins: []string{"official", "verified"},
			packageOrigin:  "community",
			shouldAllow:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create config with policy
			cfg := &config.Config{
				Policy: config.PolicyConfig{
					AllowedOrigins: tc.allowedOrigins,
				},
			}

			// Create origin policy from config
			originPolicy := policy.NewOriginPolicy(cfg.Policy.AllowedOrigins)

			// Validate the package origin
			err := originPolicy.Validate(tc.packageOrigin)

			if tc.shouldAllow && err != nil {
				t.Errorf("expected origin %q to be allowed with policy %v, got error: %v",
					tc.packageOrigin, tc.allowedOrigins, err)
			}

			if !tc.shouldAllow && err == nil {
				t.Errorf("expected origin %q to be blocked with policy %v, but it was allowed",
					tc.packageOrigin, tc.allowedOrigins)
			}
		})
	}
}

// TestOriginPolicyConfigDefault verifies that an empty policy config allows all origins
func TestOriginPolicyConfigDefault(t *testing.T) {
	cfg := &config.Config{
		Policy: config.PolicyConfig{
			AllowedOrigins: nil, // Default: no restrictions
		},
	}

	originPolicy := policy.NewOriginPolicy(cfg.Policy.AllowedOrigins)

	// All origins should be allowed with default config
	origins := []string{"official", "verified", "community", "unknown"}
	for _, origin := range origins {
		if err := originPolicy.Validate(origin); err != nil {
			t.Errorf("default policy should allow origin %q, got error: %v", origin, err)
		}
	}
}
