package policy

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCertLevelPolicyIntegration tests cert level policy with origin policy
// Simulates real-world scenarios combining both origin and cert level enforcement
func TestCertLevelPolicyIntegration_StrictOriginAndCertLevel(t *testing.T) {
	// Production environment: only official + verified, cert level >= 2
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg := &config.Config{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
		Policy: config.PolicyConfig{
			AllowedOrigins: []string{"official", "verified"},
			MinCertLevel:   2,
			CertLevelMode:  StrictMode,
		},
	}

	p := NewPolicyWithLogger(cfg, logger)

	// Test 1: official + cert level 2 = PASS
	originPolicy := NewOriginPolicy(cfg.Policy.AllowedOrigins)
	originErr := originPolicy.Validate("official")
	certErr := p.CertLevelPolicy.Validate(2)
	assert.NoError(t, originErr)
	assert.NoError(t, certErr)

	// Test 2: verified + cert level 3 = PASS
	originErr = originPolicy.Validate("verified")
	certErr = p.CertLevelPolicy.Validate(3)
	assert.NoError(t, originErr)
	assert.NoError(t, certErr)

	// Test 3: community + cert level 2 = FAIL (origin)
	originErr = originPolicy.Validate("community")
	assert.Error(t, originErr)

	// Test 4: official + cert level 1 = FAIL (cert level)
	originErr = originPolicy.Validate("official")
	certErr = p.CertLevelPolicy.Validate(1)
	assert.NoError(t, originErr)
	assert.Error(t, certErr)

	// Test 5: verified + cert level 0 = FAIL (cert level)
	originErr = originPolicy.Validate("verified")
	certErr = p.CertLevelPolicy.Validate(0)
	assert.NoError(t, originErr)
	assert.Error(t, certErr)
}

// TestCertLevelPolicyIntegration_WarnMode tests gradual rollout scenario
func TestCertLevelPolicyIntegration_WarnMode(t *testing.T) {
	// Staging environment: warn about low cert levels
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg := &config.Config{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
		Policy: config.PolicyConfig{
			MinCertLevel:  1,
			CertLevelMode: WarnMode,
		},
	}

	p := NewPolicyWithLogger(cfg, logger)

	// Test: All cert levels allowed in warn mode, but warnings logged
	for certLevel := 0; certLevel <= 3; certLevel++ {
		err := p.CertLevelPolicy.Validate(certLevel)
		assert.NoError(t, err, "warn mode should allow all cert levels")
	}
}

// TestCertLevelPolicyIntegration_DisabledMode tests backward compatibility
func TestCertLevelPolicyIntegration_DisabledMode(t *testing.T) {
	// Development environment: no enforcement
	cfg := &config.Config{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
		Policy: config.PolicyConfig{
			MinCertLevel:  2,
			CertLevelMode: DisabledMode,
		},
	}

	p := NewPolicy(cfg)

	// Test: All cert levels allowed
	for certLevel := 0; certLevel <= 3; certLevel++ {
		err := p.CertLevelPolicy.Validate(certLevel)
		assert.NoError(t, err, "disabled mode should allow all cert levels")
	}
}

// TestCertLevelPolicyIntegration_EnvironmentSpecific tests multiple policy configs
func TestCertLevelPolicyIntegration_EnvironmentSpecific(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Define policies for different environments
	environments := map[string]struct {
		minCertLevel  int
		enforceMode   string
		testCertLevel int
		shouldPass    bool
	}{
		"dev": {
			minCertLevel:  0,
			enforceMode:   DisabledMode,
			testCertLevel: 0,
			shouldPass:    true, // All allowed in disabled mode
		},
		"staging": {
			minCertLevel:  1,
			enforceMode:   WarnMode,
			testCertLevel: 0,
			shouldPass:    true, // Warn mode allows all
		},
		"prod": {
			minCertLevel:  2,
			enforceMode:   StrictMode,
			testCertLevel: 1,
			shouldPass:    false, // Strict mode blocks if below minimum
		},
	}

	for env, testCase := range environments {
		t.Run(env, func(t *testing.T) {
			policy := NewCertLevelPolicyWithLogger(
				testCase.minCertLevel,
				testCase.enforceMode,
				logger,
			)

			err := policy.Validate(testCase.testCertLevel)

			if testCase.shouldPass {
				assert.NoError(t, err, "environment %s should allow cert level %d", env, testCase.testCertLevel)
			} else {
				assert.Error(t, err, "environment %s should block cert level %d", env, testCase.testCertLevel)
			}
		})
	}
}

// TestCertLevelPolicyIntegration_RealWorldScenarios tests complete scenarios
func TestCertLevelPolicyIntegration_RealWorldScenarios(t *testing.T) {
	tests := []struct {
		name           string
		allowedOrigins []string
		minCertLevel   int
		enforceMode    string
		testOrigin     string
		testCertLevel  int
		shouldPass     bool
		description    string
	}{
		{
			name:           "strict_official_only",
			allowedOrigins: []string{"official"},
			minCertLevel:   2,
			enforceMode:    StrictMode,
			testOrigin:     "official",
			testCertLevel:  2,
			shouldPass:     true,
			description:    "Production: only official + certified",
		},
		{
			name:           "strict_official_low_cert",
			allowedOrigins: []string{"official"},
			minCertLevel:   2,
			enforceMode:    StrictMode,
			testOrigin:     "official",
			testCertLevel:  1,
			shouldPass:     false,
			description:    "Production: official but not certified enough",
		},
		{
			name:           "verified_community_allowed",
			allowedOrigins: []string{"official", "verified", "community"},
			minCertLevel:   0,
			enforceMode:    DisabledMode,
			testOrigin:     "community",
			testCertLevel:  0,
			shouldPass:     true,
			description:    "Development: all origins, no enforcement",
		},
		{
			name:           "gradual_rollout",
			allowedOrigins: []string{},
			minCertLevel:   1,
			enforceMode:    WarnMode,
			testOrigin:     "community",
			testCertLevel:  0,
			shouldPass:     true,
			description:    "Gradual rollout: warn about low certs but allow",
		},
		{
			name:           "enterprise_highest_security",
			allowedOrigins: []string{"official"},
			minCertLevel:   3,
			enforceMode:    StrictMode,
			testOrigin:     "official",
			testCertLevel:  3,
			shouldPass:     true,
			description:    "Enterprise: only runtime-certified official",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

			cfg := &config.Config{
				MaxCPU:    1000,
				MaxMemory: "512M",
				MaxPIDs:   10,
				MaxFDs:    100,
				Timeout:   5 * time.Minute,
				Policy: config.PolicyConfig{
					AllowedOrigins: tt.allowedOrigins,
					MinCertLevel:   tt.minCertLevel,
					CertLevelMode:  tt.enforceMode,
				},
			}

			p := NewPolicyWithLogger(cfg, logger)
			originPolicy := NewOriginPolicy(tt.allowedOrigins)

			// Check origin
			originErr := originPolicy.Validate(tt.testOrigin)
			// Check cert level
			certErr := p.CertLevelPolicy.Validate(tt.testCertLevel)

			// Determine if should pass (both origin and cert must pass if enforced)
			originOK := originErr == nil || len(tt.allowedOrigins) == 0
			certOK := certErr == nil || tt.enforceMode == DisabledMode

			if tt.shouldPass {
				assert.True(t, originOK && certOK,
					"%s: %s - expected pass but failed. Origin OK: %v, Cert OK: %v",
					tt.name, tt.description, originOK, certOK)
			} else {
				assert.False(t, originOK && certOK,
					"%s: %s - expected fail but passed",
					tt.name, tt.description)
			}
		})
	}
}

// TestCertLevelPolicy_PolicyInitialization tests that policy is correctly initialized from config
func TestCertLevelPolicy_PolicyInitialization(t *testing.T) {
	cfg := &config.Config{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
		Policy: config.PolicyConfig{
			AllowedOrigins: []string{"official"},
			MinCertLevel:   2,
			CertLevelMode:  StrictMode,
		},
	}

	p := NewPolicy(cfg)

	// Verify CertLevelPolicy is initialized
	require.NotNil(t, p.CertLevelPolicy)

	// Verify settings are correct
	assert.Equal(t, 2, p.CertLevelPolicy.GetMinCertLevel())
	assert.Equal(t, StrictMode, p.CertLevelPolicy.GetEnforceMode())
	assert.True(t, p.CertLevelPolicy.IsEnforced())
}

// TestCertLevelPolicy_VerboseValidation tests ValidateWithLogging
func TestCertLevelPolicy_VerboseValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	policy := NewCertLevelPolicyWithLogger(2, StrictMode, logger)

	// Test with logging
	packageID := "acme/security-tool"

	// Should log debug info and fail
	err := policy.ValidateWithLogging(1, packageID)
	assert.Error(t, err)

	// Should log debug info and pass
	err = policy.ValidateWithLogging(2, packageID)
	assert.NoError(t, err)
}

// TestCertLevelPolicy_BoundaryConditions tests edge cases
func TestCertLevelPolicy_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name        string
		minLevel    int
		testLevel   int
		enforceMode string
		shouldError bool
	}{
		// Boundary at 0
		{"min_0_test_0_strict", 0, 0, StrictMode, false},
		{"min_0_test_neg_strict", 0, -100, StrictMode, false},

		// Boundary at 3
		{"min_3_test_3_strict", 3, 3, StrictMode, false},
		{"min_3_test_100_strict", 3, 100, StrictMode, false},

		// Off-by-one errors
		{"min_1_test_0_strict", 1, 0, StrictMode, true},
		{"min_1_test_1_strict", 1, 1, StrictMode, false},
		{"min_2_test_1_strict", 2, 1, StrictMode, true},
		{"min_2_test_2_strict", 2, 2, StrictMode, false},

		// Warn mode never errors
		{"min_3_test_0_warn", 3, 0, WarnMode, false},
		{"min_3_test_neg_warn", 3, -100, WarnMode, false},

		// Disabled mode never errors
		{"min_3_test_0_disabled", 3, 0, DisabledMode, false},
		{"min_3_test_100_disabled", 3, 100, DisabledMode, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := NewCertLevelPolicy(tt.minLevel, tt.enforceMode)
			err := policy.Validate(tt.testLevel)

			if tt.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
