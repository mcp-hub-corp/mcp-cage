package policy

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/config"
	"github.com/mcp-hub-corp/mcp-cage/internal/manifest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPolicy(t *testing.T) {
	cfg := &config.Config{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}

	p := NewPolicy(cfg)

	assert.Equal(t, 1000, p.MaxCPU)
	assert.Equal(t, "512M", p.MaxMemory)
	assert.Equal(t, 10, p.MaxPIDs)
	assert.Equal(t, 100, p.MaxFDs)
	assert.Equal(t, 5*time.Minute, p.DefaultTimeout)
	assert.True(t, p.AllowSubprocess)
}

func TestNewPolicyWithLogger(t *testing.T) {
	cfg := &config.Config{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	p := NewPolicyWithLogger(cfg, logger)

	assert.Equal(t, 1000, p.MaxCPU)
	assert.NotNil(t, p.logger)
}

func TestApplyManifestPermissions(t *testing.T) {
	cfg := &config.Config{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}
	p := NewPolicy(cfg)
	// Allow subprocess so the manifest permission is accepted
	p.AllowSubprocess = true

	m := &manifest.Manifest{
		Permissions: manifest.PermissionsInfo{
			Network:     []string{"example.com", "*.api.example.com"},
			Environment: []string{"API_KEY", "DB_PASSWORD"},
			Subprocess:  true,
		},
	}

	err := p.ApplyManifestPermissions(m)
	require.NoError(t, err)

	assert.Equal(t, 2, len(p.NetworkAllowlist))
	assert.Equal(t, 2, len(p.EnvAllowlist))
}

func TestApplyManifestPermissions_SubprocessDenied(t *testing.T) {
	cfg := &config.Config{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}
	p := NewPolicy(cfg)
	// Explicitly deny subprocess via policy override
	p.AllowSubprocess = false

	m := &manifest.Manifest{
		Permissions: manifest.PermissionsInfo{
			Subprocess: true,
		},
	}

	err := p.ApplyManifestPermissions(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "subprocess permission denied")
}

func TestApplyManifestPermissions_Nil(t *testing.T) {
	cfg := &config.Config{
		Timeout: 5 * time.Minute,
	}
	p := NewPolicy(cfg)

	err := p.ApplyManifestPermissions(nil)
	assert.Error(t, err)
}

func TestApplyLimits_PolicyStricter(t *testing.T) {
	cfg := &config.Config{
		MaxCPU:    500,
		MaxMemory: "256M",
		MaxPIDs:   5,
		MaxFDs:    50,
		Timeout:   2 * time.Minute,
	}
	p := NewPolicy(cfg)

	m := &manifest.Manifest{
		Limits: manifest.LimitsInfo{
			MaxCPU:    1000,
			MaxMemory: "512M",
			MaxPIDs:   10,
			MaxFDs:    100,
			Timeout:   "5m",
		},
	}

	limits := p.ApplyLimits(m)

	assert.Equal(t, 500, limits.MaxCPU)
	assert.Equal(t, "256M", limits.MaxMemory)
	assert.Equal(t, 5, limits.MaxPIDs)
	assert.Equal(t, 50, limits.MaxFDs)
	assert.Equal(t, 2*time.Minute, limits.Timeout)
}

func TestApplyLimits_ManifestStricter(t *testing.T) {
	cfg := &config.Config{
		MaxCPU:    2000,
		MaxMemory: "1G",
		MaxPIDs:   20,
		MaxFDs:    200,
		Timeout:   10 * time.Minute,
	}
	p := NewPolicy(cfg)

	m := &manifest.Manifest{
		Limits: manifest.LimitsInfo{
			MaxCPU:    500,
			MaxMemory: "256M",
			MaxPIDs:   5,
			MaxFDs:    50,
			Timeout:   "2m",
		},
	}

	limits := p.ApplyLimits(m)

	assert.Equal(t, 500, limits.MaxCPU)
	assert.Equal(t, "256M", limits.MaxMemory)
	assert.Equal(t, 5, limits.MaxPIDs)
	assert.Equal(t, 50, limits.MaxFDs)
	assert.Equal(t, 2*time.Minute, limits.Timeout)
}

func TestApplyLimits_NilManifest(t *testing.T) {
	cfg := &config.Config{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}
	p := NewPolicy(cfg)

	limits := p.ApplyLimits(nil)

	assert.Equal(t, 1000, limits.MaxCPU)
	assert.Equal(t, "512M", limits.MaxMemory)
}

func TestValidateEnv_NoAllowlist(t *testing.T) {
	cfg := &config.Config{Timeout: 5 * time.Minute}
	p := NewPolicy(cfg)

	env := map[string]string{
		"VAR1": "value1",
		"VAR2": "value2",
	}

	result := p.ValidateEnv(env)

	assert.Equal(t, 2, len(result))
	assert.Equal(t, "value1", result["VAR1"])
	assert.Equal(t, "value2", result["VAR2"])
}

func TestValidateEnv_WithAllowlist(t *testing.T) {
	cfg := &config.Config{Timeout: 5 * time.Minute}
	p := NewPolicy(cfg)
	p.EnvAllowlist = []string{"VAR1", "VAR3"}

	env := map[string]string{
		"VAR1": "value1",
		"VAR2": "value2",
		"VAR3": "value3",
	}

	result := p.ValidateEnv(env)

	assert.Equal(t, 2, len(result))
	assert.Equal(t, "value1", result["VAR1"])
	assert.Equal(t, "value3", result["VAR3"])
	assert.NotContains(t, result, "VAR2")
}

func TestValidateNetwork_NoAllowlist(t *testing.T) {
	cfg := &config.Config{Timeout: 5 * time.Minute}
	p := NewPolicy(cfg)

	result := p.ValidateNetwork("example.com")

	assert.False(t, result)
}

func TestValidateNetwork_ExactMatch(t *testing.T) {
	cfg := &config.Config{Timeout: 5 * time.Minute}
	p := NewPolicy(cfg)
	p.NetworkAllowlist = []string{"example.com", "api.service.io"}

	assert.True(t, p.ValidateNetwork("example.com"))
	assert.True(t, p.ValidateNetwork("api.service.io"))
	assert.False(t, p.ValidateNetwork("other.com"))
}

func TestValidateNetwork_WildcardMatch(t *testing.T) {
	cfg := &config.Config{Timeout: 5 * time.Minute}
	p := NewPolicy(cfg)
	p.NetworkAllowlist = []string{"*.example.com"}

	assert.True(t, p.ValidateNetwork("sub.example.com"))
	assert.True(t, p.ValidateNetwork("deep.sub.example.com"))
	assert.False(t, p.ValidateNetwork("example.com"))
	assert.False(t, p.ValidateNetwork("other.com"))
}

func TestValidateEnv_WildcardAllowsAll(t *testing.T) {
	cfg := &config.Config{Timeout: 5 * time.Minute}
	p := NewPolicy(cfg)
	p.EnvAllowlist = []string{"*"}

	env := map[string]string{
		"VAR1":   "value1",
		"SECRET": "s3cret",
		"PATH":   "/usr/bin",
	}

	result := p.ValidateEnv(env)
	assert.Equal(t, 3, len(result))
	assert.Equal(t, "value1", result["VAR1"])
	assert.Equal(t, "s3cret", result["SECRET"])
	assert.Equal(t, "/usr/bin", result["PATH"])
}

func TestValidateEnv_WildcardMixedWithOthers(t *testing.T) {
	cfg := &config.Config{Timeout: 5 * time.Minute}
	p := NewPolicy(cfg)
	p.EnvAllowlist = []string{"VAR1", "*"}

	env := map[string]string{
		"VAR1": "value1",
		"VAR2": "value2",
	}

	result := p.ValidateEnv(env)
	assert.Equal(t, 2, len(result))
}

func TestValidateNetwork_WildcardAllowsAll(t *testing.T) {
	cfg := &config.Config{Timeout: 5 * time.Minute}
	p := NewPolicy(cfg)
	p.NetworkAllowlist = []string{"*"}

	assert.True(t, p.ValidateNetwork("example.com"))
	assert.True(t, p.ValidateNetwork("anything.io"))
	assert.True(t, p.ValidateNetwork("192.168.1.1"))
}

func TestValidateNetwork_CaseInsensitive(t *testing.T) {
	cfg := &config.Config{Timeout: 5 * time.Minute}
	p := NewPolicy(cfg)
	p.NetworkAllowlist = []string{"Example.COM"}

	assert.True(t, p.ValidateNetwork("example.com"))
	assert.True(t, p.ValidateNetwork("EXAMPLE.COM"))
}

func TestParseMemoryString(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"512M", 512 * 1024 * 1024},
		{"1G", 1024 * 1024 * 1024},
		{"256K", 256 * 1024},
		{"1024", 1024},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseMemoryString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsMoreRestrictiveMemory(t *testing.T) {
	tests := []struct {
		newLimit     string
		currentLimit string
		expected     bool
	}{
		{"256M", "512M", true},
		{"512M", "256M", false},
		{"1G", "512M", false},
		{"256M", "1G", true},
		{"invalid", "512M", false},
		{"512M", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.newLimit+" vs "+tt.currentLimit, func(t *testing.T) {
			result := isMoreRestrictiveMemory(tt.newLimit, tt.currentLimit)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPolicyIntegration_CertLevelInheritedFromConfig(t *testing.T) {
	cfg := &config.Config{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
		Policy: config.PolicyConfig{
			MinCertLevel:  2,
			CertLevelMode: StrictMode,
		},
	}
	p := NewPolicy(cfg)

	assert.NotNil(t, p.CertLevelPolicy)
	assert.Equal(t, 2, p.CertLevelPolicy.GetMinCertLevel())
	assert.Equal(t, StrictMode, p.CertLevelPolicy.GetEnforceMode())
}

func TestPolicyIntegration_CertLevelWarnMode(t *testing.T) {
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
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	p := NewPolicyWithLogger(cfg, logger)

	// Should not error in warn mode
	assert.NoError(t, p.CertLevelPolicy.Validate(0))
}

func TestPolicyIntegration_CertLevelDisabledMode(t *testing.T) {
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

	// Should not error in disabled mode
	assert.NoError(t, p.CertLevelPolicy.Validate(0))
	assert.NoError(t, p.CertLevelPolicy.Validate(1))
}

func TestApplyManifestPermissions_RejectsWildcardEnv(t *testing.T) {
	cfg := &config.Config{Timeout: 5 * time.Minute}
	p := NewPolicy(cfg)

	m := &manifest.Manifest{
		Permissions: manifest.PermissionsInfo{
			Environment: []string{"API_KEY", "*", "DB_HOST"},
		},
	}

	err := p.ApplyManifestPermissions(m)
	require.NoError(t, err)

	// Wildcard should be stripped — only the named vars remain
	assert.Equal(t, 2, len(p.EnvAllowlist))
	assert.Contains(t, p.EnvAllowlist, "API_KEY")
	assert.Contains(t, p.EnvAllowlist, "DB_HOST")
	assert.NotContains(t, p.EnvAllowlist, "*")
}

func TestApplyManifestPermissions_RejectsWildcardNetwork(t *testing.T) {
	cfg := &config.Config{Timeout: 5 * time.Minute}
	p := NewPolicy(cfg)

	m := &manifest.Manifest{
		Permissions: manifest.PermissionsInfo{
			Network: []string{"example.com", "*", "api.test.io"},
		},
	}

	err := p.ApplyManifestPermissions(m)
	require.NoError(t, err)

	// Wildcard should be stripped — only the named domains remain
	assert.Equal(t, 2, len(p.NetworkAllowlist))
	assert.Contains(t, p.NetworkAllowlist, "example.com")
	assert.Contains(t, p.NetworkAllowlist, "api.test.io")
	assert.NotContains(t, p.NetworkAllowlist, "*")
}

func TestValidateEnv_FilterFullEnvironment(t *testing.T) {
	// Simulates the fixed run.go flow: os.Environ() + env-file vars
	// all filtered through the allowlist
	cfg := &config.Config{Timeout: 5 * time.Minute}
	p := NewPolicy(cfg)
	p.EnvAllowlist = []string{"API_KEY", "HOME"}

	// Simulate full env (os.Environ() + env-file + secrets)
	fullEnv := map[string]string{
		"HOME":           "/Users/test",
		"PATH":           "/usr/bin",
		"API_KEY":        "secret123",
		"AWS_SECRET_KEY": "supersecret",
		"DB_PASSWORD":    "dbpass",
	}

	result := p.ValidateEnv(fullEnv)

	// Only allowed vars should pass through
	assert.Equal(t, 2, len(result))
	assert.Equal(t, "secret123", result["API_KEY"])
	assert.Equal(t, "/Users/test", result["HOME"])
	assert.NotContains(t, result, "PATH")
	assert.NotContains(t, result, "AWS_SECRET_KEY")
	assert.NotContains(t, result, "DB_PASSWORD")
}
