package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Reset Viper global state so config file on disk does not interfere
	viper.Reset()

	// Use a temp dir as HOME so no real ~/.smcp/config.yaml is read
	tempHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	// Clear any env vars
	os.Unsetenv("MCP_REGISTRY_URL")
	os.Unsetenv("MCP_CACHE_DIR")
	os.Unsetenv("MCP_LOG_LEVEL")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "https://registry.mcp-hub.info", cfg.RegistryURL)
	assert.Contains(t, cfg.CacheDir, filepath.FromSlash(".smcp/cache"))
	assert.Equal(t, 5*time.Minute, cfg.Timeout)
	assert.Equal(t, 1000, cfg.MaxCPU)
	assert.Equal(t, "512M", cfg.MaxMemory)
	assert.Equal(t, 256, cfg.MaxPIDs)
	assert.Equal(t, 1024, cfg.MaxFDs)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.True(t, cfg.AuditEnabled)
	assert.Contains(t, cfg.AuditLogFile, filepath.FromSlash(".smcp/audit.log"))
}

func TestLoadConfig_EnvVarOverride(t *testing.T) {
	// Set env vars
	os.Setenv("MCP_REGISTRY_URL", "https://custom-registry.example.com")
	os.Setenv("MCP_LOG_LEVEL", "debug")
	defer func() {
		os.Unsetenv("MCP_REGISTRY_URL")
		os.Unsetenv("MCP_LOG_LEVEL")
	}()

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "https://custom-registry.example.com", cfg.RegistryURL)
	assert.Equal(t, "debug", cfg.LogLevel)
}

func TestExpandPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{
			name:     "expand tilde",
			input:    "~/.smcp/config",
			contains: filepath.FromSlash(".smcp/config"),
		},
		{
			name:     "absolute path unchanged",
			input:    "/etc/mcp/config",
			contains: "/etc/mcp/config",
		},
		{
			name:     "empty path",
			input:    "",
			contains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandPath(tt.input)
			if tt.input == "" {
				assert.Equal(t, tt.contains, result)
			} else {
				assert.Contains(t, result, tt.contains)
			}
		})
	}
}
