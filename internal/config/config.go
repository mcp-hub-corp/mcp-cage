package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	RegistryURL  string        `mapstructure:"registry_url"`
	CacheDir     string        `mapstructure:"cache_dir"`
	Timeout      time.Duration `mapstructure:"timeout"`
	MaxCPU       int           `mapstructure:"max_cpu"`    // millicores
	MaxMemory    string        `mapstructure:"max_memory"` // e.g., "512M"
	MaxPIDs      int           `mapstructure:"max_pids"`
	MaxFDs       int           `mapstructure:"max_fds"`
	LogLevel     string        `mapstructure:"log_level"`
	AuditEnabled bool          `mapstructure:"audit_enabled"`
	AuditLogFile string        `mapstructure:"audit_log_file"`

	// Default limits (ALWAYS applied, cannot be disabled)
	// CRITICAL: These mandatory defaults prevent unsafe execution without resource limits
	DefaultMaxCPU    int    `mapstructure:"default_max_cpu"`    // millicores, default 1000 (1 core)
	DefaultMaxMemory string `mapstructure:"default_max_memory"` // default "512M"
	DefaultMaxPIDs   int    `mapstructure:"default_max_pids"`   // default 32
	DefaultMaxFDs    int    `mapstructure:"default_max_fds"`    // default 256
	DefaultTimeout   string `mapstructure:"default_timeout"`    // default "5m"

	// Policy configuration
	Policy PolicyConfig `mapstructure:"policy"`
}

// PolicyConfig holds policy enforcement settings
type PolicyConfig struct {
	AllowedOrigins   []string                          `mapstructure:"allowed_origins"`   // Empty = allow all origins
	MinCertLevel     int                               `mapstructure:"min_cert_level"`    // 0-3, default 0 (no minimum)
	CertLevelMode    string                            `mapstructure:"cert_level_mode"`   // strict, warn, disabled
	MinScore         int                               `mapstructure:"min_score"`         // 0-100, default 0 (no minimum)
	ScoreMode        string                            `mapstructure:"score_mode"`        // strict, warn, disabled
	WarningThreshold int                               `mapstructure:"warning_threshold"` // Score threshold for LLM security warnings (default 80)
	Environments     map[string]map[string]interface{} `mapstructure:"environments"`      // Environment-specific overrides
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig() (*Config, error) {
	// Set defaults
	viper.SetDefault("registry_url", "https://registry.mcp-hub.info")
	viper.SetDefault("cache_dir", filepath.Join(getHomeDir(), ".smcp", "cache"))
	viper.SetDefault("timeout", 5*time.Minute)
	viper.SetDefault("max_cpu", 1000) // 1 core
	viper.SetDefault("max_memory", "512M")
	viper.SetDefault("max_pids", 256)
	viper.SetDefault("max_fds", 1024)
	viper.SetDefault("log_level", "info")
	viper.SetDefault("audit_enabled", true)
	viper.SetDefault("audit_log_file", filepath.Join(getHomeDir(), ".smcp", "audit.log"))

	// CRITICAL: Mandatory default limits (ALWAYS applied, cannot be disabled)
	// These defaults ensure execution without limits is NEVER possible
	viper.SetDefault("default_max_cpu", 1000) // 1 core (millicores)
	viper.SetDefault("default_max_memory", "512M")
	viper.SetDefault("default_max_pids", 32)
	viper.SetDefault("default_max_fds", 256)
	viper.SetDefault("default_timeout", "5m")

	// Policy defaults
	viper.SetDefault("policy.min_cert_level", 0)           // No minimum by default
	viper.SetDefault("policy.cert_level_mode", "disabled") // No enforcement by default
	viper.SetDefault("policy.min_score", 0)                // No minimum by default
	viper.SetDefault("policy.score_mode", "disabled")      // No enforcement by default
	viper.SetDefault("policy.warning_threshold", 80)       // LLM security warning threshold

	// Set config file location
	configDir := filepath.Join(getHomeDir(), ".smcp")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configDir)

	// Read config file (ignore error if file doesn't exist)
	_ = viper.ReadInConfig() // nolint:errcheck // config file is optional

	// Override with environment variables
	viper.SetEnvPrefix("MCP")
	viper.AutomaticEnv()

	// Map env var names to config keys (errors are unlikely and safe to ignore)
	_ = viper.BindEnv("registry_url", "MCP_REGISTRY_URL") // nolint:errcheck // errors are unlikely here
	_ = viper.BindEnv("cache_dir", "MCP_CACHE_DIR")       // nolint:errcheck // errors are unlikely here
	_ = viper.BindEnv("log_level", "MCP_LOG_LEVEL")       // nolint:errcheck // errors are unlikely here
	_ = viper.BindEnv("timeout", "MCP_TIMEOUT")           // nolint:errcheck // errors are unlikely here

	// Unmarshal into Config struct
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// Expand ~ in paths
	cfg.CacheDir = expandPath(cfg.CacheDir)
	cfg.AuditLogFile = expandPath(cfg.AuditLogFile)

	return &cfg, nil
}

// getHomeDir returns the user's home directory
func getHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return home
}

// expandPath expands ~ to home directory
func expandPath(path string) string {
	if path == "" {
		return path
	}
	if path[0] == '~' {
		home := getHomeDir()
		return filepath.Join(home, path[1:])
	}
	return path
}
