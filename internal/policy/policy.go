package policy

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/security-mcp/mcp-client/internal/config"
	"github.com/security-mcp/mcp-client/internal/manifest"
)

// Policy represents local security policy and execution limits
type Policy struct {
	MaxCPU           int              // millicores
	MaxMemory        string           // e.g. "512M"
	MaxPIDs          int              // max process count
	MaxFDs           int              // max file descriptors
	DefaultTimeout   time.Duration    // default execution timeout
	AllowSubprocess  bool             // allow subprocess creation
	NetworkAllowlist []string         // allowed domains/IPs
	EnvAllowlist     []string         // allowed env vars (if empty, all allowed)
	CertLevelPolicy  *CertLevelPolicy // certification level policy
	ScorePolicy      *ScorePolicy     // security score policy
	logger           *slog.Logger
}

// ExecutionLimits represents the final limits to apply to execution
type ExecutionLimits struct {
	MaxCPU    int           // millicores
	MaxMemory string        // e.g. "512M"
	MaxPIDs   int           // max process count
	MaxFDs    int           // max file descriptors
	Timeout   time.Duration // execution timeout
}

// NewPolicy creates a new policy from config
func NewPolicy(cfg *config.Config) *Policy {
	logger := slog.Default()

	return &Policy{
		MaxCPU:          cfg.MaxCPU,
		MaxMemory:       cfg.MaxMemory,
		MaxPIDs:         cfg.MaxPIDs,
		MaxFDs:          cfg.MaxFDs,
		DefaultTimeout:  cfg.Timeout,
		AllowSubprocess: true, // trust manifest permissions
		CertLevelPolicy: NewCertLevelPolicyWithLogger(cfg.Policy.MinCertLevel, cfg.Policy.CertLevelMode, logger),
		ScorePolicy:     NewScorePolicyWithLogger(cfg.Policy.MinScore, cfg.Policy.ScoreMode, logger),
		logger:          logger,
	}
}

// NewPolicyWithLogger creates a new policy from config with custom logger
func NewPolicyWithLogger(cfg *config.Config, logger *slog.Logger) *Policy {
	return &Policy{
		MaxCPU:          cfg.MaxCPU,
		MaxMemory:       cfg.MaxMemory,
		MaxPIDs:         cfg.MaxPIDs,
		MaxFDs:          cfg.MaxFDs,
		DefaultTimeout:  cfg.Timeout,
		AllowSubprocess: true, // trust manifest permissions
		CertLevelPolicy: NewCertLevelPolicyWithLogger(cfg.Policy.MinCertLevel, cfg.Policy.CertLevelMode, logger),
		ScorePolicy:     NewScorePolicyWithLogger(cfg.Policy.MinScore, cfg.Policy.ScoreMode, logger),
		logger:          logger,
	}
}

// ApplyManifestPermissions merges policy with manifest permissions
func (p *Policy) ApplyManifestPermissions(m *manifest.Manifest) error {
	if m == nil {
		return fmt.Errorf("manifest cannot be nil")
	}

	// Check subprocess permission
	if m.Permissions.Subprocess && !p.AllowSubprocess {
		p.logger.Error("manifest requests subprocess but policy denies",
			slog.String("package", m.Package.ID))
		return fmt.Errorf("subprocess permission denied by policy for package %s", m.Package.ID)
	}

	// Store network allowlist from manifest.
	// SECURITY: Reject wildcard "*" from manifests — only CLI flags can grant blanket access.
	// A malicious manifest could include "*" to bypass network isolation.
	if len(m.Permissions.Network) > 0 {
		filtered := make([]string, 0, len(m.Permissions.Network))
		for _, n := range m.Permissions.Network {
			if n == "*" {
				p.logger.Warn("manifest contains wildcard '*' in network list — ignored (only CLI --allow-all-net can grant blanket access)")
				continue
			}
			filtered = append(filtered, n)
		}
		p.NetworkAllowlist = filtered
		p.logger.Debug("applied manifest network allowlist",
			slog.Int("count", len(filtered)))
	}

	// Store env allowlist from manifest (if specified).
	// SECURITY: Reject wildcard "*" from manifests — only CLI flags can grant blanket access.
	if len(m.Permissions.Environment) > 0 {
		filtered := make([]string, 0, len(m.Permissions.Environment))
		for _, e := range m.Permissions.Environment {
			if e == "*" {
				p.logger.Warn("manifest contains wildcard '*' in environment list — ignored (only CLI --allow-all-env can grant blanket access)")
				continue
			}
			filtered = append(filtered, e)
		}
		p.EnvAllowlist = filtered
		p.logger.Debug("applied manifest environment allowlist",
			slog.Int("count", len(filtered)))
	}

	return nil
}

// ApplyLimits merges policy limits with manifest limits (stricter wins)
// CRITICAL SECURITY: ALWAYS returns non-nil limits with mandatory safe defaults
// This function NEVER allows execution without resource limits
func (p *Policy) ApplyLimits(m *manifest.Manifest) *ExecutionLimits {
	if m == nil {
		m = &manifest.Manifest{}
	}

	// Start with policy limits (which come from config with mandatory defaults)
	limits := &ExecutionLimits{
		MaxCPU:    p.MaxCPU,
		MaxMemory: p.MaxMemory,
		MaxPIDs:   p.MaxPIDs,
		MaxFDs:    p.MaxFDs,
		Timeout:   p.DefaultTimeout,
	}

	// CRITICAL: Verify limits are set and valid before proceeding
	// This is a fail-safe check to catch configuration errors
	if limits.MaxCPU <= 0 {
		// Fallback to absolute minimum (EMERGENCY)
		limits.MaxCPU = 100 // 100 millicores minimum
		p.logger.Error("CRITICAL: MaxCPU not set, applying emergency minimum", slog.Int("millicores", limits.MaxCPU))
	}

	if limits.MaxMemory == "" {
		// Fallback to absolute minimum (EMERGENCY)
		limits.MaxMemory = "256M"
		p.logger.Error("CRITICAL: MaxMemory not set, applying emergency minimum", slog.String("limit", limits.MaxMemory))
	}

	if limits.MaxPIDs <= 0 {
		// Fallback to absolute minimum (EMERGENCY)
		limits.MaxPIDs = 10
		p.logger.Error("CRITICAL: MaxPIDs not set, applying emergency minimum", slog.Int("pids", limits.MaxPIDs))
	}

	if limits.MaxFDs <= 0 {
		// Fallback to absolute minimum (EMERGENCY)
		limits.MaxFDs = 64
		p.logger.Error("CRITICAL: MaxFDs not set, applying emergency minimum", slog.Int("fds", limits.MaxFDs))
	}

	if limits.Timeout <= 0 {
		// Fallback to absolute minimum (EMERGENCY)
		limits.Timeout = 1 * time.Minute
		p.logger.Error("CRITICAL: Timeout not set, applying emergency minimum", slog.Duration("timeout", limits.Timeout))
	}

	// Apply manifest limits if more restrictive (stricter wins)
	if m.Limits.MaxCPU > 0 && m.Limits.MaxCPU < limits.MaxCPU {
		limits.MaxCPU = m.Limits.MaxCPU
		p.logger.Debug("manifest limit is stricter", slog.String("limit", "max_cpu"))
	}

	if m.Limits.MaxMemory != "" && isMoreRestrictiveMemory(m.Limits.MaxMemory, limits.MaxMemory) {
		limits.MaxMemory = m.Limits.MaxMemory
		p.logger.Debug("manifest limit is stricter", slog.String("limit", "max_memory"))
	}

	if m.Limits.MaxPIDs > 0 && m.Limits.MaxPIDs < limits.MaxPIDs {
		limits.MaxPIDs = m.Limits.MaxPIDs
		p.logger.Debug("manifest limit is stricter", slog.String("limit", "max_pids"))
	}

	if m.Limits.MaxFDs > 0 && m.Limits.MaxFDs < limits.MaxFDs {
		limits.MaxFDs = m.Limits.MaxFDs
		p.logger.Debug("manifest limit is stricter", slog.String("limit", "max_fds"))
	}

	if m.Limits.Timeout != "" {
		// Parse timeout and compare
		if parsedTimeout, err := time.ParseDuration(m.Limits.Timeout); err == nil {
			if parsedTimeout > 0 && parsedTimeout < limits.Timeout {
				limits.Timeout = parsedTimeout
				p.logger.Debug("manifest limit is stricter", slog.String("limit", "timeout"))
			}
		}
	}

	// FINAL VALIDATION: Ensure all limits are still set (post-manifest application)
	if limits.MaxCPU <= 0 {
		limits.MaxCPU = 100 // Absolute minimum
		p.logger.Warn("manifest provided invalid MaxCPU, applying minimum")
	}
	if limits.MaxMemory == "" {
		limits.MaxMemory = "256M" // Absolute minimum
		p.logger.Warn("manifest provided invalid MaxMemory, applying minimum")
	}
	if limits.MaxPIDs <= 0 {
		limits.MaxPIDs = 10 // Absolute minimum
		p.logger.Warn("manifest provided invalid MaxPIDs, applying minimum")
	}
	if limits.MaxFDs <= 0 {
		limits.MaxFDs = 64 // Absolute minimum
		p.logger.Warn("manifest provided invalid MaxFDs, applying minimum")
	}
	if limits.Timeout <= 0 {
		limits.Timeout = 1 * time.Minute // Absolute minimum
		p.logger.Warn("manifest provided invalid Timeout, applying minimum")
	}

	return limits
}

// ValidateEnv filters environment variables based on manifest allowlist
func (p *Policy) ValidateEnv(env map[string]string) map[string]string {
	if len(p.EnvAllowlist) == 0 {
		// If no allowlist, pass through all env vars
		return env
	}

	// Wildcard: allow all env vars
	for _, key := range p.EnvAllowlist {
		if key == "*" {
			return env
		}
	}

	filtered := make(map[string]string)
	for _, key := range p.EnvAllowlist {
		if val, ok := env[key]; ok {
			filtered[key] = val
		}
	}

	return filtered
}

// ValidateNetwork checks if a network connection is allowed
func (p *Policy) ValidateNetwork(host string) bool {
	if len(p.NetworkAllowlist) == 0 {
		// Default deny if no allowlist specified
		return false
	}

	host = strings.ToLower(host)
	for _, allowed := range p.NetworkAllowlist {
		allowed = strings.ToLower(allowed)

		// Wildcard: allow all hosts
		if allowed == "*" {
			return true
		}

		// Exact match
		if host == allowed {
			return true
		}

		// Subdomain match (e.g., *.example.com matches sub.example.com but not example.com)
		if strings.HasPrefix(allowed, "*.") {
			domain := allowed[2:] // Remove "*."
			// Must have at least one subdomain prefix
			if strings.HasSuffix(host, "."+domain) {
				return true
			}
		}

		// IP range or CIDR matching could be added here in the future
	}

	return false
}

// isMoreRestrictiveMemory compares memory limits and returns true if new is more restrictive
func isMoreRestrictiveMemory(newLimit, currentLimit string) bool {
	newVal := parseMemoryString(newLimit)
	currentVal := parseMemoryString(currentLimit)

	if newVal <= 0 || currentVal <= 0 {
		return false // Invalid format, don't override
	}

	return newVal < currentVal
}

// parseMemoryString parses memory strings like "512M", "1G" into bytes
func parseMemoryString(s string) int64 {
	return ParseMemoryStringHelper(s)
}

// ParseMemoryStringHelper parses memory strings like "512M", "1G" into bytes
// This is exported for use by other packages like sandbox
func ParseMemoryStringHelper(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	var multiplier int64 = 1
	switch {
	case strings.HasSuffix(s, "G"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "K"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "K")
	}

	var val int64
	_, _ = fmt.Sscanf(s, "%d", &val) //nolint:errcheck // parse errors result in zero value
	return val * multiplier
}
