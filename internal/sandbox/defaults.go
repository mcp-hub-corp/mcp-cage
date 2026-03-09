package sandbox

import (
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
)

// Mandatory default limits - NEVER execute without these
// These constants define the absolute minimum safe defaults that ALWAYS apply
const (
	// DefaultMaxCPU: 1 core (1000 millicores) - provides reasonable performance for most MCP servers
	DefaultMaxCPU = 1000

	// DefaultMaxMemory: 512MB - suitable for typical MCP server operations
	DefaultMaxMemory = "512M"

	// DefaultMaxPIDs: 32 - prevents fork bombs while allowing reasonable subprocess operations
	DefaultMaxPIDs = 32

	// DefaultMaxFDs: 256 - prevents file descriptor exhaustion attacks
	DefaultMaxFDs = 256

	// DefaultTimeout: 5 minutes - prevents infinite/runaway processes
	DefaultTimeout = 5 * time.Minute
)

// GetSafeDefaults returns mandatory safe defaults for execution limits
// These defaults are ALWAYS applied unless explicitly overridden by stricter limits from manifests
// or policy configuration. This function NEVER returns nil or incomplete limits.
//
// CRITICAL SECURITY INVARIANT: Every code path must have explicit limits set before execution.
// These defaults ensure that even in cases of misconfiguration, the system remains secure.
func GetSafeDefaults() *policy.ExecutionLimits {
	return &policy.ExecutionLimits{
		MaxCPU:    DefaultMaxCPU,
		MaxMemory: DefaultMaxMemory,
		MaxPIDs:   DefaultMaxPIDs,
		MaxFDs:    DefaultMaxFDs,
		Timeout:   DefaultTimeout,
	}
}

// ValidateLimits ensures all limits are set and valid
// Returns the original limits if valid, or minimum safe defaults if not
// This function is used as a final safeguard to ensure incomplete limit configurations
// are replaced with known-safe minimums
func ValidateLimits(limits *policy.ExecutionLimits) *policy.ExecutionLimits {
	if limits == nil {
		return GetSafeDefaults()
	}

	// Check and fix each limit independently
	if limits.MaxCPU <= 0 {
		limits.MaxCPU = DefaultMaxCPU / 10 // 100 millicores minimum
	}

	if limits.MaxMemory == "" {
		limits.MaxMemory = "256M" // 256MB minimum
	}

	if limits.MaxPIDs <= 0 {
		limits.MaxPIDs = 10 // 10 PIDs minimum
	}

	if limits.MaxFDs <= 0 {
		limits.MaxFDs = 64 // 64 FDs minimum
	}

	if limits.Timeout <= 0 {
		limits.Timeout = 1 * time.Minute // 1 minute minimum
	}

	return limits
}
