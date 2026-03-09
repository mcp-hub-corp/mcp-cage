package sandbox

import (
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
)

func TestGetSafeDefaults(t *testing.T) {
	defaults := GetSafeDefaults()

	if defaults == nil {
		t.Fatal("GetSafeDefaults returned nil")
	}

	// Verify all mandatory defaults are set
	if defaults.MaxCPU != DefaultMaxCPU {
		t.Errorf("MaxCPU: expected %d, got %d", DefaultMaxCPU, defaults.MaxCPU)
	}

	if defaults.MaxMemory != DefaultMaxMemory {
		t.Errorf("MaxMemory: expected %s, got %s", DefaultMaxMemory, defaults.MaxMemory)
	}

	if defaults.MaxPIDs != DefaultMaxPIDs {
		t.Errorf("MaxPIDs: expected %d, got %d", DefaultMaxPIDs, defaults.MaxPIDs)
	}

	if defaults.MaxFDs != DefaultMaxFDs {
		t.Errorf("MaxFDs: expected %d, got %d", DefaultMaxFDs, defaults.MaxFDs)
	}

	if defaults.Timeout != DefaultTimeout {
		t.Errorf("Timeout: expected %v, got %v", DefaultTimeout, defaults.Timeout)
	}
}

func TestGetSafeDefaults_CannotBeNil(t *testing.T) {
	// This is a critical security invariant - GetSafeDefaults must NEVER return nil
	defaults := GetSafeDefaults()
	if defaults == nil {
		t.Fatal("CRITICAL: GetSafeDefaults returned nil - violates security invariant")
	}
}

func TestGetSafeDefaults_AllFieldsSet(t *testing.T) {
	defaults := GetSafeDefaults()

	// All fields must be set (non-zero) for security
	if defaults.MaxCPU <= 0 {
		t.Error("MaxCPU must be > 0")
	}

	if defaults.MaxMemory == "" {
		t.Error("MaxMemory must not be empty")
	}

	if defaults.MaxPIDs <= 0 {
		t.Error("MaxPIDs must be > 0")
	}

	if defaults.MaxFDs <= 0 {
		t.Error("MaxFDs must be > 0")
	}

	if defaults.Timeout <= 0 {
		t.Error("Timeout must be > 0")
	}
}

func TestValidateLimits_NilInput(t *testing.T) {
	validated := ValidateLimits(nil)

	if validated == nil {
		t.Fatal("ValidateLimits should not return nil")
	}

	// Should return safe defaults
	if validated.MaxCPU <= 0 {
		t.Errorf("MaxCPU should be set, got %d", validated.MaxCPU)
	}
}

func TestValidateLimits_InvalidMaxCPU(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    -1, // Invalid
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}

	validated := ValidateLimits(limits)

	if validated.MaxCPU <= 0 {
		t.Errorf("ValidateLimits should fix invalid MaxCPU, got %d", validated.MaxCPU)
	}
}

func TestValidateLimits_InvalidMaxMemory(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "", // Invalid
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}

	validated := ValidateLimits(limits)

	if validated.MaxMemory == "" {
		t.Errorf("ValidateLimits should fix invalid MaxMemory, got empty string")
	}
}

func TestValidateLimits_InvalidMaxPIDs(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   0, // Invalid
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}

	validated := ValidateLimits(limits)

	if validated.MaxPIDs <= 0 {
		t.Errorf("ValidateLimits should fix invalid MaxPIDs, got %d", validated.MaxPIDs)
	}
}

func TestValidateLimits_InvalidMaxFDs(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    -1, // Invalid
		Timeout:   5 * time.Minute,
	}

	validated := ValidateLimits(limits)

	if validated.MaxFDs <= 0 {
		t.Errorf("ValidateLimits should fix invalid MaxFDs, got %d", validated.MaxFDs)
	}
}

func TestValidateLimits_InvalidTimeout(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   -1, // Invalid
	}

	validated := ValidateLimits(limits)

	if validated.Timeout <= 0 {
		t.Errorf("ValidateLimits should fix invalid Timeout, got %v", validated.Timeout)
	}
}

func TestValidateLimits_AllFieldsInvalid(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    -1,
		MaxMemory: "",
		MaxPIDs:   -1,
		MaxFDs:    -1,
		Timeout:   -1,
	}

	validated := ValidateLimits(limits)

	if validated.MaxCPU <= 0 || validated.MaxMemory == "" || validated.MaxPIDs <= 0 ||
		validated.MaxFDs <= 0 || validated.Timeout <= 0 {
		t.Error("ValidateLimits should fix all invalid fields")
	}
}

func TestValidateLimits_PreservesValidLimits(t *testing.T) {
	originalLimits := &policy.ExecutionLimits{
		MaxCPU:    2000,
		MaxMemory: "1G",
		MaxPIDs:   50,
		MaxFDs:    500,
		Timeout:   10 * time.Minute,
	}

	validated := ValidateLimits(originalLimits)

	if validated.MaxCPU != 2000 {
		t.Errorf("ValidateLimits changed valid MaxCPU: expected 2000, got %d", validated.MaxCPU)
	}

	if validated.MaxMemory != "1G" {
		t.Errorf("ValidateLimits changed valid MaxMemory: expected 1G, got %s", validated.MaxMemory)
	}

	if validated.MaxPIDs != 50 {
		t.Errorf("ValidateLimits changed valid MaxPIDs: expected 50, got %d", validated.MaxPIDs)
	}

	if validated.MaxFDs != 500 {
		t.Errorf("ValidateLimits changed valid MaxFDs: expected 500, got %d", validated.MaxFDs)
	}

	if validated.Timeout != 10*time.Minute {
		t.Errorf("ValidateLimits changed valid Timeout: expected 10m, got %v", validated.Timeout)
	}
}
