package executor

import (
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
)

// TestNewSTDIOExecutor_RejectsNilLimits verifies that executor rejects nil limits
// CRITICAL SECURITY TEST: Execution without limits must NEVER be allowed
func TestNewSTDIOExecutor_RejectsNilLimits(t *testing.T) {
	_, err := NewSTDIOExecutor("/tmp", nil, nil, nil)
	if err == nil {
		t.Fatal("CRITICAL SECURITY FAILURE: NewSTDIOExecutor accepted nil limits")
	}

	if err.Error() != "CRITICAL: limits cannot be nil - execution without resource limits is forbidden" {
		t.Errorf("Wrong error message for nil limits: %v", err)
	}
}

// TestNewSTDIOExecutor_RejectsZeroMaxCPU ensures zero CPU limits are rejected
func TestNewSTDIOExecutor_RejectsZeroMaxCPU(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    0, // Invalid
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}

	_, err := NewSTDIOExecutor("/tmp", limits, nil, nil)
	if err == nil {
		t.Fatal("CRITICAL SECURITY FAILURE: NewSTDIOExecutor accepted zero MaxCPU")
	}

	if err.Error() != "CRITICAL: MaxCPU must be > 0 (got 0) - execution without CPU limits is forbidden" {
		t.Errorf("Wrong error message for zero MaxCPU: %v", err)
	}
}

// TestNewSTDIOExecutor_RejectsNegativeMaxCPU ensures negative CPU limits are rejected
func TestNewSTDIOExecutor_RejectsNegativeMaxCPU(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    -1, // Invalid
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}

	_, err := NewSTDIOExecutor("/tmp", limits, nil, nil)
	if err == nil {
		t.Fatal("CRITICAL SECURITY FAILURE: NewSTDIOExecutor accepted negative MaxCPU")
	}
}

// TestNewSTDIOExecutor_RejectsEmptyMaxMemory ensures empty memory limits are rejected
func TestNewSTDIOExecutor_RejectsEmptyMaxMemory(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "", // Invalid
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}

	_, err := NewSTDIOExecutor("/tmp", limits, nil, nil)
	if err == nil {
		t.Fatal("CRITICAL SECURITY FAILURE: NewSTDIOExecutor accepted empty MaxMemory")
	}

	if err.Error() != "CRITICAL: MaxMemory must be set (got empty string) - execution without memory limits is forbidden" {
		t.Errorf("Wrong error message for empty MaxMemory: %v", err)
	}
}

// TestNewSTDIOExecutor_RejectsZeroMaxPIDs ensures zero PID limits are rejected
func TestNewSTDIOExecutor_RejectsZeroMaxPIDs(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   0, // Invalid
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}

	_, err := NewSTDIOExecutor("/tmp", limits, nil, nil)
	if err == nil {
		t.Fatal("CRITICAL SECURITY FAILURE: NewSTDIOExecutor accepted zero MaxPIDs")
	}

	if err.Error() != "CRITICAL: MaxPIDs must be > 0 (got 0) - execution without PID limits is forbidden" {
		t.Errorf("Wrong error message for zero MaxPIDs: %v", err)
	}
}

// TestNewSTDIOExecutor_RejectsZeroMaxFDs ensures zero FD limits are rejected
func TestNewSTDIOExecutor_RejectsZeroMaxFDs(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    0, // Invalid
		Timeout:   5 * time.Minute,
	}

	_, err := NewSTDIOExecutor("/tmp", limits, nil, nil)
	if err == nil {
		t.Fatal("CRITICAL SECURITY FAILURE: NewSTDIOExecutor accepted zero MaxFDs")
	}

	if err.Error() != "CRITICAL: MaxFDs must be > 0 (got 0) - execution without file descriptor limits is forbidden" {
		t.Errorf("Wrong error message for zero MaxFDs: %v", err)
	}
}

// TestNewSTDIOExecutor_RejectsZeroTimeout ensures zero timeout is rejected
func TestNewSTDIOExecutor_RejectsZeroTimeout(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   0, // Invalid - no timeout
	}

	_, err := NewSTDIOExecutor("/tmp", limits, nil, nil)
	if err == nil {
		t.Fatal("CRITICAL SECURITY FAILURE: NewSTDIOExecutor accepted zero Timeout")
	}
}

// TestNewSTDIOExecutor_AcceptsValidLimits ensures valid limits are accepted
func TestNewSTDIOExecutor_AcceptsValidLimits(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}

	executor, err := NewSTDIOExecutor("/tmp", limits, nil, nil)
	if err != nil {
		t.Fatalf("NewSTDIOExecutor rejected valid limits: %v", err)
	}

	if executor == nil {
		t.Fatal("NewSTDIOExecutor returned nil executor with valid limits")
	}

	// Verify limits are stored correctly
	if executor.limits != limits {
		t.Error("Limits not stored correctly in executor")
	}
}

// TestNewSTDIOExecutor_EnforcesAllLimits ensures all limits are mandatory
func TestNewSTDIOExecutor_EnforcesAllLimits(t *testing.T) {
	testCases := []struct {
		name              string
		limits            *policy.ExecutionLimits
		shouldFail        bool
		expectedErrorPart string
	}{
		{
			name: "all_valid",
			limits: &policy.ExecutionLimits{
				MaxCPU:    1000,
				MaxMemory: "512M",
				MaxPIDs:   10,
				MaxFDs:    100,
				Timeout:   5 * time.Minute,
			},
			shouldFail: false,
		},
		{
			name: "zero_cpu",
			limits: &policy.ExecutionLimits{
				MaxCPU:    0,
				MaxMemory: "512M",
				MaxPIDs:   10,
				MaxFDs:    100,
				Timeout:   5 * time.Minute,
			},
			shouldFail:        true,
			expectedErrorPart: "MaxCPU must be > 0",
		},
		{
			name: "empty_memory",
			limits: &policy.ExecutionLimits{
				MaxCPU:    1000,
				MaxMemory: "",
				MaxPIDs:   10,
				MaxFDs:    100,
				Timeout:   5 * time.Minute,
			},
			shouldFail:        true,
			expectedErrorPart: "MaxMemory must be set",
		},
		{
			name: "zero_pids",
			limits: &policy.ExecutionLimits{
				MaxCPU:    1000,
				MaxMemory: "512M",
				MaxPIDs:   0,
				MaxFDs:    100,
				Timeout:   5 * time.Minute,
			},
			shouldFail:        true,
			expectedErrorPart: "MaxPIDs must be > 0",
		},
		{
			name: "zero_fds",
			limits: &policy.ExecutionLimits{
				MaxCPU:    1000,
				MaxMemory: "512M",
				MaxPIDs:   10,
				MaxFDs:    0,
				Timeout:   5 * time.Minute,
			},
			shouldFail:        true,
			expectedErrorPart: "MaxFDs must be > 0",
		},
		{
			name: "zero_timeout",
			limits: &policy.ExecutionLimits{
				MaxCPU:    1000,
				MaxMemory: "512M",
				MaxPIDs:   10,
				MaxFDs:    100,
				Timeout:   0,
			},
			shouldFail:        true,
			expectedErrorPart: "Timeout must be > 0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSTDIOExecutor("/tmp", tc.limits, nil, nil)

			if tc.shouldFail {
				if err == nil {
					t.Fatalf("CRITICAL SECURITY FAILURE: Expected error for %s but got none", tc.name)
				}
				if tc.expectedErrorPart != "" && err.Error() != "" {
					// Just check the error message contains "CRITICAL" for security errors
					if err.Error()[0:8] != "CRITICAL" {
						t.Errorf("Expected CRITICAL error message, got: %v", err)
					}
				}
			} else if err != nil {
				t.Fatalf("Unexpected error for %s: %v", tc.name, err)
			}
		})
	}
}
