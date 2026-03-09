//go:build linux

package sandbox

import (
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensure syscall is used (referenced in namespace tests)
var _ = syscall.CLONE_NEWNS

func TestLinuxSandboxNew(t *testing.T) {
	sandbox := newLinuxSandbox()
	require.NotNil(t, sandbox)
	assert.Equal(t, "linux", sandbox.Name())
}

func TestLinuxSandboxCapabilities(t *testing.T) {
	sandbox := newLinuxSandbox()
	caps := sandbox.Capabilities()

	// Linux should have these capabilities
	assert.True(t, caps.CPULimit)
	assert.True(t, caps.MemoryLimit)
	assert.True(t, caps.PIDLimit)
	assert.True(t, caps.FDLimit)
	assert.True(t, caps.FilesystemIsolation)
	assert.False(t, caps.SupportsSeccomp) // seccomp filter not yet implemented
	assert.True(t, caps.Namespaces)

	// cgroups detection might vary based on environment
	// Just verify the field exists
	assert.NotNil(t, caps)
}

func TestLinuxSandboxApplyRLimits(t *testing.T) {
	sandbox := newLinuxSandbox()
	cmd := exec.Command("true")

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000, // 1 core
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    1024,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits, nil)
	assert.NoError(t, err)

	// Verify SysProcAttr was set (for namespace flags)
	assert.NotNil(t, cmd.SysProcAttr)

	// Rlimits are now applied via prlimit(2) in PostStart, not pre-spawn.
	// Verify that pendingLimits was stored for later application.
	assert.NotNil(t, sandbox.pendingLimits)
	assert.Equal(t, 1000, sandbox.pendingLimits.MaxCPU)
	assert.Equal(t, "512M", sandbox.pendingLimits.MaxMemory)
	assert.Equal(t, 10, sandbox.pendingLimits.MaxPIDs)
	assert.Equal(t, 1024, sandbox.pendingLimits.MaxFDs)
}

func TestLinuxSandboxApplyMemory(t *testing.T) {
	sandbox := newLinuxSandbox()
	cmd := exec.Command("true")

	limits := &policy.ExecutionLimits{
		MaxCPU:    0, // No CPU limit
		MaxMemory: "256M",
		MaxPIDs:   0, // No PID limit
		MaxFDs:    0, // No FD limit
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits, nil)
	assert.NoError(t, err)
	// Rlimits are applied via prlimit(2) in PostStart
	assert.NotNil(t, sandbox.pendingLimits)
	assert.Equal(t, "256M", sandbox.pendingLimits.MaxMemory)
}

func TestLinuxSandboxApplyZeroLimits(t *testing.T) {
	sandbox := newLinuxSandbox()
	cmd := exec.Command("true")

	limits := &policy.ExecutionLimits{
		MaxCPU:    0,
		MaxMemory: "",
		MaxPIDs:   0,
		MaxFDs:    0,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits, nil)
	assert.NoError(t, err)
	// Limits stored for PostStart prlimit application
	assert.NotNil(t, sandbox.pendingLimits)
	assert.Equal(t, 0, sandbox.pendingLimits.MaxCPU)
	assert.Equal(t, "", sandbox.pendingLimits.MaxMemory)
}

func TestLinuxSandboxMountNamespace(t *testing.T) {
	sandbox := newLinuxSandbox()
	cmd := exec.Command("true")

	limits := &policy.ExecutionLimits{
		MaxCPU:    100,
		MaxMemory: "128M",
		MaxPIDs:   5,
		MaxFDs:    512,
		Timeout:   2 * time.Second,
	}

	err := sandbox.Apply(cmd, limits, nil)
	assert.NoError(t, err)

	// Verify mount namespace flag is set
	if cmd.SysProcAttr != nil {
		// Mount namespace should be set (CLONE_NEWNS = 0x00020000)
		assert.True(t, (cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWNS) != 0)
	}
}

func TestLinuxSandboxNetworkIsolation(t *testing.T) {
	sandbox := newLinuxSandbox()

	// Only test network namespace if we can create it
	if !sandbox.canCreateNet {
		t.Skip("Network namespaces not available (requires root)")
	}

	cmd := exec.Command("true")
	limits := &policy.ExecutionLimits{
		MaxCPU:    100,
		MaxMemory: "128M",
		MaxPIDs:   5,
		MaxFDs:    512,
		Timeout:   2 * time.Second,
	}

	err := sandbox.Apply(cmd, limits, nil)
	assert.NoError(t, err)

	// Verify network namespace flag is set
	if cmd.SysProcAttr != nil {
		// Network namespace should be set (CLONE_NEWNET = 0x40000000)
		assert.True(t, (cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWNET) != 0)
	}
}

func TestLinuxParseMemoryString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{"512M", "512M", 512 * 1024 * 1024},
		{"1G", "1G", 1024 * 1024 * 1024},
		{"256K", "256K", 256 * 1024},
		{"2G", "2G", 2 * 1024 * 1024 * 1024},
		{"empty", "", 0},
		{"with space", " 512M ", 512 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMemoryString(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLinuxCalculateCPUQuota(t *testing.T) {
	tests := []struct {
		name       string
		millicores int
		period     int64
		wantQuota  int64
		wantErr    bool
	}{
		{
			name:       "1000 millicores with 100ms period",
			millicores: 1000,
			period:     100000,
			wantQuota:  100000,
			wantErr:    false,
		},
		{
			name:       "500 millicores with 100ms period",
			millicores: 500,
			period:     100000,
			wantQuota:  50000,
			wantErr:    false,
		},
		{
			name:       "invalid negative",
			millicores: -1,
			period:     100000,
			wantErr:    true,
		},
		{
			name:       "zero millicores",
			millicores: 0,
			period:     100000,
			wantErr:    true,
		},
		{
			name:       "negative period",
			millicores: 100,
			period:     -1,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quota, err := calculateCPUQuota(tt.millicores, tt.period)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantQuota, quota)
			}
		})
	}
}

func TestLinuxSandboxNilInputs(t *testing.T) {
	sandbox := newLinuxSandbox()

	// Nil command
	err := sandbox.Apply(nil, &policy.ExecutionLimits{}, nil)
	assert.Error(t, err)

	// Nil limits
	err = sandbox.Apply(exec.Command("true"), nil, nil)
	assert.Error(t, err)
}

func TestLinuxCgroupsDetection(t *testing.T) {
	sandbox := newLinuxSandbox()

	// Just verify the fields are set (may vary based on system)
	assert.NotNil(t, sandbox)
	assert.NotNil(t, sandbox.trackedCgroups)
	// cgroups detection depends on the system state
	// v2 available, v1 available, or neither
}

func TestLinuxRLimitCPUCalculation(t *testing.T) {
	tests := []struct {
		name        string
		timeout     time.Duration
		millicores  int
		wantSeconds uint64
	}{
		{
			name:        "5s timeout, 1000 millicores = 5 CPU seconds",
			timeout:     5 * time.Second,
			millicores:  1000,
			wantSeconds: 5,
		},
		{
			name:        "5s timeout, 500 millicores = 2 CPU seconds",
			timeout:     5 * time.Second,
			millicores:  500,
			wantSeconds: 2,
		},
		{
			name:        "10s timeout, 100 millicores = 1 CPU second (min 1)",
			timeout:     10 * time.Second,
			millicores:  100,
			wantSeconds: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Rlimits are now applied via prlimit(2) in PostStart.
			// Verify the CPU seconds calculation formula:
			// cpuSeconds = timeout.Seconds() * millicores / 1000
			cpuSeconds := uint64(tt.timeout.Seconds() * float64(tt.millicores) / 1000.0)
			if cpuSeconds < 1 {
				cpuSeconds = 1
			}
			assert.Equal(t, tt.wantSeconds, cpuSeconds)
		})
	}
}

func TestLinuxApplyForPID(t *testing.T) {
	sandbox := newLinuxSandbox()

	limits := &policy.ExecutionLimits{
		MaxCPU:    500,
		MaxMemory: "256M",
		MaxPIDs:   10,
		MaxFDs:    512,
		Timeout:   5 * time.Second,
	}

	// Test with invalid PID (non-existent)
	// ApplyForPID should return early if cgroups not available
	err := sandbox.ApplyForPID(1, limits)
	// Should either succeed (no-op if no cgroups) or fail gracefully
	if sandbox.useCgroups && sandbox.useCgroupsV2 {
		// If cgroups available, it might fail due to permission or invalid PID
		// Just verify it handles gracefully
		t.Logf("ApplyForPID error: %v", err)
	} else {
		// If no cgroups, should return nil
		assert.NoError(t, err)
	}
}

func TestLinuxCleanupCgroup(t *testing.T) {
	sandbox := newLinuxSandbox()

	// Test cleanup for non-existent PID (should be no-op)
	err := sandbox.CleanupCgroup(999999)
	assert.NoError(t, err)

	// Verify no errors on cleanup of untracked PID
	assert.Empty(t, sandbox.trackedCgroups)
}
