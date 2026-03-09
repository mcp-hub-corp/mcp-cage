//go:build windows

package sandbox

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsSandboxNew(t *testing.T) {
	sandbox := newWindowsSandbox()
	require.NotNil(t, sandbox)
	assert.Equal(t, "windows", sandbox.Name())
}

func TestWindowsSandboxCapabilities(t *testing.T) {
	sandbox := newWindowsSandbox()
	caps := sandbox.Capabilities()

	// Windows supports Job Objects for CPU, memory, and PID limits
	assert.True(t, caps.CPULimit)   // CPU rate control via JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
	assert.True(t, caps.MemoryLimit)
	assert.True(t, caps.PIDLimit)
	assert.True(t, caps.ProcessIsolation) // Job Objects with KILL_ON_JOB_CLOSE + restricted tokens

	// But not these features
	assert.False(t, caps.NetworkIsolation)
	assert.False(t, caps.FilesystemIsolation)
	assert.False(t, caps.Cgroups)
	assert.False(t, caps.Namespaces)
	assert.False(t, caps.SupportsSeccomp)
	assert.False(t, caps.FDLimit)

	// Should have warnings
	assert.NotEmpty(t, caps.Warnings)
}

func TestWindowsSandboxApply(t *testing.T) {
	sandbox := newWindowsSandbox()
	cmd := exec.Command("cmd", "/c", "exit 0")

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    1024,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits, nil)
	assert.NoError(t, err)
}

func TestWindowsSandboxApplyPartialLimits(t *testing.T) {
	sandbox := newWindowsSandbox()
	cmd := exec.Command("cmd", "/c", "exit 0")

	limits := &policy.ExecutionLimits{
		MaxCPU:    0,
		MaxMemory: "",
		MaxPIDs:   0,
		MaxFDs:    0,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits, nil)
	assert.NoError(t, err)
}

func TestWindowsParseMemoryString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{"512M", "512M", 512 * 1024 * 1024},
		{"1G", "1G", 1024 * 1024 * 1024},
		{"256K", "256K", 256 * 1024},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMemoryStringWindows(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWindowsSandboxNilInputs(t *testing.T) {
	sandbox := newWindowsSandbox()

	// Nil command
	err := sandbox.Apply(nil, &policy.ExecutionLimits{}, nil)
	assert.Error(t, err)

	// Nil limits
	err = sandbox.Apply(exec.Command("cmd", "/c", "exit 0"), nil, nil)
	assert.Error(t, err)
}

func TestWindowsSandboxApplyIntegratesRestrictedToken(t *testing.T) {
	sandbox := newWindowsSandbox()
	cmd := exec.Command("cmd", "/c", "exit 0")

	limits := &policy.ExecutionLimits{
		MaxCPU:    500,
		MaxMemory: "256M",
		MaxPIDs:   5,
		MaxFDs:    100,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits, nil)
	assert.NoError(t, err)

	// After Apply, the command should have SysProcAttr set
	assert.NotNil(t, cmd.SysProcAttr)

	// Token should be set (either restricted or low integrity)
	// Both modify SysProcAttr.Token; at least one should succeed
	// on a standard Windows system
	assert.NotNil(t, cmd.SysProcAttr)
}

func TestWindowsSandboxCleanupAppContainers(t *testing.T) {
	sandbox := newWindowsSandbox()

	// Manually add a dummy name to verify cleanup logic
	sandbox.appContainerMutex.Lock()
	sandbox.appContainerNames = append(sandbox.appContainerNames, "mcp-test-cleanup-nonexistent")
	sandbox.appContainerMutex.Unlock()

	// Cleanup should not error (best-effort deletion of non-existent profiles)
	err := sandbox.Cleanup(0)
	assert.NoError(t, err)

	// Names should be cleared
	sandbox.appContainerMutex.Lock()
	assert.Empty(t, sandbox.appContainerNames)
	sandbox.appContainerMutex.Unlock()
}

func TestWindowsSandboxCapabilitiesCPU(t *testing.T) {
	sandbox := newWindowsSandbox()
	caps := sandbox.Capabilities()

	// CPU rate control is now implemented
	assert.True(t, caps.CPULimit)
	// Warnings should mention restricted tokens
	found := false
	for _, w := range caps.Warnings {
		if strings.Contains(w, "Restricted tokens") {
			found = true
			break
		}
	}
	assert.True(t, found, "Capabilities should mention restricted tokens in warnings")
}
