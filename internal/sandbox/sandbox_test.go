package sandbox

import (
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	sandbox := New()
	require.NotNil(t, sandbox)

	// Check that we get a platform-specific sandbox
	switch runtime.GOOS {
	case "linux":
		assert.Equal(t, "linux", sandbox.Name())
	case "darwin":
		assert.Equal(t, "darwin", sandbox.Name())
	case "windows":
		assert.Equal(t, "windows", sandbox.Name())
	default:
		assert.Equal(t, "noop", sandbox.Name())
	}
}

func TestSandboxCapabilities(t *testing.T) {
	sandbox := New()
	caps := sandbox.Capabilities()

	// All sandboxes should have these basic capabilities
	assert.NotNil(t, caps)

	// Platform-specific checks
	switch runtime.GOOS {
	case "linux":
		assert.True(t, caps.CPULimit)
		assert.True(t, caps.MemoryLimit)
		assert.True(t, caps.PIDLimit)
		assert.True(t, caps.FDLimit)
	case "darwin":
		// macOS cannot enforce resource limits on child processes
		assert.False(t, caps.CPULimit)
		assert.False(t, caps.MemoryLimit)
		assert.False(t, caps.Cgroups)
	case "windows":
		assert.False(t, caps.NetworkIsolation)
	}
}

func TestDiagnose(t *testing.T) {
	info := Diagnose()

	// Verify basic diagnostic info
	assert.NotEmpty(t, info.OS)
	assert.NotEmpty(t, info.Arch)
	assert.NotNil(t, info.Capabilities)

	// OS should match runtime
	assert.Equal(t, runtime.GOOS, info.OS)
	assert.Equal(t, runtime.GOARCH, info.Arch)
}

func TestDiagnoseLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	info := Diagnose()

	// Linux should have certain capabilities
	assert.True(t, info.Capabilities.CPULimit)
	assert.True(t, info.Capabilities.MemoryLimit)
	assert.True(t, info.Capabilities.PIDLimit)
	assert.True(t, info.Capabilities.FDLimit)
	assert.True(t, info.Capabilities.FilesystemIsolation)

	// cgroups version should be detected
	assert.NotEmpty(t, info.CgroupsVersion)
	assert.True(t, info.CgroupsVersion == "v1" || info.CgroupsVersion == "v2" || info.CgroupsVersion == "unavailable")
}

func TestDiagnoseDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific test")
	}

	info := Diagnose()

	// macOS does not have Linux features
	assert.False(t, info.Capabilities.Cgroups)
	assert.False(t, info.Capabilities.Namespaces)
	assert.False(t, info.Capabilities.SupportsSeccomp)

	// macOS cannot enforce resource limits on child processes
	// (Setrlimit applies to the parent on macOS)
	assert.False(t, info.Capabilities.CPULimit)
	assert.False(t, info.Capabilities.MemoryLimit)

	// sandbox-exec may provide filesystem/network isolation
	// (depends on system availability)
}

func TestDiagnoseWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}

	info := Diagnose()

	// Windows should not have these
	assert.False(t, info.Capabilities.NetworkIsolation)
	assert.False(t, info.Capabilities.Cgroups)
	assert.False(t, info.Capabilities.Namespaces)
	assert.True(t, info.Capabilities.CPULimit)         // CPU rate control via Job Objects
	assert.True(t, info.Capabilities.ProcessIsolation) // Job Objects + restricted tokens
}

func TestParseMemory(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{
			name:    "512M",
			input:   "512M",
			want:    512 * 1024 * 1024,
			wantErr: false,
		},
		{
			name:    "1G",
			input:   "1G",
			want:    1024 * 1024 * 1024,
			wantErr: false,
		},
		{
			name:    "256K",
			input:   "256K",
			want:    256 * 1024,
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    0,
			wantErr: true,
		},
		{
			name:    "invalid",
			input:   "invalid",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMemory(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestApplyWithNilInputs(t *testing.T) {
	sandbox := New()
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    1024,
		Timeout:   5 * time.Second,
	}

	// Test with nil command
	err := sandbox.Apply(nil, limits, nil)
	assert.Error(t, err)

	// Test with nil limits
	cmd := exec.Command("echo", "test")
	err = sandbox.Apply(cmd, nil, nil)
	assert.Error(t, err)
}

func TestApplyBasic(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Simplified test for non-Windows platforms")
	}

	sandbox := New()
	cmd := exec.Command("echo", "test")

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    1024,
		Timeout:   5 * time.Second,
	}

	// Should not error on basic apply
	err := sandbox.Apply(cmd, limits, nil)
	assert.NoError(t, err)

	// Command should still be valid
	assert.NotNil(t, cmd)
}

func TestNoOpSandbox(t *testing.T) {
	sandbox := &NoOpSandbox{}

	assert.Equal(t, "noop", sandbox.Name())

	caps := sandbox.Capabilities()
	assert.NotNil(t, caps)
	assert.False(t, caps.CPULimit)
	assert.Len(t, caps.Warnings, 1)

	// Should not error when applying
	cmd := exec.Command("echo", "test")
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

func TestDetectCgroupsVersion(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-specific test")
	}

	version := detectCgroupsVersion()
	// Should return one of these values
	assert.True(t, version == "v1" || version == "v2" || version == "unavailable")
}

func TestSandboxConcurrency(t *testing.T) {
	// Test that sandbox can be used concurrently
	sandbox := New()
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    1024,
		Timeout:   5 * time.Second,
	}

	done := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func() {
			cmd := exec.Command("echo", "test")
			done <- sandbox.Apply(cmd, limits, nil)
		}()
	}

	for i := 0; i < 10; i++ {
		err := <-done
		assert.NoError(t, err)
	}
}
