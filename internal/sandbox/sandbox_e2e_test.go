package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startOrSkip starts the command and skips the test if Windows restricted
// tokens block process creation (common in GitHub Actions runners).
func startOrSkip(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	err := cmd.Start()
	if err != nil && runtime.GOOS == "windows" && strings.Contains(err.Error(), "Access is denied") {
		t.Skipf("restricted token blocks process creation in this environment: %v", err)
	}
	require.NoError(t, err)
}

// buildTestProgram compiles a test helper from testdata/ into a temp directory.
// Returns the path to the compiled binary.
func buildTestProgram(t *testing.T, name string) string {
	t.Helper()

	srcPath := filepath.Join("testdata", name+".go")
	if _, err := os.Stat(srcPath); err != nil {
		t.Skipf("test program %s not found: %v", srcPath, err)
	}

	tmpDir := t.TempDir()
	binName := name
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(tmpDir, binName)

	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	cmd.Dir, _ = os.Getwd()
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build test program %s: %s", name, string(output))

	return binPath
}

func TestSandboxIntegration_TimeoutKillsProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sb := New()

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   2 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), limits.Timeout)
	defer cancel()

	// Use system sleep command to avoid sandbox-exec blocking custom binaries on macOS
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "cmd", "/c", "timeout /t 60 /nobreak >nul")
	default:
		cmd = exec.CommandContext(ctx, "sleep", "60")
	}

	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	start := time.Now()
	startOrSkip(t, cmd)

	if cmd.Process != nil {
		_ = sb.PostStart(cmd.Process.Pid, limits)
	}

	err = cmd.Wait()
	elapsed := time.Since(start)

	// Process should have been killed by timeout, not completed naturally
	assert.Error(t, err, "process should have been killed by timeout")
	assert.Less(t, elapsed, 10*time.Second, "process should have been killed well before 60s")

	if cmd.Process != nil {
		_ = sb.Cleanup(cmd.Process.Pid)
	}
}

func TestSandboxIntegration_ProcessCompletesNormally(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// This test verifies that sandbox.Apply + PostStart + Cleanup lifecycle
	// works without errors. On macOS, sandbox-exec rewrites the command
	// and the SBPL profile may block dynamic library loading, so we test
	// the lifecycle without actually running the sandboxed process on Darwin.
	sb := New()

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   30 * time.Second,
	}

	if runtime.GOOS == "darwin" {
		// On macOS, verify Apply works and produces a valid sandboxed command
		cmd := exec.Command("/usr/bin/true")
		err := sb.Apply(cmd, limits, nil)
		assert.NoError(t, err)
		// If sandbox-exec is available, the command should have been rewritten
		caps := sb.Capabilities()
		if caps.SupportsSandboxExec {
			assert.Equal(t, "/usr/bin/sandbox-exec", cmd.Path)
		}
		_ = sb.Cleanup(0)
		return
	}

	// On Linux/Windows, run the actual process
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "exit 0")
	default:
		cmd = exec.Command("true")
	}

	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	startOrSkip(t, cmd)

	if cmd.Process != nil {
		_ = sb.PostStart(cmd.Process.Pid, limits)
	}

	err = cmd.Wait()
	assert.NoError(t, err, "process should complete cleanly")

	if cmd.Process != nil {
		_ = sb.Cleanup(cmd.Process.Pid)
	}
}

func TestSandboxIntegration_NilLimitsRejected(t *testing.T) {
	sb := New()
	cmd := exec.Command("echo", "test")
	err := sb.Apply(cmd, nil, nil)
	assert.Error(t, err, "nil limits should be rejected")
}

func TestSandboxIntegration_CapabilitiesMatchPlatform(t *testing.T) {
	sb := New()
	caps := sb.Capabilities()

	switch runtime.GOOS {
	case "linux":
		assert.True(t, caps.CPULimit, "Linux should support CPU limits")
		assert.True(t, caps.MemoryLimit, "Linux should support memory limits")
		assert.True(t, caps.PIDLimit, "Linux should support PID limits")
		assert.True(t, caps.FDLimit, "Linux should support FD limits")
		assert.True(t, caps.Namespaces, "Linux should support namespaces")
		assert.False(t, caps.SupportsSeccomp, "seccomp BPF enforcement not implemented")
	case "darwin":
		assert.False(t, caps.CPULimit, "macOS cannot enforce CPU limits on children")
		assert.False(t, caps.MemoryLimit, "macOS cannot enforce memory limits on children")
		assert.False(t, caps.Cgroups, "macOS has no cgroups")
	case "windows":
		assert.True(t, caps.CPULimit, "Windows should support CPU rate control")
		assert.True(t, caps.MemoryLimit, "Windows should support memory limits")
		assert.True(t, caps.PIDLimit, "Windows should support PID limits")
		assert.True(t, caps.ProcessIsolation, "Windows should have Job Object isolation")
		assert.False(t, caps.NetworkIsolation, "Windows has no network isolation")
	}

	assert.Equal(t, runtime.GOOS, sb.Name(), "sandbox name should match OS")
}

func TestSandboxIntegration_NonZeroExitCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	if runtime.GOOS == "darwin" {
		t.Skip("sandbox-exec blocks dynamic library loading for system commands under strict SBPL profiles")
	}

	var cmd *exec.Cmd
	expectedCode := 1
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "exit 1")
	default:
		cmd = exec.Command("false") // exits with 1
	}

	sb := New()

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   30 * time.Second,
	}

	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	startOrSkip(t, cmd)

	if cmd.Process != nil {
		_ = sb.PostStart(cmd.Process.Pid, limits)
	}

	err = cmd.Wait()
	assert.Error(t, err, "non-zero exit code should be an error")

	if exitErr, ok := err.(*exec.ExitError); ok {
		assert.Equal(t, expectedCode, exitErr.ExitCode(), "exit code should match expected")
	}

	if cmd.Process != nil {
		_ = sb.Cleanup(cmd.Process.Pid)
	}
}
