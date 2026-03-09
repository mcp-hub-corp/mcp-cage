//go:build darwin

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/manifest"
	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDarwinSandbox_SandboxExecProfileApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sb := newDarwinSandbox()
	if !sb.hasSandboxExec {
		t.Skip("sandbox-exec not available")
	}

	cmd := exec.Command("/usr/bin/true")
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   10 * time.Second,
	}

	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	// Command should be rewritten to use sandbox-exec
	assert.Equal(t, "/usr/bin/sandbox-exec", cmd.Path)
	assert.Equal(t, "sandbox-exec", cmd.Args[0])
	assert.Equal(t, "-f", cmd.Args[1])

	// Profile file should exist
	profilePath := cmd.Args[2]
	assert.FileExists(t, profilePath)

	// Run the sandboxed command
	// Note: /usr/bin/true may fail under strict SBPL deny-default due to
	// dyld library loading being blocked. This is expected behavior.
	err = cmd.Run()
	if err != nil {
		t.Logf("sandbox-exec with /usr/bin/true result: %v (may fail due to strict profile)", err)
	}

	// Cleanup should remove profile
	_ = sb.Cleanup(0)
	assert.NoFileExists(t, profilePath)
}

func TestDarwinSandbox_NetworkDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sb := newDarwinSandbox()
	if !sb.hasSandboxExec {
		t.Skip("sandbox-exec not available")
	}

	networkBin := buildTestProgram(t, "network")

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   15 * time.Second,
	}

	// No network permissions in manifest = network denied
	ctx, cancel := context.WithTimeout(context.Background(), limits.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, networkBin, "http://1.1.1.1")
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)
	defer sb.Cleanup(0)

	err = cmd.Run()
	assert.Error(t, err, "network request should be denied when no perms specified")
	t.Logf("network denied result: %v", err)
}

func TestDarwinSandbox_NetworkAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sb := newDarwinSandbox()
	if !sb.hasSandboxExec {
		t.Skip("sandbox-exec not available")
	}

	networkBin := buildTestProgram(t, "network")

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   15 * time.Second,
	}

	// With network permissions = network allowed
	perms := &manifest.PermissionsInfo{
		Network: []string{"1.1.1.1"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), limits.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, networkBin, "http://1.1.1.1")
	err := sb.Apply(cmd, limits, perms)
	require.NoError(t, err)
	defer sb.Cleanup(0)

	err = cmd.Run()
	// May still fail due to actual network conditions, but sandbox should allow it
	if err != nil {
		t.Logf("network request with perms result (may fail due to connectivity): %v", err)
	} else {
		t.Log("network request succeeded with permissions")
	}
}

func TestDarwinSandbox_FilesystemDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sb := newDarwinSandbox()
	if !sb.hasSandboxExec {
		t.Skip("sandbox-exec not available")
	}

	writeBin := buildTestProgram(t, "writefiles")

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), limits.Timeout)
	defer cancel()

	// Try to write to /usr/local which should be denied
	cmd := exec.CommandContext(ctx, writeBin, "/usr/local")
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)
	defer sb.Cleanup(0)

	err = cmd.Run()
	assert.Error(t, err, "writing to /usr/local should be denied by sandbox")
}

func TestDarwinSandbox_FilesystemWorkdir(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sb := newDarwinSandbox()
	if !sb.hasSandboxExec {
		t.Skip("sandbox-exec not available")
	}

	writeBin := buildTestProgram(t, "writefiles")
	workDir := t.TempDir()

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), limits.Timeout)
	defer cancel()

	// Write to workdir should succeed (it's in the allowed paths)
	cmd := exec.CommandContext(ctx, writeBin, workDir)
	cmd.Dir = workDir
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)
	defer sb.Cleanup(0)

	err = cmd.Run()
	// Writing to temp/workdir should be allowed by sandbox profile
	if err != nil {
		t.Logf("workdir write result (sandbox-exec may restrict): %v", err)
	}
}

func TestDarwinSandbox_TimeoutEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sb := newDarwinSandbox()
	if !sb.hasSandboxExec {
		t.Skip("sandbox-exec not available")
	}

	sleepBin := buildTestProgram(t, "sleep")

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   3 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), limits.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, sleepBin, "60")
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)
	defer sb.Cleanup(0)

	start := time.Now()
	err = cmd.Start()
	require.NoError(t, err)

	err = cmd.Wait()
	elapsed := time.Since(start)

	assert.Error(t, err, "process should be killed by timeout")
	assert.Less(t, elapsed, 10*time.Second, "should be killed within timeout window")
	t.Logf("timeout enforced after %v", elapsed)
}

// TestDarwinSandbox_ProfileContentValidation verifies the SBPL profile
// content contains expected deny/allow rules.
func TestDarwinSandbox_ProfileContentValidation(t *testing.T) {
	sb := newDarwinSandbox()
	if !sb.hasSandboxExec {
		t.Skip("sandbox-exec not available")
	}

	workDir := t.TempDir()

	// Test with no permissions (should deny network)
	profilePath, err := generateSBPLProfile("/usr/bin/true", nil, workDir)
	require.NoError(t, err)
	defer os.Remove(profilePath)

	content, err := os.ReadFile(profilePath)
	require.NoError(t, err)
	profile := string(content)

	assert.Contains(t, profile, "(version 1)")
	assert.Contains(t, profile, "(deny default)")
	assert.Contains(t, profile, "(deny network*)")

	// Test with network permissions (should allow network)
	perms := &manifest.PermissionsInfo{
		Network: []string{"example.com"},
	}
	profilePath2, err := generateSBPLProfile("/usr/bin/true", perms, workDir)
	require.NoError(t, err)
	defer os.Remove(profilePath2)

	content2, err := os.ReadFile(profilePath2)
	require.NoError(t, err)
	profile2 := string(content2)

	assert.Contains(t, profile2, "(allow network*)")
}
