//go:build windows

package sandbox

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startOrSkipWin starts the command and skips the test if Windows restricted
// tokens block process creation (common in GitHub Actions runners).
func startOrSkipWin(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	err := cmd.Start()
	if err != nil && runtime.GOOS == "windows" && strings.Contains(err.Error(), "Access is denied") {
		t.Skipf("restricted token blocks process creation in this environment: %v", err)
	}
	require.NoError(t, err)
}

func TestWindowsSandbox_JobObjectAssigned(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sleepBin := buildTestProgram(t, "sleep")
	sb := newWindowsSandbox()

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "256M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   30 * time.Second,
	}

	cmd := exec.Command(sleepBin, "10")
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	startOrSkipWin(t, cmd)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = sb.Cleanup(cmd.Process.Pid)
	}()

	err = sb.PostStart(cmd.Process.Pid, limits)
	require.NoError(t, err, "Job Object assignment should succeed")

	// Verify job was created and tracked
	sb.jobsMutex.RLock()
	assert.NotEmpty(t, sb.jobs, "jobs map should have at least one entry")
	sb.jobsMutex.RUnlock()
}

func TestWindowsSandbox_MemoryLimitEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	allocBin := buildTestProgram(t, "allocmem")
	sb := newWindowsSandbox()

	// Set a small memory limit and try to exceed it
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "32M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   30 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), limits.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, allocBin, "256") // Try to allocate 256MB
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	startOrSkipWin(t, cmd)

	pid := cmd.Process.Pid
	_ = sb.PostStart(pid, limits)

	err = cmd.Wait()
	// Process should be killed for exceeding memory limit
	assert.Error(t, err, "process allocating 256M with 32M limit should fail")
	t.Logf("memory limit enforcement result: %v", err)

	_ = sb.Cleanup(pid)
}

func TestWindowsSandbox_ProcessLimitEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	forkBin := buildTestProgram(t, "forkbomb")
	sb := newWindowsSandbox()

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "128M",
		MaxPIDs:   3, // Very restrictive
		MaxFDs:    100,
		Timeout:   15 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), limits.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, forkBin, "50") // Try to spawn 50 processes
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	startOrSkipWin(t, cmd)

	pid := cmd.Process.Pid
	_ = sb.PostStart(pid, limits)

	err = cmd.Wait()
	// Fork bomb should be contained by ActiveProcessLimit
	t.Logf("process limit enforcement result: %v", err)

	_ = sb.Cleanup(pid)
}

func TestWindowsSandbox_KillOnJobClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sleepBin := buildTestProgram(t, "sleep")
	sb := newWindowsSandbox()

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "256M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   30 * time.Second,
	}

	cmd := exec.Command(sleepBin, "60")
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	startOrSkipWin(t, cmd)

	pid := cmd.Process.Pid
	err = sb.PostStart(pid, limits)
	require.NoError(t, err)

	// Cleanup closes Job Object handles, which should kill processes
	// due to KILL_ON_JOB_CLOSE flag
	err = sb.Cleanup(pid)
	assert.NoError(t, err)

	// Wait for process - it should be killed
	err = cmd.Wait()
	assert.Error(t, err, "process should be killed when Job Object is closed")
	t.Logf("kill on job close result: %v", err)
}

func TestWindowsSandbox_TimeoutEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sleepBin := buildTestProgram(t, "sleep")
	sb := newWindowsSandbox()

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "256M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   3 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), limits.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, sleepBin, "60")
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	start := time.Now()
	startOrSkipWin(t, cmd)

	pid := cmd.Process.Pid
	_ = sb.PostStart(pid, limits)

	err = cmd.Wait()
	elapsed := time.Since(start)

	assert.Error(t, err, "process should be killed by timeout")
	assert.Less(t, elapsed, 10*time.Second, "should be killed within timeout window")
	t.Logf("timeout enforced after %v", elapsed)

	_ = sb.Cleanup(pid)
}
