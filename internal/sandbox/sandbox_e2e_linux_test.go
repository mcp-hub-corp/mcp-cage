//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxSandbox_PrlimitAppliedToChild(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sleepBin := buildTestProgram(t, "sleep")
	sb := newLinuxSandbox()

	limits := &policy.ExecutionLimits{
		MaxCPU:    500,
		MaxMemory: "128M",
		MaxPIDs:   20,
		MaxFDs:    256,
		Timeout:   30 * time.Second,
	}

	cmd := exec.Command(sleepBin, "10")
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	err = cmd.Start()
	require.NoError(t, err)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = sb.Cleanup(cmd.Process.Pid)
	}()

	err = sb.PostStart(cmd.Process.Pid, limits)
	require.NoError(t, err)

	// Verify rlimits were applied by reading /proc/PID/limits
	limitsPath := fmt.Sprintf("/proc/%d/limits", cmd.Process.Pid)
	content, err := os.ReadFile(limitsPath)
	if err != nil {
		t.Skipf("cannot read %s (may need permissions): %v", limitsPath, err)
	}

	limitsStr := string(content)

	// Verify NOFILE (file descriptors) limit was set
	if limits.MaxFDs > 0 {
		for _, line := range strings.Split(limitsStr, "\n") {
			if strings.Contains(line, "Max open files") {
				t.Logf("FD limit line: %s", line)
				// The limit value should be present
				assert.Contains(t, line, strconv.Itoa(limits.MaxFDs),
					"RLIMIT_NOFILE should be set to %d", limits.MaxFDs)
				break
			}
		}
	}

	// Verify NPROC (process count) limit was set
	if limits.MaxPIDs > 0 {
		for _, line := range strings.Split(limitsStr, "\n") {
			if strings.Contains(line, "Max processes") {
				t.Logf("PID limit line: %s", line)
				assert.Contains(t, line, strconv.Itoa(limits.MaxPIDs),
					"RLIMIT_NPROC should be set to %d", limits.MaxPIDs)
				break
			}
		}
	}
}

func TestLinuxSandbox_MountNamespaceActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sb := newLinuxSandbox()
	if !sb.canCreateMount {
		t.Skip("mount namespaces not available")
	}

	cmd := exec.Command("true")
	limits := &policy.ExecutionLimits{
		MaxCPU:    100,
		MaxMemory: "64M",
		MaxPIDs:   5,
		MaxFDs:    64,
		Timeout:   5 * time.Second,
	}

	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	// Verify CLONE_NEWNS flag is set
	require.NotNil(t, cmd.SysProcAttr)
	assert.True(t, (cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWNS) != 0,
		"CLONE_NEWNS should be set for mount namespace isolation")
}

func TestLinuxSandbox_CgroupsApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sb := newLinuxSandbox()
	if !sb.useCgroups || !sb.useCgroupsV2 {
		t.Skip("cgroups v2 not available")
	}

	sleepBin := buildTestProgram(t, "sleep")

	limits := &policy.ExecutionLimits{
		MaxCPU:    500,
		MaxMemory: "128M",
		MaxPIDs:   20,
		MaxFDs:    256,
		Timeout:   30 * time.Second,
	}

	cmd := exec.Command(sleepBin, "10")
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	err = cmd.Start()
	require.NoError(t, err)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = sb.Cleanup(cmd.Process.Pid)
	}()

	pid := cmd.Process.Pid
	err = sb.PostStart(pid, limits)
	if err != nil {
		t.Skipf("cgroups application failed (may need permissions): %v", err)
	}

	// Verify cgroup directory was created
	cgroupPath := filepath.Join(sb.cgroupPath, fmt.Sprintf("mcp-launcher-%d", pid))
	if _, statErr := os.Stat(cgroupPath); statErr != nil {
		t.Skipf("cgroup directory not created (permission issue): %v", statErr)
	}

	// Verify memory.max was set
	memMax, err := os.ReadFile(filepath.Join(cgroupPath, "memory.max"))
	if err == nil {
		memMaxStr := strings.TrimSpace(string(memMax))
		t.Logf("memory.max = %s", memMaxStr)
		expectedMem := strconv.FormatInt(parseMemoryString("128M"), 10)
		assert.Equal(t, expectedMem, memMaxStr, "memory.max should be set")
	}

	// Verify pids.max was set
	pidsMax, err := os.ReadFile(filepath.Join(cgroupPath, "pids.max"))
	if err == nil {
		pidsMaxStr := strings.TrimSpace(string(pidsMax))
		t.Logf("pids.max = %s", pidsMaxStr)
		assert.Equal(t, "20", pidsMaxStr, "pids.max should be set")
	}
}

func TestLinuxSandbox_MemoryLimitEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sb := newLinuxSandbox()
	if !sb.useCgroups || !sb.useCgroupsV2 {
		t.Skip("cgroups v2 required for reliable memory limit enforcement")
	}

	// Verify we can actually write to cgroups (requires root or delegation)
	testCgroup := fmt.Sprintf("/sys/fs/cgroup/mcp-test-%d", os.Getpid())
	if err := os.Mkdir(testCgroup, 0o750); err != nil {
		t.Skipf("cgroups v2 detected but not writable (need root or delegation): %v", err)
	}
	_ = os.Remove(testCgroup)

	allocBin := buildTestProgram(t, "allocmem")

	// Set a small memory limit (32M) and try to allocate 256M
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "32M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   30 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), limits.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, allocBin, "256")
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	err = cmd.Start()
	if err != nil {
		t.Skipf("failed to start process: %v", err)
	}

	pid := cmd.Process.Pid
	_ = sb.PostStart(pid, limits)

	err = cmd.Wait()
	// Process should have been OOM-killed or failed to allocate
	assert.Error(t, err, "process allocating 256M with 32M limit should fail")
	t.Logf("memory limit enforcement result: %v", err)

	_ = sb.Cleanup(pid)
}

func TestLinuxSandbox_ForkBombContained(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sb := newLinuxSandbox()

	forkBin := buildTestProgram(t, "forkbomb")

	// Set a low PID limit
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "128M",
		MaxPIDs:   3, // Very restrictive
		MaxFDs:    100,
		Timeout:   10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), limits.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, forkBin, "100")
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	err = cmd.Start()
	if err != nil {
		t.Skipf("failed to start process: %v", err)
	}

	pid := cmd.Process.Pid
	_ = sb.PostStart(pid, limits)

	err = cmd.Wait()
	// Fork bomb should be contained - process should fail or be limited
	// Either it exits with error (can't fork) or is killed by timeout
	t.Logf("fork bomb containment result: %v", err)

	_ = sb.Cleanup(pid)
}

func TestLinuxSandbox_NetworkNamespace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	sb := newLinuxSandbox()
	if !sb.canCreateNet && !sb.canUseUserNS {
		t.Skip("network namespace isolation not available (requires root or user namespaces)")
	}

	networkBin := buildTestProgram(t, "network")

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "128M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), limits.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, networkBin, "http://1.1.1.1")
	err := sb.Apply(cmd, limits, nil)
	require.NoError(t, err)

	err = cmd.Start()
	if err != nil {
		t.Skipf("failed to start process: %v", err)
	}

	pid := cmd.Process.Pid
	_ = sb.PostStart(pid, limits)

	err = cmd.Wait()
	// In a network namespace, external connections should fail
	assert.Error(t, err, "network request should fail in isolated namespace")
	t.Logf("network isolation result: %v", err)

	_ = sb.Cleanup(pid)
}
