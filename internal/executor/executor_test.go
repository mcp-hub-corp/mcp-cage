package executor

import (
	"context"
	"testing"
	"time"

	"github.com/security-mcp/mcp-client/internal/manifest"
	"github.com/security-mcp/mcp-client/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSTDIOExecutor(t *testing.T) {
	workDir := t.TempDir()
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}
	env := map[string]string{"TEST": "value"}

	executor, err := NewSTDIOExecutor(workDir, limits, nil, env)
	require.NoError(t, err)
	require.NotNil(t, executor)
	assert.Equal(t, workDir, executor.workDir)
	assert.Equal(t, limits, executor.limits)
	assert.Equal(t, env, executor.env)
}

func TestNewSTDIOExecutor_EmptyWorkDir(t *testing.T) {
	limits := &policy.ExecutionLimits{Timeout: time.Minute}
	_, err := NewSTDIOExecutor("", limits, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "work directory")
}

func TestNewSTDIOExecutor_NilLimits(t *testing.T) {
	_, err := NewSTDIOExecutor(t.TempDir(), nil, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "limits")
}

func TestExecute_NilEntrypoint(t *testing.T) {
	executor, _ := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		Timeout: time.Second,
	}, nil, nil)

	ctx := context.Background()
	err := executor.Execute(ctx, nil, t.TempDir())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entrypoint")
}

func TestExecute_EmptyBundlePath(t *testing.T) {
	executor, _ := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		Timeout: time.Second,
	}, nil, nil)

	entrypoint := &manifest.Entrypoint{Command: "test"}
	ctx := context.Background()
	err := executor.Execute(ctx, entrypoint, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bundle path")
}

func TestExecute_CommandNotFound(t *testing.T) {
	executor, _ := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		Timeout: time.Second,
	}, nil, nil)

	entrypoint := &manifest.Entrypoint{
		Command: "nonexistent_command_xyz",
	}

	ctx := context.Background()
	err := executor.Execute(ctx, entrypoint, t.TempDir())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSTDIOExecutor_EnvironmentHandling(t *testing.T) {
	executor, err := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   32,
		MaxFDs:    256,
		Timeout:   time.Minute,
	}, nil, map[string]string{
		"KEY1": "value1",
		"KEY2": "value2",
	})
	require.NoError(t, err)
	assert.NotNil(t, executor)
	assert.Equal(t, "value1", executor.env["KEY1"])
	assert.Equal(t, "value2", executor.env["KEY2"])
}

func TestSTDIOExecutor_EmptyEnvironment(t *testing.T) {
	executor, err := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   32,
		MaxFDs:    256,
		Timeout:   time.Minute,
	}, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, executor)
	assert.Nil(t, executor.env)
}

func TestSetLogger(t *testing.T) {
	executor, err := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   32,
		MaxFDs:    256,
		Timeout:   time.Minute,
	}, nil, nil)
	require.NoError(t, err)

	// Should not panic
	executor.SetLogger(nil)
	require.NotNil(t, executor)
}

func TestBuildEnv_OnlyPassesExplicitVars(t *testing.T) {
	// SECURITY: Verify buildEnv() does NOT inherit os.Environ().
	// Only explicitly passed env vars should appear in the output.
	executor, err := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   32,
		MaxFDs:    256,
		Timeout:   time.Minute,
	}, nil, map[string]string{
		"ALLOWED_VAR": "allowed_value",
	})
	require.NoError(t, err)

	envSlice := executor.buildEnv()

	// Should contain only the explicitly passed var
	assert.Equal(t, 1, len(envSlice))
	assert.Contains(t, envSlice, "ALLOWED_VAR=allowed_value")

	// Should NOT contain parent process env vars like PATH, HOME, etc.
	for _, e := range envSlice {
		assert.NotContains(t, e, "PATH=")
		assert.NotContains(t, e, "HOME=")
	}
}

func TestBuildEnv_EmptyEnvProducesEmptySlice(t *testing.T) {
	executor, err := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   32,
		MaxFDs:    256,
		Timeout:   time.Minute,
	}, nil, nil)
	require.NoError(t, err)

	envSlice := executor.buildEnv()
	assert.Empty(t, envSlice)
}
