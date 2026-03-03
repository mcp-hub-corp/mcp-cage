//go:build darwin

package sandbox

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/security-mcp/mcp-client/internal/manifest"
	"github.com/security-mcp/mcp-client/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDarwinSandboxNew(t *testing.T) {
	sandbox := newDarwinSandbox()
	require.NotNil(t, sandbox)
	assert.Equal(t, "darwin", sandbox.Name())
}

func TestDarwinSandboxCapabilities(t *testing.T) {
	sandbox := newDarwinSandbox()
	caps := sandbox.Capabilities()

	// macOS does NOT support rlimit-based resource limits on child processes
	// (Setrlimit applies to the parent, not the child)
	assert.False(t, caps.CPULimit)
	assert.False(t, caps.MemoryLimit)
	assert.False(t, caps.PIDLimit)
	assert.False(t, caps.FDLimit)

	// No Linux-specific features
	assert.False(t, caps.Cgroups)
	assert.False(t, caps.Namespaces)
	assert.False(t, caps.SupportsSeccomp)

	// sandbox-exec availability depends on system
	if sandbox.hasSandboxExec {
		assert.True(t, caps.NetworkIsolation)
		assert.True(t, caps.FilesystemIsolation)
		assert.True(t, caps.SupportsSandboxExec)
	} else {
		assert.False(t, caps.NetworkIsolation)
		assert.False(t, caps.FilesystemIsolation)
		assert.False(t, caps.SupportsSandboxExec)
	}

	// Should have warnings
	assert.NotEmpty(t, caps.Warnings)
}

func TestDarwinSandboxApply(t *testing.T) {
	sandbox := newDarwinSandbox()
	cmd := exec.Command("true")

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    1024,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits, nil)
	assert.NoError(t, err)

	// If sandbox-exec available, command should be rewritten
	if sandbox.hasSandboxExec {
		assert.Equal(t, "/usr/bin/sandbox-exec", cmd.Path)
		assert.Equal(t, "sandbox-exec", cmd.Args[0])
		assert.Equal(t, "-f", cmd.Args[1])
		// Profile path should exist
		assert.FileExists(t, cmd.Args[2])
	}
}

func TestDarwinSandboxApplyWithPerms(t *testing.T) {
	sandbox := newDarwinSandbox()
	if !sandbox.hasSandboxExec {
		t.Skip("sandbox-exec not available")
	}

	cmd := exec.Command("/usr/bin/true")
	cmd.Dir = t.TempDir()

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    1024,
		Timeout:   5 * time.Second,
	}

	perms := &manifest.PermissionsInfo{
		Network:    []string{"example.com"},
		Subprocess: false,
		FileSystem: []string{"/tmp/test"},
	}

	err := sandbox.Apply(cmd, limits, perms)
	assert.NoError(t, err)
	assert.Equal(t, "/usr/bin/sandbox-exec", cmd.Path)
}

func TestDarwinSandboxCleanup(t *testing.T) {
	sandbox := newDarwinSandbox()
	if !sandbox.hasSandboxExec {
		t.Skip("sandbox-exec not available")
	}

	cmd := exec.Command("/usr/bin/true")
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    1024,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits, nil)
	require.NoError(t, err)

	// Profile file should exist
	profilePath := sandbox.profilePath
	assert.NotEmpty(t, profilePath)
	assert.FileExists(t, profilePath)

	// Cleanup should remove it
	err = sandbox.Cleanup(0)
	assert.NoError(t, err)
	assert.NoFileExists(t, profilePath)
	assert.Empty(t, sandbox.profilePath)
}

func TestDarwinSandboxPostStart(t *testing.T) {
	sandbox := newDarwinSandbox()
	err := sandbox.PostStart(1234, &policy.ExecutionLimits{})
	assert.NoError(t, err)
}

func TestDarwinParseMemoryString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{"512M", "512M", 512 * 1024 * 1024},
		{"1G", "1G", 1024 * 1024 * 1024},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMemoryStringDarwin(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDarwinSandboxNilInputs(t *testing.T) {
	sandbox := newDarwinSandbox()

	// Nil command
	err := sandbox.Apply(nil, &policy.ExecutionLimits{}, nil)
	assert.Error(t, err)

	// Nil limits
	err = sandbox.Apply(exec.Command("true"), nil, nil)
	assert.Error(t, err)
}

func TestGenerateSBPLProfile(t *testing.T) {
	workDir := t.TempDir()

	t.Run("default deny", func(t *testing.T) {
		profilePath, err := generateSBPLProfile("/usr/bin/true", nil, workDir)
		require.NoError(t, err)
		defer os.Remove(profilePath)

		content, err := os.ReadFile(profilePath)
		require.NoError(t, err)

		profile := string(content)
		assert.Contains(t, profile, "(version 1)")
		assert.Contains(t, profile, "(deny default)")
		assert.Contains(t, profile, "(deny network*)")
	})

	t.Run("with network permissions", func(t *testing.T) {
		perms := &manifest.PermissionsInfo{
			Network: []string{"example.com"},
		}

		profilePath, err := generateSBPLProfile("/usr/bin/true", perms, workDir)
		require.NoError(t, err)
		defer os.Remove(profilePath)

		content, err := os.ReadFile(profilePath)
		require.NoError(t, err)

		profile := string(content)
		assert.Contains(t, profile, "(allow network*)")
		assert.NotContains(t, profile, "(deny network*)")
	})

	t.Run("with filesystem permissions", func(t *testing.T) {
		perms := &manifest.PermissionsInfo{
			FileSystem: []string{"/opt/data", "/var/log"},
		}

		profilePath, err := generateSBPLProfile("/usr/bin/true", perms, workDir)
		require.NoError(t, err)
		defer os.Remove(profilePath)

		content, err := os.ReadFile(profilePath)
		require.NoError(t, err)

		profile := string(content)
		assert.Contains(t, profile, "/opt/data")
		assert.Contains(t, profile, "/var/log")
	})

	t.Run("subprocess denied", func(t *testing.T) {
		perms := &manifest.PermissionsInfo{
			Subprocess: false,
		}

		profilePath, err := generateSBPLProfile("/usr/bin/true", perms, workDir)
		require.NoError(t, err)
		defer os.Remove(profilePath)

		content, err := os.ReadFile(profilePath)
		require.NoError(t, err)

		profile := string(content)
		assert.Contains(t, profile, "Subprocess restricted")
	})

	t.Run("includes work directory", func(t *testing.T) {
		profilePath, err := generateSBPLProfile("/usr/bin/true", nil, workDir)
		require.NoError(t, err)
		defer os.Remove(profilePath)

		content, err := os.ReadFile(profilePath)
		require.NoError(t, err)

		profile := string(content)
		// Work dir should be allowed for read/write
		assert.True(t, strings.Contains(profile, workDir) || strings.Contains(profile, "private/"))
	})
}

func TestGenerateSBPLProfile_ReadOnlyPaths(t *testing.T) {
	workDir := t.TempDir()

	t.Run("read-only filesystem paths", func(t *testing.T) {
		perms := &manifest.PermissionsInfo{
			FileSystemRead: []string{"/opt/readonly", "/var/data"},
		}

		profilePath, err := generateSBPLProfile("/usr/bin/true", perms, workDir)
		require.NoError(t, err)
		defer os.Remove(profilePath)

		content, err := os.ReadFile(profilePath)
		require.NoError(t, err)

		profile := string(content)
		// Should have file-read* only (no file-write*)
		assert.Contains(t, profile, "Read-only filesystem paths")
		assert.Contains(t, profile, "(allow file-read* (subpath \"/opt/readonly\"))")
		assert.Contains(t, profile, "(allow file-read* (subpath \"/var/data\"))")
	})

	t.Run("mixed read and write paths", func(t *testing.T) {
		perms := &manifest.PermissionsInfo{
			FileSystem:     []string{"/tmp/rw"},
			FileSystemRead: []string{"/opt/ro"},
		}

		profilePath, err := generateSBPLProfile("/usr/bin/true", perms, workDir)
		require.NoError(t, err)
		defer os.Remove(profilePath)

		content, err := os.ReadFile(profilePath)
		require.NoError(t, err)

		profile := string(content)
		// Write paths get file-read* file-write*
		assert.Contains(t, profile, "(allow file-read* file-write* (subpath \"/tmp/rw\"))")
		// Read paths get file-read* only
		assert.Contains(t, profile, "(allow file-read* (subpath \"/opt/ro\"))")
	})

	t.Run("no read-only paths", func(t *testing.T) {
		perms := &manifest.PermissionsInfo{
			FileSystem: []string{"/tmp/rw"},
		}

		profilePath, err := generateSBPLProfile("/usr/bin/true", perms, workDir)
		require.NoError(t, err)
		defer os.Remove(profilePath)

		content, err := os.ReadFile(profilePath)
		require.NoError(t, err)

		profile := string(content)
		assert.NotContains(t, profile, "Read-only filesystem paths")
	})
}

func TestEscapeSBPLPath(t *testing.T) {
	// Basic path should pass through
	assert.Equal(t, "/usr/bin/test", escapeSBPLPath("/usr/bin/test"))
}
