//go:build darwin

package sandbox

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/mcp-hub-corp/mcp-cage/internal/manifest"
	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
)

func init() {
	// Register Darwin sandbox factory function
	platformNewSandbox = func() Sandbox {
		return newDarwinSandbox()
	}
}

// DarwinSandbox provides process isolation on macOS using sandbox-exec (seatbelt).
//
// Previous implementation used syscall.Setrlimit which is a BUG: Setrlimit applies
// to the PARENT process (mcp-cage itself), not the child. macOS SysProcAttr does
// not have an Rlimits field like Linux.
//
// The correct approach is to use sandbox-exec with SBPL profiles, which provides:
//   - Filesystem isolation (deny-by-default with allowlist)
//   - Network isolation (deny all or allow all)
//   - Process execution control
//
// Timeout enforcement is handled by the executor via context.WithTimeout.
type DarwinSandbox struct {
	hasSandboxExec bool
	logger         *slog.Logger
	mu             sync.Mutex
	// profilePath tracks the temp profile file for cleanup
	profilePath string
}

func newDarwinSandbox() *DarwinSandbox {
	logger := slog.Default()

	hasSandboxExec := false
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err == nil {
		hasSandboxExec = true
		logger.Debug("sandbox-exec detected at /usr/bin/sandbox-exec")
	} else {
		logger.Debug("sandbox-exec not available, limited isolation")
	}

	return &DarwinSandbox{
		hasSandboxExec: hasSandboxExec,
		logger:         logger,
	}
}

// Apply applies sandbox restrictions to a command.
//
// If sandbox-exec is available, the command is rewritten to run under sandbox-exec
// with a generated SBPL profile based on manifest permissions.
//
// NOTE: syscall.Setrlimit is NOT used because on macOS it applies to the parent
// process, not the child. Resource limits are enforced via:
//   - sandbox-exec filesystem/network isolation
//   - Context timeout in the executor
//   - cgroups equivalent not available on macOS
func (s *DarwinSandbox) Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits, perms *manifest.PermissionsInfo) error {
	if cmd == nil || limits == nil {
		return fmt.Errorf("command and limits cannot be nil")
	}

	if !s.hasSandboxExec {
		s.logger.Warn("sandbox-exec not available - running without filesystem/network isolation",
			slog.String("command", cmd.Path),
		)
		return nil
	}

	// Generate SBPL profile from manifest permissions
	profilePath, err := generateSBPLProfile(cmd.Path, perms, cmd.Dir)
	if err != nil {
		s.logger.Warn("failed to generate sandbox profile, running without isolation",
			slog.String("error", err.Error()),
		)
		return nil
	}

	s.mu.Lock()
	s.profilePath = profilePath
	s.mu.Unlock()

	// Rewrite command to use sandbox-exec
	originalPath := cmd.Path
	originalArgs := cmd.Args

	cmd.Path = "/usr/bin/sandbox-exec"
	cmd.Args = make([]string, 0, 3+len(originalArgs))
	cmd.Args = append(cmd.Args, "sandbox-exec", "-f", profilePath, originalPath)
	if len(originalArgs) > 1 {
		cmd.Args = append(cmd.Args, originalArgs[1:]...)
	}

	s.logger.Debug("sandbox-exec applied",
		slog.String("profile", profilePath),
		slog.String("original_command", originalPath),
	)

	return nil
}

// PostStart is a no-op on macOS (no post-spawn restrictions needed).
func (s *DarwinSandbox) PostStart(pid int, limits *policy.ExecutionLimits) error {
	return nil
}

// Cleanup removes the temporary SBPL profile file.
func (s *DarwinSandbox) Cleanup(pid int) error {
	s.mu.Lock()
	path := s.profilePath
	s.profilePath = ""
	s.mu.Unlock()

	if path != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			s.logger.Debug("failed to remove sandbox profile",
				slog.String("path", path),
				slog.String("error", err.Error()),
			)
		}
	}
	return nil
}

// Capabilities returns the capabilities of the macOS sandbox.
//
// IMPORTANT: Previous implementation reported CPULimit, MemoryLimit, PIDLimit, FDLimit
// as true based on Setrlimit. This was a FALSE POSITIVE: Setrlimit applies to the
// parent process on macOS, not the child. These are now correctly reported as false.
//
// sandbox-exec provides filesystem and network isolation when available.
func (s *DarwinSandbox) Capabilities() Capabilities {
	warnings := []string{
		"macOS does not support cgroups - resource limits (CPU, memory, PIDs, FDs) cannot be enforced on child processes",
		"Timeout is enforced by the executor via context cancellation (SIGKILL)",
		"For strict resource limiting, consider running in a Linux environment or VM",
	}

	if !s.hasSandboxExec {
		warnings = append(warnings,
			"sandbox-exec not available - no filesystem or network isolation",
		)
	}

	return Capabilities{
		CPULimit:            false, // macOS has no mechanism to limit child CPU
		MemoryLimit:         false, // macOS has no mechanism to limit child memory
		PIDLimit:            false, // macOS has no mechanism to limit child PIDs
		FDLimit:             false, // macOS has no mechanism to limit child FDs
		NetworkIsolation:    s.hasSandboxExec,
		FilesystemIsolation: s.hasSandboxExec,
		Cgroups:             false,
		Namespaces:          false,
		SupportsSeccomp:     false,
		SupportsSandboxExec: s.hasSandboxExec,
		RequiresRoot:        false,
		Warnings:            warnings,
	}
}

// Name returns the implementation name
func (s *DarwinSandbox) Name() string {
	return "darwin"
}

// parseMemoryStringDarwin parses memory strings like "512M", "1G" into bytes
func parseMemoryStringDarwin(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	var multiplier int64 = 1
	switch {
	case strings.HasSuffix(s, "G"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "K"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "K")
	}

	var val int64
	_, _ = fmt.Sscanf(s, "%d", &val) //nolint:errcheck // parse errors result in zero value
	return val * multiplier
}
