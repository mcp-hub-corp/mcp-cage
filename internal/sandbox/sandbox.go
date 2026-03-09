package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/mcp-hub-corp/mcp-cage/internal/manifest"
	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
)

// Sandbox provides resource isolation and limits for MCP processes
type Sandbox interface {
	// Apply applies sandbox constraints to a command before execution.
	// perms may be nil if no manifest permissions are available.
	Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits, perms *manifest.PermissionsInfo) error

	// PostStart applies post-spawn restrictions that require the child PID
	// (e.g., cgroups assignment, Windows Job Object assignment).
	PostStart(pid int, limits *policy.ExecutionLimits) error

	// Cleanup releases sandbox resources for a process (e.g., cgroup dirs, Job Object handles, temp files).
	Cleanup(pid int) error

	// Capabilities returns what this sandbox can enforce
	Capabilities() Capabilities

	// Name returns the sandbox implementation name
	Name() string
}

// Capabilities describes what isolation features are available
type Capabilities struct {
	CPULimit            bool
	MemoryLimit         bool
	PIDLimit            bool
	FDLimit             bool
	NetworkIsolation    bool
	FilesystemIsolation bool
	Cgroups             bool
	Namespaces          bool
	SupportsSeccomp     bool
	SupportsLandlock    bool // Linux 5.13+ Landlock LSM
	SupportsSandboxExec bool // macOS sandbox-exec (seatbelt)
	ProcessIsolation    bool // Windows Job Objects functioning
	RequiresRoot        bool
	Warnings            []string
}

// New creates a platform-specific sandbox
func New() Sandbox {
	// Try to use platform-specific implementation if available
	// Platform files are included via build tags
	sb := platformNewSandbox()
	if sb != nil {
		return sb
	}

	// Fallback to no-op sandbox for unsupported platforms
	return &NoOpSandbox{}
}

// platformNewSandbox is implemented in platform-specific files (linux.go, darwin.go, windows.go)
// via build tags. This declaration ensures it's available as fallback.
var platformNewSandbox = func() Sandbox {
	// Default: return nil to trigger no-op fallback
	return nil
}

// NoOpSandbox is a placeholder sandbox that performs no isolation
type NoOpSandbox struct{}

func (s *NoOpSandbox) Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits, perms *manifest.PermissionsInfo) error {
	// No-op: platform doesn't support sandboxing
	return nil
}

func (s *NoOpSandbox) PostStart(pid int, limits *policy.ExecutionLimits) error {
	return nil
}

func (s *NoOpSandbox) Cleanup(pid int) error {
	return nil
}

func (s *NoOpSandbox) Capabilities() Capabilities {
	return Capabilities{
		Warnings: []string{"Platform does not support sandboxing features"},
	}
}

func (s *NoOpSandbox) Name() string {
	return "noop"
}

// DiagnosticInfo contains system capability information for diagnostics
type DiagnosticInfo struct {
	OS              string
	Arch            string
	Capabilities    Capabilities
	RunningAsRoot   bool
	CgroupsVersion  string
	Recommendations []string
	Warnings        []string
}

// Diagnose returns diagnostic information about the current system
func Diagnose() DiagnosticInfo {
	info := DiagnosticInfo{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	// Check if running as root/admin
	info.RunningAsRoot = os.Geteuid() == 0

	// Get platform-specific capabilities
	sandbox := New()
	info.Capabilities = sandbox.Capabilities()

	// Add platform-specific diagnostics
	switch runtime.GOOS {
	case "linux":
		info.CgroupsVersion = detectCgroupsVersion()
		if !info.RunningAsRoot {
			info.Warnings = append(info.Warnings,
				"Running without root privileges: network isolation and cgroups may be limited",
			)
		}
	case "darwin":
		if info.Capabilities.SupportsSandboxExec {
			info.Warnings = append(info.Warnings,
				"macOS sandbox-exec available - filesystem and network isolation enabled",
			)
		} else {
			info.Warnings = append(info.Warnings,
				"macOS sandbox-exec not available - limited isolation",
				"macOS does not support cgroups - using sandbox-exec or rlimits only",
			)
		}
		info.Recommendations = append(info.Recommendations,
			"For strict security requirements, consider running in a Linux environment or VM",
		)
	case "windows":
		info.Warnings = append(info.Warnings,
			"Windows does not support network isolation without kernel drivers",
		)
		info.Recommendations = append(info.Recommendations,
			"Use Windows Sandbox or Hyper-V for enhanced isolation (Windows 10 Pro+ only)",
		)
	}

	// Add recommendations based on capabilities
	if !info.Capabilities.NetworkIsolation {
		info.Recommendations = append(info.Recommendations,
			"Network isolation not available - default-deny network policy cannot be enforced",
		)
	}

	if !info.Capabilities.FilesystemIsolation {
		info.Recommendations = append(info.Recommendations,
			"Filesystem isolation not available - ensure bundles are from trusted sources",
		)
	}

	if !info.Capabilities.Cgroups && runtime.GOOS == "linux" {
		info.Recommendations = append(info.Recommendations,
			"cgroups v2 not available - resource limits may be less reliable",
		)
	}

	return info
}

// detectCgroupsVersion attempts to detect which cgroups version is available on Linux
func detectCgroupsVersion() string {
	// Try cgroups v2
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		return "v2"
	}

	// Try cgroups v1
	if _, err := os.Stat("/sys/fs/cgroup/cpu"); err == nil {
		return "v1"
	}

	return "unavailable"
}

// ParseMemory parses memory strings like "512M", "1G" into bytes
func ParseMemory(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("memory string cannot be empty")
	}

	val := parseMemoryString(s)
	if val <= 0 {
		return 0, fmt.Errorf("invalid memory string: %s", s)
	}

	return val, nil
}

// parseMemoryString is a helper that parses memory strings
func parseMemoryString(s string) int64 {
	return policy.ParseMemoryStringHelper(s) // Use helper from policy package
}
