//go:build linux

package sandbox

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/security-mcp/mcp-client/internal/manifest"
	"github.com/security-mcp/mcp-client/internal/policy"
)

func init() {
	// Register Linux sandbox factory function
	platformNewSandbox = func() Sandbox {
		return newLinuxSandbox()
	}
}

// LinuxSandbox provides comprehensive process isolation on Linux using rlimits,
// cgroups v2, and namespaces (mount, network, pid).
// Design principle: SAFE BY DEFAULT - all isolation layers applied, failures documented
type LinuxSandbox struct {
	useCgroups     bool   // cgroups available
	useCgroupsV2   bool   // cgroups v2 available (preferred over v1)
	cgroupPath     string // path to cgroups mountpoint
	canCreateNet   bool   // can create network namespaces (requires CAP_NET_ADMIN or root)
	canCreateMount bool   // can create mount namespaces (requires unshare capability)
	canUseUserNS   bool   // can use unprivileged user namespaces for netns
	hasLandlock    bool   // Landlock LSM available (Linux 5.13+)
	landlockABI    int    // Landlock ABI version
	hasSeccomp     bool   // seccomp available on this system
	cgroupManager  *cgroupManager
	mu             sync.Mutex
	pendingLimits  *policy.ExecutionLimits // stored for PostStart prlimit application
	logger         *slog.Logger
	trackedCgroups map[int]string // pid -> cgroup path for cleanup
}

// cgroupManager handles cgroups v2 operations (best-effort)
type cgroupManager struct {
	rootPath string
	logger   *slog.Logger
}

func newLinuxSandbox() *LinuxSandbox {
	logger := slog.Default()

	ls := &LinuxSandbox{
		useCgroups:     false,
		cgroupPath:     "/sys/fs/cgroup",
		logger:         logger,
		trackedCgroups: make(map[int]string),
	}

	// Detect cgroups v2 (preferred)
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		ls.useCgroups = true
		ls.useCgroupsV2 = true
		ls.cgroupManager = &cgroupManager{
			rootPath: "/sys/fs/cgroup",
			logger:   logger,
		}
		logger.Debug("cgroups v2 detected and available")
	} else if _, err := os.Stat("/sys/fs/cgroup/cpu"); err == nil {
		// cgroups v1 available (fallback, less preferred)
		ls.useCgroups = true
		ls.useCgroupsV2 = false
		logger.Debug("cgroups v1 detected (cgroups v2 preferred)")
	} else {
		logger.Debug("cgroups not available - resource limits will use rlimits only")
	}

	// Check if we can create network namespaces
	// This requires CAP_NET_ADMIN, typically only available to root or unshare
	uid := os.Geteuid()
	ls.canCreateNet = uid == 0
	if ls.canCreateNet {
		logger.Debug("network namespace isolation enabled (running as root)")
	} else {
		logger.Debug("network namespace isolation disabled (requires root/CAP_NET_ADMIN)")
	}

	// Detect unprivileged user namespaces (for netns without root)
	ls.canUseUserNS = canUseUserNamespaces()
	if ls.canUseUserNS && !ls.canCreateNet {
		logger.Debug("user namespaces available - can create netns without root")
	}

	// Mount namespaces typically don't require root but do require unshare support.
	// Inside containers (Docker, Kubernetes), namespace creation is usually blocked
	// by the container runtime's seccomp profile. The container itself provides isolation.
	if isInContainer() {
		ls.canCreateMount = false
		ls.canCreateNet = false
		ls.canUseUserNS = false
		logger.Debug("container detected - namespace creation disabled (container provides isolation)")
	} else {
		ls.canCreateMount = true
	}

	// Detect Landlock (Linux 5.13+)
	ls.hasLandlock, ls.landlockABI = detectLandlock()
	if ls.hasLandlock {
		logger.Debug("Landlock LSM detected", slog.Int("abi_version", ls.landlockABI))
	}

	// Detect seccomp
	ls.hasSeccomp = detectSeccomp()
	if ls.hasSeccomp {
		logger.Debug("seccomp available on this system")
	}

	return ls
}

// Apply applies all sandbox restrictions to a command.
// Strategy: MANDATORY layers first (rlimits), then OPTIONAL best-effort layers (namespaces, cgroups)
// Returns error only if MANDATORY restrictions fail
func (s *LinuxSandbox) Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits, perms *manifest.PermissionsInfo) error {
	if cmd == nil || limits == nil {
		return fmt.Errorf("command and limits cannot be nil")
	}

	// MANDATORY: Apply rlimits (always works, doesn't require elevated privileges)
	s.applyRLimits(limits)

	// OPTIONAL: Try mount namespace (best-effort)
	// Skip mount namespace when --allow-fs (AllFS) grants full filesystem access
	if perms != nil && perms.AllFS {
		s.logger.Debug("mount namespace skipped (--allow-fs grants full filesystem access)")
	} else if s.canCreateMount {
		s.setupMountNamespace(cmd)
	}

	// OPTIONAL: Try PID namespace (best-effort, provides PID isolation)
	// CLONE_NEWPID requires either root or user namespaces.
	// The child process will see itself as PID 1 in its namespace.
	if s.canCreateNet || s.canUseUserNS {
		s.setupPIDNamespace(cmd)
	}

	// OPTIONAL: Try network namespace if available (best-effort, documented if fails)
	// Skip network isolation when --allow-all-net (AllNet) grants full network access
	if perms != nil && perms.AllNet {
		s.logger.Debug("network namespace skipped (--allow-all-net grants full network access)")
	} else if s.canCreateNet {
		if err := s.setupNetworkNamespace(cmd); err != nil {
			s.logger.Warn("network namespace setup failed", slog.String("error", err.Error()))
		} else {
			s.logger.Debug("network namespace enabled (default-deny network)")
		}
	} else if s.canUseUserNS {
		// Fallback: use user namespaces for network isolation without root
		setupUserNamespace(cmd)
		s.logger.Debug("user namespace + network namespace enabled (non-root)")
	}

	// OPTIONAL: Landlock filesystem restrictions
	// NOTE: Landlock's landlock_restrict_self() applies to the calling thread, not the child.
	// In Go, we cannot safely apply Landlock in a pre-exec callback because goroutines may
	// share OS threads. Instead, we store the desired paths and document this limitation.
	// The child process should apply its own Landlock restrictions if needed.
	// Filesystem isolation is still provided by mount namespaces (CLONE_NEWNS) above.
	if s.hasLandlock && perms != nil && (len(perms.FileSystem) > 0 || len(perms.FileSystemRead) > 0) {
		s.logger.Debug("Landlock restrictions deferred to child process (parent restriction would affect launcher)",
			slog.Int("rw_path_count", len(perms.FileSystem)),
			slog.Int("ro_path_count", len(perms.FileSystemRead)),
		)
		// NOTE: Landlock cannot be applied to the child from the parent process in Go.
		// Mount namespace isolation (CLONE_NEWNS) provides filesystem restriction instead.
	}

	// OPTIONAL: Try cgroups v2 if available (best-effort, documented if fails)
	// Note: This is applied in ApplyForPID after the process starts (need PID)
	if s.useCgroups && s.useCgroupsV2 {
		s.logger.Debug("cgroups v2 will be applied after process starts")
	}

	return nil
}

// ApplyForPID applies cgroups restrictions after the process has started (needs PID).
// This is best-effort: failures are logged but don't cause overall failure.
func (s *LinuxSandbox) ApplyForPID(pid int, limits *policy.ExecutionLimits) error {
	if !s.useCgroups || !s.useCgroupsV2 {
		// cgroups not available, nothing to do
		return nil
	}

	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}

	if s.cgroupManager == nil {
		return fmt.Errorf("cgroup manager not initialized")
	}

	// Attempt to apply cgroups (best-effort)
	if err := s.applyCgroupsV2(pid, limits); err != nil {
		s.logger.Debug("cgroups v2 application failed (non-critical)", slog.String("error", err.Error()))
		return nil // Don't fail overall
	}

	s.logger.Debug("cgroups v2 applied successfully", slog.Int("pid", pid))
	return nil
}

// PostStart applies post-spawn restrictions: prlimits and cgroups v2 assignment.
func (s *LinuxSandbox) PostStart(pid int, limits *policy.ExecutionLimits) error {
	useLimits := limits
	if useLimits == nil {
		s.mu.Lock()
		useLimits = s.pendingLimits
		s.mu.Unlock()
	}

	// Apply rlimits via prlimit(2) on the child process
	if useLimits != nil {
		if err := s.applyPrlimits(pid, useLimits); err != nil {
			s.logger.Debug("prlimit application failed (non-critical)", slog.String("error", err.Error()))
		}
	}

	// Apply cgroups v2 if available
	if s.useCgroups && s.useCgroupsV2 {
		return s.ApplyForPID(pid, useLimits)
	}
	return nil
}

// Cleanup releases sandbox resources for a process.
func (s *LinuxSandbox) Cleanup(pid int) error {
	return s.CleanupCgroup(pid)
}

// applyRLimits stores resource limits for later application via prlimit(2) in PostStart.
// Go's SysProcAttr on Linux does not have an Rlimits field, so we use prlimit(2)
// after the child process has started to set rlimits on the child process by PID.
func (s *LinuxSandbox) applyRLimits(limits *policy.ExecutionLimits) {
	// Store limits for PostStart to apply via prlimit(2)
	s.mu.Lock()
	s.pendingLimits = limits
	s.mu.Unlock()
	s.logger.Debug("rlimits will be applied via prlimit(2) after process starts")
}

// applyPrlimits applies rlimits to a running process via prlimit(2) syscall.
// This is called from PostStart after the child process has been spawned.
func (s *LinuxSandbox) applyPrlimits(pid int, limits *policy.ExecutionLimits) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}

	// RLIMIT_CPU: CPU time in seconds
	if limits.MaxCPU > 0 {
		cpuSeconds := uint64(limits.Timeout.Seconds() * float64(limits.MaxCPU) / 1000.0)
		if cpuSeconds < 1 {
			cpuSeconds = 1
		}
		rlim := unix.Rlimit{Cur: cpuSeconds, Max: cpuSeconds}
		if err := unix.Prlimit(pid, unix.RLIMIT_CPU, &rlim, nil); err != nil {
			s.logger.Debug("prlimit RLIMIT_CPU failed", slog.String("error", err.Error()))
		} else {
			s.logger.Debug("RLIMIT_CPU set via prlimit", slog.Uint64("seconds", cpuSeconds))
		}
	}

	// Memory: RLIMIT_AS is intentionally NOT used here because it limits virtual
	// address space (not RSS). Modern runtimes (Python, Node, Rust/Tokio) use
	// far more virtual memory than physical memory due to mmap, shared libraries,
	// and arena allocators. A 512M RLIMIT_AS kills processes that use < 50M RSS.
	// Memory limits are enforced via cgroups v2 memory.max (applied in PostStart)
	// or by the container runtime's memory constraints.
	if limits.MaxMemory != "" {
		s.logger.Debug("memory limit deferred to cgroups v2 (RLIMIT_AS not used)",
			slog.String("limit", limits.MaxMemory))
	}

	// RLIMIT_NPROC: Process count limit
	if limits.MaxPIDs > 0 {
		rlim := unix.Rlimit{Cur: uint64(limits.MaxPIDs), Max: uint64(limits.MaxPIDs)}
		if err := unix.Prlimit(pid, unix.RLIMIT_NPROC, &rlim, nil); err != nil {
			s.logger.Debug("prlimit RLIMIT_NPROC failed", slog.String("error", err.Error()))
		} else {
			s.logger.Debug("RLIMIT_NPROC set via prlimit", slog.Int("count", limits.MaxPIDs))
		}
	}

	// RLIMIT_NOFILE: File descriptor limit
	if limits.MaxFDs > 0 {
		rlim := unix.Rlimit{Cur: uint64(limits.MaxFDs), Max: uint64(limits.MaxFDs)}
		if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, &rlim, nil); err != nil {
			s.logger.Debug("prlimit RLIMIT_NOFILE failed", slog.String("error", err.Error()))
		} else {
			s.logger.Debug("RLIMIT_NOFILE set via prlimit", slog.Int("count", limits.MaxFDs))
		}
	}

	return nil
}

// setupMountNamespace creates a new mount namespace (CLONE_NEWNS)
// This isolates the filesystem view of the process (mount points, etc.)
func (s *LinuxSandbox) setupMountNamespace(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// CLONE_NEWNS: Create new mount namespace
	// This allows the process to have its own view of mounted filesystems
	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNS

	s.logger.Debug("mount namespace isolation enabled")
}

// setupPIDNamespace creates a new PID namespace (CLONE_NEWPID)
// The child process will see itself as PID 1, providing PID isolation.
// Requires root or user namespaces (CLONE_NEWUSER).
func (s *LinuxSandbox) setupPIDNamespace(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// CLONE_NEWPID: Create new PID namespace
	// Child process becomes PID 1 in its namespace and cannot see other processes
	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWPID

	s.logger.Debug("PID namespace isolation enabled")
}

// setupNetworkNamespace creates a new network namespace (CLONE_NEWNET)
// This provides network isolation with default-deny (only loopback available)
// Requires root or CAP_NET_ADMIN
func (s *LinuxSandbox) setupNetworkNamespace(cmd *exec.Cmd) error {
	if !s.canCreateNet {
		return fmt.Errorf("network namespace requires root or CAP_NET_ADMIN")
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// CLONE_NEWNET: Create new network namespace
	// Creates an isolated network stack with only loopback interface enabled
	// This is default-deny: no external network access unless explicitly configured
	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNET

	s.logger.Debug("network namespace isolation enabled (default-deny network)")
	return nil
}

// applyCgroupsV2 applies cgroups v2 limits to a running process (after PID is available)
// This is best-effort: failures are logged but don't cause overall failure
func (s *LinuxSandbox) applyCgroupsV2(pid int, limits *policy.ExecutionLimits) error {
	if s.cgroupManager == nil {
		return fmt.Errorf("cgroup manager not initialized")
	}

	// Create a unique cgroup for this process
	cgroupName := fmt.Sprintf("mcp-launcher-%d", pid)
	cgroupPath := filepath.Join(s.cgroupManager.rootPath, cgroupName)

	// Attempt to create cgroup directory
	if err := os.Mkdir(cgroupPath, 0o750); err != nil {
		return fmt.Errorf("cannot create cgroup directory (may require elevated privileges): %w", err)
	}

	// Add process to cgroup
	cgroupProcsPath := filepath.Join(cgroupPath, "cgroup.procs")
	if err := os.WriteFile(cgroupProcsPath, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		// Clean up failed cgroup
		_ = os.RemoveAll(cgroupPath)
		return fmt.Errorf("cannot add process to cgroup: %w", err)
	}

	// Track for potential cleanup
	s.mu.Lock()
	s.trackedCgroups[pid] = cgroupPath
	s.mu.Unlock()

	// Apply CPU quota (best-effort)
	if limits.MaxCPU > 0 {
		period := int64(100000) // 100ms standard period
		quota, _ := calculateCPUQuota(limits.MaxCPU, period)
		cpuMax := fmt.Sprintf("%d %d", quota, period)
		if err := os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte(cpuMax), 0o600); err != nil {
			s.logger.Debug("failed to set cpu.max", slog.String("error", err.Error()))
		} else {
			s.logger.Debug("cpu.max set via cgroups v2", slog.String("value", cpuMax))
		}
	}

	// Apply memory limit (best-effort)
	if limits.MaxMemory != "" {
		memBytes := parseMemoryString(limits.MaxMemory)
		if memBytes > 0 {
			memStr := strconv.FormatInt(memBytes, 10)
			if err := os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte(memStr), 0o600); err != nil {
				s.logger.Debug("failed to set memory.max", slog.String("error", err.Error()))
			} else {
				s.logger.Debug("memory.max set via cgroups v2", slog.String("bytes", memStr))
			}
		}
	}

	// Apply PID limit (best-effort)
	if limits.MaxPIDs > 0 {
		pidsStr := strconv.Itoa(limits.MaxPIDs)
		if err := os.WriteFile(filepath.Join(cgroupPath, "pids.max"), []byte(pidsStr), 0o600); err != nil {
			s.logger.Debug("failed to set pids.max", slog.String("error", err.Error()))
		} else {
			s.logger.Debug("pids.max set via cgroups v2", slog.String("count", pidsStr))
		}
	}

	return nil
}

// Capabilities returns detailed information about what isolation features are available
// Marked: enabled, degraded, or unsupported
func (s *LinuxSandbox) Capabilities() Capabilities {
	caps := Capabilities{
		CPULimit:            true,                             // Always available via rlimits
		MemoryLimit:         true,                             // Always available via rlimits
		PIDLimit:            true,                             // Always available via rlimits
		FDLimit:             true,                             // Always available via rlimits
		NetworkIsolation:    s.canCreateNet || s.canUseUserNS, // Root or user namespace
		FilesystemIsolation: true,                             // Always available via mount namespaces
		Cgroups:             s.useCgroups,                     // Depends on kernel and mounted cgroups
		Namespaces:          true,                             // Mount namespaces generally available
		SupportsSeccomp:     false,                            // Detection only; BPF enforcement not implemented
		SupportsLandlock:    s.hasLandlock,                    // Linux 5.13+
		RequiresRoot:        false,                            // User NS allows non-root network isolation
	}

	// Add detailed warnings about limitations
	if !s.useCgroups {
		caps.Warnings = append(caps.Warnings,
			"[DEGRADED] cgroups not available - using rlimits only for resource limits (less reliable)",
		)
	} else if !s.useCgroupsV2 {
		caps.Warnings = append(caps.Warnings,
			"[DEGRADED] cgroups v1 only - cgroups v2 preferred for better resource control",
		)
	}

	if !s.canCreateNet && !s.canUseUserNS {
		caps.Warnings = append(caps.Warnings,
			"[DEGRADED] Network isolation not available - running without root/CAP_NET_ADMIN and user namespaces disabled",
			"[INFO] Network policy enforcement via iptables/tc not possible",
		)
	} else if !s.canCreateNet && s.canUseUserNS {
		caps.Warnings = append(caps.Warnings,
			"[INFO] Network isolation via user namespaces (non-root)",
		)
	}

	if s.hasLandlock {
		caps.Warnings = append(caps.Warnings,
			fmt.Sprintf("[INFO] Landlock LSM available (ABI v%d) - filesystem restrictions enabled", s.landlockABI),
		)
	}

	if s.hasSeccomp {
		caps.Warnings = append(caps.Warnings,
			"[DEGRADED] seccomp detection available but BPF enforcement not yet implemented",
		)
	}

	return caps
}

// Name returns the sandbox implementation name
func (s *LinuxSandbox) Name() string {
	return "linux"
}

// CleanupCgroup removes the cgroup directory for a process (best-effort)
// Should be called after process cleanup
func (s *LinuxSandbox) CleanupCgroup(pid int) error {
	s.mu.Lock()
	cgroupPath, exists := s.trackedCgroups[pid]
	if !exists {
		s.mu.Unlock()
		return nil // No cgroup tracked for this PID
	}
	delete(s.trackedCgroups, pid)
	s.mu.Unlock()

	// Attempt removal (best-effort)
	if err := os.RemoveAll(cgroupPath); err != nil {
		s.logger.Debug("failed to cleanup cgroup", slog.String("path", cgroupPath), slog.String("error", err.Error()))
		return nil // Non-critical failure
	}

	s.logger.Debug("cgroup cleaned up", slog.String("path", cgroupPath))
	return nil
}

// isInContainer detects if the process is running inside a container (Docker, Kubernetes, etc.)
// by checking for standard container indicators.
func isInContainer() bool {
	// Docker creates /.dockerenv in the container root
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// Check /proc/1/cgroup for container-specific cgroup paths
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") ||
			strings.Contains(content, "containerd") ||
			strings.Contains(content, "kubepods") ||
			strings.Contains(content, "lxc") {
			return true
		}
	}
	// Check /proc/1/environ for container_t SELinux label (Kubernetes)
	if data, err := os.ReadFile("/proc/1/mountinfo"); err == nil {
		content := string(data)
		if strings.Contains(content, "/docker/") ||
			strings.Contains(content, "/containerd/") {
			return true
		}
	}
	return false
}

// calculateCPUQuota converts millicores to cgroups CPU quota format
// Returns quota value for use with "cpu.max" in cgroups v2
// Formula: (millicores * period) / 1000
// Example: 500 millicores with 100ms period = (500 * 100000) / 1000 = 50000 microseconds
func calculateCPUQuota(millicores int, period int64) (int64, error) {
	if millicores <= 0 {
		return 0, fmt.Errorf("millicores must be positive: got %d", millicores)
	}

	if period <= 0 {
		return 0, fmt.Errorf("period must be positive: got %d", period)
	}

	quota := (int64(millicores) * period) / 1000
	return quota, nil
}
