//go:build windows

package sandbox

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/mcp-hub-corp/mcp-cage/internal/manifest"
	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
)

func init() {
	// Register Windows sandbox factory function
	platformNewSandbox = func() Sandbox {
		return newWindowsSandbox()
	}
}

// WindowsSandbox provides process isolation on Windows using Job Objects,
// restricted tokens, low integrity levels, and AppContainers.
// Job Objects allow resource limits on CPU, memory, and process count.
// Note: Windows does not support network isolation without kernel drivers/WFP.
type WindowsSandbox struct {
	// Job Objects are created and managed per process
	// We store mapping of process handles to their job object handles
	jobsMutex sync.RWMutex
	jobs      map[uintptr]windows.Handle
	// pendingLimits stores limits from Apply for use in PostStart
	pendingMutex  sync.RWMutex
	pendingLimits *policy.ExecutionLimits
	// appContainerNames tracks created AppContainer profiles for cleanup
	appContainerMutex sync.Mutex
	appContainerNames []string
	// logger for best-effort security warnings
	logger *slog.Logger
}

func newWindowsSandbox() *WindowsSandbox {
	return &WindowsSandbox{
		jobs:   make(map[uintptr]windows.Handle),
		logger: slog.Default(),
	}
}

// Apply applies sandbox restrictions to a command.
// On Windows, we set CREATE_BREAKAWAY_FROM_JOB flag to allow the process
// to be assigned to our own job object after creation.
// CRITICAL SECURITY INVARIANT: Always attempt to apply limits, even if partial.
func (s *WindowsSandbox) Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits, perms *manifest.PermissionsInfo) error {
	if cmd == nil || limits == nil {
		return fmt.Errorf("command and limits cannot be nil")
	}

	// Set the CREATE_BREAKAWAY_FROM_JOB flag to allow us to put the process
	// in our own job object (this allows resource limits to be applied)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// CREATE_BREAKAWAY_FROM_JOB (0x01000000) allows process to be assigned to a new job
	// This is essential for applying Job Object limits
	cmd.SysProcAttr.CreationFlags |= 0x01000000 // CREATE_BREAKAWAY_FROM_JOB

	// Store limits for post-creation job assignment
	// Note: The actual job creation happens after the process starts (caller's responsibility)
	// This is because Go's exec.Cmd doesn't provide hooks for post-spawn job assignment
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}

	// Store limits for PostStart to use when assigning Job Object
	s.pendingMutex.Lock()
	s.pendingLimits = limits
	s.pendingMutex.Unlock()

	// Store limits metadata in process environment for reference
	// (This is optional, just for informational purposes)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("MCP_SANDBOX_LIMITS_CPU=%d", limits.MaxCPU),
		fmt.Sprintf("MCP_SANDBOX_LIMITS_MEMORY=%s", limits.MaxMemory),
		fmt.Sprintf("MCP_SANDBOX_LIMITS_PIDS=%d", limits.MaxPIDs),
		fmt.Sprintf("MCP_SANDBOX_LIMITS_TIMEOUT=%d", limits.Timeout.Milliseconds()),
	)

	// DEFENSE-IN-DEPTH: Apply restricted token (best-effort, log on failure).
	// This strips all privileges from the child process token.
	// Note: restricted token and low integrity both modify cmd.SysProcAttr.Token.
	// We prefer restricted token (more comprehensive). Low integrity is a fallback.
	if err := applyRestrictedToken(cmd); err != nil {
		s.logger.Debug("restricted token application failed (best-effort)",
			slog.String("error", err.Error()),
		)
		// Fallback: try low integrity level instead
		if err2 := setLowIntegrity(cmd); err2 != nil {
			s.logger.Debug("low integrity level fallback also failed (best-effort)",
				slog.String("error", err2.Error()),
			)
		} else {
			s.logger.Debug("low integrity level applied as fallback for restricted token")
		}
	} else {
		s.logger.Debug("restricted token applied to child process")
	}

	// DEFENSE-IN-DEPTH: Apply mitigation policies for subprocess control (best-effort)
	denySubprocess := true
	if perms != nil && perms.Subprocess {
		denySubprocess = false
	}
	applyMitigationPolicies(cmd, denySubprocess)

	return nil
}

// PostStart assigns the process to a Job Object after spawn.
func (s *WindowsSandbox) PostStart(pid int, limits *policy.ExecutionLimits) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}

	useLimits := limits
	if useLimits == nil {
		s.pendingMutex.RLock()
		useLimits = s.pendingLimits
		s.pendingMutex.RUnlock()
	}
	if useLimits == nil {
		return fmt.Errorf("no limits available for Job Object assignment")
	}

	// Open process handle from PID
	processHandle, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("failed to open process %d: %w", pid, err)
	}

	_, err = s.AssignProcessToJob(processHandle, useLimits)
	if err != nil {
		windows.CloseHandle(processHandle)
		return fmt.Errorf("failed to assign process to job: %w", err)
	}

	// DEFENSE-IN-DEPTH: Create AppContainer profile (best-effort, informational).
	// AppContainers provide strong isolation on Windows 10+ but require the process
	// to be launched with the AppContainer token, which we cannot do post-spawn.
	// We create and log the profile for future use and audit trail.
	containerName := generateAppContainerName("sandbox", pid)
	if info, err := createAppContainerProfile(containerName); err != nil {
		s.logger.Debug("AppContainer profile creation failed (best-effort, non-blocking)",
			slog.String("error", err.Error()),
		)
	} else {
		s.logger.Debug("AppContainer profile created for audit",
			slog.String("name", info.name),
			slog.Int("pid", pid),
		)
		s.appContainerMutex.Lock()
		s.appContainerNames = append(s.appContainerNames, containerName)
		s.appContainerMutex.Unlock()
	}

	return nil
}

// Cleanup closes Job Object handles and removes AppContainer profiles.
func (s *WindowsSandbox) Cleanup(pid int) error {
	s.jobsMutex.Lock()
	// Close all tracked job handles (best-effort)
	for handle, jobHandle := range s.jobs {
		_ = windows.CloseHandle(jobHandle)
		delete(s.jobs, handle)
	}
	s.jobsMutex.Unlock()

	// Cleanup AppContainer profiles (best-effort)
	s.appContainerMutex.Lock()
	for _, name := range s.appContainerNames {
		if err := deleteAppContainerProfile(name); err != nil {
			s.logger.Debug("failed to delete AppContainer profile (best-effort)",
				slog.String("name", name),
				slog.String("error", err.Error()),
			)
		}
	}
	s.appContainerNames = nil
	s.appContainerMutex.Unlock()

	return nil
}

// AssignProcessToJob assigns an existing process to a job object with the specified limits.
// This should be called after the process is created (after exec.Command.Start()).
// Returns the job handle which should be closed after process termination.
func (s *WindowsSandbox) AssignProcessToJob(processHandle windows.Handle, limits *policy.ExecutionLimits) (windows.Handle, error) {
	if processHandle == 0 {
		return 0, fmt.Errorf("invalid process handle")
	}
	if limits == nil {
		return 0, fmt.Errorf("limits cannot be nil")
	}

	// Create a new Job Object
	jobName := fmt.Sprintf("mcp-job-%d", os.Getpid())
	jobHandle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CRITICAL: failed to create job object: %w", err)
	}

	// Set job limits
	if err := s.setJobLimits(jobHandle, limits); err != nil {
		windows.CloseHandle(jobHandle)
		return 0, fmt.Errorf("CRITICAL: failed to set job limits: %w", err)
	}

	// Assign process to job object
	if err := windows.AssignProcessToJobObject(jobHandle, processHandle); err != nil {
		windows.CloseHandle(jobHandle)
		return 0, fmt.Errorf("CRITICAL: failed to assign process to job: %w", err)
	}

	// Store job handle for tracking
	s.jobsMutex.Lock()
	s.jobs[uintptr(processHandle)] = jobHandle
	s.jobsMutex.Unlock()

	_ = jobName // Suppress unused warning

	return jobHandle, nil
}

// setJobLimits configures resource limits on a job object using SetInformationJobObject.
// Supports memory limits, process count limits, and KILL_ON_JOB_CLOSE.
func (s *WindowsSandbox) setJobLimits(jobHandle windows.Handle, limits *policy.ExecutionLimits) error {
	info := jobObjectExtendedLimitInfo{}

	// Always set KILL_ON_JOB_CLOSE: when the last handle to the Job Object is closed,
	// all processes in the job are terminated. This prevents orphaned processes.
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose

	// Memory limit (per process and per job)
	if limits.MaxMemory != "" {
		memBytes := parseMemoryStringWindows(limits.MaxMemory)
		if memBytes > 0 {
			info.ProcessMemoryLimit = uintptr(memBytes)
			info.JobMemoryLimit = uintptr(memBytes)
			info.BasicLimitInformation.LimitFlags |= jobObjectLimitProcessMemory | jobObjectLimitJobMemory
		}
	}

	// Process count limit
	if limits.MaxPIDs > 0 {
		info.BasicLimitInformation.ActiveProcessLimit = uint32(limits.MaxPIDs)
		info.BasicLimitInformation.LimitFlags |= jobObjectLimitActiveProcess
	}

	// Call SetInformationJobObject via syscall for extended limits
	err := setInformationJobObject(
		syscall.Handle(jobHandle),
		jobObjectExtendedLimitInformation,
		unsafe.Pointer(&info),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		return fmt.Errorf("failed to set job limits: %w", err)
	}

	// CPU rate control via JOBOBJECT_CPU_RATE_CONTROL_INFORMATION (info class 15)
	// CpuRate is percentage * 100, e.g. 1000 millicores = 100% = 10000
	if limits.MaxCPU > 0 {
		cpuRate := uint32(limits.MaxCPU) * 10 // millicores to percentage*100 (1000mc = 10000 = 100%)
		if cpuRate > 10000 {
			cpuRate = 10000 // Cap at 100%
		}
		if cpuRate < 100 {
			cpuRate = 100 // Minimum 1%
		}
		cpuInfo := jobObjectCPURateControlInfo{
			ControlFlags: jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
			CpuRate:      cpuRate,
		}
		if err := setInformationJobObject(
			syscall.Handle(jobHandle),
			jobObjectCPURateControlInformation,
			unsafe.Pointer(&cpuInfo),
			uint32(unsafe.Sizeof(cpuInfo)),
		); err != nil {
			// CPU rate control is best-effort (may not be available on older Windows)
			s.logger.Debug("CPU rate control failed (best-effort)",
				slog.String("error", err.Error()),
				slog.Uint64("cpuRate", uint64(cpuRate)),
			)
		} else {
			s.logger.Debug("CPU rate control applied",
				slog.Uint64("cpuRate", uint64(cpuRate)),
				slog.Int("millicores", limits.MaxCPU),
			)
		}
	}

	return nil
}

// CloseJob closes a job object handle.
func (s *WindowsSandbox) CloseJob(jobHandle windows.Handle) error {
	if jobHandle == 0 {
		return fmt.Errorf("invalid job handle")
	}

	if err := windows.CloseHandle(jobHandle); err != nil {
		return fmt.Errorf("failed to close job handle: %w", err)
	}

	return nil
}

// Capabilities returns the capabilities of the Windows sandbox.
//
// CPU, memory, and PID limits are enforced via Job Objects with SetInformationJobObject.
// Restricted tokens and low integrity levels provide defense-in-depth privilege reduction.
func (s *WindowsSandbox) Capabilities() Capabilities {
	return Capabilities{
		CPULimit:            true,  // Job Object CPU rate control via JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
		MemoryLimit:         true,  // Job Objects limit memory via SetInformationJobObject
		PIDLimit:            true,  // Job Objects limit process count via ActiveProcessLimit
		FDLimit:             false, // Windows doesn't use file descriptor limits
		NetworkIsolation:    false, // Requires kernel drivers or WFP
		FilesystemIsolation: false, // Limited without Windows Sandbox or Hyper-V
		Cgroups:             false, // Linux concept
		Namespaces:          false, // Linux concept
		SupportsSeccomp:     false, // Linux concept
		ProcessIsolation:    true,  // Job Objects with KILL_ON_JOB_CLOSE + restricted tokens
		RequiresRoot:        false,
		Warnings: []string{
			"Windows does not support network isolation without kernel drivers or WFP",
			"Filesystem isolation limited - processes run with standard Windows ACLs",
			"Job Objects enforce KILL_ON_JOB_CLOSE for orphan prevention",
			"Restricted tokens applied (best-effort) for privilege reduction",
			"CPU rate control requires Windows 8+ and may fail on older systems",
			"Full process isolation requires Windows Sandbox or Hyper-V (Windows 10 Pro+)",
		},
	}
}

// Name returns the implementation name
func (s *WindowsSandbox) Name() string {
	return "windows"
}

// parseMemoryStringWindows parses memory strings like "512M", "1G" into bytes
func parseMemoryStringWindows(s string) int64 {
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
