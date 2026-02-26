# Mandatory Limit Enforcement

Expert reference guide for resource limit enforcement across all layers of mcp-client. This is a CRITICAL security document.

## Table of Contents
1. [Security Invariant (CRITICAL)](#security-invariant-critical)
2. [5-Layer Validation Model](#5-layer-validation-model)
3. [Default Limits](#default-limits)
4. [Emergency Minimum Limits](#emergency-minimum-limits)
5. [Validation Rules](#validation-rules-per-layer)
6. [Fail-Safe Design](#fail-safe-design)
7. [Testing Critical Cases](#testing-critical-cases)
8. [Common Mistakes](#common-mistakes)
9. [Error Messages](#error-messages)
10. [Audit Trail Requirements](#audit-trail-requirements)

---

## Security Invariant (CRITICAL)

### NEVER Execute Without Limits

This is the most important rule in mcp-client.

**Rule:** Every process execution MUST have limits applied, with NO exceptions.

**Consequences of violation:**
- Malicious server consumes all CPU (DoS)
- Malicious server consumes all memory (OOM)
- Malicious server spawns unlimited child processes (fork bomb)
- Malicious server opens unlimited file descriptors (resource exhaustion)
- Malicious server never terminates (infinite loop)

**Enforcement:** MUST fail fast and loudly if limits cannot be applied.

```go
// WRONG - no limits!
process := exec.Command(entrypoint_binary).Start()

// RIGHT - always apply limits
limits := loadLimits(config, manifest)
if limits == nil || limits.IsZero() {
  limits = defaultLimits  // Never skip limits
}
sandbox := createSandbox(limits)
process := startWithSandbox(entrypoint_binary, sandbox)
```

---

## 5-Layer Validation Model

Limits validation happens at 5 critical points, with each layer adding checks:

```
┌─────────────────────────────────────────────────┐
│ Layer 1: Config Loading (config/config.go)      │
│ - Parse YAML, env vars, CLI flags              │
│ - Basic type validation (not nil, not negative) │
└──────────────┬──────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────┐
│ Layer 2: Policy Enforcement (policy/policy.go)  │
│ - Merge manifest + config + CLI limits          │
│ - Most restrictive rule (AND operation)         │
│ - Ensure all fields present                     │
└──────────────┬──────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────┐
│ Layer 3: CLI Validation (cli/run.go)            │
│ - User-provided flags checked                   │
│ - Out-of-bounds detection                       │
│ - User gets feedback before execution           │
└──────────────┬──────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────┐
│ Layer 4: Executor Setup (executor/executor.go)  │
│ - Final validation before process spawn         │
│ - Sandbox config verified                       │
│ - No escape hatches                             │
└──────────────┬──────────────────────────────────┘
               ▼
┌─────────────────────────────────────────────────┐
│ Layer 5: Sandbox Application (sandbox/*.go)     │
│ - Actual OS-level limit application             │
│ - Verify limits took effect                     │
│ - Monitor during execution                      │
└─────────────────────────────────────────────────┘
```

Each layer MUST validate independently. Never assume lower layers validated.

---

## Default Limits

These are the standard limits applied to all executions:

```go
// internal/config/limits.go
type Limits struct {
  CPUMillis    int64         // millicores, 1000 = 1 full core
  MemoryMB     int64         // megabytes
  MaxPIDs      int64         // process count
  MaxFDs       int64         // file descriptors
  TimeoutSecs  int64         // wall-clock timeout
}

var DefaultLimits = Limits{
  CPUMillis:   1000,         // 1 core
  MemoryMB:    512,          // 512 MB
  MaxPIDs:     32,           // max 32 processes (parent + 31 children)
  MaxFDs:      256,          // max 256 file descriptors
  TimeoutSecs: 300,          // 5 minutes
}
```

### Rationale

**CPUMillis: 1000 (1 core)**
- Sufficient for most MCP servers
- Prevents CPU hogging
- Can be overridden per-package (if manifest declares higher need)

**MemoryMB: 512 MB**
- Good balance for Node.js/Python servers
- Prevents memory exhaustion
- Can be overridden per-package

**MaxPIDs: 32**
- Prevents fork bomb (unbounded process creation)
- Allows server + reasonable child processes
- Child process count = 32 - 1 (server itself)

**MaxFDs: 256**
- Prevents file descriptor exhaustion
- Typical limit on most systems
- Allows network connections + file access

**TimeoutSecs: 300 (5 minutes)**
- Long enough for slow operations
- Prevents hung servers
- Can be overridden per-invocation

### Override Examples

```yaml
# ~/.smcp/config.yaml - higher limits for production
executor:
  max_cpu: 2000        # 2 cores for compute-heavy server
  max_memory: 2048M    # 2 GB for large dataset processing
  max_pids: 64         # Allow more worker processes
  max_fds: 512         # More simultaneous connections
  default_timeout: 600 # 10 minutes
```

```bash
# CLI override for one-off execution
smcp run acme/slow-analyzer@1.0.0 \
  --max-cpu 4000 \
  --max-memory 4G \
  --timeout 30m
```

---

## Emergency Minimum Limits

If any limit is missing, invalid, or zero, apply emergency minimums (never skip):

```go
// internal/sandbox/limits.go
var EmergencyMinimumLimits = Limits{
  CPUMillis:   100,          // 0.1 core (very restrictive)
  MemoryMB:    256,          // 256 MB (minimum viable)
  MaxPIDs:     10,           // Bare minimum
  MaxFDs:      64,           // Bare minimum
  TimeoutSecs: 60,           // 1 minute (strict)
}
```

### When Emergency Minimums Apply

```go
// Layer 1: Config loading
if cfg.Executor.MaxCPU <= 0 {
  log.Warn("Invalid CPU limit in config, using emergency minimum: %d millicores", EmergencyMinimumLimits.CPUMillis)
  cfg.Executor.MaxCPU = EmergencyMinimumLimits.CPUMillis
}

// Layer 2: Policy merging
limits := mergeWithDefault(manifest_limits, config_limits)
if limits.MemoryMB <= 0 {
  log.Warn("Invalid memory limit after merge, using emergency minimum: %d MB", EmergencyMinimumLimits.MemoryMB)
  limits.MemoryMB = EmergencyMinimumLimits.MemoryMB
}

// Layer 3: CLI validation
if user_provided_timeout < 0 {
  return error("Timeout must be positive, got: %s", user_timeout_str)
}

// Layer 4: Executor setup
if final_limits == nil {
  log.Warn("No limits provided anywhere, applying emergency minimums")
  final_limits = EmergencyMinimumLimits.Copy()
}

// Layer 5: Sandbox apply
// Double-check at OS-level that limits are valid before applying
if final_limits.CPUMillis <= 0 {
  panic("BUG: CPU limit is zero at sandbox apply time!")
}
```

---

## Validation Rules Per Layer

### Layer 1: Config Loading (config/config.go)

**Responsibility:** Load raw values from file/env/flags and validate basic types

**Validation checklist:**
- All duration values parse correctly (e.g., "512M" → 512 MiB)
- All integer values are >= 0 (no negative)
- No nil fields (use zero if not provided)
- Config file permissions checked (0600)

**Code example:**

```go
func (c *Config) Validate() error {
  // CPU
  if c.Executor.MaxCPU < 0 {
    return fmt.Errorf("max_cpu must be non-negative, got: %d", c.Executor.MaxCPU)
  }
  if c.Executor.MaxCPU == 0 {
    log.Warn("max_cpu not set, using default: %d", DefaultLimits.CPUMillis)
    c.Executor.MaxCPU = DefaultLimits.CPUMillis
  }

  // Memory
  if c.Executor.MaxMemory < 0 {
    return fmt.Errorf("max_memory must be non-negative, got: %s", c.Executor.MaxMemory)
  }
  if c.Executor.MaxMemory == 0 {
    c.Executor.MaxMemory = DefaultLimits.MemoryMB
  }

  // PIDs
  if c.Executor.MaxPIDs < 0 {
    return fmt.Errorf("max_pids must be non-negative, got: %d", c.Executor.MaxPIDs)
  }
  if c.Executor.MaxPIDs == 0 {
    c.Executor.MaxPIDs = DefaultLimits.MaxPIDs
  }

  // File descriptors
  if c.Executor.MaxFDs < 0 {
    return fmt.Errorf("max_fds must be non-negative, got: %d", c.Executor.MaxFDs)
  }
  if c.Executor.MaxFDs == 0 {
    c.Executor.MaxFDs = DefaultLimits.MaxFDs
  }

  // Timeout
  if c.Executor.DefaultTimeout < 0 {
    return fmt.Errorf("timeout must be non-negative, got: %s", c.Executor.DefaultTimeout)
  }
  if c.Executor.DefaultTimeout == 0 {
    c.Executor.DefaultTimeout = DefaultLimits.TimeoutSecs
  }

  return nil
}
```

**Error pattern:**
```
[ERROR] Config validation failed: max_memory must be non-negative, got: -512
[INFO] Check ~/.smcp/config.yaml for errors
Exit Code: 1
```

---

### Layer 2: Policy Enforcement (policy/policy.go)

**Responsibility:** Merge manifest limits + config limits + CLI limits with validation

**Algorithm:**
```
1. Start with config limits as base
2. If manifest declares limits, take most restrictive (min)
3. If CLI flags provided, override with CLI values
4. Validate final result (no nil, all positive)
5. Return validated limits
```

**Code example:**

```go
func (enforcer *PolicyEnforcer) ResolveLimits(
  manifest_limits *Limits,
  config_limits *Limits,
  cli_limits *Limits,
) (*Limits, error) {

  // Start with config (never nil due to Layer 1 validation)
  result := config_limits.Copy()

  // Merge manifest (most restrictive)
  if manifest_limits != nil {
    if manifest_limits.CPUMillis > 0 && manifest_limits.CPUMillis < result.CPUMillis {
      result.CPUMillis = manifest_limits.CPUMillis
      log.Debug("Manifest declares tighter CPU limit: %d millicores", manifest_limits.CPUMillis)
    }
    if manifest_limits.MemoryMB > 0 && manifest_limits.MemoryMB < result.MemoryMB {
      result.MemoryMB = manifest_limits.MemoryMB
      log.Debug("Manifest declares tighter memory limit: %d MB", manifest_limits.MemoryMB)
    }
    if manifest_limits.MaxPIDs > 0 && manifest_limits.MaxPIDs < result.MaxPIDs {
      result.MaxPIDs = manifest_limits.MaxPIDs
    }
    if manifest_limits.MaxFDs > 0 && manifest_limits.MaxFDs < result.MaxFDs {
      result.MaxFDs = manifest_limits.MaxFDs
    }
    if manifest_limits.TimeoutSecs > 0 && manifest_limits.TimeoutSecs < result.TimeoutSecs {
      result.TimeoutSecs = manifest_limits.TimeoutSecs
    }
  }

  // Merge CLI (can relax if explicitly provided with higher value)
  if cli_limits != nil {
    // Only override if explicitly set (non-zero)
    if cli_limits.CPUMillis > 0 {
      result.CPUMillis = cli_limits.CPUMillis
    }
    if cli_limits.MemoryMB > 0 {
      result.MemoryMB = cli_limits.MemoryMB
    }
    if cli_limits.MaxPIDs > 0 {
      result.MaxPIDs = cli_limits.MaxPIDs
    }
    if cli_limits.MaxFDs > 0 {
      result.MaxFDs = cli_limits.MaxFDs
    }
    if cli_limits.TimeoutSecs > 0 {
      result.TimeoutSecs = cli_limits.TimeoutSecs
    }
  }

  // Validate final result
  if result.CPUMillis <= 0 || result.MemoryMB <= 0 || result.MaxPIDs <= 0 ||
     result.MaxFDs <= 0 || result.TimeoutSecs <= 0 {
    log.Error("BUG: Invalid limits after merge: %+v", result)
    // Apply emergency minimums
    result = EmergencyMinimumLimits.Copy()
  }

  return result, nil
}
```

**Validation guarantee:**
After Layer 2, all limits fields MUST be positive and non-nil. No exceptions.

---

### Layer 3: CLI Validation (cli/run.go)

**Responsibility:** Parse and validate user-provided CLI flags

**Code example:**

```go
func (cmd *RunCommand) ValidateFlags() error {
  // Timeout flag
  if cmd.TimeoutStr != "" {
    duration, err := time.ParseDuration(cmd.TimeoutStr)
    if err != nil {
      return fmt.Errorf("invalid timeout format: %s (expected: 5s, 10m, 1h)", cmd.TimeoutStr)
    }
    if duration <= 0 {
      return fmt.Errorf("timeout must be positive, got: %s", cmd.TimeoutStr)
    }
    if duration > 24*time.Hour {
      return fmt.Errorf("timeout too large: %s (max: 24h)", cmd.TimeoutStr)
    }
    cmd.Timeout = duration
  }

  // CPU flag
  if cmd.MaxCPU != 0 {
    if cmd.MaxCPU < 100 {
      return fmt.Errorf("CPU limit too small: %d millicores (min: 100)", cmd.MaxCPU)
    }
    if cmd.MaxCPU > 100000 {
      return fmt.Errorf("CPU limit too large: %d millicores (max: 100)", cmd.MaxCPU)
    }
  }

  // Memory flag
  if cmd.MaxMemory != "" {
    bytes, err := parseByteSize(cmd.MaxMemory)  // "512M" → 536870912
    if err != nil {
      return fmt.Errorf("invalid memory format: %s (expected: 256M, 1G)", cmd.MaxMemory)
    }
    mb := bytes / (1024 * 1024)
    if mb < 256 {
      return fmt.Errorf("memory limit too small: %d MB (min: 256)", mb)
    }
    if mb > 1024*1024 {  // 1 TB max
      return fmt.Errorf("memory limit too large: %d MB (max: 1048576)", mb)
    }
    cmd.MaxMemoryMB = mb
  }

  return nil
}
```

**Error pattern:**
```
[ERROR] Invalid --timeout: 0s (must be positive)
[INFO] Usage: smcp run <package> --timeout 5m

Exit Code: 1
```

---

### Layer 4: Executor Setup (executor/executor.go)

**Responsibility:** Final validation before process spawn, ensure no escape hatches

**Code example:**

```go
func (e *Executor) validateLimitsBeforeExec(limits *Limits) error {
  // Sanity checks
  if limits == nil {
    return errors.New("BUG: limits is nil at executor stage")
  }

  // All fields must be positive
  if limits.CPUMillis <= 0 {
    return fmt.Errorf("CPU limit invalid: %d millicores", limits.CPUMillis)
  }
  if limits.MemoryMB <= 0 {
    return fmt.Errorf("Memory limit invalid: %d MB", limits.MemoryMB)
  }
  if limits.MaxPIDs <= 0 {
    return fmt.Errorf("Max PIDs invalid: %d", limits.MaxPIDs)
  }
  if limits.MaxFDs <= 0 {
    return fmt.Errorf("Max FDs invalid: %d", limits.MaxFDs)
  }
  if limits.TimeoutSecs <= 0 {
    return fmt.Errorf("Timeout invalid: %d seconds", limits.TimeoutSecs)
  }

  // Range checks
  if limits.CPUMillis < EmergencyMinimumLimits.CPUMillis {
    return fmt.Errorf("CPU too restrictive: %d < %d millicores",
      limits.CPUMillis, EmergencyMinimumLimits.CPUMillis)
  }
  if limits.MemoryMB < EmergencyMinimumLimits.MemoryMB {
    return fmt.Errorf("Memory too restrictive: %d < %d MB",
      limits.MemoryMB, EmergencyMinimumLimits.MemoryMB)
  }

  return nil
}

func (e *Executor) Start(entrypoint Entrypoint, limits *Limits, env []string) (Process, error) {
  // Validate before doing anything
  if err := e.validateLimitsBeforeExec(limits); err != nil {
    return nil, fmt.Errorf("Cannot execute with invalid limits: %w", err)
  }

  // Create sandbox with validated limits
  sandbox := e.sandboxFactory.Create(limits)

  // Only now spawn process
  cmd := e.buildCommand(entrypoint, env)
  process, err := cmd.Start()
  if err != nil {
    return nil, fmt.Errorf("Failed to start process: %w", err)
  }

  // Apply sandbox (this must succeed)
  if err := sandbox.Apply(process.Pid); err != nil {
    process.Kill()  // Kill process immediately if sandbox fails
    return nil, fmt.Errorf("Failed to apply sandbox limits: %w (process killed)", err)
  }

  return process, nil
}
```

---

### Layer 5: Sandbox Application (sandbox/linux.go, darwin.go, windows.go)

**Responsibility:** Apply OS-level limits and verify they took effect

**Linux example (cgroups):**

```go
func (s *LinuxSandbox) Apply(cmd *exec.Cmd) error {
  // Validate limits before applying
  if s.limits.CPUMillis <= 0 {
    return errors.New("BUG: CPU limit is non-positive")
  }

  // Create cgroup
  cgroupPath := s.cgroupManager.Create(s.limits)

  // Apply CPU limit
  cpu_quota := s.limits.CPUMillis * 1000  // millicores to microseconds
  if err := s.cgroupManager.SetCPUQuota(cgroupPath, cpu_quota); err != nil {
    return fmt.Errorf("Failed to set CPU limit: %w", err)
  }

  // Apply memory limit
  memory_bytes := s.limits.MemoryMB * 1024 * 1024
  if err := s.cgroupManager.SetMemoryLimit(cgroupPath, memory_bytes); err != nil {
    return fmt.Errorf("Failed to set memory limit: %w", err)
  }

  // Apply PID limit
  if err := s.cgroupManager.SetPIDLimit(cgroupPath, s.limits.MaxPIDs); err != nil {
    return fmt.Errorf("Failed to set PID limit: %w", err)
  }

  // Set working directory + file descriptors
  cmd.Dir = s.workingDir
  // MaxFDs is enforced via rlimit inside process

  // Return callback to be called after fork but before exec
  cmd.SysProcAttr = &syscall.SysProcAttr{
    Pdeathsig: syscall.SIGKILL,  // Kill child if parent dies
    Credential: &syscall.Credential{Uid: uid, Gid: gid},  // Non-root
  }

  // Pre-exec hook to set rlimits
  cmd.SysProcAttr.ChmodRlimitFiles = true
  cmd.SysProcAttr.Rlimit = []syscall.Rlimit{
    {syscall.RLIMIT_NOFILE, s.limits.MaxFDs, s.limits.MaxFDs},
    {syscall.RLIMIT_NPROC, s.limits.MaxPIDs, s.limits.MaxPIDs},
    // ... etc
  }

  return nil
}
```

**macOS example (rlimits only):**

```go
func (s *DarwinSandbox) Apply(cmd *exec.Cmd) error {
  // macOS has no cgroups, use rlimits + timeout
  if s.limits.CPUMillis <= 0 {
    return errors.New("BUG: CPU limit is non-positive")
  }

  // Convert millicores to CPU seconds (rough approximation)
  cpu_seconds := (s.limits.CPUMillis * 60) / 1000  // 1 min per core

  cmd.SysProcAttr = &syscall.SysProcAttr{
    Rlimit: []syscall.Rlimit{
      {syscall.RLIMIT_CPU, uint64(cpu_seconds), uint64(cpu_seconds)},
      {syscall.RLIMIT_AS, uint64(s.limits.MemoryMB * 1024 * 1024), uint64(s.limits.MemoryMB * 1024 * 1024)},
      {syscall.RLIMIT_NPROC, uint64(s.limits.MaxPIDs), uint64(s.limits.MaxPIDs)},
      {syscall.RLIMIT_NOFILE, uint64(s.limits.MaxFDs), uint64(s.limits.MaxFDs)},
    },
  }

  // Timeout enforced via timer in executor
  return nil
}
```

**Verification after process starts:**

```go
// Executor monitoring loop
func (e *Executor) waitWithLimits(process *os.Process, limits *Limits) (exitCode int, err error) {
  timeout := time.Duration(limits.TimeoutSecs) * time.Second
  timer := time.AfterFunc(timeout, func() {
    log.Warn("Process exceeded timeout: %s, killing...", timeout)
    process.Signal(syscall.SIGTERM)

    // If doesn't die in 5s, SIGKILL
    time.Sleep(5 * time.Second)
    process.Kill()
  })
  defer timer.Stop()

  state, err := process.Wait()
  if err != nil {
    return -1, err
  }

  // Check if killed by signal (OOM, timeout, etc.)
  if !state.Success() {
    if state.Signal == syscall.SIGKILL {
      return 124, errors.New("process killed (timeout or resource limit)")
    }
  }

  return state.ExitCode(), nil
}
```

---

## Fail-Safe Design

The system is designed to fail safely: if any limit is invalid, apply emergency minimum (never skip).

### Principle: Restrictive > Permissive

```go
// When in doubt, apply strictest limits
if validation_uncertain {
  use_minimum_limits()  // Emergency minimums
}
```

### Example: Missing CPU Limit

```go
// Config file doesn't have max_cpu
// Layer 1 fills in default
config.MaxCPU = DefaultLimits.CPUMillis  // 1000 millicores

// Manifest doesn't declare CPU limit
// Layer 2 keeps default
limits.CPUMillis = config.MaxCPU  // 1000 millicores

// User doesn't provide --max-cpu flag
// Layer 3 uses resolved value
// Layer 4 validates: 1000 > 0 ✓

// Layer 5 applies: CPU cgroup set to 1000 millicores
```

### Example: All Limits Invalid

```go
// Config file is corrupted, all limits are -1
// Layer 1 detects and resets to defaults
if config.MaxCPU < 0 {
  config.MaxCPU = DefaultLimits.CPUMillis
}

// If somehow all defaults are missing (unlikely but possible)
// Layer 4 applies emergency minimums
if final_limits.CPUMillis <= 0 {
  log.Crit("Applying emergency minimums due to invalid configuration")
  final_limits = EmergencyMinimumLimits.Copy()
}

// Result: Process runs with strict limits (emergency minimums)
```

### Never Silent Failure

```go
// WRONG - silently skips limit if validation fails
if err := validateLimits(limits) {
  // Oops, continue without limits
  startProcess()
}

// RIGHT - fail loudly and kill process
if err := validateLimits(limits) {
  log.Crit("Limits validation failed: %v, applying minimums", err)
  limits = EmergencyMinimumLimits
  if err := startProcess(limits); err != nil {
    return error("Cannot start process with valid limits: %w", err)
  }
}
```

---

## Testing Critical Cases

### Test 1: Nil Limits → Emergency Minimum

```go
func TestNilLimits_ApplyEmergencyMinimum(t *testing.T) {
  executor := NewExecutor()

  // Nil limits
  var limits *Limits = nil

  // Should fail validation
  err := executor.validateLimitsBeforeExec(limits)
  if err == nil {
    t.Fatal("Expected error on nil limits")
  }

  // Should apply minimum
  safeLimit := executor.getOrEmergencyMinimum(limits)
  if safeLimit.CPUMillis != EmergencyMinimumLimits.CPUMillis {
    t.Errorf("Expected CPU %d, got %d", EmergencyMinimumLimits.CPUMillis, safeLimit.CPUMillis)
  }
}
```

### Test 2: Zero Limits → Emergency Minimum

```go
func TestZeroLimits_ApplyEmergencyMinimum(t *testing.T) {
  limits := &Limits{
    CPUMillis:   0,  // Invalid
    MemoryMB:    0,  // Invalid
    MaxPIDs:     0,  // Invalid
    MaxFDs:      0,  // Invalid
    TimeoutSecs: 0,  // Invalid
  }

  // Layer 1 should detect
  config := &Config{Executor: limits}
  err := config.Validate()
  if err == nil {
    t.Fatal("Expected error on zero limits")
  }

  // Should apply defaults
  if config.Executor.CPUMillis <= 0 {
    config.Executor.CPUMillis = DefaultLimits.CPUMillis
  }
  // ... similar for others

  if config.Executor.CPUMillis != DefaultLimits.CPUMillis {
    t.Errorf("Expected default CPU limit to be applied")
  }
}
```

### Test 3: Negative Limits → Reject

```go
func TestNegativeLimits_Rejected(t *testing.T) {
  limits := &Limits{
    CPUMillis: -1000,  // Invalid
  }

  err := validateLimits(limits)
  if err == nil {
    t.Fatal("Expected error on negative limit")
  }

  if !strings.Contains(err.Error(), "negative") {
    t.Errorf("Expected 'negative' in error message, got: %v", err)
  }
}
```

### Test 4: Missing Fields in Manifest → Use Config Defaults

```go
func TestMissingManifestLimits_UseConfigDefaults(t *testing.T) {
  manifest := &Manifest{
    Name: "test",
    // No limits declared
  }

  config := &Config{
    Executor: DefaultLimits,
  }

  enforcer := NewPolicyEnforcer()
  limits, err := enforcer.ResolveLimits(nil, &config.Executor, nil)
  if err != nil {
    t.Fatalf("Expected no error, got: %v", err)
  }

  // Should use config defaults
  if limits.CPUMillis != DefaultLimits.CPUMillis {
    t.Errorf("Expected default CPU limit, got %d", limits.CPUMillis)
  }
}
```

### Test 5: CLI Flag Overrides Config

```go
func TestCLIFlag_OverridesConfig(t *testing.T) {
  config := &Config{
    Executor: Limits{CPUMillis: 1000},  // 1 core
  }

  cli := &Limits{
    CPUMillis: 2000,  // 2 cores (user provided via flag)
  }

  enforcer := NewPolicyEnforcer()
  limits, err := enforcer.ResolveLimits(nil, &config.Executor, cli)
  if err != nil {
    t.Fatalf("Expected no error, got: %v", err)
  }

  // CLI should override
  if limits.CPUMillis != 2000 {
    t.Errorf("Expected CLI CPU override (2000), got %d", limits.CPUMillis)
  }
}
```

### Test 6: Manifest Declares Lower Limit → Enforce

```go
func TestManifestLowerLimit_IsEnforced(t *testing.T) {
  manifest := &Manifest{
    Name: "restricted-server",
    Limits: &Limits{CPUMillis: 500},  // Manifest declares 0.5 core
  }

  config := &Config{
    Executor: Limits{CPUMillis: 1000},  // Config allows 1 core
  }

  enforcer := NewPolicyEnforcer()
  limits, err := enforcer.ResolveLimits(&manifest.Limits, &config.Executor, nil)
  if err != nil {
    t.Fatalf("Expected no error, got: %v", err)
  }

  // Manifest limit should win (more restrictive)
  if limits.CPUMillis != 500 {
    t.Errorf("Expected manifest CPU limit (500), got %d", limits.CPUMillis)
  }
}
```

### Test 7: Process Killed on Timeout

```go
func TestTimeout_KillsProcess(t *testing.T) {
  limits := &Limits{TimeoutSecs: 1}  // 1 second timeout

  executor := NewExecutor()
  cmd := exec.Command("sleep", "10")  // Should hang

  process, err := executor.Start(cmd, limits, nil)
  if err != nil {
    t.Fatalf("Failed to start: %v", err)
  }

  exitCode, err := executor.waitWithLimits(process, limits)

  // Should be killed
  if exitCode != 124 {
    t.Errorf("Expected exit code 124 (timeout), got %d", exitCode)
  }
}
```

### Test 8: Process Killed on Memory Exceeded (Linux)

```go
// +build linux
func TestMemoryLimit_OOMKills(t *testing.T) {
  limits := &Limits{MemoryMB: 10}  // 10 MB limit

  executor := NewExecutor()
  cmd := exec.Command("./test_memory_bomb")  // Allocates 100MB

  sandbox := NewLinuxSandbox(limits)
  if err := sandbox.Apply(cmd); err != nil {
    t.Fatalf("Failed to apply sandbox: %v", err)
  }

  process, err := cmd.Start()
  if err != nil {
    t.Fatalf("Failed to start: %v", err)
  }

  exitCode, err := executor.waitWithLimits(process, limits)

  // Should be OOM killed
  if exitCode != 125 {
    t.Errorf("Expected exit code 125 (OOM), got %d", exitCode)
  }
}
```

### Test 9: All Limits Validated at Layer 4 Before Process Spawn

```go
func TestLayer4Validation_BeforeExec(t *testing.T) {
  // Manually construct invalid limits (bypassing earlier layers)
  badLimits := &Limits{CPUMillis: -100}

  executor := NewExecutor()

  // Should fail at Layer 4
  err := executor.validateLimitsBeforeExec(badLimits)
  if err == nil {
    t.Fatal("Expected Layer 4 to reject invalid limits")
  }

  // Should NOT have started process
  // (verified by mocking os.StartProcess to track calls)
}
```

---

## Common Mistakes

### Mistake 1: Allowing nil Limits

```go
// WRONG
var limits *Limits
if manifest.Limits != nil {
  limits = manifest.Limits
}
// If nil, limits is nil and we continue
startProcess(limits)  // BUG: no limits!

// RIGHT
limits := DefaultLimits.Copy()
if manifest.Limits != nil {
  limits = resolveLimits(manifest.Limits, limits)
}
// limits is always valid
```

### Mistake 2: Not Validating After Merge

```go
// WRONG
limits := merge(config, manifest, cli)
// Assume merge returned valid limits
startProcess(limits)

// RIGHT
limits := merge(config, manifest, cli)
if err := validate(limits); err != nil {
  limits = EmergencyMinimumLimits
}
startProcess(limits)
```

### Mistake 3: Silent Failure on Validation Error

```go
// WRONG
if err := sandbox.Apply(limits); err != nil {
  log.Error("Failed to apply limits: %v", err)
  // Continue anyway!
}
process.Start()

// RIGHT
if err := sandbox.Apply(limits); err != nil {
  log.Crit("Failed to apply limits: %v (aborting)", err)
  return error("Cannot execute without limits: %w", err)
}
process.Start()
```

### Mistake 4: Not Checking Limit Values After Loading Config

```go
// WRONG
config := loadYAML("~/.smcp/config.yaml")
// Assume YAML is valid
startProcess(config.Limits)

// RIGHT
config := loadYAML("~/.smcp/config.yaml")
if err := config.Validate(); err != nil {
  log.Warn("Config validation failed: %v, using defaults", err)
  config = defaultConfig()
}
startProcess(config.Limits)
```

### Mistake 5: Using Manifest Limits Without Merging

```go
// WRONG
manifest := parseManifest(data)
// Use manifest limits directly
startProcess(manifest.Limits)  // Ignores config/CLI overrides!

// RIGHT
manifest := parseManifest(data)
enforcer := NewPolicyEnforcer()
limits, err := enforcer.ResolveLimits(&manifest.Limits, &config.Limits, &cli.Limits)
startProcess(limits)
```

### Mistake 6: Applying Limits After Process Starts

```go
// WRONG
process := exec.Command(binary).Start()
// Now try to apply limits
sandbox.Apply(process.Pid)  // Too late! Process already consuming resources

// RIGHT
sandbox.Apply(cmd)  // Before Start()
process := cmd.Start()  // Limits applied at spawn time
```

---

## Error Messages

All validation errors should be clear and actionable:

### Layer 1: Config Loading

```
[ERROR] Config validation failed: max_cpu must be non-negative, got: -1000
[INFO] Check ~/.smcp/config.yaml line 12
Exit Code: 1
```

```
[WARN] max_memory not specified in config, using default: 512 MB
```

### Layer 2: Policy Merge

```
[DEBUG] Manifest declares CPU limit: 500 millicores (tighter than config: 1000)
[DEBUG] Using manifest limit: 500 millicores
```

### Layer 3: CLI Validation

```
[ERROR] Invalid --timeout: 0s
[INFO] Timeout must be positive (example: --timeout 5m)
Exit Code: 1
```

```
[ERROR] Invalid --max-memory: 99M
[INFO] Memory limit too small: 99 MB (minimum: 256 MB)
Exit Code: 1
```

### Layer 4: Executor Validation

```
[CRIT] Cannot start process: limits validation failed
[CRIT] Received: CPUMillis=-1, expected positive value
[CRIT] This is a bug in the validation pipeline
Exit Code: 1
```

### Layer 5: Sandbox Application

```
[ERROR] Failed to apply CPU limit via cgroups: permission denied
[INFO] Running as non-root user, some limits may not be enforceable
[INFO] For full isolation, run with CAP_SYS_ADMIN or in container
Exit Code: 1
```

```
[WARN] Failed to create network namespace, network will not be isolated
[INFO] This is OK for non-hostile packages, run 'smcp doctor' for details
```

---

## Audit Trail Requirements

Every execution must log limits applied:

```json
{
  "timestamp": "2026-01-18T10:30:05Z",
  "event": "start",
  "package": "acme/hello-world",
  "version": "1.2.3",
  "limits": {
    "cpu_millicores": 1000,
    "memory_mb": 512,
    "max_pids": 32,
    "max_fds": 256,
    "timeout_seconds": 300
  },
  "limits_source": {
    "cpu": "config",
    "memory": "manifest",
    "timeout": "cli"
  }
}
```

**Fields:**
- `limits` - Final applied limits
- `limits_source` - Where each limit came from (default/config/manifest/cli)

**Example audit log:**
```json
{
  "timestamp": "2026-01-18T10:30:05Z",
  "event": "start",
  "limits": {
    "cpu_millicores": 500,
    "memory_mb": 256,
    "max_pids": 20,
    "max_fds": 128,
    "timeout_seconds": 60
  },
  "limits_source": {
    "cpu": "manifest (lower than config)",
    "memory": "emergency_minimum (invalid config value)",
    "max_pids": "manifest",
    "max_fds": "config",
    "timeout": "cli"
  }
}
```

---

## Summary Checklist

Before shipping any process execution code:

- [ ] Layer 1 (Config): All limits validated, no zero/negative values
- [ ] Layer 2 (Policy): Limits merged and re-validated, no nil values
- [ ] Layer 3 (CLI): User flags validated with clear error messages
- [ ] Layer 4 (Executor): Final validation before process spawn, fail if invalid
- [ ] Layer 5 (Sandbox): OS-level limits applied and verified
- [ ] All layers use the same `Limits` struct (no inconsistency)
- [ ] Emergency minimums applied if any validation fails
- [ ] Audit log records source of each limit (config/manifest/cli)
- [ ] Error messages are clear and actionable
- [ ] Process immediately killed if limits cannot be applied
- [ ] Timeout enforced (no infinite processes)
- [ ] No silent failures (always error or apply minimum)

---

This skill is the authoritative reference for limit enforcement. When implementing any feature that starts a process, consult this document for:

- Where to validate limits
- What the minimum limits are
- How to handle invalid/missing limits
- How to test limit enforcement
- What to log

Remember: **Never execute without limits. Period.**

