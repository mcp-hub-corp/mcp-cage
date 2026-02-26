# Linux Sandbox Implementation

## Overview

The Linux sandbox provides **comprehensive process isolation** using multiple complementary layers:

1. **rlimits** (MANDATORY) - Resource limits via kernel syscalls
2. **Mount Namespaces** (OPTIONAL) - Filesystem isolation
3. **Network Namespaces** (OPTIONAL) - Network isolation with default-deny
4. **cgroups v2** (OPTIONAL) - Enhanced resource control

**Design Principle: SAFE BY DEFAULT**
- All available isolation layers are automatically applied
- Failures in optional layers are logged but don't prevent execution
- Only MANDATORY layers (rlimits) can cause failure

## Architecture

### Layer 1: rlimits (MANDATORY)

The primary safety mechanism, always applied regardless of system capabilities.

#### RLIMIT_CPU
- **Purpose**: Limit CPU time available to the process
- **Formula**: `timeout * (millicores / 1000) = CPU seconds`
- **Example**: 5 minute timeout + 500 millicores = 150 CPU seconds
- **Behavior**: Process receives SIGALRM when exceeded, then SIGKILL

#### RLIMIT_AS (Address Space)
- **Purpose**: Limit total virtual memory (heap + stack + mmap)
- **Scope**: Includes both RSS (resident) and swap
- **Behavior**: Process receives SIGSEGV when attempting allocation beyond limit

#### RLIMIT_NPROC (Process Count)
- **Purpose**: Limit number of child processes/threads
- **Scope**: Per-user limit on total processes spawned
- **Behavior**: fork/clone return EAGAIN when limit exceeded

#### RLIMIT_NOFILE (File Descriptors)
- **Purpose**: Limit open file handles, sockets, pipes
- **Scope**: Per-process limit
- **Behavior**: open/socket/pipe return EMFILE when limit exceeded

### Layer 2: Mount Namespaces (OPTIONAL)

Provides filesystem isolation via `CLONE_NEWNS` flag.

```
Process before:  /proc/self/mounts -> system mounts
Process after:   /proc/self/mounts -> isolated view
```

**Isolation achieved:**
- Process cannot unmount/remount system filesystems
- Can have different view of /mnt, /media, etc.
- Prevents escape via mount tricks

**Prerequisites:** Generally available on modern Linux (no special privileges needed)

**Applied automatically by:** `setupMountNamespace()`

### Layer 3: Network Namespaces (OPTIONAL)

Provides **default-deny network** via `CLONE_NEWNET` flag.

```
Process before:  eth0, wlan0, loopback
Process after:   loopback only (no external network)
```

**Isolation achieved:**
- Process cannot access external network (no eth0, wlan0, etc.)
- Only loopback interface available
- Default-deny: manifest must explicitly whitelist allowed hosts

**Prerequisites:** Requires `CAP_NET_ADMIN` (typically root)

**Applied automatically by:** `setupNetworkNamespace()` (if running as root)

### Layer 4: cgroups v2 (OPTIONAL)

Enhanced resource control applied **after process starts** (needs PID).

```
/sys/fs/cgroup/mcp-launcher-<pid>/
├── cpu.max           (CPU quota per period)
├── memory.max        (Memory hard limit)
└── pids.max          (Process count limit)
```

**Capabilities:**
- More precise CPU control than RLIMIT_CPU
- Stricter memory enforcement than RLIMIT_AS
- Kernel-managed vs. process-managed enforcement

**Prerequisites:**
- cgroups v2 filesystem available at `/sys/fs/cgroup`
- Write access to cgroups directory (usually root)

**Applied by:** `ApplyForPID()` called after process starts

**Best-effort:** Failures are logged but don't prevent execution

## Implementation Details

### Initialization: `newLinuxSandbox()`

Detects available isolation mechanisms:

```go
ls := &LinuxSandbox{
    useCgroups:   false,      // Set if cgroups v1/v2 available
    useCgroupsV2: false,      // Set if cgroups v2 available
    canCreateNet: false,      // Set if running as root
    canCreateMount: true,     // Always assumed available
}
```

**Detection logic:**
1. Check `/sys/fs/cgroup/cgroup.controllers` → cgroups v2 available
2. Check `/sys/fs/cgroup/cpu` → cgroups v1 available
3. Check `os.Geteuid() == 0` → can create network namespaces

### Execution: `Apply(cmd, limits)`

Called **before** process starts:

```go
err := sandbox.Apply(cmd, limits)
// Process-specific restrictions applied to exec.Cmd
// Then cmd.Run() or cmd.Start() executes with restrictions
```

**Sequence:**
1. Apply rlimits (MANDATORY - fails if error)
2. Enable mount namespace (OPTIONAL - logged if error)
3. Enable network namespace (OPTIONAL if root - logged if error)
4. Set restrictive umask (0077 - rwx------)

### Post-Execution: `ApplyForPID(pid, limits)`

Called **after** process starts (if cgroups v2 available):

```go
cmd.Start()  // Process starts
defer sandbox.ApplyForPID(cmd.Process.Pid, limits)  // Then apply cgroups
```

**Sequence:**
1. Create unique cgroup directory: `/sys/fs/cgroup/mcp-launcher-<pid>/`
2. Add PID to cgroup: `echo <pid> > cgroup.procs`
3. Write limits:
   - `cpu.max` = `quota microseconds period`
   - `memory.max` = `bytes`
   - `pids.max` = `count`

### Cleanup: `CleanupCgroup(pid)`

Called after process terminates:

```go
cmd.Wait()
defer sandbox.CleanupCgroup(cmd.Process.Pid)  // Clean up cgroup directory
```

**Removes:** `/sys/fs/cgroup/mcp-launcher-<pid>/` and associated files

## CPU Limit Calculation

CPU limiting requires careful conversion between user-facing millicores and kernel limits.

### rlimits RLIMIT_CPU

CPU time in wall-clock seconds:

```
Formula: timeout * (millicores / 1000)

Examples:
  5s timeout × 1000 millicores (1 CPU)  → 5 seconds CPU time allowed
  5s timeout × 500 millicores (0.5 CPU) → 2.5 seconds CPU time allowed
  5s timeout × 100 millicores (0.1 CPU) → 0.5 seconds CPU time allowed (min 1s)
```

**Semantics:** Hard limit; process SIGKILL'd if exceeded.

### cgroups v2 cpu.max

Period-relative CPU quota:

```
Format: "quota period"
Example: "50000 100000" = 50ms quota per 100ms period = 0.5 CPU

Formula: (millicores * period) / 1000

Examples:
  500 millicores × 100000 microsecond period = 50000 microseconds quota
  (0.5 CPU can use 50ms per 100ms = 50% of CPU)
```

**Semantics:** Soft limit; process is throttled if quota exceeded.

## Security Properties

### Mandatory Guarantees

✓ **Always enforced (rlimits):**
- CPU time limited
- Memory allocation limited
- Process count limited
- File descriptor count limited

### Best-Effort Guarantees

⚠ **Enforced if available:**
- Mount namespace isolation (filesystem view)
- Network namespace isolation (network access)
- cgroups v2 enforcement (kernel enforcement of limits)

### Documented Limitations

❌ **Not covered:**
- Side-channel attacks (timing, cache, spectre, meltdown)
- Exploits in kernel or runtime
- Attacks requiring CAP_SYS_* capabilities
- Covert channels via shared resources

## Examples

### Basic Execution with Limits

```go
import (
    "github.com/security-mcp/mcp-client/internal/sandbox"
    "github.com/security-mcp/mcp-client/internal/policy"
)

// Create sandbox
sb := sandbox.New()  // Returns LinuxSandbox on Linux

// Define limits
limits := &policy.ExecutionLimits{
    MaxCPU:    500,           // 0.5 CPU
    MaxMemory: "256M",        // 256 MB
    MaxPIDs:   10,            // Max 10 processes
    MaxFDs:    512,           // Max 512 file descriptors
    Timeout:   5 * time.Second,
}

// Create command
cmd := exec.Command("./mcp-server", "--mode", "stdio")

// Apply sandbox (before execution)
if err := sb.Apply(cmd, limits); err != nil {
    log.Fatal(err)  // Only fails if rlimits fail
}

// Start process
if err := cmd.Start(); err != nil {
    log.Fatal(err)
}

// Apply cgroups (after process starts)
if linuxSb, ok := sb.(*LinuxSandbox); ok {
    _ = linuxSb.ApplyForPID(cmd.Process.Pid, limits)  // Best-effort
}

// Wait for completion
err := cmd.Wait()

// Cleanup cgroups
if linuxSb, ok := sb.(*LinuxSandbox); ok {
    linuxSb.CleanupCgroup(cmd.Process.Pid)
}
```

### Checking Capabilities

```go
sb := sandbox.New()
caps := sb.Capabilities()

if caps.NetworkIsolation {
    fmt.Println("Network isolation available")
} else {
    fmt.Println("WARNING: Network isolation not available (running without root)")
}

if caps.Cgroups {
    fmt.Println("cgroups available - enhanced resource control enabled")
} else {
    fmt.Println("WARNING: cgroups not available - using rlimits only")
}

for _, warning := range caps.Warnings {
    fmt.Printf("⚠ %s\n", warning)
}
```

## Testing

### Unit Tests

Located in `internal/sandbox/linux_test.go`:

```bash
go test ./internal/sandbox/... -v
```

Tests cover:
- rlimit application for CPU, memory, PIDs, FDs
- Memory string parsing ("512M", "1G", etc.)
- CPU quota calculation for cgroups v2
- Namespace isolation flags
- Capability detection

### Integration Tests

Located in `test/e2e/`:

```bash
go test ./test/e2e/... -v
```

Tests verify:
- End-to-end process execution with limits
- Resource limit enforcement
- Process termination when limits exceeded
- cgroups cleanup

## Performance Considerations

### rlimits
- **Overhead:** Negligible (kernel syscalls on process creation)
- **CPU cost:** ~1-2 microseconds per limit
- **Memory cost:** ~100 bytes per process

### Mount Namespace
- **Overhead:** Minimal (kernel data structure)
- **CPU cost:** ~10-50 microseconds on fork
- **Memory cost:** ~1-2 KB per namespace

### Network Namespace
- **Overhead:** Moderate (new network stack)
- **CPU cost:** ~100-500 microseconds on fork
- **Memory cost:** ~50-100 KB per namespace

### cgroups v2
- **Overhead:** Moderate (filesystem operations)
- **CPU cost:** ~100-1000 microseconds per write
- **Memory cost:** ~1 KB per cgroup

## Troubleshooting

### Network Isolation Not Working

**Symptom:** `NetworkIsolation: false` in capabilities, process can access external network

**Cause:** Running without root/CAP_NET_ADMIN

**Solution:**
```bash
# Option 1: Run as root
sudo smcp run my-app@1.0.0

# Option 2: Grant CAP_NET_ADMIN to binary (not recommended)
sudo setcap cap_net_admin=ep ./mcp-launcher

# Option 3: Document limitation and rely on firewall
```

### cgroups Not Applied

**Symptom:** Process exceeds memory limit but doesn't get killed

**Cause:** cgroups not available or no write access

**Solution:**
```bash
# Check cgroups availability
ls /sys/fs/cgroup/cgroup.controllers  # cgroups v2
ls /sys/fs/cgroup/cpu                # cgroups v1

# Run with debug logging to see what happened
MCP_LOG_LEVEL=debug smcp run my-app@1.0.0

# Check logs for:
# "cgroups v2 detected and available"
# "failed to create cgroup directory (may require elevated privileges)"
```

### rlimits Not Taking Effect

**Symptom:** Process uses more CPU than RLIMIT_CPU allows

**Cause:** Rare; kernel bug or misconfiguration

**Solution:**
```bash
# Verify limits were applied
ps aux | grep <pid>  # Check process limits in /proc/<pid>/limits

cat /proc/<pid>/limits | grep "CPU time"

# If RLIMIT_CPU is "unlimited", limits were not applied
```

## Available Mechanisms Not Yet Implemented

The Linux kernel provides several additional sandboxing mechanisms that mcp-client does not currently use. These are documented here for completeness and to inform the roadmap.

### User Namespaces (`CLONE_NEWUSER`)

**What it provides:** Allows an unprivileged process to create a new user namespace where it has UID 0 (root) _inside_ the namespace, mapped to its unprivileged UID _outside_. This enables creating other namespace types (network, PID, mount) without actual root.

**Impact on mcp-client:** Currently, network namespace creation (`CLONE_NEWNET`) requires `CAP_NET_ADMIN` or root (`linux.go` checks `os.Geteuid() == 0`). With user namespaces, non-root users could get network isolation via:
```go
cmd.SysProcAttr = &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
    UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
    GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
}
```

**Requirements:** Kernel support (most modern distros). Some distros restrict via `kernel.unprivileged_userns_clone=0`.

**No root required** (when sysctl allows).

### seccomp-BPF (Secure Computing with BPF Filters)

**What it provides:** Filters system calls at the kernel level. A BPF program inspects each syscall and its arguments, returning allow/deny/kill decisions. Filters persist across `execve()` and are inherited by child processes.

**Impact on mcp-client:**
- Block `fork()`/`clone()`/`execve()` for manifests declaring `subprocess: false`
- Block dangerous syscalls (`ptrace`, `mount`, `reboot`, `kexec_load`)
- Enforce fine-grained access control on syscall arguments

**Current state:** `Capabilities()` reports `SupportsSeccomp: true` (linux.go:343) but **no code implements seccomp filtering**. This is a false positive.

**Requirements:** `PR_SET_NO_NEW_PRIVS` must be set before installing the filter (prevents privilege escalation). After that, the filter is locked in and cannot be relaxed.

**No root required.**

### Landlock LSM (Linux 5.13+)

**What it provides:** Unprivileged filesystem sandboxing. A process can restrict its own filesystem access to a set of allowed paths. The restrictions cannot be relaxed after application.

**API:**
```c
int ruleset_fd = landlock_create_ruleset(&ruleset_attr, size, 0);
landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_rule, 0);
landlock_restrict_self(ruleset_fd, 0);
```

**ABI versions:**
- v1 (5.13): Filesystem access control (read, write, execute, etc.)
- v2 (5.19): File refer/reparent rules
- v3 (6.2): File truncation rules
- v4 (6.7): **TCP bind and connect restrictions** (network sandboxing!)

**Impact on mcp-client:** Provides filesystem isolation without root (alternative to mount namespaces). With ABI v4, also provides network restrictions without root.

**No root required.**

### PID Namespace (`CLONE_NEWPID`)

**What it provides:** The child process becomes PID 1 in a new PID namespace. It can only see processes within its namespace. When PID 1 exits, all processes in the namespace are killed by the kernel.

**Impact on mcp-client:**
- Process tree isolation: MCP server cannot see or signal other processes
- Guaranteed cleanup: if PID 1 (the MCP server) dies, all its children are killed automatically
- Fork bomb mitigation: combined with `pids.max` cgroup, provides robust process count control

**Requirements:** Typically requires `CAP_SYS_ADMIN` or user namespaces. With `CLONE_NEWUSER | CLONE_NEWPID`, no root required.

### pivot_root Inside User Namespace

**What it provides:** `pivot_root()` changes the root filesystem of the calling process. Inside a user namespace with a mount namespace, this provides strong filesystem isolation without real root:

1. Create user namespace (get "fake root")
2. Create mount namespace
3. Bind-mount allowed directories into a new root
4. `pivot_root()` to the new root
5. Unmount old root

**Impact on mcp-client:** Stronger filesystem isolation than mount namespace alone. The MCP server literally cannot see the host filesystem outside the allowed paths.

**No real root required** (user namespace provides capabilities within the namespace).

---

## References

- Linux man pages: `man setrlimit`, `man 2 clone`, `man cgroups`
- cgroups v2 documentation: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
- kernel.org namespaces documentation: https://man7.org/linux/man-pages/man7/namespaces.7.html
- Security best practices: https://wiki.debian.org/SecureComputing
- seccomp-BPF: `man 2 seccomp`, https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
- Landlock LSM: https://docs.kernel.org/userspace-api/landlock.html
- User namespaces: `man 7 user_namespaces`
- PID namespaces: `man 7 pid_namespaces`
