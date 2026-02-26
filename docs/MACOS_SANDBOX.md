# macOS Sandbox Implementation

## Overview

This document describes the sandboxing mechanisms available on macOS, what mcp-client currently implements, known bugs, and a roadmap for improvements.

**Current status: Only timeout enforcement works. All other controls are broken or not implemented.**

---

## 1. Mechanisms macOS Provides (Independent of mcp-client)

### 1.1 sandbox-exec / Seatbelt (SBPL)

**What it is:** A kernel-enforced sandbox using Sandbox Profile Language (SBPL). Provides mandatory access control (MAC) at the kernel level, enforced by the `sandbox_init()` / `sandbox-exec` interface.

**Capabilities:**
- **Filesystem**: Per-path read/write/exec restrictions (allow/deny by regex or literal path)
- **Network**: Restrict by protocol, host, port (default-deny possible)
- **Process**: Block `fork()`, `exec()`, signal sending
- **Mach ports**: Restrict IPC access
- **Sysctl**: Block system configuration reads/writes
- **System calls**: Block specific operations (e.g., `ioctl`, `mmap`)

**Who uses it:**
- **Apple system services**: mDNSResponder, nsurlsessiond, mediaanalysisd, and hundreds of others ship with `.sb` profiles in `/System/Library/Sandbox/Profiles/`
- **Google Chrome / Chromium**: Sandboxes renderer processes with custom SBPL profiles
- **Mozilla Firefox**: Content process sandboxing via Seatbelt
- **OpenAI Codex CLI**: Uses sandbox-exec for code execution isolation
- **Nix package manager**: Uses sandbox-exec during builds for reproducibility
- **Bazel build system**: Uses sandbox-exec for hermetic builds

**"Deprecated" status clarification:**
- The `sandbox_init()` C API is marked deprecated in headers since macOS 10.x
- Apple has not provided a public replacement API
- Apple continues to use Seatbelt internally across all system services
- The kernel enforcement mechanism is NOT deprecated — only the public API annotation
- No removal date has been announced
- The `sandbox-exec` CLI tool remains functional through at least macOS 15 (Sequoia)

**No root required.** Works for any user. Profiles are applied before `exec()` and cannot be removed by the child process.

**Usage:**
```bash
sandbox-exec -f profile.sb /path/to/binary
```

### 1.2 rlimits (POSIX)

**What it is:** Standard POSIX resource limits set via `setrlimit()`.

**Available limits on macOS:**
- `RLIMIT_CPU`: CPU time in seconds
- `RLIMIT_AS`: Address space (virtual memory)
- `RLIMIT_NPROC`: Max processes per user
- `RLIMIT_NOFILE`: Max open file descriptors

**Critical caveat on macOS + Go:**
- Go's `exec.Cmd` does NOT expose `SysProcAttr.Rlimits` on Darwin builds (only Linux)
- `syscall.Setrlimit()` applies to the **calling process**, not the child
- To apply rlimits to a child process on macOS, you need either:
  - A cgo wrapper that calls `setrlimit()` between `fork()` and `exec()`
  - `sandbox-exec` with resource limit directives
  - A small C helper binary that sets limits then exec's the target

**No root required.**

### 1.3 Timeout via Parent Monitoring

**What it is:** The parent process monitors the child and sends `SIGTERM` → `SIGKILL` after a deadline.

**Properties:**
- Always works on any POSIX system
- Cannot be bypassed by the child (SIGKILL is unconditional)
- Requires the parent to remain alive

**No root required.**

### 1.4 Other macOS Mechanisms (Not Applicable to mcp-client)

| Mechanism | Requires | Why Not Applicable |
|-----------|----------|-------------------|
| **Hardened Runtime** | App signing + entitlements | Only for signed .app bundles, not arbitrary child processes |
| **App Sandbox** | App Store / entitlements | Restricts the app itself, cannot be applied to arbitrary children |
| **TCC (Transparency, Consent, Control)** | User prompts | Per-app permission grants, not programmatic sandboxing |
| **Virtualization.framework** | macOS 11+ | Full VM — too heavyweight for per-process isolation |
| **Endpoint Security** | Root + System Extension approval | Monitoring framework, not containment |

---

## 2. Example SBPL Profile for MCP Servers

A minimal sandbox profile that restricts an MCP server to:
- Read-only filesystem (except working directory + tmp)
- No network access (default-deny)
- No subprocess spawning
- No signal sending

```scheme
(version 1)
(deny default)

;; Allow reading standard system libraries and frameworks
(allow file-read*
    (subpath "/usr/lib")
    (subpath "/usr/share")
    (subpath "/System/Library")
    (subpath "/Library/Frameworks")
    (subpath "/private/var/db/dyld"))

;; Allow reading the bundle directory (where the MCP server lives)
(allow file-read*
    (subpath "/path/to/mcp/bundle"))

;; Allow read/write to working directory and tmp
(allow file-read* file-write*
    (subpath "/path/to/workdir")
    (subpath (param "TMPDIR")))

;; Allow basic process operations
(allow process-exec)
(allow sysctl-read)
(allow mach-lookup
    (global-name "com.apple.system.logger"))

;; Deny network entirely (default-deny covers this, but explicit for clarity)
(deny network*)

;; Deny subprocess spawning
(deny process-fork)

;; Deny signal sending to other processes
(deny signal (target others))
```

**To enable network for specific hosts**, replace `(deny network*)` with:
```scheme
(allow network-outbound
    (remote tcp (require-all
        (remote hostname "api.example.com")
        (remote port 443))))
```

---

## 3. What mcp-client Currently Implements

### 3.1 darwin.go: Actual Behavior

| Feature | Claimed by `Capabilities()` | Actual Behavior | Status |
|---------|----------------------------|-----------------|--------|
| CPU limits | Implied available | `syscall.Setrlimit()` on **parent process** | **BUG**: Not applied to child |
| Memory limits | Implied available | `syscall.Setrlimit()` on **parent process** | **BUG**: Not applied to child |
| PID limits | Implied available | `syscall.Setrlimit()` on **parent process** | **BUG**: Not applied to child |
| FD limits | Implied available | `syscall.Setrlimit()` on **parent process** | **BUG**: Not applied to child |
| Timeout | ✅ Available | Parent monitors child, SIGTERM → SIGKILL | **WORKS** |
| Network isolation | Not claimed | Not implemented | Correct |
| Filesystem isolation | Not claimed | Not implemented | Correct |
| Seccomp | N/A | N/A (Linux-only) | Correct |

### 3.2 The rlimit Bug (darwin.go)

**Location:** `internal/sandbox/darwin.go`, lines 69-107

**What happens:**
```go
// darwin.go:69-107 (approximate)
func (s *DarwinSandbox) Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits) error {
    // BUG: These calls set limits on the PARENT (mcp-client) process,
    // NOT on the child process that cmd.Run() will spawn.
    _ = syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{
        Cur: cpuSeconds,
        Max: cpuSeconds,
    })
    // ... more Setrlimit calls for AS, NPROC, NOFILE ...
}
```

**Why it's broken:**
1. `syscall.Setrlimit()` modifies the **calling process's** limits
2. Go's `exec.Cmd` on macOS does NOT have `SysProcAttr.Rlimits` (that field only exists on Linux)
3. After `fork()` + `exec()`, the child inherits the parent's limits, but the parent is mcp-client itself — you're limiting mcp-client, not the MCP server
4. The child process gets system defaults (effectively unlimited)

**Impact:**
- `smcp doctor` reports resource limits as available — this is a **false positive**
- Users believe they are protected when they are not
- All resource limit configurations (`max_cpu`, `max_memory`, `max_pids`, `max_fds`) have no effect on macOS

### 3.3 What Actually Works

Only **one** control is functional on macOS:

1. **Timeout enforcement**: Parent process sets a timer, sends SIGTERM then SIGKILL to the child process tree. This works correctly and cannot be bypassed.

---

## 4. Verification

To verify the rlimit bug yourself:

```bash
# 1. Run smcp doctor — it will (incorrectly) report limits as available
smcp doctor

# 2. Run an MCP server with strict limits
smcp run acme/test@1.0.0 --max-memory 64M --max-cpu 100

# 3. Inside the MCP server, check actual limits:
python3 -c "
import resource
soft, hard = resource.getrlimit(resource.RLIMIT_AS)
print(f'Address space limit: soft={soft}, hard={hard}')
# Expected (if limits worked): soft=67108864, hard=67108864
# Actual: soft=-1 (unlimited), hard=-1 (unlimited)
"
```

---

## 5. Roadmap

### P0: sandbox-exec Integration

Integrate `sandbox-exec` as the primary sandboxing mechanism on macOS:
- Generate SBPL profiles dynamically from manifest declarations
- Filesystem: read-only except working directory + TMPDIR
- Network: default-deny, with allowlist from manifest
- Process: block fork/exec if manifest says `subprocess: false`
- Resource limits: use sandbox-exec resource directives or wrapper binary

**Impact:** Brings macOS from "only timeout works" to kernel-enforced filesystem + network + process isolation.

### P0: Fix Capabilities() False Positives

`Capabilities()` must return accurate values:
- `CPULimit: false` (not applied to child)
- `MemoryLimit: false` (not applied to child)
- `PIDLimit: false` (not applied to child)
- `FDLimit: false` (not applied to child)
- `NetworkIsolation: false` (not implemented)
- `FilesystemIsolation: false` (not implemented)

`smcp doctor` must clearly warn users that resource limits are not effective on macOS.

### P1: cgo rlimit Wrapper

Write a small cgo wrapper (or standalone C helper) that:
1. Calls `setrlimit()` for all desired limits
2. Calls `exec()` to replace itself with the target binary

This would make rlimits work correctly on macOS for child processes.

### P1: Process Tree Cleanup

Ensure that when the parent kills the child on timeout, the entire process tree is killed (not just the direct child). Use `killpg()` with the process group, or walk `/proc`-equivalent on macOS.

---

## References

- Apple Sandbox documentation (headers): `/usr/include/sandbox.h`
- Sandbox profiles on disk: `/System/Library/Sandbox/Profiles/`
- Chromium macOS sandbox: `sandbox/mac/` in Chromium source
- OpenAI Codex CLI sandbox: Uses sandbox-exec for code execution
- `man sandbox-exec`, `man sandbox_init`
- [Seatbelt / SBPL syntax reference (reverse-engineered)](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)

---

**Related Documents:**
- [SECURITY_SANDBOX_LIMITATIONS.md](SECURITY_SANDBOX_LIMITATIONS.md) — Cross-platform vulnerability analysis
- [SANDBOX_ROADMAP.md](SANDBOX_ROADMAP.md) — Consolidated improvement roadmap
- [LINUX_SANDBOX.md](LINUX_SANDBOX.md) — Linux sandbox (reference implementation)
- [WINDOWS_SANDBOX.md](WINDOWS_SANDBOX.md) — Windows sandbox analysis

---

**Last Updated:** 2026-01-27
**Document Version:** 1.0
