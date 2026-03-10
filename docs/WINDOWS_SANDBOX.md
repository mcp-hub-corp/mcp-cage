# Windows Sandbox Implementation

## Overview

This document describes the sandboxing mechanisms available on Windows, what mcp-cage currently implements, known bugs, and a roadmap for improvements.

**Current status: Only timeout enforcement works. Job Object limits are created but never applied (NO-OP bug).**

---

## 1. Mechanisms Windows Provides (Independent of mcp-cage)

### 1.1 Job Objects

**What it is:** A kernel object that groups processes and applies collective resource limits.

**Capabilities:**
- **Memory**: Per-job and per-process memory limits (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `JOB_OBJECT_LIMIT_JOB_MEMORY`)
- **CPU**: CPU rate control (`JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`) — percentage-based throttling
- **Process count**: Maximum active processes in the job (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS`)
- **KILL_ON_JOB_CLOSE**: When the Job Object handle is closed, all processes in the job are terminated. Critical for cleanup.
- **I/O rate**: I/O bandwidth limits
- **Scheduling class**: Priority control

**API:** `CreateJobObject()` + `SetInformationJobObject()` + `AssignProcessToJobObject()` via `kernel32.dll`.

**No admin required.**

### 1.2 AppContainers (Windows 8+)

**What it is:** A kernel-enforced isolation boundary. Each AppContainer has a unique SID (Security Identifier) and is isolated from the rest of the system by default.

**Capabilities:**
- **Filesystem**: Default-deny. Cannot access any file outside the AppContainer directory unless explicitly granted by capability SIDs
- **Registry**: Isolated registry hive per container
- **Network**: Default-deny for inbound. Outbound allowed by default but can be restricted with Windows Filtering Platform (WFP) rules
- **Process isolation**: Cannot interact with processes outside the container
- **Object isolation**: Cannot access named kernel objects (mutexes, events, etc.) from other containers

**API:** `CreateAppContainerProfile()` + `DeleteAppContainerProfile()` via `userenv.dll`. Process created with `SECURITY_CAPABILITIES` in `STARTUPINFOEX`.

**No admin required.** This is the same mechanism used by:
- Microsoft Edge (each tab runs in an AppContainer)
- Windows Store apps (UWP)
- Windows Sandbox (partially)

### 1.3 Restricted Tokens

**What it is:** A modified access token with reduced privileges. Created from an existing token by removing groups, restricting SIDs, or deleting privileges.

**Capabilities:**
- **Remove group memberships**: e.g., remove Administrators group
- **Add restricting SIDs**: Deny access to objects unless both normal and restricting SIDs match
- **Delete privileges**: Remove SeDebugPrivilege, SeShutdownPrivilege, etc.

**API:** `CreateRestrictedToken()` via `advapi32.dll`. The restricted token is then used with `CreateProcessAsUser()`.

**No admin required.**

### 1.4 Integrity Levels

**What it is:** Mandatory Integrity Control (MIC). Objects and processes have integrity levels: Untrusted, Low, Medium, High, System. A process cannot write to objects of higher integrity.

**Levels:**
| Level | SID | Usage |
|-------|-----|-------|
| Untrusted | S-1-16-0 | Most restrictive; minimal access |
| Low | S-1-16-4096 | Used by browsers for sandboxed tabs |
| Medium | S-1-16-8192 | Standard user processes |
| High | S-1-16-12288 | Admin processes |
| System | S-1-16-16384 | OS services |

**Impact:** A Low-integrity process cannot:
- Write to Medium-integrity files (most user files)
- Send messages to Medium-integrity windows
- Create Medium-integrity objects

**API:** Set via `SetTokenInformation()` with `TokenIntegrityLevel`.

**No admin required.**

### 1.5 Process Mitigation Policies

**What it is:** Per-process security policies applied at creation time. Block specific categories of potentially dangerous operations.

**Available policies (selection):**
| Policy | Effect |
|--------|--------|
| `PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE` | Data Execution Prevention (always on modern Windows) |
| `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` | Block loading DLLs not signed by Microsoft |
| `PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON` | Block Win32k syscalls (no GUI access) |
| `PROCESS_CREATION_MITIGATION_POLICY_CHILD_PROCESS_CREATION_ALWAYS_ON` | Block creation of child processes |
| `PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON` | Block loading images from network shares |

**API:** `UpdateProcThreadAttribute()` with `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` before `CreateProcess()`.

**No admin required.**

### 1.6 Desktop / Window Station Isolation

**What it is:** Separate desktop and window station objects isolate processes from the interactive user's GUI and message queue.

**Capabilities:**
- Process cannot send/receive window messages to/from the user's desktop
- Process cannot capture screenshots
- Process cannot install keyboard hooks

**No admin required.**

### 1.7 Windows Sandbox / Hyper-V (Heavy-weight)

**What it is:** Full VM-based isolation.

**Requirements:**
- Windows 10/11 Pro, Enterprise, or Education
- Hyper-V enabled (admin required)
- Significant overhead per instance

**Not suitable for per-process sandboxing** — too heavyweight. Mentioned for completeness.

---

## 2. What mcp-cage Currently Implements

### 2.1 windows.go: Actual Behavior

| Feature | Claimed by `Capabilities()` | Actual Behavior | Status |
|---------|----------------------------|-----------------|--------|
| Memory limits | Implied available | `setJobLimits()` is NO-OP | **BUG**: Never calls Windows API |
| CPU limits | Implied available | `setJobLimits()` is NO-OP | **BUG**: Never calls Windows API |
| Process limits | Implied available | `setJobLimits()` is NO-OP | **BUG**: Never calls Windows API |
| Job Object creation | ✅ Created | `AssignProcessToJob()` works | **WORKS** (but useless without limits) |
| Timeout | ✅ Available | Parent monitors and kills | **WORKS** |
| Network isolation | Not claimed | Not implemented | Correct |
| Filesystem isolation | Not claimed | Not implemented | Correct |

### 2.2 The NO-OP Bug (windows.go)

**Location:** `internal/sandbox/windows.go`, lines 121-169

**What happens:**
```go
// windows.go:121-169 (approximate)
func (s *WindowsSandbox) setJobLimits(jobHandle windows.Handle, limits *policy.ExecutionLimits) error {
    // Code prepares the JOBOBJECT_EXTENDED_LIMIT_INFORMATION struct...
    info := JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION{
            // ... limit values calculated from policy ...
        },
    }

    // Lines 162-163: THE BUG — limits are silently discarded
    _ = info        // ❌ Prepared struct is thrown away
    _ = jobHandle   // ❌ Job handle is thrown away

    return nil      // ❌ Returns success as if limits were applied
}
```

**Why it's broken:**
1. The `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` struct is correctly prepared
2. But `SetInformationJobObject()` from `kernel32.dll` is never called
3. The function returns `nil` (success), so callers believe limits are in effect
4. `Capabilities()` reports limits as available — this is a **false positive**

**Fix required:**
```go
var (
    kernel32                     = syscall.NewLazyDLL("kernel32.dll")
    procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
)

func (s *WindowsSandbox) setJobLimits(jobHandle windows.Handle, limits *policy.ExecutionLimits) error {
    info := JOBOBJECT_EXTENDED_LIMIT_INFORMATION{...}

    ret, _, err := procSetInformationJobObject.Call(
        uintptr(jobHandle),
        9, // JobObjectExtendedLimitInformation
        uintptr(unsafe.Pointer(&info)),
        uintptr(unsafe.Sizeof(info)),
    )

    if ret == 0 {
        return fmt.Errorf("SetInformationJobObject failed: %w", err)
    }
    return nil
}
```

### 2.3 What Actually Works

Only **two** things function correctly on Windows:

1. **Job Object creation**: Processes are assigned to a Job Object. This creates process grouping but without limits it provides no resource control.
2. **Timeout enforcement**: Parent process monitors the child and kills it after the deadline.

---

## 3. Verification

To verify the NO-OP bug:

```powershell
# 1. Run smcp doctor — it will (incorrectly) report Job Object limits as available
smcp doctor

# 2. Run an MCP server with strict limits
smcp run acme/test@1.0.0 --max-memory 64M --max-cpu 100

# 3. Check the process — it will have no Job Object limits applied
Get-Process -Name "mcp-server" | Select-Object WorkingSet64, CPU
# The process will use whatever resources it wants

# 4. In Process Explorer (Sysinternals), check the Job Object:
#    - Process will be assigned to a Job Object ✅
#    - Job Object will have NO limits configured ❌
```

---

## 4. Roadmap

### P0: Fix Job Object NO-OP

Call `SetInformationJobObject` via `syscall.NewLazyDLL("kernel32.dll").NewProc("SetInformationJobObject")`.

- Apply memory limits (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`)
- Apply process count limits (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS`)
- Apply CPU rate control (`JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`)

**Impact:** Restores basic resource limiting on Windows.

### P0: KILL_ON_JOB_CLOSE

Set `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` flag on the Job Object. When the mcp-cage parent process exits (normally or crashes), all child processes in the Job Object are automatically terminated by the kernel.

**Impact:** Guarantees process tree cleanup even if mcp-cage crashes.

### P0: Fix Capabilities() False Positives

`Capabilities()` must return accurate values:
- `MemoryLimit: false` (not applied — NO-OP bug)
- `CPULimit: false` (not applied — NO-OP bug)
- `PIDLimit: false` (not applied — NO-OP bug)
- `NetworkIsolation: false` (not implemented)
- `FilesystemIsolation: false` (not implemented)

### P1: Restricted Tokens + Integrity Levels

Create child processes with:
1. A restricted token (remove unnecessary privileges, add restricting SIDs)
2. Low integrity level (prevent writing to user files)

**Impact:** Reduces the damage a compromised MCP server can do, even without AppContainer.

### P1: Process Mitigation Policies

Apply per-process mitigation policies:
- `CHILD_PROCESS_CREATION`: Block child process spawning (for `subprocess: false` manifests)
- `WIN32K_SYSTEM_CALL_DISABLE`: Block GUI access (MCP servers don't need GUI)
- `BLOCK_NON_MICROSOFT_BINARIES`: Optional hardening

**Impact:** Syscall-level restrictions similar to seccomp on Linux.

### P2: AppContainers

Full AppContainer integration:
1. Create AppContainer profile per MCP server
2. Configure filesystem capabilities (grant access to working directory only)
3. Configure network capabilities (default-deny, grant per manifest allowlist)
4. Delete profile on cleanup

**Impact:** Kernel-enforced isolation comparable to sandbox-exec on macOS. Filesystem + network + process isolation without admin.

---

## 5. Comparison: Current vs Target

| Feature | Current | After P0 | After P1 | After P2 |
|---------|---------|----------|----------|----------|
| Memory limits | ❌ NO-OP | ✅ Job Objects | ✅ Job Objects | ✅ Job Objects |
| CPU limits | ❌ NO-OP | ✅ Job Objects | ✅ Job Objects | ✅ Job Objects |
| Process limits | ❌ NO-OP | ✅ Job Objects | ✅ Job Objects | ✅ Job Objects |
| Process cleanup | ⚠️ Timeout only | ✅ KILL_ON_JOB_CLOSE | ✅ | ✅ |
| Privilege reduction | ❌ None | ❌ None | ✅ Restricted Tokens | ✅ |
| Integrity levels | ❌ None | ❌ None | ✅ Low integrity | ✅ |
| Subprocess blocking | ❌ None | ❌ None | ✅ Mitigation Policy | ✅ |
| Filesystem isolation | ❌ None | ❌ None | ❌ None | ✅ AppContainer |
| Network isolation | ❌ None | ❌ None | ❌ None | ✅ AppContainer |
| GUI blocking | ❌ None | ❌ None | ✅ Win32k disable | ✅ |

---

## References

- [Job Objects (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [AppContainers (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
- [Process Mitigation Policies (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy)
- [Mandatory Integrity Control (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [Restricted Tokens (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
- [Chromium Windows Sandbox Design](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md)

---

**Related Documents:**
- [SECURITY_SANDBOX_LIMITATIONS.md](SECURITY_SANDBOX_LIMITATIONS.md) — Cross-platform vulnerability analysis
- [SANDBOX_ROADMAP.md](SANDBOX_ROADMAP.md) — Consolidated improvement roadmap
- [LINUX_SANDBOX.md](LINUX_SANDBOX.md) — Linux sandbox (reference implementation)
- [MACOS_SANDBOX.md](MACOS_SANDBOX.md) — macOS sandbox analysis

---

**Last Updated:** 2026-01-27
**Document Version:** 1.0
