# Sandbox Security Limitations

## ⚠️ CRITICAL SECURITY NOTICE

The mcp-cage sandbox has **KNOWN LIMITATIONS** on macOS and Windows that allow malicious MCPs to bypass resource limits.

---

## macOS Limitations

### Resource Limits: RESOLVED via sandbox-exec

**Severity:** MITIGATED
**Status:** FIXED - sandbox-exec (Seatbelt SBPL) integration implemented

**What was fixed:**
- The broken `syscall.Setrlimit()` approach (which only affected the parent) has been replaced
- macOS now uses `sandbox-exec` with dynamically generated SBPL profiles
- Filesystem isolation: deny-by-default with explicit allowlists per manifest
- Network isolation: deny-all when no manifest network permissions; allow-all when permissions present
- Subprocess control: can deny process-exec via SBPL rules
- Timeout enforcement: via `context.WithTimeout` in the executor (SIGKILL)

**What WORKS on macOS:**
- Filesystem isolation via sandbox-exec (kernel-enforced, deny-by-default)
- Network isolation via sandbox-exec (deny-all or allow-all based on manifest)
- Subprocess restriction via SBPL profile rules
- Timeout enforcement via context cancellation (SIGKILL)

**What DOES NOT work on macOS:**
- CPU resource limits on child processes (no cgroups equivalent)
- Memory resource limits on child processes (no cgroups equivalent)
- PID count limits (no cgroups equivalent)
- File descriptor limits (macOS SysProcAttr has no Rlimits field)
- Per-host network filtering (sandbox-exec only supports allow-all or deny-all)

**Remaining risk:**
- Resource exhaustion (CPU/memory/PIDs) is not preventable without external tooling
- For production, use Docker containers or Linux VMs for resource limit enforcement

**Recommended Actions:**
- ✅ Development/testing: macOS provides good filesystem/network isolation
- ✅ Production: Use Linux with cgroups for resource limits; macOS sandbox-exec for filesystem/network
- ⚠️ Resource limits: External monitoring or Docker required for CPU/memory enforcement

---

## Windows Limitations

### Job Objects: RESOLVED

**Severity:** RESOLVED
**Status:** FIXED - Job Objects are now fully functional

**What was fixed:**
- `setJobLimits()` now calls `SetInformationJobObject()` via kernel32.dll syscall
- Memory limits (ProcessMemoryLimit + JobMemoryLimit) are enforced
- Process count limits (ActiveProcessLimit) are enforced
- CPU rate control via `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION` implemented
- `KILL_ON_JOB_CLOSE` ensures orphan processes are terminated

**Defense-in-depth measures integrated:**
- **Restricted tokens**: `CreateRestrictedToken()` with `DISABLE_MAX_PRIVILEGE` strips privileges from child processes (best-effort)
- **Low integrity levels**: Fallback if restricted tokens fail; prevents writing to medium-integrity objects
- **AppContainer profiles**: Created for audit trail (best-effort, non-blocking)
- **Mitigation policies**: Subprocess control via Job Object ActiveProcessLimit

**What WORKS on Windows:**
- Memory limits via Job Objects (enforced)
- Process count limits via Job Objects (enforced)
- CPU rate control via Job Objects (enforced, Windows 8+)
- Privilege reduction via restricted tokens (best-effort)
- Integrity level reduction (best-effort fallback)
- Process grouping with KILL_ON_JOB_CLOSE (enforced)
- Timeout enforcement (parent process monitoring)

**What DOES NOT work on Windows:**
- Network isolation (requires kernel drivers or WFP)
- Filesystem isolation (limited to Windows ACLs; AppContainer not applied at spawn time)

### Remaining Windows Mechanisms (Partial Integration)

**1. AppContainers (Win 10+)** — CREATED BUT NOT APPLIED AT SPAWN
- Profiles are created for audit purposes
- Full spawn-time integration requires `CreateProcessW` with `SECURITY_CAPABILITIES`, which Go's `exec.Cmd` does not support
- Profiles are cleaned up on process termination

**2. Restricted Tokens** — INTEGRATED (best-effort)
- `CreateRestrictedToken()` with `DISABLE_MAX_PRIVILEGE` applied to child processes
- Strips all enabled privileges from the token
- Falls back to low integrity if restricted token creation fails

**3. Integrity Levels (Low)** — INTEGRATED (fallback)
- Applied when restricted token creation fails
- Prevents child process from writing to medium-integrity objects

**4. Process Mitigation Policies** — PARTIAL
- Subprocess control enforced via Job Object ActiveProcessLimit
- Full `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` requires `STARTUPINFOEX` (not supported by Go's exec.Cmd)

---

## Comparison Matrix

### mcp-cage Implementation Status

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| **CPU Limits** | ✅ cgroups/rlimits | ❌ No mechanism | ✅ Job Object CPU rate control |
| **Memory Limits** | ✅ cgroups/rlimits | ❌ No mechanism | ✅ Job Object memory limits |
| **Process Limits** | ✅ cgroups/rlimits | ❌ No mechanism | ✅ Job Object ActiveProcessLimit |
| **FD Limits** | ✅ rlimits | ❌ No mechanism | ❌ N/A (Windows uses handles) |
| **Network Isolation** | ✅ netns (root/userNS) | ✅ sandbox-exec (deny/allow) | ❌ Requires WFP/drivers |
| **Filesystem Isolation** | ✅ mount NS + Landlock | ✅ sandbox-exec SBPL | ❌ ACLs only |
| **Privilege Reduction** | ✅ User NS | ⚠️ Limited | ✅ Restricted tokens + low integrity |
| **Syscall Filtering** | ⚠️ Detection only | ⚠️ sandbox-exec (partial) | ⚠️ Mitigation policies (partial) |
| **Timeout** | ✅ Parent monitoring | ✅ Context cancellation | ✅ Context cancellation |
| **Accurate Diagnostics** | ✅ Fixed | ✅ Accurate | ✅ Accurate |
| **Production Ready** | ✅ YES | ⚠️ Partial (no resource limits) | ⚠️ Partial (no network isolation) |

### OS-Level Mechanism Availability (Independent of mcp-cage)

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| **Resource Limits** | ✅ rlimits + cgroups | ✅ sandbox-exec / cgo wrapper | ✅ Job Objects |
| **Network Isolation** | ✅ netns (user NS for non-root) | ✅ sandbox-exec (per-host:port) | ✅ AppContainers |
| **Filesystem Isolation** | ✅ mount NS / Landlock / pivot_root | ✅ sandbox-exec (per-path) | ✅ AppContainers |
| **Syscall Filtering** | ✅ seccomp-BPF | ⚠️ sandbox-exec (partial) | ✅ Process Mitigation Policies |
| **Subprocess Blocking** | ✅ seccomp (block fork/exec) | ✅ sandbox-exec (deny process-fork) | ✅ Mitigation Policy (block child creation) |
| **Privilege Reduction** | ✅ User NS / capabilities | ⚠️ Limited | ✅ Restricted Tokens + Integrity Levels |

---

## Recommendations by Environment

### For Development:
- ✅ **Linux**: Full sandbox, all features work
- ⚠️ **macOS**: Acceptable with awareness of limitations
- ⚠️ **Windows**: Acceptable with awareness of limitations
- **Rule:** Never test malicious/untrusted code on macOS/Windows

### For Production:
- ✅ **Linux bare metal**: Full sandbox with cgroups v2
- ✅ **Docker on any platform**: Container resource limits
- ✅ **Kubernetes**: Pod resource quotas + Network Policies
- ❌ **macOS bare metal**: NOT RECOMMENDED
- ❌ **Windows bare metal**: NOT RECOMMENDED (wait for fix)

### For CI/CD:
- ✅ **Linux runners**: GitHub Actions, GitLab CI (ubuntu-latest)
- ⚠️ **macOS runners**: Only for compilation/unit tests, NOT for running untrusted MCPs
- ⚠️ **Windows runners**: Only for compilation/unit tests, NOT for running untrusted MCPs

### For Enterprise:
- ✅ **Kubernetes**: Best isolation + observability
- ✅ **Docker Swarm**: Good isolation + orchestration
- ✅ **Linux VMs**: KVM/Xen with cgroups
- ⚠️ **Windows VMs**: Wait for Job Object fix
- ❌ **Bare metal macOS/Windows**: PROHIBITED

---

## Status Tracking

### macOS rlimits - RESOLVED
- **Status:** FIXED via sandbox-exec (Seatbelt SBPL) integration
- **Resolution:** Replaced broken `Setrlimit()` with sandbox-exec for filesystem/network isolation
- **Remaining gap:** CPU/memory/PID resource limits cannot be enforced (no macOS mechanism available)
- **Mitigation:** Use Docker containers or Linux VMs for resource limit enforcement

### Windows Job Objects - RESOLVED
- **Status:** FIXED - all Job Object limits now enforced via SetInformationJobObject syscall
- **Resolution:**
  - [x] Added syscall wrapper for `SetInformationJobObject()` in `windows_jobobject.go`
  - [x] Implemented memory limit enforcement (ProcessMemoryLimit + JobMemoryLimit)
  - [x] Implemented process count limit enforcement (ActiveProcessLimit)
  - [x] Implemented CPU rate control (JOBOBJECT_CPU_RATE_CONTROL_INFORMATION)
  - [x] Integrated restricted tokens (DISABLE_MAX_PRIVILEGE)
  - [x] Integrated low integrity levels (fallback)
  - [x] Integrated AppContainer profile creation (audit trail)
  - [x] Added unit tests and E2E tests
  - [x] Updated documentation

### Linux seccomp (detection false positive) - RESOLVED
- **Status:** FIXED - `Capabilities()` now correctly reports `SupportsSeccomp: false`
- **Resolution:** Detection remains for diagnostics, but enforcement is honestly reported as not implemented

---

## Verification Commands

### Check if limits are applied (Linux):
```bash
# Run MCP and check cgroups
mcp run acme/tool &
cat /sys/fs/cgroup/mcp-*/memory.max
cat /sys/fs/cgroup/mcp-*/cpu.max
```

### Check if limits are applied (macOS):
```bash
# This will FAIL (limits not propagated)
mcp run acme/tool &
ps aux | grep mcp-server
# Memory/CPU limits will be system defaults, NOT configured limits
```

### Check if limits are applied (Windows):
```powershell
# This will FAIL (Job Object limits not set)
mcp run acme/tool &
Get-Process -Name "mcp-server" | Select-Object -Property WorkingSet, CPU
# No Job Object limits will be enforced
```

---

## Reporting Security Issues

If you discover additional sandbox bypass techniques:

1. **DO NOT** open a public GitHub issue
2. Email security details to: security@mcp-hub.info
3. Include:
   - Platform (Linux/macOS/Windows)
   - Version (`mcp version`)
   - Steps to reproduce bypass
   - Expected vs actual behavior
   - Proof-of-concept (if safe to share)

**Coordinated disclosure:** We aim to respond within 48 hours and release patches within 1 week for CRITICAL issues.

---

**Last Updated:** 2026-01-27
**Document Version:** 1.1
**Reviewed By:** Security Team

**Related Documents:**
- [SECURITY.md](SECURITY.md) — Comprehensive security model
- [MACOS_SANDBOX.md](MACOS_SANDBOX.md) — macOS mechanisms, bugs, and roadmap
- [WINDOWS_SANDBOX.md](WINDOWS_SANDBOX.md) — Windows mechanisms, bugs, and roadmap
- [LINUX_SANDBOX.md](LINUX_SANDBOX.md) — Linux implementation details + available mechanisms
- [SANDBOX_ROADMAP.md](SANDBOX_ROADMAP.md) — Consolidated improvement roadmap
- `internal/sandbox/darwin.go` — macOS implementation
- `internal/sandbox/windows.go` — Windows implementation
- `internal/sandbox/linux.go` — Linux implementation
