# Sandbox Improvement Roadmap

## Overview

Consolidated table of sandboxing improvements across all platforms. Prioritized by security impact and implementation complexity.

**Key insight:** All three platforms (Linux, macOS, Windows) have kernel-enforced sandboxing mechanisms available that mcp-cage does not currently use. The gap is not in the OS — it's in the implementation.

---

## Priority Matrix

| Priority | OS | Mechanism | Impact | Admin? | Description | Current State |
|----------|-----|-----------|--------|--------|-------------|---------------|
| **P0** | Windows | Fix Job Object NO-OP | Critical | No | Call `SetInformationJobObject` via syscall to actually apply memory/CPU/PID limits | `setJobLimits()` discards prepared struct (lines 162-163) |
| **P0** | Windows | KILL_ON_JOB_CLOSE | High | No | Auto-terminate all child processes when parent exits or Job handle closes | Not implemented; orphan processes possible |
| **P0** | macOS | sandbox-exec (Seatbelt) | Critical | No | Kernel-enforced filesystem, network, process isolation via SBPL profiles | Not implemented; only timeout works |
| **P0** | macOS | Fix `Capabilities()` | High | No | Return accurate values (all false for resource limits) | Reports false positives; `mcp doctor` misleads users |
| **P0** | Windows | Fix `Capabilities()` | High | No | Return accurate values (all false for resource limits) | Reports false positives; `mcp doctor` misleads users |
| **P0** | Linux | Fix `SupportsSeccomp` | Medium | No | Return false until seccomp is actually implemented | `Capabilities()` claims seccomp available (linux.go:343) but no code implements it |
| **P1** | Linux | User Namespaces | High | No | `CLONE_NEWUSER` enables network namespace creation WITHOUT root | Currently netns requires root/CAP_NET_ADMIN |
| **P1** | Linux | seccomp-BPF | High | No | Filter syscalls; block fork/exec for `subprocess: false` manifests. Requires `PR_SET_NO_NEW_PRIVS` | Claimed available but not implemented |
| **P1** | Linux | Landlock LSM | Medium | No | Filesystem sandboxing without root (Linux 5.13+). ABI v4 (6.7) adds TCP restrictions | Not implemented |
| **P1** | macOS | cgo rlimit wrapper | Medium | No | Apply rlimits to child via cgo helper that calls setrlimit() before exec() | darwin.go applies rlimits to parent, not child |
| **P1** | Windows | Restricted Tokens | High | No | Reduce child process privileges via `CreateRestrictedToken` | Not implemented |
| **P1** | Windows | Process Mitigation Policies | Medium | No | Block child process creation, GUI access, unsigned DLLs via `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` | Not implemented |
| **P2** | Linux | PID Namespace | Medium | Varies | `CLONE_NEWPID`: child sees isolated PID tree; all children die when PID 1 exits | Not implemented |
| **P2** | Linux | pivot_root in user namespace | Medium | No | Stronger filesystem isolation than mount namespace alone | Not implemented |
| **P2** | Windows | AppContainers | High | No | Full kernel-enforced isolation (filesystem, network, registry, IPC) | Not implemented |
| **P2** | Windows | Integrity Levels (Low) | Medium | No | Prevent child from writing to user files | Not implemented |
| **P3** | macOS | Endpoint Security | Low | Yes | Process monitoring (detection, not prevention) | Not applicable for sandboxing |

---

## Impact Summary by Platform

### Linux (Current: GOOD, Target: COMPREHENSIVE)

| Capability | Current | After P1 | After P2 |
|------------|---------|----------|----------|
| Resource limits (rlimits) | ✅ Works | ✅ | ✅ |
| cgroups v2 | ✅ Works (root) | ✅ | ✅ |
| Mount namespace | ✅ Works | ✅ | ✅ |
| Network namespace | ⚠️ Needs root | ✅ User NS | ✅ |
| Syscall filtering | ❌ Claimed, not implemented | ✅ seccomp-BPF | ✅ |
| Filesystem sandboxing (non-root) | ❌ None | ✅ Landlock | ✅ + pivot_root |
| PID isolation | ❌ None | ❌ | ✅ PID NS |

### macOS (Current: BROKEN, Target: GOOD)

| Capability | Current | After P0 | After P1 |
|------------|---------|----------|----------|
| Resource limits | ❌ Applied to parent | ❌ (sandbox-exec focus) | ✅ cgo wrapper |
| Filesystem isolation | ❌ None | ✅ sandbox-exec | ✅ |
| Network isolation | ❌ None | ✅ sandbox-exec | ✅ |
| Subprocess blocking | ❌ None | ✅ sandbox-exec | ✅ |
| Timeout | ✅ Works | ✅ | ✅ |
| Accurate diagnostics | ❌ False positives | ✅ Fixed | ✅ |

### Windows (Current: BROKEN, Target: GOOD)

| Capability | Current | After P0 | After P1 | After P2 |
|------------|---------|----------|----------|----------|
| Memory limits | ❌ NO-OP | ✅ Job Objects | ✅ | ✅ |
| CPU limits | ❌ NO-OP | ✅ Job Objects | ✅ | ✅ |
| Process limits | ❌ NO-OP | ✅ Job Objects | ✅ | ✅ |
| Process cleanup | ⚠️ Timeout only | ✅ KILL_ON_JOB_CLOSE | ✅ | ✅ |
| Privilege reduction | ❌ None | ❌ | ✅ Restricted Tokens | ✅ |
| Subprocess blocking | ❌ None | ❌ | ✅ Mitigation Policy | ✅ |
| Filesystem isolation | ❌ None | ❌ | ❌ | ✅ AppContainer |
| Network isolation | ❌ None | ❌ | ❌ | ✅ AppContainer |
| Accurate diagnostics | ❌ False positives | ✅ Fixed | ✅ | ✅ |

---

## Implementation Order

### Phase 1: Fix What's Broken (P0)

All P0 items can be done independently per platform:

1. **Windows**: Fix `setJobLimits()` NO-OP + add `KILL_ON_JOB_CLOSE` + fix `Capabilities()`
2. **macOS**: Implement sandbox-exec integration + fix `Capabilities()`
3. **Linux**: Fix `SupportsSeccomp` false positive in `Capabilities()`

**Goal:** Every platform's `mcp doctor` output accurately reflects reality. Windows and macOS have at least basic enforcement.

### Phase 2: Enhance Isolation (P1)

1. **Linux**: User namespaces (netns without root) + seccomp-BPF + Landlock
2. **macOS**: cgo rlimit wrapper for resource limits
3. **Windows**: Restricted Tokens + Process Mitigation Policies

**Goal:** Meaningful security improvement on all platforms without requiring admin/root.

### Phase 3: Full Sandboxing (P2)

1. **Linux**: PID namespace + pivot_root
2. **Windows**: AppContainers + Integrity Levels

**Goal:** Near-complete process isolation on Linux and Windows.

---

## Dependencies Between Items

```
Fix Capabilities() (all OS)  →  Independent, no dependencies
Fix Job Object NO-OP         →  Independent
KILL_ON_JOB_CLOSE            →  After Job Object fix
sandbox-exec                 →  Independent
User Namespaces              →  Independent
seccomp-BPF                  →  Independent
Landlock                     →  Independent
Restricted Tokens            →  After Job Object fix
Process Mitigation Policies  →  Independent
AppContainers                →  After Restricted Tokens (recommended)
PID Namespace                →  After User Namespaces (recommended)
cgo rlimit wrapper           →  Independent (but sandbox-exec is higher priority)
```

---

**Related Documents:**
- [MACOS_SANDBOX.md](MACOS_SANDBOX.md) — macOS mechanisms and bugs
- [WINDOWS_SANDBOX.md](WINDOWS_SANDBOX.md) — Windows mechanisms and bugs
- [LINUX_SANDBOX.md](LINUX_SANDBOX.md) — Linux implementation details
- [SECURITY_SANDBOX_LIMITATIONS.md](SECURITY_SANDBOX_LIMITATIONS.md) — Vulnerability documentation

---

**Last Updated:** 2026-01-27
**Document Version:** 1.0
