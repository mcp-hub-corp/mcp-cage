# Security Model

mcp-cage implements lightweight security controls to mitigate common threats when executing untrusted MCP packages. This document explains the threat model, security invariants, and platform-specific capabilities.

---

## ⚠️ CRITICAL: Known Sandbox Vulnerabilities

**Before reading further, understand these CRITICAL limitations:**

mcp-cage has documented sandbox bypass vulnerabilities on macOS and Windows. These are NOT theoretical - they are confirmed and exploitable:

- **macOS:** Resource limits are NOT enforced on child processes
- **Windows:** Job Object limits are NOT applied

**See [SECURITY_SANDBOX_LIMITATIONS.md](SECURITY_SANDBOX_LIMITATIONS.md) for:**
- Detailed technical analysis of each vulnerability
- Proof-of-concept attack vectors
- Mitigation strategies and workarounds
- Production deployment recommendations
- Fix status and ETAs

**If deploying in production, read that document FIRST.**

---

## Threat Model

### Threats Covered (Reasonable Mitigation)

#### 1. Resource Exhaustion
**Threat**: Malicious code consumes unlimited CPU, memory, processes, or file descriptors.

**Mitigation**:
- Strict limits on CPU time, memory allocation, process count, and open file descriptors
- Timeout-based termination if resource limits are exceeded
- Platform-specific enforcement (rlimits on Linux/macOS, Job Objects on Windows)

#### 2. Unauthorized Filesystem Access
**Threat**: Process writes files outside its designated working directory.

**Mitigation**:
- Filesystem isolation: process confined to working directory + temporary directory
- Best-effort enforcement via OS mechanisms (bind mount on Linux, chroot-like on macOS)
- No write access to system directories or other user data

#### 3. Unauthorized Network Access
**Threat**: Process makes network connections to unexpected hosts.

**Mitigation**:
- Default-deny network policy: no external connections unless explicitly allowed
- Network allowlist in manifest defines allowed domains/IPs
- Platform-specific enforcement (network namespaces on Linux with eBPF/iptables)

#### 4. Secret Exposure
**Threat**: Secrets passed to process are logged, exposing them in plaintext.

**Mitigation**:
- Secrets passed via environment variables, never logged
- Audit logs redact secret names and values
- Configuration prevents accidental logging of sensitive data

#### 5. Supply Chain Attacks (Manifest/Bundle Tampering)
**Threat**: Registry serves corrupted or tampered manifest/bundle.

**Mitigation**:
- Mandatory SHA-256 digest validation of all artifacts
- Digest mismatch causes immediate rejection with clear error
- Cached artifacts validated before reuse

#### 6. Subprocess Escape
**Threat**: Process spawns subprocesses to escape sandbox restrictions.

**Mitigation**:
- Subprocess control via manifest declaration: `subprocess: true/false`
- Platform-specific enforcement (seccomp on Linux, process tree monitoring)
- Failed subprocess launches logged and audited

### Threats NOT Covered (Out of Scope)

#### 1. Kernel/Hardware Exploits
- No protection against kernel vulnerabilities or side-channel attacks (Spectre, Meltdown)
- No hypervisor-level isolation
- Requires kernel patching by system administrator

#### 2. Runtime Interpreter Vulnerabilities
- If MCP server uses Python 3.8 with CVE-2021-XXXXX, mcp-cage cannot detect this
- Responsibility falls on:
  - Bundle maintainer to patch interpreter
  - System administrator to keep OS updated
  - Registry to scan bundles for known vulnerabilities

#### 3. Advanced Evasion Techniques
- Sophisticated fork bombs or resource-allocation loops may defeat limits
- Timing attacks cannot be prevented
- Covert channels (CPU cache, memory timing) are not blocked

#### 4. Windows Network/Filesystem Isolation (Fixable)
- mcp-cage does not implement network or filesystem isolation on Windows
- **However**, Windows provides AppContainers (kernel-enforced, no admin) and Process Mitigation Policies that CAN provide this isolation — they are not yet implemented
- See [WINDOWS_SANDBOX.md](WINDOWS_SANDBOX.md) for available mechanisms

#### 5. macOS Network/Filesystem Isolation (Fixable)
- mcp-cage does not implement network or filesystem isolation on macOS
- **However**, macOS provides `sandbox-exec` / Seatbelt (kernel-enforced, no root) that CAN provide filesystem + network + process isolation — it is not yet implemented
- See [MACOS_SANDBOX.md](MACOS_SANDBOX.md) for available mechanisms

#### 6. Registry Compromise
- If registry is hacked and serves signed artifacts, mcp-cage trusts the digest
- Requires registry-level security (TLS, access controls)
- Audit logs can detect suspicious activity after the fact

## Security Invariants

These rules **MUST NEVER** be violated:

### 1. Mandatory Digest Validation
```
RULE: Before using any manifest or bundle, validate SHA-256 digest.
ACTION: Reject artifact if digest mismatch → exit with code 3.
```

### 2. No Plaintext Secret Logging
```
RULE: Secrets passed by name/reference, never log values.
ACTION: Audit logs must redact secret names/values.
CONFIG: Enable/disable secret logging via explicit config flag only.
```

### 3. Default-Deny Network
```
RULE: Network isolated by default (when OS supports it).
ACTION: Only allow network if manifest declares allowlist.
FALLBACK: Document limitation if OS cannot enforce (macOS, Windows).
```

### 4. Filesystem Isolation
```
RULE: Process writes only to assigned working dir + temp dir.
ACTION: Reject attempts to write to system directories.
FALLBACK: Use OS-level permissions as last resort.
```

### 5. Resource Limits Always Applied
```
RULE: CPU, memory, pids, fds limits enforced on all platforms.
ACTION: Terminate process if limits exceeded.
FALLBACK: Use timeout + kill if OS limit mechanisms unavailable.
```

### 6. Mandatory Audit Logging
```
RULE: Every execution logged (start, end, exit code, duration).
ACTION: Write to ~/.smcp/audit.log with structured format.
CONSTRAINT: Never skip audit in normal operation.
```

### 7. No Subprocess by Default
```
RULE: Subprocess disabled unless manifest declares subprocess: true.
ACTION: Block fork/exec attempts.
FALLBACK: Terminate process if subprocess detected.
```

### 8. No Privilege Escalation
```
RULE: Never execute as root/admin.
ACTION: Refuse execution if running as root.
RECOMMENDATION: Run mcp-cage as regular user via sudo if needed.
```

## Platform-Specific Capabilities

### Linux

**Supported Security Mechanisms**:

1. **Resource Limits (rlimits)**
   - `RLIMIT_CPU`: CPU time in seconds
   - `RLIMIT_AS`: Virtual memory limit
   - `RLIMIT_NPROC`: Max process count
   - `RLIMIT_NOFILE`: Max open file descriptors
   - Status: ✅ Always available

2. **Control Groups (cgroups v2)**
   - `cpu.max`: CPU bandwidth throttling
   - `memory.max`: Memory hard limit
   - `pids.max`: PID limit
   - Status: ⚠️ Available if cgroups delegated or running as root
   - Fallback: Use rlimits if cgroups unavailable

3. **Network Namespaces**
   - Isolated network stack (eth0, lo only)
   - eBPF or iptables rules for allowlist enforcement
   - Status: ✅ Available if `CAP_NET_ADMIN` or running as root
   - Limitation: Non-root users may not have `CAP_NET_ADMIN`

4. **Seccomp (Secure Computing)**
   - Block dangerous syscalls (fork, execve if subprocess disabled)
   - Fine-grained syscall filtering
   - Status: ⚠️ Available if kernel supports BPF; disabled for compatibility

**Configuration**:
```yaml
executor:
  # These limits apply on Linux
  max_cpu: 1000       # milicores: 1000 = 1 full core
  max_memory: 512M
  max_pids: 10
  max_fds: 100
  default_timeout: 5m
```

**Diagnostic**: Run `mcp doctor` to check capabilities.

### macOS

⚠️ **CRITICAL VULNERABILITY:** Resource limits are NOT enforced on child processes. See [SECURITY_SANDBOX_LIMITATIONS.md](SECURITY_SANDBOX_LIMITATIONS.md).

**Intended Security Mechanisms** (NOT WORKING):

1. **Resource Limits (rlimits)** ❌ BROKEN
   - `syscall.Setrlimit()` is called but **does not propagate to child processes**
   - Go's `exec.Cmd` does not inherit parent's rlimits after exec()
   - Child processes run with **UNLIMITED** resources
   - Status: ❌ NOT EFFECTIVE for child processes

2. **Timeouts and Process Termination**
   - Parent process monitors child
   - SIGTERM → SIGKILL after grace period
   - Status: ✅ Always available (THIS IS THE ONLY WORKING CONTROL)

3. **Filesystem Permissions**
   - Execute in temporary directory with restricted UNIX permissions
   - Rely on UNIX DAC (Discretionary Access Control)
   - Status: ⚠️ Available (but weak, no namespace isolation)

**NOT Implemented** (but OS mechanisms exist):
- Network isolation: `sandbox-exec` can enforce per-host:port network rules (NOT IMPLEMENTED)
- Filesystem isolation: `sandbox-exec` can enforce per-path access (NOT IMPLEMENTED)
- Subprocess blocking: `sandbox-exec` can deny `process-fork` (NOT IMPLEMENTED)
- Resource limits on child processes: requires cgo wrapper or sandbox-exec (NOT IMPLEMENTED)
- cgroups: no native support (macOS does not have cgroups)
- seccomp: no BPF equivalent (but sandbox-exec provides similar capabilities)

See [MACOS_SANDBOX.md](MACOS_SANDBOX.md) for full details on `sandbox-exec` and available mechanisms.

**Limitations**:
- ❌ **CRITICAL:** No resource limits on child processes (CPU, memory, PIDs, FDs)
- ❌ No network isolation: process can access any network interface
- ❌ Weak filesystem isolation: rely on UNIX permissions (user can bypass)
- ⚠️ CPU throttling limited to timeout + kill (NO rlimit enforcement)

**Attack Vectors:**
```bash
# All of these will succeed (bypass rlimits)
:(){ :|:& };:                           # Fork bomb
python3 -c "bytearray(10*1024**3)"     # Memory bomb
while true; do :; done                  # CPU hog
```

**Configuration:**
```yaml
executor:
  # ⚠️ WARNING: These limits are NOT enforced on macOS
  max_memory: 512M        # ❌ NOT APPLIED to child processes
  max_cpu: 1000           # ❌ NOT APPLIED to child processes
  max_pids: 32            # ❌ NOT APPLIED to child processes
  max_fds: 256            # ❌ NOT APPLIED to child processes
  default_timeout: 5m     # ✅ WORKS (parent kills child)
```

**DO NOT USE macOS FOR PRODUCTION.**

**Mitigation:**
- ✅ Use Docker container on macOS (cgroups enforced by Docker)
- ✅ Use Linux VM on macOS (UTM, Parallels, VMware)
- ✅ Use Kubernetes with resource limits
- ❌ Do NOT run untrusted MCPs on bare metal macOS

### Windows

⚠️ **CRITICAL VULNERABILITIES:** Job Object limits are NOT applied to processes. See [SECURITY_SANDBOX_LIMITATIONS.md](SECURITY_SANDBOX_LIMITATIONS.md).

**Intended Security Mechanisms** (NOT WORKING):

1. **Job Objects** ❌ BROKEN
   - Job Objects are **created** but limits are **NOT applied**
   - `setJobLimits()` function is a **NO-OP** (returns without calling Windows API)
   - Processes are assigned to Job Object but run with **UNLIMITED** resources
   - Status: ❌ NOT EFFECTIVE (implementation bug)

2. **Timeouts and Termination**
   - Parent monitors child via Job Object
   - Automatic termination after timeout
   - Status: ✅ Always available (THIS IS THE ONLY WORKING CONTROL)

3. **NTFS Permissions**
   - File ACLs for directory access control
   - Execute in temporary directory
   - Status: ⚠️ Available (but weak, no namespace isolation)

**NOT Available**:
- Network namespaces (no WFP driver without admin)
- Seccomp equivalent (no BPF)
- VM-level isolation
- **Job Object resource limits** ❌ (bug in setJobLimits)

**Limitations**:
- ❌ **CRITICAL:** No resource limits applied (memory, CPU, PIDs) due to implementation bug
- ❌ No network isolation without WFP drivers
- ❌ Weak filesystem isolation: rely on NTFS ACLs
- ⚠️ Subprocess restrictions limited to Job Object rules (if limits were applied)

**Attack Vectors:**
```powershell
# All of these will succeed (Job Object limits not applied)
$data = New-Object byte[] 10GB                    # Memory bomb
1..1000 | ForEach-Object { Start-Process cmd }   # Process bomb
while ($true) { 1+1 }                             # CPU hog
```

**Configuration:**
```yaml
executor:
  # ⚠️ WARNING: These limits are NOT enforced on Windows (bug)
  max_memory: 512M        # ❌ NOT APPLIED (setJobLimits is NO-OP)
  max_cpu: 1000           # ❌ NOT APPLIED (setJobLimits is NO-OP)
  max_pids: 32            # ❌ NOT APPLIED (setJobLimits is NO-OP)
  default_timeout: 5m     # ✅ WORKS (parent kills child)
```

**DO NOT USE WINDOWS FOR PRODUCTION (until fixed).**

**Root Cause:**
```go
// In windows.go, line 121-169
func (s *WindowsSandbox) setJobLimits(...) error {
    // ... prepares limit struct ...
    _ = info         // ❌ DISCARDS limits!
    _ = jobHandle    // ❌ NEVER calls SetInformationJobObject!
    return nil       // ❌ Returns success without applying limits
}
```

**Fix Status:** HIGH PRIORITY, ETA 1 week

**Mitigation:**
- ✅ Use Docker Desktop on Windows (cgroups enforced by Docker)
- ✅ Use Windows Sandbox (Windows 10 Pro+ only, manual setup)
- ✅ Use Kubernetes with resource limits
- ⏳ Wait for fix release
- ❌ Do NOT run untrusted MCPs on bare metal Windows

## Digest Validation

### SHA-256 Enforcement

Every manifest and bundle **must** be validated before use:

```go
// Pseudocode
downloadedDigest := sha256(downloadedArtifact)
expectedDigest := registryResponse.digest
if downloadedDigest != expectedDigest {
    return Error("digest mismatch: expected %s, got %s", expectedDigest, downloadedDigest)
}
```

### Digest Format

- Supported: `sha256:` prefix (64 hex characters)
- Example: `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Validation: Case-insensitive hex parsing, error on invalid format

### Cached Validation

- On-disk cached artifacts validated against stored digest
- Re-download if cached artifact fails validation
- Audit log records validation failures

## Environment Variable Filtering

### Allowlist Model

Only environment variables declared in manifest are passed to process:

```json
{
  "manifest": {
    "environment": {
      "allowed_names": [
        "LOG_LEVEL",
        "API_KEY"
      ],
      "deny_patterns": [
        "*SECRET*",
        "*PASSWORD*"
      ]
    }
  }
}
```

### Default Behavior

If manifest omits environment config:
- Only safe, non-sensitive vars passed (none by default, explicit allowlist required)
- Process gets minimal environment (PATH, HOME if safe)

### Redaction in Logs

- Environment variable names logged
- Values **never** logged
- Audit trail shows which vars were filtered

## Network Allowlists

### Manifest Declaration

```json
{
  "manifest": {
    "network": {
      "allowlist": [
        "api.example.com",
        "registry.example.com:443",
        "10.0.0.0/8",
        "2001:db8::/32"
      ]
    }
  }
}
```

### Enforcement Per Platform

| Platform | Mechanism | Status |
|----------|-----------|--------|
| Linux | eBPF/iptables rules | ✅ Enforced |
| macOS | pf rules (limited) | ⚠️ Best-effort |
| Windows | WFP driver (if installed) | ❌ Not enforced |

### Fallback

If enforcement not available:
- Warn user with clear message: "Network isolation not available on this platform"
- Document in `mcp doctor`
- Log warning in audit trail

## Filesystem Isolation

### Working Directory

Process executes with:
- CWD set to isolated working directory
- No write access to parent directories
- Read-only mounts for system directories (Linux only)

### Temporary Directory

Process can create files in:
- `$TMPDIR` / Windows temp directory
- Subdirectories cleaned up after process terminates

### Best-Effort Approach

- Linux: bind mounts + mount namespaces (strong)
- macOS: chroot-like workaround (weak, advisory only)
- Windows: directory ACLs (weak, advisory only)

## Audit Logging for Compliance

### Audit Log Format

```json
{
  "timestamp": "2026-01-18T10:30:00Z",
  "event": "start",
  "package": "acme/tool",
  "version": "1.2.3",
  "digest": "sha256:abc123...",
  "entrypoint": "/bin/mcp-server",
  "user": "alice",
  "exit_code": 0,
  "duration_ms": 5000,
  "limits": {
    "cpu_ms": 1000,
    "memory_mb": 512,
    "pids": 10,
    "fds": 100
  }
}
```

### Log Location

- File: `~/.smcp/audit.log`
- Permissions: `0600` (read/write owner only)
- Rotation: Configurable size/time based

### Compliance

- Suitable for:
  - Security incident investigation
  - Compliance audits (what ran, when, by whom)
  - Usage analytics (non-invasive)

- NOT suitable for:
  - Real-time monitoring (use SIEM integration if needed)
  - PII/sensitive data (never logged)

## Default-Deny Policies

### Network Default-Deny

```
If manifest.network.allowlist is empty:
  → No external connections allowed
  → Loopback (127.0.0.1, ::1) still accessible
Else:
  → Only allowlist + loopback allowed
```

### Subprocess Default-Deny

```
If manifest.subprocess is not set:
  → No child processes allowed
  → fork() / clone() rejected
Else if manifest.subprocess == true:
  → Child processes allowed (inherit limits)
  → fork bombs still limited by pids
```

### Environment Default-Deny

```
If manifest.environment is not set:
  → No env vars passed (empty environment except PATH/HOME)
Else:
  → Only allowlist vars passed
  → Deny patterns filtered out
```

## Known Limitations Per Platform

### Linux
- ✅ Comprehensive isolation available
- ⚠️ Requires proper capabilities/permissions for namespaces
- ℹ️ If running as non-root, some mechanisms limited

### macOS
- ❌ Network isolation NOT implemented (but `sandbox-exec` CAN provide it — see [MACOS_SANDBOX.md](MACOS_SANDBOX.md))
- ❌ Filesystem strict isolation NOT implemented (but `sandbox-exec` CAN provide it)
- ❌ Resource limits NOT applied to child processes (`Setrlimit()` on parent, not child)
- ✅ Timeout enforcement works
- ℹ️ Recommended: Run in VM for untrusted code (until sandbox-exec integration)

### Windows
- ❌ Network isolation NOT implemented (but AppContainers CAN provide it — see [WINDOWS_SANDBOX.md](WINDOWS_SANDBOX.md))
- ❌ Filesystem strict isolation NOT implemented (but AppContainers CAN provide it)
- ❌ Resource limits NOT applied (`setJobLimits()` is NO-OP)
- ✅ Timeout enforcement works
- ℹ️ Recommended: Docker Desktop until Job Object fix ships

## Security Best Practices

1. **Keep mcp-cage Updated**
   - Regularly update to get security fixes
   - Subscribe to security advisories

2. **Verify Package Authenticity**
   - Check digest against known-good values
   - Use private registries for sensitive packages
   - Review manifest before execution

3. **Minimal Permissions**
   - Run mcp-cage as regular user, not root/admin
   - Grant only required network/filesystem access in manifest
   - Restrict environment variables to minimum necessary

4. **Audit Log Monitoring**
   - Rotate and archive `~/.smcp/audit.log` regularly
   - Monitor for unexpected packages/digests
   - Alert on repeated failures or resource limit hits

5. **Platform-Specific Hardening**
   - **Linux**: Enable cgroups, namespaces; use SELinux/AppArmor if available
   - **macOS**: Use VM, restrict resource access, consider macOS Sandbox
   - **Windows**: Use Windows Sandbox; enable code signing verification

6. **Registry Security**
   - Authenticate with strong credentials
   - Use HTTPS and verify TLS certificates
   - Monitor for unauthorized access
   - Implement registry-side scanning/attestation

## Reporting Security Issues

If you discover a security vulnerability in mcp-cage:

1. **Do NOT** open a public GitHub issue
2. Email security details to: security@mcp-hub.info
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Proposed fix (if available)
   - Timeline you prefer for disclosure

We aim to respond within 48 hours and release patches promptly.

---

**Last Updated**: 2026-01-27
**Document Version**: 1.1

## Mandatory Default Limits

**CRITICAL SECURITY FEATURE**: mcp-cage ALWAYS applies resource limits, even if not configured.

### Default Limits (v1.0+)

These limits are MANDATORY and applied to every execution:

| Resource | Default Value | Emergency Minimum | Adjustable |
|----------|---------------|-------------------|------------|
| CPU | 1000 millicores (1 core) | 100 millicores | Yes (stricter only) |
| Memory | 512M | 256M | Yes (stricter only) |
| PIDs | 32 processes | 10 processes | Yes (stricter only) |
| FDs | 256 descriptors | 64 descriptors | Yes (stricter only) |
| Timeout | 5 minutes | 1 minute | Yes (stricter only) |

**Guarantee**: No code path allows execution without these minimums.

### Validation Layers

1. **Config**: Defaults loaded from config.yaml or viper.SetDefault()
2. **Policy**: ApplyLimits() validates and applies stricter manifest limits
3. **Executor**: NewSTDIOExecutor() rejects nil or invalid limits with CRITICAL errors
4. **Sandbox**: Platform-specific enforcement (rlimits/cgroups/Job Objects)

## Platform Isolation Matrix

### Linux

| Layer | Status | Requirements | Description |
|-------|--------|--------------|-------------|
| rlimits | ✅ ENABLED | None | CPU, memory, PID, FD limits (MANDATORY) |
| Mount NS | ✅ ENABLED | Modern kernel | Filesystem isolation (OPTIONAL) |
| Network NS | ⚠️ DEGRADED | root/CAP_NET_ADMIN | Default-deny network (OPTIONAL) |
| cgroups v2 | ⚠️ DEGRADED | Privileges | Enhanced kernel enforcement (OPTIONAL) |
| Umask | ✅ ENABLED | None | Restrictive file permissions (0077) |

**Security Level**: COMPREHENSIVE (with root) / GOOD (non-root)

### macOS

| Layer | Status | Requirements | Description |
|-------|--------|--------------|-------------|
| rlimits | ❌ **BROKEN** | None | ❌ NOT applied to child processes |
| Timeout | ✅ ENABLED | None | Parent monitors and kills child (ONLY working control) |
| Mount NS | ❌ UNSUPPORTED | N/A | macOS has no mount namespaces |
| Network NS | ❌ UNSUPPORTED | N/A | macOS has no network namespaces |
| cgroups | ❌ UNSUPPORTED | N/A | macOS has no cgroups |
| Umask | ⚠️ INHERITED | None | Process inherits parent umask |

**Security Level**: ❌ **CRITICAL - NOT PRODUCTION READY**

**Actual Status:**
- ❌ No CPU limits (rlimits not propagated)
- ❌ No memory limits (rlimits not propagated)
- ❌ No PID limits (rlimits not propagated)
- ❌ No FD limits (rlimits not propagated)
- ✅ Timeout works (parent kills child)
- ❌ No network isolation possible
- ❌ No filesystem isolation possible

**Use Docker/VM for production.**

### Windows

| Layer | Status | Requirements | Description |
|-------|--------|--------------|-------------|
| Job Objects | ❌ **BROKEN** | None | ❌ Limits NOT applied |
| Timeout | ✅ ENABLED | None | Parent monitors and kills child (ONLY working control) |
| Network Isolation | ❌ UNSUPPORTED | WFP/drivers | No network isolation without kernel components |
| Filesystem | ⚠️ DEGRADED | ACLs | Standard Windows ACL enforcement only |
| Umask | ❌ UNSUPPORTED | N/A | Windows uses different permission model |

**Security Level**: ❌ **CRITICAL - NOT PRODUCTION READY**

**Actual Status:**
- ❌ No memory limits (setJobLimits is NO-OP)
- ❌ No CPU limits (setJobLimits is NO-OP)
- ❌ No PID limits (setJobLimits is NO-OP)
- ✅ Timeout works (parent kills child)
- ❌ No network isolation without WFP
- ❌ No namespace support (Windows concept different from Linux)
- ❌ FD limits not available (Windows uses handles)

**Fix ETA: 1 week. Use Docker until fixed.**

## Default-Deny Security Posture

### Network Access

- **Linux (root)**: Default-deny via network namespace (only loopback)
- **Linux (non-root)**: DEGRADED - network accessible
- **macOS**: DEGRADED - network accessible (documented limitation)
- **Windows**: DEGRADED - network accessible (documented limitation)

Manifest can request network allowlist, enforced best-effort per platform.

### Filesystem Access

- **Linux**: Isolated mount namespace (process view of mounts)
- **macOS**: DEGRADED - standard UNIX permissions
- **Windows**: DEGRADED - standard ACLs

Working directory isolated, HOME set to workdir.

### Subprocess Control

- **Linux**: seccomp can block fork/exec (not yet implemented; claimed available but no code)
- **macOS**: RLIMIT_NPROC NOT applied to child (bug); `sandbox-exec` can deny process-fork (not implemented)
- **Windows**: Job Object limits NOT applied (NO-OP bug); Process Mitigation Policies can block child creation (not implemented)

Manifest must declare subprocess: true to spawn children.

---

## Cross-Reference: Detailed Sandbox Documentation

For detailed analysis of each platform's available mechanisms, bugs, and roadmap:

- **macOS**: [MACOS_SANDBOX.md](MACOS_SANDBOX.md) — sandbox-exec, rlimit bug, SBPL profiles
- **Windows**: [WINDOWS_SANDBOX.md](WINDOWS_SANDBOX.md) — Job Object NO-OP bug, AppContainers, Restricted Tokens
- **Linux**: [LINUX_SANDBOX.md](LINUX_SANDBOX.md) — Implementation details + unimplemented mechanisms (user NS, seccomp, Landlock)
- **Vulnerabilities**: [SECURITY_SANDBOX_LIMITATIONS.md](SECURITY_SANDBOX_LIMITATIONS.md) — Critical bugs and attack vectors
- **Roadmap**: [SANDBOX_ROADMAP.md](SANDBOX_ROADMAP.md) — Prioritized improvement plan across all platforms

