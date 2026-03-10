# MCP-Client Architecture & Workflows

Expert reference guide for understanding mcp-cage system design, module interactions, and execution flows.

## Table of Contents
1. [Module Responsibilities](#module-responsibilities)
2. [Data Flow Architecture](#data-flow-architecture)
3. [Execution Workflow](#execution-workflow-12-step-flow)
4. [Security Layers](#security-layers)
5. [Configuration Precedence](#configuration-precedence)
6. [Error Propagation](#error-propagation-through-layers)
7. [Concurrency Model](#concurrency-model)
8. [Integration Points](#integration-points)
9. [Extension Points](#extension-points)
10. [Common Workflows](#common-workflows)

---

## Module Responsibilities

### `config/` - Configuration Management
**Responsibility:** Load and validate configuration from multiple sources with clear precedence.

**Key Components:**
- `config.go` - Load YAML file + environment variables + CLI flags
- `auth.go` - Manage registry authentication (JWT, Bearer tokens)
- `validation.go` - Validate config schema and values

**Guarantees:**
- Single source of truth for all config (no scattered env lookups)
- Clear precedence: defaults < file < env < flags
- All auth tokens stored securely (0600 perms)
- Config can be re-loaded without restart

**Inputs:** `~/.smcp/config.yaml`, `MCP_*` env vars, CLI flags
**Outputs:** `Config` struct with all settings

---

### `registry/` - Registry Client
**Responsibility:** Communicate with MCP registry to resolve packages and download artifacts.

**Key Components:**
- `client.go` - HTTP client with auth, retries, redirects
- `types.go` - Request/response structures
- `auth.go` - Bearer token injection

**Guarantees:**
- Follows redirects (presigned URLs from S3/GCS) up to 10 hops
- Retries on 5xx with exponential backoff (3 attempts)
- No retries on 4xx except 429 (rate limiting)
- Validates response digest against expected hash
- Rejects corrupted artifacts before caching

**Inputs:** Package reference (org/name@version), auth token
**Outputs:** Manifest + bundle digests, download URLs

**Error Handling:**
- 404 → "Package not found"
- 401/403 → "Authentication failed"
- 5xx → Retry with backoff
- Network timeout → Clear error message with retry instruction

---

### `cache/` - Content-Addressable Storage
**Responsibility:** Store and retrieve manifests/bundles indexed by SHA-256 digest.

**Key Components:**
- `store.go` - Read/write artifacts by digest path
- `locking.go` - Concurrent access without race conditions
- `eviction.go` - LRU eviction when max size exceeded

**Guarantees:**
- Directory structure: `~/.smcp/cache/manifests/sha256:abc.../manifest.json`
- File-level locks prevent concurrent writes to same digest
- Partial downloads cleaned up on error
- Metadata (size, last-accessed, path) tracked for eviction

**Inputs:** Artifact content + expected digest
**Outputs:** Artifact path when requested by digest

**Cache Hit Logic:**
1. Check if digest file exists
2. Verify file size/hash match (paranoid check)
3. Return path (no re-download)

**Cache Miss Logic:**
1. Lock digest path
2. Download artifact
3. Validate digest
4. Write to cache
5. Unlock
6. Return path

---

### `manifest/` - Manifest Parsing & Validation
**Responsibility:** Parse manifest JSON, validate schema, select appropriate entrypoint.

**Key Components:**
- `parser.go` - Unmarshal JSON into `Manifest` struct
- `validator.go` - Schema validation (required fields, valid references)
- `selector.go` - Choose entrypoint by OS/arch

**Guarantees:**
- All manifests must have required fields (name, version, entrypoints)
- Entrypoint selection is deterministic (GOOS, GOARCH)
- Transport must be STDIO or HTTP (no custom)
- Validation fails early with clear error messages

**Inputs:** Raw manifest JSON
**Outputs:** Validated manifest + selected entrypoint

**Validation Rules:**
```
Required: name, version, entrypoints
Transport must be: STDIO or HTTP
Entrypoint for platform/arch must exist
Size limits: manifest ≤ 10MB
```

---

### `policy/` - Security Policy Enforcement
**Responsibility:** Apply manifest-declared security policies (network, env, subprocess).

**Key Components:**
- `policy.go` - Coordinate all policies
- `network.go` - Validate network allowlist
- `env.go` - Filter environment variables

**Guarantees:**
- Policies are additive, never relaxed
- Default-deny for network (if manifest not allowlist, no network)
- Env vars not in allowlist are stripped
- Subprocess blocked unless manifest declares `subprocess: true`

**Inputs:** Manifest + desired env vars
**Outputs:** Sanitized env, network rules, subprocess flag

**Policy Application:**
1. Start with empty policy
2. Parse manifest policy section
3. Validate against whitelist of allowed policies
4. Apply most restrictive rule (AND operation)
5. Return combined policy

---

### `executor/` - Process Execution
**Responsibility:** Start and manage MCP process, handle transport (STDIO/HTTP).

**Key Components:**
- `executor.go` - Interface + common logic
- `stdio.go` - STDIO mode (stdin/stdout, JSON-RPC 2.0)
- `http.go` - HTTP mode (reverse proxy, health checks)

**Guarantees:**
- Process started with sandbox applied
- Env vars set before exec
- Working directory isolated
- PID captured for monitoring
- Graceful shutdown (SIGTERM → SIGKILL)

**Inputs:** Manifest entrypoint, sandbox config, env vars
**Outputs:** Running process, communication channel

**Execution Modes:**
- **STDIO:** Parent reads/writes JSON-RPC to process stdin/stdout
- **HTTP:** Parent proxies HTTP to process localhost:port

---

### `sandbox/` - Isolation & Resource Limits
**Responsibility:** Apply OS-level limits and isolation (different per platform).

**Key Components:**
- `sandbox.go` - Interface
- `linux.go` - cgroups v2, rlimits, namespaces
- `darwin.go` - rlimits, timeouts (no isolation available)
- `windows.go` - Job Objects

**Guarantees:**
- All limits enforced (CPU, memory, PIDs, FDs, timeout)
- Linux: can isolate network + filesystem
- macOS/Windows: best-effort (document limitations)
- Timeouts always enforced (kill if exceeded)

**Platform Strategy:**

**Linux:**
- rlimits (CPU, AS, NPROC, NOFILE)
- cgroups v2 (cpu.max, memory.max, pids.max)
- Network namespaces (empty by default, allowlist override)
- Bind mount filesystem

**macOS:**
- rlimits only
- Process timeouts via parent
- No network isolation possible
- Filesystem perms based on UNIX

**Windows:**
- Job Objects (CPU, memory, process count)
- No network isolation
- Filesystem perms based on NTFS

---

### `audit/` - Audit Logging
**Responsibility:** Record all executions securely (no secrets exposed).

**Key Components:**
- `logger.go` - Structured JSON logging
- `event.go` - Event types (start, end, error)

**Guarantees:**
- All execs logged to `~/.smcp/audit.log` (0600 perms)
- Secrets never logged (redacted or name-only)
- Format: newline-delimited JSON for easy parsing
- Immutable once written (append-only)

**Events Logged:**
- **start:** timestamp, package ref, digest, entrypoint, limits, env allowlist (values redacted)
- **end:** duration, exit code, signal
- **error:** error type, message, recovery action

**Example Event:**
```json
{
  "timestamp": "2026-01-18T10:30:05Z",
  "event": "start",
  "package": "acme/hello-world",
  "ref": "1.2.3",
  "manifest_digest": "sha256:abc123",
  "bundle_digest": "sha256:def456",
  "entrypoint": "/bin/mcp-server",
  "limits": {"cpu_ms": 1000, "memory_mb": 512, "timeout_s": 300},
  "env_allowed": ["API_KEY", "DEBUG"],
  "env_denied": []
}
```

---

## Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ CLI (root.go, run.go, pull.go, cache.go, login.go, doctor.go)  │
└────────────────────────┬────────────────────────────────────────┘
                         │ Parse flags, load config
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Config (config.go)                                              │
│ - Load YAML file, env vars, CLI flags                          │
│ - Validate and merge with defaults                             │
└────────────────────────┬────────────────────────────────────────┘
                         │ Registry URL, auth token, limits, cache dir
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Registry Client (client.go)                                     │
│ - Resolve org/name@ref to manifest/bundle digests             │
│ - Download manifest + bundle (with redirects, retries)        │
└────────────────────────┬────────────────────────────────────────┘
                         │ Raw manifest JSON, bundle tar.gz
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Cache (store.go, locking.go)                                    │
│ - Validate digests                                              │
│ - Store in content-addressable dir (~/.smcp/cache/)            │
│ - Return cached paths for future use                           │
└────────────────────────┬────────────────────────────────────────┘
                         │ Manifest path, bundle path
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Manifest Parser (parser.go, validator.go, selector.go)         │
│ - Unmarshal JSON                                                │
│ - Validate schema (required fields, valid entrypoint)         │
│ - Select entrypoint for GOOS/GOARCH                           │
└────────────────────────┬────────────────────────────────────────┘
                         │ Validated Manifest, selected Entrypoint
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Policy Enforcer (policy.go, network.go, env.go)               │
│ - Apply network allowlist                                       │
│ - Filter environment variables                                 │
│ - Check subprocess permissions                                 │
└────────────────────────┬────────────────────────────────────────┘
                         │ Sanitized Env, Network Rules, Subprocess Flag
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Sandbox Configurator (linux.go, darwin.go, windows.go)        │
│ - Calculate rlimits, cgroups, Job Objects                     │
│ - Prepare namespace configs (Linux)                            │
│ - Set working directory isolation                              │
└────────────────────────┬────────────────────────────────────────┘
                         │ Sandbox Config
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Executor (executor.go, stdio.go, http.go)                      │
│ - Start process with sandbox applied                            │
│ - Set env vars, working dir                                    │
│ - Handle transport (STDIO or HTTP)                             │
└────────────────────────┬────────────────────────────────────────┘
                         │ Running Process, communication channel
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│ Audit Logger (logger.go, event.go)                             │
│ - Log start event (package, digest, entrypoint, limits)       │
│ - Monitor process (on error)                                   │
│ - Log end event (exit code, duration)                          │
└─────────────────────────────────────────────────────────────────┘
```

### Data Structures at Each Layer

```go
// Layer 1: CLI
args := ParseFlags()  // org/name@version, --timeout, --env-file, etc.

// Layer 2: Config
cfg := LoadConfig()  // Registry URL, auth token, default limits

// Layer 3: Registry
manifest_digest, bundle_digest, urls := Resolve(args.Ref)
manifest_bytes, bundle_bytes := Download(urls)

// Layer 4: Cache
manifest_path := Cache.Store("manifests", manifest_digest, manifest_bytes)
bundle_path := Cache.Store("bundles", bundle_digest, bundle_bytes)

// Layer 5: Manifest
manifest := parser.Parse(manifest_bytes)
manifest.Validate()
entrypoint := manifest.SelectEntrypoint(runtime.GOOS, runtime.GOARCH)

// Layer 6: Policy
policy := enforcer.Apply(manifest.Policy, args.Env)

// Layer 7: Sandbox
sandbox_cfg := configurator.Build(manifest.Limits, cfg.DefaultLimits)

// Layer 8: Executor
process := executor.Start(entrypoint, sandbox_cfg, policy.Env)
result := executor.Wait(process, sandbox_cfg.Timeout)

// Layer 9: Audit
audit.Log("start", manifest.Name, manifest_digest, entrypoint, sandbox_cfg.Limits)
audit.Log("end", process.ExitCode, process.Duration)
```

---

## Execution Workflow: 12-Step Flow

Complete workflow from `smcp run org/name@version` to process completion:

### Step 1: Parse CLI Arguments
**Who:** `cli/run.go`

```
Input: ["mcp", "run", "acme/hello@1.2.3", "--timeout", "60s"]
Output: RunCommand{Ref: "acme/hello@1.2.3", Timeout: 60s}
Actions:
  - Validate reference format
  - Parse flags (timeout, env-file, registry, etc.)
  - Return structured command object
```

---

### Step 2: Load Configuration
**Who:** `config/config.go`

```
Input: RunCommand, home directory
Output: Config{Registry: "...", Cache: "...", Limits: ...}
Actions:
  - Load ~/.smcp/config.yaml (if exists)
  - Load MCP_* environment variables
  - Apply CLI flag overrides
  - Merge with hardcoded defaults
  - Validate all values (positive durations, readable paths)
```

---

### Step 3: Resolve Package Reference
**Who:** `registry/client.go`

```
Input: "acme/hello@1.2.3", Config.Registry, auth token
Output: ResolveResponse{
  Manifest: {Digest: "sha256:abc...", URL: "https://..."},
  Bundle: {Digest: "sha256:def...", URL: "https://..."}
}
Actions:
  - HTTP GET /v1/packages/acme/hello/resolve?ref=1.2.3
  - Follow redirects (up to 10)
  - Validate response status
  - Retry on 5xx with backoff
  - Return digest + download URLs

Error Cases:
  - 404: "Package acme/hello not found in registry"
  - 401/403: "Authentication failed: check MCP_REGISTRY_TOKEN"
  - Network timeout: "Registry unreachable, retrying..."
  - All retries exhausted: "Failed to resolve after 3 attempts"
```

---

### Step 4: Check Cache for Manifest
**Who:** `cache/store.go`

```
Input: Manifest digest "sha256:abc123..."
Output: (manifest_path, hit_bool) or error
Actions:
  - Check if ~/.smcp/cache/manifests/sha256:abc123.../manifest.json exists
  - Verify file size and hash (paranoid double-check)
  - Update last-accessed timestamp for eviction
  - Return path if valid, else report miss

Cache Hit:
  → Skip download, advance to Step 5

Cache Miss:
  → Continue to Step 5a (download)
```

---

### Step 5: Download Manifest (if cache miss)
**Who:** `registry/client.go`

```
Input: Manifest URL, expected digest
Output: manifest_bytes
Actions:
  - HTTP GET manifest URL (with redirects)
  - Calculate SHA-256 of response
  - Compare against expected digest
  - Return bytes

Validation:
  - Reject if digest doesn't match (CRITICAL SECURITY)
  - Reject if size > 10MB
  - Reject if malformed JSON

Error:
  - Retry up to 3 times on 5xx
  - Fail immediately on 4xx
```

---

### Step 6: Cache Manifest
**Who:** `cache/store.go`

```
Input: manifest_bytes, digest "sha256:abc123..."
Output: manifest_path
Actions:
  - Acquire file lock on digest path
  - Write to temp file
  - Atomic rename to final location
  - Release lock
  - Return path

Race Condition Safety:
  - If two processes try to cache same digest simultaneously:
    - First locks, writes, commits
    - Second waits on lock, finds cache hit, returns path
    - No corruption or duplication
```

---

### Step 7: Parse & Validate Manifest
**Who:** `manifest/parser.go` + `manifest/validator.go`

```
Input: manifest_bytes (raw JSON)
Output: *Manifest (validated, typed struct)
Actions:
  - Unmarshal JSON into struct
  - Validate required fields (name, version, entrypoints)
  - Validate schema (transport must be STDIO or HTTP)
  - Select entrypoint for current platform/arch
  - Return validated manifest

Validation Failures:
  - Missing name/version: "Invalid manifest: missing 'name' field"
  - Invalid JSON: "Manifest parsing error: ..."
  - No entrypoint for platform: "No entrypoint for linux/amd64"
  - Invalid transport: "Transport must be STDIO or HTTP, got: ..."
  - All failures are fatal, exit code 3
```

---

### Step 8: Select Entrypoint
**Who:** `manifest/selector.go`

```
Input: Manifest, runtime.GOOS, runtime.GOARCH
Output: Entrypoint{Command: "...", Args: [...]}
Actions:
  - Build platform key (e.g., "linux-amd64")
  - Look up in manifest.Entrypoints
  - Extract command and args
  - Validate command is executable (in bundle context)
  - Return resolved entrypoint

Examples:
  Manifest declares: {"entrypoints": {"linux-amd64": {"command": "./bin/server"}}}
  Runtime: linux/amd64
  Output: Entrypoint{Command: "./bin/server", Args: []}

  Fallback strategy: If exact match not found, try arch-only (e.g., "*-amd64")
```

---

### Step 9: Check Cache for Bundle
**Who:** `cache/store.go`

```
Input: Bundle digest "sha256:def456..."
Output: (bundle_path, hit_bool) or error
Actions:
  - Check if ~/.smcp/cache/bundles/sha256:def456.../bundle.tar.gz exists
  - Verify file size and hash
  - Return path if valid

Cache Hit:
  → Skip download, advance to Step 10

Cache Miss:
  → Continue to Step 9a (download)
```

---

### Step 10: Download & Cache Bundle (if cache miss)
**Who:** `registry/client.go` + `cache/store.go`

```
Input: Bundle URL, expected digest
Output: bundle_path in cache
Actions:
  - HTTP GET bundle URL (with redirects, retries)
  - Calculate SHA-256 of streaming response
  - Compare against expected digest
  - Atomic write to cache
  - Return cache path

Notes:
  - For large bundles (up to 100MB), stream to temp file (don't hold in RAM)
  - Show progress bar during download
  - Same race condition safety as manifest caching
```

---

### Step 11: Apply Security Policies & Configure Sandbox
**Who:** `policy/policy.go` + `sandbox/linux|darwin|windows.go`

```
Input: Manifest, CLI env, Config default limits
Output: ExecutionContext{Env, Limits, NetworkRules}
Actions:
  - Parse manifest policy (network allowlist, env allowlist, subprocess flag)
  - Merge with CLI-provided env and limits
  - Validate all values (no nil, positive, within reasonable bounds)
  - Build platform-specific sandbox config:

    Linux:
      - rlimits (CPU, AS, NPROC, NOFILE, CORE)
      - cgroups v2 paths (if available)
      - network namespace setup (empty by default)
      - seccomp filter (if subprocess: false)
      - mount namespace (bind mount bundle dir, isolate /tmp)

    macOS:
      - rlimits only
      - Timeout tracking

    Windows:
      - Job Object handle with limits

  - Return ready-to-use execution context
```

---

### Step 12: Execute Process & Audit
**Who:** `executor/executor.go` + `executor/stdio.go|http.go` + `audit/logger.go`

```
Input: ExecutionContext, bundle_path, entrypoint
Output: Process completion, exit code
Actions:

  12a. Log START event
    → timestamp, package, digest, entrypoint, limits (values redacted)
    → write to ~/.smcp/audit.log (append-only JSON)

  12b. Extract bundle
    → tar.gz → temp directory OR embedded execution
    → prepare working directory

  12c. Apply sandbox
    → set rlimits (all platforms)
    → create cgroups (Linux)
    → setup namespace (Linux)
    → create Job Object (Windows)
    → set working directory, umask

  12d. Set environment
    → start with clean env
    → add allowlist vars from policy
    → add entrypoint-specific overrides
    → never expose secrets directly

  12e. Execute process
    → fork/exec with all configs applied
    → capture PID
    → attach stderr/stdout (for logging)

  12f. Monitor process
    → poll exit status
    → enforce timeout (SIGTERM → SIGKILL after delay)
    → capture exit code
    → log any errors

  12g. Log END event
    → timestamp, exit code, duration, signal (if killed)
    → write to audit log

  12h. Return to user
    → exit code from process (or 124 if timeout, 125 if signal)
    → all output already streamed (STDIO) or proxied (HTTP)

Process Monitoring:
  - If timeout exceeded: send SIGTERM, wait 5s, send SIGKILL
  - If memory exceeded (Linux cgroups): OOM kill, exit code reflects
  - If too many FDs: process cannot create more, syscall fails
  - All limits applied at process spawn (no runtime adjustment)
```

---

## Security Layers

### Layer 1: Digest Validation (Supply Chain)
**Where:** Registry client, cache store
**What:** Validates SHA-256 of manifest and bundle before use

```go
// Before caching manifest
computed := sha256.Sum256(manifest_bytes)
if computed != expected_digest {
    return error("Digest mismatch: package may be corrupted or tampered")
}
// Only then cache and use
```

**Invariant:** No execution without validated digest
**Threat:** MITM attack, corrupted download
**Trust:** Registry digest is correct (registry integrity is assumed)

---

### Layer 2: Manifest Validation (Schema)
**Where:** Manifest parser
**What:** Validates manifest structure and coherence

```
Required fields: name, version, entrypoints, (optional: policy)
Entrypoint must exist for current platform/arch
Transport must be STDIO or HTTP (no custom)
Command path must be relative (no absolute /bin/... unless sandboxed)
Size limit: manifest ≤ 10MB
```

**Invariant:** No execution without valid manifest
**Threat:** Malformed manifest causes undefined behavior
**Recovery:** Fail fast with clear error, exit code 3

---

### Layer 3: Policy Enforcement (Execution Control)
**Where:** Policy enforcer
**What:** Applies manifest-declared policies to limit process capabilities

```
Network: Default-deny
  - If manifest.policy.network.allowlist exists, only allow those domains
  - Otherwise, drop all network (or document OS limitation)

Environment: Default-deny
  - If manifest.policy.env.allow exists, only pass those vars
  - Otherwise, strip all env except PATH, HOME, SHELL

Subprocess: Default-deny
  - If manifest.policy.subprocess: true, allow fork/exec
  - Otherwise, block with seccomp (Linux) or document limitation
```

**Invariant:** Policy is additive and never relaxed
**Threat:** Process escape, unauthorized network access, subprocess chain
**Recovery:** Policy violation is audit logged but not always blockable (depends on OS)

---

### Layer 4: Resource Limits (Denial of Service)
**Where:** Sandbox configurator
**What:** Applies OS-level resource limits to prevent resource exhaustion

```
CPU: 1000 millicores (1 core) by default
  - Enforced via rlimit RLIMIT_CPU or cgroups
  - Process slowed/killed if exceeded

Memory: 512 MB by default
  - Enforced via rlimit RLIMIT_AS or cgroups
  - Process OOM killed if exceeded

PIDs: 32 by default
  - Enforced via RLIMIT_NPROC or cgroups pids.max
  - fork() fails if exceeded

File Descriptors: 256 by default
  - Enforced via RLIMIT_NOFILE
  - open() fails if exceeded

Timeout: 5 minutes by default
  - Enforced by parent process timer
  - SIGTERM → SIGKILL sequence

All values validated before applied (no nil, no negative, reasonable bounds)
```

**Invariant:** All limits always applied, never skipped
**Threat:** DoS, resource exhaustion, infinite loop
**Recovery:** Kill process with extreme prejudice (SIGKILL), exit code 124

---

### Layer 5: Isolation (Containment)
**Where:** Sandbox OS-specific
**What:** Isolates process from system (to degree supported by OS)

**Linux:**
- Network namespace: Empty by default, can't access external network
- Mount namespace: Bundle mounted, /tmp isolated
- PID namespace: Process can't see siblings
- Seccomp: Block unauthorized syscalls

**macOS:**
- No strong isolation (document limitation)
- Rely on UNIX perms and kernel isolation

**Windows:**
- Job Object: Limits propagate to children
- No network isolation (document limitation)

**Invariant:** Best-effort isolation per platform
**Threat:** Process reads sensitive files, communicates with attacker
**Recovery:** Audit logs reveal unauthorized access attempts

---

### Layer 6: Audit Trail (Forensics)
**Where:** Audit logger
**What:** Records all executions for forensic analysis

```json
{
  "timestamp": "2026-01-18T10:30:05Z",
  "event": "start",
  "package": "acme/hello",
  "version": "1.2.3",
  "manifest_digest": "sha256:abc123",
  "bundle_digest": "sha256:def456",
  "entrypoint": "/bin/server --mode stdio",
  "limits": {
    "cpu_millis": 1000,
    "memory_mb": 512,
    "timeout_seconds": 300
  },
  "env_allowed": ["API_KEY", "DEBUG"],
  "env_denied": ["SECRET", "PASSWORD"]
}
```

**Invariant:** All execs logged, secrets never exposed
**Threat:** Unauthorized execution, forensic evasion
**Recovery:** Audit log immutable, queryable with jq/Elasticsearch

---

## Configuration Precedence

Clear hierarchy ensures predictable configuration resolution:

```
Priority 4 (Lowest): Hardcoded defaults
↑
Priority 3: ~/.smcp/config.yaml (file)
↑
Priority 2: MCP_* environment variables (env)
↑
Priority 1 (Highest): CLI flags (command line)
```

### Example Resolution

**Default limits:**
```yaml
executor:
  max_cpu: 1000        # millicores
  max_memory: 512M     # bytes
  max_pids: 32
  max_fds: 256
  default_timeout: 5m
```

**File override (~/.smcp/config.yaml):**
```yaml
executor:
  max_memory: 1G
  default_timeout: 10m
```

**Env override:**
```bash
export MCP_MAX_CPU=2000
export MCP_TIMEOUT=30s
```

**CLI override:**
```bash
smcp run acme/test@1.0.0 --timeout 60s --max-memory 2G
```

**Final resolved config:**
```
max_cpu: 2000        (from CLI)
max_memory: 2G       (from CLI)
max_pids: 32         (from file, since no CLI override)
max_fds: 256         (from file)
default_timeout: 60s (from CLI)
```

### Per-Command Overrides

Some settings can be overridden per-execution:

```bash
# Use different registry for this run
smcp run acme/test@1.0.0 --registry https://custom.registry.com

# Increase timeout for slow server
smcp run acme/slow-tool@1.0.0 --timeout 30m

# Pass environment file
smcp run acme/tool@1.0.0 --env-file ./prod.env

# Add secret (not exposed in process env, only passed to manifest allowlist)
smcp run acme/tool@1.0.0 --secret API_KEY=$APIKEY
```

---

## Error Propagation Through Layers

Each layer must handle errors from lower layers and add context:

```
Layer 1: CLI
  Input error from Config
    ↓ Wrap with context
  Output: "Config error: invalid timeout value: foo (expected duration)"

Layer 2: Config
  Input error from file reader
    ↓ Wrap with context
  Output: "Failed to load config: permission denied: ~/.smcp/config.yaml"

Layer 3: Registry
  Input network error from HTTP client
    ↓ Wrap with context, attempt retries
  Output: "Failed to resolve after 3 attempts: [attempt 1: timeout, attempt 2: 502, attempt 3: 502]"

Layer 4: Cache
  Input digest validation failure
    ↓ Wrap with context
  Output: "Manifest digest validation failed: expected sha256:abc, got sha256:xyz (corrupted download?)"

Layer 5: Manifest
  Input malformed JSON
    ↓ Wrap with context
  Output: "Invalid manifest: JSON parsing error at line 5: unexpected token"

Layer 6: Policy
  Input manifest security policy violation
    ↓ Log and continue (some violations not blockable)
  Output: "Network policy: org/name declares network access but OS doesn't support isolation"

Layer 7: Sandbox
  Input rlimit set failure
    ↓ Wrap with context
  Output: "Failed to apply resource limits: operation not permitted (running as non-root?)"

Layer 8: Executor
  Input process start failure
    ↓ Wrap with context
  Output: "Failed to start process: command not found: /bin/server"

Layer 9: Audit
  Input file write failure
    ↓ Critical: always log even if audit fails
  Output: "Failed to write audit log: disk full"
```

**Error Exit Codes:**
- 0: Success
- 1: Config error (precedence, validation)
- 2: Network/registry error (resolve, download)
- 3: Validation error (digest, manifest, policy)
- 4: Execution error (process failed, entrypoint not found)
- 5: Timeout error (exceeded max duration)
- 124: Signal termination (SIGKILL)
- 125: Resource limit exceeded (OOM, NPROC, etc.)

---

## Concurrency Model

### Thread-Safe Components

**Cache store:**
- File-level locks on each digest path
- Multiple processes can safely cache/retrieve simultaneously
- Lock held only during write (fast)

**Audit logger:**
- Append-only file (atomic writes)
- Multiple processes can log simultaneously
- OS guarantees atomic append (on most filesystems)

### Serialized Components

**Registry resolve:**
- Single HTTP request per reference
- No concurrent resolve needed (result is immutable)

**Process execution:**
- One process per command invocation
- Parent process waits (sequential)

### Race Condition Prevention

**Cache write race:**
```
Process A                          Process B
Check cache (miss)                Check cache (miss)
Acquire lock A  ----wait----→  (blocked)
Download/validate               (blocked)
Write to cache                  (blocked)
Release lock A                  Acquire lock B
                                Check cache (hit!)
                                Return path
                                Release lock B
```

No corruption, both processes eventually succeed without duplication.

### No Goroutines in Core Flow

The main execution path (CLI → Registry → Cache → Manifest → Executor) is intentionally sequential:
- Simpler error handling
- Easier auditing and debugging
- Clear dependency flow
- No deadlock potential

Concurrency only used for:
- Timeout monitoring (separate goroutine as watchdog)
- Progress bar updates (non-critical)

---

## Integration Points

### Registry ↔ Cache

**Contract:**
Registry downloads artifact → validates digest → passes to cache
Cache stores artifact → returns path

```go
// registry/client.go
manifest_bytes := downloadManifest(url)
manifest_digest := validateDigest(manifest_bytes, expected_digest)
cache_path := cache.Store("manifests", manifest_digest, manifest_bytes)
```

**Error Handling:**
- If digest validation fails in registry, artifact never reaches cache
- If cache.Store fails, download is wasted but previous cache remains valid

---

### Manifest ↔ Policy

**Contract:**
Manifest declares policies → policy enforcer validates and applies them

```go
// manifest/parser.go
manifest := parseManifest(json)

// policy/policy.go
policy := enforcer.Apply(manifest.Policy, cli_env)
policy.Env  // validated, allowlisted env vars only
policy.Network  // validated allowlist
policy.Subprocess  // validated boolean
```

**Error Handling:**
- Invalid policy in manifest is fatal (manifest validation catches it)
- Policy application is logged but violations may not be blockable (OS limitation)

---

### Policy ↔ Sandbox

**Contract:**
Policy outputs security requirements → sandbox implements per-OS

```go
// sandbox/linux.go
func (s *LinuxSandbox) Apply(policy *Policy, limits *Limits) error {
  // Create network namespace based on policy.Network.Allowlist
  // Apply cgroups based on limits.MaxCPU, limits.MaxMemory
  // Load seccomp filter based on policy.Subprocess
}
```

**Error Handling:**
- Sandbox fails early if limits invalid (validation happens in policy layer)
- Some policies unsupported on some OS (documented with smcp doctor)

---

### Executor ↔ Audit

**Contract:**
Executor starts process with all configs → audit logs start + end

```go
// executor/executor.go
audit.Log("start", package, manifest_digest, entrypoint, limits)
process := os.StartProcess(entrypoint, env, sandbox)
exit_code, duration := process.Wait()
audit.Log("end", exit_code, duration)
```

**Error Handling:**
- Start event logged before process launch
- End event logged after process exit (or timeout)
- Audit logs even if process fails

---

## Extension Points

### Adding a New Transport Type

**Current:** STDIO, HTTP
**Example:** GRPC (hypothetical future)

**Steps:**

1. Define in manifest schema:
```json
{
  "transport": "grpc",
  "grpc": {
    "port": 50051,
    "tls": true
  }
}
```

2. Add Executor implementation:
```go
// executor/grpc.go
type GRPCExecutor struct {}

func (e *GRPCExecutor) Start(ctx context.Context, cmd Entrypoint, env []string) (Transport, error) {
  // Start process
  // Connect to localhost:50051
  // Return gRPC client
}
```

3. Register in executor factory:
```go
// executor/executor.go
switch manifest.Transport {
  case "stdio":
    return newStdioExecutor(...)
  case "http":
    return newHTTPExecutor(...)
  case "grpc":
    return newGRPCExecutor(...)
}
```

4. Add tests:
```go
// executor/grpc_test.go
func TestGRPCExecutor_Start(t *testing.T) { ... }
func TestGRPCExecutor_Communication(t *testing.T) { ... }
```

---

### Adding a New Authentication Method

**Current:** Bearer token, Basic auth
**Example:** OAuth2 (hypothetical future)

**Steps:**

1. Add config option:
```yaml
auth:
  type: oauth2
  oauth2:
    client_id: "..."
    client_secret: "..."
    token_url: "https://..."
```

2. Implement auth provider:
```go
// config/auth.go
type OAuth2Provider struct { ... }

func (p *OAuth2Provider) GetToken() (string, error) {
  // Exchange credentials for access token
  // Cache token + refresh logic
  // Return Bearer token
}
```

3. Register in auth factory:
```go
// config/auth.go
switch cfg.Auth.Type {
  case "bearer":
    return newBearerAuth(cfg.Auth.Bearer)
  case "basic":
    return newBasicAuth(cfg.Auth.Basic)
  case "oauth2":
    return newOAuth2Auth(cfg.Auth.OAuth2)
}
```

4. Add tests:
```go
// config/auth_test.go
func TestOAuth2Auth_GetToken(t *testing.T) { ... }
func TestOAuth2Auth_Refresh(t *testing.T) { ... }
```

---

### Adding a New Sandbox Platform

**Current:** Linux, macOS, Windows
**Example:** FreeBSD (hypothetical future)

**Steps:**

1. Create implementation:
```go
// sandbox/freebsd.go
type FreeBSDSandbox struct {}

func NewFreeBSDSandbox(limits *Limits) *FreeBSDSandbox { ... }

func (s *FreeBSDSandbox) Apply(cmd *exec.Cmd) error {
  // Use FreeBSD jails or rctl for limits
  // Set env, working dir, etc.
  return nil
}

func (s *FreeBSDSandbox) Capabilities() string {
  return "rlimits,jails,rctl (document limitations)"
}
```

2. Register in factory:
```go
// sandbox/sandbox.go
func NewSandbox(limits *Limits) Sandbox {
  switch runtime.GOOS {
    case "linux":
      return NewLinuxSandbox(limits)
    case "darwin":
      return NewDarwinSandbox(limits)
    case "windows":
      return NewWindowsSandbox(limits)
    case "freebsd":
      return NewFreeBSDSandbox(limits)
  }
}
```

3. Add tests:
```go
// sandbox/freebsd_test.go
// +build freebsd
func TestFreeBSDSandbox_RctlLimits(t *testing.T) { ... }
```

4. Update `smcp doctor`:
```go
// cli/doctor.go
case "freebsd":
  checkJails()
  checkRctl()
  checkCapabilities()
```

---

## Common Workflows

### Workflow 1: smcp run (Execute)

```bash
smcp run acme/hello-world@1.2.3
```

**Steps:**
1. Parse CLI flags
2. Load config (~/.smcp/config.yaml)
3. Resolve reference (registry.resolve)
4. Cache check/download manifest
5. Cache check/download bundle
6. Parse + validate manifest
7. Select entrypoint
8. Apply policies + sandbox
9. Extract bundle (if needed)
10. Execute process (STDIO/HTTP)
11. Wait for completion
12. Log audit event

**Typical output:**
```
[2026-01-18T10:30:00Z] Resolving acme/hello-world@1.2.3...
[2026-01-18T10:30:01Z] Resolved to sha256:abc... (manifest), sha256:def... (bundle)
[2026-01-18T10:30:01Z] Downloading manifest (4.2 KB)...
[2026-01-18T10:30:02Z] Downloading bundle (12.5 MB)...
[2026-01-18T10:30:05Z] Validating digests...
[2026-01-18T10:30:05Z] Starting MCP server (STDIO)...
[2026-01-18T10:30:05Z] Server running (PID 12345)
```

---

### Workflow 2: smcp pull (Pre-download)

```bash
smcp pull acme/hello-world@1.2.3
```

**Steps:**
1-6. Same as `smcp run`
7-12. Skip (no execution)

**Output:**
```
[2026-01-18T10:30:00Z] Pulling acme/hello-world@1.2.3...
[2026-01-18T10:30:05Z] Successfully pulled. Manifest: sha256:abc..., Bundle: sha256:def...
```

**Use case:** CI/CD pipeline pre-caches bundles before deployment

---

### Workflow 3: smcp login (Authenticate)

```bash
smcp login --token <JWT>
```

**Steps:**
1. Parse token
2. Validate JWT structure (no validation of claims, just structure)
3. Store in ~/.smcp/auth.json (0600 perms)
4. Load in subsequent runs (config layer)

**Output:**
```
[2026-01-18T10:30:00Z] Authenticating with registry...
[2026-01-18T10:30:00Z] Token saved to ~/.smcp/auth.json
```

**Subsequent runs:**
- Config loader reads ~/.smcp/auth.json
- Registry client adds Authorization: Bearer <token> header
- Private packages resolved and downloaded

---

### Workflow 4: smcp cache ls (Inspect Cache)

```bash
smcp cache ls
```

**Steps:**
1. Read ~/.smcp/cache/ directory structure
2. List all manifests and bundles
3. Show size + last-accessed time
4. Output in table format

**Output:**
```
TYPE      DIGEST                                  SIZE      LAST USED
manifest  sha256:abc123...                        4.2 KB    2 hours ago
bundle    sha256:def456...                        12.5 MB   2 hours ago
manifest  sha256:ghi789...                        3.8 KB    1 week ago
```

---

### Workflow 5: smcp cache rm (Evict)

```bash
smcp cache rm sha256:ghi789...
```

**Steps:**
1. Validate digest format
2. Delete from ~/.smcp/cache/
3. Update metadata

**Output:**
```
Removed manifest sha256:ghi789... (freed 3.8 KB)
```

**Or bulk:**
```bash
smcp cache rm --all
```

Output:
```
Removed 3 artifacts (freed 20.3 MB)
```

---

### Workflow 6: smcp doctor (Diagnose)

```bash
smcp doctor
```

**Steps:**
1. Detect OS, arch
2. Check cgroups availability (Linux)
3. Check network namespaces (Linux)
4. Check seccomp (Linux)
5. Check rlimits (all OS)
6. Check cache directory
7. Check auth file
8. Summary of capabilities/limitations

**Output:**
```
MCP Launcher Diagnosis
======================

System:
  OS: Linux 5.15.0 (amd64)

Security Capabilities:
  ✓ Resource Limits (rlimits): available
  ✓ Cgroups v2: available
  ✓ Network Namespaces: available (requires CAP_NET_ADMIN)
  ✓ Seccomp: available

Running Context:
  User: dani
  Root: no

Limitations:
  ⚠ Running as non-root: cgroups delegation may be limited
  ⚠ CAP_NET_ADMIN not available: can't create network namespaces

Storage:
  Cache Directory: ~/.smcp/cache (writable, 12.3 MB used)
  Auth File: ~/.smcp/auth.json (readable, 1 token registered)

Recommendations:
  • For full network isolation, run with CAP_NET_ADMIN or in rootless container
  • Monitor cache size, run 'smcp cache rm --all' to free space
```

---

### Workflow 7: Error Recovery

**Scenario:** Network timeout during manifest download

```
[2026-01-18T10:30:01Z] Downloading manifest...
[2026-01-18T10:30:31Z] Network timeout (30s exceeded)
[2026-01-18T10:30:31Z] Retrying (attempt 2/3)...
[2026-01-18T10:31:01Z] Network timeout (30s exceeded)
[2026-01-18T10:31:01Z] Retrying (attempt 3/3)...
[2026-01-18T10:31:31Z] Network timeout (30s exceeded)
[2026-01-18T10:31:31Z] Failed to download after 3 attempts

ERROR: Network error: Failed to resolve acme/hello-world@1.2.3
  Cause: All retries exhausted
  Suggestion: Check internet connection or try --registry <custom-registry>

Exit Code: 2
```

**User actions:**
- Check internet: `ping registry.example.com`
- Retry with custom registry: `smcp run acme/test@1.0.0 --registry https://mirror.com`
- Increase timeout: `smcp run acme/test@1.0.0 --registry-timeout 60s` (if added to config)

---

This skill document serves as the authoritative reference for mcp-cage system design. When working on the project, consult this document for:

- Where to make changes (which module owns which responsibility)
- How data flows through the system
- What guarantees each layer provides
- How errors should be handled and propagated
- Where concurrency is allowed and where it must be serialized
- How to extend the system with new features

