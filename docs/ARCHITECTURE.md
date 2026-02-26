# Architecture Documentation

## System Overview

mcp-client is a CLI tool that implements a secure launcher for MCP servers. It follows a layered architecture with clear separation of concerns.

```
┌─────────────────────────────────────────────────────────┐
│                   User Interface (CLI)                   │
│  Commands: run, pull, info, login, cache, doctor        │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                  Core Orchestration                      │
│  - Package reference parsing                            │
│  - Workflow coordination                                │
│  - Error handling and user feedback                     │
└─┬──────────┬──────────┬──────────┬──────────┬──────────┘
  │          │          │          │          │
  ▼          ▼          ▼          ▼          ▼
┌───────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
│Config │ │Registry│ │ Cache  │ │Manifest│ │ Policy │
│       │ │Client  │ │ Store  │ │Parser  │ │Engine  │
└───────┘ └────────┘ └────────┘ └────────┘ └────────┘
                     │
            ┌────────▼────────┐
            │   Executor      │
            │   (STDIO/HTTP)  │
            └────────┬────────┘
                     │
            ┌────────▼────────┐
            │    Sandbox      │
            │ (Linux/Mac/Win) │
            └────────┬────────┘
                     │
            ┌────────▼────────┐
            │  Audit Logger   │
            │  (JSON events)  │
            └─────────────────┘
```

## Module Responsibilities

### 1. CLI Layer (`internal/cli/`)

**Purpose**: User interaction and command routing

**Components**:
- `root.go`: Root command setup, global flags, version info
- `run.go`: Execute MCP servers (main workflow)
- `pull.go`: Pre-download packages
- `info.go`: Display package information
- `cache.go`: Cache management (ls, rm, gc)
- `doctor.go`: System diagnostics
- `login.go` / `logout.go`: Authentication (placeholders)

**Responsibilities**:
- Parse command-line arguments
- Load configuration
- Coordinate module interactions
- Format output for users
- Handle errors gracefully

### 2. Configuration (`internal/config/`)

**Purpose**: Centralized configuration management

**Components**:
- `config.go`: Config struct and loading logic
- `config_test.go`: Configuration tests

**Features**:
- YAML file loading from `~/.smcp/config.yaml`
- Environment variable overrides (MCP_*)
- Command-line flag overrides
- Sensible defaults
- Path expansion (`~` support)

**Configuration Sources** (priority order):
1. Command-line flags (highest)
2. Environment variables
3. Config file
4. Default values (lowest)

### 3. Registry Client (`internal/registry/`)

**Purpose**: HTTP API client for MCP registry

**Components**:
- `client.go`: Main HTTP client with retry logic
- `types.go`: API request/response structures
- `auth.go`: Authentication and token management
- `digest.go`: Digest parsing and validation
- `errors.go`: Custom error types

**Features**:
- Resolve package references to artifact URLs
- Download manifests and bundles
- Follow redirects (presigned URLs)
- Retry with exponential backoff (5xx errors)
- Multiple auth methods (Bearer, Token, Basic)
- SHA-256 digest validation
- Structured logging

**API Endpoints**:
- `GET /v1/org/{org}/mcps/{name}/resolve?ref={ref}`
- `GET /v1/org/{org}/artifacts/{digest}/manifest`
- `GET /v1/org/{org}/artifacts/{digest}/bundle`
- `POST /v1/auth/login`
- `GET /v1/catalog`

### 4. Cache Store (`internal/cache/`)

**Purpose**: Content-addressable local cache

**Components**:
- `store.go`: Cache operations (Put, Get, Delete, List)
- `locking.go`: File-based locking for concurrency
- `store_test.go`: Comprehensive test suite

**Design**:
- Content-addressable by digest
- Separate directories for manifests and bundles:
  ```
  ~/.smcp/cache/
    manifests/
      sha256:abc123.../
    bundles/
      sha256:def456.../
  ```
- Atomic writes (temp file + rename)
- Thread-safe with RWMutex
- Metadata tracking (size, last access)

**Operations**:
- `PutManifest/GetManifest`: Store/retrieve manifests
- `PutBundle/GetBundle`: Store/retrieve bundles
- `Exists`: Check artifact presence
- `Delete`: Remove artifacts
- `List`: Enumerate all cached items
- `Size`: Calculate total cache size
- `CopyToPath`: Extract artifact to destination

### 5. Manifest Parser (`internal/manifest/`)

**Purpose**: Parse and validate MCP package manifests

**Components**:
- `parser.go`: Manifest struct and parsing logic
- `parser_test.go`: Validation tests

**Manifest Schema**:
```json
{
  "schema_version": "1.0",
  "package": {
    "id": "org/name",
    "version": "1.0.0",
    "git_sha": "abc123"
  },
  "bundle": {
    "digest": "sha256:...",
    "size_bytes": 12345
  },
  "transport": {
    "type": "stdio"
  },
  "entrypoints": [
    {
      "os": "linux",
      "arch": "amd64",
      "command": "./bin/server",
      "args": ["--mode", "stdio"]
    }
  ],
  "permissions_requested": {
    "network": ["*.example.com"],
    "environment": ["HOME", "USER"],
    "subprocess": false,
    "filesystem": ["/tmp"]
  },
  "limits_recommended": {
    "max_cpu": 1000,
    "max_memory": "512M",
    "max_pids": 10,
    "max_fds": 100,
    "timeout": "5m"
  }
}
```

**Validation Rules**:
- Required fields present
- Package ID format (`org/name`)
- Digest format (`sha256:` or `sha512:`)
- Transport type (`stdio` or `http`)
- Entrypoint for current platform exists
- HTTP transport has port specified

**Entrypoint Selection**:
1. Match exact OS and arch
2. Fall back to OS match with any arch
3. Error if no compatible entrypoint

### 6. Policy Engine (`internal/policy/`)

**Purpose**: Security policy enforcement

**Components**:
- `policy.go`: Policy struct and enforcement logic
- `policy_test.go`: Policy tests (100% coverage)

**Policy Types**:
1. **Package Allowlists**: Which org/packages are allowed
2. **Resource Limits**: Max CPU, memory, PIDs, FDs, timeout
3. **Network Allowlists**: Allowed domains/IPs
4. **Environment Filtering**: Which env vars to pass
5. **Subprocess Control**: Allow/deny subprocess creation

**Limit Merging**:
- Policy limits vs manifest limits
- **Stricter always wins** (minimum of both)
- Policy can override manifest requests

**Network Allowlist**:
- Wildcard support: `*.example.com`
- Case-insensitive matching
- Default-deny if no allowlist

### 7. Executor (`internal/executor/`)

**Purpose**: Process execution and lifecycle management

**Components**:
- `executor.go`: STDIO executor implementation

**Execution Flow**:
1. Create `exec.Cmd` with entrypoint
2. Set working directory
3. Configure environment variables
4. Apply sandbox restrictions
5. Connect stdin/stdout/stderr
6. Start process
7. Wait with timeout
8. Extract exit code
9. Return outcome

**Timeout Handling**:
- Context-based cancellation
- SIGTERM first, then SIGKILL
- Proper cleanup on timeout

### 8. Sandbox (`internal/sandbox/`)

**Purpose**: Platform-specific resource isolation

**Architecture**:
```
sandbox.go (interface)
    │
    ├─→ linux.go (//go:build linux)
    │   ├─ rlimits (RLIMIT_CPU, AS, NPROC, NOFILE)
    │   ├─ cgroups v2 (cpu.max, memory.max, pids.max)
    │   └─ namespaces (net, mount, pid)
    │
    ├─→ darwin.go (//go:build darwin)
    │   ├─ rlimits (CPU, AS, NPROC, NOFILE)
    │   └─ documented limitations
    │
    └─→ windows.go (//go:build windows)
        ├─ Job Objects (CPU, memory, PIDs)
        └─ documented limitations
```

**Capabilities** (platform-specific):
| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| CPU Limit | ✅ | ✅ | ✅ |
| Memory Limit | ✅ | ✅ | ✅ |
| PID Limit | ✅ | ✅ | ✅ |
| FD Limit | ✅ | ✅ | ❌ |
| Network Isolation | ✅* | ❌ | ❌ |
| Filesystem Isolation | ✅* | ⚠️ | ⚠️ |

*Requires root or CAP_NET_ADMIN

**Resource Limit Application**:
- CPU: millicores → rlimit seconds
- Memory: parse K/M/G → bytes
- PIDs: direct mapping
- FDs: direct mapping (NOFILE)

### 9. Audit Logger (`internal/audit/`)

**Purpose**: Compliance and forensic logging

**Components**:
- `logger.go`: JSON structured logger
- `logger_test.go`: Audit tests

**Event Types**:
1. **Start**: Execution begins
2. **End**: Execution completes
3. **Error**: Execution fails

**Log Format** (JSON Lines):
```json
{"timestamp":"2026-01-18T15:00:00Z","event":"start","package":"org/name","version":"1.0.0","git_sha":"abc123","entrypoint":"./bin/server","limits":{"max_cpu":1000}}
{"timestamp":"2026-01-18T15:01:00Z","event":"end","package":"org/name","duration":"60s","exit_code":0,"outcome":"success"}
{"timestamp":"2026-01-18T15:02:00Z","event":"error","package":"org/name","error":"timeout exceeded"}
```

**Security**:
- No secret values logged
- File permissions 0600
- Thread-safe writes
- ISO 8601 timestamps

## Data Flow

### smcp run org/name@1.0.0

```
1. Parse Reference
   org/name@1.0.0 → {org: "org", name: "name", ref: "1.0.0"}

2. Resolve via Registry
   GET /v1/org/org/mcps/name/resolve?ref=1.0.0
   → manifest_digest, manifest_url, bundle_digest, bundle_url

3. Check Cache
   cache.Exists(manifest_digest) && cache.Exists(bundle_digest)
   → If miss: Download and validate

4. Parse Manifest
   manifest_bytes → Manifest struct
   → Validate schema
   → Select entrypoint for current OS/arch

5. Apply Policy
   policy.CheckPackage("org/name")
   policy.ApplyLimits(manifest)
   → ExecutionLimits (merged policy + manifest)

6. Extract Bundle
   bundle.tar.gz → /tmp/mcp-XXXXX/
   → Verify paths (no directory traversal)
   → Enforce size limits
   → Set permissions (0600)

7. Setup Environment
   Load from --env-file
   Filter via policy allowlist
   → Final env vars

8. Create Sandbox
   sandbox.New() → platform-specific implementation
   sandbox.Apply(cmd, limits)

9. Audit Start
   logger.LogStart(package, version, entrypoint, limits)

10. Execute
    cmd.Start() → wait with timeout
    → Connect stdin/stdout/stderr

11. Audit End
    logger.LogEnd(package, duration, exit_code, outcome)

12. Cleanup
    Remove /tmp/mcp-XXXXX/
```

## Concurrency Model

### Thread Safety

**Cache Store**:
- `sync.RWMutex` for read/write locking
- Atomic file writes (temp + rename)
- File-based locks for multi-process safety

**Audit Logger**:
- `sync.Mutex` for write serialization
- Single file handle with exclusive access

**Registry Client**:
- Stateless (safe for concurrent use)
- Each request creates new http.Request

### Concurrent Operations

Safe concurrent operations:
- Multiple `smcp run` commands (different packages)
- Multiple `smcp pull` commands (different packages)
- `smcp cache ls` while downloading

Serialized operations:
- Cache writes for same digest
- Audit log writes

## Error Handling Strategy

### Error Types

1. **User Errors** (exit code 1)
   - Invalid package reference
   - Configuration errors
   - Missing required flags

2. **Network Errors** (exit code 2)
   - Registry unreachable
   - Download failures
   - Timeout during API calls

3. **Validation Errors** (exit code 3)
   - Digest mismatch
   - Invalid manifest schema
   - Unsupported platform

4. **Execution Errors** (exit code 4)
   - Process failed to start
   - MCP server crashed
   - Sandbox application failed

5. **Timeout** (exit code 5)
   - Execution exceeded timeout
   - Process killed

### Error Recovery

**Automatic Retry**:
- Registry API calls (5xx errors, 3 attempts)
- Download operations (transient network errors)

**No Retry**:
- 4xx errors (client errors)
- Validation failures
- Execution failures

**Cleanup on Error**:
- Remove partial downloads
- Delete temporary directories
- Close file handles
- Log error event

## Security Architecture

### Defense in Depth

**Layer 1: Input Validation**
- Package reference format
- Manifest schema validation
- Digest format verification

**Layer 2: Integrity Verification**
- SHA-256 digest validation (mandatory)
- Manifest-to-bundle consistency
- No execution without valid digests

**Layer 3: Policy Enforcement**
- Package allowlists
- Resource limit caps
- Network allowlists
- Environment filtering

**Layer 4: Process Isolation**
- Sandbox resource limits
- Filesystem isolation (platform-dependent)
- Network isolation (Linux only)
- Subprocess control

**Layer 5: Audit Trail**
- All executions logged
- Immutable audit log
- Secret redaction
- Forensic capability

### Trust Boundaries

**Trusted Components**:
- mcp-client binary itself
- Configuration file (user-controlled)
- Local policy settings
- Registry (digest-verified)

**Untrusted Components**:
- MCP package bundles (sandboxed)
- Manifest content (validated)
- Network traffic (TLS + digest verified)

**Trust Verification**:
- Registry → Digest validation
- Bundle → Manifest coherence
- Execution → Audit logging

## Performance Considerations

### Optimization Strategies

**Caching**:
- Content-addressable cache avoids re-downloads
- Lazy loading (download only when needed)
- Cache reuse across references (digest-based)

**Concurrent Operations**:
- Parallel downloads when safe
- Lock-free reads from cache
- Minimal lock contention

**Resource Usage**:
- Streaming downloads (no full buffering)
- Temp file cleanup
- Configurable cache size limits

### Bottlenecks

**Potential**:
- Registry latency (download time)
- Bundle extraction (tar.gz decompression)
- Audit log writes (disk I/O)

**Mitigations**:
- HTTP pipelining for multiple requests
- Parallel extraction possible in future
- Async audit logging (buffered writes)

## Extension Points

### Adding New Platforms

1. Create `internal/sandbox/{platform}.go` with build tag
2. Implement `Sandbox` interface
3. Register in `init()` function
4. Add platform-specific tests
5. Document capabilities and limitations

### Adding New Transports

1. Create executor in `internal/executor/{transport}.go`
2. Implement transport-specific logic
3. Update manifest validation
4. Add transport-specific tests

### Adding New Auth Methods

1. Extend `internal/registry/auth.go`
2. Add token type to `Token` struct
3. Implement header construction
4. Update login/logout commands

## Testing Strategy

### Test Pyramid

```
       ┌─────────────┐
       │     E2E     │  ← Full workflow tests
       ├─────────────┤
       │ Integration │  ← Multi-module tests
       ├─────────────┤
       │    Unit     │  ← Per-function tests (majority)
       └─────────────┘
```

**Unit Tests** (majority):
- Fast, isolated, comprehensive
- Mock external dependencies
- Table-driven where appropriate
- Platform-agnostic when possible

**Integration Tests**:
- Registry mock with httptest
- Cache with real filesystem (tmpdir)
- End-to-end command flows

**Platform Tests**:
- Build tags: `//go:build linux`
- Skip on non-target platforms
- Test actual OS capabilities

### Coverage Targets

- **Minimum**: 70% overall
- **Critical paths**: 90%+ (cache, registry, manifest)
- **Platform-specific**: Best-effort (60%+)

## Deployment Models

### Standalone Binary

```bash
# Direct execution
./smcp run org/name@1.0.0

# System-wide installation
sudo cp smcp /usr/local/bin/
smcp run org/name@1.0.0
```

### Docker Container

```bash
# Build image
docker build -t mcp-client .

# Run in container
docker run --rm mcp-client run org/name@1.0.0
```

### CI/CD Integration

```yaml
# GitHub Actions
- name: Run MCP tool
  run: |
    curl -sSL https://github.com/security-mcp/mcp-client/releases/download/v1.0.0/smcp-linux-amd64 -o smcp
    chmod +x smcp
    ./smcp run org/tool@1.0.0
```

## Future Architecture Considerations

### HTTP Transport (v1.1)

- HTTP executor in `internal/executor/http.go`
- Proxy mode (forward requests to MCP server)
- Health check integration
- Port allocation strategy

### Multi-Registry (v1.2)

- Registry selection per package
- Fallback registries
- Federation support

### Enhanced Isolation (v1.3)

- gVisor integration (Linux)
- Windows Sandbox API
- Full seccomp profiles

## Glossary

**Artifact**: Generic term for manifest or bundle
**Bundle**: Compressed tar.gz with MCP server executable
**Digest**: SHA-256 or SHA-512 hash (content-addressable ID)
**Entrypoint**: Platform-specific command to execute
**Manifest**: JSON file describing package metadata
**Resolve**: Map package reference to artifact digests/URLs
**Transport**: Communication protocol (STDIO or HTTP)
