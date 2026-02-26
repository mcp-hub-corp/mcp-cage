# MCP-Client Overview

mcp-client is a secure launcher/executor for MCP (Model Context Protocol) servers. It downloads, validates, and executes MCP packages from a compatible registry with lightweight security policies and resource isolation.

## What is mcp-client?

**mcp-client** is a command-line tool that:
- Resolves immutable package references (`org/name@version`, `org/name@sha`, `org/name@digest`)
- Downloads and validates manifests and bundles from a registry
- Applies security policies (network allowlists, environment filtering, subprocess control)
- Enforces resource limits (CPU, memory, processes, file descriptors)
- Executes MCP servers in isolated processes
- Audits all executions locally

## What mcp-client is NOT

- **Not a container runtime**: No Docker, Kubernetes, or VM-level isolation (uses OS-level mechanisms)
- **Not a package manager**: Does not manage dependencies or version resolution (registry handles that)
- **Not a code analyzer**: Does not inspect or modify package code
- **Not compatible with npm/pip/docker**: Only understands MCP package format (manifest + bundle)
- **Not a sandbox escape detector**: Assumes attacks at kernel/hardware level are out of scope
- **Not a registry**: Only consumes packages, does not publish or store them

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  User: smcp run org/name@version                                │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ CLI (cobra)                                              │  │
│  │ - Parse args, load config, validate inputs              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                          ↓                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Registry Client                                          │  │
│  │ - Resolve reference → get manifest/bundle digests       │  │
│  │ - Download with auth, follow redirects                  │  │
│  │ - Retry with exponential backoff                         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                          ↓                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Cache (Content-Addressable)                             │  │
│  │ - Store by SHA-256 digest                               │  │
│  │ - Concurrent access with locking                        │  │
│  │ - LRU eviction when size limit reached                  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                          ↓                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Manifest Parser & Validator                             │  │
│  │ - Parse JSON schema                                      │  │
│  │ - Validate coherence (manifest → bundle)                │  │
│  │ - Select correct entrypoint for OS/arch                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                          ↓                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Policy Engine                                            │  │
│  │ - Apply network allowlist                                │  │
│  │ - Filter environment variables                           │  │
│  │ - Control subprocess execution                           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                          ↓                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Sandbox (Platform-Specific)                             │  │
│  │ - Linux: cgroups v2, namespaces, seccomp                │  │
│  │ - macOS: rlimits, timeouts (limited isolation)          │  │
│  │ - Windows: Job Objects                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                          ↓                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Executor (STDIO / HTTP)                                  │  │
│  │ - Start process with sandbox config                      │  │
│  │ - Handle stdin/stdout for STDIO mode                     │  │
│  │ - Proxy HTTP requests in HTTP mode                       │  │
│  │ - Monitor for timeout/resource exhaustion                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                          ↓                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Audit Logger                                             │  │
│  │ - Log start/end events                                   │  │
│  │ - Record resource usage, exit code                       │  │
│  │ - Redact secrets from logs                               │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Key Concepts

### Package Reference

Identifies a package version immutably:

- **Semantic Version**: `org/name@1.2.3` (resolved by registry)
- **SHA Reference**: `org/name@sha:abc123def456` (git commit SHA)
- **Digest Reference**: `org/name@digest:sha256:abc123...` (full digest)

Example:
```bash
smcp run acme/hello-world@1.2.3
smcp run acme/hello-world@sha:abc123
smcp run acme/hello-world@digest:sha256:abc123...
```

### Manifest

JSON file describing an MCP package:

```json
{
  "name": "org/hello-world",
  "version": "1.2.3",
  "description": "Simple hello world MCP server",
  "author": "Acme Corp",
  "license": "MIT",

  "entrypoints": {
    "linux-amd64": {
      "command": "./bin/mcp-server",
      "args": ["--mode", "stdio"]
    },
    "darwin-amd64": {
      "command": "./bin/mcp-server",
      "args": ["--mode", "stdio"]
    }
  },

  "transport": "stdio",

  "environment": {
    "allowed_names": ["LOG_LEVEL", "API_KEY"],
    "deny_patterns": ["*_PASSWORD", "*_SECRET"]
  },

  "network": {
    "allowlist": ["api.example.com", "10.0.0.0/8"]
  },

  "subprocess": false,

  "resources": {
    "cpu_millicores": 1000,
    "memory_mb": 512,
    "max_processes": 10,
    "max_fds": 100
  }
}
```

### Bundle

Compressed archive (tar.gz) containing executable code:

```
bundle.tar.gz
├── bin/
│   ├── mcp-server          (compiled binary)
│   └── helper-tool
├── lib/
│   ├── libfoo.so
│   └── libbar.so
├── python/
│   └── requirements.txt
└── data/
    └── config.json
```

### Digest

SHA-256 hash uniquely identifying an artifact:

```
sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Format: `sha256:` prefix + 64 hex characters

**Property**: Content-addressable (same content = same digest)

### Entrypoint

Command to execute for given OS/architecture:

```json
{
  "entrypoints": {
    "linux-amd64": {
      "command": "./bin/mcp-server",
      "args": ["--mode", "stdio"]
    },
    "darwin-arm64": {
      "command": "./bin/mcp-server-arm64",
      "args": ["--mode", "stdio"]
    }
  }
}
```

mcp-client automatically selects the correct entrypoint based on runtime OS and CPU architecture.

### Transport

How the MCP server communicates:

- **STDIO**: Server reads JSON-RPC from stdin, writes to stdout
- **HTTP**: Server exposes HTTP API on configured port

### Cache

Local content-addressable storage:

```
~/.smcp/cache/
├── manifests/
│   └── sha256:abc123.../manifest.json
└── bundles/
    └── sha256:def456.../bundle.tar.gz
```

**Benefits**:
- Avoid re-downloading same artifacts
- Concurrent access with locking
- Automatic eviction when full

### Resolve

Registry API operation to resolve package reference:

```
Request:
  GET /v1/packages/org/name/resolve?ref=1.2.3

Response:
  {
    "manifest": {
      "digest": "sha256:abc123...",
      "url": "https://registry.example.com/manifests/..."
    },
    "bundle": {
      "digest": "sha256:def456...",
      "url": "https://registry.example.com/bundles/..."
    }
  }
```

## Execution Workflow

```
1. User runs: smcp run acme/hello-world@1.2.3

2. Resolve
   - Query registry: POST /v1/packages/acme/hello-world/resolve
   - Get manifest digest, bundle digest, download URLs

3. Download (or use cache)
   - Check cache for manifest (by digest)
   - If not cached, download from URL
   - Repeat for bundle

4. Validate
   - Calculate SHA-256 of downloaded manifest
   - Compare with expected digest → reject if mismatch
   - Repeat for bundle
   - Store in cache

5. Parse
   - Load manifest JSON
   - Validate schema and coherence
   - Select entrypoint for current OS/arch

6. Policy
   - Apply network allowlist
   - Filter environment variables
   - Check subprocess permissions

7. Sandbox
   - Configure resource limits (CPU, memory, pids, fds)
   - Set up filesystem isolation
   - Enable network restrictions

8. Execute
   - Fork process with sandbox config
   - Start MCP server executable
   - Connect stdin/stdout (STDIO mode)

9. Audit
   - Log start event: package, version, digest, user, PID
   - Wait for process completion or timeout
   - Log end event: exit code, duration, resource usage

10. Cleanup
    - Terminate process if timeout exceeded
    - Close file descriptors
    - Clean up temporary files
```

## Security Model (Lightweight)

mcp-client implements **process-level isolation** (not VM-level):

### Linux
- **CPU/Memory Limits**: cgroups v2 + rlimits
- **Network Isolation**: Network namespaces (default-deny)
- **Filesystem Isolation**: Bind mounts + mount namespaces
- **Subprocess Control**: seccomp filters

### macOS
- **CPU/Memory Limits**: rlimits only (soft limits)
- **Network Isolation**: Not available (no netns)
- **Filesystem Isolation**: Directory permissions
- **Subprocess Control**: Process monitoring

### Windows
- **CPU/Memory Limits**: Job Objects
- **Network Isolation**: Not available (requires drivers)
- **Filesystem Isolation**: NTFS permissions
- **Subprocess Control**: Job Object process limits

**Important**: See `docs/SECURITY.md` for detailed threat model and limitations per platform.

## Module Structure

### `internal/config`
- Load configuration from YAML, environment, flags
- Validate configuration
- Merge sources (priority: flags > env > file > defaults)

### `internal/registry`
- HTTP client for registry API
- Resolve package references
- Download manifests and bundles
- Handle authentication (JWT, tokens)
- Follow redirects (presigned URLs)

### `internal/cache`
- Content-addressable storage by digest
- Concurrent access with locking
- Eviction policy (LRU)
- Digest validation on retrieval

### `internal/manifest`
- Parse JSON manifests
- Validate schema and coherence
- Select entrypoint for OS/arch

### `internal/executor`
- Execute processes with stdio or HTTP
- Manage stdin/stdout (STDIO mode)
- Proxy HTTP requests (HTTP mode)
- Handle process termination

### `internal/sandbox`
- Platform-specific resource isolation
- Apply limits, set up namespaces/Job Objects
- Implementations: linux.go, darwin.go, windows.go

### `internal/policy`
- Network allowlist enforcement
- Environment variable filtering
- Subprocess control

### `internal/audit`
- Structured JSON logging
- Redact secrets
- Record execution events

### `internal/cli`
- Command-line interface (Cobra)
- Commands: run, pull, info, cache, login, doctor

## Quick Start

### Installation

```bash
# Build from source
git clone https://github.com/security-mcp/mcp-client
cd mcp-client
make build
./smcp --help

# Or install to $GOPATH/bin
make install
```

### Execute a Package

```bash
# Run with version
smcp run acme/hello-world@1.2.3

# Check system capabilities
smcp doctor

# Pre-download package
smcp pull acme/tool@1.0.0

# Manage cache
smcp cache ls
smcp cache rm sha256:abc123...
```

### Configure Registry

```bash
# Login to private registry
smcp login --token my-secret-token

# Or create ~/.smcp/config.yaml
cat > ~/.smcp/config.yaml <<EOF
registry:
  url: https://registry.example.com
  timeout: 30s

executor:
  default_timeout: 5m
  max_memory: 512M
EOF
```

## Threat Model Summary

### Covered
✅ Resource exhaustion (CPU, memory, processes, FDs)
✅ Filesystem breakout (isolation + permissions)
✅ Network unauthorized access (allowlist enforcement)
✅ Secret exposure (log redaction)
✅ Supply chain attacks (digest validation)
✅ Subprocess escape (seccomp, policy)

### Not Covered
❌ Kernel exploits (Spectre, meltdown, etc.)
❌ Runtime vulnerabilities (Python, Node.js, etc.)
❌ Hardware side-channels
❌ Advanced evasion techniques
❌ Registry compromise (assumes trusted registry)

See `docs/SECURITY.md` for detailed analysis.

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Resource Limits | ✅ | ⚠️ | ✅ |
| Network Isolation | ✅ | ❌ | ❌ |
| Filesystem Isolation | ✅ | ⚠️ | ⚠️ |
| Subprocess Control | ✅ | ⚠️ | ✅ |
| Audit Logging | ✅ | ✅ | ✅ |

⚠️ = Limited or requires specific OS setup

## Configuration

Default config location: `~/.smcp/config.yaml`

See `docs/config.example.yaml` for all options.

## Usage Examples

See `docs/EXAMPLES.md` for:
- Basic usage (run, pull, info)
- Environment variables and secrets
- Resource limits and timeouts
- Network restrictions
- Cache management
- CI/CD integration
- Troubleshooting

## Security Documentation

See `docs/SECURITY.md` for:
- Detailed threat model
- Security invariants (never break these rules)
- Platform-specific capabilities
- Digest validation
- Audit logging
- Best practices

## Registry Contract

See `docs/REGISTRY-CONTRACT.md` for:
- API endpoints and formats
- Authentication methods
- Content addressing (digests)
- Version status
- Error responses

## Command Reference

### `smcp run <ref>`
Execute an MCP server

```bash
smcp run acme/tool@1.2.3 --timeout 5m --env LOG_LEVEL=debug
```

### `smcp pull <ref>`
Pre-download package without executing

```bash
smcp pull acme/tool@1.2.3
```

### `smcp info <ref>`
Display package information

```bash
smcp info acme/tool@1.2.3 --json
```

### `smcp login`
Authenticate with registry

```bash
smcp login --token secret123
```

### `smcp cache ls/rm`
Manage local cache

```bash
smcp cache ls
smcp cache rm sha256:abc123...
smcp cache rm --all
```

### `smcp doctor`
Diagnose system capabilities

```bash
smcp doctor
```

## Building and Testing

```bash
# Format code
make fmt

# Run tests
make test

# Run linters
make lint

# Build binary
make build

# Clean artifacts
make clean
```

## Contributing

This is a reference implementation. Community contributions welcome!

See project issues and discussion threads.

---

**Project Status**: Production Ready (v1.0+)

**Last Updated**: 2026-01-18

**Documentation Version**: 1.0
