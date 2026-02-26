# MCP-CLIENT

## Project Identity and Ecosystem Context

**mcp-client** is the execution plane of **MCP Hub Platform** — a trust infrastructure for publishing, certifying, and running MCP (Model Context Protocol) servers in a predictable, auditable, and governable way.

The platform is built as a pipeline of four components:

1. **mcp-hub** (Control Plane) — Ingests MCP server source code, orchestrates security analysis, computes deterministic certification scores, publishes certified artifacts
2. **mcp-scan** (Analysis Engine) — Static security analyzer that detects 14 vulnerability classes (A-N) using pattern matching, taint analysis, and optional AI detection
3. **mcp-registry** (Data Plane) — Content-addressed artifact distribution with SHA-256 integrity, JWT auth, and scope-based authorization
4. **mcp-client** (Execution Plane) — **This repository.** The last mile of the pipeline — where all upstream certification materializes as runtime enforcement

The client is where trust becomes real. The hub can analyze, score, and certify all day — but none of that matters if the execution layer does not validate digests, enforce policies, sandbox processes, and log everything. This component is responsible for half of the platform's security guarantees.

---

## The Trust Problem This Solves

MCP servers execute arbitrary code with the full permissions of the user account. Today, the standard way to run an MCP server is:

```bash
uvx some-mcp-server          # arbitrary code, full system access
npx @someone/mcp-tool        # no verification, no limits, no audit
```

For individual developers experimenting, this might be acceptable. For organizations deploying MCP servers in production — connected to internal databases, APIs, and infrastructure — this is not. A compromised MCP server can exfiltrate secrets, pivot through internal networks, exhaust resources, or persist backdoors.

MCP Hub Platform solves this with an automated pipeline:

1. Developer publishes source code to mcp-hub
2. mcp-scan analyzes it for 14 classes of vulnerabilities (injection, data exfiltration, privilege escalation, etc.)
3. Hub computes a deterministic score (0-100) and maps it to a certification level (0-3)
4. Certified artifact is published to mcp-registry with immutable SHA-256 digest
5. **mcp-client resolves, validates, enforces policy, sandboxes, and audits the execution**

This client is responsible for steps 5 — the runtime enforcement half of the security model. Every invariant below exists because without it, the upstream certification would be meaningless.

---

## Design Philosophy and Non-Negotiable Invariants

These rules **MUST NEVER** be violated in any code change. They are the security contract this project makes with its users.

### 1. Mandatory SHA-256 Digest Validation
Every manifest and bundle must be validated against its SHA-256 digest before use. No code path — including cache hits, retries, and fallbacks — may bypass this validation. A digest mismatch causes immediate rejection (exit code 3).

### 2. Resource Limits Always Applied
CPU, memory, PID, and file descriptor limits are mandatory on every execution. There is no flag, config option, or code path that disables them. Default limits apply even if the user provides no configuration.

### 3. Default-Deny Security Posture
Network access is denied by default (Linux). Subprocess creation is denied by default. Environment variables are denied by default. Each must be explicitly permitted via the manifest or configuration.

### 4. No Privilege Escalation
The client never executes as root or admin. If it detects elevated privileges, it refuses to run. MCP servers inherit the user's non-elevated context.

### 5. Mandatory Audit Logging
Every execution is logged as structured JSON — start, end, exit code, duration, applied limits, package reference, digest. No code path may skip audit logging in normal operation.

### 6. Secrets Never Logged
Secret values are never written to logs, stdout, or stderr at any verbosity level. Secrets are passed by reference only. Audit logs redact both names and values.

---

## Certification Pipeline Context

Understanding where artifacts come from is critical for working on this codebase. The client does not exist in isolation — it consumes artifacts produced by the upstream pipeline.

```
Developer
    |  smcp push / git commit
    v
[mcp-hub]  ──AMQP: ANALYZE job──>  [mcp-scan worker]
    |                                     |
    |  <──AMQP: ANALYZE_COMPLETE──────────┘
    |
    |  score (0-100) → cert_level (0-3)
    |  publishes certified artifact
    v
[mcp-registry]  ── content-addressed storage (SHA-256)
    ^
    |  resolve + download + validate
    |
[mcp-client]  ── policy check → sandbox → execute → audit
```

Step by step:

1. **Developer pushes code** to mcp-hub (Git repo, webhook, or `smcp push` CLI upload)
2. **Hub-worker uploads tarball** to S3 and publishes an ANALYZE job to AMQP
3. **Scan-worker runs mcp-scan** — 14 vulnerability classes (A-N): injection, exfiltration, privilege escalation, resource abuse, etc.
4. **Results return via AMQP** — hub-worker downloads results, runs controls mapping, scoring, and snapshot building
5. **Score maps to cert_level** — 0: Integrity Verified, 1: Static Verified (>=60), 2: Security Certified (>=80), 3: Runtime Certified (>=90, future)
6. **Hub publishes** manifest + bundle to mcp-registry with cert_level metadata and immutable SHA-256 digest
7. **Client resolves** the package reference, downloads manifest and bundle, validates SHA-256 digests, checks organizational policy (min cert_level, allowed origins), applies sandbox, executes, and writes audit log

When modifying client code, remember: the cert_level, origin, and digest metadata this client consumes were produced by the upstream pipeline. The client trusts the registry's digest but validates it independently. The client enforces policy based on cert_level but does not recompute it.

---

## Features

- Immutable package resolution (`org/name@version`, `org/name@sha`, `org/name@digest`)
- Content-addressable local cache with mandatory SHA-256 validation
- Lightweight process-level sandboxing (not VM-level)
- Platform-specific resource limits (CPU, memory, PIDs, file descriptors)
- Network default-deny with manifest-controlled allowlists (Linux only)
- Filesystem isolation to working directory (Linux only, best-effort on other OSes)
- Security policy enforcement: certification level, origin filtering, environment filtering, subprocess control
- Structured JSON audit logging with secret redaction
- STDIO transport for MCP servers (HTTP transport planned)
- Package publishing via `smcp push` to MCP Hub (currently hidden/disabled — under development)

---

## Stack

- **Language:** Go 1.24+
- **CLI Framework:** Cobra
- **Configuration:** Viper (YAML + env vars + flags)
- **Testing:** Testify
- **Build/Release:** Makefile, Goreleaser
- **Containerization:** Docker

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `smcp run <ref>` | Execute an MCP server from a package reference |
| `smcp pull <ref>` | Pre-download a package without executing (useful for CI/CD) |
| `smcp info <ref>` | Display package manifest details |
| `smcp login` | Authenticate with the registry (interactive or token-based) |
| `smcp logout` | Remove stored authentication credentials |
| `smcp cache ls` | List cached artifacts |
| `smcp cache rm` | Remove cached artifacts (by digest or `--all`) |
| `smcp doctor` | Diagnose system sandbox capabilities |

> **Note:** `smcp push` exists in the codebase but is currently hidden/disabled. It is not registered in the CLI command tree. Do not expose it without explicit instruction.

---

## Quick Start

```bash
# Build from source
make build

# Check system capabilities
./smcp doctor

# Pull and run a package
./smcp pull acme/hello-world@1.2.3
./smcp run acme/hello-world@1.2.3
```

---

## Configuration

**Config file:** `~/.smcp/config.yaml`

Key sections: `registry` (URL, timeout), `cache` (directory, max size, TTL), `executor` (default timeout, resource limits), `security` (network deny, subprocess control), `audit` (log file, format), `policy` (cert level enforcement, allowed origins).

**Environment variables** (override config):

| Variable | Purpose |
|----------|---------|
| `MCP_REGISTRY_URL` | Registry endpoint URL |
| `MCP_REGISTRY_TOKEN` | Authentication token |
| `MCP_CACHE_DIR` | Cache directory path |
| `MCP_LOG_LEVEL` | Log verbosity (debug, info, warn, error) |
| `MCP_TIMEOUT` | Default execution timeout |

**CLI flags** override both config file and environment variables. Use `--registry`, `--cache-dir`, `--verbose`, `--json`.

**Auth tokens** are stored in `~/.smcp/auth.json` with `0600` permissions.

---

## Security Model

- **Digest validation:** All manifests and bundles are validated against SHA-256 before use
- **Resource limits:** CPU, memory, PIDs, and file descriptors are always enforced (mandatory defaults cannot be disabled)
- **Network isolation:** Default-deny on Linux via network namespaces; not available on macOS/Windows
- **Filesystem isolation:** Process confined to working directory on Linux; best-effort on other platforms
- **Subprocess control:** Restricted by default unless the manifest explicitly declares subprocess permissions
- **Secret handling:** Secrets passed by reference only, never logged in plaintext
- **No elevated privileges:** The launcher never runs as root/admin
- **Policy enforcement:** Configurable minimum certification level (0-3) and allowed origin types (Official, Verified, Community)

---

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Resource Limits | cgroups v2 + rlimits | rlimits only | Job Objects |
| Network Isolation | Network namespaces | Not available | Not available |
| Filesystem Isolation | Bind mounts + Landlock | Best-effort (UNIX perms) | Best-effort (NTFS perms) |
| Subprocess Control | seccomp | Limited | Not available |
| Audit Logging | Full | Full | Full |
| **Production Ready** | Yes | No | No |

**Critical:** macOS and Windows sandboxes have known bypass vulnerabilities. Use Linux with cgroups or Docker containers for production workloads running untrusted MCPs.

---

## Integration with Registry

The client communicates with mcp-registry via REST API:
- **Resolve:** `POST /v1/packages/:org/:name/resolve` to get manifest and bundle digests/URLs
- **Download:** `GET /manifests/:digest` and `GET /bundles/:digest` with redirect support for presigned URLs
- **Authentication:** JWT Bearer tokens for enterprise mode; optional for OSS mode
- **Retries:** Exponential backoff on 5xx errors (3 attempts), respects 429 rate limits
- **Cache headers:** Honors `Cache-Control` and `ETag`/`If-None-Match`

The client also communicates with mcp-hub for the `push` workflow (upload init/finalize) — currently disabled.

---

## Package Structure

```
internal/
├── cli/         # Cobra command handlers (9 commands)
├── config/      # Configuration loading (YAML + env + flags)
├── registry/    # Registry API client with auth & retries
├── manifest/    # MCP manifest parsing and validation
├── cache/       # Content-addressable SHA-256 cache
├── policy/      # Security policy & resource limits
├── executor/    # Process execution with sandbox
├── sandbox/     # Platform-specific isolation
│   ├── linux.go       # cgroups, namespaces, seccomp, Landlock
│   ├── darwin.go      # rlimits, Seatbelt (limited)
│   └── windows.go     # Job Objects, integrity levels
├── audit/       # Structured JSON audit logging
├── hub/         # Hub API client (push workflow)
└── packaging/   # Bundle creation with security checks
```

---

## Development Commands

| Target | Description |
|--------|-------------|
| `make build` | Build the `smcp` binary |
| `make test` | Run all tests with race detection and coverage |
| `make test-coverage` | Generate HTML coverage report |
| `make lint` | Run golangci-lint |
| `make fmt` | Format code (gofmt + goimports) |
| `make clean` | Remove build artifacts |
| `make install` | Install binary to `$GOPATH/bin` |
| `make tidy` | Run `go mod tidy` |
| `make deps` | Download dependencies |
| `make all` | Format, lint, test, and build |
| `make docker-build` | Build Docker image |
| `make release-snapshot` | Build release snapshot (requires goreleaser) |

---

## Testing

```bash
make test              # Unit + integration tests with race detection
make test-coverage     # Generate HTML coverage report
```

Tests include unit, integration, benchmark, fuzz, and E2E tests. Platform-specific sandbox tests use build tags (`linux`, `darwin`, `windows`). All tests run offline using fixtures and mock HTTP servers.

---

## Gotchas

- Linux sandbox tests require root or cgroups v2 delegation; skip with `-short` flag if unavailable
- macOS and Windows cannot provide network isolation; `smcp doctor` reports these limitations
- Binary name is `smcp` (not `mcp-client`); built to `./smcp` by default
- Registry must be running and accessible for `pull`/`run` commands to work
- Auth tokens stored in `~/.smcp/auth.json` with 0600 perms; token expiry is not auto-refreshed
- `push` command is hidden/disabled — the code exists but is not registered in the CLI
- CGO_ENABLED=0 by default for cross-platform builds

## Commits

- **Author:** Dani (cr0hn@cr0hn.com)
- **Format:** Conventional Commits (`feat:`, `fix:`, `docs:`, etc.)
- **Changelog:** Document all changes in `CHANGELOG.md`
