# MCP-Client Skills Directory

This directory contains comprehensive expert knowledge bases for implementing critical components of the mcp-cage launcher.

## Available Skills

### Optimization & Tooling Skills

#### 1. golang-performance.md (495 lines, 17 KB)
**Expert knowledge for Go performance optimization and profiling**

Key topics:
- pprof profiling: CPU profiling (pprof), memory profiling, goroutine leaks
- Benchmark writing: Proper setup with ResetTimer, StopTimer, RunParallel
- Benchmark interpretation: ns/op, B/op, allocs/op metrics
- Memory optimization: Escape analysis, heap allocations, stack vs heap
- Common bottlenecks: JSON parsing, crypto, disk I/O, network I/O
- Optimization patterns: Buffer pooling, avoiding copies, string builder
- Tools: go tool pprof, go tool trace, benchstat
- Real examples from mcp-cage: digest_bench_test.go, cache_bench_test.go
- Goroutine leak detection with runtime.NumGoroutine()
- CI/CD regression detection with benchstat

**Use when:** Optimizing performance, profiling hot code, reducing allocations, comparing optimizations

**Real code patterns from mcp-cage:**
- Cache put/get benchmarks with sync.Pool
- Manifest parsing benchmarks with full workflow
- Concurrent benchmark patterns with RunParallel

---

#### 2. debugging-production.md (605 lines, 23 KB)
**Expert knowledge for production debugging and troubleshooting**

Key topics:
- Exit codes and error message interpretation
- Common error scenarios: 404 not found, digest mismatch, timeout, auth failure
- Verbose/debug logging with --log-level debug
- Structured log analysis with jq
- System call tracing: strace (Linux), dtrace (macOS)
- Network debugging: curl timing, tcpdump, wireshark, DNS resolution
- Cache inspection: List, verify integrity, cleanup
- Sandbox limits verification: cgroups, rlimits, network isolation
- Process inspection: lsof, ps, monitoring resource usage
- Troubleshooting workflows and decision trees
- Real-world examples: Package not found, digest mismatch, timeout, memory exceeded
- 10+ production debugging scenarios with solutions

**Use when:** Debugging failures, analyzing logs, tracing system calls, verifying cache integrity

**Key commands:**
- smcp doctor (system capabilities)
- smcp cache ls (artifact inspection)
- strace -e open,read,write (trace syscalls)
- jq 'select(.level=="ERROR")' (parse JSON logs)

---

#### 3. ci-cd-mcp-cage.md (650 lines, 22 KB)
**Expert knowledge for CI/CD automation specific to mcp-cage**

Key topics:
- GitHub Actions workflow design (CI, linting, build, release)
- Multi-platform testing matrix: Linux, macOS, Windows × Go 1.21, 1.22
- Build tags for platform-specific tests (// +build linux, darwin)
- Test execution with -race, -coverprofile, -timeout
- golangci-lint configuration and common linter issues
- Coverage reporting: go tool cover, codecov integration
- Release automation: goreleaser, multi-platform builds
- Build optimization: strip symbols (-s -w), cross-compilation
- Artifact management: Checksums, SBOM generation
- Caching strategies: Go modules, build cache, benchmark cache
- Common CI/CD issues: Flaky tests, slow pipeline, OOM, timeouts
- Advanced patterns: Conditional steps, reusable workflows
- Real configs from project: .github/workflows/ci.yml, release.yml

**Use when:** Setting up CI/CD, fixing pipeline issues, optimizing build times, creating releases

**Real workflows in mcp-cage:**
- Test matrix: 3 OS × 2 Go versions = 6 parallel jobs
- Coverage upload to codecov.io (ubuntu-latest, go 1.22 only)
- Multi-platform binary build for releases
- SHA256 checksum generation

---

### Core Implementation Skills

### 1. registry-api.md (996 lines, 25 KB)
**Expert knowledge for MCP registry HTTP client implementation**

Key topics:
- OpenAPI contract reference for github.com/security-mcp/mcp-registry
- Authentication methods: Bearer JWT, API Token, Basic Auth
- Core endpoints: Login, Resolve, Download Manifest, Download Bundle, Catalog
- HTTP client setup with timeouts and redirect handling
- Retry logic with exponential backoff (3 max attempts)
- Digest validation (SHA-256/SHA-512) - critical security invariant
- Error handling and custom HTTP error types
- Debugging commands (curl examples, code logging)
- Testing patterns with mock registry and retry simulation
- Response caching and ETag support
- Security considerations (no token logging, HTTPS only)

**Use when:** Implementing registry integration, HTTP client setup, authentication, artifact downloads

**Key code patterns:**
- Client initialization with auth headers
- Redirect following with presigned URLs
- SHA-256/SHA-512 digest validation
- Retry logic with exponential backoff + jitter
- Metadata struct mapping (ResolveResponse, CatalogResponse)

---

### 2. mcp-manifest.md (1214 lines, 27 KB)
**Expert knowledge for MCP manifest parsing and validation**

Key topics:
- Complete manifest schema with all fields defined
- Package ID format validation (org/name regex patterns)
- Semantic version validation (semver patterns)
- Digest format validation (sha256:hex or sha512:hex)
- Transport types: stdio (default) vs http
- Entrypoint selection algorithm with OS/arch matching
- Permissions structure: network allowlists, environment variables, subprocess control, filesystem
- Resource limits: cpu_millis, memory_mb, max_pids, max_fds, timeout_seconds
- Health check configuration (HTTP transport only)
- Manifest-to-bundle coherence validation
- 8 common manifest mistakes and their fixes
- Example valid manifests (simple STDIO, HTTP with health check, minimal)
- Testing patterns for validation and entrypoint selection
- JSON parsing and file I/O patterns

**Use when:** Parsing manifests, validating manifest structure, selecting entrypoints, designing manifest examples

**Key validation rules:**
- Required fields: schema_version, package (org/name/version), bundle (digest/size), transport, entrypoints
- Entrypoint keys: must be platform-arch (e.g., linux-amd64, darwin-arm64)
- Transport values: must be "stdio" or "http" (default: stdio)
- Network allowlist: domain patterns, CIDR ranges, port-specific rules
- Secrets: passed by NAME only, never in plaintext

---

### 3. content-cache.md (1156 lines, 28 KB)
**Expert knowledge for content-addressable cache implementation**

Key topics:
- Content-addressable design principles (immutability, deduplication, integrity)
- Directory structure: ~/.smcp/cache/{manifests,bundles}/sha256:*/
- Metadata file structure (digest, size, timestamps, package info)
- Store interface definition with core operations
- Atomic write pattern: temp file → validate → rename (prevents corruption)
- Get operation with last-access timestamp updates
- Exists checks (single and batch)
- Delete operation with cleanup
- List operation with sorting and filtering
- Cache size calculation (total and by type)
- Eviction strategies: TTL-based, LRU, size-based
- Thread-safety patterns: RWMutex, per-digest locks
- Filesystem locking (optional, platform-specific)
- CopyToPath operation for bundle extraction
- 5 common issues with solutions:
  1. Race conditions on concurrent writes
  2. Partial writes on disk full
  3. Corrupted metadata files
  4. Unbounded cache growth
  5. Lost last-access metadata
- Testing patterns: atomic writes, concurrent access, eviction policies
- Integration with registry client (caching downloaded artifacts)
- Debugging and inspection commands
- Schema versioning for future upgrades

**Use when:** Implementing cache store, handling concurrent access, eviction policies, bundle extraction

**Key patterns:**
- Per-digest mutex locks prevent concurrent corruption
- Atomic writes: write to temp, validate hash, rename to final location
- Digest always used as key (never trust filename)
- Content verified after download and after cache retrieval
- Async last-access updates don't block reads

---

## How to Use These Skills

### Performance & Profiling Workflow

When optimizing mcp-cage:

1. **Profile first** → Use **golang-performance.md** for pprof setup
2. **Identify bottlenecks** → Analyze with go tool pprof and flamegraphs
3. **Benchmark changes** → Write benchmarks with proper ResetTimer patterns
4. **Compare results** → Use benchstat to quantify improvements
5. **Track in CI** → Add benchmark regression tests (see ci-cd-mcp-cage.md)

### Production Troubleshooting Workflow

When debugging failures:

1. **Check exit code** → Reference exit code table in debugging-production.md
2. **Enable logging** → Use --log-level debug and JSON format
3. **Analyze logs** → Parse with jq commands from debugging-production.md
4. **Trace calls** → Use strace/dtrace commands from debugging-production.md
5. **Verify cache** → Use smcp cache ls and integrity checks
6. **Check system** → Run smcp doctor to verify capabilities

### CI/CD Implementation Workflow

When setting up automation:

1. **Design matrix** → Use testing strategy from ci-cd-mcp-cage.md
2. **Configure linting** → Reference golangci-lint settings
3. **Setup coverage** → Integrate codecov as shown
4. **Create release** → Use goreleaser patterns for multi-platform builds
5. **Handle artifacts** → Generate checksums and optional SBOM
6. **Monitor performance** → Add benchmark regression detection

---

## How to Use These Skills

### In Claude Code / Agent Workflows

Reference the skills explicitly when working on related components:

```
@claude-code analyze registry-api to implement HTTP client with proper retry logic
@claude-code use mcp-manifest for manifest parser validation logic
@claude-code reference content-cache for thread-safe store implementation
```

### For Implementation Tasks

When implementing registry integration:
1. Start with **registry-api.md** for HTTP client structure and endpoints
2. Use **mcp-manifest.md** for manifest parsing logic
3. Apply **content-cache.md** patterns for caching downloaded artifacts

### For Code Review

When reviewing:
- Registry client code → check against registry-api.md patterns
- Manifest parser → validate against mcp-manifest.md schema
- Cache implementation → verify concurrency patterns in content-cache.md

---

## Cross-References Between Skills

### Performance & Profiling Connections

**golang-performance.md** connections:
- **→ cache_bench_test.go**: Real benchmarks in project (PutManifest, GetBundle, List operations)
- **→ manifest/parser_bench_test.go**: Real benchmarks (Parse, Validate, SelectEntrypoint)
- **→ ci-cd-mcp-cage.md**: Add benchmark regression detection to CI pipeline
- **→ debugging-production.md**: Use profiling output to diagnose slow operations

### Production Debugging Connections

**debugging-production.md** connections:
- **→ ci-cd-mcp-cage.md**: Automated testing catches issues before production
- **→ golang-performance.md**: Profile when diagnosing performance issues
- **→ smcp doctor**: First command to run (coverage in debugging-production.md)

### CI/CD Connections

**ci-cd-mcp-cage.md** connections:
- **→ golang-performance.md**: Add benchmark regression tests to CI matrix
- **→ debugging-production.md**: CI logs help diagnose failures
- **→ .golangci.yml**: Linting configuration (referenced in CI workflow)
- **→ .github/workflows/**: Real GitHub Actions workflows

### Implementation Skill Connections

### registry-api → mcp-manifest
- Resolve endpoint returns manifest digest
- Download manifest endpoint returns JSON matching manifest schema
- Manifest validation required before execution

### mcp-manifest → content-cache
- Manifest stored in cache by digest
- Digest validation matches content-cache atomic write patterns
- Bundle digest must match manifest bundle.digest

### content-cache → registry-api
- Cache stores artifacts downloaded from registry
- Digest validation follows registry-api patterns
- Concurrent downloads use content-cache locking

---

## Related Files

- **CLAUDE.md** - Project specification and goals
- **docs/REGISTRY-CONTRACT.md** - Detailed registry API contract
- **docs/ARCHITECTURE.md** - System architecture overview
- **internal/registry/client.go** - Registry client implementation
- **internal/manifest/parser.go** - Manifest parsing logic
- **internal/cache/store.go** - Cache store implementation

---

## Skill Maintenance

**Created on 2026-01-18**, reflecting current project state:

### Core Implementation Skills
- MCP Registry OpenAPI spec (github.com/security-mcp/mcp-registry)
- Manifest schema version 1.0
- Cache schema version 1
- Go best practices for HTTP clients, JSON parsing, concurrency

### Optimization & Tooling Skills
- Go benchmarking patterns (pprof, benchstat)
- Real benchmarks from mcp-cage: cache_bench_test.go, manifest/parser_bench_test.go
- GitHub Actions CI/CD with matrix testing (3 OS × 2 Go versions)
- golangci-lint v1.55+ configuration
- goreleaser release automation
- Production debugging with structured logs (JSON format)

**Periodic review needed when:**
- Registry API changes (breaking changes to endpoints)
- Manifest schema evolution (new required fields)
- Cache requirements change (new eviction policies)
- **New Go version releases** (update version matrix in CI)
- **New benchmark bottlenecks discovered** (update golang-performance.md)
- **New production failure patterns** (update debugging-production.md)
- **GitHub Actions actions update** (e.g., setup-go, cache versions)
