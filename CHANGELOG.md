# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2026-03-10

### Fixed

- **2026-03-10**: Fixed remaining `ifElseChain` (gocritic) CI lint failures in Linux-only files:
  - Converted 3-branch if-else-if chain in `internal/sandbox/linux.go` (`setupSandbox` network namespace section) to a `switch` statement. This was missed in the previous fix because the file has `//go:build linux` and was only linted in CI's Ubuntu runner, not locally on macOS.
  - Converted 2-branch if-else-if chain in `internal/cli/pull.go` (`resolveHubMCP` version selection) to a `switch` statement as a preventive fix.

- **2026-03-10**: Fixed all golangci-lint errors in `internal/mcp/proxy.go`, `internal/mcp/warning.go`, and `internal/mcp/warning_test.go`:
  - Converted if-else chains to switch statements in `buildSandboxSuggestion` (proxy.go), and in the network/environment access sections of `generateSandboxContextWarning` (warning.go) — resolves `ifElseChain` (gocritic) warnings.
  - Inverted two nested if conditions in `injectSandboxErrorInResult` to use early `continue` instead of deeply nested bodies — resolves `nestingReduce` (gocritic) warnings.
  - Changed `writeToClient` return type from `(int, error)` to `error` since the int (bytes written) was never used by any caller — resolves `unparam` warning. Updated all call sites in proxy.go, proxy_test.go.
  - Applied `gofmt` formatting fixes to warning.go (struct field alignment) and warning_test.go (composite literal formatting).

- **2026-03-10**: Fixed CI test failures in `TestBuildSandboxSuggestion`. Synced `buildSandboxSuggestion` messages with test expectations: generic errors now mention "restricted resource", AllFS/AllNet active cases now include "already fully granted" in the status message.

## [0.3.1] - 2026-03-03

### Added

- **2026-03-03**: Inject sandbox error warnings directly into MCP tool results. Instead of only sending a separate `notifications/message`, the proxy now detects sandbox-blocked operations in JSON-RPC tool results (`CallToolResult` and `JSONRPCError`) and appends an `[SMCP SANDBOX ALERT]` content block inline. This ensures LLMs see the security context as part of the tool output, even if they ignore notifications.

- **2026-03-03**: Improved CLI help text with usage examples and updated description (`smcp` → "Secure MCP Client").

- **2026-03-03**: Enhanced security warning instructions — LLM now asked to request explicit user confirmation before proceeding with low-score packages.

- **2026-03-03**: Improved sandbox suggestion messages — restructured as structured security alerts with Action/Status/Reason/Impact fields. LLM is now instructed to NOT suggest bypassing security unless the user explicitly requests it.

- **2026-03-03**: Auto-enable MCP security proxy in pipe mode for LLM sandbox awareness. When stdin is not a terminal (i.e., called by an LLM client like Claude Code), the security proxy now activates automatically without requiring `--trust`. This ensures LLMs always receive sandbox context in `initialize` response instructions, reactive `notifications/message` alerts for sandbox-blocked operations, and stderr scanning for sandbox error patterns. Also skips interactive low-score confirmation in pipe mode (no terminal to prompt). Added `SetStderr()` to `MCPProxy` with mutex-protected client writes so stderr sandbox errors inject notifications on stdout without races. Executor now pipes stderr through the proxy in proxy mode.

### Fixed

- **2026-03-03**: Stderr pipe deadlock in MCP proxy causing 60s timeout on Claude Desktop. The `processStderr()` goroutine was started only after the handshake completed, but MCP servers write startup logs to stderr *during* the handshake. If the OS pipe buffer (~64KB) filled, the server blocked on stderr write and never sent the initialize response. Fix: start stderr processing immediately in `Run()` before the handshake. Also fixed a data race in `handleHandshake()` which wrote to `clientWriter` without the mutex (now uses `writeToClient()`).

- **2026-03-03**: MCP proxy goroutine lifecycle and EOF propagation fixes causing premature server disconnect on Claude Desktop. Two bugs: (1) proxy goroutine was fire-and-forget — `cmd.Wait()` returned when the process exited but `Execute()` returned immediately without waiting for the proxy to drain in-flight data, causing the CLI to exit and orphan the goroutine. Fix: use `sync.WaitGroup` to wait for proxy completion after `cmd.Wait()`. (2) When the client disconnected (stdin EOF), the server's stdin pipe was never closed, so the MCP server never received EOF and kept running → deadlock. Fix: added `closeServerWriter()` with `sync.Once` that closes the server's stdin pipe when either copy direction finishes, propagating EOF correctly in all proxy modes (raw, buffered, error-scanning).

- **2026-03-03**: Security hardening of sandbox permission system (5 critical + 5 high-priority fixes):
  - **CRITICAL: Environment variable leak** — `buildEnv()` in executor inherited full `os.Environ()`, bypassing the policy env allowlist. All parent secrets (API keys, tokens) leaked to MCP servers regardless of allowlist. Fixed: env filtering now happens once in `run.go` before passing to executor; `buildEnv()` only uses explicitly-approved vars.
  - **CRITICAL: Manifest wildcard injection** — Malicious manifests could include `"*"` in `environment` or `network` fields to bypass filtering without CLI flags. Fixed: `ApplyManifestPermissions()` now strips `"*"` from manifest-provided lists (only CLI `--allow-all-env`/`--allow-all-net` can grant blanket access).
  - **CRITICAL: Darwin subprocess default-deny inversion** — `perms == nil || perms.Subprocess` in SBPL generation allowed global `process-exec` when no permissions were set (nil). Fixed: changed to `perms != nil && perms.Subprocess` (default-deny).
  - **HIGH: Reactive proxy wrong suggestions** — Proxy suggested `--allow-write` even when `--allow-fs` was active. Fixed: `buildSandboxSuggestion()` now receives `SandboxContext` and tailors recommendations based on already-active permissions.
  - **HIGH: Missing env restriction info for LLM** — Warning text only showed env info when `AllEnv=true`. Fixed: now shows specific allowed vars when restricted, or "manifest-declared only" when empty.
  - Added macOS SBPL per-domain network limitation documentation (sandbox-exec is all-or-nothing for network).
  - Added comprehensive tests: wildcard injection rejection, env filtering with full os.Environ(), subprocess default-deny verification, combined AllFS+AllNet SBPL, proxy suggestion accuracy with blanket flags.

### Added

- **2026-03-03**: Fixed blanket permission flags to actually work at runtime, not just in warning text. `--allow-fs` now skips mount namespace on Linux and generates `(allow file-read* file-write*)` in macOS SBPL. `--allow-all-net` skips network namespace on Linux and enables `(allow network*)` on macOS. `--allow-all-env` now uses `"*"` wildcard in `ValidateEnv()` to pass all env vars through (was broken: treated `"*"` as literal var name, stripped everything). `ValidateNetwork()` also supports `"*"` wildcard. Added tests for all blanket flag propagation paths.

- **2026-03-03**: Blanket permission flags: `--allow-fs` (full filesystem), `--allow-all-net` (all network), `--allow-all-env` (all env vars), `--allow-all` (everything at once). These complement the granular `--allow-read`/`--allow-write`/`--allow-net`/`--allow-env` flags.

- **2026-03-03**: Sandbox permission CLI flags and LLM notification system. Added `--allow-read`, `--allow-write`, `--allow-net`, `--allow-subprocess`, `--allow-env` flags to `smcp run` for granting specific sandbox permissions. Added proactive `[SANDBOX CONTEXT]` section in MCP handshake so the LLM knows about sandbox restrictions upfront. Added reactive sandbox error interception — when the sandbox blocks an operation, the proxy detects the error pattern in real-time and injects a `notifications/message` to the LLM explaining what happened and which `--allow-*` flag to suggest. Added `FileSystemRead` field to `PermissionsInfo` for read-only filesystem paths. Added read-only path support in macOS SBPL profiles (`file-read*` only). Proxy now always activates with `--trust` (not just for low-score packages) to enable sandbox context and error scanning for all packages.

### Fixed

- **2026-02-26**: Fixed missed `mcp` → `smcp` references in `.claude/` agent and skill files (26 files total). Changed `~/.mcp/` → `~/.smcp/` config/cache/audit paths, CLI command references (`mcp run` → `smcp run`, `mcp doctor` → `smcp doctor`, etc.), Cobra `Use: "mcp"` → `Use: "smcp"`, build targets `cmd/mcp` → `cmd/smcp`, cgroup names, and binary references (`./mcp` → `./smcp`). Preserved MCP protocol name, `mcp-cage` project name, `MCP_*` env vars, and Go import paths.

### Added

- **2026-02-25**: Ubuntu PPA packaging (`ppa:mcphub/smcp`). Added `debian/` directory with full Debian source packaging (control, rules, copyright, changelog). Added `scripts/ppa-upload.sh` for building and uploading source packages to Launchpad PPA targeting Noble (24.04 LTS) and Jammy (22.04 LTS). Added `.github/workflows/ppa.yml` for automated PPA uploads on git tag push. Orig tarball is built once and shared across releases to ensure identical checksums. Users can install with `sudo add-apt-repository ppa:mcphub/smcp && sudo apt install smcp`.

### Changed

- **2026-02-24**: Switched release pipeline from manual `go build` to GoReleaser v2. Adds Homebrew tap auto-publishing to `mcp-hub-corp/homebrew-tap`. Install with `brew install mcp-hub-corp/tap/smcp`. Fixed GitHub org reference from `security-mcp` to `mcp-hub-corp` in `.goreleaser.yml`. Updated README install section with Homebrew as recommended method.

### Changed (previous)

- **2026-02-24**: CLI output refresh — Docker Build style. Steps now align vertically with fixed-width description columns. Info card replaced box-drawing borders with compact indented text (Score, Origin, SHA, Format on minimal lines). Sandbox capabilities shown inline (`net:✓ fs:✓ exec:✓`). Subprocess output (uv, pip, etc.) hidden by default, shown with `--verbose`. Executor "starting STDIO executor" log demoted to Debug level.

- **2026-02-24**: Refactored `run.go` to use `ProgressUI` from `progress.go` for Docker-style step progress output. Replaced old `printSecurityBanner`, `printSecuritySummary`, `printField`, `printSecCapability`, `printWarning` functions and ANSI constants with the new `ProgressUI` API. The run command now shows 6 progress steps (Resolving package, Checking policies, Fetching manifest, Fetching bundle, Extracting bundle, Preparing execution) with spinner, cache-skip, and failure indicators. `InfoCard` is always displayed (no longer gated by `--verbose`). Added SIGINT/SIGTERM signal handling for graceful shutdown with audit logging.

### Added

- **2026-02-24**: SIGINT/SIGTERM signal handling in `smcp run`. The executor runs in a goroutine; signals cancel the context and wait for clean shutdown, logging the event to the audit trail.
- **2026-02-23**: Pretty CLI log handler (`PrettyHandler`) replacing `slog.TextHandler`. Terminal: ANSI colors + icons (`⚠` warn, `✗` error), no timestamps. Non-terminal: plain `[LEVEL] message` format.
- **2026-02-23**: Runtime/command consistency warning in `parseHubManifest()` — warns when `runtime.type` doesn't match the entrypoint command (e.g., python runtime with node command).

### Fixed

- **2026-02-20**: Fixed cross-platform test compilation:
  - `sandbox_e2e_test.go` referenced `DarwinSandbox` type without build tag, breaking Linux builds
  - Replaced concrete type assertion with `Capabilities().SupportsSandboxExec` interface check
- **2026-02-20**: Fixed data race in `LinuxSandbox`:
  - `pendingLimits` and `trackedCgroups` accessed without synchronization in concurrent usage
  - Added `sync.Mutex` to protect shared state in `applyRLimits`, `PostStart`, and `CleanupCgroup`

### Changed

- **2026-02-20**: Code cleanup for open source readiness:
  - Fixed placeholder email in CONTRIBUTING.md (security@mcp-hub.info)
  - Fixed hardcoded User-Agent in pull.go (uses Version variable via ldflags)
  - Fixed stale TODO comment in login.go
  - Fixed Go version in release.yml (1.22 → 1.24)
  - Fixed goreleaser to exclude docs/internal/ from releases
  - Removed empty TestReadInput test in login_test.go
  - Removed internal CLIENT-CRIT-XXX IDs from public security docs
  - Merged 3 init() functions into 1 in root.go
  - Cleaned personal filesystem paths in docs/internal/
- **2026-02-20**: Eliminated all lint warnings (~60 fixes across 15 files):
  - Fixed errcheck: proper deferred Close() patterns with explicit error discard
  - Fixed govet/shadow: renamed inner `:=` variables to avoid shadowing
  - Fixed gocritic: append merging, octal literals, filepath.Join, exitAfterDefer
  - Fixed gofmt: whitespace formatting
  - Fixed unparam: nolint directives for intentionally uniform helper signatures
- **2026-02-20**: Rewritten README.md for open-source release with professional structure, comparison table vs uvx/npx, security model documentation, and architecture diagram
- **2026-02-20**: Moved 10 internal development docs to docs/internal/ to clean up repository root
- **2026-02-20**: Updated .gitignore to exclude binaries, test artifacts, OS/IDE files

## [1.0.0] - 2026-01-18

### Added

- Initial release of mcp-cage
- CLI commands: run, pull, info, login, logout, cache, doctor
- Registry integration with authentication (Bearer, Token, Basic)
- Content-addressable cache with atomic operations
- Manifest parsing and validation
- Policy engine with resource limits and allowlists
- Audit logging with JSON structured format
- STDIO executor for MCP servers
- Platform-specific sandbox implementations:
  - Linux: rlimits, cgroups v2 detection, namespace support
  - macOS: rlimits with documented limitations
  - Windows: Job Objects placeholder with documented limitations
- SHA-256 digest validation for all artifacts
- Comprehensive documentation (OVERVIEW, SECURITY, EXAMPLES)
- Full test coverage (75.8% average)
- Multi-platform support (Linux, macOS, Windows)

### Security

- Mandatory digest validation (SHA-256)
- Default-deny network policies (Linux only)
- Environment variable filtering
- Subprocess control
- Audit logging for compliance
- Resource limits enforcement
- Directory traversal protection
- Decompression bomb protection

### Documentation

- Complete architecture overview
- Comprehensive threat model
- Platform-specific capabilities matrix
- 50+ usage examples
- Configuration reference
- Troubleshooting guide
- Contributing guidelines
- Code of Conduct

[Unreleased]: https://github.com/mcp-hub-corp/mcp-cage/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/mcp-hub-corp/mcp-cage/releases/tag/v1.0.0
