# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

- Initial release of mcp-client
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

[Unreleased]: https://github.com/security-mcp/mcp-client/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/security-mcp/mcp-client/releases/tag/v1.0.0
