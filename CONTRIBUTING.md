# Contributing to mcp-cage

Thank you for your interest in contributing to mcp-cage! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior** vs **actual behavior**
- **Environment details**: OS, architecture, Go version
- **Relevant logs** (use `--verbose` flag)
- **Output of `smcp doctor`** if applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear, descriptive title**
- **Provide detailed description** of the proposed functionality
- **Explain why this enhancement would be useful**
- **List any alternative solutions** you've considered

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow the coding standards** (see below)
3. **Write or update tests** for your changes
4. **Update documentation** if you change functionality
5. **Ensure tests pass**: `make test`
6. **Ensure linting passes**: `make lint`
7. **Write meaningful commit messages**
8. **Submit the pull request**

## Development Setup

### Prerequisites

- Go 1.21 or later
- golangci-lint (for linting)
- make

### Building from Source

```bash
git clone https://github.com/mcp-hub-corp/mcp-cage.git
cd mcp-cage
make build
```

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run tests for specific package
go test ./internal/registry/...
```

### Code Style

We follow standard Go conventions:

- Use `go fmt` for formatting (enforced by CI)
- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `golangci-lint` for linting (enforced by CI)
- Write godoc comments for exported functions
- Keep functions focused and testable

### Testing Guidelines

- Write unit tests for all new functionality
- Maintain test coverage above 70%
- Use table-driven tests where appropriate
- Use `testify` for assertions
- Mock external dependencies
- Use build tags for platform-specific tests:
  - `//go:build linux` for Linux-only tests
  - `//go:build darwin` for macOS-only tests
  - `//go:build windows` for Windows-only tests

### Documentation

- Update README.md for user-facing changes
- Update docs/ for architectural changes
- Add examples to docs/EXAMPLES.md for new features
- Document security implications in docs/SECURITY.md
- Update CHANGELOG.md with your changes

## Platform-Specific Contributions

### Linux Contributions

When contributing Linux-specific code (sandbox, cgroups, namespaces):

- Use build tag: `//go:build linux`
- Test on multiple distributions (Ubuntu, Fedora, Alpine)
- Document kernel version requirements
- Consider both cgroups v1 and v2
- Test with and without root privileges

### macOS Contributions

When contributing macOS-specific code:

- Use build tag: `//go:build darwin`
- Test on multiple macOS versions
- Document limitations clearly (no cgroups, no network namespaces)
- Consider both Intel and Apple Silicon

### Windows Contributions

When contributing Windows-specific code:

- Use build tag: `//go:build windows`
- Test on Windows 10 and 11
- Document limitations (no network isolation without drivers)
- Use Job Objects for resource limits

## Commit Message Guidelines

Use conventional commits format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `chore`: Maintenance tasks

**Examples:**
```
feat(cache): add LRU eviction policy

Implement LRU eviction when cache exceeds max size.
Uses last access time to determine which artifacts to remove.

Closes #123
```

```
fix(sandbox): correct memory limit parsing on macOS

Memory limits were being parsed incorrectly on macOS due to
different units. Now properly handles K/M/G suffixes.

Fixes #456
```

## Security Contributions

Security is a top priority. When contributing security-related changes:

- **Never introduce security regressions**
- **Follow security invariants** in docs/SECURITY.md
- **Document threat model implications**
- **Add security tests** for new attack vectors
- **Use constant-time comparisons** for secrets
- **Validate all inputs**
- **Sanitize all outputs**

### Reporting Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email security@mcp-hub.info with details
2. Include steps to reproduce
3. Suggested fix if you have one
4. We will acknowledge within 48 hours
5. We will provide a fix timeline

## Release Process

Releases follow semantic versioning (semver):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

Release process:
1. Update CHANGELOG.md
2. Update version in code
3. Create git tag
4. Build binaries for all platforms
5. Publish GitHub release
6. Update documentation

## Community

- **GitHub Discussions**: For questions and discussions
- **GitHub Issues**: For bug reports and feature requests
- **Pull Requests**: For code contributions

## Recognition

Contributors will be recognized in:
- CHANGELOG.md for each release
- README.md contributors section
- GitHub contributors page

Thank you for contributing to mcp-cage!
