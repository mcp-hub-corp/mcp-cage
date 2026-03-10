# CI/CD Automation for mcp-cage

## Overview

This skill covers designing, implementing, and optimizing CI/CD pipelines for mcp-cage. Includes GitHub Actions workflows, multi-platform testing, release automation, and best practices for Go projects.

**Key Areas:**
- GitHub Actions CI/CD workflows
- Multi-platform testing matrix
- Build tags and conditional compilation
- Test execution and coverage
- Linting and quality checks
- Release automation with goreleaser
- Artifact management and checksums
- Caching strategies

---

## 1. CI/CD Pipeline Architecture

### 1.1 Overall Pipeline

```
Push/PR → CI (test, lint, build) → Artifacts
            ↓
            PR check gate
            ↓
Merge → Release (tagged) → goreleaser → Multi-platform binaries
            ↓
            Upload to GitHub Releases
            ↓
            Checksums + SBOM
```

### 1.2 Jobs in Pipeline

1. **Test Job** - Unit/integration tests on multiple OS/Go versions
2. **Lint Job** - Code quality checks (golangci-lint, gosec)
3. **Build Job** - Verify binaries build on all platforms
4. **Release Job** - Triggered on version tags, builds release binaries

---

## 2. GitHub Actions CI Workflow

### 2.1 Current CI Configuration

**Location:** `/Users/cr0hn/Dropbox/Projects/mcp-cage/.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

permissions:
  contents: read

jobs:
  test:
    name: Test
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        go: ['1.21', '1.22']
    steps:
    - uses: actions/checkout@v4

    - name: Set up Go
      uses: actions/setup-go@v5
      with:
        go-version: ${{ matrix.go }}

    - name: Cache Go modules
      uses: actions/cache@v4
      with:
        path: ~/go/pkg/mod
        key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
        restore-keys: |
          ${{ runner.os }}-go-

    - name: Download dependencies
      run: go mod download

    - name: Run tests
      run: go test -v -race -coverprofile=coverage.out ./...

    - name: Upload coverage
      uses: codecov/codecov-action@v4
      if: matrix.os == 'ubuntu-latest' && matrix.go == '1.22'
      with:
        files: ./coverage.out
        flags: unittests

  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Set up Go
      uses: actions/setup-go@v5
      with:
        go-version: '1.22'

    - name: golangci-lint
      uses: golangci/golangci-lint-action@v4
      with:
        version: latest
        args: --timeout=5m

  build:
    name: Build
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
    - uses: actions/checkout@v4

    - name: Set up Go
      uses: actions/setup-go@v5
      with:
        go-version: '1.22'

    - name: Build
      run: go build -v ./cmd/smcp

    - name: Verify binary
      run: ./mcp --version || mcp.exe --version
      shell: bash
```

### 2.2 Interpreting CI Results

**Successful run:**
```
✓ Test (ubuntu-latest, 1.21)
✓ Test (ubuntu-latest, 1.22)
✓ Test (macos-latest, 1.21)
✓ Test (macos-latest, 1.22)
✓ Test (windows-latest, 1.21)
✓ Test (windows-latest, 1.22)
✓ Lint
✓ Build (ubuntu-latest)
✓ Build (macos-latest)
✓ Build (windows-latest)
```

**Failed run investigation:**
```bash
# Click on failed job → Logs
# Look for:
# 1. Test failure - which test, what assertion
# 2. Lint failure - which files, what rule violated
# 3. Build failure - compilation error, missing dependency

# Run locally to reproduce
go test -v ./... -run TestName
golangci-lint run ./...
go build ./cmd/smcp
```

---

## 3. Multi-Platform Testing Matrix

### 3.1 OS Matrix

**Current matrix:**
```yaml
os: [ubuntu-latest, macos-latest, windows-latest]
```

**Platform details:**
- **ubuntu-latest**: Ubuntu 22.04 LTS, Linux kernel 6.x
- **macos-latest**: macOS 13.x (Intel), macOS 14.x (ARM)
- **windows-latest**: Windows Server 2022

### 3.2 Go Version Matrix

**Current matrix:**
```yaml
go: ['1.21', '1.22']
```

**Rationale:**
- Test on multiple Go versions
- Catch compatibility issues early
- Ensure module compatibility

**Future considerations:**
```yaml
go: ['1.21', '1.22', '1.23']  # Add new versions
```

### 3.3 Architecture Matrix

**For cross-compilation testing:**
```yaml
strategy:
  matrix:
    include:
      - os: ubuntu-latest
        go: '1.22'
        build_matrix: |
          GOOS=linux GOARCH=amd64
          GOOS=linux GOARCH=arm64
          GOOS=darwin GOARCH=amd64
          GOOS=darwin GOARCH=arm64
          GOOS=windows GOARCH=amd64
```

### 3.4 Platform-Specific Tests

**Using build tags:**
```go
// internal/sandbox/linux_test.go
// +build linux

func TestLinuxCgroups(t *testing.T) {
	// Only runs on Linux
}

// internal/sandbox/darwin_test.go
// +build darwin

func TestDarwinRlimits(t *testing.T) {
	// Only runs on macOS
}
```

**Running with tags:**
```bash
# Test only Linux build
go test -tags linux ./internal/sandbox

# Test all builds
go test ./internal/sandbox
```

---

## 4. Test Execution

### 4.1 Test Flags and Options

**Current test command:**
```bash
go test -v -race -coverprofile=coverage.out ./...
```

**Flag breakdown:**
- `-v`: Verbose output (show all tests)
- `-race`: Enable race detector (detects data races)
- `-coverprofile=coverage.out`: Generate coverage file

### 4.2 Advanced Test Options

**Timeout and parallelism:**
```bash
# Increase timeout for long tests
go test -timeout 10m ./...

# Control parallelism (default is number of CPUs)
go test -parallel 4 ./...

# Run sequentially (for non-parallel tests)
go test -parallel 1 ./...
```

**Benchmarks with tests:**
```bash
# Run tests and benchmarks
go test -bench=. -benchtime=10s ./internal/cache

# Run only benchmarks
go test -bench=. -run=^$ ./internal/cache

# Benchmark with CPU profile
go test -bench=. -cpuprofile=cpu.prof ./internal/cache
```

**Coverage options:**
```bash
# Coverage per statement
go test -cover ./...

# Generate HTML report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Coverage with race detector
go test -race -coverprofile=coverage.out ./...
```

### 4.3 Test Filtering

**Run specific test:**
```bash
# Run one test
go test -run TestRunCommand ./internal/cli

# Run tests matching pattern
go test -run "^Test.*Cache" ./internal/cache

# Run except integration tests
go test -run "^Test[^I]" ./...
```

**Skip tests:**
```bash
# Skip tests matching pattern
go test -skip "Integration" ./...

# Run short tests only (in tests: if testing.Short() { t.Skip() })
go test -short ./...
```

---

## 5. Linting and Code Quality

### 5.1 golangci-lint Configuration

**Location:** `/Users/cr0hn/Dropbox/Projects/mcp-cage/.golangci.yml`

```yaml
# GolangCI-Lint configuration
linters:
  enable-all: true
  disable:
    - exhaustivestruct  # Too strict
    - forbidigo         # False positives
    - nilnil            # Edge cases

issues:
  exclude-rules:
    - path: _test\.go$
      linters:
        - gocyclo        # Tests can be complex
        - funlen         # Test setup can be long
    - path: cmd/
      linters:
        - lll            # CLI strings can be long
```

### 5.2 Running golangci-lint

**Local:**
```bash
# Install
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin

# Run linter
golangci-lint run

# Run with specific config
golangci-lint run -c .golangci.yml

# Fix auto-fixable issues
golangci-lint run --fix
```

**In CI:**
```yaml
- name: golangci-lint
  uses: golangci/golangci-lint-action@v4
  with:
    version: latest
    args: --timeout=5m
```

### 5.3 Common Linter Issues

**Unused variables:**
```bash
golangci-lint run 2>&1 | grep "unused"
# Fix: Remove or use variable
```

**Imported but unused packages:**
```bash
golangci-lint run 2>&1 | grep "import"
# Fix: Remove import or use package
```

**Shadowed variables:**
```bash
golangci-lint run 2>&1 | grep "shadow"
# Fix: Rename variable to avoid shadowing outer scope
```

**Cyclomatic complexity:**
```bash
golangci-lint run 2>&1 | grep "cyclomatic"
# Fix: Break function into smaller functions
```

### 5.4 Security Linting

**gosec integration:**
```yaml
linters:
  enable:
    - gosec  # Security issues
```

**Common security checks:**
```bash
# Check for:
# - Weak cryptography
# - SQL injection
# - Hard-coded secrets
# - Unsafe file operations
gosec ./...
```

---

## 6. Coverage Reporting

### 6.1 Generate Coverage Reports

**Local:**
```bash
# Generate coverage profile
go test -coverprofile=coverage.out ./...

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html
open coverage.html

# View in terminal
go tool cover -func=coverage.out
```

**Output:**
```
github.com/security-mcp/mcp-cage/internal/cache/store.go:42:  NewStore        80.0%
github.com/security-mcp/mcp-cage/internal/cache/store.go:52:  GetManifest     95.0%
...
```

### 6.2 Coverage Goals

**Recommended:**
- Overall: >70%
- Critical paths (cache, manifest): >85%
- CLI: >60% (harder to test)
- Sandbox: >80%

**Enforce in CI:**
```yaml
- name: Check coverage
  run: |
    coverage=$(go tool cover -func=coverage.out | grep total | awk '{print int($NF)}')
    if [ $coverage -lt 70 ]; then
      echo "Coverage ${coverage}% below 70% threshold"
      exit 1
    fi
    echo "Coverage: ${coverage}%"
```

### 6.3 Codecov Integration

**Upload to codecov.io:**
```yaml
- name: Upload coverage
  uses: codecov/codecov-action@v4
  if: matrix.os == 'ubuntu-latest' && matrix.go == '1.22'
  with:
    files: ./coverage.out
    flags: unittests
    codecov_token: ${{ secrets.CODECOV_TOKEN }}
```

**Badge in README:**
```markdown
[![codecov](https://codecov.io/gh/security-mcp/mcp-cage/branch/main/graph/badge.svg)](https://codecov.io/gh/security-mcp/mcp-cage)
```

---

## 7. Release Automation

### 7.1 Release Workflow Configuration

**Location:** `/Users/cr0hn/Dropbox/Projects/mcp-cage/.github/workflows/release.yml`

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  release:
    name: Release
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0

    - name: Set up Go
      uses: actions/setup-go@v5
      with:
        go-version: '1.22'

    - name: Run tests
      run: make test

    - name: Build binaries
      run: |
        GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X github.com/security-mcp/mcp-cage/internal/cli.Version=${GITHUB_REF#refs/tags/}" -o mcp-linux-amd64 ./cmd/smcp
        GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X github.com/security-mcp/mcp-cage/internal/cli.Version=${GITHUB_REF#refs/tags/}" -o mcp-linux-arm64 ./cmd/smcp
        GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -X github.com/security-mcp/mcp-cage/internal/cli.Version=${GITHUB_REF#refs/tags/}" -o mcp-darwin-amd64 ./cmd/smcp
        GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -X github.com/security-mcp/mcp-cage/internal/cli.Version=${GITHUB_REF#refs/tags/}" -o mcp-darwin-arm64 ./cmd/smcp
        GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X github.com/security-mcp/mcp-cage/internal/cli.Version=${GITHUB_REF#refs/tags/}" -o mcp-windows-amd64.exe ./cmd/smcp

    - name: Create checksums
      run: |
        sha256sum mcp-* > checksums.txt

    - name: Create Release
      uses: softprops/action-gh-release@v1
      with:
        files: |
          mcp-linux-amd64
          mcp-linux-arm64
          mcp-darwin-amd64
          mcp-darwin-arm64
          mcp-windows-amd64.exe
          checksums.txt
        generate_release_notes: true
        draft: false
        prerelease: false
```

### 7.2 Triggering a Release

**Create and push version tag:**
```bash
# Checkout main
git checkout main
git pull origin main

# Create annotated tag
git tag -a v1.2.3 -m "Release version 1.2.3"

# Push tag
git push origin v1.2.3
```

**Watch release:**
```bash
# GitHub Actions will automatically:
# 1. Run tests
# 2. Build multi-platform binaries
# 3. Create checksums
# 4. Create GitHub Release
# 5. Upload artifacts

# Check status
gh run list --workflow=release.yml
gh run view <run-id>
```

### 7.3 goreleaser Alternative

**Modern alternative to release.yml:**

```yaml
# .goreleaser.yml
version: 2

builds:
  - main: ./cmd/smcp
    binary: smcp
    ldflags: -X github.com/security-mcp/mcp-cage/internal/cli.Version={{.Version}}
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64

archives:
  - format: tar.gz
    format_overrides:
      - goos: windows
        format: zip

checksum:
  name_template: 'checksums.txt'
  algorithm: sha256

release:
  github:
    owner: security-mcp
    name: mcp-cage
```

**Usage:**
```bash
# Install goreleaser
brew install goreleaser  # macOS
# or
curl -sL https://git.io/goreleaser | bash

# Build snapshot locally
goreleaser release --snapshot --clean

# Build and release (requires git tag)
goreleaser release --clean
```

---

## 8. Build Configuration

### 8.1 Makefile Targets

**Location:** `/Users/cr0hn/Dropbox/Projects/mcp-cage/Makefile`

```makefile
.PHONY: build test lint fmt clean install help

# Binary name
BINARY=smcp

# Build variables
VERSION ?= dev
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X github.com/security-mcp/mcp-cage/internal/cli.Version=$(VERSION) \
           -X github.com/security-mcp/mcp-cage/internal/cli.GitCommit=$(GIT_COMMIT) \
           -X github.com/security-mcp/mcp-cage/internal/cli.BuildDate=$(BUILD_DATE)

build: ## Build the mcp binary
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/smcp

test: ## Run tests
	go test -v -race -coverprofile=coverage.out ./...

lint: ## Run linters
	golangci-lint run

fmt: ## Format code
	go fmt ./...

clean: ## Clean build artifacts
	rm -f $(BINARY) coverage.out coverage.html
	go clean

install: build ## Install the binary
	go install -ldflags "$(LDFLAGS)" ./cmd/smcp

all: fmt lint test build ## Run all targets
```

**Using Makefile:**
```bash
make build      # Build binary
make test       # Run tests
make lint       # Run linters
make fmt        # Format code
make install    # Install binary
make all        # Everything
make clean      # Clean artifacts
```

### 8.2 Build Optimization

**Strip symbols for smaller binary:**
```bash
# Debug build (larger, with symbols)
go build -o smcp ./cmd/smcp

# Release build (smaller, no symbols)
go build -ldflags "-s -w" -o mcp ./cmd/smcp

# Check size difference
ls -lh mcp
```

**Cross-compilation:**
```bash
# Build for Linux ARM64
GOOS=linux GOARCH=arm64 go build -o smcp-linux-arm64 ./cmd/smcp

# Build for macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o smcp-darwin-amd64 ./cmd/smcp

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o smcp-windows-amd64.exe ./cmd/smcp
```

---

## 9. Artifact Management

### 9.1 Creating Checksums

**SHA256 checksums:**
```bash
# Create checksums for all binaries
sha256sum mcp-* > checksums.txt

# Output:
# abc123def456... mcp-linux-amd64
# def456abc123... mcp-linux-arm64
# 789012ghi345... mcp-darwin-amd64
# ...
```

**Verify checksum:**
```bash
# Verify single binary
sha256sum -c checksums.txt

# Verify with integrity check
sha256sum -c checksums.txt --strict
```

### 9.2 Software Bill of Materials (SBOM)

**Generate SBOM with syft:**
```bash
# Install
brew install syft  # macOS
# or
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# Generate SBOM
syft mcp-linux-amd64 -o json > sbom.json
syft mcp-linux-amd64 -o cyclonedx > sbom.xml
```

**Include in release:**
```yaml
- name: Generate SBOM
  run: |
    syft mcp-linux-amd64 -o json > sbom.json

- name: Upload SBOM
  uses: softprops/action-gh-release@v1
  with:
    files: sbom.json
```

### 9.3 Signing Releases (Optional)

**Using cosign:**
```bash
# Install
brew install cosign

# Sign binary
cosign sign-blob mcp-linux-amd64 > mcp-linux-amd64.sig

# Verify
cosign verify-blob mcp-linux-amd64 --signature mcp-linux-amd64.sig
```

---

## 10. Caching Strategies

### 10.1 Go Module Cache

**Current caching:**
```yaml
- name: Cache Go modules
  uses: actions/cache@v4
  with:
    path: ~/go/pkg/mod
    key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
    restore-keys: |
      ${{ runner.os }}-go-
```

**How it works:**
- Key: OS + hash of go.sum
- If go.sum changes, cache is invalidated
- Fallback to OS-specific cache if exact match not found

### 10.2 Build Cache

**Experimental Go build cache:**
```yaml
- name: Cache build
  uses: actions/cache@v4
  with:
    path: ~/.cache/go-build
    key: ${{ runner.os }}-build-${{ hashFiles('**/*.go') }}
    restore-keys: |
      ${{ runner.os }}-build-
```

### 10.3 Benchmark Cache

**Store baseline benchmarks:**
```yaml
- name: Cache benchmarks
  uses: actions/cache@v4
  with:
    path: .benchmarks
    key: ${{ runner.os }}-bench-${{ github.ref }}
```

---

## 11. Secrets Management

### 11.1 GitHub Secrets

**Define in repository settings:**
```
Settings → Secrets and variables → Actions
```

**Common secrets:**
- `CODECOV_TOKEN`: For codecov.io uploads
- `REGISTRY_TOKEN`: For pushing to registry
- `GPG_KEY`: For signing releases
- `SLACK_WEBHOOK`: For notifications

**Use in workflow:**
```yaml
- name: Upload coverage
  uses: codecov/codecov-action@v4
  with:
    codecov_token: ${{ secrets.CODECOV_TOKEN }}
```

### 11.2 Secure Environment Variables

**Never hardcode secrets:**
```yaml
# ✗ Wrong
- run: curl -H "Authorization: Bearer abc123def456" ...

# ✓ Correct
- run: curl -H "Authorization: Bearer ${{ secrets.REGISTRY_TOKEN }}" ...
```

---

## 12. Notifications and Reporting

### 12.1 Status Badges

**In README:**
```markdown
[![CI](https://github.com/security-mcp/mcp-cage/actions/workflows/ci.yml/badge.svg)](https://github.com/security-mcp/mcp-cage/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/security-mcp/mcp-cage/branch/main/graph/badge.svg)](https://codecov.io/gh/security-mcp/mcp-cage)
```

### 12.2 Slack Notifications (Optional)

```yaml
- name: Notify Slack
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "CI Failed: ${{ github.repository }} - ${{ github.ref }}"
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

---

## 13. Common CI/CD Issues and Solutions

### 13.1 Flaky Tests

**Problem:** Tests pass sometimes, fail other times

**Solutions:**
```bash
# Run test multiple times
go test -count=100 ./internal/cache

# Run with race detector
go test -race ./...

# Run in parallel
go test -parallel 8 ./...

# Increase timeout
go test -timeout 10m ./...
```

### 13.2 Slow CI Pipeline

**Problem:** Tests take >10 minutes

**Solutions:**
```yaml
# Parallelize jobs
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest, windows-latest]
    go: ['1.21', '1.22']
  # Runs 6 jobs in parallel instead of sequentially

# Skip expensive jobs on PR
- if: github.event_name == 'pull_request'
  name: Skip coverage upload on PR
  run: echo "Skipping coverage"
```

### 13.3 Out-of-Memory in CI

**Problem:** Go build or tests run out of memory

**Solutions:**
```yaml
# Limit parallelism
- run: go test -parallel 1 ./...

# Reduce build optimization
- run: go build -gcflags='-N' ./cmd/smcp
```

### 13.4 Network Timeouts

**Problem:** Downloads timeout in CI

**Solutions:**
```yaml
# Increase timeout
- run: go test -timeout 10m ./...

# Use caching to avoid re-download
- uses: actions/cache@v4
  with:
    path: ~/go/pkg/mod
```

---

## 14. Advanced CI/CD Patterns

### 14.1 Conditional Steps

```yaml
# Only run on main branch
- if: github.ref == 'refs/heads/main'
  run: make publish

# Only run on PR
- if: github.event_name == 'pull_request'
  run: make test-coverage

# Only run on failure
- if: failure()
  run: make debug-logs
```

### 14.2 Multiple Workflows

```
.github/workflows/
├── ci.yml           # Test on every commit
├── release.yml      # Release on tag
├── benchmark.yml    # Nightly benchmarks
├── security.yml     # Dependency scanning
└── docs.yml         # Deploy docs
```

### 14.3 Reusable Workflows

```yaml
# .github/workflows/test.yml (reusable)
on:
  workflow_call:
    inputs:
      go-version:
        required: true
        type: string

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ inputs.go-version }}
      - run: go test ./...

# .github/workflows/ci.yml (calls reusable)
jobs:
  test-1-21:
    uses: ./.github/workflows/test.yml
    with:
      go-version: '1.21'
  test-1-22:
    uses: ./.github/workflows/test.yml
    with:
      go-version: '1.22'
```

---

## 15. CI/CD Checklist

When setting up CI/CD for mcp-cage:

- [ ] All tests pass locally before pushing
- [ ] CI runs on push and PR to main
- [ ] Tests run on multiple OS (Linux, macOS, Windows)
- [ ] Tests run on multiple Go versions (1.21, 1.22)
- [ ] Coverage reported to codecov
- [ ] Linting passes (golangci-lint)
- [ ] Binary builds successfully on all platforms
- [ ] Race detector enabled in tests
- [ ] Release workflow triggers on version tags
- [ ] Checksums generated for all binaries
- [ ] No hardcoded secrets in workflows
- [ ] Caching reduces build time
- [ ] Artifacts uploaded to GitHub Releases
- [ ] Status badges in README
- [ ] Notifications for failures (optional)

---

## 16. Reference: Quick Commands

```bash
# Local testing (mirrors CI)
go test -v -race -coverprofile=coverage.out ./...
golangci-lint run
go build -v ./cmd/smcp

# Test on specific Go version
go1.21 test ./...

# Build for release
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X ..." -o mcp-linux-amd64 ./cmd/smcp
GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -X ..." -o mcp-darwin-arm64 ./cmd/smcp

# Create checksums
sha256sum mcp-* > checksums.txt

# Verify checksums
sha256sum -c checksums.txt

# Trigger release (requires git tag)
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3
```

---

## 17. Key Takeaways

1. **Fail fast, fail often** - CI catches bugs before code review
2. **Parallelize tests** - Use matrix strategy for speed
3. **Cache wisely** - Cache dependencies, not build outputs
4. **Multi-platform essential** - Test on Linux, macOS, Windows
5. **Automate releases** - Remove manual steps, reduce errors
6. **Checksum everything** - Verify binary integrity
7. **Monitor trends** - Watch coverage, test time, failure rate
8. **No secrets in code** - Use GitHub secrets, never hardcode
9. **Keep CI fast** - Aim for <5 minutes for PR feedback
10. **Document workflows** - Future maintainers need context
