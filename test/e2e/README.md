# End-to-End Tests

## Overview

This directory contains E2E tests that validate the complete mcp-cage workflow against a real mcp-registry server.

## Prerequisites

1. **mcp-registry running**:
   ```bash
   cd /tmp && gh repo clone security-mcp/mcp-registry
   cd mcp-registry
   make build
   ./bin/mcp-registry -config /tmp/mcp-e2e-config.yaml
   ```

2. **smcp binary built**:
   ```bash
   make build
   ```

## Running E2E Tests

```bash
# Run all E2E tests
go test ./test/e2e/... -tags=e2e -v

# Run specific test
go test ./test/e2e/... -tags=e2e -v -run=TestE2E_Doctor

# Run E2E benchmarks
go test ./test/e2e/... -tags=e2e -bench=. -run=^$
```

## Test Coverage

Current E2E tests:
- ✅ CLI commands (doctor, version, help, cache)
- ✅ Registry connectivity
- ✅ JSON output parsing
- ⏭️ Package operations (requires published packages)

## Registry Configuration

Tests expect registry at: `http://localhost:8090`

Sample config: `/tmp/mcp-e2e-config.yaml`

## Adding E2E Tests

1. Add test function to `e2e_test.go`
2. Use `runMCP()` helper to execute commands
3. Verify stdout, stderr, and exit codes
4. Clean up resources with `t.TempDir()` or `defer`

## Notes

- E2E tests use build tag `// +build e2e`
- Only run when explicitly requested with `-tags=e2e`
- Require external registry dependency
- Not run in standard CI (integration tests cover most workflows)
