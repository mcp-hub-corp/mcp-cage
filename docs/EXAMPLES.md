# Usage Examples

This document provides practical examples of using mcp-cage for different scenarios.

## Basic Usage

### Execute a Package

```bash
# Run with version
smcp run acme/hello-world@1.2.3

# Run with semantic version constraint
smcp run acme/hello-world@latest

# Run with SHA reference
smcp run acme/hello-world@sha:abc123def456

# Run with digest reference
smcp run acme/hello-world@digest:sha256:abc123...
```

### Pre-download Without Running

Useful for CI/CD to populate cache before execution:

```bash
# Download to cache
smcp pull acme/tool@1.2.3

# Verify download completed
smcp cache ls | grep acme

# Later, run from cache (instant)
smcp run acme/tool@1.2.3
```

### Check System Capabilities

```bash
# See what isolation features are available
smcp doctor

# Example output on Linux with cgroups:
# [✓] OS: linux (amd64)
# [✓] Cgroups v2: available
# [✓] Network namespaces: available (requires CAP_NET_ADMIN)
# [✓] Seccomp: available
# [!] Running as non-root: network isolation limited
# [✓] Cache directory: /home/user/.smcp/cache (writable)
```

## Environment Variables

### Pass Environment Variables

```bash
# From command line (unsafe for secrets)
smcp run acme/api-tool@1.0.0 \
  --env LOG_LEVEL=debug \
  --env API_ENDPOINT=https://api.example.com

# From .env file (safer for secrets)
smcp run acme/api-tool@1.0.0 \
  --env-file .env

# Mix both
smcp run acme/api-tool@1.0.0 \
  --env-file .env \
  --env DEBUG=true
```

### Example .env File

```bash
# .env
LOG_LEVEL=info
API_ENDPOINT=https://api.example.com
TIMEOUT=30s
# Database credentials should be here, not in manifest
DATABASE_URL=postgres://user:pass@localhost/db
```

### Environment Filtering

By default, only environment variables declared in manifest are passed. Check manifest:

```bash
# View package manifest (includes env configuration)
smcp info acme/api-tool@1.0.0 --json | jq '.manifest.environment'

# Example manifest with environment config:
# {
#   "allowed_names": ["LOG_LEVEL", "API_ENDPOINT", "TIMEOUT"],
#   "deny_patterns": ["*SECRET*", "*PASSWORD*"]
# }
```

## Resource Limits and Timeouts

### Set Timeout for Long-Running Operations

```bash
# Default timeout: 5 minutes
smcp run acme/quick-task@1.0.0

# Override timeout (short-lived task)
smcp run acme/quick-task@1.0.0 --timeout 10s

# Long-running task
smcp run acme/batch-processor@1.0.0 --timeout 2h
```

### Configure Resource Limits

Edit `~/.smcp/config.yaml`:

```yaml
executor:
  # Timeout for all operations
  default_timeout: 5m

  # CPU limit (millicores: 1000 = 1 core)
  max_cpu: 1000           # 1 core

  # Memory limit
  max_memory: 512M        # 512 MB

  # Process limit (prevents fork bombs)
  max_pids: 10            # max 10 processes

  # File descriptor limit
  max_fds: 100            # max 100 open files
```

### Monitor Resource Usage

```bash
# Run with verbose output to see resource limits applied
smcp run acme/tool@1.0.0 --verbose

# Example output:
# [DEBUG] Applying resource limits: CPU=1000ms/s, Memory=512MB, PIDs=10
# [DEBUG] Applying timeout: 5m
```

## Network Access

### Restrict Network Access

Manifest controls which domains/IPs are accessible:

```bash
# View manifest to see network policy
smcp info acme/web-crawler@1.0.0 --json | jq '.manifest.network'

# Example manifest with network allowlist:
# {
#   "allowlist": [
#     "api.example.com",
#     "cdn.example.com:443",
#     "10.0.0.0/8"
#   ]
# }
```

### No Network Access (Default)

If manifest doesn't declare network allowlist:

```bash
# Package gets no external network access
# Only loopback (127.0.0.1) is accessible
smcp run acme/local-processor@1.0.0 --verbose
# [DEBUG] Network policy: deny (no allowlist)
```

### Test Network Access

```bash
# If package has network allowlist, it can access those domains
smcp run acme/http-client@1.0.0 \
  --env TARGET_URL=https://api.example.com \
  --timeout 30s
```

## Cache Management

### List Cached Packages

```bash
# Show all cached artifacts
smcp cache ls

# Example output:
# DIGEST                                          TYPE      SIZE     LAST USED
# sha256:abc123...                                manifest  4.2 KB   2 hours ago
# sha256:def456...                                bundle    12.5 MB  2 hours ago
# sha256:ghi789...                                manifest  5.1 KB   30 mins ago
```

### Clear Cache

```bash
# Remove specific artifact
smcp cache rm sha256:abc123...

# Clear all cache
smcp cache rm --all

# List cache after cleanup
smcp cache ls
# (empty)
```

### Force Fresh Download

```bash
# Ignore cache, force re-download
smcp run acme/tool@1.2.3 --no-cache

# Useful when registry updated package at same version
```

## Logging and Debugging

### Enable Verbose Output

```bash
# Show debug information
smcp run acme/tool@1.0.0 --verbose

# Example output:
# [DEBUG] Config loaded from /home/user/.smcp/config.yaml
# [DEBUG] Registry URL: https://registry.example.com
# [DEBUG] Cache hit: manifest sha256:abc123
# [DEBUG] Cache miss: bundle sha256:def456
# [DEBUG] Downloading bundle (12.5 MB)...
# [DEBUG] Digest validation: OK (sha256:def456)
# [DEBUG] Applying resource limits: CPU=1000ms/s, Memory=512MB
# [DEBUG] Entrypoint: /bin/mcp-server --mode stdio
# [DEBUG] Process started (PID 12345)
```

### JSON Output

```bash
# Output structured JSON for logging/monitoring
smcp run acme/tool@1.0.0 --json

# Also works with other commands
smcp info acme/tool@1.0.0 --json
smcp cache ls --json
```

### Check Audit Log

```bash
# View local audit trail
tail -f ~/.smcp/audit.log

# Each line is a JSON event:
# {"timestamp":"2026-01-18T10:30:00Z","event":"start","package":"acme/tool",...}
# {"timestamp":"2026-01-18T10:30:05Z","event":"end","package":"acme/tool",...}

# Parse with jq
cat ~/.smcp/audit.log | jq '.event'
# "start"
# "end"
```

## Advanced Configuration

### Multiple Registries

```bash
# Login to different registry
smcp login --registry https://private-registry.example.com --token secret123

# Later, packages resolve from default registry
smcp run acme/public-tool@1.0.0

# Switch registry for specific command
smcp run acme/private-tool@1.0.0 --registry https://private-registry.example.com
```

### Custom Config File

```bash
# Use custom config location
export MCP_CONFIG_PATH=/etc/mcp/config.yaml
smcp run acme/tool@1.0.0

# Or via flag (priority over env var)
smcp run acme/tool@1.0.0 --config /custom/path/config.yaml
```

### Environment Variable Overrides

```bash
# Override config via environment variables
export MCP_REGISTRY_URL=https://custom-registry.com
export MCP_CACHE_DIR=/tmp/mcp-cache
export MCP_LOG_LEVEL=debug

smcp run acme/tool@1.0.0
```

## CI/CD Integration

### Pre-download Packages

```bash
# In CI setup phase, pre-download all packages
# This speeds up test execution
smcp pull acme/tool@1.2.3
smcp pull acme/other@2.0.0

# Later, smcp run uses cache (instant)
smcp run acme/tool@1.2.3
smcp run acme/other@2.0.0
```

### GitHub Actions Example

```yaml
name: Run MCP Tools

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Download mcp-cage
        run: |
          curl -sSL https://github.com/security-mcp/mcp-cage/releases/download/v1.0.0/smcp-linux-amd64 \
            -o /usr/local/bin/smcp
          chmod +x /usr/local/bin/smcp

      - name: Pre-download packages
        run: |
          smcp pull acme/linter@1.0.0
          smcp pull acme/formatter@1.0.0

      - name: Run linter
        run: smcp run acme/linter@1.0.0 -- ./src

      - name: Run formatter
        run: smcp run acme/formatter@1.0.0 -- --check ./src

      - name: Cache cleanup
        run: smcp cache rm --all
```

### Docker Example

```dockerfile
FROM golang:1.21

# Download mcp-cage
RUN curl -sSL https://github.com/security-mcp/mcp-cage/releases/download/v1.0.0/smcp-linux-amd64 \
    -o /usr/local/bin/smcp && chmod +x /usr/local/bin/smcp

# Pre-download packages
RUN smcp pull acme/analyzer@2.0.0

WORKDIR /app
COPY . .

# Run MCP tool
RUN smcp run acme/analyzer@2.0.0

# Build application
RUN go build -o app .
```

## Troubleshooting

### Package Not Found

```bash
# Error: package not found (404)

# Check package name and version
smcp info acme/typo-name@1.0.0
# Error: not found

# Verify correct name
smcp info acme/correct-name@1.0.0
# OK

# List available packages (if registry supports it)
smcp info --list
```

### Authentication Failed

```bash
# Error: unauthorized (401)

# Login with token
smcp login --token your-token-here

# Verify login worked
smcp info acme/tool@1.0.0
# Should work now
```

### Digest Validation Failed

```bash
# Error: digest validation failed

# This indicates package corruption or tampering
# Solution: Force re-download
smcp run acme/tool@1.0.0 --no-cache

# If still fails, contact registry administrator
# Check audit log for details
tail ~/.smcp/audit.log
```

### Timeout During Execution

```bash
# Error: process killed by timeout (60s exceeded)

# Increase timeout for this package
smcp run acme/slow-tool@1.0.0 --timeout 5m

# Or update config permanently
# Edit ~/.smcp/config.yaml:
# executor:
#   default_timeout: 10m
```

### Resource Limits Exceeded

```bash
# Error: process killed: memory limit exceeded

# Package needs more memory
# Either update config:
# executor:
#   max_memory: 1G
#
# Or investigate if package has a memory leak

# Check verbose output for resource usage
smcp run acme/tool@1.0.0 --verbose
```

### No Network Access

```bash
# Package fails with network errors
# (e.g., "cannot reach api.example.com")

# Check if package has network allowlist
smcp info acme/tool@1.0.0 --json | jq '.manifest.network'

# If allowlist is empty, no external network allowed
# Add to config or contact package maintainer

# If allowlist exists but domain not included, it's intentional
# Contact package maintainer to request access
```

### Check Platform Capabilities

```bash
# macOS user trying to run package with network restrictions?
smcp doctor

# Output shows:
# [!] Network isolation not available on darwin

# This is expected on macOS - no network namespaces
# Solution: Run in Linux VM or use private/trusted packages only
```

## Performance Tips

### Cache Pre-warming

```bash
# In CI/CD, pre-warm cache in parallel setup job
# Speeds up individual test jobs
smcp pull acme/tool@1.0.0 &
smcp pull acme/other@2.0.0 &
smcp pull acme/third@3.0.0 &
wait
```

### Reuse Cached Binaries

```bash
# Don't use --no-cache unnecessarily
# Cached binaries are validated and instant

# Good: use cache
smcp run acme/tool@1.0.0

# Bad: avoid forcing re-download
smcp run acme/tool@1.0.0 --no-cache  # only if you have reason
```

### Monitor Cache Size

```bash
# Check cache usage
du -sh ~/.smcp/cache

# Clear if getting too large
smcp cache rm --all

# Set max cache size in config
# executor:
#   cache:
#     max_size: 10GB
```

---

**Last Updated**: 2026-01-18
**Examples Version**: 1.0
