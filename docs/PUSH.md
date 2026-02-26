# MCP Push Command

The `smcp push` command allows you to publish MCP packages to the hub for certification and distribution.

## Overview

The push command performs the following steps:

1. **Validates** the source directory structure
2. **Generates** a manifest from the source code
3. **Creates** a reproducible tar.gz bundle
4. **Uploads** the bundle to the hub
5. **Queues** the MCP for certification analysis

## Usage

```bash
smcp push <org>/<name>@<version> [flags]
```

### Examples

```bash
# Publish from current directory
smcp push acme/hello-world@1.0.0

# Publish from a specific directory
smcp push acme/hello-world@1.0.0 --source ./my-mcp

# Dry run (validate and package without uploading)
smcp push acme/hello-world@1.0.0 --dry-run

# Verbose output
smcp push acme/hello-world@1.0.0 --verbose

# Custom hub URL
smcp push acme/hello-world@1.0.0 --hub-url https://hub.example.com
```

## Flags

- `--source <dir>` - Source directory containing the MCP (default: current directory)
- `--hub-url <url>` - Hub URL (defaults to config or `MCP_HUB_URL` env var)
- `--token <token>` - Authentication token (defaults to `MCP_HUB_TOKEN` env var or stored credentials)
- `--dry-run` - Validate and package without uploading
- `--verbose, -v` - Enable verbose output

## Package Reference Format

The package reference must follow this format:

```
<org>/<name>@<version>
```

Where:
- `org` - Organization name (alphanumeric, hyphens, underscores)
- `name` - Package name (alphanumeric, hyphens, underscores)
- `version` - Semantic version (e.g., `1.0.0`, `v2.1.3`, `1.0.0-beta.1`)

Examples:
- `acme/hello-world@1.0.0`
- `myorg/data-tool@v2.1.3`
- `security-org/scanner@1.0.0-beta.1`

## Authentication

The push command requires authentication with the hub. You can provide credentials in several ways:

### 1. Environment Variable (Recommended)

```bash
export MCP_HUB_TOKEN="your-token-here"
smcp push acme/hello-world@1.0.0
```

### 2. Command Flag

```bash
smcp push acme/hello-world@1.0.0 --token your-token-here
```

### 3. Stored Credentials (Future)

```bash
smcp login
smcp push acme/hello-world@1.0.0
```

## Source Directory Structure

Your MCP source directory should contain:

- **Required**: Entrypoint files (e.g., `index.js`, `main.py`, `main.go`)
- **Optional**: `.mcpignore` file to exclude files from the bundle

### Supported Runtimes

The push command auto-detects the runtime based on files in the source directory:

- **Node.js**: `package.json` present
- **Python**: `requirements.txt`, `setup.py`, or `pyproject.toml` present
- **Go**: `go.mod` present
- **Binary**: Compiled executable

## .mcpignore File

Create a `.mcpignore` file to exclude files from the bundle (similar to `.gitignore`):

```
# .mcpignore example

# Node.js
node_modules/
*.log

# Python
__pycache__/
*.pyc
.venv/

# Build artifacts
dist/
build/
*.tar.gz

# Development
.git/
.env
*.test
```

Supported patterns:
- `*.log` - Match files with extension
- `node_modules/` - Match directory and contents
- `**/*.tmp` - Match files in any subdirectory
- `**/test/` - Match test directories anywhere

## Bundle Creation

The push command creates a reproducible tar.gz bundle with:

- **Normalized timestamps** - All files have timestamp `2000-01-01T00:00:00Z`
- **Normalized permissions** - Directories: `0750`, Files: `0640`
- **Sorted entries** - Files are sorted alphabetically
- **Content addressing** - SHA-256 digest calculated

This ensures that the same source code always produces the same bundle digest.

## Manifest Generation

The push command automatically generates a manifest with:

- **Package metadata** - Org, name, version
- **Bundle information** - SHA-256 digest, size
- **Transport configuration** - stdio (default) or http
- **Entrypoints** - Commands for different OS/arch combinations
- **Permissions** - Requested network, filesystem, subprocess access
- **Resource limits** - CPU, memory, PIDs, file descriptors

Example generated manifest:

```json
{
  "schema_version": "1.0",
  "package": {
    "id": "acme/hello-world",
    "version": "1.0.0"
  },
  "bundle": {
    "digest": "sha256:abcdef1234567890...",
    "size_bytes": 12345
  },
  "transport": {
    "type": "stdio"
  },
  "entrypoints": [
    {
      "os": "linux",
      "arch": "amd64",
      "command": "node index.js"
    }
  ],
  "permissions_requested": {
    "network": [],
    "filesystem": [],
    "subprocess": false
  },
  "limits_recommended": {
    "max_cpu": 1000,
    "max_memory": "512M",
    "max_pids": 100,
    "max_fds": 256,
    "timeout": "30s"
  }
}
```

## Upload Process

1. **Initialize Upload** - Request presigned URLs from hub
2. **Upload Bundle** - Upload tar.gz to S3 via presigned URL
3. **Finalize Upload** - Notify hub that upload is complete
4. **Queue Analysis** - Hub queues MCP for certification analysis

Progress bars show upload status:

```
📦 Packaging acme/hello-world@1.0.0
   Source: /path/to/mcp

  ✓ Bundle created (1.2 MB in 123ms)

→ Initializing upload...
  ✓ Upload initialized (ID: upload-abc123)

→ Uploading bundle...
  Uploading... 100.0% (1.2 MB / 1.2 MB) at 2.5 MB/s
  ✓ Bundle uploaded (456ms)

→ Finalizing upload...
  ✓ Upload finalized
    Version ID: version-xyz789
    Status: ingested

✅ Successfully published!

Your MCP is now queued for certification analysis.
You can check the status at: https://hub.example.com/versions/version-xyz789
```

## Dry Run Mode

Use `--dry-run` to validate and package without uploading:

```bash
smcp push acme/hello-world@1.0.0 --dry-run
```

Output:

```
📦 Packaging acme/hello-world@1.0.0
   Source: /path/to/mcp

  ✓ Bundle created (1.2 MB in 123ms)

✓ Dry run completed successfully

Generated files:
  Bundle: /tmp/mcp-push-123/bundle.tar.gz (1.2 MB)
  Manifest: /tmp/mcp-push-123/manifest.json

To publish, run without --dry-run flag
```

## Error Handling

Common errors and solutions:

### Invalid Package Reference

```
Error: invalid package reference: expected format: org/name@version
```

**Solution**: Use format `org/name@version`, e.g., `acme/tool@1.0.0`

### Source Directory Not Found

```
Error: source directory does not exist: /path/to/mcp
```

**Solution**: Check the `--source` flag or current directory

### Authentication Required

```
Error: authentication token required
```

**Solution**: Set `MCP_HUB_TOKEN` environment variable or use `--token` flag

### Hub Connection Failed

```
Error: failed to initialize upload: connection refused
```

**Solution**: Check hub URL with `--hub-url` flag or `MCP_HUB_URL` env var

### Bundle Too Large

```
Error: bundle exceeds maximum size of 1073741824 bytes
```

**Solution**: Add more entries to `.mcpignore` to reduce bundle size

## Configuration

The push command respects the following configuration sources (in order of precedence):

1. Command-line flags
2. Environment variables
3. Config file (`~/.smcp/config.yaml`)
4. Defaults

### Environment Variables

- `MCP_HUB_URL` - Hub URL
- `MCP_HUB_TOKEN` - Authentication token

### Config File

```yaml
# ~/.smcp/config.yaml
hub_url: https://hub.example.com
```

## Certification Process

After pushing, your MCP goes through the certification pipeline:

1. **Ingested** - Bundle received and validated
2. **Analyzing** - Security analysis (Trivy, Semgrep)
3. **Scored** - Scoring (0-100) calculated
4. **Certified** - Cert level (0-3) assigned
5. **Published** - Available in registry

You can monitor progress in the hub dashboard.

## Best Practices

### Version Strategy

- Use semantic versioning: `major.minor.patch`
- Tag releases in Git with `v` prefix: `v1.0.0`
- Use pre-release tags for testing: `1.0.0-beta.1`

### Source Organization

- Keep source clean and minimal
- Use `.mcpignore` to exclude unnecessary files
- Include only runtime dependencies

### Security

- Never include secrets in source code
- Use environment variables for configuration
- Review permissions in generated manifest

### Testing

- Test locally before pushing: `smcp run ./path/to/source`
- Use dry run to validate: `smcp push --dry-run`
- Verify manifest is correct

## Troubleshooting

### Bundle Validation Errors

If the bundle fails validation, check:

- File permissions are readable
- No symlinks outside the source directory
- Total uncompressed size < 1GB

### Manifest Generation Issues

If manifest generation fails, ensure:

- Runtime is auto-detectable (package.json, go.mod, etc.)
- Entrypoint files exist
- Project structure is valid

### Upload Timeouts

If uploads timeout:

- Check network connectivity
- Verify hub URL is correct
- Try with smaller bundle (use `.mcpignore`)

## Related Commands

- `smcp run` - Execute an MCP locally
- `smcp pull` - Download an MCP from registry
- `smcp info` - View MCP information
- `smcp login` - Authenticate with hub (future)

## See Also

- [MCP Protocol Documentation](../docs/PROTOCOL.md)
- [Manifest Schema](../docs/MANIFEST.md)
- [Security Guidelines](../docs/SECURITY.md)
