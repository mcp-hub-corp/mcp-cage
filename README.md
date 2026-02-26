<p align="center">
  <h1 align="center">smcp</h1>
  <p align="center">
    <strong>Run MCP servers without blindly trusting them.</strong>
  </p>
  <p align="center">
    <a href="https://github.com/mcp-hub-corp/mcp-client/actions"><img src="https://github.com/mcp-hub-corp/mcp-client/workflows/CI/badge.svg" alt="CI"></a>
    <a href="https://goreportcard.com/report/github.com/mcp-hub-corp/mcp-client"><img src="https://goreportcard.com/badge/github.com/mcp-hub-corp/mcp-client" alt="Go Report Card"></a>
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
    <a href="go.mod"><img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white" alt="Go Version"></a>
    <a href="https://github.com/mcp-hub-corp/mcp-client/releases"><img src="https://img.shields.io/github/v/release/mcp-hub-corp/mcp-client?color=orange" alt="Release"></a>
    <a href="https://mcp-hub.info"><img src="https://img.shields.io/badge/ecosystem-MCP%20Hub%20Platform-blueviolet" alt="MCP Hub Platform"></a>
  </p>
</p>

---

## The problem

Every time you run an MCP server, you're executing arbitrary code with your full system permissions:

```bash
uvx some-mcp-server       # What does this code actually do?
npx @someone/mcp-tool     # Can it read your SSH keys? Yes.
```

No verification. No limits. No sandboxing. No audit trail. For production environments connected to internal databases and APIs, this is an unacceptable risk.

## What `smcp` does

`smcp` is a drop-in replacement for `uvx`/`npx` that adds the security layer they don't have:

1. **Verifies** every package against its SHA-256 digest before execution
2. **Sandboxes** processes with CPU, memory, network, and filesystem limits
3. **Enforces** certification policies (only run code that passed security analysis)
4. **Audits** every execution with structured logs and automatic secret redaction

Packages are analyzed upstream by [MCP Hub Platform](https://mcp-hub.info) for **14 classes of security vulnerabilities** and assigned a certification level (0-3) before they ever reach your machine.

## `uvx`/`npx` vs `smcp`

| | `uvx` / `npx` | `smcp` |
|---|---|---|
| Integrity verification | None | SHA-256 on every artifact |
| Security analysis | None | 14 vulnerability classes, cert levels 0-3 |
| Sandboxing | None (full system access) | CPU, memory, PID, FD limits |
| Network | Unrestricted | Default-deny (Linux) |
| Filesystem | Full access | Confined to workdir (Linux) |
| Secret handling | Visible in env/logs | Automatically redacted |
| Audit trail | None | Structured JSON logs |

---

## Install

### Ubuntu / Debian (apt)

```bash
sudo add-apt-repository ppa:mcphub/smcp
sudo apt update
sudo apt install smcp
```

Supports Ubuntu Noble (24.04 LTS) and Jammy (22.04 LTS).

### Homebrew (macOS)

```bash
brew install mcp-hub-corp/tap/smcp
```

### Binary

Download from [Releases](https://github.com/mcp-hub-corp/mcp-client/releases/latest):

```bash
# macOS (Apple Silicon)
curl -sSL -o smcp https://github.com/mcp-hub-corp/mcp-client/releases/latest/download/smcp_*_darwin_arm64.tar.gz
tar xzf smcp_*_darwin_arm64.tar.gz && sudo mv smcp /usr/local/bin/

# macOS (Intel)
curl -sSL -o smcp https://github.com/mcp-hub-corp/mcp-client/releases/latest/download/smcp_*_darwin_amd64.tar.gz
tar xzf smcp_*_darwin_amd64.tar.gz && sudo mv smcp /usr/local/bin/

# Linux (amd64)
curl -sSL -o smcp https://github.com/mcp-hub-corp/mcp-client/releases/latest/download/smcp_*_linux_amd64.tar.gz
tar xzf smcp_*_linux_amd64.tar.gz && sudo mv smcp /usr/local/bin/

# Linux (arm64)
curl -sSL -o smcp https://github.com/mcp-hub-corp/mcp-client/releases/latest/download/smcp_*_linux_arm64.tar.gz
tar xzf smcp_*_linux_arm64.tar.gz && sudo mv smcp /usr/local/bin/
```

### From source

```bash
go install github.com/mcp-hub-corp/mcp-client/cmd/smcp@latest
```

### Verify

```bash
smcp --version
smcp doctor     # shows which security features your system supports
```

---

## Usage

```bash
# Run a certified MCP server
smcp run acme/hello-world@1.2.3

# Run latest version
smcp run acme/tool@latest

# Run by exact digest (immutable)
smcp run acme/tool@sha256:a1b2c3...

# Pre-download for CI/CD
smcp pull acme/tool@1.2.3

# Inspect before running
smcp info acme/tool@1.2.3

# Manage cache
smcp cache ls
smcp cache rm --all
```

### Authentication

```bash
smcp login --token YOUR_TOKEN
# or
export MCP_REGISTRY_TOKEN=YOUR_TOKEN
```

---

## Configuration

Create `~/.smcp/config.yaml`:

```yaml
registry_url: "https://registry.mcp-hub.info"
timeout: 5m
max_memory: "512M"
max_cpu: 1000              # millicores (1000 = 1 core)
log_level: "info"

audit_enabled: true
audit_log_file: "~/.smcp/audit.log"

policy:
  min_cert_level: 1        # reject uncertified packages (0-3)
  cert_level_mode: strict  # strict | warn | disabled
  allowed_origins:         # empty = allow all
    - official
    - verified
```

CLI flags override config. Environment variables use `MCP_` prefix (`MCP_REGISTRY_URL`, `MCP_CACHE_DIR`, etc.).

---

## Platform support

| | Linux | macOS | Windows |
|---|:---:|:---:|:---:|
| Resource limits | cgroups v2 | rlimits | Job Objects |
| Network isolation | namespaces | -- | -- |
| Filesystem isolation | Landlock | -- | -- |
| Audit logging | full | full | full |
| **Production ready** | **Yes** | No | No |

> For production with untrusted MCP servers, use Linux or Docker. Run `smcp doctor` to check your system.

---

## Documentation

| | |
|---|---|
| [Architecture](./docs/OVERVIEW.md) | How the pieces fit together |
| [Security model](./docs/SECURITY.md) | Threat model and invariants |
| [Examples](./docs/EXAMPLES.md) | Usage patterns and CI/CD integration |
| [Linux sandbox](./docs/LINUX_SANDBOX.md) | cgroups, namespaces, Landlock, seccomp |
| [Config reference](./docs/config.example.yaml) | All available options |
| [Contributing](./CONTRIBUTING.md) | Development guidelines |

---

## License

MIT -- see [`LICENSE`](./LICENSE).

---

<p align="center">
  Part of <a href="https://mcp-hub.info">MCP Hub Platform</a> -- trust infrastructure for MCP servers.
</p>
