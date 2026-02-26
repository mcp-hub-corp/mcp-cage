# Certification Level Policy Enforcement

## Overview

The `cert_level_mode` policy allows MCP Client to enforce minimum certification level requirements for MCP execution. This is part of Fase 4 (Políticas Avanzadas) of the ecosystem roadmap.

## Certification Levels

The registry assigns MCPs a certification level (0-3) based on security analysis:

| Level | Name | Requirements | Access |
|-------|------|--------------|--------|
| **0** | Integrity Verified | SHA-256 digest validation, schema validation | Everyone (free) |
| **1** | Static Verified | Trivy + Semgrep basic, SBOM | PRO+ |
| **2** | Security Certified | Advanced analysis, evidences, MSSS | Enterprise |
| **3** | Runtime Certified | Dynamic analysis in sandbox | Enterprise (future) |

## Enforcement Modes

### Strict Mode
```yaml
policy:
  min_cert_level: 2
  cert_level_mode: strict
```

**Behavior:**
- Blocks execution if `cert_level < min_cert_level`
- Returns error immediately with clear message
- Suitable for production environments requiring certified MCPs

**Example Error:**
```
certification level policy violation: certification level 1 (Static Verified)
is below minimum required level 2 (Security Certified)
```

### Warn Mode
```yaml
policy:
  min_cert_level: 1
  cert_level_mode: warn
```

**Behavior:**
- Allows execution even if below minimum
- Logs warning with details about cert level mismatch
- Suitable for gradual rollout or development environments
- Helps identify MCPs needing certification before strict enforcement

**Example Warning:**
```
time=2026-01-19T12:28:41Z level=WARN msg="certification level 0 (Integrity Verified)
is below minimum required level 1 (Static Verified)"
certification_level=0 minimum_required=1 enforce_mode=warn
```

### Disabled Mode (Default)
```yaml
policy:
  min_cert_level: 2
  cert_level_mode: disabled
```

**Behavior:**
- No enforcement at all
- All MCPs allowed regardless of certification level
- Default mode for backward compatibility

## Configuration

### Global Configuration

Set in `~/.smcp/config.yaml`:

```yaml
policy:
  allowed_origins: []          # Origin enforcement (optional)
  min_cert_level: 0            # 0-3 (default: 0 = no minimum)
  cert_level_mode: disabled    # strict | warn | disabled (default: disabled)
```

### Environment Variables

Override configuration via environment variables:

```bash
# Set minimum certification level
export MCP_POLICY_MIN_CERT_LEVEL=2

# Set enforcement mode
export MCP_POLICY_CERT_LEVEL_MODE=strict

# Then run MCP
smcp run acme/tool@latest
```

### Environment-Specific Overrides (Future)

The configuration supports environment-specific settings:

```yaml
policy:
  min_cert_level: 0          # Default (development)
  cert_level_mode: disabled

  environments:
    dev:
      min_cert_level: 0
      cert_level_mode: disabled

    staging:
      min_cert_level: 1
      cert_level_mode: warn

    prod:
      min_cert_level: 2
      cert_level_mode: strict
```

Usage (future implementation):
```bash
MCP_ENV=prod smcp run acme/tool@latest
```

## Usage Examples

### Example 1: Development (No Enforcement)
```yaml
policy:
  min_cert_level: 0
  cert_level_mode: disabled
```

Allows running any MCP without restrictions. Suitable for local development.

### Example 2: Production (Strict Certification)
```yaml
policy:
  min_cert_level: 2
  cert_level_mode: strict
  allowed_origins: ["official", "verified"]
```

Only allows MCPs from official or verified publishers with Security Certified level or higher.

### Example 3: Gradual Rollout (Warn Mode)
```yaml
policy:
  min_cert_level: 1
  cert_level_mode: warn
```

Logs warnings for MCPs below level 1, but allows execution. Useful for monitoring before strict enforcement.

### Example 4: Enterprise Policy
```yaml
policy:
  min_cert_level: 3
  cert_level_mode: strict
  allowed_origins: ["official"]
```

Highest security: only official MCPs with runtime certification.

## CLI Usage

### Check Certification Level
```bash
# Run will now validate cert_level from resolve response
smcp run acme/tool@1.0.0

# If cert_level is below minimum and mode is strict:
# Error: certification level policy violation: ...
```

### Verify Policy Configuration
```bash
# Via smcp doctor (future enhancement)
smcp doctor --check-policy

# Shows current policy settings:
# Policy enforcement mode: strict
# Minimum cert level: 2 (Security Certified)
# Allowed origins: [official, verified]
```

## Audit Logging

When cert_level validation fails or warnings are issued, they are logged:

**Audit Log Example (Strict Mode - Blocked):**
```json
{
  "timestamp": "2026-01-19T12:28:41Z",
  "event": "certification_level_policy_violation",
  "package": "acme/tool",
  "version": "1.0.0",
  "certification_level": 1,
  "minimum_required": 2,
  "enforce_mode": "strict",
  "error": "certification level 1 (Static Verified) is below minimum required level 2 (Security Certified)"
}
```

**Audit Log Example (Warn Mode - Allowed with Warning):**
```json
{
  "timestamp": "2026-01-19T12:28:41Z",
  "event": "certification_level_policy_warning",
  "package": "acme/tool",
  "version": "1.0.0",
  "certification_level": 0,
  "minimum_required": 1,
  "enforce_mode": "warn",
  "warning": "certification level 0 (Integrity Verified) is below minimum required level 1 (Static Verified), but execution allowed in warn mode"
}
```

## Integration with Origin Policy

Cert level policy works alongside origin policy:

```go
// Example: Production environment
policy:
  allowed_origins: ["official", "verified"]  # Origin filtering
  min_cert_level: 2                          # Certification filtering
  cert_level_mode: strict
```

**Both checks must pass:**
1. Origin must be in `allowed_origins` (if set)
2. Cert level must be >= `min_cert_level` (if mode is not disabled)

**Order of validation** (in `run.go`):
1. Registry resolve succeeds and returns cert_level
2. Origin validation (if configured)
3. Cert level validation (if configured)
4. Manifest download and execution

## API Reference

### CertLevelPolicy Type

```go
type CertLevelPolicy struct {
    MinCertLevel int    // 0-3
    EnforceMode  string // "strict" | "warn" | "disabled"
    logger       *slog.Logger
}

// Create policy
policy := NewCertLevelPolicy(2, "strict")

// Validate
err := policy.Validate(certLevel)  // Returns error in strict mode if below minimum
if err != nil {
    // Handle violation
}

// Check if enforced
if policy.IsEnforced() {
    // Policy is active (strict or warn mode)
}

// Get values
minLevel := policy.GetMinCertLevel()
mode := policy.GetEnforceMode()
```

### Certification Level Names

```go
var CertLevelNames = map[int]string{
    0: "Integrity Verified",
    1: "Static Verified",
    2: "Security Certified",
    3: "Runtime Certified",
}
```

## Security Considerations

### Strengths
- **Clear governance**: Explicit minimum requirements for MCPs
- **Gradual rollout**: Warn mode helps identify affected MCPs before strict enforcement
- **Auditability**: All violations logged for compliance
- **Flexibility**: Works with origin policy for multi-layer enforcement

### Limitations
- **Registry trust**: Assumes registry is trusted to correctly assign cert_levels
- **No signature validation**: MCPs are not cryptographically signed (future enhancement)
- **Static analysis only**: Cert levels (0-2) based on static analysis, not runtime behavior
- **No per-package overrides**: Policy is global; no exceptions per package (yet)

## Future Enhancements

### Environment-Specific Policies
```yaml
environments:
  dev:
    min_cert_level: 0
  prod:
    min_cert_level: 2
```

Usage: `MCP_ENV=prod smcp run acme/tool@latest`

### Per-Package Exceptions
```yaml
policy:
  min_cert_level: 2
  exceptions:
    - package: "acme/legacy-tool"
      min_cert_level: 1  # Exception for this package
```

### Dry-Run Mode
```bash
smcp run --dry-run --check-policy acme/tool@latest
# Shows what would happen without actually executing
```

### Compliance Reporting
```bash
smcp policy report --format=json
# Generates JSON report of policy enforcement history
```

## Troubleshooting

### Error: "certification level policy violation"

**Cause:** Cert level is below minimum and strict mode is enabled.

**Solution:**
1. Update the MCP to a version with higher certification
2. Or decrease `min_cert_level` in config
3. Or set `cert_level_mode: warn` for gradual rollout

### Warning: "certification level X is below minimum"

**Cause:** Warn mode is enabled and cert level is below minimum.

**Action:** Optional - you can upgrade the MCP or adjust policy.

### Policy seems ignored

**Check:**
1. Is `cert_level_mode` set to `disabled`? (Default)
2. Is `min_cert_level` set to 0? (No minimum)
3. Run `smcp doctor --check-policy` to verify current policy

## References

- [Fase 4 Roadmap](../CLAUDE.md) - Políticas Avanzadas
- [Origin Policy](./ORIGIN_POLICY.md) - Complementary policy
- [Security Model](./SECURITY.md) - Overall threat model
- [Configuration Guide](./CONFIG.md) - Full config reference
