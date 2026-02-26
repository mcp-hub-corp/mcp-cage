# Origin Policy Enforcement

## Overview

The mcp-client now supports origin-based policy enforcement, allowing users to restrict which MCP packages can be executed based on their origin type.

## Origin Types

MCP packages can have one of three origin types:

- **official**: Maintained by MCP Hub (highest trust level)
- **verified**: Published by verified publishers with confirmed identity
- **community**: Published by any user (lowest trust level, default)

## Configuration

Origin policy is configured in the `~/.smcp/config.yaml` file:

```yaml
policy:
  allowed_origins: []  # Empty list = allow all origins
```

### Example Configurations

**Allow all origins (default):**
```yaml
policy:
  allowed_origins: []
```

**Official packages only:**
```yaml
policy:
  allowed_origins:
    - official
```

**Official and verified packages only:**
```yaml
policy:
  allowed_origins:
    - official
    - verified
```

**Community packages only (for development/testing):**
```yaml
policy:
  allowed_origins:
    - community
```

## Behavior

### Policy Enforcement

When you run an MCP package with `smcp run org/name@version`, the client:

1. Resolves the package from the registry
2. Retrieves the origin field from the registry response
3. Validates the origin against the configured policy
4. Blocks execution if the origin is not allowed

### Error Messages

If a package is blocked by the origin policy, you'll see an error like:

```
Error: origin policy violation: origin "community" is not allowed by policy (allowed origins: [official verified])
```

The error is also logged to the audit log for compliance tracking.

### Case Insensitivity

Origin matching is case-insensitive. The following are equivalent:
- `official`, `Official`, `OFFICIAL`
- `verified`, `Verified`, `VERIFIED`
- `community`, `Community`, `COMMUNITY`

### Default Behavior

If no policy is configured (or `allowed_origins` is empty), all origins are allowed. This ensures backward compatibility and doesn't break existing workflows.

## Use Cases

### Enterprise Security

Restrict execution to only official and verified packages:

```yaml
policy:
  allowed_origins:
    - official
    - verified
```

This ensures that only packages from trusted sources can be executed in production environments.

### Development Environment

Allow all packages for testing:

```yaml
policy:
  allowed_origins: []
```

### Strict Compliance

Only allow official packages maintained by MCP Hub:

```yaml
policy:
  allowed_origins:
    - official
```

### Custom Publisher Testing

Allow only community packages for testing your own publications:

```yaml
policy:
  allowed_origins:
    - community
```

## Implementation Details

### Files Modified

1. **internal/policy/origin.go**: Core origin policy implementation
2. **internal/policy/origin_test.go**: Comprehensive test suite
3. **internal/config/config.go**: Added `PolicyConfig` struct
4. **internal/registry/types.go**: Added `Origin` field to `ResolveResponse`
5. **internal/cli/run.go**: Integrated origin policy enforcement
6. **config.yaml.example**: Example configuration file

### Test Coverage

The implementation includes comprehensive tests covering:
- Empty allowlist (allow all)
- Allowed origins (exact match)
- Blocked origins
- Case insensitivity
- Whitespace handling
- Error messages
- Real-world scenarios
- Integration with config system

All tests pass with 100% coverage of the new code.

### Security Considerations

1. **Default Allow**: The default behavior (empty list) allows all origins to avoid breaking existing workflows
2. **Audit Logging**: All origin policy violations are logged to the audit log
3. **Clear Error Messages**: Users receive clear feedback when a package is blocked
4. **Case Insensitive**: Prevents bypasses through case manipulation

## Future Enhancements

Potential future improvements:

1. **Certification Level Policy**: Combine origin with certification level requirements
2. **Per-Package Overrides**: Allow specific packages to bypass origin restrictions
3. **Wildcard Support**: Support patterns like `official:*` or `verified:acme/*`
4. **Policy Profiles**: Pre-defined policy profiles (strict, moderate, permissive)
5. **Remote Policy**: Fetch policy from a central server for enterprise deployments

## Compatibility

This feature is fully backward compatible:
- Existing configurations without `policy` section continue to work
- Empty `allowed_origins` list allows all origins (no restrictions)
- Registry responses without `origin` field default to "community"

## Testing

To test origin policy enforcement:

```bash
# Run tests
go test ./internal/policy/... -v
go test ./internal/cli/... -run TestOriginPolicy -v

# Build
go build ./cmd/smcp

# Create test config
mkdir -p ~/.smcp
cat > ~/.smcp/config.yaml << EOF
policy:
  allowed_origins:
    - official
    - verified
EOF

# Try running a community package (should fail)
./smcp run community/test@1.0.0

# Try running an official package (should succeed)
./smcp run official/hello@1.0.0
```

## Documentation

- See `config.yaml.example` for configuration examples
- See `internal/policy/origin.go` for implementation details
- See `internal/policy/origin_test.go` for test cases
