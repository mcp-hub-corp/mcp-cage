# Security Policy Enforcement Skill

Expert knowledge for implementing and enforcing security policies in the mcp-client launcher.

## Overview

Security policy enforcement is the layer between the manifest requirements and the actual sandbox enforcement. It:
1. Merges policies from multiple sources (config, manifest, CLI flags)
2. Applies the strictest constraint when conflicts exist
3. Validates all policies before passing to sandbox
4. Ensures mandatory defaults are applied
5. Prevents security bypasses through policy conflicts

## Policy Types

### 1. Package Allowlists
Controls which packages can be executed.

**Definition:**
```go
type PackageAllowlist struct {
    Enabled bool     // Enable allowlist enforcement
    Packages []string // Format: "org/name" or "org/name@version"
    Mode    string   // "allow" or "deny" (allow = positive list, deny = blocklist)
}
```

**Examples:**
```yaml
# Config-level package allowlist
security:
  packages:
    mode: allow  # only these packages allowed
    list:
      - acme/hello-world
      - acme/tool
      - org/*  # wildcards allowed

# OR deny mode
security:
  packages:
    mode: deny  # block only these
    list:
      - malicious/bad-package
      - evil/*
```

**Validation Rules:**
- If allowlist is empty in "allow" mode, NO packages are allowed (fail-safe)
- Wildcards (*, ?) match against org/name segments
- Version matching: @1.2.3, @1.*, @latest
- Package matching is case-sensitive
- Empty blocklist in "deny" mode allows all (except denied)

### 2. Resource Limits

Control CPU, memory, process count, file descriptors, and execution time.

**Definition:**
```go
type ResourceLimits struct {
    CPU       int           // millicores (1000 = 1 core)
    Memory    uint64        // bytes
    PIDs      int           // max process count
    FDs       int           // max file descriptors
    Timeout   time.Duration // execution timeout
}
```

**Default Mandatory Values (Emergency Fallbacks):**
```
CPU:     1000 millicores (1.0 core)
Memory:  512 MiB
PIDs:    32
FDs:     256
Timeout: 5 minutes
```

**Limit Merging Strategy:**
- Take the minimum (strictest) value from all sources
- Sources in priority order: CLI flag > manifest > config > defaults
- Example:
  ```
  Config: CPU=2000mc, Manifest: CPU=1000mc, CLI: CPU=500mc
  Result: 500mc (strictest)
  ```

**Validation Rules:**
```
CPU:     1-8000 millicores (0.001-8 cores)
Memory:  10MiB-32GiB
PIDs:    1-10000
FDs:     10-65536
Timeout: 1s-1h
```

**Invalid Values Handling:**
- If value is below minimum: use minimum
- If value is above maximum: use maximum
- If value is invalid (negative, zero): use default
- Log warning when fallback is triggered

### 3. Network Allowlist

Controls outbound network access via domain/IP allowlist.

**Definition:**
```go
type NetworkPolicy struct {
    DefaultDeny bool      // Default deny all network (except 127.0.0.1)
    Allowlist   []string  // Allowed domains/IPs/CIDR
}
```

**Allowlist Format:**
```
IPv4:              192.168.1.1
IPv4 CIDR:         10.0.0.0/8
IPv6:              2001:db8::1
IPv6 CIDR:         2001:db8::/32
Hostname:          example.com
Wildcard domain:   *.example.com (matches a.example.com, b.example.com, etc)
Wildcard domain:   example.* (matches example.com, example.org, etc)
Localhost:         127.0.0.1, localhost, [::1]
```

**Matching Rules:**
- Domain matching is case-insensitive
- Wildcard (*) matches zero or more characters in a single label
- CIDR ranges match exact network (10.0.0.0/8 includes 10.0.0.1-10.255.255.255)
- Localhost (127.0.0.1, ::1) always allowed (required for STDIO communication)
- DNS resolution: allowlist is checked AFTER resolution

**Policy Merging:**
- Manifest cannot make network policy MORE permissive than config
- If manifest declares allowlist, it must be subset of config allowlist
- If manifest has no allowlist, use config allowlist
- Invalid entries in manifest are rejected (fail-safe)

**Default Behavior:**
- Linux: default-deny if not explicitly allowed (via seccomp/netns)
- macOS: NO enforcement (capability limitation, must be documented)
- Windows: NO enforcement (capability limitation, must be documented)

**Validation:**
```
- Reject invalid CIDR notation
- Reject invalid domain names (invalid characters)
- Reject entries with spaces
- Reject duplicate entries (deduplicate)
- Warn if allowlist is very permissive (e.g., *.com)
```

### 4. Environment Variable Filtering

Controls which environment variables are passed to the process.

**Definition:**
```go
type EnvPolicy struct {
    Mode      string   // "allowlist" or "blocklist"
    Variables []string // Variable names (case-sensitive on Unix, case-insensitive on Windows)
    BlockVars []string // Only for blocklist mode
}
```

**Examples:**
```yaml
# Allowlist mode: only pass these vars
security:
  env:
    mode: allowlist
    allow:
      - PATH
      - HOME
      - USER
      - MCP_*  # Wildcard: all vars starting with MCP_

# Blocklist mode: block specific vars
security:
  env:
    mode: blocklist
    block:
      - AWS_SECRET_ACCESS_KEY
      - PRIVATE_*
```

**Implementation Strategy:**
1. If mode is "allowlist":
   - Start with EMPTY environment
   - Add only specified variables from parent process
   - Wildcards (*, ?, [abc]) supported
   - Variables not in parent are skipped (no error)

2. If mode is "blocklist":
   - Start with FULL parent environment
   - Remove specified variables
   - Wildcards supported
   - Removed variables are logged (names only, never values)

**Mandatory Variables (always passed unless explicitly blocklisted):**
```
Unix:     PATH, HOME, LANG, LC_*, TERM
Windows:  PATH, USERPROFILE, COMPUTERNAME, SystemRoot
All:      MCP_* (any var starting with MCP_)
```

**Validation Rules:**
- Variable names: [A-Za-z_][A-Za-z0-9_]*
- Reject invalid variable names
- No variable values should appear in logs
- Wildcard patterns must be valid glob syntax

**Policy Merging:**
- Allowlist in manifest cannot ADD variables (must be subset of config)
- Blocklist in manifest can EXPAND blocked vars (add more restrictions)
- If manifest declares env allowlist, config allowlist must be superset

### 5. Subprocess Control

Controls whether the process can spawn child processes.

**Definition:**
```go
type SubprocessPolicy struct {
    AllowSubprocess bool // Default: false (deny)
}
```

**Behavior:**
```
AllowSubprocess = false:
  - Process cannot use fork(), exec(), etc.
  - Enforced via seccomp on Linux
  - Monitored/limited on macOS
  - Job Objects on Windows

AllowSubprocess = true:
  - Process can spawn subprocesses
  - Subprocesses inherit resource limits
  - Subprocess count included in PIDs limit
```

**Validation Rules:**
- Default is ALWAYS deny (fail-safe)
- Manifest can only set to true if config allows it
- If manifest has AllowSubprocess=true but config has false, reject

**Testing Subprocess Control:**
```go
// Should fail if subprocess denied
cmd := exec.Command("bash", "-c", "sleep 10 &")
err := sandbox.Apply(cmd, policy)
// err != nil (subprocess denied)

// Should succeed if subprocess allowed
policy.SubprocessPolicy.AllowSubprocess = true
err = sandbox.Apply(cmd, policy)
// err == nil
```

## Policy Application Layers

### Layer 1: Configuration Loading
```go
// Load policy from ~/.smcp/config.yaml
configPolicy, err := loadConfigPolicy()

// Validate no critical errors
if configPolicy.NetworkPolicy.DefaultDeny && len(configPolicy.NetworkPolicy.Allowlist) == 0 {
    // Warn: default-deny with empty allowlist means zero network access
    // (acceptable, but may be unintended)
}
```

### Layer 2: Manifest Validation
```go
// Manifest declares additional policy constraints
manifestPolicy, err := parseManifestPolicy()

// Validate manifest policy is compatible with config
if err := mergeAndValidate(configPolicy, manifestPolicy); err != nil {
    return fmt.Errorf("manifest policy conflict: %w", err)
}

mergedPolicy = merge(configPolicy, manifestPolicy) // strictest wins
```

### Layer 3: CLI Flag Overrides
```go
// CLI flags can be more restrictive
cliPolicy := parseCliFlags()

// Merge with strictest-wins strategy
finalPolicy = merge(mergedPolicy, cliPolicy)

// Validate final policy
if err := finalPolicy.Validate(); err != nil {
    return fmt.Errorf("final policy validation failed: %w", err)
}
```

### Layer 4: Executor Application
```go
// Pass final policy to executor
executor.Run(manifest, finalPolicy, sandbox)

// Executor applies policy to sandbox
sandbox.Apply(policy)
```

## Mandatory Defaults (Emergency Fallbacks)

When policy values are invalid, missing, or unspecified, these defaults are ALWAYS applied:

```go
const (
    DefaultCPUMillicores = 1000      // 1 core
    DefaultMemoryBytes   = 512 * 1024 * 1024 // 512 MiB
    DefaultMaxPIDs       = 32
    DefaultMaxFDs        = 256
    DefaultTimeout       = 5 * time.Minute
)
```

**Application:**
1. Config specifies no limits → use defaults
2. Manifest specifies invalid values → use defaults
3. During policy merge, result is below minimum → use minimum
4. CLI flag specifies impossible value → use default and warn

**Validation Code:**
```go
func (p *ResourceLimits) ApplyDefaults() {
    if p.CPU <= 0 || p.CPU > 8000 {
        p.CPU = DefaultCPUMillicores
    }
    if p.Memory < 10*1024*1024 || p.Memory > 32*1024*1024*1024 {
        p.Memory = DefaultMemoryBytes
    }
    if p.PIDs < 1 || p.PIDs > 10000 {
        p.PIDs = DefaultMaxPIDs
    }
    if p.FDs < 10 || p.FDs > 65536 {
        p.FDs = DefaultMaxFDs
    }
    if p.Timeout < 1*time.Second || p.Timeout > 1*time.Hour {
        p.Timeout = DefaultTimeout
    }
}
```

## Limit Merging Algorithm

This is the core logic for combining policies from multiple sources:

```go
// MergeResourceLimits applies strictest-wins strategy
func MergeResourceLimits(sources ...ResourceLimits) ResourceLimits {
    result := ResourceLimits{
        CPU:     math.MaxInt32,
        Memory:  math.MaxUint64,
        PIDs:    math.MaxInt32,
        FDs:     math.MaxInt32,
        Timeout: 1 * time.Hour, // max reasonable timeout
    }

    for _, src := range sources {
        // Take minimum value (strictest)
        if src.CPU > 0 && src.CPU < result.CPU {
            result.CPU = src.CPU
        }
        if src.Memory > 0 && src.Memory < result.Memory {
            result.Memory = src.Memory
        }
        if src.PIDs > 0 && src.PIDs < result.PIDs {
            result.PIDs = src.PIDs
        }
        if src.FDs > 0 && src.FDs < result.FDs {
            result.FDs = src.FDs
        }
        if src.Timeout > 0 && src.Timeout < result.Timeout {
            result.Timeout = src.Timeout
        }
    }

    // Apply emergency fallbacks
    result.ApplyDefaults()
    return result
}

// Example usage
configLimits := ResourceLimits{CPU: 2000, Memory: 1024*1024*1024, PIDs: 64, ...}
manifestLimits := ResourceLimits{CPU: 1000, Memory: 512*1024*1024, PIDs: 32, ...}
cliFLimits := ResourceLimits{CPU: 500, ...}

finalLimits := MergeResourceLimits(configLimits, manifestLimits, cliFlags)
// Result: CPU=500mc (strictest), Memory=512MiB, PIDs=32
```

## Network Allowlist Matching Algorithm

```go
// IsNetworkAllowed checks if a domain/IP is in the allowlist
func (p *NetworkPolicy) IsNetworkAllowed(target string) (bool, error) {
    if !p.DefaultDeny {
        return true, nil // No restrictions
    }

    // Localhost always allowed
    if isLocalhost(target) {
        return true, nil
    }

    for _, allowedEntry := range p.Allowlist {
        if matchNetworkEntry(target, allowedEntry) {
            return true, nil
        }
    }

    return false, nil
}

// matchNetworkEntry handles IP, CIDR, and domain matching
func matchNetworkEntry(target, entry string) bool {
    // Try CIDR match first
    if cidrNet, err := net.ParseCIDR(entry); err == nil {
        if ip := net.ParseIP(target); ip != nil {
            return cidrNet.Contains(ip)
        }
    }

    // Try exact IP match
    if net.ParseIP(entry) != nil && entry == target {
        return true
    }

    // Try domain match (case-insensitive, wildcard support)
    return matchDomain(strings.ToLower(target), strings.ToLower(entry))
}

func matchDomain(target, pattern string) bool {
    // Use filepath.Match for wildcard support (*, ?)
    matched, _ := filepath.Match(pattern, target)
    return matched
}
```

## Environment Variable Construction

```go
// ConstructEnvironment builds the environment for the process
func ConstructEnvironment(parentEnv []string, policy EnvPolicy) []string {
    envMap := make(map[string]string)

    if policy.Mode == "allowlist" {
        // Start empty, add only allowed vars
        for _, envStr := range parentEnv {
            parts := strings.SplitN(envStr, "=", 2)
            if len(parts) != 2 {
                continue
            }
            varName := parts[0]

            // Check if var matches allowlist
            if matchesAllowlist(varName, policy.Variables) {
                envMap[varName] = parts[1]
            }
        }

        // Add mandatory vars that aren't already present
        for _, mandatoryVar := range getMandatoryVars() {
            if _, exists := envMap[mandatoryVar]; !exists {
                if val, found := getenv(parentEnv, mandatoryVar); found {
                    envMap[mandatoryVar] = val
                }
            }
        }
    } else {
        // Start full, remove blocked vars
        for _, envStr := range parentEnv {
            parts := strings.SplitN(envStr, "=", 2)
            if len(parts) != 2 {
                continue
            }
            varName := parts[0]

            // Skip if blocked
            if matchesBlocklist(varName, policy.BlockVars) {
                continue
            }

            envMap[varName] = parts[1]
        }
    }

    // Convert map to []string format
    result := make([]string, 0, len(envMap))
    for name, value := range envMap {
        result = append(result, fmt.Sprintf("%s=%s", name, value))
    }
    sort.Strings(result)
    return result
}

func matchesAllowlist(varName string, allowlist []string) bool {
    for _, pattern := range allowlist {
        matched, _ := filepath.Match(pattern, varName)
        if matched {
            return true
        }
    }
    return false
}
```

## Critical Errors and Abort Conditions

These conditions MUST cause execution to abort immediately:

### 1. Package Not Allowed
```go
if !policy.PackageAllowlist.IsAllowed(pkg) {
    return fmt.Errorf("package %s is not in allowlist", pkg)
}
```

### 2. Policy Conflicts
```
- Manifest attempts to make network MORE permissive than config
- Manifest attempts to enable subprocess when config forbids it
- Manifest declares invalid policy that cannot be reconciled
```

### 3. Invalid Final Policy
```go
if err := finalPolicy.Validate(); err != nil {
    return fmt.Errorf("final policy validation failed (security invariant broken): %w", err)
}
```

### 4. Resource Limits Below Minimum
```
If after all merging and defaults, any of these conditions exist:
- CPU < 1 millicore
- Memory < 10 MiB
- PIDs < 1
- FDs < 10
- Timeout < 1 second
→ ABORT with critical error
```

### 5. Zero Network Access
```go
// Warning (not abort), but user must acknowledge
if policy.NetworkPolicy.DefaultDeny && len(policy.NetworkPolicy.Allowlist) == 0 {
    log.Warn("Process will have ZERO network access (including DNS)")
    // User must confirm they understand this
}
```

## Testing Security Policies

### Unit Test Categories

**1. Limit Merging Tests:**
```go
func TestMergeResourceLimits_TakesMinimum(t *testing.T) {
    limits1 := ResourceLimits{CPU: 2000, Memory: 1024*1024*1024}
    limits2 := ResourceLimits{CPU: 1000, Memory: 512*1024*1024}

    result := MergeResourceLimits(limits1, limits2)

    assert.Equal(t, 1000, result.CPU)
    assert.Equal(t, 512*1024*1024, result.Memory)
}

func TestMergeResourceLimits_AppliesDefaults(t *testing.T) {
    limits := ResourceLimits{CPU: -1, Memory: 0} // Invalid
    limits.ApplyDefaults()

    assert.Equal(t, DefaultCPUMillicores, limits.CPU)
    assert.Equal(t, DefaultMemoryBytes, limits.Memory)
}
```

**2. Package Allowlist Tests:**
```go
func TestPackageAllowlist_Wildcard(t *testing.T) {
    allowlist := PackageAllowlist{
        Mode: "allow",
        Packages: []string{"acme/*"},
    }

    assert.True(t, allowlist.IsAllowed("acme/tool"))
    assert.True(t, allowlist.IsAllowed("acme/hello-world"))
    assert.False(t, allowlist.IsAllowed("other/tool"))
}

func TestPackageAllowlist_EmptyAllowlistDeniesAll(t *testing.T) {
    allowlist := PackageAllowlist{
        Mode: "allow",
        Packages: []string{}, // Empty!
    }

    assert.False(t, allowlist.IsAllowed("acme/tool"))
}
```

**3. Network Allowlist Tests:**
```go
func TestNetworkAllowlist_CIDRMatching(t *testing.T) {
    policy := NetworkPolicy{
        DefaultDeny: true,
        Allowlist: []string{"10.0.0.0/8"},
    }

    allowed, _ := policy.IsNetworkAllowed("10.0.0.1")
    assert.True(t, allowed)

    allowed, _ = policy.IsNetworkAllowed("11.0.0.1")
    assert.False(t, allowed)
}

func TestNetworkAllowlist_WildcardDomain(t *testing.T) {
    policy := NetworkPolicy{
        DefaultDeny: true,
        Allowlist: []string{"*.example.com"},
    }

    allowed, _ := policy.IsNetworkAllowed("api.example.com")
    assert.True(t, allowed)

    allowed, _ = policy.IsNetworkAllowed("example.com")
    assert.False(t, allowed) // Doesn't match *.
}

func TestNetworkAllowlist_LocalhostAlwaysAllowed(t *testing.T) {
    policy := NetworkPolicy{
        DefaultDeny: true,
        Allowlist: []string{}, // Empty!
    }

    // Localhost must always be allowed for STDIO
    allowed, _ := policy.IsNetworkAllowed("127.0.0.1")
    assert.True(t, allowed)

    allowed, _ = policy.IsNetworkAllowed("localhost")
    assert.True(t, allowed)
}
```

**4. Environment Filtering Tests:**
```go
func TestEnvPolicy_AllowlistMode(t *testing.T) {
    parentEnv := []string{
        "PATH=/usr/bin",
        "HOME=/home/user",
        "SECRET_API_KEY=abc123",
    }

    policy := EnvPolicy{
        Mode: "allowlist",
        Variables: []string{"PATH", "HOME"},
    }

    result := ConstructEnvironment(parentEnv, policy)

    assert.Contains(t, result, "PATH=/usr/bin")
    assert.Contains(t, result, "HOME=/home/user")
    assert.NotContains(t, result, "SECRET_API_KEY=abc123")
}

func TestEnvPolicy_MandatoryVarsAlwaysIncluded(t *testing.T) {
    parentEnv := []string{"PATH=/usr/bin"}

    policy := EnvPolicy{
        Mode: "allowlist",
        Variables: []string{}, // Empty allowlist
    }

    result := ConstructEnvironment(parentEnv, policy)

    // Mandatory vars like PATH should still be included
    assert.Contains(t, result, "PATH=/usr/bin")
}

func TestEnvPolicy_WildcardMatching(t *testing.T) {
    parentEnv := []string{
        "MCP_DEBUG=1",
        "MCP_LOG_LEVEL=info",
        "OTHER_VAR=value",
    }

    policy := EnvPolicy{
        Mode: "allowlist",
        Variables: []string{"MCP_*"},
    }

    result := ConstructEnvironment(parentEnv, policy)

    assert.Contains(t, result, "MCP_DEBUG=1")
    assert.Contains(t, result, "MCP_LOG_LEVEL=info")
    assert.NotContains(t, result, "OTHER_VAR=value")
}
```

**5. Policy Conflict Tests:**
```go
func TestMergePolicy_ManifestCannotMakeMorePermissive(t *testing.T) {
    configPolicy := NetworkPolicy{
        DefaultDeny: true,
        Allowlist: []string{"example.com"},
    }

    manifestPolicy := NetworkPolicy{
        DefaultDeny: false, // More permissive!
        Allowlist: []string{"*"},
    }

    err := ValidateMergedPolicy(configPolicy, manifestPolicy)
    assert.Error(t, err) // Should reject
}

func TestMergePolicy_SubprocessDenyCannotBeOverridden(t *testing.T) {
    configPolicy := SubprocessPolicy{AllowSubprocess: false}
    manifestPolicy := SubprocessPolicy{AllowSubprocess: true}

    err := ValidateMergedPolicy(configPolicy, manifestPolicy)
    assert.Error(t, err) // Should reject
}
```

### Integration Test Categories

**1. Full Policy Application:**
```go
func TestFullPolicyApplication(t *testing.T) {
    // Load config with policy
    config := loadTestConfig()

    // Create manifest with additional policy
    manifest := loadTestManifest()

    // Apply CLI overrides
    cliPolicy := parseTestCliFlags()

    // Merge all policies
    finalPolicy, err := ApplyPolicies(config.Policy, manifest.Security, cliPolicy)
    assert.NoError(t, err)

    // Validate final policy
    assert.NoError(t, finalPolicy.Validate())
}
```

**2. Restrictive Policy Application:**
```go
func TestRestrictivePolicy_ProcessCannot(t *testing.T) {
    policy := &FinalPolicy{
        ResourceLimits: ResourceLimits{
            CPU: 100, // Very limited
            Memory: 50*1024*1024, // 50 MiB
            PIDs: 1,
            FDs: 20,
            Timeout: 1*time.Second,
        },
        SubprocessPolicy: SubprocessPolicy{AllowSubprocess: false},
        NetworkPolicy: NetworkPolicy{DefaultDeny: true, Allowlist: []string{}},
        EnvPolicy: EnvPolicy{Mode: "allowlist", Variables: []string{}},
    }

    // Process should be heavily restricted
    // Verify via sandbox application
}
```

## Common Mistakes and Anti-Patterns

### Mistake 1: Permissive Defaults
**WRONG:**
```go
policy := &ResourceLimits{} // All zero!
// Incorrectly assumes exec.Cmd has built-in limits
```

**CORRECT:**
```go
policy := GetDefaultResourceLimits()
policy.ApplyDefaults() // Ensure mandatory minimums
```

### Mistake 2: Not Validating Manifest Policy
**WRONG:**
```go
// Just use manifest policy directly
finalPolicy := manifestPolicy
// Manifest might have removed security constraints!
```

**CORRECT:**
```go
finalPolicy := merge(configPolicy, manifestPolicy)
if err := ValidateMergedPolicy(configPolicy, manifestPolicy); err != nil {
    return err // Reject if manifest tries to escalate privileges
}
```

### Mistake 3: Logging Secret Values
**WRONG:**
```go
log.Infof("Setting env var %s=%s", name, value) // NEVER log values!
```

**CORRECT:**
```go
log.Infof("Setting env var %s (value redacted)", name)
```

### Mistake 4: Empty Allowlist in "Allow" Mode
**WRONG:**
```go
policy := PackageAllowlist{
    Mode: "allow",
    Packages: []string{}, // Empty!
}
// All packages are implicitly allowed!
```

**CORRECT:**
```go
// Check before allowing execution
if len(policy.Packages) == 0 && policy.Mode == "allow" {
    return fmt.Errorf("allowlist mode with zero packages: nothing is allowed")
}
```

### Mistake 5: Not Merging Network Policies
**WRONG:**
```go
// Only use manifest network policy
networkPolicy := manifest.Security.NetworkPolicy
// Ignores config-level restrictions
```

**CORRECT:**
```go
// Merge with config policy (strictest wins)
networkPolicy := mergeNetworkPolicies(config.NetworkPolicy, manifest.Security.NetworkPolicy)
```

### Mistake 6: Missing Mandatory Environment Variables
**WRONG:**
```go
env := []string{} // Start completely empty
for _, allowed := range policy.AllowedVars {
    env = append(env, os.Getenv(allowed))
}
// PATH, LANG, etc. are missing!
```

**CORRECT:**
```go
env := ConstructEnvironment(os.Environ(), policy)
// Ensures mandatory vars are included even in strict allowlist mode
```

### Mistake 7: Not Checking for Policy Conflicts
**WRONG:**
```go
// Blindly apply manifest policy
sandbox.Apply(manifest.Security)
// Manifest might be trying to disable security!
```

**CORRECT:**
```go
if err := ValidateMergedPolicy(config.Policy, manifest.Security); err != nil {
    return fmt.Errorf("security policy conflict: %w", err)
}
```

### Mistake 8: Resource Limit Below Emergency Minimum
**WRONG:**
```go
policy.CPU = 1 // 1 millicore
// Violates minimum of 1 core (1000mc)
```

**CORRECT:**
```go
if policy.CPU < MinimumCPU {
    policy.CPU = DefaultCPU
    log.Warn("CPU limit below minimum, using default")
}
```

## Security Checklist

Before executing any process, verify:

- [ ] Policy loaded from config without errors
- [ ] Manifest policy validated against config policy
- [ ] Package is in allowlist (if allowlist mode enabled)
- [ ] Resource limits are within valid ranges
- [ ] Network policy is consistent (no escalation from config)
- [ ] Subprocess policy is consistent (no escalation from config)
- [ ] Environment variables filtered per policy
- [ ] Final policy passes Validate()
- [ ] No secret values appear in logs
- [ ] Audit logger will record execution
- [ ] Sandbox has been configured with final policy

## References

- CLAUDE.md Section 3: Threat Model
- CLAUDE.md Section 4: Security Invariants
- CLAUDE.md Section 5: Platform Strategy
