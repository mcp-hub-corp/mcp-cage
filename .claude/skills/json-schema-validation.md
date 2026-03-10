# JSON Schema Validation in Go

## Overview

This skill covers validating JSON/YAML data against schemas in Go, with focus on the mcp-cage project. Proper validation is critical for security (reject malformed manifests), user experience (clear validation errors), and reliability (ensure data integrity before use).

**mcp-cage context:** Manifests are JSON with strict schema requirements: package info, transport type, entrypoints with OS/arch, permissions, limits. Invalid manifests must be rejected with clear field-level errors.

---

## Core Principles

1. **Struct Tags:** Use `json`, `yaml` tags for marshaling/unmarshaling
2. **Required Field Validation:** Check zero values after unmarshaling
3. **Type Validation:** Ensure correct types (string, int, bool, arrays, objects)
4. **Format Validation:** Email, URL, semver, digest, enum values
5. **Range Validation:** Min/max for numbers, length for strings
6. **Unknown Fields:** Reject unexpected fields (security risk)
7. **Clear Errors:** Include field path and expected format
8. **Nested Validation:** Recursive validation for complex structures
9. **Custom Validation:** Implement Unmarshaler interface for complex rules
10. **Testing:** Valid/invalid schemas, boundary cases, error messages

---

## Struct Tags: json, yaml, mapstructure

### Basic Struct Tags

```go
// From internal/manifest/parser.go

type Manifest struct {
	// json tag: name in JSON, omitempty = exclude if empty
	SchemaVersion string `json:"schema_version"`
	Package       PackageInfo `json:"package"`
	Bundle        BundleInfo `json:"bundle"`
	Transport     TransportInfo `json:"transport"`

	// Omitempty: optional fields
	Entrypoints   []Entrypoint `json:"entrypoints,omitempty"`
	Permissions   PermissionsInfo `json:"permissions_requested,omitempty"`

	// Private fields: no tag = not marshaled
	internalState bool
}

type PackageInfo struct {
	// Tag conventions:
	// - lowercase for JSON keys (convention)
	// - omitempty for optional fields
	// - string for integers that might be very large
	ID      string `json:"id"`
	Version string `json:"version"`
	GitSHA  string `json:"git_sha"`
}

type TransportInfo struct {
	Type string `json:"type"` // "stdio" or "http"

	// Optional field (Port only needed for http)
	Port int `json:"port,omitempty"`
}
```

### Advanced Tag Features

```go
// Nested struct with different tag names
type Entrypoint struct {
	OS   string `json:"os" yaml:"os"`       // Works with both JSON and YAML
	Arch string `json:"arch" yaml:"arch"`
	Cmd  string `json:"command" yaml:"cmd"` // Different key for YAML

	// String tag for large numbers
	Size int64 `json:"size_bytes,string"`
}

// Multiple tags with mapstructure (for config files)
type Config struct {
	Registry string `json:"registry" yaml:"registry" mapstructure:"registry"`
	Timeout  string `json:"timeout" yaml:"timeout" mapstructure:"timeout"`

	// Tag `inline` embeds fields
	Limits LimitsInfo `mapstructure:",squash"`
}

// Enum-like values with specific tags
type Transport struct {
	Type string `json:"type"` // Will validate against ("stdio", "http")
}
```

### Unmarshaling with Struct Tags

```go
// Parse JSON bytes into struct
var manifest Manifest
if err := json.Unmarshal(data, &manifest); err != nil {
	// Error: "json: unknown field" or "json: cannot unmarshal bool into string"
	return nil, fmt.Errorf("invalid manifest JSON: %w", err)
}

// Parse YAML (requires separate decoder)
var manifest Manifest
if err := yaml.Unmarshal(data, &manifest); err != nil {
	return nil, fmt.Errorf("invalid manifest YAML: %w", err)
}

// Disallow unknown fields (json.Decoder can do this)
decoder := json.NewDecoder(bytes.NewReader(data))
decoder.DisallowUnknownFields() // Returns error if extra fields exist
var manifest Manifest
if err := decoder.Decode(&manifest); err != nil {
	return nil, fmt.Errorf("manifest contains unknown fields: %w", err)
}
```

---

## Required Field Validation: Checking Zero Values

After unmarshaling, validate that required fields are not empty/zero.

### Required String Fields

```go
type Manifest struct {
	SchemaVersion string `json:"schema_version"`
	Package       PackageInfo `json:"package"`
}

func Validate(m *Manifest) error {
	// Required string field
	if m.SchemaVersion == "" {
		return fmt.Errorf("schema_version is required")
	}

	// Nested required struct
	if m.Package.ID == "" {
		return fmt.Errorf("package.id is required")
	}

	return nil
}
```

### Required Integer/Boolean Fields

```go
type TransportInfo struct {
	Type string `json:"type"` // Required
	Port int    `json:"port"` // Required for HTTP, ignored for STDIO
}

func ValidateTransport(t *TransportInfo) error {
	// Type must be set
	if t.Type == "" {
		return fmt.Errorf("transport.type is required")
	}

	// Port requirement depends on type
	if t.Type == "http" && t.Port == 0 {
		return fmt.Errorf("transport.port is required for http transport")
	}

	// Boolean fields: check context, not zero value
	// (since `false` is valid, not absence)
	return nil
}
```

### Required Array/Slice Fields

```go
type Manifest struct {
	Entrypoints []Entrypoint `json:"entrypoints"`
	Permissions PermissionsInfo `json:"permissions_requested"`
}

func Validate(m *Manifest) error {
	// Array must not be empty
	if len(m.Entrypoints) == 0 {
		return fmt.Errorf("at least one entrypoint is required")
	}

	// Array elements must be validated
	for i, ep := range m.Entrypoints {
		if ep.Command == "" {
			return fmt.Errorf("entrypoints[%d].command is required", i)
		}
	}

	return nil
}
```

### Required Nested Struct Fields

```go
type Manifest struct {
	Package PackageInfo `json:"package"`
	Bundle  BundleInfo  `json:"bundle"`
}

type PackageInfo struct {
	ID      string `json:"id"`      // Required
	Version string `json:"version"` // Required
}

func Validate(m *Manifest) error {
	// Struct fields themselves can't be nil (they're embedded)
	// but their string/int fields can be zero
	if m.Package.ID == "" {
		return fmt.Errorf("package.id is required")
	}

	// Pointer fields CAN be nil
	if m.OptionalData == nil {
		// OK: optional struct pointer
	}

	return nil
}
```

---

## Type Validation: Ensuring Correct Types

### String vs Integer Type Issues

```go
// Bad JSON that causes unmarshaling errors:
// {"port": "8080"} // String instead of int!

type TransportInfo struct {
	Type string `json:"type"`
	Port int    `json:"port"`
}

var t TransportInfo
err := json.Unmarshal([]byte(`{"port": "8080"}`), &t)
// Error: "json: cannot unmarshal string into Go struct field TransportInfo.port of type int"

// Good: handle type mismatches
if err := json.Unmarshal(data, &t); err != nil {
	return nil, fmt.Errorf("invalid manifest: %w", err)
}
```

### String Tags for Large Numbers

```go
// Sometimes JSON sends large integers as strings
type BundleInfo struct {
	SizeBytes int64 `json:"size_bytes,string"` // Accepts "12345" or 12345
	Digest    string `json:"digest"`
}

// Both of these unmarshal correctly:
// {"size_bytes": 12345, "digest": "sha256:abc"}
// {"size_bytes": "12345", "digest": "sha256:abc"}

var b BundleInfo
json.Unmarshal([]byte(`{"size_bytes": "12345"}`), &b)
fmt.Println(b.SizeBytes) // 12345 (int64)
```

### Complex Type Validation

```go
// Ensure slice contains only strings
type PermissionsInfo struct {
	Network     []string `json:"network"`     // List of domain names/IPs
	Environment []string `json:"environment"` // List of env var names
}

func ValidatePermissions(p *PermissionsInfo) error {
	// Slice validation
	for i, host := range p.Network {
		if host == "" {
			return fmt.Errorf("network[%d] cannot be empty", i)
		}
		if !isValidHostname(host) {
			return fmt.Errorf("network[%d] is not a valid hostname: %s", i, host)
		}
	}

	return nil
}

// Map validation (if you use maps)
type Metadata map[string]interface{}

func ValidateMetadata(m Metadata) error {
	for key, value := range m {
		// Type assertions to ensure correct types
		switch v := value.(type) {
		case string:
			if v == "" {
				return fmt.Errorf("metadata[%q] cannot be empty string", key)
			}
		case float64: // JSON numbers come as float64
			if v < 0 {
				return fmt.Errorf("metadata[%q] must be non-negative", key)
			}
		case nil:
			return fmt.Errorf("metadata[%q] cannot be null", key)
		default:
			return fmt.Errorf("metadata[%q] has unsupported type %T", key, v)
		}
	}

	return nil
}
```

---

## Format Validation: Email, URL, Semver, Digest

### URL Validation

```go
import "net/url"

type RegistryConfig struct {
	URL string `json:"url"`
}

func ValidateRegistry(r *RegistryConfig) error {
	// Parse URL
	parsed, err := url.Parse(r.URL)
	if err != nil {
		return fmt.Errorf("registry.url is not a valid URL: %w", err)
	}

	// Ensure it's HTTPS (security requirement)
	if parsed.Scheme != "https" {
		return fmt.Errorf("registry.url must use https://, got: %s", parsed.Scheme)
	}

	// Ensure it has a hostname
	if parsed.Host == "" {
		return fmt.Errorf("registry.url must have a hostname")
	}

	return nil
}
```

### Semantic Version Validation

```go
import "regexp"

type PackageInfo struct {
	Version string `json:"version"`
}

// Semver pattern: MAJOR.MINOR.PATCH[-prerelease][+build]
var semverPattern = regexp.MustCompile(
	`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
	`(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
	`(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`,
)

func ValidateVersion(version string) error {
	if !semverPattern.MatchString(version) {
		return fmt.Errorf("version must be semantic version (e.g., 1.2.3, 1.0.0-alpha): %s", version)
	}
	return nil
}

// Or use a library: github.com/Masterminds/semver
import "github.com/Masterminds/semver/v3"

func ValidateVersionWithLibrary(version string) error {
	if _, err := semver.NewVersion(version); err != nil {
		return fmt.Errorf("version is not valid semver: %w", err)
	}
	return nil
}
```

### SHA-256 Digest Validation

```go
import (
	"regexp"
	"strings"
)

type BundleInfo struct {
	Digest string `json:"digest"` // "sha256:abc123..."
}

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func ValidateDigest(digest string) error {
	// Format: "sha256:" followed by 64 hex characters
	if !digestPattern.MatchString(digest) {
		return fmt.Errorf("digest must be sha256:hex64 format, got: %s", digest)
	}

	// Optionally: validate it's lowercase (prevents confusion)
	if digest != strings.ToLower(digest) {
		return fmt.Errorf("digest must be lowercase: %s", digest)
	}

	return nil
}

// Validation in context
func ValidateBundle(b *BundleInfo) error {
	if b.Digest == "" {
		return fmt.Errorf("bundle.digest is required")
	}

	if err := ValidateDigest(b.Digest); err != nil {
		return fmt.Errorf("bundle.digest is invalid: %w", err)
	}

	if b.SizeBytes <= 0 {
		return fmt.Errorf("bundle.size_bytes must be > 0, got: %d", b.SizeBytes)
	}

	return nil
}
```

### Enum/Choice Validation

```go
type TransportInfo struct {
	Type string `json:"type"` // Only "stdio" or "http"
	Port int    `json:"port,omitempty"`
}

func ValidateTransport(t *TransportInfo) error {
	// Enum validation
	validTypes := map[string]bool{"stdio": true, "http": true}
	if !validTypes[t.Type] {
		return fmt.Errorf("transport.type must be 'stdio' or 'http', got: %s", t.Type)
	}

	// Conditional validation based on enum
	if t.Type == "http" && t.Port == 0 {
		return fmt.Errorf("transport.port is required for http transport")
	}

	if t.Type == "stdio" && t.Port != 0 {
		return fmt.Errorf("transport.port should not be set for stdio transport")
	}

	return nil
}
```

### Operating System and Architecture Validation

```go
type Entrypoint struct {
	OS   string `json:"os"`   // "linux", "darwin", "windows"
	Arch string `json:"arch"` // "amd64", "arm64"
}

var validOS = map[string]bool{
	"linux":   true,
	"darwin":  true,
	"windows": true,
}

var validArch = map[string]bool{
	"amd64": true,
	"arm64": true,
}

func ValidateEntrypoint(ep *Entrypoint) error {
	if !validOS[ep.OS] {
		return fmt.Errorf("entrypoint.os must be linux/darwin/windows, got: %s", ep.OS)
	}

	if !validArch[ep.Arch] {
		return fmt.Errorf("entrypoint.arch must be amd64/arm64, got: %s", ep.Arch)
	}

	return nil
}
```

---

## Range Validation: Min/Max, Length

### Number Range Validation

```go
type LimitsInfo struct {
	MaxCPU    int `json:"max_cpu"`    // Millicores
	MaxMemory int `json:"max_memory"` // Bytes (or use string like "512M")
	MaxPIDs   int `json:"max_pids"`
	MaxFDs    int `json:"max_fds"`
	Timeout   int `json:"timeout_seconds"`
}

func ValidateLimits(l *LimitsInfo) error {
	// CPU range: 10-10000 millicores (0.01-10 cores)
	if l.MaxCPU < 10 || l.MaxCPU > 10000 {
		return fmt.Errorf("max_cpu must be 10-10000 millicores, got: %d", l.MaxCPU)
	}

	// Memory range: 1MB-64GB
	const minMemory = 1024 * 1024      // 1 MB
	const maxMemory = 64 * 1024 * 1024 * 1024 // 64 GB
	if l.MaxMemory < minMemory || l.MaxMemory > maxMemory {
		return fmt.Errorf("max_memory must be 1MB-64GB, got: %d bytes", l.MaxMemory)
	}

	// PIDs range: 1-1000
	if l.MaxPIDs < 1 || l.MaxPIDs > 1000 {
		return fmt.Errorf("max_pids must be 1-1000, got: %d", l.MaxPIDs)
	}

	// Timeout range: 1-3600 seconds
	if l.Timeout < 1 || l.Timeout > 3600 {
		return fmt.Errorf("timeout must be 1-3600 seconds, got: %d", l.Timeout)
	}

	return nil
}
```

### String Length Validation

```go
type PackageInfo struct {
	ID      string `json:"id"`      // org/name format
	Version string `json:"version"` // Semver
}

func ValidatePackageID(id string) error {
	// Length checks
	if len(id) < 3 {
		return fmt.Errorf("package.id too short (min 3 chars): %s", id)
	}
	if len(id) > 255 {
		return fmt.Errorf("package.id too long (max 255 chars): %s", id)
	}

	// Format check
	parts := strings.Split(id, "/")
	if len(parts) != 2 {
		return fmt.Errorf("package.id must be format org/name, got: %s", id)
	}

	org, name := parts[0], parts[1]

	// Org and name length
	if len(org) < 1 || len(org) > 100 {
		return fmt.Errorf("org name must be 1-100 chars, got: %d", len(org))
	}
	if len(name) < 1 || len(name) > 100 {
		return fmt.Errorf("package name must be 1-100 chars, got: %d", len(name))
	}

	// Character validation (alphanumeric + hyphen)
	if !isValidIdentifier(org) || !isValidIdentifier(name) {
		return fmt.Errorf("org and name must contain only alphanumeric and hyphens: %s", id)
	}

	return nil
}

func isValidIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, ch := range s {
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
			return false
		}
	}
	return !strings.HasPrefix(s, "-") && !strings.HasSuffix(s, "-")
}
```

### Array Size Validation

```go
type PermissionsInfo struct {
	Network     []string `json:"network"`
	Environment []string `json:"environment"`
}

func ValidatePermissions(p *PermissionsInfo) error {
	// Max network allowlist size
	if len(p.Network) > 100 {
		return fmt.Errorf("network allowlist too large (max 100 domains), got: %d", len(p.Network))
	}

	// Max environment variables
	if len(p.Environment) > 50 {
		return fmt.Errorf("environment allowlist too large (max 50 vars), got: %d", len(p.Environment))
	}

	return nil
}
```

---

## Unknown Fields: Detecting Unexpected Fields

Rejecting unknown fields prevents typos and malicious data.

### Method 1: json.Decoder.DisallowUnknownFields()

```go
import "encoding/json"

func ParseManifest(data []byte) (*Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields() // Strict mode

	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("manifest contains unknown fields: %w", err)
		// Error message: "json: unknown field "xyzField""
	}

	return &manifest, nil
}
```

### Method 2: Unmarshaling into map[string]interface{}

```go
func ParseAndValidateManifest(data []byte) (*Manifest, error) {
	// First, unmarshal into generic map to detect unknown fields
	var rawManifest map[string]interface{}
	if err := json.Unmarshal(data, &rawManifest); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Check for known fields
	allowedFields := map[string]bool{
		"schema_version":       true,
		"package":              true,
		"bundle":               true,
		"transport":            true,
		"entrypoints":          true,
		"permissions_requested": true,
		"limits_recommended":   true,
	}

	for key := range rawManifest {
		if !allowedFields[key] {
			return nil, fmt.Errorf("manifest contains unknown field: %q", key)
		}
	}

	// Now unmarshal into typed struct
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &manifest, nil
}
```

### Checking Nested Unknown Fields

```go
func ValidateManifestStructure(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// Validate top-level fields
	if _, ok := raw["package"]; !ok {
		return fmt.Errorf("manifest missing required field: package")
	}

	// Validate nested object fields
	if pkgData, ok := raw["package"].(map[string]interface{}); ok {
		allowedPkgFields := map[string]bool{"id": true, "version": true, "git_sha": true}
		for key := range pkgData {
			if !allowedPkgFields[key] {
				return fmt.Errorf("package contains unknown field: %q", key)
			}
		}
	}

	return nil
}
```

---

## Custom Validation: Implementing Unmarshaler

For complex validation rules that can't be expressed with struct tags, implement the `json.Unmarshaler` interface.

### Custom Unmarshaler for Entrypoint

```go
type Entrypoint struct {
	OS      string
	Arch    string
	Command string
	Args    []string
}

// Implement json.Unmarshaler
func (ep *Entrypoint) UnmarshalJSON(data []byte) error {
	// Step 1: unmarshal into raw map
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to parse entrypoint: %w", err)
	}

	// Step 2: validate required fields
	osVal, ok := raw["os"].(string)
	if !ok || osVal == "" {
		return fmt.Errorf("entrypoint.os is required")
	}

	archVal, ok := raw["arch"].(string)
	if !ok || archVal == "" {
		return fmt.Errorf("entrypoint.arch is required")
	}

	cmdVal, ok := raw["command"].(string)
	if !ok || cmdVal == "" {
		return fmt.Errorf("entrypoint.command is required")
	}

	// Step 3: validate values
	if !isValidOS(osVal) {
		return fmt.Errorf("entrypoint.os must be linux/darwin/windows, got: %s", osVal)
	}

	if !isValidArch(archVal) {
		return fmt.Errorf("entrypoint.arch must be amd64/arm64, got: %s", archVal)
	}

	// Step 4: parse optional fields
	var args []string
	if argsVal, ok := raw["args"].([]interface{}); ok {
		for i, arg := range argsVal {
			if argStr, ok := arg.(string); ok {
				args = append(args, argStr)
			} else {
				return fmt.Errorf("entrypoint.args[%d] must be string, got: %T", i, arg)
			}
		}
	}

	// Step 5: assign to struct
	ep.OS = osVal
	ep.Arch = archVal
	ep.Command = cmdVal
	ep.Args = args

	return nil
}
```

### Custom Unmarshaler for Memory Size

```go
type MemorySize int64

// Parse "512M", "1GB", "100MB" into bytes
func (ms *MemorySize) UnmarshalJSON(data []byte) error {
	var val string
	if err := json.Unmarshal(data, &val); err != nil {
		return fmt.Errorf("memory size must be string: %w", err)
	}

	// Parse size like "512M", "1GB"
	bytes, err := parseMemorySize(val)
	if err != nil {
		return fmt.Errorf("invalid memory size: %w", err)
	}

	*ms = MemorySize(bytes)
	return nil
}

func parseMemorySize(s string) (int64, error) {
	s = strings.TrimSpace(s)

	// Parse number and unit
	var num float64
	var unit string

	// Extract number
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return !((r >= '0' && r <= '9') || r == '.')
	})

	if len(parts) < 1 {
		return 0, fmt.Errorf("invalid format: %s", s)
	}

	var err error
	num, err = strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %w", err)
	}

	// Extract unit
	unitIdx := strings.Index(s, parts[0]) + len(parts[0])
	unit = strings.ToUpper(strings.TrimSpace(s[unitIdx:]))

	// Convert to bytes
	multiplier := map[string]int64{
		"B":  1,
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"TB": 1024 * 1024 * 1024 * 1024,
	}[unit]

	if multiplier == 0 {
		return 0, fmt.Errorf("unknown unit: %s (valid: B, KB, MB, GB, TB)", unit)
	}

	bytes := int64(num * float64(multiplier))
	return bytes, nil
}
```

---

## Nested Validation: Recursive Validation

Validate complex nested structures recursively.

### Validating Manifest with Nested Objects

```go
// From internal/manifest/parser.go

func Validate(manifest *Manifest) error {
	if manifest == nil {
		return fmt.Errorf("manifest cannot be nil")
	}

	// Step 1: validate top-level required fields
	if manifest.SchemaVersion == "" {
		return fmt.Errorf("schema_version is required")
	}

	// Step 2: validate nested structs
	if err := validatePackageInfo(&manifest.Package); err != nil {
		return fmt.Errorf("invalid package: %w", err)
	}

	if err := validateBundleInfo(&manifest.Bundle); err != nil {
		return fmt.Errorf("invalid bundle: %w", err)
	}

	if err := validateTransportInfo(&manifest.Transport); err != nil {
		return fmt.Errorf("invalid transport: %w", err)
	}

	// Step 3: validate arrays of nested structs
	if len(manifest.Entrypoints) == 0 {
		return fmt.Errorf("at least one entrypoint is required")
	}

	for i, ep := range manifest.Entrypoints {
		if err := validateEntrypoint(&ep); err != nil {
			return fmt.Errorf("entrypoints[%d]: %w", i, err)
		}
	}

	// Step 4: validate permissions (if present)
	if err := validatePermissions(&manifest.Permissions); err != nil {
		return fmt.Errorf("invalid permissions: %w", err)
	}

	return nil
}

func validatePackageInfo(p *PackageInfo) error {
	if p.ID == "" {
		return fmt.Errorf("id is required")
	}

	if err := ValidatePackageID(p.ID); err != nil {
		return err
	}

	if p.Version == "" {
		return fmt.Errorf("version is required")
	}

	if err := ValidateVersion(p.Version); err != nil {
		return err
	}

	return nil
}

func validateBundleInfo(b *BundleInfo) error {
	if b.Digest == "" {
		return fmt.Errorf("digest is required")
	}

	if err := ValidateDigest(b.Digest); err != nil {
		return err
	}

	if b.SizeBytes <= 0 {
		return fmt.Errorf("size_bytes must be > 0")
	}

	return nil
}

func validateEntrypoint(ep *Entrypoint) error {
	if ep.OS == "" {
		return fmt.Errorf("os is required")
	}

	if ep.Arch == "" {
		return fmt.Errorf("arch is required")
	}

	if ep.Command == "" {
		return fmt.Errorf("command is required")
	}

	if !isValidOS(ep.OS) {
		return fmt.Errorf("os must be linux/darwin/windows, got: %s", ep.OS)
	}

	if !isValidArch(ep.Arch) {
		return fmt.Errorf("arch must be amd64/arm64, got: %s", ep.Arch)
	}

	return nil
}

func validatePermissions(p *PermissionsInfo) error {
	// Validate network allowlist
	for i, host := range p.Network {
		if host == "" {
			return fmt.Errorf("network[%d] cannot be empty", i)
		}
		// Could validate as domain/IP
	}

	// Validate environment allowlist
	for i, env := range p.Environment {
		if env == "" {
			return fmt.Errorf("environment[%d] cannot be empty", i)
		}
		// Could validate as valid env var name
	}

	return nil
}
```

---

## Error Messages: Clear, Actionable Messages with Field Paths

### Good Error Messages

```go
// Bad: vague
"validation failed"

// Good: include field path and expected format
"manifest validation failed: entrypoints[2].command - required field missing"

// Good: show what's allowed
"transport.type must be 'stdio' or 'http', got: 'grpc'"

// Good: include value and reason
"package.id 'my-pkg' is invalid - must be org/name format"

// Good: suggest fix
"bundle.size_bytes must be > 0, got: 0 - bundles cannot be empty"

// Implementation:
func validateWithContext(field string, value interface{}, constraint string) error {
	return fmt.Errorf("manifest validation failed: %s - %s (got: %v)", field, constraint, value)
}

// Usage:
if bundle.SizeBytes <= 0 {
	return validateWithContext("bundle.size_bytes", bundle.SizeBytes, "must be > 0")
}
```

### Batch Validation Errors

```go
// Collect multiple validation errors, return all at once
type ValidationErrors []ValidationError

type ValidationError struct {
	Field    string // "entrypoints[1].command"
	Message  string // "required field"
	Value    interface{}
}

func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return ""
	}

	var msgs []string
	for _, err := range ve {
		msgs = append(msgs, fmt.Sprintf("%s: %s", err.Field, err.Message))
	}

	return fmt.Sprintf("manifest validation failed with %d errors:\n  - %s",
		len(ve), strings.Join(msgs, "\n  - "))
}

// Validation that collects errors
func ValidateWithErrors(manifest *Manifest) error {
	var errs ValidationErrors

	if manifest.SchemaVersion == "" {
		errs = append(errs, ValidationError{
			Field:   "schema_version",
			Message: "required field",
		})
	}

	if manifest.Package.ID == "" {
		errs = append(errs, ValidationError{
			Field:   "package.id",
			Message: "required field",
		})
	}

	for i, ep := range manifest.Entrypoints {
		if ep.Command == "" {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("entrypoints[%d].command", i),
				Message: "required field",
			})
		}
	}

	if len(errs) > 0 {
		return errs
	}

	return nil
}
```

---

## Testing: Valid Schemas, Invalid Schemas, Boundary Cases

```go
// From internal/manifest/parser_test.go

func TestValidateManifest_ValidSchema(t *testing.T) {
	manifest := &Manifest{
		SchemaVersion: "1.0.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.2.3",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{Type: "stdio"},
		Entrypoints: []Entrypoint{
			{
				OS:      "linux",
				Arch:    "amd64",
				Command: "./bin/server",
			},
		},
	}

	if err := Validate(manifest); err != nil {
		t.Fatalf("expected valid manifest to pass validation: %v", err)
	}
}

func TestValidateManifest_MissingSchemaVersion(t *testing.T) {
	manifest := &Manifest{} // Missing schema_version

	err := Validate(manifest)
	if err == nil {
		t.Fatal("expected validation to fail for missing schema_version")
	}

	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error message should mention field: %v", err)
	}
}

func TestValidateManifest_InvalidPackageID(t *testing.T) {
	testCases := []struct {
		name      string
		packageID string
	}{
		{"missing org", "hello"},
		{"extra slashes", "org/name/extra"},
		{"empty org", "/name"},
		{"empty name", "org/"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := &Manifest{
				SchemaVersion: "1.0.0",
				Package: PackageInfo{
					ID:      tc.packageID,
					Version: "1.2.3",
				},
			}

			err := Validate(manifest)
			if err == nil {
				t.Fatal("expected validation to fail")
			}

			if !strings.Contains(err.Error(), "package.id") {
				t.Errorf("error should mention package.id: %v", err)
			}
		})
	}
}

func TestValidateManifest_InvalidDigest(t *testing.T) {
	testCases := []struct {
		name   string
		digest string
	}{
		{"wrong prefix", "md5:abc123"},
		{"short hex", "sha256:abc"},
		{"not hex", "sha256:xyz123"},
		{"uppercase", "sha256:ABC123..."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDigest(tc.digest)
			if err == nil {
				t.Fatal("expected validation to fail for digest:", tc.digest)
			}
		})
	}
}

func TestValidateEntrypoints_NoEntrypoints(t *testing.T) {
	manifest := &Manifest{
		Entrypoints: []Entrypoint{}, // Empty!
	}

	err := Validate(manifest)
	if err == nil {
		t.Fatal("expected validation to fail for empty entrypoints")
	}

	if !strings.Contains(err.Error(), "entrypoint") {
		t.Errorf("error should mention entrypoints: %v", err)
	}
}

func TestValidateTransport_HTTPWithoutPort(t *testing.T) {
	manifest := &Manifest{
		Transport: TransportInfo{
			Type: "http",
			Port: 0, // Missing!
		},
	}

	err := validateTransportInfo(&manifest.Transport)
	if err == nil {
		t.Fatal("expected validation to fail for http without port")
	}

	if !strings.Contains(err.Error(), "port") {
		t.Errorf("error should mention port: %v", err)
	}
}

func TestUnmarshal_UnknownFields(t *testing.T) {
	jsonData := []byte(`{
		"schema_version": "1.0.0",
		"package": {"id": "acme/hello", "version": "1.2.3"},
		"bundle": {"digest": "sha256:...", "size_bytes": 1024},
		"transport": {"type": "stdio"},
		"entrypoints": [{"os": "linux", "arch": "amd64", "command": "./bin/server"}],
		"unknown_field": "should fail"
	}`)

	decoder := json.NewDecoder(bytes.NewReader(jsonData))
	decoder.DisallowUnknownFields()

	var manifest Manifest
	err := decoder.Decode(&manifest)
	if err == nil {
		t.Fatal("expected decoding to fail with unknown field")
	}

	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("error should mention unknown field: %v", err)
	}
}

func TestParseMemorySize(t *testing.T) {
	testCases := []struct {
		input    string
		expected int64
	}{
		{"512M", 512 * 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
		{"100MB", 100 * 1024 * 1024},
		{"1KB", 1024},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			size, err := parseMemorySize(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if size != tc.expected {
				t.Errorf("expected %d, got %d", tc.expected, size)
			}
		})
	}
}
```

---

## Common Mistakes and How to Avoid Them

### 1. Ignoring Validation

```go
// Bad: unmarshaling without validation
var manifest Manifest
json.Unmarshal(data, &manifest)
// manifest might have empty required fields!

// Good: validate after unmarshaling
var manifest Manifest
if err := json.Unmarshal(data, &manifest); err != nil {
	return nil, fmt.Errorf("invalid JSON: %w", err)
}

if err := Validate(&manifest); err != nil {
	return nil, fmt.Errorf("validation failed: %w", err)
}
```

### 2. Weak Field Path in Error Messages

```go
// Bad: no context
if manifest.Package.ID == "" {
	return fmt.Errorf("ID is required")
}

// Good: include full path
if manifest.Package.ID == "" {
	return fmt.Errorf("package.id is required")
}

// Good: include array index
for i, ep := range manifest.Entrypoints {
	if ep.Command == "" {
		return fmt.Errorf("entrypoints[%d].command is required", i)
	}
}
```

### 3. Allowing Unknown Fields

```go
// Bad: no check for typos
json.Unmarshal(data, &manifest)
// If user typed "transport_type" instead of "transport.type", no error!

// Good: reject unknown fields
decoder := json.NewDecoder(bytes.NewReader(data))
decoder.DisallowUnknownFields()
decoder.Decode(&manifest)
```

### 4. Not Testing Edge Cases

```go
// Missing tests for:
// - Empty arrays
// - Null values
// - Very large numbers
// - Very long strings
// - Invalid enum values
// - Missing nested fields

// Solution: comprehensive test coverage
func TestValidate_BoundaryConditions(t *testing.T) {
	// Empty arrays
	manifest := &Manifest{Entrypoints: []Entrypoint{}}
	if err := Validate(manifest); err == nil {
		t.Fatal("should reject empty entrypoints")
	}

	// Very large numbers
	manifest.Limits.MaxMemory = math.MaxInt64
	if err := validateLimits(&manifest.Limits); err == nil {
		t.Fatal("should reject unrealistic memory limit")
	}

	// Very long strings
	manifest.Package.ID = strings.Repeat("a", 10000)
	if err := ValidatePackageID(manifest.Package.ID); err == nil {
		t.Fatal("should reject too-long ID")
	}
}
```

---

## Summary Checklist

- [x] Define all struct tags (`json`, `yaml`)
- [x] Validate all required fields (non-zero after unmarshal)
- [x] Validate field types (string, int, bool, array, object)
- [x] Validate field formats (URL, semver, digest, enum)
- [x] Validate field ranges (min/max, length)
- [x] Reject unknown fields (DisallowUnknownFields)
- [x] Implement custom Unmarshaler for complex validation
- [x] Validate nested structures recursively
- [x] Include field paths in error messages
- [x] Test valid schemas, invalid schemas, boundary cases
- [x] No silent validation failures
- [x] Clear, actionable error messages
