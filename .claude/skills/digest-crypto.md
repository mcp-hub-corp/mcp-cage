# Digest Validation & Cryptography in Go

## Overview

This skill covers cryptographic hash validation (SHA-256, SHA-512) and secure digest handling. Essential for mcp-cage's core security invariant: **always validate manifest and bundle integrity before execution**.

---

## Digest Format & Conventions

### Standard Digest Format

Digests follow the pattern: `algorithm:hexvalue`

```
sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234
\____/ \__________________________________________________________________/
  |                            |
algo              64 hex chars (SHA-256 = 256 bits = 32 bytes)

sha512:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234
\____/ \__________________________________________________________________________________________________________________________________/
  |                            |
algo              128 hex chars (SHA-512 = 512 bits = 64 bytes)
```

### Hash Algorithm Comparison

| Algorithm | Output Bits | Hex Chars | Strength | Use Case |
|-----------|------------|-----------|----------|----------|
| SHA-256   | 256        | 64        | Strong   | Default for mcp-cage |
| SHA-512   | 512        | 128       | Stronger | Future-proofing |
| MD5       | 128        | 32        | Broken   | NEVER USE |
| SHA-1     | 160        | 40        | Weak     | NEVER USE |

**mcp-cage mandate:** Only SHA-256 for v1.0, SHA-512 for future upgrades.

---

## Core Security Invariants

### INVARIANT 1: Always Validate Before Use

```go
// WRONG: Skip validation
data := downloadFile(url)
processData(data) // VULNERABLE!

// CORRECT: Always validate
data := downloadFile(url)
if err := ValidateDigest(data, expectedDigest); err != nil {
	return fmt.Errorf("validation failed: %w", err)
}
processData(data) // Safe
```

### INVARIANT 2: Never Trust Network Values

```go
// WRONG: Use digest from untrusted source
digestFromHeader := resp.Header.Get("X-Digest")
data := io.ReadAll(resp.Body)
ValidateDigest(data, digestFromHeader) // Worthless!

// CORRECT: Use pre-computed digest
expectedDigest := manifest.BundleDigest // From previously-validated manifest
data := io.ReadAll(resp.Body)
if err := ValidateDigest(data, expectedDigest); err != nil {
	return fmt.Errorf("validation failed: %w", err)
}
```

### INVARIANT 3: Timing-Safe Comparison

```go
// WRONG: String comparison (timing attack)
if computed == expected {
	// Leaks length info via timing
}

// CORRECT: Constant-time comparison
if subtle.ConstantTimeCompare([]byte(computed), []byte(expected)) != 1 {
	return fmt.Errorf("digest mismatch")
}
```

### INVARIANT 4: Always Compute Fresh Hash

```go
// WRONG: Trust stored hash
storedHash := readCachedHash(filePath)
if storedHash == expectedDigest {
	// File might have been modified!
}

// CORRECT: Always recompute
actualHash := ComputeSHA256(fileData)
if actualHash != expectedDigest {
	return fmt.Errorf("validation failed")
}
```

---

## Implementation Patterns

### Basic Digest Validation

```go
package registry

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// ValidateDigest validates that data matches the expected digest
// SECURITY: Uses constant-time comparison, never panics
func ValidateDigest(data []byte, expectedDigest string) error {
	// 1. Validate input
	if expectedDigest == "" {
		return fmt.Errorf("digest validation: expected digest cannot be empty")
	}

	if data == nil {
		return fmt.Errorf("digest validation: data cannot be nil")
	}

	// 2. Parse expected digest
	algorithm, expectedHex, err := ParseDigest(expectedDigest)
	if err != nil {
		return fmt.Errorf("digest validation: failed to parse expected digest: %w", err)
	}

	// 3. Validate algorithm
	if algorithm != "sha256" {
		return fmt.Errorf("digest validation: unsupported algorithm %q (only sha256 supported)", algorithm)
	}

	// 4. Compute actual hash
	actualHash := sha256.Sum256(data)
	actualHex := hex.EncodeToString(actualHash[:])

	// 5. Compare using constant-time comparison
	// Convert to bytes for timing-safe comparison
	if subtle.ConstantTimeCompare([]byte(expectedHex), []byte(actualHex)) != 1 {
		// NOTE: Don't include actual values in error (timing info leak)
		return fmt.Errorf("digest validation failed: computed digest does not match expected")
	}

	return nil
}
```

### Digest Parsing

```go
// ParseDigest parses "algorithm:hexvalue" format
// Returns (algorithm, hexvalue, error)
func ParseDigest(digest string) (algorithm, hex string, err error) {
	// 1. Check for empty
	if digest == "" {
		return "", "", fmt.Errorf("digest cannot be empty")
	}

	// 2. Split on colon
	parts := strings.Split(digest, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid digest format, expected 'algorithm:hexvalue', got %q", digest)
	}

	algorithm = parts[0]
	hex = parts[1]

	// 3. Validate non-empty parts
	if algorithm == "" || hex == "" {
		return "", "", fmt.Errorf("invalid digest format, algorithm and hex cannot be empty")
	}

	// 4. Validate hex characters
	// Must be lowercase a-f or 0-9 (to prevent timing attacks with case conversion)
	for i, char := range hex {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return "", "", fmt.Errorf(
				"invalid digest format, hex contains non-hexadecimal character %q at position %d",
				char, i)
		}
	}

	// 5. Validate length based on algorithm
	switch algorithm {
	case "sha256":
		if len(hex) != 64 {
			return "", "", fmt.Errorf(
				"invalid sha256 digest length: expected 64 hex chars, got %d",
				len(hex))
		}
	case "sha512":
		if len(hex) != 128 {
			return "", "", fmt.Errorf(
				"invalid sha512 digest length: expected 128 hex chars, got %d",
				len(hex))
		}
	default:
		return "", "", fmt.Errorf("unsupported digest algorithm %q (supported: sha256, sha512)", algorithm)
	}

	return algorithm, hex, nil
}
```

### Hash Computation

```go
import (
	"crypto/sha256"
	"encoding/hex"
)

// ComputeSHA256 computes SHA-256 hash of data
// Returns lowercase hex string (64 characters)
func ComputeSHA256(data []byte) string {
	// Handle nil by treating as empty
	if data == nil {
		data = []byte{}
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ComputeSHA512 computes SHA-512 hash of data
// Returns lowercase hex string (128 characters)
func ComputeSHA512(data []byte) string {
	hash := sha512.Sum512(data)
	return hex.EncodeToString(hash[:])
}
```

---

## Validation Workflow

### Complete Digest Validation Flow

```go
package executor

import (
	"fmt"
	"io"
	"os"
	"github.com/security-mcp/mcp-cage/internal/registry"
)

// DownloadAndValidate downloads a file and validates its digest
// SECURITY: Validation is mandatory, never skipped
func DownloadAndValidate(
	url string,
	expectedDigest string,
	outputPath string,
) error {
	// 1. Validate expected digest format early
	if _, _, err := registry.ParseDigest(expectedDigest); err != nil {
		return fmt.Errorf("invalid expected digest: %w", err)
	}

	// 2. Download file
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	// 3. Read into memory or temp file (depending on size)
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	// 4. CRITICAL: Validate digest BEFORE storing
	if err := registry.ValidateDigest(data, expectedDigest); err != nil {
		return fmt.Errorf("digest validation failed: %w", err)
	}

	// 5. Write validated data to output
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	return nil
}
```

### Streaming Validation (Large Files)

```go
import (
	"crypto/sha256"
	"io"
)

// StreamValidate validates large files without loading into memory
func StreamValidate(filePath string, expectedDigest string) error {
	// 1. Validate expected digest
	algo, expectedHex, err := ParseDigest(expectedDigest)
	if err != nil {
		return fmt.Errorf("invalid digest: %w", err)
	}

	if algo != "sha256" {
		return fmt.Errorf("only sha256 supported, got %q", algo)
	}

	// 2. Open file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("cannot open file: %w", err)
	}
	defer file.Close()

	// 3. Stream hash computation
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	// 4. Get computed hash
	actualHex := hex.EncodeToString(hasher.Sum(nil))

	// 5. Constant-time compare
	if subtle.ConstantTimeCompare([]byte(expectedHex), []byte(actualHex)) != 1 {
		return fmt.Errorf("digest validation failed")
	}

	return nil
}
```

---

## Testing Digest Functions

### Unit Tests for Validation

```go
package registry

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDigest_Success(t *testing.T) {
	data := []byte("test content")
	expectedDigest := "sha256:" + ComputeSHA256(data)

	err := ValidateDigest(data, expectedDigest)
	assert.NoError(t, err)
}

func TestValidateDigest_Mismatch(t *testing.T) {
	data := []byte("test content")
	wrongDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	err := ValidateDigest(data, wrongDigest)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
	// Error should NOT leak actual/expected values for timing safety
}

func TestValidateDigest_EmptyExpected(t *testing.T) {
	data := []byte("test content")

	err := ValidateDigest(data, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestValidateDigest_NilData(t *testing.T) {
	err := ValidateDigest(nil, "sha256:abc123")
	assert.Error(t, err)
}

func TestValidateDigest_UnsupportedAlgorithm(t *testing.T) {
	data := []byte("test content")
	digest := "md5:abc123"

	err := ValidateDigest(data, digest)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

// Test with real data (not mocked hash)
func TestValidateDigest_RealSHA256(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"simple string", []byte("hello world")},
		{"json", []byte(`{"name":"test"}`)},
		{"binary", []byte{0x00, 0x01, 0x02, 0xff}},
		{"empty", []byte("")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash := ComputeSHA256(tc.data)
			digest := "sha256:" + hash

			// Correct digest should validate
			err := ValidateDigest(tc.data, digest)
			require.NoError(t, err)

			// Modified data should fail
			modified := append([]byte("x"), tc.data...)
			err = ValidateDigest(modified, digest)
			assert.Error(t, err)
		})
	}
}
```

### Fuzz Tests for Parsing

```go
func FuzzParseDigest(f *testing.F) {
	// Seed corpus with valid and edge cases
	f.Add("sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	f.Add("sha512:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	f.Add("sha256:")     // Empty hex
	f.Add(":abc123")     // Empty algorithm
	f.Add("sha256")      // Missing colon
	f.Add("")            // Empty string
	f.Add("md5:abc123")  // Invalid algorithm
	f.Add("SHA256:ABCD") // Uppercase (should fail)
	f.Add("sha256:" + strings.Repeat("0", 1000)) // Very long hex

	f.Fuzz(func(t *testing.T, input string) {
		// Must never panic, even with malicious input
		_, _, err := ParseDigest(input)

		// Either succeeds with valid format OR returns error
		// But MUST NOT panic or hang
		_ = err
	})
}

func FuzzValidateDigest(f *testing.F) {
	f.Add([]byte("test data"), "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	f.Add([]byte(""), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	f.Add([]byte("hello"), "sha512:abc123")
	f.Add([]byte{0x00, 0x01, 0x02}, "sha256:invalid")

	f.Fuzz(func(t *testing.T, data []byte, digest string) {
		// Must never panic
		err := ValidateDigest(data, digest)
		// Result is either valid or invalid, but no panics
		_ = err
	})
}
```

### Benchmark Tests

```go
func BenchmarkComputeSHA256_SmallData(b *testing.B) {
	data := []byte("test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeSHA256(data)
	}
	// Result: ~1000 ns/op (very fast for small data)
}

func BenchmarkComputeSHA256_1MB(b *testing.B) {
	data := make([]byte, 1*1024*1024)
	// Fill with random data for realistic test
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeSHA256(data)
	}
	// Result: ~1-2 ms/op
}

func BenchmarkComputeSHA256_100MB(b *testing.B) {
	data := make([]byte, 100*1024*1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeSHA256(data)
	}
	// Result: ~100-200 ms/op
	// Note: Bundle size limit is ~100MB
}

func BenchmarkValidateDigest_SmallData(b *testing.B) {
	data := []byte("test data for validation")
	digest := "sha256:" + ComputeSHA256(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateDigest(data, digest)
	}
}

func BenchmarkValidateDigest_100MB(b *testing.B) {
	data := make([]byte, 100*1024*1024)
	rand.Read(data)
	digest := "sha256:" + ComputeSHA256(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateDigest(data, digest)
	}
}

func BenchmarkParseDigest(b *testing.B) {
	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ParseDigest(digest)
	}
	// Result: ~10-20 ns/op (very fast)
}
```

**Benchmark Analysis:**
- SHA-256 computation: ~1 microsecond per MB
- Parsing: ~10-20 nanoseconds (negligible)
- Validation: dominated by hash computation

---

## Common Mistakes & Fixes

### Mistake 1: Case-Sensitive Comparison

Bad:
```go
// Allows uppercase hex (timing attack vector)
if hex != expectedHex { // Case-sensitive!
	return fmt.Errorf("mismatch")
}
```

Good:
```go
// Always convert to lowercase
hex := strings.ToLower(hex)
expectedHex := strings.ToLower(expectedHex)

// Use constant-time comparison
if subtle.ConstantTimeCompare([]byte(expectedHex), []byte(hex)) != 1 {
	return fmt.Errorf("mismatch")
}
```

### Mistake 2: Trust Values from Response

Bad:
```go
// VULNERABLE: Attacker can change header
digestFromHeader := resp.Header.Get("X-Digest")
data := io.ReadAll(resp.Body)
ValidateDigest(data, digestFromHeader)
```

Good:
```go
// Use digest from manifest (already validated)
manifestDigest := manifest.BundleDigest
data := io.ReadAll(resp.Body)
if err := ValidateDigest(data, manifestDigest); err != nil {
	return fmt.Errorf("validation failed: %w", err)
}
```

### Mistake 3: Loading Large Files Entirely

Bad:
```go
// Uses too much memory for 100MB files
data, _ := os.ReadFile(filePath)
ValidateDigest(data, digest)
```

Good:
```go
// Stream validation for large files
if err := StreamValidate(filePath, digest); err != nil {
	return err
}
```

### Mistake 4: Not Handling Uppercase Hex

Bad:
```go
func ParseDigest(digest string) (algo, hex string, err error) {
	// Fails for uppercase: "SHA256:ABC123"
	for _, char := range hex {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return "", "", fmt.Errorf("invalid hex")
		}
	}
	return algo, hex, nil
}
```

Good:
```go
func ParseDigest(digest string) (algo, hex string, err error) {
	// Convert to lowercase for consistency
	digest = strings.ToLower(digest)

	for _, char := range hex {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return "", "", fmt.Errorf("invalid hex")
		}
	}
	return algo, hex, nil
}
```

### Mistake 5: String Concatenation for Error Messages

Bad:
```go
return fmt.Errorf("expected %s, got %s", expectedHex, actualHex)
// Leaks values for timing attacks!
```

Good:
```go
return fmt.Errorf("digest validation failed: computed digest does not match expected")
// No value leakage
```

---

## Security Checklist

- [ ] **Always validate before use:** No exceptions, ever
- [ ] **Use SHA-256 minimum:** Never MD5, SHA-1, or weak algorithms
- [ ] **Constant-time comparison:** Use `crypto/subtle.ConstantTimeCompare`
- [ ] **Fresh computation:** Always recompute, never trust cached values
- [ ] **No value leakage:** Error messages don't include actual digests
- [ ] **Lowercase hex:** Normalize all hex strings to lowercase
- [ ] **Format validation:** Validate digest format before using
- [ ] **Stream large files:** Don't load 100MB files entirely into memory
- [ ] **Test with fuzz:** Run FuzzValidateDigest and FuzzParseDigest
- [ ] **Benchmark performance:** Ensure SHA-256 doesn't bottleneck
- [ ] **Handle nil:** Return error for nil input, never panic
- [ ] **Empty input validation:** Reject empty digests and data

---

## Algorithm Roadmap

### Current (v1.0)
- SHA-256: Primary algorithm
- Mandatory validation on all downloads

### Future (v1.1+)
- SHA-512: Add support for stronger security
- Dual validation: support both SHA-256 and SHA-512
- Algorithm negotiation: registry advertises supported algorithms

### Never
- MD5: Cryptographically broken
- SHA-1: Deprecated, collision demonstrated
- No-hash mode: Validation is not optional

---

## Performance Considerations

### Hash Computation Speed

On modern CPUs (2023+):
- **SHA-256:** ~1 GB/second
- **SHA-512:** ~0.5 GB/second
- **Bundle size limit:** 100 MB → ~100ms to compute SHA-256

### Optimization Strategies

1. **Parallel hashing** (not worth it for bundles < 500MB)
2. **Hardware acceleration:** Crypto/SHA-NI instructions (automatic in Go)
3. **Streaming:** For files > 50MB, use streaming validation

### Memory Usage

```go
// Small data (manifests: < 10MB)
data := make([]byte, 10*1024*1024) // 10 MB in memory
hash := sha256.Sum256(data)         // Minimal overhead

// Large data (bundles: < 100MB)
// Use streaming to avoid 100MB allocation
```

---

## Example: Complete Validation Flow

```go
package executor

import (
	"fmt"
	"io"
	"os"
	"github.com/security-mcp/mcp-cage/internal/manifest"
	"github.com/security-mcp/mcp-cage/internal/registry"
)

// ExecutePackage is the complete workflow
func ExecutePackage(
	packageRef string,
	client *registry.Client,
	cache cache.Store,
) error {
	// 1. Resolve reference
	resolved, err := client.Resolve(packageRef)
	if err != nil {
		return fmt.Errorf("resolve failed: %w", err)
	}

	// 2. Get manifest
	manifestData := getFromCache(cache, resolved.ManifestDigest)
	if manifestData == nil {
		// Not in cache, must download
		manifestData, err = client.Download(resolved.ManifestURL)
		if err != nil {
			return fmt.Errorf("manifest download failed: %w", err)
		}

		// CRITICAL: Validate manifest digest
		if err := registry.ValidateDigest(manifestData, resolved.ManifestDigest); err != nil {
			return fmt.Errorf("manifest validation failed: %w", err)
		}

		// Cache for future use
		cache.Put(resolved.ManifestDigest, manifestData)
	}

	// 3. Parse manifest (no validation needed, already validated)
	mf, err := manifest.Parse(manifestData)
	if err != nil {
		return fmt.Errorf("manifest parse failed: %w", err)
	}

	// 4. Get bundle
	bundleData := getFromCache(cache, resolved.BundleDigest)
	if bundleData == nil {
		// Download bundle
		bundleData, err = client.Download(resolved.BundleURL)
		if err != nil {
			return fmt.Errorf("bundle download failed: %w", err)
		}

		// CRITICAL: Validate bundle digest (from manifest)
		if err := registry.ValidateDigest(bundleData, mf.Bundle.Digest); err != nil {
			return fmt.Errorf("bundle validation failed: %w", err)
		}

		// Cache validated bundle
		cache.Put(mf.Bundle.Digest, bundleData)
	}

	// 5. Extract and execute
	if err := extractAndExecute(mf, bundleData); err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}

	return nil
}
```

---

## Summary

The digest validation system is the foundation of mcp-cage's security:

1. **Mandatory validation:** Always validate manifest and bundle digests
2. **SHA-256:** Primary algorithm, non-negotiable
3. **Constant-time comparison:** Protect against timing attacks
4. **No value leakage:** Error messages don't include digests
5. **Test thoroughly:** Unit, fuzz, and benchmark tests required
6. **Performance:** Negligible impact on execution (< 100ms for 100MB files)
