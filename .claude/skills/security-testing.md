# Security-Focused Testing in Go

## Overview

This skill covers comprehensive testing strategies for security-critical applications, with emphasis on the mcp-cage project's security invariants: input validation, digest verification, resource limits, and policy enforcement.

---

## Test Types & Strategies

### 1. Unit Tests

**Purpose:** Test individual functions in isolation with clear inputs/outputs.

**When to use:**
- Testing business logic
- Validating error handling
- Testing edge cases

**Example Pattern (Digest Validation):**

```go
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
}
```

**Best Practices:**
- Use `assert` for non-critical checks, `require` for critical ones
- Test both success and error paths
- Include boundary conditions (empty, nil, zero values)
- Test with realistic data

---

### 2. Integration Tests

**Purpose:** Test multiple components working together.

**When to use:**
- Testing API client + cache + validation flow
- Registry resolution + digest validation
- Manifest parsing + entrypoint selection

**Example Pattern (Registry + Cache):**

```go
func TestRegistryAndCache_DownloadAndValidate(t *testing.T) {
	// 1. Mock registry server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := []byte(`{"name":"test"}`)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer server.Close()

	// 2. Create cache in temp directory
	cacheDir := t.TempDir()
	store := cache.NewStore(cacheDir)

	// 3. Download manifest
	manifest := []byte(`{"name":"test"}`)
	digest := "sha256:" + registry.ComputeSHA256(manifest)

	// 4. Cache and validate
	err := store.Put(digest, manifest)
	require.NoError(t, err)

	retrieved, err := store.Get(digest)
	require.NoError(t, err)

	err = registry.ValidateDigest(retrieved, digest)
	assert.NoError(t, err)
}
```

**Best Practices:**
- Use `httptest.NewServer()` for registry mocking
- Use `t.TempDir()` for filesystem operations
- Test error scenarios (network failures, validation errors)
- Clean up resources in defer

---

### 3. Fuzz Testing

**Purpose:** Find edge cases and crash conditions with automated input generation.

**When to use:**
- Input validation (digest parsing, manifest parsing)
- Untrusted data sources
- Security-critical paths

**Fuzz Test Structure:**

```go
// Fuzz test for digest parsing - security critical
func FuzzParseDigest(f *testing.F) {
	// Seed corpus with valid and edge cases
	f.Add("sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	f.Add("sha512:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	f.Add("sha256:")  // Empty hex
	f.Add(":abc123")   // Empty algorithm
	f.Add("sha256")    // Missing colon
	f.Add("")          // Empty string
	f.Add("md5:abc123") // Invalid algorithm
	f.Add("SHA256:ABCD1234") // Uppercase (might be invalid)

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic or hang
		_, _, err := ParseDigest(input)

		// Either succeeds OR returns error, but no panics
		_ = err
	})
}

// Fuzz test for validation
func FuzzValidateDigest(f *testing.F) {
	f.Add([]byte("test data"), "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	f.Add([]byte(""), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	f.Add([]byte("hello"), "sha512:abc123")

	f.Fuzz(func(t *testing.T, data []byte, digest string) {
		// Must not panic
		err := ValidateDigest(data, digest)
		_ = err // No assertion needed, just shouldn't panic
	})
}
```

**Running Fuzz Tests:**

```bash
# Run for 30 seconds
go test -fuzz=FuzzParseDigest -fuzztime=30s ./internal/registry

# Run with seed corpus
go test -fuzz=FuzzParseDigest -fuzztime=5m ./internal/registry

# Minimize failing inputs
go test -fuzz=FuzzParseDigest ./internal/registry
```

**Security Benefits:**
- Discovers panic conditions
- Finds unexpected input handling
- Validates error paths
- Tests with millions of inputs

---

### 4. Benchmark Tests

**Purpose:** Measure performance of critical paths.

**When to use:**
- Crypto operations (SHA-256, validation)
- I/O operations (large file processing)
- Detecting performance regressions

**Benchmark Pattern:**

```go
func BenchmarkComputeSHA256_SmallData(b *testing.B) {
	data := []byte("test data")

	b.ResetTimer() // Reset timer to exclude setup
	for i := 0; i < b.N; i++ {
		_ = ComputeSHA256(data)
	}
}

func BenchmarkValidateDigest_1MB(b *testing.B) {
	data := make([]byte, 1*1024*1024)
	_, _ = rand.Read(data)
	digest := "sha256:" + ComputeSHA256(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateDigest(data, digest)
	}
}

func BenchmarkValidateDigest_100MB(b *testing.B) {
	data := make([]byte, 100*1024*1024)
	_, _ = rand.Read(data)
	digest := "sha256:" + ComputeSHA256(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateDigest(data, digest)
	}
}
```

**Running Benchmarks:**

```bash
# Run benchmarks
go test -bench=. -benchmem ./internal/registry

# Compare with baseline
go test -bench=. -benchmem ./internal/registry > new.txt
go test -bench=. -benchmem ./internal/registry > old.txt
benchstat old.txt new.txt

# Run specific benchmark
go test -bench=BenchmarkValidateDigest ./internal/registry
```

**Benchmark Considerations:**
- Use `b.ResetTimer()` to exclude setup time
- Test with realistic data sizes
- Test small AND large inputs
- Monitor memory allocations with `-benchmem`

---

### 5. Concurrency Testing

**Purpose:** Detect race conditions and synchronization issues.

**When to use:**
- Testing cache with concurrent access
- Testing locks and semaphores
- Testing goroutine-safe operations

**Race Detection:**

```bash
# Run tests with race detector
go test -race ./internal/cache

# Run all tests with race detection
go test -race ./...
```

**Concurrency Test Pattern (File Locking):**

```go
func TestFileLock_ConcurrentLocking(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")

	var wg sync.WaitGroup
	successCount := 0
	mu := sync.Mutex{} // Protect counter

	// Try to acquire lock from 10 goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			lock := NewFileLock(lockPath)
			if lock.TryLock() {
				defer lock.Unlock()

				mu.Lock()
				successCount++
				mu.Unlock()

				time.Sleep(10 * time.Millisecond) // Hold lock briefly
			}
		}()
	}

	wg.Wait()

	// Only one goroutine should have acquired the lock
	assert.Equal(t, 1, successCount)
}
```

**Concurrency Best Practices:**
- Use `sync.WaitGroup` to synchronize goroutines
- Use `sync.Mutex` to protect shared data
- Always run with `-race` flag
- Test both contention and no-contention scenarios

---

### 6. Table-Driven Tests

**Purpose:** Test multiple scenarios efficiently with a single test function.

**When to use:**
- Testing with many input variations
- Testing matrix of parameters
- Reducing test boilerplate

**Table-Driven Pattern (Digest Parsing):**

```go
func TestParseDigest_ValidFormats(t *testing.T) {
	testCases := []struct {
		name           string
		digest         string
		expectedAlgo   string
		expectedLength int
		shouldFail     bool
	}{
		{
			name:           "valid sha256",
			digest:         "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			expectedAlgo:   "sha256",
			expectedLength: 64,
			shouldFail:     false,
		},
		{
			name:           "valid sha512",
			digest:         "sha512:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			expectedAlgo:   "sha512",
			expectedLength: 128,
			shouldFail:     false,
		},
		{
			name:       "invalid digest format",
			digest:     "nocolon",
			shouldFail: true,
		},
		{
			name:       "unsupported algorithm",
			digest:     "md5:abc123",
			shouldFail: true,
		},
		{
			name:       "empty hex",
			digest:     "sha256:",
			shouldFail: true,
		},
		{
			name:       "empty algorithm",
			digest:     ":abc123",
			shouldFail: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			algo, hex, err := ParseDigest(tc.digest)

			if tc.shouldFail {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedAlgo, algo)
				assert.Len(t, hex, tc.expectedLength)
			}
		})
	}
}
```

**Table-Driven Benefits:**
- Easy to add new test cases
- Clear test scenario names
- Reduces code duplication
- Easy to spot patterns in test data

---

### 7. Platform-Specific Tests

**Purpose:** Test code that behaves differently on different operating systems.

**When to use:**
- Testing cgroups (Linux only)
- Testing Job Objects (Windows only)
- Testing rlimits (UNIX only)

**Build Tags Pattern:**

```go
// +build linux
package sandbox

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestLinuxSandbox_CgroupsLimits(t *testing.T) {
	sandbox := NewLinuxSandbox("/tmp", cpuLimit, memoryLimit)

	// Test cgroups-specific functionality
	assert.NotNil(t, sandbox.cgroupPath)
}

// +build darwin
package sandbox

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestDarwinSandbox_RlimitsOnly(t *testing.T) {
	sandbox := NewDarwinSandbox("/tmp", cpuLimit, memoryLimit)

	// Test rlimit-only functionality
	assert.NotNil(t, sandbox)
}
```

**Running Platform-Specific Tests:**

```bash
# Run only Linux tests
GOOS=linux go test -v ./internal/sandbox

# Run only macOS tests
GOOS=darwin go test -v ./internal/sandbox

# Run all tests on current platform
go test -v ./...
```

---

### 8. HTTP Server Mocking

**Purpose:** Test code that makes HTTP requests without real network calls.

**When to use:**
- Testing registry client
- Testing auth header handling
- Testing error scenarios

**httptest Pattern:**

```go
func TestRegistryClient_ResolvePackage(t *testing.T) {
	// Create mock registry server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/packages/acme/hello-world/resolve", r.URL.Path)

		// Check auth header
		auth := r.Header.Get("Authorization")
		assert.NotEmpty(t, auth)
		assert.Contains(t, auth, "Bearer ")

		// Return response
		response := map[string]interface{}{
			"manifest": map[string]string{
				"digest": "sha256:abc123...",
				"url":    server.URL + "/manifests/sha256:abc123",
			},
			"bundle": map[string]string{
				"digest": "sha256:def456...",
				"url":    server.URL + "/bundles/sha256:def456",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create client pointing to mock server
	client := NewClient(server.URL, "dummy-token")

	// Test
	result, err := client.Resolve("acme/hello-world", "1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "sha256:abc123...", result.Manifest.Digest)
}
```

**httptest Features:**
- Returns mock URL you can use with your client
- Captures requests for assertion
- Can return custom responses
- Automatic cleanup with defer

---

### 9. Security Test Patterns

**Critical Security Assertions:**

#### Nil Input Validation

```go
func TestValidateDigest_NilInput(t *testing.T) {
	// Must never accept nil data
	err := ValidateDigest(nil, "sha256:abc123")
	assert.Error(t, err)
}
```

#### Empty Input Validation

```go
func TestValidateDigest_EmptyExpected(t *testing.T) {
	data := []byte("test content")

	// Must reject empty digest
	err := ValidateDigest(data, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}
```

#### Resource Limit Enforcement

```go
// CRITICAL SECURITY TEST: Execution without limits must NEVER be allowed
func TestNewSTDIOExecutor_RejectsNilLimits(t *testing.T) {
	_, err := NewSTDIOExecutor("/tmp", nil, nil)
	if err == nil {
		t.Fatal("CRITICAL SECURITY FAILURE: NewSTDIOExecutor accepted nil limits")
	}
}

func TestNewSTDIOExecutor_RejectsZeroMaxCPU(t *testing.T) {
	limits := &policy.ExecutionLimits{
		MaxCPU:    0, // Invalid
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}

	_, err := NewSTDIOExecutor("/tmp", limits, nil)
	if err == nil {
		t.Fatal("CRITICAL SECURITY FAILURE: NewSTDIOExecutor accepted zero MaxCPU")
	}
}
```

#### Malicious Input Testing

```go
func TestParseDigest_MaliciousInputs(t *testing.T) {
	testCases := []string{
		"sha256:'; DROP TABLE manifests; --",
		"sha256:../../../etc/passwd",
		"sha256:" + strings.Repeat("a", 1000),
		"sha256:\x00\x01\x02",
		"sha256:" + strings.Repeat("0", 64) + "EXTRA",
	}

	for _, input := range testCases {
		t.Run(input[:20], func(t *testing.T) {
			_, _, err := ParseDigest(input)
			// Should either reject or handle gracefully
			// Never panic or crash
			_ = err
		})
	}
}
```

---

## Test Coverage Goals

### Coverage Targets

- **Overall:** >70% line coverage
- **Critical security modules:** >85% coverage
  - `internal/registry/digest.go`
  - `internal/executor/executor.go`
  - `internal/policy/policy.go`
  - `internal/sandbox/*.go`
- **Configuration:** >80% coverage
- **Audit logging:** >80% coverage

### Measuring Coverage

```bash
# Generate coverage report
go test -cover ./...

# Generate detailed coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Check coverage of specific package
go test -cover ./internal/registry
```

### Coverage Interpretation

```
coverage: 87.5% of statements
```

- Statements cover assignments, loops, conditionals
- Aim for branch coverage (if/else, error paths)
- Test both success and error paths

---

## Common Mistakes & Fixes

### Mistake 1: Not Testing Error Paths

Bad:
```go
func TestParseDigest(t *testing.T) {
	algo, hex, _ := ParseDigest("sha256:abcd...")
	assert.Equal(t, "sha256", algo)
}
```

Good:
```go
func TestParseDigest_Success(t *testing.T) {
	algo, hex, err := ParseDigest("sha256:abcd...")
	require.NoError(t, err)
	assert.Equal(t, "sha256", algo)
}

func TestParseDigest_Invalid(t *testing.T) {
	_, _, err := ParseDigest("invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid format")
}
```

### Mistake 2: Missing Race Detection

Bad:
```bash
go test ./...
```

Good:
```bash
go test -race ./...
```

Always run with `-race` flag to catch synchronization bugs.

### Mistake 3: Weak Assertions

Bad:
```go
assert.NotNil(t, result) // Doesn't verify correctness
```

Good:
```go
require.NotNil(t, result)        // Must succeed
assert.Equal(t, expected, result) // Verify exact value
assert.Contains(t, result, part)  // Verify content
```

### Mistake 4: Not Using Table-Driven Tests

Bad:
```go
func TestParseDigest_SHA256(t *testing.T) { ... }
func TestParseDigest_SHA512(t *testing.T) { ... }
func TestParseDigest_Invalid1(t *testing.T) { ... }
func TestParseDigest_Invalid2(t *testing.T) { ... }
// Lots of duplicate code
```

Good:
```go
func TestParseDigest(t *testing.T) {
	testCases := []struct {
		name       string
		digest     string
		shouldFail bool
	}{
		{"sha256", "sha256:...", false},
		{"sha512", "sha512:...", false},
		{"invalid1", "nocolon", true},
		{"invalid2", "md5:abc", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) { ... })
	}
}
```

### Mistake 5: Hardcoding Paths

Bad:
```go
err := ioutil.WriteFile("/tmp/test", data, 0600)
```

Good:
```go
tmpDir := t.TempDir()
testFile := filepath.Join(tmpDir, "test")
err := ioutil.WriteFile(testFile, data, 0600)
```

Use `t.TempDir()` for automatic cleanup.

### Mistake 6: Not Cleaning Up Resources

Bad:
```go
server := httptest.NewServer(handler)
// No defer, server stays running
```

Good:
```go
server := httptest.NewServer(handler)
defer server.Close()
```

Always use defer for cleanup.

---

## Test Organization

### File Naming Convention

```
internal/
  registry/
    digest.go              # Implementation
    digest_test.go         # Unit tests
    digest_fuzz_test.go    # Fuzz tests
    digest_bench_test.go   # Benchmark tests
```

### Test Structure

```
// Unit tests
TestFunctionName_Scenario
TestFunctionName_ErrorPath
TestFunctionName_EdgeCase

// Fuzz tests
FuzzFunctionName

// Benchmark tests
BenchmarkFunctionName_ScenarioSize
```

### Example Test File Structure

```go
package registry

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Table-driven tests for multiple scenarios
func TestParseDigest_ValidFormats(t *testing.T) { ... }

// Specific test for error cases
func TestParseDigest_InvalidFormat(t *testing.T) { ... }

// Specific test for security concern
func TestParseDigest_MaliciousInput(t *testing.T) { ... }

// Integration test
func TestValidateDigest_WithRealData(t *testing.T) { ... }
```

---

## Running Tests Effectively

### Commands

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run with race detection
go test -race ./...

# Run specific test
go test -run TestParseDigest ./internal/registry

# Run specific test with pattern
go test -run Test.*/Invalid ./internal/registry

# Run benchmarks
go test -bench=. -benchmem ./internal/registry

# Run fuzz tests
go test -fuzz=FuzzParseDigest -fuzztime=30s ./internal/registry

# Run tests in parallel
go test -parallel 8 ./...

# Run with coverage
go test -cover ./...

# Combine flags
go test -race -cover -v ./...
```

### CI/CD Integration

```yaml
# GitHub Actions example
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      # Run all tests with race detection
      - run: go test -race -cover ./...

      # Run fuzz tests (5 minutes)
      - run: go test -fuzz=. -fuzztime=5m ./...

      # Generate coverage report
      - run: go test -coverprofile=coverage.out ./...
      - uses: codecov/codecov-action@v3
```

---

## Summary Checklist

- [ ] Write unit tests for all functions (success + error paths)
- [ ] Use table-driven tests for multiple scenarios
- [ ] Include fuzz tests for input validation
- [ ] Add benchmarks for performance-critical code
- [ ] Run tests with `-race` flag for concurrency issues
- [ ] Test platform-specific code with build tags
- [ ] Mock external dependencies (HTTP, filesystem)
- [ ] Aim for >70% overall, >85% critical modules coverage
- [ ] Include security-specific tests (nil inputs, limits, malicious data)
- [ ] Document non-obvious test scenarios with comments
