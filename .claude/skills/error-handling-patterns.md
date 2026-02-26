# Go Error Handling Patterns

## Overview

This skill covers best practices for error handling in Go, tailored to the mcp-client project. Error handling is critical for security (never expose secrets), user experience (clear messages), and reliability (proper propagation and recovery).

**mcp-client context:** Errors come from registry failures, digest validation, manifest parsing, sandbox setup, policy enforcement, and executor timeouts. Each error type must map to a specific exit code and user-facing message.

---

## Core Principles

1. **Error Wrapping with `%w`:** Always wrap errors with context
2. **Explicit Error Checking:** Never ignore errors silently
3. **No Secrets in Logs:** Redact sensitive data (tokens, file paths)
4. **User-Friendly Messages:** Technical errors → clear CLI output
5. **Proper Exit Codes:** Exit code reflects error category
6. **Error Type Checking:** Use `errors.Is()` and `errors.As()` for specific handling

---

## Error Wrapping: fmt.Errorf with %w

**Good:** Wrap errors with context and preserve the original error chain.

```go
// From internal/registry/client.go
func (c *Client) Resolve(ctx context.Context, org, name, ref string) (*ResolveResponse, error) {
	if org == "" {
		return nil, fmt.Errorf("org cannot be empty")
	}

	// Wrap network error with context
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s/%s@%s: %w", org, name, ref, err)
	}

	if resp.StatusCode != http.StatusOK {
		// Don't just return the HTTP error; wrap it
		return nil, fmt.Errorf("registry returned %d for %s/%s@%s: %w",
			resp.StatusCode, org, name, ref, errors.New("request failed"))
	}

	return &resp, nil
}
```

**Key Points:**
- Use `%w` to wrap the underlying error, not `%v`
- Add context: what operation failed, which package, what ref
- Don't expose internals: "request failed" is better than full stack trace

**Using errors.Unwrap():**

```go
// Unwrap to access the underlying error
err := someOperation()
underlyingErr := errors.Unwrap(err)

// Useful when you need to log the original error without the wrapper
if underlyingErr != nil {
	log.Printf("root cause: %v", underlyingErr)
}
```

---

## Sentinel Errors: var ErrXxx = errors.New()

Sentinel errors are predefined errors that you compare against using `errors.Is()`. Use them for **expected failure conditions** that callers need to handle specially.

### When to Use Sentinel Errors

```go
// From internal/registry/errors.go - DO NOT use sentinel for dynamic errors!

// Use sentinel errors for specific, expected conditions:
var (
	// Good: callers may want to handle "not found" specially
	ErrPackageNotFound = errors.New("package not found in registry")

	// Good: callers may want to retry on "too many requests"
	ErrRateLimited = errors.New("registry rate limit exceeded")

	// Good: callers may want to re-authenticate
	ErrUnauthorized = errors.New("authentication required")
)

// Bad: don't use sentinels for dynamic errors
var ErrInvalidDigest = errors.New("invalid digest") // Too generic

// Better: use custom error types for rich context (see Error Types section)
type InvalidDigestError struct {
	Expected string
	Got      string
}
```

### Checking Sentinel Errors

```go
// Good: use errors.Is() to check
err := someOperation()
if errors.Is(err, ErrPackageNotFound) {
	return fmt.Errorf("package not in registry, check name: %w", err)
}

// Bad: don't use == because error wrapping won't work
if err == ErrPackageNotFound { // WRONG! Won't catch wrapped errors
	// ...
}

// Good: sentinel errors work with wrapped errors
func resolveWithFallback(ref string) error {
	result, err := registry.Resolve(ref)
	if errors.Is(err, ErrPackageNotFound) {
		// Check local cache as fallback
		return checkLocalCache(ref)
	}
	return err
}
```

### mcp-client Registry Sentinels

```go
// internal/registry/errors.go
var (
	// Package resolution failures
	ErrPackageNotFound = errors.New("package not found")
	ErrVersionNotFound = errors.New("version not found")
	ErrAccessDenied = errors.New("access denied")

	// Network/transport issues (retryable)
	ErrTimeout = errors.New("request timeout")
	ErrNetworkError = errors.New("network error")

	// Validation failures (not retryable)
	ErrDigestMismatch = errors.New("digest mismatch")
	ErrManifestInvalid = errors.New("manifest schema invalid")
)
```

---

## Error Types: Custom Errors with Error() Method

Use **custom error types** when you need to attach structured data to an error. This allows callers to extract details using `errors.As()`.

### Anatomy of a Custom Error Type

```go
// From internal/registry/errors.go
type Error struct {
	Code    int    // HTTP status code
	Message string // User-facing message
	Err     error  // Underlying error (for wrapping)
}

// Implement the error interface
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%d] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

// Implement Unwrap for error wrapping
func (e *Error) Unwrap() error {
	return e.Err
}

// Add domain-specific methods (no need to type-assert)
func (e *Error) IsRetryable() bool {
	return e.Code >= http.StatusInternalServerError // 5xx errors
}

func (e *Error) IsAuthError() bool {
	return e.Code == http.StatusUnauthorized || e.Code == http.StatusForbidden
}

// Constructor
func NewError(code int, message string, err error) *Error {
	return &Error{Code: code, Message: message, Err: err}
}
```

### Using Custom Error Types with errors.As()

```go
// Caller can extract structured data
err := someOperation()

// Good: use errors.As() to check
var registryErr *Error
if errors.As(err, &registryErr) {
	// Now we have access to Code, Message, IsRetryable(), etc.
	if registryErr.IsRetryable() {
		return retryWithBackoff()
	}

	if registryErr.IsAuthError() {
		return fmt.Errorf("authentication failed: %s", registryErr.Message)
	}
}

// Bad: type assertion without checking
if regErr := err.(*Error); regErr != nil { // WRONG! panics if nil
	// ...
}
```

### mcp-client Custom Error Types

```go
// internal/manifest/error.go
type ValidationError struct {
	Field   string // e.g., "entrypoints[2].command"
	Message string // e.g., "required field missing"
	Value   string // actual value (or empty if missing)
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("manifest validation failed: %s - %s", e.Field, e.Message)
}

// Caller usage
var valErr *ValidationError
if errors.As(err, &valErr) {
	fmt.Printf("Error in field %q: %s\n", valErr.Field, valErr.Message)
}

// Batch validation errors
type ValidationErrors []ValidationError

func (es ValidationErrors) Error() string {
	var msgs []string
	for _, e := range es {
		msgs = append(msgs, e.Error())
	}
	return strings.Join(msgs, "; ")
}
```

---

## Error Context: Adding Information Without Exposing Secrets

**Never log or display:**
- Authentication tokens (JWT, API keys, Bearer tokens)
- Environment variable values (except names)
- File paths containing user home directory
- Network credentials
- Private key material

**Always log or display:**
- Package name and version
- Error category (e.g., "network error", "validation error")
- Relevant field names (for validation errors)
- User-friendly hints ("check package name" vs "package org/name not found")

### Good Error Context

```go
// Good: descriptive context without secrets
func (c *Client) downloadWithAuth(ctx context.Context, url string, token string) ([]byte, error) {
	// BAD: never do this
	// return nil, fmt.Errorf("failed to download from %s with token %s", url, token)

	// GOOD: expose operation and URL, not token
	if err := validateURL(url); err != nil {
		return nil, fmt.Errorf("invalid manifest URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for manifest: %w", err)
	}

	// Never include token in error messages
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download manifest from %s: %w", url, err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed: token may be invalid or expired")
	}

	return io.ReadAll(resp.Body)
}
```

### Logging Errors Without Secrets

```go
// Use structured logging (slog) to redact sensitive fields
logger.Error("authentication failed",
	slog.String("package", "org/name"),
	slog.String("registry", "registry.example.com"),
	slog.Int("http_status", 401),
	// slog.String("token", token) // NEVER DO THIS
)

// If you need to log a token for debugging, use a redacted version
redactedToken := token[:10] + "...[" + strconv.Itoa(len(token)-10) + " chars]"
logger.Debug("token details", slog.String("token_prefix", redactedToken))
```

---

## Exit Code Mapping: Error → Exit Code

Define exit codes for different error categories. Used in main.go or CLI root command.

```go
// From mcp-client specification

const (
	ExitSuccess         = 0
	ExitConfigError     = 1  // Config file not found, invalid flags
	ExitNetworkError    = 2  // Registry unreachable, download failed
	ExitValidationError = 3  // Digest mismatch, manifest invalid
	ExitExecutionError  = 4  // Process failed, signal received
	ExitTimeout         = 5  // Timeout exceeded
	ExitSignalTerm      = 124 // SIGTERM received (bash convention)
)

// Mapping errors to exit codes
func exitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}

	// Check for custom error types
	var registryErr *Error
	if errors.As(err, &registryErr) {
		if registryErr.Code == 401 || registryErr.Code == 403 {
			return ExitValidationError // Invalid credentials
		}
		if registryErr.Code >= 500 {
			return ExitNetworkError // Server error (retryable)
		}
		if registryErr.Code == 404 {
			return ExitValidationError // Package not found
		}
	}

	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		return ExitValidationError
	}

	// Check for sentinel errors
	if errors.Is(err, context.DeadlineExceeded) {
		return ExitTimeout
	}
	if errors.Is(err, context.Canceled) {
		return ExitSignalTerm
	}

	// Default to execution error
	return ExitExecutionError
}

// Usage in main.go
func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(exitCode(err))
	}
}
```

---

## Nil Checks: Proper Nil Error Checking

Go's zero value for errors is `nil`, not an empty error. Always check for `nil` before calling methods on errors.

### Good Nil Checking

```go
// Good: check err != nil
if err := operation(); err != nil {
	// Handle error
	return fmt.Errorf("operation failed: %w", err)
}

// Good: use defer for cleanup, even if err is nil
defer func() {
	if err != nil {
		logger.Error("cleanup failed", slog.String("error", err.Error()))
	}
}()

// Good: separate error from successful result
data, err := fetchData()
if err != nil {
	return nil, err
}
// Now safe to use data

// Bad: ignore error
_ = operation() // This is sometimes OK for cleanup, but always document why

// Bad: don't assume nested errors exist
if err.Error() == "" { } // WRONG! err might be nil → panic

// Good: nil-safe error message
msg := ""
if err != nil {
	msg = err.Error()
}
```

### Nil Pointer Dereference Prevention

```go
// Bad: might panic if err is nil after unwrapping
err := someOperation()
wrapped := errors.Unwrap(err) // might be nil!
msg := wrapped.Error()         // PANIC!

// Good: check before dereferencing
err := someOperation()
if underlying := errors.Unwrap(err); underlying != nil {
	msg := underlying.Error()
	// ...
}

// Good: when working with custom error types
var customErr *Error
if errors.As(err, &customErr) && customErr != nil {
	// Safe to use customErr methods
	if customErr.IsRetryable() { }
}
```

---

## Error Propagation: When to Wrap, Replace, or Ignore

### When to Wrap: Add Context, Keep Original Error

```go
// Do: wrap errors with context
func resolvePackage(ref string) (*Package, error) {
	manifest, err := downloadManifest(ref)
	if err != nil {
		// Wrap: adds context about what we were doing
		return nil, fmt.Errorf("failed to resolve %s: %w", ref, err)
	}
	return parseManifest(manifest)
}

// Do: wrap external API errors with local context
func (c *Client) validateBundle(digest string) error {
	sha256, err := hashFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to validate bundle %s: %w", digest[:16], err)
	}
	return nil
}

// Good: multiple wraps create an error chain for debugging
func downloadAndValidate(ref string) error {
	manifestBytes, err := downloadManifest(ref)
	if err != nil {
		return fmt.Errorf("failed to download manifest for %s: %w", ref, err)
	}

	if err := validateDigest(manifestBytes); err != nil {
		return fmt.Errorf("invalid manifest digest for %s: %w", ref, err)
	}

	return nil
}
// Caller sees full chain: "invalid manifest digest for pkg@1.0 → failed to download ... → network timeout"
```

### When to Replace: Translate Errors

```go
// Do: replace with domain-specific error
func selectEntrypoint(manifest *Manifest) (*Entrypoint, error) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	for _, ep := range manifest.Entrypoints {
		if ep.OS == goos && ep.Arch == goarch {
			return &ep, nil
		}
	}

	// Replace: user cares about what's supported, not iteration details
	return nil, fmt.Errorf(
		"no entrypoint for %s/%s; supported: %v",
		goos, goarch, listSupportedPlatforms(manifest),
	)
}

// Do: replace library errors with user-friendly messages
func parseConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// User-friendly: specific suggestion
			return nil, fmt.Errorf(
				"config file not found at %s; create with: smcp init",
				path,
			)
		}
		// Generic: wrap permission errors
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	return unmarshalConfig(data)
}

// Do: replace panics (if you must recover)
func safeParseJSON(data []byte) (*Data, error) {
	defer func() {
		if r := recover(); r != nil {
			// Replace panic with error
			err = fmt.Errorf("JSON parsing panicked: %v", r)
		}
	}()

	var d Data
	err := json.Unmarshal(data, &d)
	return &d, err
}
```

### When to Ignore: Document Why

```go
// Acceptable: cleanup operations that shouldn't block
defer func() {
	_ = cacheStore.Close() // Best-effort cleanup
}()

// Acceptable: non-critical logging
if err := auditLogger.LogEvent(event); err != nil {
	logger.Warn("audit logging failed", slog.String("error", err.Error()))
	// Continue execution; audit failure shouldn't break the app
}

// Wrong: silently ignoring critical errors
_ = validateDigest(data) // This MUST NOT be ignored!

// Right: explicitly document why error is ignored
_ = conn.Close() // Ignore: connection closing is best-effort
```

---

## Logging Errors: What to Log, What Not

### Good Error Logging

```go
// Use structured logging (slog)
logger.Error("failed to validate digest",
	slog.String("package", "acme/tool"),
	slog.String("digest_expected", expectedDigest[:16]+"..."),
	slog.String("digest_got", gotDigest[:16]+"..."),
	slog.String("error", err.Error()),
)

// Debug level: more detail
logger.Debug("resolve request details",
	slog.String("registry_url", "https://registry.example.com"),
	slog.String("package", "acme/tool"),
	slog.String("ref", "1.2.3"),
	// slog.String("auth_token", token) // NEVER
)

// Warn level: recoverable errors
logger.Warn("retrying failed request",
	slog.Int("attempt", 2),
	slog.Duration("backoff", 100*time.Millisecond),
	slog.String("error", err.Error()),
)
```

### Bad Error Logging (DON'T DO THIS)

```go
// Bad: logging full errors with secrets
logger.Error("Auth failed: " + err.Error()) // Might include token!

// Bad: logging request bodies with credentials
logger.Debug("Request: " + string(requestBytes)) // Exposes Authorization header!

// Bad: logging full file paths in user homes
logger.Info("Using config: " + configPath) // Exposes /Users/username/

// Bad: unclear error messages
logger.Error("Error") // No context!

// Bad: logging at wrong level
logger.Debug("Critical security validation failed: ...") // Should be Error!
```

---

## User-Friendly Messages: Technical vs User-Facing

Errors shown to users (via CLI stdout/stderr) should be different from internal errors (in logs).

### User-Facing Error Messages

```go
// CLI command should catch errors and format for users
func runMCPServer(cmd *cobra.Command, args []string) error {
	// Internal error handling
	err := executeServer()

	// User-facing error formatting
	if errors.Is(err, ErrPackageNotFound) {
		var regErr *Error
		if errors.As(err, &regErr) {
			fmt.Fprintf(os.Stderr, "Error: Package not found in registry\n")
			fmt.Fprintf(os.Stderr, "  Package: %s\n", packageRef)
			fmt.Fprintf(os.Stderr, "  Hint: Check package name is correct (org/name@version)\n")
			fmt.Fprintf(os.Stderr, "  Registry: %s\n", cfg.RegistryURL)
			return err // Return error for exit code
		}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintf(os.Stderr, "Error: Execution timeout exceeded (5m)\n")
		fmt.Fprintf(os.Stderr, "  Hint: Package took too long to initialize\n")
		fmt.Fprintf(os.Stderr, "  Fix: Increase timeout with --timeout flag\n")
		return err
	}

	// Generic error for unexpected failures
	fmt.Fprintf(os.Stderr, "Error: Failed to execute MCP server\n")
	if cfg.LogLevel == "debug" {
		fmt.Fprintf(os.Stderr, "  Details: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "  Hint: Run with --log-level debug for more information\n")

	return err
}
```

### Internal Error Messages

```go
// Logs can be more technical
logger.Error("package resolution failed",
	slog.String("package", "acme/tool"),
	slog.String("error", err.Error()),
	slog.String("registry_response", responseBody), // OK in logs, not in CLI
)
```

---

## Testing Errors: errors.Is, errors.As, Messages

```go
// From internal/registry/errors_test.go

func TestErrorsAreRetryable(t *testing.T) {
	// Test error methods
	err := NewError(http.StatusInternalServerError, "server error", nil)
	if !err.RetryableError() {
		t.Error("expected error to be retryable")
	}
}

func TestErrorChaining(t *testing.T) {
	// Test error wrapping
	originalErr := errors.New("connection refused")
	wrappedErr := fmt.Errorf("failed to resolve package: %w", originalErr)

	if !errors.Is(wrappedErr, originalErr) {
		t.Error("error chain broken")
	}
}

func TestSentinelErrors(t *testing.T) {
	// Test sentinel error detection
	err := fmt.Errorf("operation failed: %w", ErrPackageNotFound)

	if !errors.Is(err, ErrPackageNotFound) {
		t.Error("sentinel error not detected in wrapped error")
	}
}

func TestCustomErrorTypeAssertion(t *testing.T) {
	// Test errors.As() with custom types
	err := NewError(404, "not found", nil)

	var registryErr *Error
	if !errors.As(err, &registryErr) {
		t.Fatal("expected to extract custom error type")
	}

	if registryErr.Code != 404 {
		t.Errorf("expected code 404, got %d", registryErr.Code)
	}
}

func TestErrorMessageFormatting(t *testing.T) {
	// Test error message is user-friendly
	err := NewError(401, "authentication required", nil)
	msg := err.Error()

	if !strings.Contains(msg, "401") || !strings.Contains(msg, "authentication") {
		t.Errorf("error message missing key info: %s", msg)
	}
}

func TestErrorWithoutWrappedError(t *testing.T) {
	// Test error works without underlying error
	err := NewError(500, "internal server error", nil)

	if err.Unwrap() != nil {
		t.Error("expected nil unwrapped error")
	}

	// Message should still be useful
	msg := err.Error()
	if msg == "" {
		t.Error("error message should not be empty")
	}
}
```

---

## Common Mistakes and How to Avoid Them

### 1. Ignoring Errors

```go
// BAD: silently ignoring critical errors
manifestBytes, _ := downloadManifest(ref)
parseManifest(manifestBytes) // manifestBytes might be nil!

// GOOD: always handle errors
manifestBytes, err := downloadManifest(ref)
if err != nil {
	return fmt.Errorf("failed to download: %w", err)
}
parseManifest(manifestBytes)

// BAD: ignoring validation
_ = registry.ValidateDigest(bundleData) // SECURITY ISSUE!

// GOOD: fail on validation error
if err := registry.ValidateDigest(bundleData); err != nil {
	return fmt.Errorf("bundle integrity check failed: %w", err)
}
```

### 2. Wrapping Too Many Times

```go
// BAD: excessive wrapping layers
err := operation()
if err != nil {
	return fmt.Errorf("step 1 failed: %w", err)
}
return fmt.Errorf("step 2 failed: %w", fmt.Errorf("step 3 failed: %w", err))

// GOOD: wrap once with full context
err := operation()
if err != nil {
	return fmt.Errorf("failed to download and validate manifest for %s: %w", ref, err)
}

// GOOD: wrap at each layer if context is new
data, err := fetchManifest(ref)
if err != nil {
	return fmt.Errorf("failed to fetch manifest: %w", err)
}

if err := validate(data); err != nil {
	return fmt.Errorf("manifest validation failed for %s: %w", ref, err)
}
```

### 3. Exposing Internals

```go
// BAD: exposing internal paths
if err := writeToFile(path, data); err != nil {
	return fmt.Errorf("write failed: %w", err)
}

// GOOD: hide internal details
if err := writeToFile(path, data); err != nil {
	return fmt.Errorf("failed to cache manifest: %w", err)
}

// BAD: exposing library internals
return fmt.Errorf("yaml parsing error at line %d: %w", line, err)

// GOOD: translate to domain language
return fmt.Errorf("manifest schema error: invalid field: %w", err)
```

### 4. Type Assertions Without Checking

```go
// BAD: panics if error type doesn't match
customErr := err.(*CustomError)
msg := customErr.Message // PANIC if err is not *CustomError!

// GOOD: use errors.As()
var customErr *CustomError
if errors.As(err, &customErr) {
	msg := customErr.Message
}

// BAD: comparing with == instead of errors.Is()
if err == ErrNotFound {} // Doesn't work with wrapped errors

// GOOD: use errors.Is()
if errors.Is(err, ErrNotFound) {} // Works with wrapped errors
```

### 5. Losing Error Information

```go
// BAD: error is lost
data, _ := downloadManifest(ref)
if data == nil {
	return fmt.Errorf("download failed") // Lost the original error!
}

// GOOD: preserve error information
data, err := downloadManifest(ref)
if err != nil {
	return fmt.Errorf("failed to download manifest: %w", err) // Original error preserved
}

// BAD: replacing with generic error
if !validate(data) {
	return fmt.Errorf("validation failed") // What specifically failed?
}

// GOOD: include details
if !validate(data) {
	return fmt.Errorf("validation failed: manifest missing required field 'package.version'")
}
```

---

## Real Code Examples: mcp-client Modules

### registry/client.go Error Handling

```go
// Wrapping network errors with context
func (c *Client) Resolve(ctx context.Context, org, name, ref string) (*ResolveResponse, error) {
	if org == "" || name == "" {
		return nil, fmt.Errorf("org and name are required")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.resolveURL(org, name, ref), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resolve request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Wrap network error
		return nil, fmt.Errorf("failed to resolve %s/%s@%s: %w", org, name, ref, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Use custom error type for structured response
		return nil, NewError(resp.StatusCode, "resolve failed", fmt.Errorf("%s", string(body)))
	}

	var result ResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse resolve response: %w", err)
	}

	return &result, nil
}
```

### manifest/parser.go Error Handling

```go
// Returning validation errors with field information
func Validate(manifest *Manifest) error {
	if manifest == nil {
		return fmt.Errorf("manifest cannot be nil")
	}

	// Validate fields with field path
	if manifest.Package.ID == "" {
		return fmt.Errorf("package.id is required")
	}

	// Validate entrypoints with index
	for i, ep := range manifest.Entrypoints {
		if ep.Command == "" {
			return fmt.Errorf("entrypoints[%d].command is required", i)
		}
	}

	return nil
}
```

### CLI Error Handling

```go
// From internal/cli/run.go - error propagation with context
func runMCPServer(cmd *cobra.Command, args []string) error {
	ref := args[0]

	// Parse with context
	org, name, version, err := parsePackageRef(ref)
	if err != nil {
		return fmt.Errorf("invalid package reference %q: %w", ref, err)
	}

	// Resolve with context
	resolveResp, err := registryClient.Resolve(ctx, org, name, version)
	if err != nil {
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, err.Error())
		}
		return fmt.Errorf("failed to resolve package: %w", err)
	}

	return nil
}
```

---

## Summary Checklist

- [x] Use `fmt.Errorf` with `%w` to wrap errors
- [x] Use `errors.Is()` for sentinel error checks
- [x] Use `errors.As()` for custom error type extraction
- [x] Define custom error types for rich context
- [x] Never log or display secrets (tokens, credentials, paths)
- [x] Always check `err != nil` before dereferencing
- [x] Map errors to exit codes (0, 1, 2, 3, 4, 5, 124)
- [x] Provide user-friendly messages in CLI output
- [x] Test error chains with `errors.Is()` and `errors.As()`
- [x] Avoid wrapping errors too many times
- [x] Don't ignore critical errors (validation, security)
- [x] Use structured logging (slog) for error details
