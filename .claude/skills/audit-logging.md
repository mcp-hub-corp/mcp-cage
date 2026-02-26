# Audit Logging Skill

Expert knowledge for implementing comprehensive security audit logging in the mcp-client launcher.

## Overview

Audit logging is the non-repudiation and accountability layer. It:
1. Records every execution attempt (success, failure, timeout)
2. Captures critical metadata for security investigation
3. Redacts sensitive information (secrets, private data)
4. Ensures log immutability and completeness
5. Enables forensic analysis of what code was executed

## Audit Trail Requirements

### CRITICAL Principles

1. **Non-Repudiation**: Launcher cannot deny an execution happened
2. **Completeness**: Every start must have a corresponding end record
3. **Immutability**: Logs must not be modified after writing (append-only)
4. **Completeness**: No execution gaps or missing entries
5. **Accuracy**: Timestamps must be precise and synchronized
6. **Privacy**: Secret values MUST NEVER appear in logs (only variable names)

## JSON Structured Logging

### Format

Each log entry is a complete JSON object on a single line:

```
{"timestamp":"2026-01-18T10:30:00.123Z","event":"start","..."}
{"timestamp":"2026-01-18T10:30:05.456Z","event":"end","..."}
```

**Never multiple lines per entry. One entry = one line.**

### Timestamp Format

Always use ISO 8601 with millisecond precision and UTC timezone:

```
Format: 2006-01-02T15:04:05.000Z07:00
Example: 2026-01-18T10:30:00.123Z

// Go code
timestamp := time.Now().UTC().Format(time.RFC3339Nano)
```

### File Format

```
~/.smcp/audit.log

File permissions: 0600 (owner read/write only)
Append-only: always append, never truncate or modify
Encoding: UTF-8, one JSON object per line
```

## Event Types

### 1. Start Event (audit.start)

Records the beginning of execution.

```json
{
  "timestamp": "2026-01-18T10:30:00.123Z",
  "event": "start",
  "package": "acme/hello-world",
  "version": "1.2.3",
  "digest": "sha256:abc123def456...",
  "git_sha": "abc123def456abc123def456abc123def456abc1",
  "entrypoint": "/bin/mcp-server",
  "transport": "stdio",
  "host": "macOS-laptop",
  "user": "dani",
  "pid": 12345,
  "policy_summary": {
    "cpu_millicores": 1000,
    "memory_bytes": 536870912,
    "timeout_seconds": 300,
    "network_default_deny": true,
    "subprocess_allowed": false
  }
}
```

**Required Fields:**
- `timestamp`: ISO 8601 UTC timestamp
- `event`: "start"
- `package`: org/name format
- `version`: semantic version
- `digest`: sha256:... manifest digest
- `git_sha`: (optional) git commit hash of launcher binary
- `entrypoint`: command to execute
- `transport`: "stdio" or "http"
- `pid`: process ID
- `user`: username of executor
- `policy_summary`: policy applied (summary only, not detailed)

**Policy Summary (High-Level Only):**
```json
{
  "cpu_millicores": 1000,
  "memory_bytes": 536870912,
  "max_pids": 32,
  "max_fds": 256,
  "timeout_seconds": 300,
  "network_default_deny": true,
  "network_allowlist_count": 3,  // Count only, not the list
  "subprocess_allowed": false,
  "env_filter_mode": "allowlist",  // "allowlist" or "blocklist"
  "env_var_count": 8  // Count only
}
```

### 2. End Event (audit.end)

Records successful completion.

```json
{
  "timestamp": "2026-01-18T10:30:05.456Z",
  "event": "end",
  "package": "acme/hello-world",
  "version": "1.2.3",
  "digest": "sha256:abc123def456...",
  "exit_code": 0,
  "outcome": "success",
  "duration_seconds": 5.333,
  "pid": 12345,
  "signal": null
}
```

**Required Fields:**
- `timestamp`: ISO 8601 UTC timestamp
- `event`: "end"
- `package`: org/name format
- `version`: semantic version
- `digest`: sha256:... manifest digest
- `exit_code`: numeric exit code (0-255)
- `outcome`: "success", "timeout", "killed", "error"
- `duration_seconds`: floating-point duration
- `pid`: process ID (must match start event)
- `signal`: null or signal number if killed by signal

**Outcome Values:**
- `success`: Exit code 0
- `timeout`: context.DeadlineExceeded (exit code 5)
- `killed`: SIGKILL or SIGTERM received (exit code 124)
- `error`: Non-zero exit code (exit code 1-4)

### 3. Error Event (audit.error)

Records execution failures.

```json
{
  "timestamp": "2026-01-18T10:30:00.500Z",
  "event": "error",
  "package": "acme/hello-world",
  "version": "1.2.3",
  "digest": "sha256:abc123def456...",
  "error_type": "validation_error",
  "error_message": "manifest validation failed",
  "error_details": "entrypoint not found for linux-amd64",
  "stage": "manifest_validation",
  "pid": null,
  "severity": "critical"
}
```

**Required Fields:**
- `timestamp`: ISO 8601 UTC timestamp
- `event`: "error"
- `package`: org/name format
- `version`: semantic version (may be "unknown" if resolution failed)
- `digest`: sha256:... manifest digest (may be null if resolution failed)
- `error_type`: error classification
- `error_message`: user-friendly error message
- `error_details`: technical details for investigation
- `stage`: "validation", "policy", "sandbox", "execution", "cleanup"
- `pid`: process ID (null if never started)
- `severity`: "critical", "warning"

**Error Types:**
```
resolution_error      // Registry lookup failed
download_error        // Manifest/bundle download failed
validation_error      // Manifest validation failed
policy_error          // Policy application failed
sandbox_error         // Sandbox setup failed
execution_error       // Process execution failed
timeout_error         // Process exceeded timeout
resource_error        // Resource limit exceeded
network_error         // Network operation failed
file_error            // File system operation failed
permission_error      // Permission denied
io_error              // I/O operation failed
unknown_error         // Uncategorized error
```

## Secret Redaction

### CRITICAL: Never Log Secret Values

This is the most critical audit requirement.

**WRONG - DO NOT DO THIS:**
```json
{
  "event": "start",
  "env": "API_KEY=super-secret-123456"  // NEVER!
}

{
  "event": "start",
  "secrets": {"API_KEY": "super-secret-123456"}  // NEVER!
}
```

**CORRECT:**
```json
{
  "event": "start",
  "env_allowlist": ["PATH", "HOME", "API_KEY"],  // Names only
  "env_count": 8
}
```

### Redaction Rules

**1. Environment Variables:**
```go
// WRONG - logs value
log.Infof("Setting env: API_KEY=%s", value)

// CORRECT - logs only name
log.Infof("Setting env: API_KEY (value redacted)")

// In audit logs, only include:
{
  "event": "start",
  "env_filter": {
    "mode": "allowlist",
    "count": 8
  }
}
```

**2. Secrets:**
```go
// WRONG - logs value
for name, value := range secrets {
    log.Infof("Secret %s=%s", name, value)
}

// CORRECT - logs only name
for name := range secrets {
    log.Infof("Secret %s (value redacted)", name)
}

// In audit logs:
{
  "event": "start",
  "secrets_count": 3  // Only count, never values
}
```

**3. Credentials:**
```go
// WRONG
log.Infof("Auth token: %s", token)

// CORRECT
log.Infof("Auth token: *** (redacted)")

// In audit logs:
{
  "event": "start",
  "auth_used": "token"  // Type only
}
```

**4. Network Allowlist:**
```go
// WRONG - might reveal sensitive domains
{
  "event": "start",
  "network_allowlist": ["internal.corp.com", "10.0.1.0/24"]
}

// CORRECT - count only
{
  "event": "start",
  "network_allowlist_count": 2
}
```

### Redaction Implementation

```go
// RedactedLogger wraps logger to prevent accidental secret logging
type RedactedLogger struct {
    inner *slog.Logger
    mu    sync.Mutex
}

// secretPatterns matches common secret patterns
var secretPatterns = []*regexp.Regexp{
    regexp.MustCompile(`(password|passwd|pwd)\s*=\s*\S+`),
    regexp.MustCompile(`(token|apikey|api_key)\s*=\s*\S+`),
    regexp.MustCompile(`(secret|token)\s*:\s*\S+`),
    regexp.MustCompile(`(authorization|auth)\s*:\s*Bearer\s+\S+`),
}

// SanitizeLogMessage removes secrets from log messages
func SanitizeLogMessage(msg string) string {
    for _, pattern := range secretPatterns {
        msg = pattern.ReplaceAllString(msg, "$1=(redacted)")
    }
    return msg
}

func (rl *RedactedLogger) Log(level slog.Level, msg string, args ...interface{}) {
    sanitized := SanitizeLogMessage(msg)
    rl.inner.Log(level, sanitized, args...)
}
```

## File Permissions and Access

### Audit Log File Permissions

```bash
# Unix/Linux/macOS
ls -la ~/.smcp/audit.log
-rw------- 1 dani staff 102400 Jan 18 10:30 /Users/dani/.mcp/audit.log

# Permissions: 0600 (owner read/write, no others)
```

### Permission Setting in Go

```go
// CreateAuditLog creates audit log file with correct permissions
func CreateAuditLog(path string) (*os.File, error) {
    // Create file with restrictive permissions
    f, err := os.OpenFile(
        path,
        os.O_CREATE|os.O_APPEND|os.O_WRONLY,
        0600, // rw------- (owner only)
    )
    if err != nil {
        return nil, err
    }

    // Verify permissions are correct
    info, err := f.Stat()
    if err != nil {
        return nil, err
    }

    mode := info.Mode()
    if mode.Perm() != 0600 {
        return nil, fmt.Errorf("audit log has insecure permissions: %o", mode.Perm())
    }

    return f, nil
}

// VerifyAuditLogSecure checks that audit log has correct permissions
func VerifyAuditLogSecure(path string) error {
    info, err := os.Stat(path)
    if err != nil {
        return err
    }

    mode := info.Mode()

    // Check permissions
    if mode.Perm() != 0600 {
        return fmt.Errorf("audit log permissions insecure: %o (expected 0600)", mode.Perm())
    }

    // Check it's a regular file
    if !mode.IsDir() && mode&os.ModeSymlink == 0 {
        return fmt.Errorf("audit log is not a regular file")
    }

    return nil
}
```

## Thread-Safety and Concurrency

### Mutex-Protected Logging

```go
// AuditLogger is thread-safe audit logger
type AuditLogger struct {
    mu   sync.Mutex
    file *os.File
}

// Log writes a single audit event (thread-safe)
func (al *AuditLogger) Log(event interface{}) error {
    al.mu.Lock()
    defer al.mu.Unlock()

    data, err := json.Marshal(event)
    if err != nil {
        return fmt.Errorf("failed to marshal event: %w", err)
    }

    // Write JSON followed by newline (atomic)
    n, err := al.file.Write(append(data, '\n'))
    if err != nil {
        return fmt.Errorf("failed to write audit log: %w", err)
    }

    if n != len(data)+1 {
        return fmt.Errorf("partial write to audit log")
    }

    // Flush to disk (important for durability)
    if err := al.file.Sync(); err != nil {
        return fmt.Errorf("failed to sync audit log: %w", err)
    }

    return nil
}

// LogStart logs start event (thread-safe)
func (al *AuditLogger) LogStart(event StartEvent) error {
    return al.Log(event)
}

// LogEnd logs end event (thread-safe)
func (al *AuditLogger) LogEnd(event EndEvent) error {
    return al.Log(event)
}

// LogError logs error event (thread-safe)
func (al *AuditLogger) LogError(event ErrorEvent) error {
    return al.Log(event)
}
```

### Concurrent Write Testing

```go
func TestAuditLogger_ConcurrentWrites(t *testing.T) {
    // Create audit logger
    f, err := ioutil.TempFile("", "audit")
    assert.NoError(t, err)
    defer os.Remove(f.Name())

    logger := &AuditLogger{file: f}

    // Write events concurrently
    var wg sync.WaitGroup
    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()

            event := StartEvent{
                Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
                Event: "start",
                Package: fmt.Sprintf("test/pkg-%d", id),
            }

            if err := logger.LogStart(event); err != nil {
                t.Errorf("LogStart failed: %v", err)
            }
        }(i)
    }

    wg.Wait()

    // Verify all events were written
    content, _ := ioutil.ReadFile(f.Name())
    lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
    assert.Equal(t, 100, len(lines))

    // Verify all lines are valid JSON
    for _, line := range lines {
        var event map[string]interface{}
        assert.NoError(t, json.Unmarshal(line, &event))
    }
}
```

## Event Structures

### Go Struct Definitions

```go
// StartEvent is logged when execution begins
type StartEvent struct {
    Timestamp    string                 `json:"timestamp"`
    Event        string                 `json:"event"` // "start"
    Package      string                 `json:"package"`
    Version      string                 `json:"version"`
    Digest       string                 `json:"digest"`
    GitSha       string                 `json:"git_sha,omitempty"`
    Entrypoint   string                 `json:"entrypoint"`
    Transport    string                 `json:"transport"` // "stdio" or "http"
    Host         string                 `json:"host"`
    User         string                 `json:"user"`
    PID          int                    `json:"pid"`
    PolicySummary PolicySummary          `json:"policy_summary"`
}

// EndEvent is logged when execution completes
type EndEvent struct {
    Timestamp   string `json:"timestamp"`
    Event       string `json:"event"` // "end"
    Package     string `json:"package"`
    Version     string `json:"version"`
    Digest      string `json:"digest"`
    ExitCode    int    `json:"exit_code"`
    Outcome     string `json:"outcome"` // "success", "timeout", "killed", "error"
    DurationSec float64 `json:"duration_seconds"`
    PID         int    `json:"pid"`
    Signal      *int   `json:"signal"` // null if not killed by signal
}

// ErrorEvent is logged when execution fails
type ErrorEvent struct {
    Timestamp    string `json:"timestamp"`
    Event        string `json:"event"` // "error"
    Package      string `json:"package"`
    Version      string `json:"version"`
    Digest       string `json:"digest,omitempty"`
    ErrorType    string `json:"error_type"`
    ErrorMessage string `json:"error_message"`
    ErrorDetails string `json:"error_details"`
    Stage        string `json:"stage"`
    PID          *int   `json:"pid"` // null if not started
    Severity     string `json:"severity"` // "critical" or "warning"
}

// PolicySummary contains high-level policy info (no secrets)
type PolicySummary struct {
    CPUMillicores         int    `json:"cpu_millicores"`
    MemoryBytes           uint64 `json:"memory_bytes"`
    MaxPIDs               int    `json:"max_pids"`
    MaxFDs                int    `json:"max_fds"`
    TimeoutSeconds        int    `json:"timeout_seconds"`
    NetworkDefaultDeny    bool   `json:"network_default_deny"`
    NetworkAllowlistCount int    `json:"network_allowlist_count"`
    SubprocessAllowed     bool   `json:"subprocess_allowed"`
    EnvFilterMode         string `json:"env_filter_mode"`
    EnvVarCount           int    `json:"env_var_count"`
}
```

## ISO 8601 Timestamps

### Correct Timestamp Generation

```go
// GetTimestamp returns current time in ISO 8601 with milliseconds
func GetTimestamp() string {
    // Go's RFC3339Nano format includes nanoseconds
    // Example: 2006-01-02T15:04:05.000000000Z07:00
    timestamp := time.Now().UTC().Format(time.RFC3339Nano)

    // If you want exactly 3 decimal places (milliseconds) instead of 9 (nanoseconds):
    return formatTimestampMS(timestamp)
}

// formatTimestampMS converts RFC3339Nano to 3-digit milliseconds
func formatTimestampMS(nanoTimestamp string) string {
    // Example input: 2026-01-18T10:30:00.123456789Z
    // Example output: 2026-01-18T10:30:00.123Z

    // Parse with nanosecond precision
    t, err := time.Parse(time.RFC3339Nano, nanoTimestamp)
    if err != nil {
        return nanoTimestamp // Fallback if parsing fails
    }

    // Format with 3 decimal places (milliseconds)
    return t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// Example usage
func TestTimestampFormat(t *testing.T) {
    ts := GetTimestamp()

    // Verify it's valid ISO 8601
    _, err := time.Parse(time.RFC3339, ts)
    assert.NoError(t, err)

    // Verify 3 decimal places
    assert.Regexp(t, `\.\d{3}Z$`, ts)
}
```

### Ensuring Synchronization

```go
// TimeSource provides consistent timestamps
type TimeSource interface {
    Now() time.Time
}

// SystemTimeSource uses system clock
type SystemTimeSource struct{}

func (s *SystemTimeSource) Now() time.Time {
    return time.Now().UTC()
}

// MockTimeSource for testing
type MockTimeSource struct {
    mu   sync.Mutex
    time time.Time
}

func (m *MockTimeSource) Now() time.Time {
    m.mu.Lock()
    defer m.mu.Unlock()
    return m.time
}

// AuditLogger uses TimeSource
type AuditLogger struct {
    mu   sync.Mutex
    file *os.File
    time TimeSource
}

func (al *AuditLogger) LogStart(pkg string) error {
    event := StartEvent{
        Timestamp: al.time.Now().UTC().Format(time.RFC3339Nano),
        Event: "start",
        Package: pkg,
    }

    return al.Log(event)
}
```

## Duration Formatting

### Accurate Duration Recording

```go
// RecordDuration calculates and formats duration
func RecordDuration(startTime, endTime time.Time) float64 {
    duration := endTime.Sub(startTime)

    // Return seconds as floating point (e.g., 5.333)
    return duration.Seconds()
}

// Example
startTime := time.Now()
// ... execute process
endTime := time.Now()
durationSec := RecordDuration(startTime, endTime)

event := EndEvent{
    Timestamp: endTime.UTC().Format(time.RFC3339Nano),
    DurationSec: durationSec,
}
```

## Outcome Determination

### Determining Outcome from Exit Code

```go
// DetermineOutcome maps exit code and error to outcome string
func DetermineOutcome(exitCode int, err error) string {
    if err == nil && exitCode == 0 {
        return "success"
    }

    if errors.Is(err, context.DeadlineExceeded) {
        return "timeout"
    }

    // Check for signal-based termination
    if exitErr, ok := err.(*exec.ExitError); ok {
        if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
            if status.Signaled() {
                signal := status.Signal()
                if signal == syscall.SIGKILL || signal == syscall.SIGTERM {
                    return "killed"
                }
            }
        }
    }

    return "error"
}

// Example
exitCode := extractExitCode(processErr)
outcome := DetermineOutcome(exitCode, processErr)

// outcomes: "success", "error", "timeout", "killed"
```

## Complete Execution Logging Example

```go
// LogExecutionFlow shows complete logging from start to end
func LogExecutionFlow() {
    logger := GetAuditLogger()
    timeSource := &SystemTimeSource{}

    // 1. Log start event
    startTime := timeSource.Now()
    startEvent := StartEvent{
        Timestamp: startTime.UTC().Format(time.RFC3339Nano),
        Event: "start",
        Package: "acme/hello-world",
        Version: "1.2.3",
        Digest: "sha256:abc123...",
        Entrypoint: "/bin/server",
        Transport: "stdio",
        Host: os.Getenv("HOSTNAME"),
        User: getCurrentUser(),
        PID: os.Getpid(),
        PolicySummary: PolicySummary{
            CPUMillicores: 1000,
            MemoryBytes: 512*1024*1024,
            MaxPIDs: 32,
            TimeoutSeconds: 300,
            NetworkDefaultDeny: true,
            NetworkAllowlistCount: 2,
            SubprocessAllowed: false,
            EnvFilterMode: "allowlist",
            EnvVarCount: 8,
        },
    }
    logger.LogStart(startEvent)

    // 2. Execute process
    cmd := exec.Command("/bin/server")
    var exitCode int
    var exitErr error

    cmdErr := cmd.Run()
    exitCode = extractExitCode(cmdErr)
    exitErr = cmdErr

    // 3. Calculate duration
    endTime := timeSource.Now()
    duration := RecordDuration(startTime, endTime)

    // 4. Determine outcome
    outcome := DetermineOutcome(exitCode, exitErr)

    // 5. Log end event
    endEvent := EndEvent{
        Timestamp: endTime.UTC().Format(time.RFC3339Nano),
        Event: "end",
        Package: "acme/hello-world",
        Version: "1.2.3",
        Digest: "sha256:abc123...",
        ExitCode: exitCode,
        Outcome: outcome,
        DurationSec: duration,
        PID: os.Getpid(),
        Signal: extractSignal(exitErr), // nil if no signal
    }
    logger.LogEnd(endEvent)

    // 6. On error, also log error event
    if exitErr != nil {
        errorEvent := ErrorEvent{
            Timestamp: endTime.UTC().Format(time.RFC3339Nano),
            Event: "error",
            Package: "acme/hello-world",
            Version: "1.2.3",
            Digest: "sha256:abc123...",
            ErrorType: classifyError(exitErr),
            ErrorMessage: exitErr.Error(),
            ErrorDetails: formatErrorDetails(exitErr),
            Stage: "execution",
            PID: intPtr(os.Getpid()),
            Severity: classifySeverity(exitErr),
        }
        logger.LogError(errorEvent)
    }
}
```

## Testing Audit Logging

### Unit Tests

**1. Event Serialization:**
```go
func TestStartEvent_ValidJSON(t *testing.T) {
    event := StartEvent{
        Timestamp: "2026-01-18T10:30:00.123Z",
        Event: "start",
        Package: "test/pkg",
        Version: "1.0.0",
        Digest: "sha256:abc123",
        PID: 12345,
    }

    data, err := json.Marshal(event)
    assert.NoError(t, err)

    var unmarshaled StartEvent
    err = json.Unmarshal(data, &unmarshaled)
    assert.NoError(t, err)
    assert.Equal(t, event, unmarshaled)
}

func TestEndEvent_OutcomeValues(t *testing.T) {
    outcomes := []string{"success", "error", "timeout", "killed"}

    for _, outcome := range outcomes {
        event := EndEvent{
            Timestamp: "2026-01-18T10:30:05Z",
            Event: "end",
            Outcome: outcome,
        }

        data, _ := json.Marshal(event)
        assert.NotNil(t, data)
    }
}
```

**2. Secret Redaction:**
```go
func TestSecretRedaction_NeverLogsValues(t *testing.T) {
    secretValue := "super-secret-api-key-12345"
    logOutput := &strings.Builder{}

    logger := slog.New(slog.NewTextHandler(logOutput, nil))
    logger.Info("env var", "name", "API_KEY")  // Name only

    assert.NotContains(t, logOutput.String(), secretValue)
}

func TestSanitizeLogMessage_RemovesSecrets(t *testing.T) {
    tests := []struct {
        input    string
        contains string
        notContains string
    }{
        {
            input: "password=secret123",
            notContains: "secret123",
        },
        {
            input: "Authorization: Bearer abc123def456",
            notContains: "abc123def456",
        },
    }

    for _, tt := range tests {
        sanitized := SanitizeLogMessage(tt.input)
        assert.NotContains(t, sanitized, tt.notContains)
    }
}
```

**3. Timestamp Validation:**
```go
func TestTimestamp_ValidISO8601(t *testing.T) {
    ts := GetTimestamp()

    // Should parse as RFC3339
    _, err := time.Parse(time.RFC3339, ts)
    assert.NoError(t, err)

    // Should have millisecond precision (3 decimal places)
    assert.Regexp(t, `\.\d{3}Z`, ts)
}

func TestTimestamp_UTCTimezone(t *testing.T) {
    ts := GetTimestamp()

    // Should end with Z (UTC indicator)
    assert.True(t, strings.HasSuffix(ts, "Z"))
}
```

**4. File Permissions:**
```go
func TestAuditLogFile_SecurePermissions(t *testing.T) {
    dir := t.TempDir()
    logPath := filepath.Join(dir, "audit.log")

    f, err := CreateAuditLog(logPath)
    assert.NoError(t, err)
    defer f.Close()

    info, err := os.Stat(logPath)
    assert.NoError(t, err)

    // Check permissions are 0600
    assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
```

**5. Concurrent Writes:**
```go
func TestAuditLogger_ConcurrentWrites_NoCorruption(t *testing.T) {
    dir := t.TempDir()
    logPath := filepath.Join(dir, "audit.log")

    f, _ := CreateAuditLog(logPath)
    logger := &AuditLogger{file: f}

    var wg sync.WaitGroup
    for i := 0; i < 50; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()

            event := StartEvent{
                Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
                Event: "start",
                Package: fmt.Sprintf("pkg-%d", id),
                PID: id,
            }

            logger.LogStart(event)
        }(i)
    }

    wg.Wait()
    f.Close()

    // Verify log file can be read and parsed
    content, _ := ioutil.ReadFile(logPath)
    lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))

    for _, line := range lines {
        var event map[string]interface{}
        err := json.Unmarshal(line, &event)
        assert.NoError(t, err, "line not valid JSON: %s", string(line))
    }

    // Verify all events written
    assert.Equal(t, 50, len(lines))
}
```

### Integration Tests

**1. Full Audit Trail:**
```go
func TestAuditTrail_CompleteFlow(t *testing.T) {
    dir := t.TempDir()
    logPath := filepath.Join(dir, "audit.log")

    f, _ := CreateAuditLog(logPath)
    logger := &AuditLogger{file: f}

    // Log start
    startEvent := StartEvent{
        Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
        Event: "start",
        Package: "test/pkg",
        Version: "1.0.0",
        PID: 99999,
    }
    logger.LogStart(startEvent)

    // Simulate execution
    time.Sleep(100 * time.Millisecond)

    // Log end
    endEvent := EndEvent{
        Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
        Event: "end",
        Package: "test/pkg",
        Version: "1.0.0",
        ExitCode: 0,
        Outcome: "success",
        DurationSec: 0.1,
        PID: 99999,
    }
    logger.LogEnd(endEvent)

    f.Close()

    // Verify audit trail
    content, _ := ioutil.ReadFile(logPath)
    lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))

    assert.Equal(t, 2, len(lines))

    var startLogged, endLogged bool
    for _, line := range lines {
        var event map[string]interface{}
        json.Unmarshal(line, &event)

        if event["event"].(string) == "start" {
            startLogged = true
        }
        if event["event"].(string) == "end" {
            endLogged = true
        }
    }

    assert.True(t, startLogged, "start event not logged")
    assert.True(t, endLogged, "end event not logged")
}
```

## Common Mistakes and Anti-Patterns

### Mistake 1: Logging Secret Values
**WRONG:**
```go
log.Infof("API_KEY=%s", apiKey) // NEVER!
auditLog.ApiKey = apiKey // NEVER!
```

**CORRECT:**
```go
log.Infof("API_KEY=(redacted)")
// Don't include value in audit logs
```

### Mistake 2: Not Using Timestamps Consistently
**WRONG:**
```go
timestamp := time.Now().String() // Inconsistent format
```

**CORRECT:**
```go
timestamp := time.Now().UTC().Format(time.RFC3339Nano)
```

### Mistake 3: Not Protecting Audit Log File
**WRONG:**
```go
f, _ := os.Create(path) // Default permissions!
```

**CORRECT:**
```go
f, _ := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
```

### Mistake 4: Logging Incomplete Events
**WRONG:**
```go
// Log start but forget to log end
logger.LogStart(event)
// ... process runs ...
// Missing logger.LogEnd()
```

**CORRECT:**
```go
logger.LogStart(event)
// ... process runs ...
logger.LogEnd(event)
```

### Mistake 5: Not Syncing to Disk
**WRONG:**
```go
f.WriteString(line)
// Power fails - event lost!
```

**CORRECT:**
```go
f.WriteString(line)
f.Sync() // Ensure written to disk
```

### Mistake 6: Race Conditions in Concurrent Logging
**WRONG:**
```go
f.WriteString(line1)
// Another goroutine writes: f.WriteString(line2)
// Result: interleaved output (corrupted)
```

**CORRECT:**
```go
mu.Lock()
defer mu.Unlock()
f.WriteString(line)
f.Sync()
```

### Mistake 7: Not Capturing All Error Details
**WRONG:**
```json
{
  "event": "error",
  "error_message": "failed"
  // No context about what failed!
}
```

**CORRECT:**
```json
{
  "event": "error",
  "error_type": "sandbox_error",
  "error_message": "sandbox setup failed",
  "error_details": "cgroup limit not available",
  "stage": "sandbox"
}
```

### Mistake 8: Using Local Time Instead of UTC
**WRONG:**
```go
timestamp := time.Now().Format(time.RFC3339) // Local timezone!
```

**CORRECT:**
```go
timestamp := time.Now().UTC().Format(time.RFC3339)
```

## Security Checklist

For audit logging implementation:

- [ ] All execution events have both start and end records
- [ ] Timestamps are ISO 8601 UTC format
- [ ] Exit codes properly extracted and recorded
- [ ] Outcomes correctly determined (success/error/timeout/killed)
- [ ] Durations calculated in floating-point seconds
- [ ] Process IDs match between start and end events
- [ ] No secret values appear in any log entries
- [ ] File permissions set to 0600 (owner read/write only)
- [ ] Concurrent writes are mutex-protected
- [ ] All writes include Sync() for durability
- [ ] Audit log is append-only (never truncated/modified)
- [ ] Error events include stage and classification
- [ ] Policy summary includes only counts, not actual policies
- [ ] Network allowlist logged as count only
- [ ] Environment variables logged as count/mode, not values
- [ ] Log file integrity verified on startup

## References

- CLAUDE.md Section 3: Threat Model
- CLAUDE.md Section 4: Security Invariants
- security-policy.md: Policy enforcement
- process-execution.md: Process lifecycle
