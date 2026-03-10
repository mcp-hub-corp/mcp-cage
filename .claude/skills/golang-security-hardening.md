# Go Security Hardening: Comprehensive Reference

**Expert knowledge for writing secure Go code** - covering input validation, injection prevention, cryptography, memory safety, concurrency, and common vulnerabilities specific to Go applications.

Essential for mcp-cage's security posture and applicable to any Go project prioritizing security.

---

## Table of Contents

1. [Input Validation Patterns](#input-validation-patterns)
2. [Injection Prevention](#injection-prevention)
3. [Constant-Time Operations](#constant-time-operations)
4. [Secure Random Generation](#secure-random-generation)
5. [Memory Safety](#memory-safety)
6. [Integer and Arithmetic Safety](#integer-and-arithmetic-safety)
7. [Concurrency & Race Conditions](#concurrency--race-conditions)
8. [Panic Recovery & Error Handling](#panic-recovery--error-handling)
9. [Dependency Security](#dependency-security)
10. [Static Analysis & SAST Tools](#static-analysis--sast-tools)
11. [Secret Management](#secret-management)
12. [Error Message Safety](#error-message-safety)
13. [Resource Exhaustion Prevention](#resource-exhaustion-prevention)
14. [Denial of Service Prevention](#denial-of-service-prevention)
15. [Security Testing](#security-testing)
16. [Common Vulnerabilities & Mitigations](#common-vulnerabilities--mitigations)
17. [Go-Specific Vulnerabilities](#go-specific-vulnerabilities)
18. [Security Checklist](#security-checklist)
19. [Real-World mcp-cage Patterns](#real-world-mcp-cage-patterns)

---

## Input Validation Patterns

### Fundamental Rules

**Rule 1: Whitelist > Blacklist**
- Whitelist (positive) validation is always safer than blacklist (negative)
- Allows you to explicitly define what IS acceptable
- Blacklist requires knowing ALL bad patterns (impossible)

**Rule 2: Validate Early & Consistently**
- Validate at entry points (CLI, HTTP, file parsing)
- Re-validate if data is modified or comes from new source
- Don't assume internal functions receive valid input

**Rule 3: Defense in Depth**
- Use multiple validation layers
- Each layer catches different error types

### Pattern: Whitelist Validation

```go
// WRONG: Blacklist approach (incomplete)
func ValidateName(name string) bool {
	return !strings.Contains(name, ";") &&
		!strings.Contains(name, "&") &&
		!strings.Contains(name, "|")
	// Still misses many injection vectors!
}

// CORRECT: Whitelist approach
func ValidateName(name string) bool {
	if name == "" {
		return false
	}
	if len(name) > 255 {
		return false
	}
	// Only allow alphanumeric, dash, underscore
	for _, ch := range name {
		if !isNameCharacter(ch) {
			return false
		}
	}
	return true
}

func isNameCharacter(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '-' || ch == '_'
}
```

### Pattern: Length Limits

```go
// WRONG: No length validation
func ProcessInput(input string) error {
	data := strings.Split(input, ",")
	for _, item := range data {
		// Processes each item
		process(item)
	}
	return nil
}

// CORRECT: Length validation
const (
	MaxInputLength    = 10 * 1024      // 10 KB
	MaxItemCount      = 1000
	MaxItemLength     = 1024
)

func ProcessInput(input string) error {
	// Check total length
	if len(input) > MaxInputLength {
		return fmt.Errorf("input exceeds maximum length %d", MaxInputLength)
	}

	data := strings.Split(input, ",")

	// Check item count
	if len(data) > MaxItemCount {
		return fmt.Errorf("too many items: %d (max %d)", len(data), MaxItemCount)
	}

	for _, item := range data {
		// Check each item length
		if len(item) > MaxItemLength {
			return fmt.Errorf("item exceeds maximum length %d", MaxItemLength)
		}
		if err := process(item); err != nil {
			return err
		}
	}
	return nil
}
```

### Pattern: Character Set Validation

```go
// WRONG: Assumes strings are safe
func ValidateEmail(email string) bool {
	return strings.Contains(email, "@")
}

// CORRECT: Strict character set
func ValidateEmail(email string) bool {
	// Use regex or explicit character validation
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !re.MatchString(email) {
		return false
	}
	if len(email) > 254 { // RFC 5321
		return false
	}
	return true
}

// Character set validation for package names (mcp-cage pattern)
func ValidatePackageName(name string) error {
	if name == "" {
		return errors.New("package name cannot be empty")
	}
	if len(name) > 255 {
		return errors.New("package name too long")
	}

	parts := strings.Split(name, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid package format: expected 'org/name', got '%s'", name)
	}

	for _, part := range parts {
		if !isValidOrgOrName(part) {
			return fmt.Errorf("invalid package segment: %q", part)
		}
	}
	return nil
}

func isValidOrgOrName(segment string) bool {
	if segment == "" {
		return false
	}
	for _, ch := range segment {
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-') {
			return false
		}
	}
	// Cannot start/end with dash
	return segment[0] != '-' && segment[len(segment)-1] != '-'
}
```

### Pattern: Semantic Validation

```go
// WRONG: Syntactically valid but semantically invalid
func ScheduleTask(duration time.Duration) error {
	task := NewTask(duration)
	task.Execute() // What if duration is 0 or negative?
	return nil
}

// CORRECT: Semantic validation
func ScheduleTask(duration time.Duration) error {
	const (
		MinDuration = 100 * time.Millisecond
		MaxDuration = 24 * time.Hour
	)

	if duration < MinDuration {
		return fmt.Errorf("duration too short: %v (min: %v)", duration, MinDuration)
	}
	if duration > MaxDuration {
		return fmt.Errorf("duration too long: %v (max: %v)", duration, MaxDuration)
	}

	task := NewTask(duration)
	task.Execute()
	return nil
}
```

---

## Injection Prevention

### Command Injection

**Rule: Never pass user input directly to shell. Use exec.Command with args array.**

```go
import "os/exec"

// WRONG: User input in shell command (CRITICAL VULNERABILITY)
func RunCommand(userInput string) error {
	cmd := exec.Command("sh", "-c", "echo "+userInput)
	// If userInput = "; rm -rf /", this executes deletion!
	return cmd.Run()
}

// CORRECT: Arguments array (safe from shell injection)
func RunCommand(userInput string) error {
	// Validate input first
	if err := ValidateInput(userInput); err != nil {
		return err
	}
	// Use args array - shell metacharacters treated as literals
	cmd := exec.Command("echo", userInput)
	return cmd.Run()
}

func ValidateInput(input string) error {
	if len(input) > 1024 {
		return errors.New("input too long")
	}
	// Whitelist safe characters
	for _, ch := range input {
		if !((ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == ' ' || ch == '-') {
			return fmt.Errorf("unsupported character: %c", ch)
		}
	}
	return nil
}
```

**mcp-cage Pattern: Bundle Execution**

```go
// CORRECT: Safe entrypoint execution
func (e *Executor) executeBundle(entrypoint *Manifest.Entrypoint, args []string) error {
	// Never construct command string
	// Always use args array
	allArgs := append([]string{}, entrypoint.Args...)
	allArgs = append(allArgs, args...)

	cmd := exec.Command(entrypoint.Command, allArgs...)
	return cmd.Run()
}

// NOT:
// cmd := exec.Command("sh", "-c", entrypoint.Command + " " + strings.Join(args, " "))
```

### Path Injection

**Rule: Use filepath.Clean, reject "..", validate components separately.**

```go
import "path/filepath"

// WRONG: Path traversal vulnerability
func ReadConfig(userPath string) ([]byte, error) {
	// User could provide "../../../etc/passwd"
	data, err := ioutil.ReadFile(userPath)
	return data, err
}

// CORRECT: Clean and validate path
func ReadConfig(userPath string) ([]byte, error) {
	// Validate length first
	if len(userPath) > 4096 {
		return nil, errors.New("path too long")
	}

	// Clean the path
	cleanPath := filepath.Clean(userPath)

	// Reject absolute paths
	if filepath.IsAbs(cleanPath) {
		return nil, errors.New("absolute paths not allowed")
	}

	// Reject path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return nil, errors.New("path traversal detected")
	}

	// Reject sensitive paths
	if strings.HasPrefix(cleanPath, ".") {
		return nil, errors.New("hidden paths not allowed")
	}

	// Ensure path stays within allowed directory
	basePath := "/app/config"
	absolutePath := filepath.Join(basePath, cleanPath)
	cleanAbsolute := filepath.Clean(absolutePath)

	if !strings.HasPrefix(cleanAbsolute, filepath.Clean(basePath)) {
		return nil, errors.New("path escapes allowed directory")
	}

	data, err := ioutil.ReadFile(cleanAbsolute)
	return data, err
}

// CORRECT: Component-by-component validation
func ValidatePathComponents(path string) error {
	components := strings.Split(path, string(filepath.Separator))
	for _, comp := range components {
		// Reject empty, "..", "."
		if comp == "" || comp == ".." || comp == "." {
			continue // empty is OK between slashes
		}
		if strings.Contains(comp, "..") {
			return errors.New("parent directory reference detected")
		}
		// Reject hidden files
		if strings.HasPrefix(comp, ".") {
			return errors.New("hidden files not allowed")
		}
	}
	return nil
}
```

**mcp-cage Pattern: Bundle Extraction**

```go
// CORRECT: Safe tar extraction with path validation
func extractBundle(tarReader *tar.Reader, destDir string) error {
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Validate file path
		if err := validateTarPath(header.Name); err != nil {
			return fmt.Errorf("invalid path in archive: %w", err)
		}

		// Ensure path stays within destination
		targetPath := filepath.Join(destDir, header.Name)
		if !strings.HasPrefix(filepath.Clean(targetPath), filepath.Clean(destDir)) {
			return errors.New("path escapes destination directory")
		}

		if header.IsDir() {
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return err
			}
		} else {
			if err := extractFile(tarReader, targetPath, header.FileInfo().Mode()); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateTarPath(path string) error {
	if path == "" {
		return errors.New("empty path in archive")
	}
	if strings.HasPrefix(path, "/") {
		return errors.New("absolute path in archive")
	}
	if strings.Contains(path, "..") {
		return errors.New("parent directory reference in archive")
	}
	return nil
}
```

### Template Injection

**Rule: Use text/template with automatic escaping for HTML, or html/template for safe HTML output.**

```go
import "text/template"
import "html/template"

// WRONG: Unsafe template with user data
func RenderTemplate(userInput string) (string, error) {
	tmpl, err := template.New("test").Parse("<p>{{.}}</p>")
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, userInput); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// If userInput = "<script>alert('xss')</script>", output is:
// <p><script>alert('xss')</script></p>  <- VULNERABLE!

// CORRECT: html/template auto-escapes
func RenderHTMLTemplate(userInput string) (string, error) {
	// html/template automatically HTML-escapes {{.}}
	tmpl, err := html.ParseFiles("template.html")
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, userInput); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// If userInput = "<script>alert('xss')</script>", output is:
// <p>&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;</p>  <- SAFE!

// CORRECT: Whitelist template structure
func RenderSafeTemplate(name string, version string) (string, error) {
	// Validate inputs before using in template
	if err := ValidatePackageName(name); err != nil {
		return "", err
	}
	if err := ValidateVersion(version); err != nil {
		return "", err
	}

	tmpl, err := template.New("package").Parse(`<p>{{.Name}}/{{.Version}}</p>`)
	if err != nil {
		return "", err
	}

	data := struct {
		Name    string
		Version string
	}{
		Name:    name,
		Version: version,
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
```

### JSON/Unmarshaling Injection

```go
// WRONG: Unmarshal to map without validation
func ProcessJSON(jsonData []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return err
	}
	// No validation - arbitrary keys/values allowed
	for key, value := range data {
		process(key, value)
	}
	return nil
}

// CORRECT: Unmarshal to typed struct with validation
type ManifestConfig struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

func ProcessManifest(jsonData []byte) error {
	// Length limit first
	if len(jsonData) > 1*1024*1024 { // 1 MB max
		return errors.New("manifest too large")
	}

	var config ManifestConfig
	if err := json.Unmarshal(jsonData, &config); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// Validate each field
	if err := ValidatePackageName(config.Name); err != nil {
		return err
	}
	if err := ValidateVersion(config.Version); err != nil {
		return err
	}
	if err := ValidateCommand(config.Command); err != nil {
		return err
	}
	for _, arg := range config.Args {
		if err := ValidateArg(arg); err != nil {
			return err
		}
	}

	return nil
}
```

---

## Constant-Time Operations

### Timing Attack Prevention

**Rule: Use crypto/subtle for comparing secrets. Never use == for security-sensitive data.**

```go
import "crypto/subtle"

// WRONG: Timing attack vulnerability
func VerifyToken(provided string, expected string) bool {
	return provided == expected
	// String comparison stops at first mismatch
	// Timing reveals how many characters matched
	// Attacker can brute-force character by character!
}

// CORRECT: Constant-time comparison
func VerifyToken(provided string, expected string) bool {
	return subtle.ConstantTimeCompare(
		[]byte(provided),
		[]byte(expected),
	) == 1
	// Always compares all bytes regardless of match position
	// Timing is independent of mismatched position
}

// Example: Digest verification (mcp-cage)
func VerifyDigest(computed string, expected string) error {
	if subtle.ConstantTimeCompare(
		[]byte(computed),
		[]byte(expected),
	) != 1 {
		return errors.New("digest mismatch")
	}
	return nil
}
```

### Preventing Timing Leaks in Loops

```go
// WRONG: Early exit on mismatch (timing leak)
func ComparePasswords(provided, stored []byte) bool {
	if len(provided) != len(stored) {
		return false // Reveals length information!
	}
	for i := range provided {
		if provided[i] != stored[i] {
			return false // Leaks position of first mismatch!
		}
	}
	return true
}

// CORRECT: Always compare all bytes
func ComparePasswords(provided, stored []byte) bool {
	// Hash both to fixed length first (prevents length leak)
	providedHash := sha256.Sum256(provided)
	storedHash := sha256.Sum256(stored)
	return subtle.ConstantTimeCompare(providedHash[:], storedHash[:]) == 1
}

// CORRECT: Use bcrypt (handles timing safety)
func VerifyPassword(provided string, hash string) bool {
	return bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(provided),
	) == nil
	// bcrypt is constant-time
}
```

---

## Secure Random Generation

### Rule: Use crypto/rand, Never Use math/rand

```go
import (
	"crypto/rand"
	"math/rand"
)

// WRONG: math/rand is predictable (NOT cryptographically secure)
func GenerateToken() string {
	// math/rand uses system time as seed by default
	// Attacker can predict tokens!
	rand.Seed(time.Now().UnixNano())
	token := rand.Intn(1000000)
	return fmt.Sprintf("%d", token)
}

// CORRECT: crypto/rand for security-sensitive randomness
func GenerateToken() (string, error) {
	const tokenLength = 32 // bytes
	token := make([]byte, tokenLength)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

// CORRECT: Generate random port for HTTP server
func FindRandomPort() (int, error) {
	// Generate random int for port
	buf := make([]byte, 2)
	if _, err := rand.Read(buf); err != nil {
		return 0, err
	}
	// Range: 49152-65535 (ephemeral port range)
	port := 49152 + int(binary.BigEndian.Uint16(buf))%16384
	return port, nil
}
```

### Seeding & Initialization

```go
// WRONG: Predictable initialization
func init() {
	rand.Seed(1) // NEVER hardcode seed!
}

// WRONG: Time-based seed (guessable)
func init() {
	rand.Seed(time.Now().UnixNano())
	// Time granularity is predictable
}

// CORRECT: crypto/rand never needs seeding
// It reads from OS entropy (/dev/urandom on Linux)
// Just import and use crypto/rand.Read()

// Example: mcp-cage secure cache directory
func CreateSecureCache() (string, error) {
	// Generate random suffix to prevent timing attacks
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	suffix := hex.EncodeToString(randomBytes)

	cachePath := filepath.Join(os.ExpandEnv("$HOME/.mcp/cache"), suffix)
	if err := os.MkdirAll(cachePath, 0700); err != nil {
		return "", err
	}
	return cachePath, nil
}
```

### Handling rand.Read Errors

```go
// CORRECT: Never ignore rand.Read errors
func GenerateSecret(length int) ([]byte, error) {
	secret := make([]byte, length)
	_, err := rand.Read(secret)
	if err != nil {
		// rand.Read failed - entropy source is broken
		// Cannot continue securely
		return nil, fmt.Errorf("failed to generate secure random: %w", err)
	}
	return secret, nil
}

// WRONG: Ignoring errors
func GenerateSecret(length int) []byte {
	secret := make([]byte, length)
	rand.Read(secret) // Error ignored!
	return secret
}
```

---

## Memory Safety

### Zeroing Sensitive Data

**Rule: Explicitly zero out sensitive data (passwords, keys, tokens) after use.**

```go
// WRONG: Sensitive data remains in memory
func VerifyPassword(provided string, hash string) bool {
	hashedProvided := hashPassword(provided)
	return hashedProvided == hash
	// String 'provided' stays in memory indefinitely
	// Vulnerable to memory dumps, core dumps
}

// CORRECT: Zero sensitive data explicitly
import "crypto/subtle"

func VerifyPassword(provided string, hash string) bool {
	defer func() {
		// Zero out the string (convert to bytes)
		providedBytes := []byte(provided)
		for i := range providedBytes {
			providedBytes[i] = 0
		}
		// Note: Strings in Go are immutable, can't directly zero
		// But slices can be zeroed
	}()

	hashedProvided := hashPassword(provided)
	return hashedProvided == hash
}

// BETTER: Use byte slices for sensitive data
func VerifyPasswordBytes(provided []byte, hash string) bool {
	defer func() {
		// Zero out immediately after use
		for i := range provided {
			provided[i] = 0
		}
	}()

	hashedProvided := hashPasswordBytes(provided)
	return hashedProvided == hash
}

// BEST: Use a utility function
func ZeroSlice(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func VerifyPasswordSecure(provided []byte, hash string) bool {
	defer ZeroSlice(provided)
	hashedProvided := hashPasswordBytes(provided)
	return hashedProvided == hash
}
```

### API Keys & Secrets

```go
// WRONG: Hardcoded secret
const APIKey = "sk-1234567890abcdef"

func CallAPI() error {
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	req.Header.Set("Authorization", "Bearer "+APIKey)
	// Secret visible in binary, version control, logs
	return nil
}

// CORRECT: Load from secure storage
func GetAPIKey() (string, error) {
	// Load from environment variable
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		return "", errors.New("API_KEY not set")
	}

	// Validate format before using
	if len(apiKey) < 20 {
		return "", errors.New("API_KEY format invalid")
	}

	return apiKey, nil
}

func CallAPI() error {
	apiKey, err := GetAPIKey()
	if err != nil {
		return err
	}

	// Zero out after use
	defer func() {
		keyBytes := []byte(apiKey)
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}()

	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	// ...
	return nil
}
```

### Buffer Management

```go
// WRONG: Reusing buffers with sensitive data
func ReadSecret(reader io.Reader) string {
	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	secret := string(buf[:n])
	// buf still contains the secret in memory
	// If reused elsewhere, leaks data
	return secret
}

// CORRECT: Create new buffer, zero after use
func ReadSecret(reader io.Reader) string {
	buf := make([]byte, 1024)
	defer ZeroSlice(buf)

	n, err := reader.Read(buf)
	if err != nil {
		return ""
	}

	secret := string(buf[:n])
	// buf will be zeroed when function returns
	return secret
}

// CORRECT: Use sync.Pool for temporary buffers (advanced)
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096)
	},
}

func ProcessWithPooledBuffer(data []byte) error {
	buf := bufferPool.Get().([]byte)
	defer func() {
		ZeroSlice(buf)
		bufferPool.Put(buf)
	}()

	// Use buf...
	return nil
}
```

---

## Integer and Arithmetic Safety

### Overflow Detection

```go
// WRONG: No overflow check
func AllocateBuffer(size int) ([]byte, error) {
	return make([]byte, size), nil
	// If size is negative or very large, panics or allocates wrong size
}

// CORRECT: Bounds checking
const MaxBufferSize = 1 << 30 // 1 GB

func AllocateBuffer(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid size: %d", size)
	}
	if size > MaxBufferSize {
		return nil, fmt.Errorf("size exceeds limit: %d > %d", size, MaxBufferSize)
	}
	return make([]byte, size), nil
}

// Arithmetic overflow check
func SafeAdd(a, b int) (int, error) {
	// Check if a + b would overflow
	if a > 0 && b > 0 && a > math.MaxInt-b {
		return 0, errors.New("integer overflow")
	}
	if a < 0 && b < 0 && a < math.MinInt-b {
		return 0, errors.New("integer underflow")
	}
	return a + b, nil
}

// Safe multiplication
func SafeMultiply(a, b int) (int, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	if a > 0 && b > 0 && a > math.MaxInt/b {
		return 0, errors.New("multiplication overflow")
	}
	if a < 0 && b < 0 && a < math.MaxInt/b {
		return 0, errors.New("multiplication overflow")
	}
	return a * b, nil
}
```

### Safe Parsing

```go
// WRONG: No bounds checking on parsed values
func ParsePort(portStr string) int {
	port, _ := strconv.Atoi(portStr)
	return port
	// If portStr = "99999", returns invalid port number
}

// CORRECT: Bounds checking
const (
	MinPort = 1
	MaxPort = 65535
)

func ParsePort(portStr string) (int, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %w", err)
	}
	if port < MinPort || port > MaxPort {
		return 0, fmt.Errorf("port out of range: %d", port)
	}
	return port, nil
}

// Safe parsing of size values
func ParseSize(sizeStr string) (int64, error) {
	// Remove common suffixes: B, KB, MB, GB
	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))

	var multiplier int64 = 1
	switch {
	case strings.HasSuffix(sizeStr, "GB"):
		multiplier = 1 << 30
		sizeStr = strings.TrimSuffix(sizeStr, "GB")
	case strings.HasSuffix(sizeStr, "MB"):
		multiplier = 1 << 20
		sizeStr = strings.TrimSuffix(sizeStr, "MB")
	case strings.HasSuffix(sizeStr, "KB"):
		multiplier = 1 << 10
		sizeStr = strings.TrimSuffix(sizeStr, "KB")
	}

	value, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
	if err != nil {
		return 0, err
	}

	// Check for overflow in multiplication
	if value > 0 && multiplier > 0 && value > math.MaxInt64/multiplier {
		return 0, errors.New("size value overflow")
	}

	return value * multiplier, nil
}
```

---

## Concurrency & Race Conditions

### Data Race Detection

```go
// WRONG: Data race on counter
type Handler struct {
	RequestCount int
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.RequestCount++ // RACE CONDITION!
	w.WriteHeader(http.StatusOK)
}

// Multiple goroutines accessing RequestCount simultaneously without synchronization

// CORRECT: Protected with mutex
type Handler struct {
	mu           sync.Mutex
	RequestCount int
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.RequestCount++
	w.WriteHeader(http.StatusOK)
}

// BETTER: Use atomic for simple counters
type Handler struct {
	RequestCount atomic.Int64
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.RequestCount.Add(1)
	w.WriteHeader(http.StatusOK)
}
```

### Proper Mutex Usage

```go
// WRONG: Forgetting to unlock or improper locking scope
func (h *Handler) ReadData() string {
	h.mu.Lock()
	// If panic occurs here, lock is never released!
	data := h.data
	h.mu.Unlock()
	return data
}

// CORRECT: Defer unlock
func (h *Handler) ReadData() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.data
}

// CORRECT: Minimize critical section
type Cache struct {
	mu    sync.RWMutex
	items map[string]interface{}
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.items[key]
	return val, ok
	// Lock released immediately after read
	// Won't block other readers
}

func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = value
	// Lock held for write operation only
}
```

### Channel Deadlock Prevention

```go
// WRONG: Unbuffered channel deadlock
func SendData() {
	ch := make(chan string)
	ch <- "data" // Blocks forever - no one receiving!
}

// CORRECT: Buffered channel or receive in goroutine
func SendData() {
	ch := make(chan string, 1) // Buffered channel
	ch <- "data"
	value := <-ch
	fmt.Println(value)
}

// CORRECT: Goroutine for concurrent receive
func SendData() {
	ch := make(chan string)
	go func() {
		value := <-ch
		fmt.Println(value)
	}()
	ch <- "data"
}

// CORRECT: Context cancellation to prevent hanging
func SendDataWithTimeout(ctx context.Context) error {
	ch := make(chan string)
	go func() {
		value := <-ch
		fmt.Println(value)
	}()

	select {
	case ch <- "data":
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
```

### Process Goroutine Limits

```go
// WRONG: Unbounded goroutine spawning (denial of service)
func HandleRequests(listener net.Listener) {
	for {
		conn, _ := listener.Accept()
		go handleConnection(conn) // DANGEROUS! One goroutine per connection
		// If 100k requests arrive, spawns 100k goroutines
		// Exhausts memory, crashes server
	}
}

// CORRECT: Worker pool with bounded concurrency
func HandleRequests(listener net.Listener, maxWorkers int) {
	work := make(chan net.Conn, maxWorkers)

	// Start fixed number of workers
	for i := 0; i < maxWorkers; i++ {
		go func() {
			for conn := range work {
				handleConnection(conn)
			}
		}()
	}

	// Distribute connections to workers
	for {
		conn, _ := listener.Accept()
		select {
		case work <- conn:
			// Successfully sent to worker
		default:
			// All workers busy, drop connection
			conn.Close()
		}
	}
}

// CORRECT: Using semaphore pattern
type Semaphore struct {
	sem chan struct{}
}

func NewSemaphore(maxConcurrent int) *Semaphore {
	return &Semaphore{
		sem: make(chan struct{}, maxConcurrent),
	}
}

func (s *Semaphore) Acquire() { s.sem <- struct{}{} }
func (s *Semaphore) Release() { <-s.sem }

func HandleRequests(listener net.Listener, maxConcurrent int) {
	sem := NewSemaphore(maxConcurrent)
	for {
		conn, _ := listener.Accept()
		go func(c net.Conn) {
			sem.Acquire()
			defer sem.Release()
			handleConnection(c)
		}(conn)
	}
}
```

---

## Panic Recovery & Error Handling

### Recovering from Panics

```go
// WRONG: Unrecovered panic crashes goroutine
go func() {
	data := untrustedData()
	jsonStr := data["key"].(string) // May panic if type wrong
	process(jsonStr)
} ()
// Panic crashes entire goroutine and main thread may not know

// CORRECT: Recover panics in goroutines
go func() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
			// Log stack trace for debugging
			log.Printf("Stack trace: %s", debug.Stack())
		}
	}()

	data := untrustedData()
	jsonStr := data["key"].(string)
	process(jsonStr)
}()
```

### Safe Type Assertions

```go
// WRONG: Panic on failed type assertion
func ProcessValue(value interface{}) {
	str := value.(string) // Panics if not string
	fmt.Println(str)
}

// CORRECT: Use comma-ok pattern
func ProcessValue(value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("expected string, got %T", value)
	}
	fmt.Println(str)
	return nil
}

// CORRECT: Use type switch for multiple types
func ProcessValue(value interface{}) error {
	switch v := value.(type) {
	case string:
		fmt.Println("String:", v)
	case int:
		fmt.Println("Int:", v)
	case []byte:
		fmt.Println("Bytes:", v)
	default:
		return fmt.Errorf("unsupported type: %T", v)
	}
	return nil
}
```

### Error Wrapping & Stack Traces

```go
// WRONG: Exposing stack traces to users
func HandleRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			// Sends stack trace to user
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Error: %v\n%s", r, debug.Stack())
		}
	}()
	// ...
}

// CORRECT: Log stack trace, return generic error
func HandleRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			// Log detailed error internally
			log.Printf("Panic: %v\nStack: %s", r, debug.Stack())
			// Return generic error to user
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error"))
		}
	}()
	// ...
}

// CORRECT: Error wrapping with context
func ReadFile(path string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
		// Use %w to wrap, allows Is() and As() to work
	}
	return data, nil
}

func ProcessFileChain() error {
	data, err := ReadFile("config.json")
	if err != nil {
		return fmt.Errorf("initialization failed: %w", err)
	}
	// ... further processing
	return nil
}

// Caller can check errors:
// if errors.Is(err, os.ErrNotExist) { ... }
```

---

## Dependency Security

### go.mod Management

```bash
# CORRECT: Regular updates and audits
go mod tidy              # Remove unused dependencies
go mod verify            # Verify checksums
go list -u all          # Check for updates
go get -u ./...         # Update dependencies

# Audit for known vulnerabilities
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Never commit lock file changes without review
git log --oneline go.sum | head
```

### Vendoring Dependencies

```go
// CORRECT: Use vendor directory for reproducible builds
// go mod vendor  (creates vendor/ directory with all dependencies)
// go build -mod=vendor  (builds using vendored code)

// In go.mod:
module example.com/app

go 1.21

require (
	github.com/some/lib v1.2.3
)

// After vendoring, vendor/ contains full source code
// Provides protection against supply chain attacks
```

### Dependency Constraints

```go
// CORRECT: Pin major versions, allow patch updates
require (
	github.com/secure/lib v1.2.x  // Allow 1.2.0 - 1.2.999
	github.com/crypto/lib v2.x    // Allow 2.0.0 - 2.999.999
)

// WRONG: Unvetted dependency with no version
require github.com/unknown/lib

// CORRECT: Review transitive dependencies
go mod graph | grep "=>" | sort -u
// Shows all indirect dependencies
```

### Evaluating Dependencies

```bash
# Security assessment checklist:
1. Check repository activity (recent commits)
   git log --oneline -n 5

2. Review security history
   git log --grep="security\|CVE\|cve" --oneline

3. Check issue tracker for open vulnerabilities

4. Verify signed commits and tags
   git tag -v v1.2.3

5. Review major version changes for breaking changes

6. Check license compatibility

7. Evaluate maintainer trustworthiness
   git log --format="%aN" | sort | uniq -c | sort -rn

8. Look for SECURITY.md or similar policy
```

---

## Static Analysis & SAST Tools

### gosec - Security Linter

```bash
# Install
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Run on codebase
gosec ./...

# Ignore specific rules (with caution)
gosec -exclude=G307 ./...

# Output JSON for CI
gosec -fmt=json ./... > gosec-report.json
```

### Common gosec Issues

```go
// G101: Hardcoded credentials detected
const Password = "mypassword123" // FLAGGED

// G102: SQL injection possibility
query := "SELECT * FROM users WHERE id = " + userInput // FLAGGED

// G201: SQL injection via string concatenation
db.Query("SELECT * FROM users WHERE id = " + id) // FLAGGED

// G202: SQL injection via string format
db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)) // FLAGGED

// G203: Use of unescaped data in HTML templates
html.Parse("<h1>" + userInput + "</h1>") // FLAGGED

// G301: Weak file permissions
os.Chmod(file, 0777) // FLAGGED - too permissive

// G302: Read file without checking error
ioutil.ReadFile(file) // FLAGGED - error ignored

// G303: File permissions check via os.Getenv
os.Getenv("SENSITIVE") // FLAGGED - credentials in env

// G305: File traversal via tar extraction
tarReader.Next() // May FLAGGED if not validated

// G306: Poor file permissions on new file
os.Create(file) // FLAGGED - default 0644, should be 0600 for secrets

// G307: Poor file permissions in WriteFile
ioutil.WriteFile(file, data, 0644) // FLAGGED - too permissive for secrets
```

### staticcheck - General Code Quality

```bash
# Install
go install honnef.co/go/tools/cmd/staticcheck@latest

# Run analysis
staticcheck ./...

# Check specific categories
staticcheck -checks=S1000,S1001 ./...
```

### go vet - Built-in Analyzer

```bash
# Run built-in vet checks
go vet ./...

# Common issues found:
# - Unused variables
# - Incorrect format strings
# - Unreachable code
# - Suspicious comparison
```

### CI/CD Integration

```yaml
# GitHub Actions example
name: Security Checks

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run gosec
        run: |
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          gosec ./...

      - name: Run staticcheck
        run: |
          go install honnef.co/go/tools/cmd/staticcheck@latest
          staticcheck ./...

      - name: Run go vet
        run: go vet ./...

      - name: Check for vulnerable dependencies
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...
```

---

## Secret Management

### Environment Variables

```go
// CORRECT: Load secrets from environment
func GetDatabasePassword() (string, error) {
	password := os.Getenv("DB_PASSWORD")
	if password == "" {
		return "", errors.New("DB_PASSWORD not set")
	}
	return password, nil
}

// CORRECT: Validate secret format
func ValidateAPIKey(key string) error {
	if len(key) < 32 {
		return errors.New("API key too short")
	}
	// Verify it matches expected format (e.g., starts with "sk_")
	if !strings.HasPrefix(key, "sk_") {
		return errors.New("invalid API key format")
	}
	return nil
}

// WRONG: Logging secret
func ConnectDB() error {
	password := os.Getenv("DB_PASSWORD")
	log.Printf("Connecting to DB with password: %s", password) // LEAKED!
	return nil
}

// CORRECT: Never log secrets
func ConnectDB() error {
	password := os.Getenv("DB_PASSWORD")
	log.Println("Connecting to database...")
	// Don't log password
	return connect(password)
}
```

### Config Files

```go
// CORRECT: Load config from file with restricted permissions
func LoadConfig(filePath string) (Config, error) {
	// Check file permissions first
	info, err := os.Stat(filePath)
	if err != nil {
		return Config{}, err
	}

	// Warn if file is world-readable
	mode := info.Mode()
	if mode&0o077 != 0 {
		log.Printf("WARNING: config file has overly permissive permissions: %o", mode)
	}

	// Load config
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return Config{}, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Config{}, err
	}

	return config, nil
}

// CORRECT: Write secrets with restricted permissions
func SaveSecretConfig(filePath string, config Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	// Write file with permissions 0600 (owner read/write only)
	if err := ioutil.WriteFile(filePath, data, 0600); err != nil {
		return err
	}

	// Verify permissions
	info, _ := os.Stat(filePath)
	if info.Mode()&0o077 != 0 {
		log.Printf("ERROR: Failed to set proper permissions on secret file")
		os.Remove(filePath)
		return errors.New("permission issue on secret file")
	}

	return nil
}
```

### Secret Providers

```go
// CORRECT: Pluggable secret provider pattern
type SecretProvider interface {
	GetSecret(ctx context.Context, name string) (string, error)
}

// Environment variable provider
type EnvSecretProvider struct{}

func (p *EnvSecretProvider) GetSecret(ctx context.Context, name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("secret not found: %s", name)
	}
	return value, nil
}

// File-based provider
type FileSecretProvider struct {
	basePath string
}

func (p *FileSecretProvider) GetSecret(ctx context.Context, name string) (string, error) {
	// Validate path to prevent directory traversal
	if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		return "", errors.New("invalid secret name")
	}

	filePath := filepath.Join(p.basePath, name)
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read secret: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}

// Usage
func GetSecret(name string) (string, error) {
	provider := &EnvSecretProvider{}
	return provider.GetSecret(context.Background(), name)
}
```

---

## Error Message Safety

### No Secrets in Errors

```go
// WRONG: Exposing secrets in error messages
func VerifyPassword(provided, stored string) error {
	if provided != stored {
		return fmt.Errorf("password mismatch: got %q, expected %q", provided, stored)
		// EXPOSES both passwords in error!
	}
	return nil
}

// CORRECT: Generic error messages
func VerifyPassword(provided, stored string) error {
	if provided != stored {
		return errors.New("password verification failed")
	}
	return nil
}

// WRONG: Exposing file paths (info disclosure)
func ReadConfig() ([]byte, error) {
	data, err := ioutil.ReadFile("/etc/app/secrets.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %v", err)
		// Reveals internal path structure
	}
	return data, nil
}

// CORRECT: Generic error to user, detailed log internally
func ReadConfig() ([]byte, error) {
	data, err := ioutil.ReadFile("/etc/app/secrets.conf")
	if err != nil {
		log.Printf("ERROR: Failed to read config file: %v", err)
		// Log detailed error
		return nil, errors.New("configuration error")
		// Return generic error to user
	}
	return data, nil
}
```

### SQL Errors

```go
// WRONG: Exposing query details
func GetUser(id string) (User, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
	rows, err := db.Query(query)
	if err != nil {
		return User{}, fmt.Errorf("database error: %v for query: %s", err, query)
		// EXPOSES query structure!
	}
	// ...
	return User{}, nil
}

// CORRECT: Use parameterized queries and generic errors
func GetUser(id string) (User, error) {
	// Parameterized query prevents SQL injection
	rows, err := db.Query("SELECT * FROM users WHERE id = ?", id)
	if err != nil {
		log.Printf("DEBUG: Database error: %v (query attempted with id: %s)", err, id)
		// Log details internally
		return User{}, errors.New("database error")
		// Return generic error to user
	}
	// ...
	return User{}, nil
}
```

### Stack Traces

```go
// WRONG: Returning stack trace to user
func HandleRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			// EXPOSES stack trace to attacker
			fmt.Fprintf(w, "Error: %v\n%s", err, debug.Stack())
		}
	}()
	// ...
}

// CORRECT: Log stack trace, return generic error
func HandleRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			// Log everything internally
			log.Printf("PANIC: %v\nStack:\n%s", err, debug.Stack())
			// Return safe error to user
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error"))
		}
	}()
	// ...
}
```

---

## Resource Exhaustion Prevention

### Goroutine Limits

```go
// WRONG: Unbounded goroutine creation
func ProcessRequests(requestChan <-chan Request) {
	for req := range requestChan {
		go handleRequest(req) // One goroutine per request - DOS!
	}
}

// CORRECT: Worker pool
func ProcessRequests(requestChan <-chan Request, maxWorkers int) {
	for i := 0; i < maxWorkers; i++ {
		go func() {
			for req := range requestChan {
				handleRequest(req)
			}
		}()
	}
}
```

### Memory Limits

```go
// WRONG: Unbounded buffer
type Handler struct {
	queue chan Request
}

func NewHandler() *Handler {
	return &Handler{
		queue: make(chan Request), // Unbuffered - blocks on full
	}
}

// CORRECT: Bounded buffer with size limits
const MaxQueueSize = 10000

type Handler struct {
	queue chan Request
}

func NewHandler() *Handler {
	return &Handler{
		queue: make(chan Request, MaxQueueSize),
	}
}

func (h *Handler) Submit(req Request) error {
	select {
	case h.queue <- req:
		return nil
	default:
		return errors.New("queue full - rejecting request")
	}
}

// CORRECT: Memory usage monitoring
type MemoryLimitedHandler struct {
	maxMemory int64
	used      atomic.Int64
	queue     chan Request
}

func (h *MemoryLimitedHandler) Submit(req Request) error {
	size := int64(req.EstimateSize())
	if h.used.Load()+size > h.maxMemory {
		return errors.New("memory limit exceeded")
	}
	h.used.Add(size)
	h.queue <- req
	return nil
}
```

### File Descriptor Limits

```go
// WRONG: Opening files without limit
func ProcessFiles(filePaths []string) error {
	files := make([]*os.File, len(filePaths))
	for i, path := range filePaths {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		files[i] = f
		// If len(filePaths) > max FDs, crashes!
	}
	// ...
	for _, f := range files {
		f.Close()
	}
	return nil
}

// CORRECT: Limit concurrent file operations
func ProcessFiles(filePaths []string, maxConcurrent int) error {
	sem := make(chan struct{}, maxConcurrent)
	errors := make(chan error, len(filePaths))

	for _, path := range filePaths {
		go func(p string) {
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			f, err := os.Open(p)
			if err != nil {
				errors <- err
				return
			}
			defer f.Close()

			// Process file
			errors <- processFile(f)
		}(path)
	}

	// Collect errors
	for i := 0; i < len(filePaths); i++ {
		if err := <-errors; err != nil {
			return err
		}
	}
	return nil
}
```

### Time/Timeout Limits

```go
// WRONG: No timeout on long operations
func FetchData(url string) ([]byte, error) {
	resp, err := http.Get(url)
	// No timeout - could hang forever!
	// ...
	return ioutil.ReadAll(resp.Body)
}

// CORRECT: HTTP client with timeout
func FetchData(url string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Limit read size to prevent memory exhaustion
	limitedBody := io.LimitReader(resp.Body, 10*1024*1024) // 10 MB max
	return ioutil.ReadAll(limitedBody)
}

// CORRECT: Context with timeout for operations
func FetchData(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limitedBody := io.LimitReader(resp.Body, 10*1024*1024)
	return ioutil.ReadAll(limitedBody)
}
```

---

## Denial of Service Prevention

### Rate Limiting

```go
// CORRECT: Token bucket rate limiter
type RateLimiter struct {
	tokens float64
	maxTps float64
	mu     sync.Mutex
	ticker *time.Ticker
}

func NewRateLimiter(tps float64) *RateLimiter {
	rl := &RateLimiter{
		tokens: 0,
		maxTps: tps,
	}
	rl.ticker = time.NewTicker(time.Second)
	go func() {
		for range rl.ticker.C {
			rl.mu.Lock()
			rl.tokens = math.Min(rl.tokens+rl.maxTps, rl.maxTps)
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.tokens >= 1.0 {
		rl.tokens--
		return true
	}
	return false
}

// Usage in HTTP handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.limiter.Allow() {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	// Process request
}
```

### Algorithmic DOS Prevention

```go
// WRONG: Regex that could cause DOS (ReDoS)
// This regex has catastrophic backtracking
// Pattern: (a+)+$ with input: "aaaa...aaaaX"
func ValidateInput(input string) bool {
	// VULNERABLE to ReDoS
	matched, _ := regexp.MatchString(`^(a+)+$`, input)
	return matched
}

// CORRECT: Use safer regex patterns
func ValidateInput(input string) bool {
	// Atomic grouping prevents backtracking
	matched, _ := regexp.MatchString(`^a+$`, input)
	return matched
}

// WRONG: Inefficient algorithm with large input
func Fibonacci(n int) int {
	if n <= 1 {
		return n
	}
	return Fibonacci(n-1) + Fibonacci(n-2)
	// Exponential time complexity - DOS on large n!
}

// CORRECT: Efficient implementation
func Fibonacci(n int) int {
	if n <= 1 {
		return n
	}
	a, b := 0, 1
	for i := 2; i <= n; i++ {
		a, b = b, a+b
	}
	return b
}

// CORRECT: Add input limits for expensive operations
func Fibonacci(n int) (int, error) {
	const maxN = 90 // Maximum reasonable value
	if n < 0 || n > maxN {
		return 0, fmt.Errorf("input out of range: %d", n)
	}
	// ... compute
	return 0, nil
}
```

### Slowloris Prevention

```go
// CORRECT: Read timeout on HTTP server
server := &http.Server{
	Addr:         ":8080",
	ReadTimeout:  15 * time.Second,
	WriteTimeout: 15 * time.Second,
	IdleTimeout:  60 * time.Second,
}

// CORRECT: Limit request header size
server := &http.Server{
	Addr:           ":8080",
	MaxHeaderBytes: 1 << 20, // 1 MB max header
	ReadTimeout:    15 * time.Second,
	WriteTimeout:   15 * time.Second,
}

// CORRECT: Limit request body size
func LimitBodyMiddleware(maxSize int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxSize)
			next.ServeHTTP(w, r)
		})
	}
}
```

---

## Security Testing

### Unit Tests for Security

```go
// Test: Command injection prevention
func TestCommandExecution_PreventsInjection(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid input", "hello", false},
		{"shell metacharacter", "; rm -rf /", true},
		{"pipe", "hello | cat", true},
		{"redirection", "hello > file", true},
		{"backticks", "$(whoami)", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInput(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateInput(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// Test: Path traversal prevention
func TestPathValidation_PreventsTraversal(t *testing.T) {
	baseDir := "/app/data"
	tests := []struct {
		path    string
		wantErr bool
	}{
		{"file.txt", false},
		{"subdir/file.txt", false},
		{"../../../etc/passwd", true},
		{"/etc/passwd", true},
		{".hidden", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := ValidatePath(tt.path, baseDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

// Test: Constant-time comparison
func TestConstantTimeComparison(t *testing.T) {
	// Can't really test timing in unit tests without statistical analysis
	// But can verify correctness
	tests := []struct {
		a, b  string
		equal bool
	}{
		{"secret", "secret", true},
		{"secret", "other", false},
		{"", "", true},
		{"a", "b", false},
	}

	for _, tt := range tests {
		if subtle.ConstantTimeCompare([]byte(tt.a), []byte(tt.b)) == 1 != tt.equal {
			t.Errorf("ConstantTimeCompare(%q, %q) failed", tt.a, tt.b)
		}
	}
}
```

### Fuzzing

```go
// Fuzz test for input parser
func FuzzParseInput(f *testing.F) {
	testcases := []string{"valid", ";rm", "../..", ""}
	for _, tc := range testcases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Should never panic or hang
		_ = ValidateInput(input)
	})
}

// Fuzz JSON unmarshaling
func FuzzParseJSON(f *testing.F) {
	testcases := [][]byte{
		[]byte(`{"name":"test"}`),
		[]byte(`{}`),
		[]byte(`{"x":1}`),
	}
	for _, tc := range testcases {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var config ManifestConfig
		// Should handle any input gracefully
		_ = json.Unmarshal(data, &config)
	})
}
```

### Negative Tests

```go
// Test denial of service prevention
func TestMemoryLimits_RejectsLargeInput(t *testing.T) {
	h := NewHandler()

	// Attempt to create massive request
	req := Request{
		Data: make([]byte, 1<<30), // 1 GB
	}

	err := h.Submit(req)
	if err == nil {
		t.Error("Expected error for oversized request, got nil")
	}
}

// Test panic recovery
func TestPanicRecovery(t *testing.T) {
	// This should not panic
	result := recoverablePanicFunction()
	if result != "recovered" {
		t.Errorf("Expected 'recovered', got %q", result)
	}
}

// Test integer overflow handling
func TestIntegerArithmetic_DetectsOverflow(t *testing.T) {
	sum, err := SafeAdd(math.MaxInt, 1)
	if err == nil {
		t.Error("Expected overflow error, got nil")
	}
	if sum != 0 {
		t.Errorf("Expected sum=0, got %d", sum)
	}
}
```

---

## Common Vulnerabilities & Mitigations

### CWE-22: Path Traversal

**Vulnerability:**
```go
func ReadFile(userPath string) ([]byte, error) {
	return ioutil.ReadFile(userPath) // User can provide "../../../etc/passwd"
}
```

**Mitigation:**
```go
func ReadFile(userPath string) ([]byte, error) {
	basePath := "/safe/dir"
	cleanPath := filepath.Clean(filepath.Join(basePath, userPath))
	if !strings.HasPrefix(cleanPath, filepath.Clean(basePath)) {
		return nil, errors.New("path escapes safe directory")
	}
	return ioutil.ReadFile(cleanPath)
}
```

### CWE-78: OS Command Injection

**Vulnerability:**
```go
cmd := exec.Command("sh", "-c", "echo "+userInput)
```

**Mitigation:**
```go
cmd := exec.Command("echo", userInput) // Args array is safe
```

### CWE-79: Cross-Site Scripting (XSS)

**Vulnerability:**
```go
w.Write([]byte("<p>" + userInput + "</p>"))
```

**Mitigation:**
```go
w.Write([]byte("<p>" + html.EscapeString(userInput) + "</p>"))
```

### CWE-89: SQL Injection

**Vulnerability:**
```go
rows := db.Query("SELECT * FROM users WHERE id = " + userID)
```

**Mitigation:**
```go
rows := db.Query("SELECT * FROM users WHERE id = ?", userID)
```

### CWE-94: Code Injection

**Vulnerability:**
```go
code := "return " + userInput
result := eval(code)
```

**Mitigation:**
```go
// Don't use eval! Parse safely or use whitelist
result := evaluateWhitelist(userInput)
```

### CWE-200: Information Disclosure

**Vulnerability:**
```go
return fmt.Errorf("database error: %v for query: %s", err, query)
```

**Mitigation:**
```go
log.Printf("DEBUG: %v", err)
return errors.New("database error")
```

### CWE-307: Improper Restriction of Rendered UI Layers

**Vulnerability:**
```go
if provided == expected { // Timing leak
	return true
}
```

**Mitigation:**
```go
if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1 {
	return true
}
```

### CWE-330: Use of Insufficiently Random Values

**Vulnerability:**
```go
token := rand.Int63() // math/rand not cryptographically secure
```

**Mitigation:**
```go
token := make([]byte, 32)
rand.Read(token)
return hex.EncodeToString(token) // crypto/rand
```

### CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization

**Vulnerability:**
```go
var counter int
go func() { counter++ }()
go func() { counter++ }()
```

**Mitigation:**
```go
var counter atomic.Int64
go func() { counter.Add(1) }()
go func() { counter.Add(1) }()
```

### CWE-400: Uncontrolled Resource Consumption

**Vulnerability:**
```go
for {
	conn, _ := listener.Accept()
	go handleConnection(conn) // Unbounded goroutines
}
```

**Mitigation:**
```go
sem := make(chan struct{}, maxWorkers)
for {
	conn, _ := listener.Accept()
	go func() {
		sem <- struct{}{}
		defer func() { <-sem }()
		handleConnection(conn)
	}()
}
```

---

## Go-Specific Vulnerabilities

### Unsafe String Operations

```go
// WRONG: Assuming strings are always valid UTF-8
s := "hello"
for i := 0; i < len(s); i++ {
	ch := s[i] // Works but ignores rune boundaries
	// If s contains non-ASCII, mishandles characters
}

// CORRECT: Iterate over runes
s := "hello 世界"
for i, ch := range s {
	fmt.Printf("Position %d: %c\n", i, ch)
}
```

### Unsafe Reflection

```go
// WRONG: Using reflection without type checks
func Call(fn interface{}, args ...interface{}) interface{} {
	fnValue := reflect.ValueOf(fn)
	argValues := make([]reflect.Value, len(args))
	for i, arg := range args {
		argValues[i] = reflect.ValueOf(arg)
	}
	results := fnValue.Call(argValues) // Could panic!
	return results[0].Interface()
}

// CORRECT: Type and safety checks
func Call(fn interface{}, args ...interface{}) (interface{}, error) {
	fnValue := reflect.ValueOf(fn)
	if fnValue.Kind() != reflect.Func {
		return nil, errors.New("not a function")
	}

	fnType := fnValue.Type()
	if fnType.NumIn() != len(args) {
		return nil, fmt.Errorf("expected %d args, got %d", fnType.NumIn(), len(args))
	}

	argValues := make([]reflect.Value, len(args))
	for i, arg := range args {
		argVal := reflect.ValueOf(arg)
		if !argVal.Type().AssignableTo(fnType.In(i)) {
			return nil, fmt.Errorf("arg %d: type mismatch", i)
		}
		argValues[i] = argVal
	}

	if fnType.NumOut() == 0 {
		fnValue.Call(argValues)
		return nil, nil
	}

	results := fnValue.Call(argValues)
	if fnType.NumOut() > 0 {
		return results[0].Interface(), nil
	}
	return nil, nil
}
```

### Unsafe Type Assertions

```go
// WRONG: Type assertion without ok check
func GetString(data map[string]interface{}) string {
	return data["key"].(string) // Panics if not string
}

// CORRECT: Use comma-ok
func GetString(data map[string]interface{}) (string, error) {
	val, ok := data["key"]
	if !ok {
		return "", errors.New("key not found")
	}
	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("expected string, got %T", val)
	}
	return str, nil
}
```

---

## Security Checklist

### Pre-Commit Review (20+ items)

- [ ] **Input Validation**: All external inputs validated (length, format, whitelist)
- [ ] **Command Execution**: No shell injection (args array used, not string concat)
- [ ] **Path Handling**: No path traversal (filepath.Clean, validation, containment check)
- [ ] **Template Safety**: Using html/template or proper escaping
- [ ] **SQL Safety**: Using parameterized queries, not string concat
- [ ] **Constant-Time Comparison**: Using crypto/subtle for secrets/tokens
- [ ] **Random Generation**: Using crypto/rand, not math/rand
- [ ] **Secret Handling**: No hardcoded secrets, env vars only, zeroing after use
- [ ] **Error Messages**: No secrets, paths, or sensitive data in error messages
- [ ] **Logging**: No secrets logged, debug logs don't expose internal structure
- [ ] **Memory Safety**: Sensitive data zeroed explicitly
- [ ] **Integer Arithmetic**: Overflow/underflow checks on calculations
- [ ] **Race Conditions**: Proper mutex/atomic usage, no unsynchronized access
- [ ] **Panic Recovery**: All goroutines have defer+recover, no stack trace leaks
- [ ] **Resource Limits**: Timeouts, goroutine limits, memory limits, fd limits
- [ ] **Concurrency**: No deadlocks, channels properly closed
- [ ] **Dependency Security**: go mod verify, vulnerable deps scanned
- [ ] **SAST Tools**: gosec, staticcheck, go vet all pass
- [ ] **Security Tests**: Negative tests, fuzzing, boundary conditions
- [ ] **Documentation**: Security assumptions documented
- [ ] **File Permissions**: Secret files 0600, others 0644, world-readable check
- [ ] **Crypto Functions**: Not rolling own crypto, using stdlib
- [ ] **TLS/HTTPS**: Certificate validation, strong ciphers, no self-signed in prod
- [ ] **Authentication**: No plaintext passwords, use bcrypt/argon2
- [ ] **Authorization**: Proper access control, no privilege escalation

---

## Real-World mcp-cage Patterns

### Pattern 1: Digest Validation (Safe Crypto)

```go
import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// VerifyDigest safely compares computed and expected digests
// Uses constant-time comparison to prevent timing attacks
func VerifyDigest(computed, expected string) error {
	// Validate format first
	if !isValidDigestFormat(computed) {
		return fmt.Errorf("invalid computed digest format: %s", computed)
	}
	if !isValidDigestFormat(expected) {
		return fmt.Errorf("invalid expected digest format: %s", expected)
	}

	// Parse digests
	compBytes, err := parseDigest(computed)
	if err != nil {
		return err
	}
	expBytes, err := parseDigest(expected)
	if err != nil {
		return err
	}

	// Constant-time comparison (prevents timing attacks)
	if subtle.ConstantTimeCompare(compBytes, expBytes) != 1 {
		return fmt.Errorf("digest mismatch")
	}
	return nil
}

func isValidDigestFormat(digest string) bool {
	parts := strings.Split(digest, ":")
	return len(parts) == 2 && parts[0] == "sha256" && len(parts[1]) == 64
}

func parseDigest(digest string) ([]byte, error) {
	parts := strings.Split(digest, ":")
	return hex.DecodeString(parts[1])
}
```

### Pattern 2: Safe Bundle Execution (Command Injection Prevention)

```go
// ExecuteBundle safely runs a bundle's entrypoint
// Never constructs command strings that could be injected
func (e *Executor) ExecuteBundle(
	entrypoint *manifest.Entrypoint,
	userArgs []string,
) error {
	// Validate entrypoint command path
	if err := validateCommand(entrypoint.Command); err != nil {
		return err
	}

	// Validate all arguments
	for _, arg := range userArgs {
		if err := validateArg(arg); err != nil {
			return err
		}
	}

	// Build safe argument list (no shell involved)
	cmd := exec.Command(entrypoint.Command)
	cmd.Args = append(cmd.Args, entrypoint.Args...)
	cmd.Args = append(cmd.Args, userArgs...)

	// Set working directory
	cmd.Dir = e.workDir

	// Run with environment restrictions
	cmd.Env = filterEnv(os.Environ(), entrypoint.AllowedEnv)

	return cmd.Run()
}

func validateCommand(cmd string) error {
	// Must be relative path within bundle
	if filepath.IsAbs(cmd) {
		return errors.New("command must be relative path")
	}
	if strings.Contains(cmd, "..") {
		return errors.New("command contains parent directory reference")
	}
	return nil
}

func validateArg(arg string) error {
	if len(arg) > 4096 {
		return errors.New("argument too long")
	}
	// Additional validation per policy
	return nil
}

func filterEnv(allEnv []string, allowlist []string) []string {
	allowMap := make(map[string]bool)
	for _, key := range allowlist {
		allowMap[key] = true
	}

	var filtered []string
	for _, env := range allEnv {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && allowMap[parts[0]] {
			filtered = append(filtered, env)
		}
	}
	return filtered
}
```

### Pattern 3: Safe Cache Operations (Race Condition Prevention)

```go
type ContentCache struct {
	mu        sync.RWMutex
	digestMap map[string]string // digest -> filepath
	lru       *lru.Cache        // Eviction policy
	maxSize   int64
	used      int64
}

// GetOrFetch safely retrieves from cache or fetches new
func (c *ContentCache) GetOrFetch(
	digest string,
	fetch func() ([]byte, error),
) ([]byte, error) {
	// Try read lock first (fast path)
	c.mu.RLock()
	if path, ok := c.digestMap[digest]; ok {
		c.mu.RUnlock()
		return ioutil.ReadFile(path)
	}
	c.mu.RUnlock()

	// Cache miss - fetch with exclusive lock
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring lock (another goroutine might have fetched)
	if path, ok := c.digestMap[digest]; ok {
		c.mu.Unlock()
		return ioutil.ReadFile(path)
	}

	// Fetch data
	data, err := fetch()
	if err != nil {
		return nil, err
	}

	// Validate digest
	if err := VerifyDigest(computeDigest(data), digest); err != nil {
		return nil, fmt.Errorf("digest validation failed: %w", err)
	}

	// Store in cache
	path := c.pathForDigest(digest)
	if err := ioutil.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}

	// Update metadata
	c.digestMap[digest] = path
	c.used += int64(len(data))
	c.lru.Add(digest, true)

	// Evict if necessary
	if c.used > c.maxSize {
		c.evictLRU()
	}

	return data, nil
}

func (c *ContentCache) evictLRU() {
	if oldest, ok := c.lru.RemoveOldest(); ok {
		digest := oldest.(string)
		if path, ok := c.digestMap[digest]; ok {
			os.Remove(path)
			delete(c.digestMap, digest)
		}
	}
}
```

### Pattern 4: Secure Configuration Loading (Secret Protection)

```go
type Config struct {
	Registry struct {
		URL   string
		Token string // Never logged or exposed
	}
	Cache struct {
		Dir     string
		MaxSize int64
	}
}

// LoadConfig safely loads configuration
// Secrets loaded from environment, not config files
func LoadConfig(configPath string) (*Config, error) {
	cfg := &Config{}

	// Load config file (no secrets)
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	// Validate file permissions
	info, _ := os.Stat(configPath)
	if info.Mode()&0o077 != 0 {
		log.Printf("WARNING: config file has overly permissive permissions")
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Load secrets from environment (never from config)
	cfg.Registry.Token = os.Getenv("MCP_REGISTRY_TOKEN")
	if cfg.Registry.Token == "" {
		return nil, errors.New("MCP_REGISTRY_TOKEN not set")
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Registry.URL == "" {
		return errors.New("registry URL required")
	}
	if c.Registry.Token == "" {
		return errors.New("registry token required")
	}
	if len(c.Registry.Token) < 32 {
		return errors.New("registry token too short")
	}
	return nil
}

// Never print or log the token
func (c *Config) String() string {
	return fmt.Sprintf(
		"Config{Registry: %s, Cache: %s}",
		c.Registry.URL,
		c.Cache.Dir,
	)
}
```

---

## Summary: Top 10 Rules for Secure Go

1. **Input Whitelist**: Define what IS valid, not what isn't
2. **No Shell**: Use exec.Command with args array, never string concat
3. **Path Safety**: filepath.Clean + containment checks, reject ".."
4. **Constant-Time**: Use crypto/subtle for secrets, never ==
5. **Secure Random**: crypto/rand always, never math/rand
6. **Zero Secrets**: Explicitly zero sensitive data after use
7. **Safe Errors**: Log details internally, generic errors to users
8. **Resource Limits**: Timeouts, goroutine limits, memory bounds
9. **Race-Free**: Proper mutex/atomic usage, no unsynchronized access
10. **Tool-Assisted**: Run gosec, staticcheck, go vet, govulncheck

---

## References & Further Reading

- **OWASP**: https://owasp.org/www-project-top-ten/
- **CWE**: https://cwe.mitre.org/
- **gosec**: https://github.com/securego/gosec
- **Go Security**: https://golang.org/doc/security
- **crypto/subtle**: https://pkg.go.dev/crypto/subtle
- **Go Memory Model**: https://golang.org/ref/mem
- **Context Package**: https://pkg.go.dev/context
