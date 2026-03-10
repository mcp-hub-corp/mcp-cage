# HTTP Client Hardening: Secure Network Communication

This skill provides expert knowledge for secure HTTP client implementation in mcp-cage.

## Security Threats

### 1. TLS/SSL Configuration Vulnerabilities
**Threat**: Weak TLS versions, weak cipher suites, or disabled certificate validation enable MITM attacks.

**Examples**:
- TLS 1.0/1.1: Vulnerable to downgrade attacks (POODLE, FREAK)
- NULL ciphers: No encryption (attacker reads all traffic)
- Disabled cert verification: MITM accepts any certificate (easy compromise)

**Mitigation**:
- **Enforce TLS 1.2+**: `MinVersion: tls.VersionTLS12`
- **Use modern cipher suites**: Disable weak ciphers, enable ECDHE (forward secrecy)
- **Always verify certificates**: `InsecureSkipVerify: false` (never disable in production)
- **Prefer system cert store**: Use default CA verification (already includes system roots)

**mcp-cage Implementation** (internal/registry/client.go - **MISSING**, should add):
```go
import "crypto/tls"

func createSecureHTTPClient(timeout time.Duration) *http.Client {
    // TLS configuration: enforce modern standards
    tlsConfig := &tls.Config{
        MinVersion:               tls.VersionTLS12,
        // Disable weaker ciphers, prefer ECDHE for forward secrecy
        CipherSuites: []uint16{
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        },
        // Enable certificate verification (default: true)
        InsecureSkipVerify: false,
        // Use system certificate pool (default)
        RootCAs: nil, // nil means use system roots
    }

    return &http.Client{
        Timeout: timeout,
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
            // Other transport settings...
        },
    }
}
```

**Current mcp-cage** (internal/registry/client.go):
```go
// Creates clients but does NOT explicitly configure TLS
// Relies on Go defaults (which ARE secure: TLS 1.2+ minimum)
apiClient := &http.Client{
    Timeout: DefaultAPITimeout,
    // Missing: explicit TLS config for clarity
}
```

**Trade-offs**:
- Explicit TLS config makes security intent clear (documentation)
- Go defaults are secure, so missing config is not a vulnerability
- Modern ciphers (ECDHE) add latency but provide forward secrecy

---

### 2. Certificate Pinning (Advanced)
**Threat**: Registry certificate is compromised or CA is breached, enabling MITM even with valid cert.

**When to use**:
- High-security deployments (defense-in-depth)
- Registry operator controls mcp-cage config (static pins)
- NOT recommended for public OSS (pins break on cert renewal)

**Implementation** (optional enhancement):
```go
import "crypto/sha256"
import "crypto/x509"

func createPinnedHTTPClient(registryHost string, pinnedCertSHA256 string) (*http.Client, error) {
    tlsConfig := &tls.Config{
        MinVersion: tls.VersionTLS12,
        VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
            // 1. Perform standard cert verification first
            opts := x509.VerifyOptions{
                // ... (use system roots, etc)
            }
            // Verify chain is valid
            _, err := x509.ParseCertificate(rawCerts[0])
            if err != nil {
                return fmt.Errorf("failed to parse certificate: %w", err)
            }

            // 2. Pin the leaf certificate SHA-256
            cert, err := x509.ParseCertificate(rawCerts[0])
            if err != nil {
                return err
            }
            pin := sha256.Sum256(cert.Raw)
            pinStr := hex.EncodeToString(pin[:])

            if pinStr != pinnedCertSHA256 {
                return fmt.Errorf("certificate pin mismatch: expected %s, got %s",
                    pinnedCertSHA256, pinStr)
            }

            return nil
        },
    }

    return &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }, nil
}

// Extract pin from certificate
// openssl s_client -servername registry.example.com -connect registry.example.com:443 </dev/null 2>/dev/null | \
//   openssl x509 -outform DER | openssl dgst -sha256 -hex
```

**Recommendation for mcp-cage**: NOT IMPLEMENTED (keep simple, trust system CAs)

---

### 3. Timeout Strategy
**Threat**: Slow/hanging registry causes mcp-cage to block indefinitely, hangs container/CI/process.

**Scenarios**:
- Registry is slow (network issue, overloaded)
- Registry is down (permanent hang)
- Attacker controls registry and sends 0 bytes (slow loris)
- Client makes large request with default timeout (5 minutes is too long)

**Mitigation**:
- **ConnectTimeout**: 10s (initial TCP handshake)
- **ResponseHeaderTimeout**: 30s (wait for headers)
- **TotalTimeout**: 5m for downloads, 30s for API calls
- **Prevent slow loris**: io.LimitReader per-response body

**Timeout Hierarchy**:
```
1. ConnectTimeout: 10s (TCP connect phase)
2. ResponseHeaderTimeout: 30s (wait for first byte of response)
3. TotalTimeout: 5m (entire operation)
   Best strategy: use context.WithTimeout() for total timeout
```

**mcp-cage Implementation** (internal/registry/client.go - GOOD):
```go
const (
    DefaultAPITimeout = 30 * time.Second      // For resolve, metadata
    DefaultDownloadTimeout = 5 * time.Minute  // For manifests/bundles
)

// API client (resolve, etc)
apiClient := &http.Client{
    Timeout: DefaultAPITimeout,  // 30s total
}

// Download client (bundles)
httpClient := &http.Client{
    Timeout: DefaultDownloadTimeout,  // 5m total
}
```

**Enhanced Implementation** (explicit connection timeouts):
```go
func createHTTPClientWithTimeouts(totalTimeout time.Duration) *http.Client {
    transport := &http.Transport{
        // Connection phase timeout
        DialContext: (&net.Dialer{
            Timeout: 10 * time.Second,
            KeepAlive: 30 * time.Second,
        }).DialContext,

        // Wait for response headers
        ResponseHeaderTimeout: 30 * time.Second,

        // Connection reuse settings
        MaxIdleConns: 100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout: 90 * time.Second,
    }

    return &http.Client{
        Timeout: totalTimeout,
        Transport: transport,
    }
}
```

**Testing timeouts**:
```bash
# Slow server (100ms delay before headers)
timeout 10s nc -l localhost 8080 < <(echo ""; sleep 10) &
# Should fail: context deadline exceeded

# Server that sends nothing (test ResponseHeaderTimeout)
nc -l localhost 8080 < /dev/null &
curl --max-time 5 http://localhost:8080
# Should timeout in ~5s
```

---

### 4. Connection Pooling & Keep-Alive
**Threat**: Improper connection pooling leads to resource exhaustion or connection leaks.

**Issues**:
- **Too many connections**: `MaxIdleConns` not set → open many idle conns → server reject
- **Connection reuse**: Idle conns not closed → port exhaustion
- **Keep-Alive abuse**: Attacker keeps connections alive indefinitely

**Mitigation**:
- **MaxIdleConns**: 100 (total idle connections across all hosts)
- **MaxIdleConnsPerHost**: 10 (per-host limit)
- **IdleConnTimeout**: 90s (close idle after 90s)
- **DisableKeepAlives**: false (reuse is good for performance)

**mcp-cage Implementation** (internal/registry/client.go - **MISSING**, relies on defaults):
```go
transport := &http.Transport{
    // Connection pooling limits
    MaxIdleConns: 100,              // Total idle connections
    MaxIdleConnsPerHost: 10,        // Per-host idle connections
    IdleConnTimeout: 90 * time.Second,

    // Keep-Alive
    DisableKeepAlives: false,       // Reuse connections (good)

    // DNS caching via Go runtime (no explicit control needed)
}

client := &http.Client{
    Transport: transport,
}
```

**Why Keep-Alive is safe**:
- Go closes idle conns after `IdleConnTimeout`
- Server can close conn anytime (HTTP 1.1 default)
- Attacker cannot force client to hold conn open longer than `IdleConnTimeout`

**Default Go behavior**:
- MaxIdleConns: 100 ✓
- MaxIdleConnsPerHost: 2 (⚠️ low for multiple registries)
- IdleConnTimeout: 90s ✓
- DisableKeepAlives: false ✓

---

### 5. Context Propagation
**Threat**: Missing context propagation loses timeout/cancellation semantics in nested calls.

**Problem**:
```go
// WRONG: No context passed to Download
func Resolve(baseURL string, org string) {
    // API call with context
    resp, err := http.Get(baseURL + path)  // Uses request context
    // ...

    // WRONG: Download uses default context (no timeout!)
    bundle, err := http.Get(bundleURL)  // No context → no timeout
}

// CORRECT: Pass context through
func Resolve(ctx context.Context, baseURL string, org string) {
    req, _ := http.NewRequestWithContext(ctx, "GET", baseURL+path, nil)
    resp, _ := client.Do(req)

    req2, _ := http.NewRequestWithContext(ctx, "GET", bundleURL, nil)
    resp2, _ := client.Do(req2)  // Uses same timeout!
}
```

**mcp-cage Implementation** (internal/registry/client.go - GOOD):
```go
// Resolve() accepts ctx and propagates to HTTP call
func (c *Client) Resolve(ctx context.Context, org, name, ref string) (*ResolveResponse, error) {
    path := fmt.Sprintf("/v1/org/%s/mcps/%s/resolve", url.QueryEscape(org), url.QueryEscape(name))
    endpoint := c.baseURL + path
    q := url.Values{}
    q.Set("ref", ref)
    endpoint = endpoint + "?" + q.Encode()

    // ✓ Uses context with timeout
    req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    resp, err := c.apiClient.Do(req)
    // ... handle response
}

// Download() also accepts ctx
func (c *Client) DownloadBundle(ctx context.Context, org, digest string) ([]byte, error) {
    path := fmt.Sprintf("/v1/org/%s/bundles/%s", url.QueryEscape(org), url.QueryEscape(digest))

    // ✓ Uses context
    req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+path, nil)
    if err != nil {
        return nil, err
    }

    resp, err := c.httpClient.Do(req)
    // ... handle response
}
```

**Best Practice Pattern**:
```go
// API function signature includes context
func (c *Client) FetchData(ctx context.Context) ([]byte, error) {
    // Create request WITH context
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil, err
    }

    // Do request
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // Read body WITH timeout awareness
    // (if ctx times out, Read will fail)
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    return body, nil
}

// Caller sets timeout
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
data, err := client.FetchData(ctx)
```

---

### 6. Redirect Handling
**Threat**: Attacker redirects client to malicious host, or causes redirect loops leading to DoS.

**Attack vectors**:
- **Redirect to attacker host**: Presigned URL redirects to attacker's server → steal secrets
- **Redirect loop**: URL1 → URL2 → URL3 → ... → URL1 → infinite loop → timeout/resource leak
- **Protocol downgrade**: HTTPS → HTTP (MITM possible)

**Mitigation**:
- **Max redirects**: 10 (reasonable for S3/GCS presigned URLs, blocks loops)
- **Validate redirect URL**: Ensure still HTTPS (no protocol downgrade)
- **Log redirects**: Audit where traffic goes

**mcp-cage Implementation** (internal/registry/client.go - GOOD):
```go
const MaxRedirects = 10

apiClient := &http.Client{
    Timeout: DefaultAPITimeout,
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        // Block after MaxRedirects
        if len(via) >= MaxRedirects {
            return fmt.Errorf("too many redirects (max %d)", MaxRedirects)
        }
        return nil
    },
}

httpClient := &http.Client{
    Timeout: DefaultDownloadTimeout,
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        // Block after MaxRedirects
        if len(via) >= MaxRedirects {
            return fmt.Errorf("too many redirects (max %d)", MaxRedirects)
        }
        return nil
    },
}
```

**Enhanced version** (validate redirect safety):
```go
CheckRedirect: func(req *http.Request, via []*http.Request) error {
    // Block after MaxRedirects
    if len(via) >= MaxRedirects {
        return fmt.Errorf("too many redirects (max %d)", MaxRedirects)
    }

    // Security: Only allow HTTPS (no downgrade)
    if req.URL.Scheme != "https" {
        return fmt.Errorf("redirect to non-HTTPS URL not allowed: %s", req.URL)
    }

    // Security: Only allow same host or trusted CDN hosts
    originalHost := via[0].URL.Host
    if req.URL.Host != originalHost {
        // Allow S3/GCS CDN redirects (optional whitelist)
        trustedHosts := []string{"s3.amazonaws.com", "storage.googleapis.com"}
        allowed := false
        for _, h := range trustedHosts {
            if strings.HasSuffix(req.URL.Host, h) {
                allowed = true
                break
            }
        }
        if !allowed {
            return fmt.Errorf("redirect to unauthorized host not allowed: %s → %s",
                originalHost, req.URL.Host)
        }
    }

    return nil
},
```

---

### 7. Request Headers & User-Agent
**Threat**: Missing or malformed headers leak client identity or fail authentication.

**Headers**:
- **User-Agent**: Identifies client (e.g., `mcp-cage/1.0.0`)
- **Authorization**: Auth token (must not leak in logs)
- **Accept**: Desired response format
- **Content-Type**: Request body format
- **Host**: Required by HTTP/1.1

**mcp-cage Implementation** (internal/registry/auth.go):
```go
// Add Authorization header if token is set
func (c *Client) addAuthHeader(req *http.Request) {
    if c.token != "" {
        req.Header.Set("Authorization", "Bearer "+c.token)  // ✓ Proper format
    }
}

// In resolve request (internal/registry/client.go):
c.logger.Debug("resolving package", slog.String("endpoint", endpoint))

// Create request
req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
if err != nil {
    return nil, fmt.Errorf("failed to create request: %w", err)
}

// Add standard headers
req.Header.Set("User-Agent", fmt.Sprintf("mcp-cage/%s", version))  // ✓ Good
req.Header.Set("Accept", "application/json")                         // ✓ Good

// Add auth if present
c.addAuthHeader(req)  // ✓ Uses Bearer token
```

**Best Practice**:
```go
// Set User-Agent once in client init
const UserAgentVersion = "1.0.0"

func (c *Client) newRequest(ctx context.Context, method, urlStr string) (*http.Request, error) {
    req, err := http.NewRequestWithContext(ctx, method, urlStr, nil)
    if err != nil {
        return nil, err
    }

    // Set standard headers
    req.Header.Set("User-Agent", fmt.Sprintf("mcp-cage/%s", UserAgentVersion))
    req.Header.Set("Accept", "application/json")

    // Set auth if present
    if c.token != "" {
        req.Header.Set("Authorization", "Bearer "+c.token)
    }

    return req, nil
}
```

**Security Note on Authorization**:
```go
// WRONG: Logs token (security breach)
logger.Info("request", slog.String("auth", "Bearer "+token))

// CORRECT: Don't log token value
logger.Info("request", slog.String("auth", "Bearer ****"))

// CORRECT: Don't log at all (silent)
req.Header.Set("Authorization", "Bearer "+token)
// No logging
```

---

### 8. Response Validation
**Threat**: Server sends unexpected response (wrong content-type, corrupted body, huge response), causing parsing errors or resource exhaustion.

**Validations**:
- **Status code**: Expect 2xx (200, 206 for partial), handle 3xx/4xx/5xx
- **Content-Type**: Verify `application/json` or `application/octet-stream`
- **Content-Length**: Validate claimed size before reading (prevents resource exhaustion)
- **Body size**: Limit body read to MaxManifestSize/MaxBundleSize

**mcp-cage Implementation** (internal/registry/client.go - PARTIAL):
```go
const (
    MaxManifestSize = 10 * 1024 * 1024    // 10 MB
    MaxBundleSize = 100 * 1024 * 1024     // 100 MB
)

func (c *Client) DownloadBundle(ctx context.Context, org, digest string) ([]byte, error) {
    path := fmt.Sprintf("/v1/org/%s/bundles/%s", url.QueryEscape(org), url.QueryEscape(digest))
    endpoint := c.baseURL + path

    req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
    if err != nil {
        return nil, err
    }

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to download bundle: %w", err)
    }
    defer resp.Body.Close()

    // Check status
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
    }

    // Limit body read to MaxBundleSize
    limitedBody := io.LimitReader(resp.Body, MaxBundleSize+1)
    data, err := io.ReadAll(limitedBody)
    if err != nil {
        return nil, fmt.Errorf("failed to read bundle: %w", err)
    }

    // Check size limit
    if int64(len(data)) > MaxBundleSize {
        return nil, fmt.Errorf("bundle size exceeds limit: %d > %d",
            len(data), MaxBundleSize)
    }

    return data, nil
}
```

**Enhanced validation**:
```go
// Validate Content-Type (optional but good practice)
if ct := resp.Header.Get("Content-Type"); ct != "" &&
   !strings.Contains(ct, "application/octet-stream") &&
   !strings.Contains(ct, "application/gzip") {
    return nil, fmt.Errorf("unexpected content-type: %s", ct)
}

// Validate Content-Length (if present)
if cl := resp.Header.Get("Content-Length"); cl != "" {
    contentLen, err := strconv.ParseInt(cl, 10, 64)
    if err != nil {
        return nil, fmt.Errorf("invalid content-length: %s", cl)
    }
    if contentLen > MaxBundleSize {
        return nil, fmt.Errorf("content-length exceeds limit: %d > %d",
            contentLen, MaxBundleSize)
    }
}
```

---

### 9. Retry Strategy
**Threat**: Transient network errors cause failure, but without proper retry logic, causes cascading failures.

**Design**:
- **Retryable errors**: 5xx (server error), network timeouts, connection resets
- **Non-retryable errors**: 4xx (client error, except 429), malformed request
- **Backoff**: Exponential backoff with jitter (prevents thundering herd)
- **Max attempts**: 3 retries (total 4 attempts)

**Backoff formula**:
```
delay = min(baseDelay * 2^attempt + jitter, maxDelay)
jitter = random(0, 1) * baseDelay * 2^attempt
```

**Example**:
```
Attempt 1: immediate (no delay)
Attempt 2: 1s + jitter (max 2s)
Attempt 3: 2s + jitter (max 4s)
Attempt 4: 4s + jitter (max 8s)
Total max time: 15s for API calls
```

**mcp-cage Implementation** (internal/registry/client.go - **MISSING**, could add):
```go
const (
    MaxRetries = 3
    BaseBackoff = 100 * time.Millisecond
    MaxBackoff = 10 * time.Second
)

func (c *Client) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
    var lastErr error

    for attempt := 0; attempt <= MaxRetries; attempt++ {
        resp, err := c.httpClient.Do(req)

        // Success
        if err == nil && resp.StatusCode < 500 {
            return resp, nil
        }

        // Determine if retryable
        retryable := false
        if err != nil {
            // Network errors are retryable
            if _, ok := err.(net.Error); ok {
                retryable = true
            }
            // Context errors are NOT retryable
            if errors.Is(err, context.Canceled) {
                return nil, err
            }
        } else if resp.StatusCode >= 500 || resp.StatusCode == 429 {
            // 5xx and rate limit errors are retryable
            retryable = true
            resp.Body.Close()
        }

        if !retryable {
            if resp != nil {
                resp.Body.Close()
            }
            return resp, err
        }

        lastErr = err

        // Last attempt, don't backoff
        if attempt >= MaxRetries {
            break
        }

        // Exponential backoff with jitter
        backoff := time.Duration(math.Pow(2, float64(attempt))) * BaseBackoff
        if backoff > MaxBackoff {
            backoff = MaxBackoff
        }
        jitter := time.Duration(rand.Int63n(int64(backoff)))
        delay := backoff + jitter

        c.logger.Debug("retrying request",
            slog.Int("attempt", attempt+2),
            slog.Duration("delay", delay))

        select {
        case <-time.After(delay):
            // Continue
        case <-ctx.Done():
            return nil, ctx.Err()
        }
    }

    return nil, fmt.Errorf("failed after %d attempts: %w", MaxRetries+1, lastErr)
}
```

---

### 10. Error Classification
**Threat**: Treating non-retryable errors as retryable (or vice versa) causes wrong behavior.

**Classification**:
```
RETRYABLE (wait and retry):
  - 500 Internal Server Error
  - 502 Bad Gateway
  - 503 Service Unavailable
  - 504 Gateway Timeout
  - 429 Too Many Requests (rate limit)
  - Network timeout (context deadline exceeded)
  - Connection reset by peer
  - Temporary DNS failure

NON-RETRYABLE (fail immediately):
  - 400 Bad Request
  - 401 Unauthorized
  - 403 Forbidden
  - 404 Not Found
  - 405 Method Not Allowed
  - Client error (malformed request)
  - Context canceled (user requested cancel)
  - TLS certificate error
```

**mcp-cage Implementation** (internal/registry/errors.go - already has error types):
```go
// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
    // Network errors
    var netErr net.Error
    if errors.As(err, &netErr) {
        // Timeout is retryable
        if netErr.Timeout() {
            return true
        }
        // Temporary is usually retryable (connection reset, etc)
        if netErr.Temporary() {
            return true
        }
    }

    // Context errors are NOT retryable
    if errors.Is(err, context.Canceled) {
        return false
    }
    if errors.Is(err, context.DeadlineExceeded) {
        return false  // Already timed out, don't retry
    }

    // Default: not retryable
    return false
}

// IsRetryableStatusCode checks if HTTP status is retryable
func IsRetryableStatusCode(status int) bool {
    switch status {
    case 500, 502, 503, 504: // 5xx errors
        return true
    case 429: // Rate limit
        return true
    default:
        return false
    }
}
```

---

## Secure HTTP Client Template

**Production-ready implementation**:
```go
package registry

import (
    "context"
    "crypto/tls"
    "errors"
    "fmt"
    "io"
    "log/slog"
    "math"
    "math/rand"
    "net"
    "net/http"
    "net/url"
    "strconv"
    "strings"
    "time"
)

const (
    DefaultAPITimeout = 30 * time.Second
    DefaultDownloadTimeout = 5 * time.Minute

    MaxRedirects = 10
    MaxRetries = 3

    MaxManifestSize = 10 * 1024 * 1024
    MaxBundleSize = 100 * 1024 * 1024

    BaseBackoff = 100 * time.Millisecond
    MaxBackoff = 10 * time.Second
)

// Client is a secure HTTP client for registry communication
type Client struct {
    baseURL    string
    apiClient  *http.Client      // For API calls (30s timeout)
    httpClient *http.Client      // For downloads (5m timeout)
    token      string
    logger     *slog.Logger
}

// NewClient creates a new secure registry client
func NewClient(baseURL string) *Client {
    if baseURL == "" {
        baseURL = "https://registry.mcp-hub.info"
    }

    // TLS configuration: secure defaults
    tlsConfig := &tls.Config{
        MinVersion: tls.VersionTLS12,
        // Go default cipher suites are modern, no need to override
        InsecureSkipVerify: false,
        RootCAs: nil, // Use system certificate pool
    }

    // API client for metadata operations
    apiClient := createClient(DefaultAPITimeout, tlsConfig)

    // Download client for large file operations
    downloadClient := createClient(DefaultDownloadTimeout, tlsConfig)

    return &Client{
        baseURL:    baseURL,
        apiClient:  apiClient,
        httpClient: downloadClient,
        logger:     slog.Default(),
    }
}

// createClient creates an HTTP client with proper configuration
func createClient(timeout time.Duration, tlsConfig *tls.Config) *http.Client {
    transport := &http.Transport{
        // TLS configuration
        TLSClientConfig: tlsConfig,

        // Connection timeouts
        DialContext: (&net.Dialer{
            Timeout: 10 * time.Second,
            KeepAlive: 30 * time.Second,
        }).DialContext,
        ResponseHeaderTimeout: 30 * time.Second,

        // Connection pooling
        MaxIdleConns: 100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout: 90 * time.Second,

        // Keep-Alive enabled (connection reuse)
        DisableKeepAlives: false,
    }

    return &http.Client{
        Timeout: timeout,
        Transport: transport,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            // Limit redirects
            if len(via) >= MaxRedirects {
                return fmt.Errorf("too many redirects (max %d)", MaxRedirects)
            }

            // Security: only HTTPS
            if req.URL.Scheme != "https" {
                return fmt.Errorf("redirect to non-HTTPS not allowed: %s", req.URL)
            }

            return nil
        },
    }
}

// newRequest creates a new HTTP request with proper headers
func (c *Client) newRequest(ctx context.Context, method, urlStr string) (*http.Request, error) {
    req, err := http.NewRequestWithContext(ctx, method, urlStr, nil)
    if err != nil {
        return nil, err
    }

    // Set standard headers
    req.Header.Set("User-Agent", "mcp-cage/1.0.0")
    req.Header.Set("Accept", "application/json")

    // Add auth token if present
    if c.token != "" {
        req.Header.Set("Authorization", "Bearer "+c.token)
    }

    return req, nil
}

// doWithRetry performs request with exponential backoff retry
func (c *Client) doWithRetry(ctx context.Context, req *http.Request, maxSize int64) (*http.Response, error) {
    var lastErr error

    for attempt := 0; attempt <= MaxRetries; attempt++ {
        resp, err := c.apiClient.Do(req)

        // Success
        if err == nil && resp.StatusCode < 500 {
            return resp, nil
        }

        // Determine if retryable
        retryable := false
        if err != nil {
            retryable = isRetryableError(err)
        } else if isRetryableStatusCode(resp.StatusCode) {
            retryable = true
            resp.Body.Close()
        }

        if !retryable {
            if resp != nil {
                resp.Body.Close()
            }
            return resp, err
        }

        lastErr = err

        // Last attempt, don't backoff
        if attempt >= MaxRetries {
            break
        }

        // Exponential backoff with jitter
        delay := calculateBackoff(attempt)
        c.logger.Debug("retrying request",
            slog.Int("attempt", attempt+2),
            slog.Duration("delay", delay))

        select {
        case <-time.After(delay):
            // Continue
        case <-ctx.Done():
            return nil, ctx.Err()
        }
    }

    return nil, fmt.Errorf("failed after %d attempts: %w", MaxRetries+1, lastErr)
}

// calculateBackoff computes exponential backoff with jitter
func calculateBackoff(attempt int) time.Duration {
    backoff := time.Duration(math.Pow(2, float64(attempt))) * BaseBackoff
    if backoff > MaxBackoff {
        backoff = MaxBackoff
    }
    jitter := time.Duration(rand.Int63n(int64(backoff)))
    return backoff + jitter
}

// isRetryableError checks if an error should be retried
func isRetryableError(err error) bool {
    // Network errors
    var netErr net.Error
    if errors.As(err, &netErr) {
        return netErr.Timeout() || netErr.Temporary()
    }

    // Context errors are NOT retryable
    if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
        return false
    }

    return false
}

// isRetryableStatusCode checks if HTTP status is retryable
func isRetryableStatusCode(status int) bool {
    switch status {
    case 500, 502, 503, 504, 429:
        return true
    default:
        return false
    }
}

// Resolve resolves a package reference
func (c *Client) Resolve(ctx context.Context, org, name, ref string) (*ResolveResponse, error) {
    path := fmt.Sprintf("/v1/org/%s/mcps/%s/resolve", url.QueryEscape(org), url.QueryEscape(name))
    endpoint := c.baseURL + path
    q := url.Values{}
    q.Set("ref", ref)
    endpoint = endpoint + "?" + q.Encode()

    req, err := c.newRequest(ctx, "GET", endpoint)
    if err != nil {
        return nil, err
    }

    resp, err := c.doWithRetry(ctx, req, MaxManifestSize)
    if err != nil {
        return nil, fmt.Errorf("failed to resolve: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("resolve failed: status %d", resp.StatusCode)
    }

    var result ResolveResponse
    if err := parseJSONResponse(resp, &result, MaxManifestSize); err != nil {
        return nil, err
    }

    return &result, nil
}

// DownloadManifest downloads a manifest from registry
func (c *Client) DownloadManifest(ctx context.Context, org, digest string) ([]byte, error) {
    path := fmt.Sprintf("/v1/org/%s/manifests/%s", url.QueryEscape(org), url.QueryEscape(digest))
    endpoint := c.baseURL + path

    req, err := c.newRequest(ctx, "GET", endpoint)
    if err != nil {
        return nil, err
    }

    resp, err := c.doWithRetry(ctx, req, MaxManifestSize)
    if err != nil {
        return nil, fmt.Errorf("failed to download manifest: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("download failed: status %d", resp.StatusCode)
    }

    return readLimitedBody(resp, MaxManifestSize)
}

// DownloadBundle downloads a bundle from registry
func (c *Client) DownloadBundle(ctx context.Context, org, digest string) ([]byte, error) {
    path := fmt.Sprintf("/v1/org/%s/bundles/%s", url.QueryEscape(org), url.QueryEscape(digest))
    endpoint := c.baseURL + path

    req, err := c.newRequest(ctx, "GET", endpoint)
    if err != nil {
        return nil, err
    }

    resp, err := c.doWithRetry(ctx, req, MaxBundleSize)
    if err != nil {
        return nil, fmt.Errorf("failed to download bundle: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("download failed: status %d", resp.StatusCode)
    }

    return readLimitedBody(resp, MaxBundleSize)
}

// readLimitedBody reads response body with size limit
func readLimitedBody(resp *http.Response, maxSize int64) ([]byte, error) {
    // Check Content-Length if present
    if cl := resp.Header.Get("Content-Length"); cl != "" {
        contentLen, err := strconv.ParseInt(cl, 10, 64)
        if err == nil && contentLen > maxSize {
            return nil, fmt.Errorf("content length exceeds limit: %d > %d",
                contentLen, maxSize)
        }
    }

    // Read with limit
    limitedBody := io.LimitReader(resp.Body, maxSize+1)
    data, err := io.ReadAll(limitedBody)
    if err != nil {
        return nil, fmt.Errorf("failed to read response: %w", err)
    }

    if int64(len(data)) > maxSize {
        return nil, fmt.Errorf("response size exceeds limit: %d > %d",
            len(data), maxSize)
    }

    return data, nil
}

// parseJSONResponse parses JSON response with size limit
func parseJSONResponse(resp *http.Response, v interface{}, maxSize int64) error {
    // Only accept JSON
    ct := resp.Header.Get("Content-Type")
    if !strings.Contains(ct, "application/json") {
        return fmt.Errorf("unexpected content-type: %s", ct)
    }

    body, err := readLimitedBody(resp, maxSize)
    if err != nil {
        return err
    }

    if err := json.Unmarshal(body, v); err != nil {
        return fmt.Errorf("failed to parse JSON: %w", err)
    }

    return nil
}
```

---

## Testing HTTP Client

### Unit Tests
```go
func TestClient_TLSConfiguration(t *testing.T) {
    client := NewClient("https://registry.example.com")
    transport := client.apiClient.Transport.(*http.Transport)

    // Verify TLS 1.2+
    assert.Equal(t, tls.VersionTLS12, transport.TLSClientConfig.MinVersion)
    // Verify cert verification enabled
    assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestClient_Timeouts(t *testing.T) {
    client := NewClient("https://registry.example.com")

    // API client should have 30s timeout
    assert.Equal(t, 30*time.Second, client.apiClient.Timeout)
    // Download client should have 5m timeout
    assert.Equal(t, 5*time.Minute, client.httpClient.Timeout)
}

func TestClient_ConnectionPooling(t *testing.T) {
    client := NewClient("https://registry.example.com")
    transport := client.apiClient.Transport.(*http.Transport)

    assert.Equal(t, 100, transport.MaxIdleConns)
    assert.Equal(t, 10, transport.MaxIdleConnsPerHost)
    assert.False(t, transport.DisableKeepAlives)
}

func TestClient_RedirectLimit(t *testing.T) {
    // Mock server with infinite redirects
    // Verify client stops after MaxRedirects
}

func TestClient_RetryLogic(t *testing.T) {
    // Mock server returning 503
    // Verify client retries and eventually succeeds
    // Verify backoff increases between attempts
}

func TestClient_SizeLimit(t *testing.T) {
    // Mock server returning response > MaxBundleSize
    // Verify client rejects with error
}
```

---

## Security Checklist

- [ ] TLS 1.2+ enforced (MinVersion set)
- [ ] Certificate verification enabled (InsecureSkipVerify: false)
- [ ] Cipher suites appropriate (prefer ECDHE)
- [ ] Context propagation used (all operations accept context.Context)
- [ ] Timeouts set (API: 30s, Download: 5m)
- [ ] Connection pooling configured (MaxIdleConns, IdleConnTimeout)
- [ ] Redirect limit enforced (MaxRedirects: 10)
- [ ] Redirect URL validated (HTTPS only, optional host check)
- [ ] Request headers set (User-Agent, Authorization)
- [ ] Response status validated (check StatusCode)
- [ ] Response body size limited (io.LimitReader)
- [ ] Retry logic implemented (exponential backoff, jitter)
- [ ] Retry classification correct (5xx/429 yes, 4xx/context.Canceled no)
- [ ] Secrets not logged (Authorization header value masked)
- [ ] Error messages user-friendly (no stack traces, actionable)

---

## References

- [NIST: TLS 1.2 Minimum](https://csrc.nist.gov/publications/detail/sp/800-52/rev-1)
- [Go http package](https://pkg.go.dev/net/http)
- [Go tls package](https://pkg.go.dev/crypto/tls)
- [OWASP: Certificate Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)
- [AWS: Presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
