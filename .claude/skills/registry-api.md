# Registry API Skill

Expert knowledge for implementing and interacting with MCP registry HTTP client.

## OpenAPI Contract Overview

The MCP registry follows REST conventions with JSON request/response bodies. The canonical OpenAPI specification is maintained at:
**github.com/security-mcp/mcp-registry/blob/main/openapi/registry.yaml**

Key characteristics:
- Base URL: `https://registry.example.com/v1` (configurable)
- All artifact endpoints support both direct download and HTTP redirects
- All responses include proper HTTP status codes and error details
- Requires `User-Agent: mcp-cage/<version>` header in all requests

---

## Authentication Methods

### 1. Bearer JWT (Enterprise/Private Registries)

**Format:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**JWT Claims (Expected):**
```json
{
  "sub": "user@example.com",           // Subject: unique user identifier
  "org": "acme",                        // Organization (optional, for filtering)
  "exp": 1735689600,                    // Expiration timestamp (Unix seconds)
  "iat": 1704153600,                    // Issued at timestamp
  "scope": "mcp:read mcp:write"         // Scope of permissions
}
```

**Lifecycle:**
- Obtained via login endpoint or external IdP
- Expires at `exp` claim
- Must be refreshed before expiry
- Store securely in `~/.smcp/auth.json`

**Implementation:**
```go
// Add JWT to request
req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

// Check expiration before use
if time.Now().Unix() > claims.ExpiresAt {
    return fmt.Errorf("token expired at %d", claims.ExpiresAt)
}
```

### 2. API Token (Enterprise Service Accounts)

**Format:**
```
Authorization: Token <token_id>:<secret>
```

**Usage:**
- For CI/CD pipelines and service-to-service auth
- Token ID and secret provided by registry admin
- Never embed in version control

**Example:**
```
Authorization: Token tok_3c8f2a9b:secret_w7x9kq2m
```

### 3. Basic Auth (OSS Mode Only)

**Format:**
```
Authorization: Basic base64(username:password)
```

**Usage:**
- Only available in open-source mode
- Not recommended for production
- Credentials transmitted as base64 (not encrypted)

**Go Implementation:**
```go
req.SetBasicAuth("username", "password")
```

---

## Key Endpoints

### 1. Login (OSS Mode)

**Endpoint:** `POST /v1/auth/login`

**Request:**
```json
{
  "username": "user@example.com",
  "password": "password123"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Errors:**
- `400 Bad Request`: Missing username/password
- `401 Unauthorized`: Invalid credentials
- `429 Too Many Requests`: Too many failed attempts (implement backoff)

**Client Implementation:**
```go
func (c *Client) Login(ctx context.Context, username, password string) (string, error) {
    req := struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }{username, password}

    var resp struct {
        AccessToken string `json:"access_token"`
        ExpiresIn   int    `json:"expires_in"`
    }

    if err := c.post(ctx, "/v1/auth/login", req, &resp); err != nil {
        return "", err
    }

    return resp.AccessToken, nil
}
```

---

### 2. Resolve Package Reference

**Endpoint:** `GET /v1/org/{org}/mcps/{name}/resolve`

**Query Parameters:**
- `ref` (required): Version reference - can be:
  - Semantic version: `1.2.3`
  - Git SHA: `abc123def456`
  - Digest: `sha256:abc123...` or `sha512:abc123...`

**Response (200 OK):**
```json
{
  "package": "acme/hello-world",
  "ref": "1.2.3",
  "resolved": {
    "version": "1.2.3",
    "git_sha": "abc123def456789",
    "status": "published",
    "certification_level": 2,
    "manifest": {
      "digest": "sha256:abc123...",
      "url": "https://registry.example.com/v1/org/acme/artifacts/sha256:abc123/manifest"
    },
    "bundle": {
      "digest": "sha256:def456...",
      "url": "https://registry.example.com/v1/org/acme/artifacts/sha256:def456/bundle",
      "size_bytes": 12345678
    },
    "evidence": [
      {
        "type": "security_scan",
        "status": "passed",
        "timestamp": "2026-01-15T10:30:00Z"
      }
    ]
  }
}
```

**Errors:**
- `400 Bad Request`: Invalid ref format
- `401 Unauthorized`: Missing/invalid authentication
- `404 Not Found`: Package or version not found
- `429 Too Many Requests`: Rate limited

**Package Status Values:**
- `draft`: Work in progress, not published
- `ingested`: Uploaded but not verified
- `scanned`: Security scanned but not published
- `published`: Public and available
- `quarantined`: Blocked due to security issues
- `deprecated`: No longer recommended
- `revoked`: Removed from distribution

**Certification Levels:**
- `0`: No certification
- `1`: Basic security scanning
- `2`: Security + license verification
- `3`: Full audit + attestation

**Client Implementation:**
```go
type ResolveResponse struct {
    Package string `json:"package"`
    Ref     string `json:"ref"`
    Resolved struct {
        Version             string `json:"version"`
        GitSHA              string `json:"git_sha"`
        Status              string `json:"status"`
        CertificationLevel  int    `json:"certification_level"`
        Manifest struct {
            Digest string `json:"digest"`
            URL    string `json:"url"`
        } `json:"manifest"`
        Bundle struct {
            Digest    string `json:"digest"`
            URL       string `json:"url"`
            SizeBytes int64  `json:"size_bytes"`
        } `json:"bundle"`
    } `json:"resolved"`
}

func (c *Client) Resolve(ctx context.Context, org, name, ref string) (*ResolveResponse, error) {
    endpoint := fmt.Sprintf("/v1/org/%s/mcps/%s/resolve?ref=%s", org, name, url.QueryEscape(ref))
    var resp ResolveResponse
    if err := c.get(ctx, endpoint, &resp); err != nil {
        return nil, err
    }
    return &resp, nil
}
```

---

### 3. Download Manifest

**Endpoint:** `GET /v1/org/{org}/artifacts/{digest}/manifest`

**Path Parameters:**
- `org`: Organization name
- `digest`: Manifest digest (e.g., `sha256:abc123...`)

**Response (200 OK):**
```
Content-Type: application/json
Content-Length: 4096

{
  "schema_version": "1.0",
  "package": {
    "org": "acme",
    "name": "hello-world",
    "version": "1.2.3",
    "description": "...",
    "author": "...",
    "license": "MIT"
  },
  ...
}
```

**Redirect Handling:**
- May return `302 Found` or `307 Temporary Redirect` with `Location` header
- Used for presigned S3/GCS URLs
- Follow redirects up to 10 times
- Validate digest on final content (after all redirects)

**Errors:**
- `401 Unauthorized`: Missing/invalid authentication
- `404 Not Found`: Digest not found
- `429 Too Many Requests`: Rate limited

**Client Implementation:**
```go
func (c *Client) DownloadManifest(ctx context.Context, org, digest string) ([]byte, error) {
    endpoint := fmt.Sprintf("/v1/org/%s/artifacts/%s/manifest", org, digest)

    // Create request with redirect handling
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+endpoint, nil)
    if err != nil {
        return nil, err
    }
    c.addHeaders(req)

    // Follow redirects (max 10)
    client := &http.Client{
        Timeout: 30 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= 10 {
                return fmt.Errorf("too many redirects")
            }
            return nil
        },
    }

    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("download failed: %d", resp.StatusCode)
    }

    return io.ReadAll(resp.Body)
}
```

---

### 4. Download Bundle

**Endpoint:** `GET /v1/org/{org}/artifacts/{digest}/bundle`

**Path Parameters:**
- `org`: Organization name
- `digest`: Bundle digest (e.g., `sha256:def456...`)

**Response (200 OK):**
```
Content-Type: application/gzip
Content-Length: 12345678

[binary tar.gz data]
```

**Special Considerations:**
- Returns compressed tar.gz archive
- Large files may take time to download
- Implement progress tracking for large bundles (>10MB)
- Validate digest AFTER decompression

**Digest Validation Pattern:**
```go
func (c *Client) DownloadAndValidateBundle(ctx context.Context, org, digest string) ([]byte, error) {
    // Extract expected hash from digest string
    parts := strings.Split(digest, ":")
    if len(parts) != 2 {
        return nil, fmt.Errorf("invalid digest format: %s", digest)
    }
    algo, expectedHash := parts[0], parts[1]

    // Download content
    content, err := c.downloadBundle(ctx, org, digest)
    if err != nil {
        return nil, err
    }

    // Validate hash
    h := sha256.New()
    if algo == "sha512" {
        h = sha512.New()
    }
    h.Write(content)
    actualHash := hex.EncodeToString(h.Sum(nil))

    if actualHash != expectedHash {
        return nil, fmt.Errorf("digest mismatch: expected %s, got %s", expectedHash, actualHash)
    }

    return content, nil
}
```

---

### 5. List Catalog

**Endpoint:** `GET /v1/catalog`

**Query Parameters (optional):**
- `org`: Filter by organization
- `limit`: Maximum results (default: 100, max: 1000)
- `offset`: Pagination offset

**Response (200 OK):**
```json
{
  "packages": [
    {
      "package": "acme/hello-world",
      "visibility": "public",
      "latest_version": "1.2.3",
      "description": "Hello World MCP Server",
      "certification_level": 2
    },
    {
      "package": "acme/tool-box",
      "visibility": "private",
      "latest_version": "2.0.0",
      "description": "Collection of tools",
      "certification_level": 1
    }
  ],
  "total": 42,
  "offset": 0,
  "limit": 100
}
```

**Visibility Values:**
- `public`: Available to all users
- `private`: Only accessible to authenticated users with permission
- `internal`: Only accessible to organization members

**Client Implementation:**
```go
type CatalogResponse struct {
    Packages []struct {
        Package              string `json:"package"`
        Visibility          string `json:"visibility"`
        LatestVersion       string `json:"latest_version"`
        Description         string `json:"description"`
        CertificationLevel  int    `json:"certification_level"`
    } `json:"packages"`
    Total  int `json:"total"`
    Offset int `json:"offset"`
    Limit  int `json:"limit"`
}

func (c *Client) ListCatalog(ctx context.Context, org string, limit, offset int) (*CatalogResponse, error) {
    params := url.Values{}
    if org != "" {
        params.Set("org", org)
    }
    params.Set("limit", strconv.Itoa(limit))
    params.Set("offset", strconv.Itoa(offset))

    endpoint := "/v1/catalog?" + params.Encode()
    var resp CatalogResponse
    if err := c.get(ctx, endpoint, &resp); err != nil {
        return nil, err
    }
    return &resp, nil
}
```

---

## HTTP Client Setup

### Basic Configuration

```go
type RegistryClient struct {
    baseURL    string
    token      string
    httpClient *http.Client
    userAgent  string
}

func NewRegistryClient(baseURL, token, version string) *RegistryClient {
    return &RegistryClient{
        baseURL:   strings.TrimSuffix(baseURL, "/"),
        token:     token,
        userAgent: fmt.Sprintf("mcp-cage/%s", version),
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
            Transport: &http.Transport{
                MaxIdleConns:        10,
                MaxIdleConnsPerHost: 5,
                IdleConnTimeout:     30 * time.Second,
            },
        },
    }
}

func (c *RegistryClient) addHeaders(req *http.Request) {
    req.Header.Set("User-Agent", c.userAgent)
    if c.token != "" {
        req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
    }
}
```

### Request Helper Methods

```go
func (c *RegistryClient) get(ctx context.Context, path string, result interface{}) error {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
    if err != nil {
        return err
    }
    c.addHeaders(req)

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    return c.handleResponse(resp, result)
}

func (c *RegistryClient) post(ctx context.Context, path string, body, result interface{}) error {
    data, err := json.Marshal(body)
    if err != nil {
        return err
    }

    req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
    if err != nil {
        return err
    }
    c.addHeaders(req)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    return c.handleResponse(resp, result)
}

func (c *RegistryClient) handleResponse(resp *http.Response, result interface{}) error {
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return err
    }

    // Handle HTTP errors
    if resp.StatusCode >= 400 {
        var errResp struct {
            Message string `json:"message"`
            Code    string `json:"code"`
        }
        _ = json.Unmarshal(body, &errResp)
        return fmt.Errorf("HTTP %d: %s", resp.StatusCode, errResp.Message)
    }

    return json.Unmarshal(body, result)
}
```

---

## Retry Logic and Error Handling

### Retry Strategy

**Retryable Errors (5xx, 429):**
- Implement exponential backoff: 2^n * baseDelay (base: 1s, max: 1m)
- Maximum 3 retry attempts
- Do NOT retry on 4xx (except 429)
- Add jitter to prevent thundering herd

**Non-Retryable Errors (401, 403, 404):**
- Fail immediately
- Log error with context
- Do not retry

### Implementation Example

```go
func (c *RegistryClient) DoWithRetry(ctx context.Context, fn func() error) error {
    const maxAttempts = 3
    const baseDelay = 1 * time.Second
    const maxDelay = 1 * time.Minute

    var lastErr error
    for attempt := 0; attempt < maxAttempts; attempt++ {
        if attempt > 0 {
            delay := time.Duration(math.Pow(2, float64(attempt))) * baseDelay
            if delay > maxDelay {
                delay = maxDelay
            }
            // Add jitter (±20%)
            jitter := time.Duration(rand.Int63n(int64(delay/5)))
            delay = delay - delay/5 + jitter

            select {
            case <-time.After(delay):
            case <-ctx.Done():
                return ctx.Err()
            }
        }

        lastErr = fn()
        if lastErr == nil {
            return nil
        }

        // Check if error is retryable
        if !isRetryable(lastErr) {
            return lastErr
        }
    }

    return fmt.Errorf("max retries exceeded: %w", lastErr)
}

func isRetryable(err error) bool {
    var httpErr *HTTPError
    if !errors.As(err, &httpErr) {
        return false
    }

    // Retry on 5xx and 429
    return httpErr.StatusCode >= 500 || httpErr.StatusCode == 429
}
```

---

## Redirect Handling

### Presigned URLs and Redirects

Registries often return HTTP 302/307 redirects to presigned URLs (S3, GCS) for actual artifact delivery.

**Rules:**
1. Follow 3xx redirects automatically (up to 10 times)
2. Preserve HTTP method on 307, convert to GET on 302
3. Validate content digest after following all redirects
4. Do not leak auth tokens to redirect targets

**Example:**
```go
func (c *RegistryClient) downloadWithRedirects(ctx context.Context, url string, maxSize int64) ([]byte, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return nil, err
    }
    c.addHeaders(req)

    client := &http.Client{
        Timeout: 2 * time.Minute,  // Longer for large downloads
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) > 10 {
                return fmt.Errorf("too many redirects (%d)", len(via))
            }
            // Remove auth from redirect targets (security)
            req.Header.Del("Authorization")
            return nil
        },
    }

    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // Limit response size
    lr := io.LimitReader(resp.Body, maxSize+1)
    body, _ := io.ReadAll(lr)

    if int64(len(body)) > maxSize {
        return nil, fmt.Errorf("response exceeds max size (%d > %d)", len(body), maxSize)
    }

    return body, nil
}
```

---

## Digest Validation

### SHA-256 Validation Pattern

**Critical Rule:** ALWAYS validate digest after download.

```go
func ValidateSHA256(data []byte, digest string) error {
    // Expected format: "sha256:abc123..."
    parts := strings.Split(digest, ":")
    if len(parts) != 2 || parts[0] != "sha256" {
        return fmt.Errorf("invalid digest format: %s", digest)
    }

    expectedHash := strings.ToLower(parts[1])

    // Calculate hash
    h := sha256.New()
    h.Write(data)
    actualHash := hex.EncodeToString(h.Sum(nil))

    if actualHash != expectedHash {
        return fmt.Errorf("digest mismatch: expected %s, got %s", expectedHash, actualHash)
    }

    return nil
}
```

### SHA-512 Support

```go
func ValidateDigest(data []byte, digest string) error {
    parts := strings.Split(digest, ":")
    if len(parts) != 2 {
        return fmt.Errorf("invalid digest format: %s", digest)
    }

    algo, expectedHash := parts[0], parts[1]
    expectedHash = strings.ToLower(expectedHash)

    var h hash.Hash
    switch algo {
    case "sha256":
        h = sha256.New()
    case "sha512":
        h = sha512.New()
    default:
        return fmt.Errorf("unsupported digest algorithm: %s", algo)
    }

    h.Write(data)
    actualHash := hex.EncodeToString(h.Sum(nil))

    if actualHash != expectedHash {
        return fmt.Errorf("digest mismatch: expected %s:%s, got %s:%s", algo, expectedHash, algo, actualHash)
    }

    return nil
}
```

---

## Error Types

### Standard HTTP Status Codes

| Status | Meaning | Action |
|--------|---------|--------|
| 200 | OK | Success |
| 302/307 | Redirect | Follow to new URL |
| 400 | Bad Request | Fix request, don't retry |
| 401 | Unauthorized | Check token, may need re-login |
| 403 | Forbidden | User lacks permission, don't retry |
| 404 | Not Found | Resource doesn't exist, don't retry |
| 429 | Too Many Requests | Backoff exponentially, retry |
| 500 | Server Error | Retry with exponential backoff |
| 503 | Service Unavailable | Retry with exponential backoff |

### Custom Error Type

```go
type HTTPError struct {
    StatusCode int
    Message    string
    Code       string
    Endpoint   string
}

func (e *HTTPError) Error() string {
    return fmt.Sprintf("HTTP %d: %s (endpoint: %s)", e.StatusCode, e.Message, e.Endpoint)
}

func (e *HTTPError) IsRetryable() bool {
    return e.StatusCode >= 500 || e.StatusCode == 429
}

func (e *HTTPError) IsAuthError() bool {
    return e.StatusCode == 401 || e.StatusCode == 403
}
```

### Common Error Scenarios

**Token Expired:**
```
HTTP 401: Unauthorized (code: token_expired)
→ Action: Refresh token, retry request
```

**Package Not Found:**
```
HTTP 404: Package not found (code: package_not_found)
→ Action: Suggest checking package name/org, list catalog
```

**Registry Offline:**
```
HTTP 503: Service Unavailable
→ Action: Retry with backoff, suggest using cached version
```

**Invalid Digest:**
```
Digest validation failed: expected sha256:abc, got sha256:xyz
→ Action: Delete cached artifact, re-download, fail if mismatch persists
```

---

## Debugging Commands

### cURL Examples

**Resolve package:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://registry.example.com/v1/org/acme/mcps/hello-world/resolve?ref=1.0.0"
```

**Download manifest (follow redirects):**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  -L "https://registry.example.com/v1/org/acme/artifacts/sha256:abc123/manifest" \
  -o manifest.json
```

**Validate digest after download:**
```bash
sha256sum manifest.json
# Compare with: sha256:abc123...
```

**Login and get token:**
```bash
curl -X POST https://registry.example.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}' \
  | jq '.access_token'
```

**List catalog with pagination:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://registry.example.com/v1/catalog?limit=10&offset=0"
```

### Debugging in Code

```go
// Enable verbose HTTP logging
func NewVerboseClient(baseURL, token string) *RegistryClient {
    client := NewRegistryClient(baseURL, token, "1.0.0")
    client.httpClient.Transport = &http.Transport{
        Proxy: http.ProxyFromEnvironment,
    }

    // Wrap transport with logging
    return &RegistryClient{
        baseURL: client.baseURL,
        token:   client.token,
        httpClient: &http.Client{
            Transport: &debugTransport{client.httpClient.Transport},
        },
    }
}

type debugTransport struct {
    inner http.RoundTripper
}

func (d *debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    fmt.Printf("[DEBUG] %s %s\n", req.Method, req.URL)
    resp, err := d.inner.RoundTrip(req)
    if err == nil {
        fmt.Printf("[DEBUG] Response: %d %s\n", resp.StatusCode, resp.Status)
    }
    return resp, err
}
```

---

## Caching HTTP Responses

Some registry endpoints support HTTP caching headers.

**Respect Cache-Control:**
```go
// Example: resolve endpoint may return Cache-Control: max-age=3600
func (c *RegistryClient) Resolve(ctx context.Context, ...) (*ResolveResponse, error) {
    // Check local cache before making request
    if cached, ok := c.resolveCache.Get(cacheKey); ok && cached.IsValid() {
        return cached.Data, nil
    }

    // Make request
    resp, err := c.resolve(ctx, ...)
    if err != nil {
        return nil, err
    }

    // Cache if server says to
    c.resolveCache.Set(cacheKey, resp)
    return resp, nil
}
```

**ETag Validation:**
```go
// Use ETag to avoid re-downloading unchanged content
func (c *RegistryClient) DownloadWithETag(ctx context.Context, url, etag string) ([]byte, error) {
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if etag != "" {
        req.Header.Set("If-None-Match", etag)
    }

    resp, _ := c.httpClient.Do(req)
    if resp.StatusCode == http.StatusNotModified {
        // Content unchanged, use cached version
        return c.getFromCache(url)
    }

    // 200: new content, cache it
    return io.ReadAll(resp.Body)
}
```

---

## Security Considerations

1. **Never log tokens** - Sanitize logs before output
2. **Validate HTTPS** - Always use TLS for production registries
3. **Token storage** - Save tokens with `0600` permissions only
4. **Timeout protection** - Always set reasonable timeouts (avoid hanging)
5. **No plaintext fallback** - Require HTTPS, no HTTP registry support
6. **Auth header stripping** - Remove auth headers on redirects to untrusted hosts

---

## Testing Patterns

### Mock Registry for Tests

```go
func TestResolve(t *testing.T) {
    // Create mock HTTP server
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/v1/org/test/mcps/pkg/resolve" {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(ResolveResponse{
                Package: "test/pkg",
                Resolved: struct {
                    Manifest struct {
                        Digest string `json:"digest"`
                        URL    string `json:"url"`
                    }
                }{
                    Manifest: struct {
                        Digest string `json:"digest"`
                        URL    string `json:"url"`
                    }{
                        Digest: "sha256:abc123",
                        URL:    server.URL + "/manifest",
                    },
                },
            })
        }
    }))
    defer server.Close()

    client := NewRegistryClient(server.URL, "", "test")
    resp, err := client.Resolve(context.Background(), "test", "pkg", "1.0.0")

    if err != nil {
        t.Fatal(err)
    }
    if resp.Package != "test/pkg" {
        t.Fail()
    }
}
```

### Simulating Retries

```go
func TestRetryLogic(t *testing.T) {
    attempts := 0
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        attempts++
        if attempts < 3 {
            w.WriteHeader(http.StatusServiceUnavailable)
        } else {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
        }
    }))

    client := NewRegistryClient(server.URL, "", "test")
    err := client.DoWithRetry(context.Background(), func() error {
        _, err := client.Resolve(context.Background(), "test", "pkg", "1.0.0")
        return err
    })

    if err != nil {
        t.Fatal(err)
    }
    if attempts != 3 {
        t.Errorf("expected 3 attempts, got %d", attempts)
    }
}
```
