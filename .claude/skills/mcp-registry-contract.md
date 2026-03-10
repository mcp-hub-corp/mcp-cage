# MCP Registry Integration Contract

Expert reference guide for MCP Registry API integration, package references, authentication, and testing patterns.

## Table of Contents
1. [Registry Overview](#registry-overview)
2. [Package References](#package-references)
3. [API Endpoints](#api-endpoints)
4. [Authentication Methods](#authentication-methods)
5. [Request/Response Structures](#requestresponse-structures)
6. [Version Statuses & Lifecycle](#version-statuses--lifecycle)
7. [Content Addressing](#content-addressing)
8. [Size & Rate Limits](#size--rate-limits)
9. [Error Handling](#error-handling)
10. [HTTP Headers & Caching](#http-headers--caching)
11. [Redirects & Presigned URLs](#redirects--presigned-urls)
12. [Testing Patterns](#testing-patterns-with-httptest)

---

## Registry Overview

### Purpose
MCP Registry is a centralized package distribution service for Model Context Protocol servers. It provides:
- Package discovery and versioning
- Manifest and bundle distribution
- Authentication and authorization
- Content addressing (immutable by digest)

### Default Registry
```
https://registry.mcp-hub.info
```

**Alternative registries:**
- Enterprise: `https://registry.example.com` (self-hosted)
- Development: `http://localhost:8000` (local)

### Source of Truth
The definitive API specification is:
```
https://github.com/security-mcp/mcp-registry/blob/main/openapi/registry.yaml
```

**Check this file before implementing any integration.**

---

## Package References

All package references follow immutable naming patterns to ensure reproducibility.

### Format Variants

#### Version Reference (Semantic Versioning)
```
org/name@1.2.3
org/name@latest
org/name@1.2.x
```

**What happens:**
1. mcp-cage sends to registry: `/resolve?ref=1.2.3`
2. Registry returns: Manifest digest, Bundle digest, URLs
3. Client caches by digest (immutable from now on)

**Example:**
```bash
smcp run acme/hello-world@1.2.3
# Registry resolves to:
# - manifest: sha256:abc123...
# - bundle: sha256:def456...
```

---

#### SHA Reference (Shortened Commit Hash)
```
org/name@sha:abc123
```

**What happens:**
1. Registry looks up sha:abc123 in version control
2. Returns corresponding manifest + bundle digests
3. Same immutability guarantee (by commit SHA)

**Example:**
```bash
smcp run acme/hello-world@sha:abc123abc
# Registry resolves to manifest + bundle for that commit
```

**Use case:** CI/CD pipeline references exact commit that was tested

---

#### Digest Reference (Full SHA-256)
```
org/name@digest:sha256:abc123def456...
```

**What happens:**
1. Client specifies exact manifest digest
2. Registry skips resolve step
3. Client downloads manifest directly from /artifacts/{digest}/manifest

**Example:**
```bash
smcp run acme/hello-world@digest:sha256:abc123def456abc123def456abc123def456abc1
# Client downloads from:
# GET /artifacts/sha256:abc123def456.../manifest
# GET /artifacts/sha256:def456ghi789.../bundle
```

**Use case:** Pinning to exact manifest version (most reproducible)

---

### Reference Resolution Algorithm

```
Input: org/name@ref

if ref matches ^[0-9]+\.[0-9]+\.[0-9]+$ :
  // Version reference
  registry.Resolve(org, name, {type: "version", ref: ref})

else if ref starts with "sha:" :
  // Commit SHA reference
  registry.Resolve(org, name, {type: "sha", ref: ref})

else if ref starts with "digest:" :
  // Digest reference (skip resolve, go direct to download)
  parsed_digest := ref.split(":")[1]
  return ParsedRef{ManifestDigest: parsed_digest, Type: "digest"}

else :
  error "Invalid reference format"
```

---

## API Endpoints

All endpoints return JSON unless specified. Base URL: `https://registry.mcp-hub.info`

### 1. Resolve Package (Immutable Reference to Digests)

**Endpoint:** `POST /v1/packages/:org/:name/resolve`

**Purpose:** Convert mutable reference (version/sha) to immutable digests

**Request:**
```bash
curl -X POST https://registry.mcp-hub.info/v1/packages/acme/hello-world/resolve \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "ref": "1.2.3",
    "platform": "linux",
    "arch": "amd64"
  }'
```

**Request Body (optional platform filter):**
```json
{
  "ref": "1.2.3",                    // Required: version, sha, or 'latest'
  "platform": "linux|darwin|windows",  // Optional: filter entrypoints
  "arch": "amd64|arm64"               // Optional: filter entrypoints
}
```

**Response (200 OK):**
```json
{
  "manifest": {
    "digest": "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456",
    "url": "https://registry.mcp-hub.info/v1/artifacts/sha256:abc123.../manifest",
    "size_bytes": 4200
  },
  "bundle": {
    "digest": "sha256:def456ghi789def456ghi789def456ghi789def456ghi789def456ghi789",
    "url": "https://registry.mcp-hub.info/v1/artifacts/sha256:def456.../bundle",
    "size_bytes": 13107200
  }
}
```

**Response Fields:**
- `manifest.digest` - SHA-256 of manifest JSON (immutable identifier)
- `manifest.url` - Download URL (may redirect to presigned S3/GCS URL)
- `bundle.digest` - SHA-256 of bundle tar.gz (immutable identifier)
- `bundle.url` - Download URL (may redirect to presigned S3/GCS URL)

**Errors:**
```json
// 404 Not Found
{
  "error": "not_found",
  "message": "Package 'acme/hello-world' not found"
}

// 400 Bad Request
{
  "error": "invalid_ref",
  "message": "Reference '1.99.99' does not exist (available: 1.0.0, 1.1.0, 1.2.0)"
}

// 401 Unauthorized
{
  "error": "unauthorized",
  "message": "Invalid or expired token"
}

// 403 Forbidden
{
  "error": "forbidden",
  "message": "You don't have access to package 'acme/hello-world'"
}
```

**Implementation Notes:**
- Resolve is cached by registry (may return old digest for 5-10 minutes)
- Client should cache resolve result by reference
- URLs may redirect (follow up to 10 redirects)
- digest is immutable: if same ref resolved, get same digest

---

### 2. Download Manifest

**Endpoint:** `GET /v1/artifacts/:digest/manifest`

**Purpose:** Download manifest JSON by digest

**Request:**
```bash
curl -H "Authorization: Bearer <token>" \
  https://registry.mcp-hub.info/v1/artifacts/sha256:abc123.../manifest
```

**Response (200 OK):**
```json
{
  "name": "hello-world",
  "version": "1.2.3",
  "org": "acme",
  "author": "acme-corp",
  "license": "MIT",
  "description": "A simple hello world MCP server",
  "entrypoints": {
    "linux-amd64": {
      "command": "./bin/mcp-server",
      "args": ["--mode", "stdio"]
    },
    "linux-arm64": { ... },
    "darwin-amd64": { ... },
    "windows-amd64": { ... }
  },
  "transport": "stdio",
  "policy": {
    "network": {
      "allowlist": ["api.example.com"]
    },
    "env": {
      "allow": ["API_KEY", "DEBUG"]
    },
    "subprocess": false
  }
}
```

**Response Headers:**
```
Content-Type: application/json
Content-Length: 4200
Cache-Control: public, immutable, max-age=31536000
ETag: "sha256:abc123..."
```

**Redirects (302/307):**
```
HTTP 302 Found
Location: https://s3.amazonaws.com/mcp-registry/manifests/abc123?Signature=...
```

**Validation:**
Client must:
1. Calculate SHA-256 of response body
2. Compare against expected digest from resolve response
3. Reject if mismatch

---

### 3. Download Bundle

**Endpoint:** `GET /v1/artifacts/:digest/bundle`

**Purpose:** Download bundle (tar.gz with executable) by digest

**Request:**
```bash
curl -H "Authorization: Bearer <token>" \
  -o bundle.tar.gz \
  https://registry.mcp-hub.info/v1/artifacts/sha256:def456.../bundle
```

**Response (200 OK):**
```
[binary tar.gz content]
```

**Response Headers:**
```
Content-Type: application/gzip
Content-Length: 13107200
Cache-Control: public, immutable, max-age=31536000
ETag: "sha256:def456..."
```

**Bundle Contents (typical):**
```
bundle.tar.gz
├── bin/
│   └── mcp-server          (executable)
├── lib/
│   ├── libfoo.so           (dependencies)
│   └── libbar.so
├── config/
│   └── default.conf
└── README.txt
```

**Or with embedded runtime:**
```
bundle.tar.gz
├── bin/
│   └── mcp-server          (Python script)
├── venv/
│   ├── bin/python
│   ├── lib/site-packages/  (dependencies)
```

**Extraction:**
```bash
tar -xzf bundle.tar.gz -C /tmp/mcp-work-dir/
```

**Validation:**
Client must:
1. Stream tar.gz to disk (don't hold entire bundle in RAM)
2. Calculate SHA-256 during streaming
3. Verify at end: computed digest == expected digest
4. Reject if mismatch

---

### 4. List Package Versions

**Endpoint:** `GET /v1/packages/:org/:name/versions`

**Purpose:** Discover available versions for a package

**Request:**
```bash
curl -H "Authorization: Bearer <token>" \
  https://registry.mcp-hub.info/v1/packages/acme/hello-world/versions
```

**Response (200 OK):**
```json
{
  "versions": [
    {
      "version": "1.2.3",
      "status": "published",
      "created_at": "2026-01-15T10:00:00Z",
      "manifest_digest": "sha256:abc123..."
    },
    {
      "version": "1.2.2",
      "status": "published",
      "created_at": "2026-01-10T10:00:00Z",
      "manifest_digest": "sha256:xyz789..."
    },
    {
      "version": "1.2.1",
      "status": "deprecated",
      "created_at": "2026-01-01T10:00:00Z",
      "manifest_digest": "sha256:old999..."
    }
  ]
}
```

**Status field values:**
- `draft` - Work in progress, not publicly available
- `ingested` - Uploaded but not yet scanned
- `scanned` - Security scan passed, not published
- `published` - Available for public use
- `deprecated` - Published but superseded
- `revoked` - No longer safe, pulled from registry

---

### 5. Package Metadata (Optional)

**Endpoint:** `GET /v1/packages/:org/:name`

**Purpose:** Get package info (not required for execution)

**Request:**
```bash
curl -H "Authorization: Bearer <token>" \
  https://registry.mcp-hub.info/v1/packages/acme/hello-world
```

**Response (200 OK):**
```json
{
  "org": "acme",
  "name": "hello-world",
  "description": "A simple hello world MCP server",
  "homepage": "https://github.com/acme/hello-world",
  "license": "MIT",
  "downloads": 15234,
  "latest_version": "1.2.3",
  "latest_status": "published"
}
```

---

## Authentication Methods

### 1. Bearer Token (Default)

Used for all authenticated requests.

**Header format:**
```
Authorization: Bearer <token>
```

**Token acquisition:**
```bash
smcp login --token <JWT>
```

**Stored in:**
```
~/.smcp/auth.json
```

**Example token (JWT):**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiJ1c2VyLTEyMyIsIm9yZyI6ImFjbWUiLCJleHAiOjE3MDY3OTIwMDB9.
<signature>
```

**Decoded payload:**
```json
{
  "sub": "user-123",
  "org": "acme",
  "exp": 1706792000,
  "iat": 1706705600
}
```

**Token claims:**
- `sub` - Subject (user/service ID)
- `org` - Organization (for scoping access)
- `exp` - Expiration timestamp (unix epoch)
- `iat` - Issued at (unix epoch)

**Token rotation:**
Tokens expire after 90 days by default. Client should handle 401 and prompt for re-login:
```
[ERROR] Authentication failed (401): Token expired
[INFO] Run 'smcp login' to refresh your token
```

---

### 2. Custom Registry with Token

Enterprise registries may use different token format:

```bash
smcp login --registry https://custom.registry.com --token <custom-token>
```

**Stored as:**
```json
{
  "registries": {
    "https://custom.registry.com": {
      "token": "<custom-token>",
      "expires_at": "2026-04-18T10:00:00Z"
    }
  }
}
```

**Usage:**
```bash
smcp run org/name@1.0.0 --registry https://custom.registry.com
# Automatically uses token from auth.json
```

---

### 3. No Authentication (Public Packages)

Public packages don't require authentication:

```bash
smcp run org/public-package@1.0.0
# No token needed, registry accessible without Authorization header
```

**Client behavior:**
- If no token available for registry, send request without Authorization header
- If registry returns 401, prompt user to login
- If registry returns 200, allow access

---

## Request/Response Structures

### Manifest Structure (Canonical)

```json
{
  "name": "hello-world",
  "version": "1.2.3",
  "org": "acme",
  "author": "acme-corp <team@acme.com>",
  "license": "MIT",
  "description": "A simple hello world MCP server",
  "homepage": "https://github.com/acme/hello-world",
  "repository": {
    "type": "git",
    "url": "https://github.com/acme/hello-world.git"
  },
  "entrypoints": {
    "linux-amd64": {
      "command": "./bin/mcp-server",
      "args": ["--mode", "stdio"]
    },
    "linux-arm64": {
      "command": "./bin/mcp-server-arm64",
      "args": ["--mode", "stdio"]
    },
    "darwin-amd64": {
      "command": "./bin/mcp-server-macos",
      "args": ["--mode", "stdio"]
    },
    "darwin-arm64": {
      "command": "./bin/mcp-server-macos",
      "args": ["--mode", "stdio"]
    },
    "windows-amd64": {
      "command": ".\\bin\\mcp-server.exe",
      "args": ["--mode", "stdio"]
    }
  },
  "transport": "stdio",
  "policy": {
    "network": {
      "allowlist": ["api.example.com", "*.example.com"]
    },
    "env": {
      "allow": ["API_KEY", "DEBUG", "LOG_LEVEL"]
    },
    "subprocess": false
  }
}
```

**Required fields:**
- `name` - Package name (lowercase, alphanumeric + dash)
- `version` - Semantic version (X.Y.Z)
- `org` - Organization (lowercase, alphanumeric + dash)
- `entrypoints` - At least one platform-arch combination
- `transport` - "stdio" or "http"

**Optional fields:**
- `author`, `license`, `description`, `homepage`, `repository`
- `policy` - Security declarations

---

### Entrypoint Selection Algorithm

```
Manifest entrypoints:
{
  "linux-amd64": {...},
  "linux-arm64": {...},
  "darwin-amd64": {...},
  "windows-amd64": {...}
}

Runtime: GOOS=linux, GOARCH=amd64

Selection:
1. Try exact match: "linux-amd64" ✓ Found
   Return: ./bin/mcp-server

If not found:
2. Try pattern: "linux-*" (matches any arch)
3. Try fallback: "*-amd64" (matches any OS)
4. Error if nothing matches
```

---

## Version Statuses & Lifecycle

Packages go through a state machine from upload to publication:

```
draft
  ↓ (upload complete)
ingested
  ↓ (security scan started)
scanned
  ↓ (scan passed)
published ←─────────────┐ (available for use)
  ↓                     │
deprecated (new version published)
  ↓
revoked (security issue found)
  └─ (pulled from registry)
```

### Status Meanings

**draft**
- Package uploaded but not yet finalized
- Not visible to other users
- Creator can still delete or modify

**ingested**
- Upload complete, queued for security scan
- Not visible to public
- May take hours to scan

**scanned**
- Security scan complete (passed)
- Not yet published
- Creator must explicitly publish

**published**
- Visible and downloadable to all authorized users
- Immutable once published
- Digest is stable

**deprecated**
- New version exists and is recommended instead
- Still available for download (backwards compatibility)
- Clients may warn on use

**revoked**
- Security vulnerability discovered
- Pulled from registry (not downloadable)
- Clients should avoid use
- Audit logs show when it was revoked

### Client Handling

```go
// When resolving to a deprecated version:
if manifest.Status == "deprecated" {
  log.Warn("Version %s is deprecated. Latest: %s", version, latestVersion)
}

// When resolving to a revoked version:
if manifest.Status == "revoked" {
  return error("Package version %s has been revoked (reason: %s)", version, reason)
}
```

---

## Content Addressing

All artifacts identified by immutable SHA-256 digest. This guarantees:
- Same manifest always produces same digest
- Same bundle always produces same digest
- Digest never changes (immutable reference)
- Deduplication (same content = same digest)

### Digest Format

```
sha256:abc123def456abc123def456abc123def456abc123def456abc123def456
```

- Prefix: `sha256:`
- Hash: 64 hexadecimal characters (256 bits)
- Full digest: 71 characters

### Validation in Client

```go
import "crypto/sha256"

// After downloading manifest
computed := sha256.Sum256(manifest_bytes)
computed_hex := hex.EncodeToString(computed[:])
expected := "abc123def456..." // from resolve response

if computed_hex != expected {
  return error("Digest mismatch: corrupted download or MITM attack")
}
// Only then use manifest
cache.Store(computed_hex, manifest_bytes)
```

### Streaming Validation (for large bundles)

```go
import (
  "crypto/sha256"
  "io"
)

hash := sha256.New()
file, _ := os.Create("/tmp/bundle.tar.gz")
writer := io.MultiWriter(file, hash)

// Download and hash simultaneously
resp, _ := http.Get(bundle_url)
io.Copy(writer, resp.Body)

computed_hex := hex.EncodeToString(hash.Sum(nil))
if computed_hex != expected {
  os.Remove("/tmp/bundle.tar.gz")
  return error("Bundle validation failed")
}
```

---

## Size & Rate Limits

### Size Limits

```
Manifest: 10 MB max
Bundle: 100 MB max
Total per package: 500 MB
```

Client should enforce on download:
```go
const (
  MaxManifestSize = 10 * 1024 * 1024   // 10 MB
  MaxBundleSize   = 100 * 1024 * 1024  // 100 MB
)

resp, _ := http.Get(manifest_url)
defer resp.Body.Close()

if resp.ContentLength > MaxManifestSize {
  return error("Manifest too large: %d > %d", resp.ContentLength, MaxManifestSize)
}

// Limited reader to prevent unbounded download
limited := io.LimitReader(resp.Body, MaxManifestSize+1)
body, _ := io.ReadAll(limited)
if len(body) > MaxManifestSize {
  return error("Manifest exceeded size limit")
}
```

### Rate Limiting

Registry returns `429 Too Many Requests` if rate limited.

```
HTTP 429 Too Many Requests
Retry-After: 60
```

Client should:
1. Parse `Retry-After` header
2. Wait before retrying
3. Exponential backoff

```go
if resp.StatusCode == 429 {
  retry_after := resp.Header.Get("Retry-After")
  wait_seconds := parseRetryAfter(retry_after, 60)
  log.Info("Rate limited, waiting %d seconds...", wait_seconds)
  time.Sleep(time.Duration(wait_seconds) * time.Second)
  // Retry
}
```

---

## Error Handling

### HTTP Status Codes

**2xx Success**
```
200 OK - Request succeeded
```

**3xx Redirect**
```
302 Found - Temporary redirect (follow)
307 Temporary Redirect - Follow with same method
308 Permanent Redirect - Cache this redirect
```

**4xx Client Error**
```
400 Bad Request - Invalid request format (don't retry)
401 Unauthorized - Auth failed (prompt for login, don't retry)
403 Forbidden - Access denied (don't retry)
404 Not Found - Resource doesn't exist (don't retry)
429 Too Many Requests - Rate limited (retry with backoff)
```

**5xx Server Error**
```
500 Internal Server Error - Server error (retry)
502 Bad Gateway - Temporary issue (retry)
503 Service Unavailable - Maintenance (retry)
```

### Error Response Format

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "details": {
    "field": "value"
  }
}
```

**Common error codes:**

| Code | HTTP | Meaning | Action |
|------|------|---------|--------|
| `not_found` | 404 | Package/version doesn't exist | Fail, suggest alternatives |
| `invalid_ref` | 400 | Reference format invalid | Fail, show correct format |
| `unauthorized` | 401 | Auth token invalid/expired | Prompt for login |
| `forbidden` | 403 | Access denied to package | Fail, check permissions |
| `rate_limited` | 429 | Too many requests | Retry with backoff |
| `server_error` | 500 | Registry internal error | Retry with backoff |

### Client Retry Strategy

```
Request type: Resolve (stateless)
  Errors: 5xx, network timeout
  Retries: 3 with exponential backoff (1s, 2s, 4s)
  Non-retryable: 4xx (except 429)

Request type: Download (idempotent)
  Errors: 5xx, network timeout
  Retries: 3 with exponential backoff
  Non-retryable: 4xx (except 429)
  Validation: Always check digest

Rate limit (429):
  Retry-After: Parse header
  Exponential backoff: 60s, 120s, 300s
  Max retries: 3
```

---

## HTTP Headers & Caching

### Request Headers (Client → Registry)

```
GET /v1/artifacts/sha256:abc123/manifest HTTP/1.1
Host: registry.mcp-hub.info
Authorization: Bearer <token>
User-Agent: mcp-cage/0.1.0 (linux/amd64)
Accept: application/json
If-None-Match: "sha256:abc123..."
```

**Header meanings:**
- `Authorization` - Bearer token (if required)
- `User-Agent` - Client identification (for analytics/debugging)
- `Accept` - Content type expected (application/json for manifest)
- `If-None-Match` - ETag validation (cache check)

### Response Headers (Registry → Client)

```
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 4200
Cache-Control: public, immutable, max-age=31536000
ETag: "sha256:abc123..."
Last-Modified: Mon, 15 Jan 2026 10:00:00 GMT
X-Checksum-SHA256: sha256:abc123...
Date: Fri, 18 Jan 2026 10:30:00 GMT
```

**Header meanings:**
- `Cache-Control` - Caching directive (immutable = cache forever)
- `ETag` - Entity tag (for conditional requests)
- `X-Checksum-SHA256` - Digest for quick validation (optional)
- `Last-Modified` - Timestamp of last change

### Caching Strategy

**Immutable artifacts (by digest):**
```
Cache-Control: public, immutable, max-age=31536000
```
- Cache forever (1 year)
- Safe to reuse without validation
- Example: manifest with digest sha256:abc123

**Mutable resources (by version):**
```
Cache-Control: public, max-age=300
```
- Cache for 5 minutes
- Requires validation (If-None-Match)
- Example: version list, resolve response

**Client should:**
1. Check local cache first (filesystem)
2. If cache miss, fetch from registry
3. Validate with ETag if local cache expired
4. Store with appropriate TTL

---

## Redirects & Presigned URLs

### Following Redirects

Registry may redirect to CDN or cloud storage for large artifacts.

```
Client: GET /v1/artifacts/sha256:def456.../bundle
Registry: 302 Found
  Location: https://s3.amazonaws.com/mcp-registry/bundles/def456?Signature=...&Expires=1705708800
Client: GET https://s3.amazonaws.com/... (presigned URL)
S3: 200 OK with binary data
```

**Client requirements:**
- Follow redirects automatically (up to 10 hops)
- Support all redirect codes (301, 302, 303, 307, 308)
- Preserve auth headers on same-domain redirects
- May drop auth headers on cross-domain (e.g., to S3)

### Presigned URL Handling

S3/GCS presigned URLs include:
- Query params: `Signature`, `Expires`, `Access-Key-Id`
- Query params must not be modified
- URL is valid only for limited time (usually 1 hour)
- URL may be downloaded by multiple clients

**Client must:**
1. Follow redirect immediately (don't cache URL)
2. Download from presigned URL
3. Validate digest against expected (same as registry)
4. Don't share presigned URL (expires soon)

---

## Testing Patterns with httptest

### Test 1: Mock Registry Resolve

```go
package registry

import (
  "encoding/json"
  "net/http"
  "net/http/httptest"
  "testing"
)

func TestRegistryClient_Resolve(t *testing.T) {
  // Start mock registry server
  server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path != "/v1/packages/acme/hello-world/resolve" {
      http.NotFound(w, r)
      return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
      "manifest": map[string]interface{}{
        "digest": "sha256:abc123...",
        "url":    server.URL + "/manifest",
      },
      "bundle": map[string]interface{}{
        "digest": "sha256:def456...",
        "url":    server.URL + "/bundle",
      },
    })
  }))
  defer server.Close()

  // Create client pointing to mock server
  client := NewRegistryClient(server.URL, "")

  // Test resolve
  result, err := client.Resolve("acme/hello-world", "1.2.3", "")
  if err != nil {
    t.Fatalf("Unexpected error: %v", err)
  }

  if result.Manifest.Digest != "sha256:abc123..." {
    t.Errorf("Expected manifest digest sha256:abc123, got %s", result.Manifest.Digest)
  }
}
```

### Test 2: Mock Manifest Download with Validation

```go
func TestRegistryClient_DownloadManifest_ValidatesDigest(t *testing.T) {
  server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path == "/manifest" {
      w.Header().Set("Content-Type", "application/json")
      w.Write([]byte(`{"name":"test"}`))
      return
    }
    http.NotFound(w, r)
  }))
  defer server.Close()

  client := NewRegistryClient(server.URL, "")

  // Download with correct digest
  manifest, err := client.Download(server.URL+"/manifest", "sha256:8717ba7166f61e7b1f4c7a1f23d1f5e5f3f9c5f5...")
  if err != nil {
    t.Fatalf("Expected no error with correct digest, got: %v", err)
  }

  // Download with incorrect digest
  _, err = client.Download(server.URL+"/manifest", "sha256:wrongdigest...")
  if err == nil {
    t.Fatal("Expected digest validation error, got none")
  }
}
```

### Test 3: Mock Redirect (Presigned URL)

```go
func TestRegistryClient_FollowsRedirects(t *testing.T) {
  // Final destination (S3 presigned URL simulator)
  final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/gzip")
    w.Write(testBundleData) // Mock bundle tar.gz
  }))
  defer final.Close()

  // Registry server (redirects to presigned URL)
  registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path == "/bundle" {
      http.Redirect(w, r, final.URL, http.StatusFound)
      return
    }
    http.NotFound(w, r)
  }))
  defer registry.Close()

  client := NewRegistryClient(registry.URL, "")

  bundle, err := client.Download(registry.URL+"/bundle", expectedBundleDigest)
  if err != nil {
    t.Fatalf("Failed to download via redirect: %v", err)
  }

  // Validate that we got the bundle
  if len(bundle) == 0 {
    t.Fatal("Empty bundle after download")
  }
}
```

### Test 4: Mock Rate Limiting

```go
func TestRegistryClient_RetriesOn429(t *testing.T) {
  attempts := 0
  server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    attempts++
    if attempts < 3 {
      w.Header().Set("Retry-After", "1")
      http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
      return
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
  }))
  defer server.Close()

  client := NewRegistryClient(server.URL, "")
  client.SetRetryConfig(3, 1*time.Millisecond) // Fast retries for test

  _, err := client.Resolve("acme/test", "1.0.0", "")
  if err != nil {
    t.Fatalf("Failed after retries: %v", err)
  }

  if attempts != 3 {
    t.Errorf("Expected 3 attempts, got %d", attempts)
  }
}
```

### Test 5: Mock 401 Unauthorized (no retry)

```go
func TestRegistryClient_NoRetryOn401(t *testing.T) {
  attempts := 0
  server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    attempts++
    http.Error(w, "Unauthorized", http.StatusUnauthorized)
  }))
  defer server.Close()

  client := NewRegistryClient(server.URL, "invalid-token")

  _, err := client.Resolve("acme/test", "1.0.0", "")
  if err == nil {
    t.Fatal("Expected error on 401")
  }

  if attempts != 1 {
    t.Errorf("Expected 1 attempt (no retry on 401), got %d", attempts)
  }

  if !strings.Contains(err.Error(), "unauthorized") {
    t.Errorf("Expected 'unauthorized' error message, got: %v", err)
  }
}
```

### Test 6: Integration Test with Real Bundle

```go
func TestIntegration_PullPackageEnd2End(t *testing.T) {
  // Create temporary cache directory
  tmpdir := t.TempDir()

  // Start mock registry
  server := startMockRegistry(t)
  defer server.Close()

  // Create client
  client := NewRegistryClient(server.URL, "")

  // Resolve
  ref, err := client.Resolve("acme/test", "1.0.0", "")
  if err != nil {
    t.Fatalf("Resolve failed: %v", err)
  }

  // Cache manifest
  manifest_path, err := cacheStore.Store("manifests", ref.Manifest.Digest, manifestBytes)
  if err != nil {
    t.Fatalf("Manifest cache failed: %v", err)
  }

  // Cache bundle
  bundle_path, err := cacheStore.Store("bundles", ref.Bundle.Digest, bundleBytes)
  if err != nil {
    t.Fatalf("Bundle cache failed: %v", err)
  }

  // Verify cached files exist and are correct
  if _, err := os.Stat(manifest_path); err != nil {
    t.Fatalf("Manifest not cached: %v", err)
  }

  if _, err := os.Stat(bundle_path); err != nil {
    t.Fatalf("Bundle not cached: %v", err)
  }
}
```

---

This skill document is the authoritative reference for MCP Registry integration. Use it when:

- Implementing registry client (resolve, download)
- Handling authentication and tokens
- Validating digests
- Implementing retry logic
- Writing integration tests
- Debugging registry API issues

Key invariants to remember:
- **Always validate digest before using artifact** (security critical)
- **Follow redirects up to 10 times** (presigned URLs)
- **Retry 5xx errors with exponential backoff** (rate limiting)
- **Don't retry 4xx errors** (except 429)
- **Cache immutable artifacts forever** (by digest)

