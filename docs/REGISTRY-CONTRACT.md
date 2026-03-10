# MCP Registry API Contract

This document describes the registry API contract extracted from the official OpenAPI specification.

## Authentication

The registry supports three authentication methods:

1. **Bearer Token (JWT)**: `Authorization: Bearer <jwt>`
2. **API Token**: `Authorization: Token <token_id>:<secret>`
3. **Basic Auth** (OSS mode only): `Authorization: Basic <base64>`

## Key Endpoints

### 1. Login (OSS Mode)

```
POST /v1/auth/login
```

Request:
```json
{
  "username": "string",
  "password": "string"
}
```

Response:
```json
{
  "access_token": "string (JWT)",
  "expires_in": 3600
}
```

### 2. Resolve Package Version

```
GET /v1/org/{org}/mcps/{name}/resolve?ref={ref}
```

Parameters:
- `org`: organization name
- `name`: package name
- `ref`: version reference (semver, git SHA, or digest)

Response:
```json
{
  "package": "org/name",
  "ref": "1.0.0",
  "resolved": {
    "version": "1.0.0",
    "git_sha": "abc123def456",
    "status": "published",
    "certification_level": 0,
    "manifest": {
      "digest": "sha256:...",
      "url": "https://..."
    },
    "bundle": {
      "digest": "sha256:...",
      "url": "https://...",
      "size_bytes": 1234567
    },
    "evidence": []
  }
}
```

### 3. Download Manifest

```
GET /v1/org/{org}/artifacts/{digest}/manifest
```

Returns: Raw manifest bytes (JSON)

### 4. Download Bundle

```
GET /v1/org/{org}/artifacts/{digest}/bundle
```

Returns: Raw bundle bytes (tar.gz)

### 5. List Catalog

```
GET /v1/catalog
```

Response:
```json
{
  "packages": [
    {
      "package": "org/name",
      "visibility": "public|private",
      "latest_version": "1.0.0"
    }
  ]
}
```

## Content Addressing

All artifacts are identified by SHA256 digests:
- Format: `sha256:<64-char-hex>` or `sha512:<128-char-hex>`
- Maximum manifest size: 10 MB
- Maximum bundle size: 100 MB

## Version Status

Versions can have the following statuses:
- `draft`: Work in progress
- `ingested`: Uploaded but not verified
- `scanned`: Security scanned
- `published`: Public and available
- `quarantined`: Blocked due to security issues
- `deprecated`: No longer recommended
- `revoked`: Removed from distribution

## Error Responses

Standard HTTP status codes:
- `400`: Bad request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not found
- `409`: Conflict
- `429`: Too many requests
- `500`: Internal server error

## Implementation Notes

1. **Redirects**: Follow 302/307 redirects for presigned URLs
2. **Retries**: Retry 5xx errors with exponential backoff (3 attempts max)
3. **Digest Validation**: Always validate SHA256 after download
4. **User Agent**: Send `User-Agent: mcp-cage/<version>`
5. **Timeouts**: Use reasonable timeouts (30s for API calls, longer for downloads)
