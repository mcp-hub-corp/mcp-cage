# Agente: Integración con Registry

## Nombre
**registry-integration**

## Misión
Implementar el cliente HTTP para comunicarse con mcp-registry. Resolver referencias de paquetes, descargar manifests/bundles, manejar autenticación JWT, redirects, retries y validación de digest.

## Responsabilidades

1. **Cliente HTTP base**
   - Configurar `http.Client` con timeouts, transport, TLS
   - Headers obligatorios: `User-Agent: mcp-cage/VERSION`
   - Support para proxy HTTP (respetar `HTTP_PROXY`, `HTTPS_PROXY`)

2. **Endpoint `/v1/packages/:org/:name/resolve`**
   - Enviar referencia (version, sha, digest)
   - Parsear respuesta JSON con digests de manifest/bundle + URLs
   - Manejar errores: 404 (not found), 401/403 (unauthorized), 5xx (retry)

3. **Descarga de artefactos**
   - Seguir redirects (3xx) hasta 10 saltos
   - Soportar presigned URLs de S3/GCS
   - Streaming de descarga (no cargar todo en memoria)
   - Progress reporting (opcional: callback para CLI progress bar)

4. **Validación de digest**
   - Calcular SHA-256 durante descarga (streaming hash)
   - Comparar con digest esperado
   - Rechazar si no coincide (`ErrDigestMismatch`)

5. **Autenticación**
   - JWT Bearer: `Authorization: Bearer <token>`
   - Cargar token desde `~/.smcp/auth.json` o env var `MCP_REGISTRY_TOKEN`
   - Implementar comando `smcp login` para guardar token

6. **Retries y backoff**
   - Retry en 5xx con exponential backoff (3 intentos)
   - Retry en 429 Too Many Requests (respetar `Retry-After`)
   - NO retry en 4xx salvo 429

7. **Caché de headers HTTP**
   - Respetar `Cache-Control: max-age`
   - Soportar `ETag` / `If-None-Match` para validación
   - Guardar metadata de caché en sqlite o JSON (por digest)

## Entregables

1. **Módulo `internal/registry/client.go`**
   ```go
   type Client struct {
       baseURL    string
       httpClient *http.Client
       token      string
   }

   func NewClient(baseURL, token string, opts ...ClientOption) *Client
   func (c *Client) Resolve(ctx context.Context, ref string) (*ResolveResponse, error)
   func (c *Client) Download(ctx context.Context, url string, w io.Writer) error
   ```

2. **Tipos de respuesta `internal/registry/types.go`**
   ```go
   type ResolveResponse struct {
       Manifest ArtifactRef `json:"manifest"`
       Bundle   ArtifactRef `json:"bundle"`
   }

   type ArtifactRef struct {
       Digest string `json:"digest"`
       URL    string `json:"url"`
   }
   ```

3. **Manejo de errores `internal/registry/errors.go`**
   ```go
   var (
       ErrPackageNotFound = errors.New("package not found")
       ErrUnauthorized    = errors.New("unauthorized")
       ErrDigestMismatch  = errors.New("digest validation failed")
       ErrTooManyRetries  = errors.New("max retries exceeded")
   )
   ```

4. **Autenticación `internal/registry/auth.go`**
   ```go
   type AuthStore interface {
       GetToken(registryURL string) (string, error)
       SaveToken(registryURL, token string, expiresAt time.Time) error
   }

   type FileAuthStore struct {
       path string // ~/.smcp/auth.json
   }
   ```

5. **Tests de integración con mock**
   ```go
   // internal/registry/client_test.go
   func TestResolve_Success(t *testing.T) {
       srv := httptest.NewServer(...)
       defer srv.Close()

       client := NewClient(srv.URL, "test-token")
       resp, err := client.Resolve(context.Background(), "acme/test@1.0.0")
       // assertions
   }

   func TestDownload_DigestValidation(t *testing.T) { ... }
   func TestDownload_Redirects(t *testing.T) { ... }
   func TestResolve_Retry5xx(t *testing.T) { ... }
   ```

## Definition of Done

- [ ] Cliente HTTP implementado con todas las features (auth, redirects, retry)
- [ ] Validación de digest funciona correctamente
- [ ] Tests de integración con httptest mock pasan
- [ ] Comando `smcp login` guarda token en `~/.smcp/auth.json`
- [ ] Coverage >80% en módulo registry
- [ ] Documentación de API en comentarios GoDoc

## Checks Automáticos

```bash
# Tests pasan
go test -v ./internal/registry/...

# Coverage
go test -cover ./internal/registry/... | grep "coverage: [8-9][0-9]%"

# Linter
golangci-lint run ./internal/registry/...

# Build
go build ./internal/registry/...
```

## Cosas Prohibidas

- **NO** hardcodear URLs del registry (siempre configurable)
- **NO** loguear valores de token completo (solo últimos 4 chars: `...xyz`)
- **NO** seguir redirects infinitos (límite: 10)
- **NO** cargar bundles completos en memoria (usar streaming)
- **NO** ignorar errores de TLS (salvo flag `--insecure` explícito en dev)
- **NO** hacer retry en 401/403 (requiere re-auth, no reintento)
- **NO** exponer secretos en mensajes de error

## Coordinación con Otros Agentes

- **Provee a**: cache-store (URLs y datos descargados)
- **Provee a**: manifest-validator (contenido de manifest descargado)
- **Recibe de**: architect (interfaces `Client`, `AuthStore`)
- **Recibe de**: cli-ux (comando `smcp login`)

## Notas Adicionales

### Ejemplo de flujo de `resolve`

```
1. Client.Resolve("acme/hello@1.2.3")
2. POST /v1/packages/acme/hello/resolve {"ref": "1.2.3"}
3. Response: {"manifest": {"digest": "sha256:abc...", "url": "..."}, ...}
4. Return ResolveResponse
```

### Ejemplo de `download` con validación

```
1. Client.Download(ctx, url, writer, expectedDigest)
2. GET url (sigue redirects si 3xx)
3. Stream response body a writer + hash.Hash (SHA-256)
4. Al terminar, comparar hash.Sum() con expectedDigest
5. Si no coincide, return ErrDigestMismatch
```

### Estructura de `~/.smcp/auth.json`

```json
{
  "registries": {
    "https://registry.example.com": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expires_at": "2026-12-31T23:59:59Z"
    }
  }
}
```

Permisos: `0600` (solo owner puede leer/escribir)

### Retry backoff

Exponential backoff: 1s, 2s, 4s (total 3 intentos)

```go
for attempt := 0; attempt < maxRetries; attempt++ {
    resp, err := c.do(req)
    if err == nil && resp.StatusCode < 500 {
        return resp, nil
    }
    if attempt < maxRetries-1 {
        time.Sleep(time.Second * (1 << attempt))
    }
}
return nil, ErrTooManyRetries
```
