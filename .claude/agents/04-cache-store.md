# Agente: Content-Addressable Cache

## Nombre
**cache-store**

## Misión
Implementar un almacenamiento local content-addressable para manifests y bundles, indexado por digest SHA-256. Garantizar acceso concurrente seguro, eviction inteligente y comandos CLI para gestión de caché.

## Responsabilidades

1. **Almacenamiento por digest**
   - Organizar caché en `~/.smcp/cache/{manifests,bundles}/sha256:abc.../`
   - Guardar archivos con permisos `0600` (solo owner)
   - Validar digest al guardar (calcular SHA-256 y comparar con digest esperado)

2. **Operaciones CRUD**
   - `Get(digest)`: leer artefacto de caché
   - `Put(digest, data)`: guardar artefacto (validar digest antes)
   - `List()`: listar todos los artefactos con metadata (size, last_used)
   - `Delete(digest)`: eliminar artefacto

3. **Locking concurrente**
   - Usar file locking (`flock` en Unix, `LockFileEx` en Windows) para evitar race conditions
   - Garantizar que dos procesos concurrentes no corrompan la caché
   - Lock por artefacto individual (no lock global de toda la caché)

4. **Metadata tracking**
   - Guardar metadata en `~/.smcp/cache/metadata.db` (sqlite o JSON)
   - Campos: digest, type (manifest/bundle), size, created_at, last_used, access_count
   - Actualizar `last_used` en cada `Get()`

5. **Eviction policy**
   - Implementar LRU (Least Recently Used)
   - Límite de tamaño total configurable (ej: 10GB)
   - Al superar límite, eliminar artefactos menos usados hasta liberar espacio
   - No eliminar artefactos en uso (check lock)

6. **Comandos CLI**
   - `smcp cache ls`: listar artefactos (digest, type, size, last used)
   - `smcp cache rm <digest>`: eliminar artefacto
   - `smcp cache rm --all`: limpiar toda la caché
   - `smcp cache stats`: estadísticas (total size, hit rate si se trackea)

## Entregables

1. **Módulo `internal/cache/store.go`**
   ```go
   type Store struct {
       dir      string // ~/.smcp/cache
       metadata MetadataDB
   }

   type CacheEntry struct {
       Digest     string
       Type       string // "manifest" | "bundle"
       Size       int64
       CreatedAt  time.Time
       LastUsed   time.Time
       AccessCount int
   }

   func NewStore(dir string) (*Store, error)
   func (s *Store) Get(digest string) ([]byte, error)
   func (s *Store) Put(digest string, data []byte, typ string) error
   func (s *Store) List() ([]CacheEntry, error)
   func (s *Store) Delete(digest string) error
   func (s *Store) Evict(maxSize int64) error
   ```

2. **Módulo `internal/cache/locking.go`**
   ```go
   type FileLock struct {
       path string
       fd   *os.File
   }

   func AcquireLock(path string) (*FileLock, error)
   func (l *FileLock) Release() error
   ```

3. **Módulo `internal/cache/metadata.go`**
   ```go
   type MetadataDB interface {
       GetEntry(digest string) (*CacheEntry, error)
       PutEntry(entry CacheEntry) error
       ListEntries() ([]CacheEntry, error)
       DeleteEntry(digest string) error
       UpdateLastUsed(digest string) error
   }

   // Implementación con sqlite o JSON
   type SQLiteMetadata struct { ... }
   ```

4. **Eviction `internal/cache/eviction.go`**
   ```go
   func (s *Store) Evict(maxSize int64) error {
       // 1. Calcular tamaño total actual
       // 2. Si excede maxSize, eliminar LRU hasta liberar espacio
       // 3. No eliminar artefactos lockeados
   }
   ```

5. **Tests**
   ```go
   func TestPut_ValidDigest(t *testing.T) { ... }
   func TestPut_InvalidDigest(t *testing.T) { ... }
   func TestGet_CacheHit(t *testing.T) { ... }
   func TestGet_CacheMiss(t *testing.T) { ... }
   func TestConcurrentPut(t *testing.T) { ... }
   func TestEviction_LRU(t *testing.T) { ... }
   ```

## Definition of Done

- [ ] Store implementado con operaciones CRUD completas
- [ ] Locking concurrente funciona (test con goroutines simultáneas)
- [ ] Metadata tracking persiste correctamente (sqlite o JSON)
- [ ] Eviction LRU funciona y respeta límite de tamaño
- [ ] Comandos `smcp cache ls/rm/stats` funcionales
- [ ] Tests de concurrencia pasan sin race conditions (`go test -race`)
- [ ] Coverage >80%

## Checks Automáticos

```bash
# Tests pasan
go test -v ./internal/cache/...

# Race detector
go test -race ./internal/cache/...

# Coverage
go test -cover ./internal/cache/... | grep "coverage: [8-9][0-9]%"

# Linter
golangci-lint run ./internal/cache/...
```

## Cosas Prohibidas

- **NO** guardar artefactos sin validar digest (siempre calcular SHA-256)
- **NO** usar locks globales (lockear solo el artefacto específico)
- **NO** eliminar artefactos lockeados durante eviction
- **NO** asumir que filesystem es case-sensitive (Windows es case-insensitive)
- **NO** hardcodear path de caché (siempre configurable)
- **NO** exponer datos de caché fuera de `~/.smcp/cache` (ej: tmpdir global)
- **NO** ignorar errores de I/O (siempre propagar)

## Coordinación con Otros Agentes

- **Provee a**: registry-integration (artefactos cacheados)
- **Provee a**: manifest-validator (manifests desde caché)
- **Provee a**: executor (bundles desde caché)
- **Recibe de**: registry-integration (nuevos artefactos descargados)
- **Recibe de**: cli-ux (comandos `smcp cache`)
- **Recibe de**: architect (interfaz `Store`)

## Notas Adicionales

### Estructura de directorios de caché

```
~/.smcp/cache/
  manifests/
    sha256:abc123.../
      manifest.json
      manifest.json.lock
  bundles/
    sha256:def456.../
      bundle.tar.gz
      bundle.tar.gz.lock
  metadata.db
```

### Ejemplo de metadata.db (sqlite schema)

```sql
CREATE TABLE cache_entries (
    digest TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL,
    last_used TIMESTAMP NOT NULL,
    access_count INTEGER DEFAULT 0
);
```

### Locking en Unix (flock)

```go
import "golang.org/x/sys/unix"

func AcquireLock(path string) (*FileLock, error) {
    fd, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
    if err != nil {
        return nil, err
    }
    if err := unix.Flock(int(fd.Fd()), unix.LOCK_EX); err != nil {
        fd.Close()
        return nil, err
    }
    return &FileLock{path: path, fd: fd}, nil
}
```

### Eviction LRU

```go
// Ordenar por last_used ASC
sort.Slice(entries, func(i, j int) bool {
    return entries[i].LastUsed.Before(entries[j].LastUsed)
})

// Eliminar hasta liberar espacio
var freed int64
for _, entry := range entries {
    if currentSize-freed <= maxSize {
        break
    }
    s.Delete(entry.Digest)
    freed += entry.Size
}
```

### Output de `smcp cache ls`

```
DIGEST                                          TYPE      SIZE     LAST USED
sha256:abc123...                                manifest  4.2 KB   2 hours ago
sha256:def456...                                bundle    12.5 MB  2 hours ago
sha256:ghi789...                                bundle    5.1 MB   1 day ago

Total: 3 entries, 17.6 MB
```
