# MCP Packaging

El paquete `packaging` proporciona funcionalidad para crear bundles tar.gz reproducibles y seguros desde directorios locales.

## Características

- **Bundles reproducibles**: Los mismos archivos siempre generan el mismo SHA256
- **Anti path-traversal**: Previene ataques de escape de directorio
- **Anti decompression bomb**: Limita el tamaño descomprimido a 1GB
- **Permisos normalizados**: Garantiza permisos consistentes (dirs 0750, files 0640)
- **Timestamps normalizados**: Todos los archivos usan 2000-01-01 para reproducibilidad
- **Soporte .mcpignore**: Excluye patrones de archivos similares a .gitignore

## Uso

### Crear un bundle básico

```go
package main

import (
	"log"
	"github.com/mcp-hub-corp/mcp-cage/internal/packaging"
)

func main() {
	bundler := packaging.NewBundler()

	result, err := bundler.Create("/path/to/source", "/path/to/bundle.tar.gz")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Bundle created: %s", result.Path)
	log.Printf("SHA256: %s", result.SHA256)
	log.Printf("Files: %d, Dirs: %d", result.FileCount, result.DirCount)
	log.Printf("Uncompressed: %d bytes, Compressed: %d bytes",
		result.UncompressedSize, result.CompressedSize)
}
```

### Usar .mcpignore

1. Crea un archivo `.mcpignore` en el directorio raíz:

```
# Version control
.git/
.gitignore

# Dependencies
node_modules/
vendor/

# Build artifacts
dist/
build/

# Logs
*.log
debug/

# Environment
.env
.env.*
```

2. Carga el archivo en el bundler:

```go
bundler := packaging.NewBundler()
if err := bundler.LoadIgnoreFile("/path/to/source/.mcpignore"); err != nil {
	log.Fatal(err)
}

result, err := bundler.Create("/path/to/source", "/path/to/bundle.tar.gz")
```

### Añadir patrones de ignore programáticamente

```go
bundler := packaging.NewBundler()
bundler.AddIgnorePattern("*.log")
bundler.AddIgnorePattern("**/*.tmp")
bundler.AddIgnorePattern("node_modules/")

result, err := bundler.Create(sourceDir, outputPath)
```

## Patrones soportados

El `.mcpignore` soporta patrones similares a `.gitignore`:

| Patrón | Descripción | Ejemplo |
|--------|-------------|---------|
| `*.log` | Archivos que terminan con `.log` | `debug.log`, `error.log` |
| `.git/` | Directorio y su contenido | `.git/`, `.git/config` |
| `node_modules/` | Directorio y su contenido | `node_modules/pkg` |
| `.env*` | Archivos que comienzan con `.env` | `.env`, `.env.local` |
| `build/` | Directorio específico | `build/output.js` |
| `**/*.tmp` | Archivos en cualquier nivel | `a/b/c/file.tmp` |

## Formato del bundle

El bundle es un archivo tar.gz con la siguiente estructura:

```
bundle.tar.gz
├── archivo1.txt
├── archivo2.go
├── directorio1/
│   ├── archivo3.txt
│   └── subdirectorio/
│       └── archivo4.txt
└── directorio2/
    └── archivo5.go
```

## Seguridad

### Path Traversal Protection

El bundler previene ataques de path traversal:
- Resuelve symlinks y valida que estén dentro del directorio base
- Rechaza rutas que intenten escapar del directorio origen

### Decompression Bomb Protection

El bundler rechaza bundles que excedan 1GB descomprimidos:
- Monitorea el tamaño total durante la creación
- Falla antes de escribir el archivo si se excede el límite

### Permisos Normalizados

Para reproducibilidad y seguridad:
- Directorios: `0750` (rwxr-x---)
- Archivos: `0640` (rw-r-----)
- Todos los timestamps se normalizan a 2000-01-01

## Estructura del BundleResult

```go
type BundleResult struct {
	Path             string // Ruta del bundle creado
	SHA256           string // Digest SHA256 (ej: "sha256:abc123...")
	UncompressedSize int64  // Tamaño sin comprimir en bytes
	CompressedSize   int64  // Tamaño comprimido en bytes
	FileCount        int    // Cantidad de archivos
	DirCount         int    // Cantidad de directorios
}
```

## Reproducibilidad

Los bundles son completamente reproducibles:
- El orden de los archivos es determinista (ordenado alfabéticamente)
- Los timestamps son normalizados a una fecha fija
- Los permisos son normalizados
- El SHA256 será idéntico si el contenido no cambia

```go
// Múltiples llamadas producen el mismo SHA256
bundler1 := packaging.NewBundler()
result1, _ := bundler1.Create(sourceDir, "bundle1.tar.gz")

bundler2 := packaging.NewBundler()
result2, _ := bundler2.Create(sourceDir, "bundle2.tar.gz")

// result1.SHA256 == result2.SHA256
```

## Limitaciones

- Tamaño máximo descomprimido: **1GB**
- No soporta permisos ejecutables específicos (se normalizan)
- Los symlinks se siguen (pueden causar path traversal si no se validan)
- Las metadata especiales (ACLs, xattrs) se pierden

## Integración con la CLI

El packaging se utiliza internamente en el comando `mcp push`:

```bash
mcp push org/name@1.0.0 --source ./src
# Internamente:
# 1. Carga .mcpignore si existe
# 2. Crea bundle con NewBundler
# 3. Calcula SHA256
# 4. Sube el bundle al registry
```

## Testing

El paquete incluye tests completos:

```bash
go test -v ./internal/packaging/...
```

Todos los tests pasan incluidas:
- Creación básica de bundles
- Manejo de subdirectorios
- Respeto de patrones .mcpignore
- Protección contra path traversal
- Límite de tamaño
- Reproducibilidad
- Patrones glob
