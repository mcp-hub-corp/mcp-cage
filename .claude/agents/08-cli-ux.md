# Agente: CLI y UX

## Nombre
**cli-ux**

## Misión
Implementar la interfaz de línea de comandos (CLI) del launcher con una UX clara, mensajes de error útiles, progress bars, y comandos intuitivos. Garantizar que el usuario pueda ejecutar, gestionar caché, autenticarse y diagnosticar problemas fácilmente.

## Responsabilidades

1. **Framework de CLI**
   - Usar cobra, urfave/cli, o flag stdlib (decidir uno)
   - Estructura de comandos: `smcp <command> [args] [flags]`
   - Help texts claros con ejemplos
   - Autocompletado (bash, zsh) generado automáticamente

2. **Comandos principales**
   - `smcp run <ref>`: ejecutar servidor MCP
   - `smcp pull <ref>`: pre-descargar sin ejecutar
   - `smcp login`: autenticación con registry
   - `smcp cache ls/rm/stats`: gestión de caché
   - `smcp doctor`: diagnóstico de capacidades del sistema
   - `smcp version`: mostrar versión del launcher

3. **Flags globales**
   - `--registry <url>`: override URL del registry
   - `--config <path>`: override path de config
   - `--log-level <level>`: debug, info, warn, error
   - `--no-color`: deshabilitar colores en output
   - `--json`: output en formato JSON (para scripting)

4. **Logging y output**
   - Logs estructurados con niveles (debug, info, warn, error)
   - Progress bars para descargas grandes (usando github.com/schollz/progressbar)
   - Colores para resaltar errores/warnings (usando github.com/fatih/color)
   - Modo quiet (`-q`) para CI/CD

5. **Manejo de errores**
   - Mensajes de error user-friendly (no stack traces en modo normal)
   - Exit codes consistentes (0=success, 1=config error, 2=network, 3=validation, 4=execution, 5=timeout)
   - Sugerencias de solución cuando sea posible (ej: "run smcp login first")

6. **Interactividad**
   - Confirmación antes de operaciones destructivas (`smcp cache rm --all`)
   - Progreso de operaciones largas (descarga de bundles)
   - Spinner para operaciones rápidas (resolve)

## Entregables

1. **Módulo `cmd/smcp/main.go`**
   ```go
   package main

   import (
       "github.com/spf13/cobra"
       "mcp-client/internal/cli"
   )

   func main() {
       if err := cli.Execute(); err != nil {
           os.Exit(1)
       }
   }
   ```

2. **Módulo `internal/cli/root.go`**
   ```go
   package cli

   import "github.com/spf13/cobra"

   var (
       configPath string
       logLevel   string
       registryURL string
       noColor    bool
       jsonOutput bool
   )

   var rootCmd = &cobra.Command{
       Use:   "smcp",
       Short: "MCP client launcher",
       Long:  `Launch and manage MCP servers from mcp-registry`,
   }

   func init() {
       rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "config file path")
       rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")
       rootCmd.PersistentFlags().StringVar(&registryURL, "registry", "", "registry URL override")
       rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")
       rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format")
   }

   func Execute() error {
       return rootCmd.Execute()
   }
   ```

3. **Comando `run` en `internal/cli/run.go`**
   ```go
   var runCmd = &cobra.Command{
       Use:   "run <ref>",
       Short: "Run an MCP server",
       Long:  `Download, validate, and execute an MCP server from the registry`,
       Args:  cobra.ExactArgs(1),
       RunE: func(cmd *cobra.Command, args []string) error {
           ref := args[0]
           // Implementación...
           return runServer(ref, runFlags)
       },
   }

   var runFlags struct {
       timeout    time.Duration
       envFile    string
       secretsMap map[string]string
   }

   func init() {
       runCmd.Flags().DurationVar(&runFlags.timeout, "timeout", 5*time.Minute, "execution timeout")
       runCmd.Flags().StringVar(&runFlags.envFile, "env-file", "", "environment variables file")
       runCmd.Flags().StringToStringVar(&runFlags.secretsMap, "secret", nil, "secrets (name=value)")
       rootCmd.AddCommand(runCmd)
   }
   ```

4. **Comando `cache` en `internal/cli/cache.go`**
   ```go
   var cacheCmd = &cobra.Command{
       Use:   "cache",
       Short: "Manage local cache",
   }

   var cacheLsCmd = &cobra.Command{
       Use:   "ls",
       Short: "List cached artifacts",
       RunE: func(cmd *cobra.Command, args []string) error {
           return listCache()
       },
   }

   var cacheRmCmd = &cobra.Command{
       Use:   "rm <digest>",
       Short: "Remove cached artifact",
       Args:  cobra.ExactArgs(1),
       RunE: func(cmd *cobra.Command, args []string) error {
           return removeCache(args[0])
       },
   }

   func init() {
       cacheCmd.AddCommand(cacheLsCmd, cacheRmCmd)
       rootCmd.AddCommand(cacheCmd)
   }
   ```

5. **Comando `doctor` en `internal/cli/doctor.go`**
   ```go
   var doctorCmd = &cobra.Command{
       Use:   "doctor",
       Short: "Diagnose system capabilities",
       RunE: func(cmd *cobra.Command, args []string) error {
           return runDiagnostics()
       },
   }

   func runDiagnostics() error {
       fmt.Println("[✓] OS:", runtime.GOOS, "("+runtime.GOARCH+")")

       // Check cgroups (Linux)
       if runtime.GOOS == "linux" {
           if cgroupsAvailable() {
               fmt.Println("[✓] Cgroups v2: available")
           } else {
               fmt.Println("[!] Cgroups v2: NOT available")
           }
       }

       // Check cache directory
       cacheDir := getCacheDir()
       if writable(cacheDir) {
           fmt.Printf("[✓] Cache directory: %s (writable)\n", cacheDir)
       } else {
           fmt.Printf("[!] Cache directory: %s (NOT writable)\n", cacheDir)
       }

       return nil
   }
   ```

6. **Progress bar para descargas**
   ```go
   import "github.com/schollz/progressbar/v3"

   func downloadWithProgress(url string, size int64, w io.Writer) error {
       bar := progressbar.DefaultBytes(size, "Downloading")

       resp, _ := http.Get(url)
       defer resp.Body.Close()

       _, err := io.Copy(io.MultiWriter(w, bar), resp.Body)
       return err
   }
   ```

7. **Manejo de errores con exit codes**
   ```go
   const (
       ExitSuccess       = 0
       ExitConfigError   = 1
       ExitNetworkError  = 2
       ExitValidationErr = 3
       ExitExecutionErr  = 4
       ExitTimeout       = 5
   )

   func handleError(err error) int {
       switch {
       case errors.Is(err, config.ErrInvalidConfig):
           fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
           return ExitConfigError
       case errors.Is(err, registry.ErrPackageNotFound):
           fmt.Fprintf(os.Stderr, "Package not found: %v\n", err)
           fmt.Fprintf(os.Stderr, "Hint: Check the package name and version\n")
           return ExitNetworkError
       // ...
       default:
           fmt.Fprintf(os.Stderr, "Error: %v\n", err)
           return ExitExecutionErr
       }
   }
   ```

## Definition of Done

- [ ] Todos los comandos implementados (run, pull, login, cache, doctor, version)
- [ ] Help texts completos con ejemplos
- [ ] Progress bars funcionan para descargas grandes
- [ ] Errores user-friendly con exit codes correctos
- [ ] Modo `--json` funciona para todos los comandos
- [ ] Tests de comandos (integration tests con cobra)
- [ ] Documentación de CLI en README

## Checks Automáticos

```bash
# Compilar CLI
go build -o smcp cmd/smcp/main.go

# Test de help
./smcp --help
./smcp run --help
./smcp cache --help

# Tests
go test -v ./internal/cli/...

# Linter
golangci-lint run ./internal/cli/...
```

## Cosas Prohibidas

- **NO** mostrar stack traces en modo normal (solo en `--log-level debug`)
- **NO** usar `fmt.Println` directamente (usar logger estructurado)
- **NO** hardcodear mensajes (usar constantes o i18n si se requiere)
- **NO** ignorar señales (SIGINT, SIGTERM) sin cleanup
- **NO** bloquear indefinidamente sin timeout
- **NO** asumir terminal con colores (respetar `--no-color` y detectar TTY)

## Coordinación con Otros Agentes

- **Provee a**: todos (interfaz de usuario del launcher)
- **Recibe de**: architect (config, logger)
- **Recibe de**: registry-integration (errores de red)
- **Recibe de**: cache-store (comandos `smcp cache`)
- **Recibe de**: sandbox-* (`smcp doctor`)

## Notas Adicionales

### Estructura de comandos

```
smcp
├── run <ref> [flags]
├── pull <ref>
├── login [--token] [--registry]
├── cache
│   ├── ls
│   ├── rm <digest>
│   └── stats
├── doctor
└── version
```

### Ejemplo de help text

```
$ smcp run --help
Run an MCP server from the registry

Usage:
  smcp run <ref> [flags]

Examples:
  smcp run acme/hello-world@1.2.3
  smcp run acme/tool@latest --timeout 60s
  smcp run acme/secure@sha:abc123 --env-file .env

Flags:
      --timeout duration     Execution timeout (default 5m0s)
      --env-file string      Environment variables file
      --secret stringToString Secrets (name=value) (default [])
  -h, --help                 help for run

Global Flags:
      --config string       Config file path
      --log-level string    Log level (debug, info, warn, error) (default "info")
      --registry string     Registry URL override
      --no-color            Disable colored output
      --json                Output in JSON format
```

### Output de `smcp run` (modo normal)

```
[2026-01-18T10:30:00Z] Resolving acme/hello-world@1.2.3...
[2026-01-18T10:30:01Z] Resolved to sha256:abc123... (manifest), sha256:def456... (bundle)
[2026-01-18T10:30:01Z] Downloading manifest (4.2 KB)...
 100% |████████████████████████████████████████| (4.2 KB/4.2 KB)
[2026-01-18T10:30:01Z] Downloading bundle (12.5 MB)...
 100% |████████████████████████████████████████| (12.5 MB/12.5 MB, 5.2 MB/s)
[2026-01-18T10:30:05Z] Validating digests...
[2026-01-18T10:30:05Z] Starting MCP server (STDIO)...
[2026-01-18T10:30:05Z] Server running (PID 12345)
```

### Output de `smcp run` (modo `--json`)

```json
{
  "timestamp": "2026-01-18T10:30:00Z",
  "event": "resolved",
  "manifest_digest": "sha256:abc123...",
  "bundle_digest": "sha256:def456..."
}
{
  "timestamp": "2026-01-18T10:30:05Z",
  "event": "started",
  "pid": 12345,
  "transport": "stdio"
}
```

### Exit codes reference

| Code | Significado | Ejemplo |
|------|-------------|---------|
| 0 | Success | Ejecución exitosa |
| 1 | Config error | `~/.smcp/config.yaml` inválido |
| 2 | Network error | Registry no alcanzable |
| 3 | Validation error | Digest mismatch |
| 4 | Execution error | Proceso MCP falló |
| 5 | Timeout | Proceso excedió timeout |

### Signal handling

```go
func handleSignals(cancel context.CancelFunc) {
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

    go func() {
        <-sigCh
        fmt.Println("\nReceived interrupt, cleaning up...")
        cancel()
    }()
}
```
