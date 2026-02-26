# Agente: Auditoría y Logging

## Nombre
**audit-logging**

## Misión
Implementar un sistema de auditoría local que registre todas las ejecuciones de servidores MCP de forma estructurada, sin exponer datos sensibles. Garantizar trazabilidad completa para cumplimiento y debugging.

## Responsabilidades

1. **Structured logging**
   - Formato JSON estructurado para fácil parsing
   - Usar `slog` de stdlib (Go 1.21+) o `zerolog`
   - Niveles: debug, info, warn, error
   - Contexto: timestamp, package ref, digest, operation

2. **Eventos de auditoría**
   - `execution.started`: inicio de ejecución (package, version, digest, entrypoint, user)
   - `execution.completed`: fin exitoso (exit code, duration)
   - `execution.failed`: fin con error (error message, exit code)
   - `execution.timeout`: timeout excedido
   - `download.started`: inicio de descarga (artifact type, digest)
   - `download.completed`: descarga exitosa (size, duration)
   - `validation.failed`: fallo de validación (digest mismatch, manifest invalid)

3. **Redacción de secretos**
   - **NUNCA** loguear valores de secretos
   - Loguear solo nombres de secretos: `"secrets": ["DB_PASSWORD", "API_KEY"]`
   - Redactar tokens completos, loguear solo últimos 4 chars: `"token": "...xyz"`

4. **Persistencia**
   - Guardar en `~/.smcp/audit.log` (rotación opcional)
   - Append-only (no modificar logs históricos)
   - Permisos `0600` (solo owner puede leer)

5. **Rotación de logs (opcional)**
   - Rotar por tamaño (ej: 100MB) o por fecha (diario)
   - Comprimir logs antiguos (gzip)
   - Retention policy configurable (ej: 30 días)

6. **Query de logs**
   - Comando `smcp audit ls` para listar ejecuciones recientes
   - Filtros: por package, por fecha, por exit code
   - Output: tabla o JSON (`--json`)

## Entregables

1. **Módulo `internal/audit/logger.go`**
   ```go
   package audit

   import "log/slog"

   type Logger struct {
       logger *slog.Logger
       file   *os.File
   }

   type Event struct {
       Timestamp time.Time         `json:"timestamp"`
       Type      string             `json:"type"`
       Package   string             `json:"package,omitempty"`
       Version   string             `json:"version,omitempty"`
       Digest    string             `json:"digest,omitempty"`
       PID       int                `json:"pid,omitempty"`
       ExitCode  int                `json:"exit_code,omitempty"`
       Duration  time.Duration      `json:"duration,omitempty"`
       Error     string             `json:"error,omitempty"`
       Metadata  map[string]any     `json:"metadata,omitempty"`
   }

   func NewLogger(path string) (*Logger, error)
   func (l *Logger) LogEvent(event Event) error
   func (l *Logger) Close() error
   ```

2. **Tipos de eventos `internal/audit/events.go`**
   ```go
   const (
       EventExecutionStarted  = "execution.started"
       EventExecutionCompleted = "execution.completed"
       EventExecutionFailed   = "execution.failed"
       EventExecutionTimeout  = "execution.timeout"
       EventDownloadStarted   = "download.started"
       EventDownloadCompleted = "download.completed"
       EventValidationFailed  = "validation.failed"
   )

   func ExecutionStarted(pkg, version, digest string, pid int, entrypoint string) Event {
       return Event{
           Timestamp: time.Now(),
           Type:      EventExecutionStarted,
           Package:   pkg,
           Version:   version,
           Digest:    digest,
           PID:       pid,
           Metadata:  map[string]any{"entrypoint": entrypoint},
       }
   }

   func ExecutionCompleted(pkg, digest string, exitCode int, duration time.Duration) Event {
       return Event{
           Timestamp: time.Now(),
           Type:      EventExecutionCompleted,
           Package:   pkg,
           Digest:    digest,
           ExitCode:  exitCode,
           Duration:  duration,
       }
   }

   // ... otros eventos
   ```

3. **Redacción de secretos `internal/audit/redact.go`**
   ```go
   func RedactToken(token string) string {
       if len(token) <= 4 {
           return "***"
       }
       return "..." + token[len(token)-4:]
   }

   func RedactSecrets(secrets map[string]string) []string {
       names := make([]string, 0, len(secrets))
       for name := range secrets {
           names = append(names, name)
       }
       return names // solo nombres, no valores
   }
   ```

4. **Rotación de logs `internal/audit/rotation.go`**
   ```go
   import "gopkg.in/natefinch/lumberjack.v2"

   func NewRotatingLogger(path string, maxSizeMB, maxBackups, maxAgeDays int) (*Logger, error) {
       rotator := &lumberjack.Logger{
           Filename:   path,
           MaxSize:    maxSizeMB,
           MaxBackups: maxBackups,
           MaxAge:     maxAgeDays,
           Compress:   true,
       }

       logger := slog.New(slog.NewJSONHandler(rotator, nil))
       return &Logger{logger: logger, file: rotator}, nil
   }
   ```

5. **Query de logs `internal/audit/query.go`**
   ```go
   type QueryFilter struct {
       Package   string
       StartDate time.Time
       EndDate   time.Time
       ExitCode  *int
   }

   func Query(logPath string, filter QueryFilter) ([]Event, error) {
       // Leer audit.log línea por línea
       // Parsear JSON
       // Filtrar según QueryFilter
       // Return eventos matcheados
   }
   ```

6. **Comando CLI `internal/cli/audit.go`**
   ```go
   var auditCmd = &cobra.Command{
       Use:   "audit",
       Short: "Query audit logs",
   }

   var auditLsCmd = &cobra.Command{
       Use:   "ls",
       Short: "List recent executions",
       RunE: func(cmd *cobra.Command, args []string) error {
           events, _ := audit.Query(auditLogPath, audit.QueryFilter{})
           for _, e := range events {
               fmt.Printf("%s %s@%s PID=%d ExitCode=%d\n",
                   e.Timestamp.Format(time.RFC3339),
                   e.Package, e.Version, e.PID, e.ExitCode)
           }
           return nil
       },
   }
   ```

7. **Tests**
   ```go
   func TestLogger_LogEvent(t *testing.T) { ... }
   func TestRedactToken(t *testing.T) { ... }
   func TestRedactSecrets_OnlyNames(t *testing.T) { ... }
   func TestQuery_FilterByPackage(t *testing.T) { ... }
   ```

## Definition of Done

- [ ] Logger estructurado implementado (JSON format)
- [ ] Todos los eventos de auditoría definidos y documentados
- [ ] Redacción de secretos funciona correctamente
- [ ] Rotación de logs implementada (opcional pero recomendado)
- [ ] Comando `smcp audit ls` funcional
- [ ] Tests verifican que NO se loguean valores de secretos
- [ ] Documentación de formato de eventos

## Checks Automáticos

```bash
# Tests pasan
go test -v ./internal/audit/...

# Verificar que NO hay secrets en logs
go test -v ./internal/audit/... -run TestNoSecretsInLogs

# Linter
golangci-lint run ./internal/audit/...

# Verificar formato JSON
jq . ~/.smcp/audit.log > /dev/null
```

## Cosas Prohibidas

- **NO** loguear valores de secretos (solo nombres)
- **NO** loguear tokens completos (solo últimos 4 chars)
- **NO** loguear información personal sensible (ej: IPs, emails si no es necesario)
- **NO** modificar logs históricos (append-only)
- **NO** usar permisos abiertos (siempre `0600` para audit.log)
- **NO** asumir que logs caben en memoria (usar streaming)
- **NO** bloquear el proceso principal en I/O de logs (usar buffering)

## Coordinación con Otros Agentes

- **Provee a**: todos (logging de operaciones)
- **Recibe de**: executor (eventos de ejecución)
- **Recibe de**: registry-integration (eventos de descarga)
- **Recibe de**: manifest-validator (eventos de validación)
- **Recibe de**: cli-ux (comando `smcp audit`)

## Notas Adicionales

### Ejemplo de audit.log

```json
{"timestamp":"2026-01-18T10:30:00Z","type":"execution.started","package":"acme/hello-world","version":"1.2.3","digest":"sha256:abc123","pid":12345,"metadata":{"entrypoint":"./bin/mcp-server","transport":"stdio","user":"alice"}}
{"timestamp":"2026-01-18T10:30:05Z","type":"execution.completed","package":"acme/hello-world","digest":"sha256:abc123","exit_code":0,"duration":5000000000}
{"timestamp":"2026-01-18T10:31:00Z","type":"execution.failed","package":"acme/buggy","version":"0.1.0","digest":"sha256:def456","exit_code":1,"error":"process killed by signal: killed","duration":60000000000}
{"timestamp":"2026-01-18T10:32:00Z","type":"validation.failed","digest":"sha256:xyz789","error":"digest mismatch: expected sha256:xyz789, got sha256:aaa111"}
```

### Output de `smcp audit ls`

```
TIMESTAMP                  PACKAGE              VERSION  PID    EXIT  DURATION
2026-01-18T10:30:00Z       acme/hello-world     1.2.3    12345  0     5s
2026-01-18T10:31:00Z       acme/buggy           0.1.0    12346  1     1m0s
2026-01-18T10:32:00Z       acme/test            2.0.0    12347  0     2s
```

### Redacción de secretos

```go
secrets := map[string]string{
    "DB_PASSWORD": "super-secret-123",
    "API_KEY":     "sk-abc-xyz-789",
}

event := ExecutionStarted(...)
event.Metadata["secrets"] = RedactSecrets(secrets)
// Result: {"secrets": ["DB_PASSWORD", "API_KEY"]}
```

### Formato de timestamp

Usar RFC3339 para compatibilidad:
```go
time.Now().Format(time.RFC3339)
// Output: "2026-01-18T10:30:00Z"
```

### Rotación con lumberjack

```yaml
audit:
  enabled: true
  log_file: ~/.smcp/audit.log
  rotation:
    max_size_mb: 100
    max_backups: 3
    max_age_days: 30
    compress: true
```

### Query API (para futuro)

Considerar exponer API HTTP para query de logs (fase 2):
```
GET /api/audit?package=acme/hello&start=2026-01-01&end=2026-01-31
```

### Compliance

El formato de auditoría debe ser suficiente para:
- **SOC2**: trazabilidad de ejecuciones
- **GDPR**: no loguear PII sin consentimiento
- **PCI-DSS**: no loguear secretos/tokens completos
