# Agente: Sandbox macOS

## Nombre
**sandbox-macos**

## Misión
Implementar límites de recursos para procesos MCP en macOS. Dado que macOS carece de cgroups y network namespaces nativos, aplicar el mejor esfuerzo con rlimits, timeouts, y filesystem isolation. Documentar claramente las limitaciones.

## Responsabilidades

1. **Límites de recursos (rlimits)**
   - `RLIMIT_CPU`: tiempo de CPU en segundos
   - `RLIMIT_AS`: memoria virtual (menos confiable que en Linux)
   - `RLIMIT_NPROC`: número de procesos
   - `RLIMIT_NOFILE`: número de file descriptors
   - Aplicar con `syscall.Setrlimit()`

2. **Timeout enforcement**
   - Usar `context.WithTimeout()` para matar proceso
   - Kill tree: usar `pkill -P <pid>` para matar hijos
   - Signal escalation: SIGTERM → 5s → SIGKILL

3. **Filesystem isolation (limitada)**
   - Crear directorio de trabajo temporal: `/tmp/mcp-<digest>/`
   - Ejecutar proceso con `cmd.Dir` apuntando a tmpdir
   - Confiar en permisos UNIX para aislamiento (no hay bind mount equivalente fácil)

4. **Network isolation (NO DISPONIBLE)**
   - macOS no tiene network namespaces
   - Documentar claramente que network default-deny NO es posible
   - Recomendar ejecutar en VM/container si se requiere aislamiento de red

5. **Subprocess monitoring**
   - No se puede bloquear fork/exec sin kernel extension
   - Monitorear pids hijos y matarlos en cleanup
   - Documentar limitación

6. **Documentación de limitaciones**
   - Actualizar `smcp doctor` para reportar capabilities limitadas en macOS
   - Crear sección en `docs/SECURITY.md` explicando qué NO funciona en macOS

## Entregables

1. **Módulo `internal/sandbox/darwin.go`**
   ```go
   // +build darwin

   type DarwinSandbox struct {
       limits   ResourceLimits
       workDir  string
       timeout  time.Duration
   }

   type ResourceLimits struct {
       CPUSeconds  int64
       MemoryBytes int64
       MaxProcs    int64
       MaxFDs      int64
   }

   func NewDarwinSandbox(limits ResourceLimits, timeout time.Duration) (*DarwinSandbox, error)
   func (s *DarwinSandbox) Apply(cmd *exec.Cmd) error
   func (s *DarwinSandbox) Cleanup() error
   ```

2. **Rlimits `internal/sandbox/rlimits_darwin.go`**
   ```go
   // +build darwin

   func applyRlimits(limits ResourceLimits) error {
       syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: uint64(limits.CPUSeconds), Max: uint64(limits.CPUSeconds)})
       syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: uint64(limits.MemoryBytes), Max: uint64(limits.MemoryBytes)})
       syscall.Setrlimit(syscall.RLIMIT_NPROC, &syscall.Rlimit{Cur: uint64(limits.MaxProcs), Max: uint64(limits.MaxProcs)})
       syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: uint64(limits.MaxFDs), Max: uint64(limits.MaxFDs)})
       return nil
   }
   ```

3. **Timeout con kill tree `internal/sandbox/timeout_darwin.go`**
   ```go
   // +build darwin

   func killProcessTree(pid int) error {
       // Matar proceso principal
       proc, _ := os.FindProcess(pid)
       proc.Signal(syscall.SIGTERM)

       // Esperar 5s
       time.Sleep(5 * time.Second)

       // Matar con SIGKILL
       proc.Signal(syscall.SIGKILL)

       // Matar hijos (usar pkill -P)
       exec.Command("pkill", "-P", fmt.Sprintf("%d", pid)).Run()
       return nil
   }
   ```

4. **Filesystem isolation `internal/sandbox/fs_darwin.go`**
   ```go
   // +build darwin

   func createWorkDir(digest string) (string, error) {
       dir := filepath.Join(os.TempDir(), "mcp-"+digest)
       if err := os.MkdirAll(dir, 0700); err != nil {
           return "", err
       }
       return dir, nil
   }

   func cleanupWorkDir(dir string) error {
       return os.RemoveAll(dir)
   }
   ```

5. **Tests (ejecutar en macOS)**
   ```go
   // +build darwin
   func TestDarwinSandbox_Rlimits(t *testing.T) { ... }
   func TestDarwinSandbox_Timeout(t *testing.T) { ... }
   func TestDarwinSandbox_Cleanup(t *testing.T) { ... }
   ```

6. **Documentación `docs/SECURITY.md` (sección macOS)**
   ```markdown
   ## macOS Limitations

   macOS does not support the following security features:

   - **Network isolation**: No network namespaces. Processes can access network freely.
   - **Cgroups**: No cgroups equivalent. Only rlimits available.
   - **Subprocess blocking**: Cannot block fork/exec without kernel extension.
   - **Filesystem sandbox**: No bind mounts. Only UNIX permissions.

   **Recommendation**: For strict security requirements, run mcp-cage in a Linux VM or container on macOS.
   ```

## Definition of Done

- [ ] Rlimits aplicados correctamente
- [ ] Timeout funciona con kill tree (SIGTERM → SIGKILL)
- [ ] Directorio temporal creado y limpiado
- [ ] Tests en macOS pasan (GitHub Actions macOS runner)
- [ ] `smcp doctor` reporta limitaciones de macOS
- [ ] Documentación `docs/SECURITY.md` actualizada
- [ ] No hay warnings de features no soportadas sin contexto

## Checks Automáticos

```bash
# Tests (solo en macOS)
go test -v -tags darwin ./internal/sandbox/

# Linter
golangci-lint run ./internal/sandbox/

# Verificar que código compila en macOS
GOOS=darwin go build ./internal/sandbox/
```

## Cosas Prohibidas

- **NO** usar `sandbox-exec` (deprecated desde macOS 10.15)
- **NO** prometer network isolation (no existe en macOS)
- **NO** asumir que rlimits funcionan perfectamente (ej: RLIMIT_AS menos confiable)
- **NO** dejar procesos huérfanos (siempre kill tree en cleanup)
- **NO** usar comandos externos para límites (ej: `ulimit` CLI)
- **NO** fallar si no se pueden aplicar todos los límites (degradar gracefully)

## Coordinación con Otros Agentes

- **Provee a**: executor (configuración de sandbox aplicada a `exec.Cmd`)
- **Recibe de**: architect (interfaz `Sandbox`)
- **Recibe de**: manifest-validator (políticas de security)
- **Coordina con**: cli-ux (comando `smcp doctor`)
- **Coordina con**: docs (actualizar `SECURITY.md`)

## Notas Adicionales

### Output de `smcp doctor` en macOS

```
[✓] OS: darwin (arm64)
[✓] Rlimits: supported
[!] Cgroups: NOT available (Linux only)
[!] Network namespaces: NOT available (Linux only)
[!] Seccomp: NOT available (Linux only)
[!] Network isolation: NOT supported on macOS
[✓] Timeout enforcement: supported
[⚠] Recommendation: Use Linux VM for strict security requirements
```

### Aplicación de sandbox en `exec.Cmd`

```go
func (s *DarwinSandbox) Apply(cmd *exec.Cmd) error {
    // Crear directorio de trabajo
    workDir, err := createWorkDir(s.digest)
    if err != nil {
        return err
    }
    s.workDir = workDir
    cmd.Dir = workDir

    // Aplicar rlimits en pre-exec hook
    cmd.SysProcAttr = &syscall.SysProcAttr{
        Setpgid: true, // crear process group
    }

    // Rlimits se aplican después de fork, antes de exec
    // (usar runtime.LockOSThread si es necesario)

    return nil
}
```

### Timeout con context

```go
ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
defer cancel()

cmd := exec.CommandContext(ctx, ...)
s.Apply(cmd)

if err := cmd.Run(); err != nil {
    if ctx.Err() == context.DeadlineExceeded {
        killProcessTree(cmd.Process.Pid)
    }
    return err
}
```

### Limitaciones de RLIMIT_AS en macOS

En macOS, `RLIMIT_AS` no es tan efectivo como en Linux porque:
- Procesos pueden tener memoria virtual muy grande debido a librerías compartidas
- El límite puede ser ignorado en algunos casos

**Workaround**: Combinar con `RLIMIT_DATA` y monitoreo de memoria real (fuera de scope inicial).

### Kill tree con pkill

```bash
# Matar proceso y todos sus hijos
pkill -P <pid>
```

**Nota**: Requiere que el proceso esté en un process group (usar `Setpgid: true`).

### Filesystem isolation limitada

macOS no tiene `mount --bind` fácilmente. Alternativas:
- Usar directorio temporal con permisos `0700`
- Confiar en permisos UNIX
- No garantizar que el proceso no pueda leer fuera del tmpdir

**Documentar** que el aislamiento filesystem es "best effort".

### Consideraciones de seguridad

- **No usar** en producción si se requiere aislamiento estricto
- **Recomendar** Docker Desktop for Mac o Linux VM
- **Evaluar** uso de Apple Sandbox API (requiere entitlements y es complejo)
