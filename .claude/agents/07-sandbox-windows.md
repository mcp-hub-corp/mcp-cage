# Agente: Sandbox Windows

## Nombre
**sandbox-windows**

## Misión
Implementar límites de recursos para procesos MCP en Windows usando Job Objects. Aplicar límites de CPU, memoria, pids y I/O. Documentar limitaciones de network isolation y filesystem isolation.

## Responsabilidades

1. **Job Objects (límites de recursos)**
   - Crear Job Object con `CreateJobObject()`
   - Configurar límites con `SetInformationJobObject()`:
     - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`: número de procesos
     - `JOB_OBJECT_LIMIT_JOB_MEMORY`: memoria total del job
     - `JOB_OBJECT_LIMIT_JOB_TIME`: tiempo de CPU total
   - Asignar proceso al job con `AssignProcessToJobObject()`
   - Los procesos hijos heredan automáticamente el job

2. **Timeout enforcement**
   - Usar `context.WithTimeout()` + `TerminateJobObject()`
   - Job Objects permiten matar todos los procesos del job de golpe

3. **Filesystem isolation (limitada)**
   - Crear directorio temporal: `%TEMP%\mcp-<digest>\`
   - Ejecutar proceso con `cmd.Dir` apuntando a tmpdir
   - Confiar en permisos NTFS para aislamiento

4. **Network isolation (NO DISPONIBLE)**
   - Windows no tiene network namespaces nativos
   - Alternativa: Windows Filtering Platform (WFP) requiere driver kernel
   - Documentar que network default-deny NO es posible sin drivers

5. **Subprocess control**
   - Job Objects propagan restricciones a child processes automáticamente
   - No se puede bloquear fork/exec específicamente sin API adicional

6. **Cleanup**
   - `CloseHandle()` del job object cierra automáticamente todos los procesos
   - Eliminar directorio temporal

## Entregables

1. **Módulo `internal/sandbox/windows.go`**
   ```go
   // +build windows

   import (
       "golang.org/x/sys/windows"
   )

   type WindowsSandbox struct {
       jobHandle windows.Handle
       workDir   string
       limits    ResourceLimits
       timeout   time.Duration
   }

   type ResourceLimits struct {
       CPUMillis   int64 // tiempo de CPU en milisegundos
       MemoryBytes int64
       MaxProcs    int64
   }

   func NewWindowsSandbox(limits ResourceLimits, timeout time.Duration) (*WindowsSandbox, error)
   func (s *WindowsSandbox) Apply(cmd *exec.Cmd) error
   func (s *WindowsSandbox) Cleanup() error
   ```

2. **Job Objects `internal/sandbox/jobobject_windows.go`**
   ```go
   // +build windows

   import (
       "golang.org/x/sys/windows"
       "unsafe"
   )

   func createJobObject(limits ResourceLimits) (windows.Handle, error) {
       job, err := windows.CreateJobObject(nil, nil)
       if err != nil {
           return 0, err
       }

       // Configurar límites
       var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
       info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
           windows.JOB_OBJECT_LIMIT_JOB_MEMORY |
           windows.JOB_OBJECT_LIMIT_JOB_TIME

       info.BasicLimitInformation.ActiveProcessLimit = uint32(limits.MaxProcs)
       info.JobMemoryLimit = uintptr(limits.MemoryBytes)
       info.BasicLimitInformation.PerJobUserTimeLimit = int64(limits.CPUMillis * 10000) // 100ns units

       windows.SetInformationJobObject(
           job,
           windows.JobObjectExtendedLimitInformation,
           uintptr(unsafe.Pointer(&info)),
           uint32(unsafe.Sizeof(info)),
       )

       return job, nil
   }

   func assignProcessToJob(job windows.Handle, pid int) error {
       handle, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(pid))
       if err != nil {
           return err
       }
       defer windows.CloseHandle(handle)

       return windows.AssignProcessToJobObject(job, handle)
   }
   ```

3. **Timeout `internal/sandbox/timeout_windows.go`**
   ```go
   // +build windows

   func (s *WindowsSandbox) killWithTimeout(timeout time.Duration) error {
       time.Sleep(timeout)
       return windows.TerminateJobObject(s.jobHandle, 1)
   }
   ```

4. **Filesystem isolation `internal/sandbox/fs_windows.go`**
   ```go
   // +build windows

   import "path/filepath"

   func createWorkDir(digest string) (string, error) {
       tmpDir := os.Getenv("TEMP")
       if tmpDir == "" {
           tmpDir = "C:\\Temp"
       }
       dir := filepath.Join(tmpDir, "mcp-"+digest)
       if err := os.MkdirAll(dir, 0700); err != nil {
           return "", err
       }
       return dir, nil
   }

   func cleanupWorkDir(dir string) error {
       return os.RemoveAll(dir)
   }
   ```

5. **Tests (ejecutar en Windows)**
   ```go
   // +build windows
   func TestWindowsSandbox_JobObject(t *testing.T) { ... }
   func TestWindowsSandbox_MemoryLimit(t *testing.T) { ... }
   func TestWindowsSandbox_Timeout(t *testing.T) { ... }
   func TestWindowsSandbox_Cleanup(t *testing.T) { ... }
   ```

6. **Documentación `docs/SECURITY.md` (sección Windows)**
   ```markdown
   ## Windows Limitations

   Windows supports resource limits via Job Objects but has the following limitations:

   - **Network isolation**: No network namespaces. Requires Windows Filtering Platform (WFP) driver for true isolation.
   - **Filesystem sandbox**: Limited to NTFS permissions. No mount namespaces.
   - **Subprocess control**: Job Objects propagate restrictions automatically but cannot block specific syscalls.

   **Recommendation**: For strict security requirements, use Windows Sandbox API (Windows 10 Pro+) or run in WSL2/VM.
   ```

## Definition of Done

- [ ] Job Objects creados y configurados correctamente
- [ ] Límites de CPU, memoria, pids aplicados
- [ ] Timeout funciona (TerminateJobObject)
- [ ] Cleanup libera job handle y tmpdir
- [ ] Tests en Windows pasan (GitHub Actions Windows runner)
- [ ] `smcp doctor` reporta capabilities de Windows
- [ ] Documentación `docs/SECURITY.md` actualizada

## Checks Automáticos

```bash
# Tests (solo en Windows)
go test -v -tags windows ./internal/sandbox/

# Linter
golangci-lint run ./internal/sandbox/

# Verificar que código compila en Windows
GOOS=windows go build ./internal/sandbox/
```

## Cosas Prohibidas

- **NO** asumir que WFP está disponible (requiere driver kernel)
- **NO** prometer network isolation sin drivers
- **NO** usar APIs deprecated (ej: `CreateProcess` sin job objects)
- **NO** dejar job handles sin cerrar (leak de recursos)
- **NO** hardcodear paths de Windows (usar `os.Getenv("TEMP")`)
- **NO** asumir que permisos funcionan igual que en UNIX

## Coordinación con Otros Agentes

- **Provee a**: executor (configuración de sandbox aplicada a `exec.Cmd`)
- **Recibe de**: architect (interfaz `Sandbox`)
- **Recibe de**: manifest-validator (políticas de security)
- **Coordina con**: cli-ux (comando `smcp doctor`)
- **Coordina con**: docs (actualizar `SECURITY.md`)

## Notas Adicionales

### Output de `smcp doctor` en Windows

```
[✓] OS: windows (amd64)
[✓] Job Objects: supported
[✓] Resource limits: CPU, memory, pids supported
[!] Network isolation: NOT available (requires WFP driver)
[!] Filesystem sandbox: limited (NTFS permissions only)
[⚠] Recommendation: Use Windows Sandbox or WSL2 for strict security
```

### Creación de Job Object completo

```go
func (s *WindowsSandbox) Apply(cmd *exec.Cmd) error {
    // Crear directorio de trabajo
    workDir, err := createWorkDir(s.digest)
    if err != nil {
        return err
    }
    s.workDir = workDir
    cmd.Dir = workDir

    // Crear job object
    job, err := createJobObject(s.limits)
    if err != nil {
        return err
    }
    s.jobHandle = job

    // Asignar proceso al job (después de iniciar)
    // En Windows, el proceso se asigna después de cmd.Start()
    return nil
}

func (s *WindowsSandbox) Start(cmd *exec.Cmd) error {
    if err := cmd.Start(); err != nil {
        return err
    }

    // Asignar al job
    if err := assignProcessToJob(s.jobHandle, cmd.Process.Pid); err != nil {
        cmd.Process.Kill()
        return err
    }

    // Iniciar goroutine de timeout
    go func() {
        time.Sleep(s.timeout)
        windows.TerminateJobObject(s.jobHandle, 1)
    }()

    return nil
}
```

### Cleanup de Job Object

```go
func (s *WindowsSandbox) Cleanup() error {
    if s.jobHandle != 0 {
        // Terminar todos los procesos del job
        windows.TerminateJobObject(s.jobHandle, 0)
        windows.CloseHandle(s.jobHandle)
        s.jobHandle = 0
    }

    if s.workDir != "" {
        os.RemoveAll(s.workDir)
    }

    return nil
}
```

### Límites de Job Object

**CPU Time**: En unidades de 100 nanosegundos
```go
info.BasicLimitInformation.PerJobUserTimeLimit = int64(limits.CPUMillis * 10000)
```

**Memory**: En bytes
```go
info.JobMemoryLimit = uintptr(limits.MemoryBytes)
```

**Process count**:
```go
info.BasicLimitInformation.ActiveProcessLimit = uint32(limits.MaxProcs)
```

### Flags importantes

```go
const (
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    JOB_OBJECT_LIMIT_JOB_MEMORY     = 0x00000200
    JOB_OBJECT_LIMIT_JOB_TIME       = 0x00000004
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000 // importante: matar procesos al cerrar job
)
```

### Propagación a child processes

Los Job Objects en Windows automáticamente incluyen todos los child processes. No hace falta configuración adicional.

### Alternativas avanzadas (fuera de scope inicial)

- **Windows Sandbox API**: requiere Windows 10 Pro+, muy pesado
- **AppContainers**: requiere UWP, complejo
- **Windows Filtering Platform**: requiere driver kernel, fuera de scope
