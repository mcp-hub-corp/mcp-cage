# Agente: Sandbox Linux

## Nombre
**sandbox-linux**

## Misión
Implementar aislamiento y límites de recursos para procesos MCP en Linux. Usar rlimits, cgroups v2, namespaces y seccomp para garantizar seguridad razonable sin requerir virtualización completa.

## Responsabilidades

1. **Límites de recursos (rlimits)**
   - `RLIMIT_CPU`: tiempo de CPU en segundos
   - `RLIMIT_AS`: memoria virtual (address space)
   - `RLIMIT_NPROC`: número de procesos
   - `RLIMIT_NOFILE`: número de file descriptors
   - Aplicar con `syscall.Setrlimit()` antes de `exec`

2. **Cgroups v2 (si disponibles)**
   - Crear cgroup en `/sys/fs/cgroup/mcp-cage/<digest>/`
   - Límites: `cpu.max`, `memory.max`, `pids.max`
   - Mover proceso a cgroup con `echo $PID > cgroup.procs`
   - Cleanup: eliminar cgroup al terminar

3. **Network isolation (network namespaces)**
   - Crear netns vacío con `unshare(CLONE_NEWNET)`
   - Solo loopback disponible (default-deny)
   - Si manifest tiene allowlist, configurar iptables/nftables o usar eBPF (avanzado)
   - Requiere `CAP_NET_ADMIN` (root o ambient capabilities)

4. **Filesystem isolation**
   - Crear directorio de trabajo temporal: `/tmp/mcp-<digest>/`
   - Bind mount privado del bundle extraído
   - Opcionalmente: mount namespace con `chroot` o `pivot_root`
   - tmpfs para `/tmp` dentro del sandbox

5. **Subprocess restrictions (seccomp)**
   - Si manifest tiene `subprocess.allow: false`, bloquear syscalls: `fork`, `clone`, `execve`
   - Usar `libseccomp` o escribir filtro BPF manual
   - Aplicar con `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`

6. **Timeout enforcement**
   - Usar `context.WithTimeout()` para matar proceso al exceder límite
   - Signal escalation: SIGTERM → esperar 5s → SIGKILL

## Entregables

1. **Módulo `internal/sandbox/linux.go`**
   ```go
   // +build linux

   type LinuxSandbox struct {
       limits   ResourceLimits
       cgroupPath string
       netns    bool
   }

   type ResourceLimits struct {
       CPUSeconds  int64 // RLIMIT_CPU
       MemoryBytes int64 // RLIMIT_AS
       MaxProcs    int64 // RLIMIT_NPROC
       MaxFDs      int64 // RLIMIT_NOFILE
   }

   func NewLinuxSandbox(limits ResourceLimits) (*LinuxSandbox, error)
   func (s *LinuxSandbox) Apply(cmd *exec.Cmd) error
   func (s *LinuxSandbox) Cleanup() error
   ```

2. **Rlimits `internal/sandbox/rlimits_linux.go`**
   ```go
   func applyRlimits(limits ResourceLimits) error {
       syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: limits.CPUSeconds, Max: limits.CPUSeconds})
       syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: limits.MemoryBytes, Max: limits.MemoryBytes})
       // ...
   }
   ```

3. **Cgroups `internal/sandbox/cgroups_linux.go`**
   ```go
   func createCgroup(path string, limits ResourceLimits) error {
       os.MkdirAll(path, 0755)
       os.WriteFile(path+"/cpu.max", []byte(fmt.Sprintf("%d 100000", limits.CPUSeconds*1000)), 0644)
       os.WriteFile(path+"/memory.max", []byte(fmt.Sprintf("%d", limits.MemoryBytes)), 0644)
       os.WriteFile(path+"/pids.max", []byte(fmt.Sprintf("%d", limits.MaxProcs)), 0644)
   }

   func addProcessToCgroup(path string, pid int) error {
       return os.WriteFile(path+"/cgroup.procs", []byte(fmt.Sprintf("%d", pid)), 0644)
   }

   func cleanupCgroup(path string) error {
       return os.Remove(path)
   }
   ```

4. **Network namespaces `internal/sandbox/netns_linux.go`**
   ```go
   import "golang.org/x/sys/unix"

   func createNetNS() error {
       return unix.Unshare(unix.CLONE_NEWNET)
   }

   // Si manifest tiene allowlist, configurar iptables (fuera de scope inicial)
   ```

5. **Seccomp `internal/sandbox/seccomp_linux.go`**
   ```go
   import "github.com/seccomp/libseccomp-golang"

   func applySeccomp(allowSubprocess bool) error {
       if allowSubprocess {
           return nil
       }

       filter, _ := seccomp.NewFilter(seccomp.ActAllow)
       filter.AddRule(seccomp.ActErrno, seccomp.ScmpSysFork)
       filter.AddRule(seccomp.ActErrno, seccomp.ScmpSysClone)
       filter.AddRule(seccomp.ActErrno, seccomp.ScmpSysExecve)
       return filter.Load()
   }
   ```

6. **Tests (requieren VM Linux o container)**
   ```go
   // +build linux
   func TestLinuxSandbox_Rlimits(t *testing.T) { ... }
   func TestLinuxSandbox_Cgroups(t *testing.T) { ... }
   func TestLinuxSandbox_Timeout(t *testing.T) { ... }
   ```

## Definition of Done

- [ ] Rlimits aplicados correctamente (verificar con `ulimit` dentro del proceso)
- [ ] Cgroups funcionan (si disponibles y con permisos)
- [ ] Network namespace aísla correctamente (solo loopback)
- [ ] Seccomp bloquea subprocess si manifest lo pide
- [ ] Timeout mata proceso con SIGTERM → SIGKILL
- [ ] Cleanup libera recursos (cgroups, netns, tmpdir)
- [ ] Tests en VM Linux o GitHub Actions pasan
- [ ] Documentación de requisitos (CAP_NET_ADMIN, cgroups delegación)

## Checks Automáticos

```bash
# Tests (solo en Linux)
go test -v -tags linux ./internal/sandbox/

# Race detector
go test -race -tags linux ./internal/sandbox/

# Linter
golangci-lint run ./internal/sandbox/

# Verificar que código compila en Linux
GOOS=linux go build ./internal/sandbox/
```

## Cosas Prohibidas

- **NO** asumir que siempre hay permisos de root (documentar requisitos)
- **NO** usar cgroups v1 (obsoleto, usar solo v2)
- **NO** hardcodear path de cgroups (detectar montaje dinámicamente)
- **NO** fallar si cgroups no están disponibles (degradar gracefully a solo rlimits)
- **NO** crear netns si no hay `CAP_NET_ADMIN` (degradar a no-isolation + warning)
- **NO** dejar cgroups sin limpiar (siempre `defer cleanup()`)
- **NO** usar `kill -9` inmediatamente (primero SIGTERM, luego SIGKILL)

## Coordinación con Otros Agentes

- **Provee a**: executor (configuración de sandbox aplicada a `exec.Cmd`)
- **Recibe de**: architect (interfaz `Sandbox`)
- **Recibe de**: manifest-validator (políticas de security)
- **Coordina con**: cli-ux (comando `smcp doctor` debe reportar capabilities)

## Notas Adicionales

### Detección de cgroups v2

```go
func cgroupsAvailable() bool {
    _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
    return err == nil
}
```

### Aplicación de rlimits en `exec.Cmd`

```go
cmd := exec.Command(...)
cmd.SysProcAttr = &syscall.SysProcAttr{
    Setpgid: true, // crear process group para kill tree
}

// Pre-exec hook para rlimits
cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid} // drop privs
```

### Timeout con context

```go
ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
defer cancel()

cmd := exec.CommandContext(ctx, ...)
if err := cmd.Run(); err != nil {
    if ctx.Err() == context.DeadlineExceeded {
        // Timeout, matar con SIGKILL
        cmd.Process.Signal(syscall.SIGKILL)
    }
}
```

### Output de `smcp doctor` en Linux

```
[✓] OS: linux (amd64)
[✓] Cgroups v2: available at /sys/fs/cgroup
[!] Cgroups delegation: limited (non-root user)
[✓] Network namespaces: available (requires CAP_NET_ADMIN)
[✓] Seccomp: available
[✓] Rlimits: supported
```

### Escalation de señales

```go
func killWithTimeout(proc *os.Process, timeout time.Duration) error {
    proc.Signal(syscall.SIGTERM)

    done := make(chan error, 1)
    go func() {
        _, err := proc.Wait()
        done <- err
    }()

    select {
    case <-time.After(timeout):
        proc.Signal(syscall.SIGKILL)
        return <-done
    case err := <-done:
        return err
    }
}
```

### Limitaciones conocidas

- **Network allowlist**: requiere iptables/nftables o eBPF (complejo, puede ser fase 2)
- **Cgroups sin root**: requiere systemd user slice o delegación explícita
- **Seccomp**: puede romper binarios que usan fork internamente (documentar)
