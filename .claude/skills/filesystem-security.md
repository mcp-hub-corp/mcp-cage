# Filesystem Security: Safe File Operations

This skill provides expert knowledge for secure filesystem operations in mcp-client.

## Security Threats

### 1. Path Traversal Attack
**Threat**: Attacker-controlled path escapes containment directory via `..`, absolute paths, or symlinks.

**Examples**:
- Extract `/etc/passwd` to system
- Write `../../sensitive/data` outside intended directory
- Follow symlink outside allowed scope

**Mitigation Strategy**:
1. **Normalize path**: `filepath.Clean()` (removes `..`, collapses `/`)
2. **Check for absolute paths**: Reject if starts with `/`
3. **Verify containment**: Ensure final path is within allowed root directory
4. **Detect symlinks**: Use `os.Lstat()` (not `os.Stat()`) to detect symlinks without following

**mcp-client Implementation** (internal/cli/run.go - GOOD):
```go
func isSafePath(basePath, targetPath string) bool {
    // 1. Normalize both paths
    basePath = filepath.Clean(basePath)
    targetPath = filepath.Clean(targetPath)

    // 2. Reject absolute paths
    if filepath.IsAbs(targetPath) {
        return false
    }

    // 3. Join and verify containment
    fullPath := filepath.Join(basePath, targetPath)
    fullPath = filepath.Clean(fullPath)

    // 4. Ensure fullPath starts with basePath
    return strings.HasPrefix(fullPath, basePath+string(filepath.Separator)) ||
           fullPath == basePath
}

// Usage in extraction:
cleanPath := filepath.Clean(header.Name)
if strings.HasPrefix(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
    return fmt.Errorf("invalid tar path: %s", header.Name)
}

targetPath := filepath.Join(destDir, cleanPath)
destDirClean := filepath.Clean(destDir)

if !strings.HasPrefix(targetPath, destDirClean+string(filepath.Separator)) &&
   targetPath != destDirClean {
    return fmt.Errorf("tar path traversal detected: %s", header.Name)
}
```

**Edge Cases**:
- Empty filename: `filepath.Join(destDir, "")` → `destDir` ✓
- `.` : `filepath.Clean(".")` → `.` (rejected)
- Multiple `../`: `../../etc` cleaned to `../../etc`, detected by prefix check ✓
- Windows UNC paths: `//host/share` → `filepath.Clean()` handles properly ✓
- Trailing slashes: `dir/` → `filepath.Clean()` removes

**Testing**:
```bash
# Path traversal attempt
isSafePath("/tmp/safe", "../etc/passwd")  # Should return false

# Normal path
isSafePath("/tmp/safe", "dir/file.txt")   # Should return true

# Absolute path
isSafePath("/tmp/safe", "/etc/passwd")    # Should return false
```

---

### 2. Symlink Attack Prevention
**Threat**: Archive or filesystem contains symlinks pointing outside containment, enabling:
- **Escape**: Read/write sensitive files via symlink
- **TOCTOU**: Create symlink, then replace with real file (race condition)
- **Permission bypass**: Link to files with different permissions

**Scenarios**:
1. **Extract archive with symlink**: `link → /etc/passwd`
2. **Symlink race**: Extract `link → file1`, then attacker changes link to `→ file2` before execution
3. **Follow symlink**: Code uses `os.Stat()` (follows link), attacker controls target

**Mitigation**:

**Option 1: Reject all symlinks** (SAFEST for untrusted archives)
```go
// Check if path is symlink BEFORE following
fi, err := os.Lstat(path)  // ✓ Lstat doesn't follow symlinks
if err != nil {
    return err
}

if fi.Mode()&os.ModeSymlink != 0 {
    return fmt.Errorf("symlinks not allowed: %s", path)
}
```

**Option 2: Resolve symlink safely** (for trusted archives)
```go
// Resolve symlink and verify it points within allowed directory
fi, err := os.Lstat(path)  // ✓ Use Lstat
if err != nil {
    return err
}

if fi.Mode()&os.ModeSymlink != 0 {
    // Resolve the link
    target, err := os.Readlink(path)
    if err != nil {
        return err
    }

    // Verify target is within allowed directory
    // (relative to link's directory, not basePath)
    resolvedPath := filepath.Join(filepath.Dir(path), target)
    resolvedPath = filepath.Clean(resolvedPath)

    // Check containment
    if !strings.HasPrefix(resolvedPath, basePath) {
        return fmt.Errorf("symlink escape detected: %s → %s", path, target)
    }

    // Safe to use
    return os.Symlink(target, path)
}
```

**Why `os.Lstat()` not `os.Stat()`**:
```go
// WRONG: Follows symlinks
fi, err := os.Stat("/tmp/link")
if err != nil && os.IsNotExist(err) {
    // Link target missing → reports error
    // Even if link is inside allowed dir, target outside → vulnerability
}

// CORRECT: Doesn't follow symlinks
fi, err := os.Lstat("/tmp/link")
if fi.Mode()&os.ModeSymlink != 0 {
    // Detected symlink before following it
    // Can then validate target or reject
}
```

**mcp-client Current Implementation** (internal/cli/run.go - **MISSING**):
The tar extraction doesn't explicitly handle `tar.TypeSymlink` or `tar.TypeLink`:
```go
switch header.Typeflag {
case tar.TypeDir:
    // ... extract directory
case tar.TypeReg:
    // ... extract file
// MISSING: case tar.TypeSymlink, tar.TypeLink
default:
    // Does not reach here currently
}
```

**Recommended Enhancement**:
```go
case tar.TypeSymlink:
    return fmt.Errorf("symlinks not allowed in bundle: %s", header.Name)

case tar.TypeLink:
    return fmt.Errorf("hard links not allowed in bundle: %s", header.Name)

default:
    return fmt.Errorf("unsupported tar entry type: %v for %s", header.Typeflag, header.Name)
```

**Testing**:
```bash
# Create archive with malicious symlink
mkdir -p /tmp/evil
ln -s /etc/passwd /tmp/evil/link
tar -czf evil.tar.gz -C /tmp evil

# Extraction should fail: "symlinks not allowed"
```

---

### 3. Temporary File Safety
**Threat**: Temp files with predictable names or loose permissions enable race conditions and privilege escalation.

**Attacks**:
1. **Predictable names**: Create `/tmp/mcp-bundle-1` before tool does → symlink to `/etc/shadow`
2. **Loose permissions**: Create temp file as 0o644 → attacker reads sensitive data
3. **Race condition**: Create file, attacker modifies before use → TOCTOU

**Mitigation**:
- **Use `os.CreateTemp()`**: Generates random, cryptographically unique names
- **Restrictive permissions**: `0o600` (rw-------, owner only)
- **Atomic rename**: Write to temp file, then atomic rename to final location (prevents partial reads)

**mcp-client Implementation** (internal/cli/run.go):
```go
// GOOD: Using os.MkdirTemp() with random name
tempDir, err := os.MkdirTemp("", "mcp-bundle-*")
if err != nil {
    return fmt.Errorf("failed to create temp directory: %w", err)
}
defer os.RemoveAll(tempDir)

// GOOD: Extracting into temp dir with restrictive perms
if err := os.MkdirAll(targetPath, 0o700); err != nil {  // 0o700 = rwx------
    return fmt.Errorf("failed to create directory: %w", err)
}

// GOOD: Files created with 0o600
file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
if err != nil {
    return fmt.Errorf("failed to create file: %w", err)
}
```

**Why not `ioutil.TempDir()`**:
- Deprecated in Go 1.16+, use `os.CreateTemp()` instead
- Provides same security guarantees

**Atomic rename pattern** (cache operations):
```go
import "io"

// Write to temp file
tempFile, err := os.CreateTemp(filepath.Dir(finalPath), "*.tmp")
if err != nil {
    return err
}
defer os.Remove(tempFile.Name())  // Clean up on error

// Write data
if _, err := io.Copy(tempFile, reader); err != nil {
    tempFile.Close()
    return err
}

// Sync to disk (ensure durability)
if err := tempFile.Sync(); err != nil {
    tempFile.Close()
    return err
}
if err := tempFile.Close(); err != nil {
    return err
}

// Atomic rename
// (On most filesystems, rename is atomic if on same filesystem)
if err := os.Rename(tempFile.Name(), finalPath); err != nil {
    return err
}
```

**Key Properties**:
- **Random name**: os.CreateTemp generates unique, unpredictable names
- **Mode 0600**: File not readable by other users
- **Atomic rename**: Single syscall (os.Rename) ensures atomicity

**Testing**:
```bash
# Create race condition attempt
while true; do
  [ -L /tmp/mcp-bundle-race ] && ln -s /etc/passwd /tmp/mcp-bundle-race
done &

# Should fail safely (uses random name, not predictable path)
smcp run test@1.0.0
```

---

### 4. Directory Permissions
**Threat**: Loose directory permissions expose sensitive data or allow modification.

**Scenarios**:
- Cache directory 0o755 (world-readable) → attacker reads cached secrets
- Work directory 0o777 (world-writable) → attacker modifies executable before execution
- Sensitive directory 0o777 → attacker can delete/replace files

**Mitigation**:
- **Sensitive directories** (cache, work, secrets): `0o700` (rwx------)
- **Public directories** (shared resources): `0o755` (rwxr-xr-x)
- **Never use 0o777 or 0o666**: No world access for sensitive operations

**Directory Hierarchy in mcp-client**:
```
~/.smcp/                         0o700 (sensitive: cache, auth)
  cache/                        0o700
    manifests/                  0o700
    bundles/                    0o700
  auth.json                     0o600 (file permissions)
  audit.log                     0o600

/tmp/mcp-bundle-RANDOM/         0o700 (work directory)
  bin/                          0o700
  lib/                          0o700
```

**mcp-client Implementation** (internal/cache/store.go - GOOD):
```go
// Create cache directories with restrictive permissions
manifestDir := filepath.Join(baseDir, "manifests")
bundleDir := filepath.Join(baseDir, "bundles")

if err := os.MkdirAll(manifestDir, 0o700); err != nil {  // ✓ 0o700
    return nil, fmt.Errorf("failed to create manifest cache directory: %w", err)
}

if err := os.MkdirAll(bundleDir, 0o700); err != nil {    // ✓ 0o700
    return nil, fmt.Errorf("failed to create bundle cache directory: %w", err)
}
```

**Verification**:
```bash
# Check smcp cache directory
ls -la ~/.smcp/
# Expected: drwx------ (0o700)

# Check subdirectories
ls -la ~/.smcp/cache/
# Expected: drwx------ for manifests, bundles

# Check extracted bundle directory
ls -la /tmp/mcp-bundle-*/
# Expected: drwx------ (0o700)
```

---

### 5. File Permissions
**Threat**: Files with loose permissions or executable bit compromise security.

**Threats**:
- File with 0o644 in cache → attacker reads sensitive manifest/bundle
- File with 0o755 in work dir → attacker executes modified binary
- File with setuid bit → privilege escalation

**Mitigation**:
- **Sensitive files** (cache, auth, config): `0o600` (rw-------)
- **Regular files**: `0o644` (rw-r--r--) if public
- **Executables**: `0o755` (rwxr-xr-x) only when explicitly needed (NOT by default)
- **Never extract with executable bit**: Force 0o600 on all extracted files

**mcp-client Implementation** (internal/cli/run.go - GOOD):
```go
// Extract files with restrictive permissions
file, err := os.OpenFile(targetPath,
    os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
    0o600)  // ✓ No execute bit, owner-only
if err != nil {
    return fmt.Errorf("failed to create file: %w", err)
}
```

**Why NOT use `header.Mode`** (from tar archive):
```go
// WRONG: Uses archive-specified permissions
file, _ := os.OpenFile(targetPath,
    os.O_CREATE|os.O_WRONLY,
    os.FileMode(header.Mode))  // ✗ Archive says 0o755 → executable!

// CORRECT: Always use 0o600
file, _ := os.OpenFile(targetPath,
    os.O_CREATE|os.O_WRONLY,
    0o600)  // ✓ Not executable, owner-only
```

**Make executable explicitly (after verification)**:
```go
// After extraction and verification
if isEntrypoint {
    // Only make executable if validated to be safe
    if err := os.Chmod(extractedBinary, 0o755); err != nil {
        return err
    }
}
```

**Cache file permissions** (internal/cache/store.go):
```go
// Write to temp, then atomic rename
tempFile, err := os.CreateTemp(filepath.Dir(targetPath), "*.tmp")
if err != nil {
    return err
}

// Write data
io.Copy(tempFile, reader)
tempFile.Sync()
tempFile.Close()

// Chmod to 0o600 before rename (redundant but explicit)
os.Chmod(tempFile.Name(), 0o600)

// Atomic rename to final location
os.Rename(tempFile.Name(), targetPath)
```

---

### 6. Atomic Operations
**Threat**: Partial writes, interrupted operations, or concurrent access cause corruption or inconsistency.

**Scenarios**:
1. **Partial write**: Process crashes while writing bundle to cache → incomplete file
2. **Concurrent write**: Two processes write same manifest simultaneously → corruption
3. **TOCTOU**: Check file exists, then use it, but file deleted in between

**Mitigation**:
- **Write to temp, sync, rename**: Ensures atomicity (write-only completes or fails)
- **Locking**: Prevent concurrent modifications (use sync.RWMutex or file locks)
- **Sync to disk**: `File.Sync()` forces kernel to write (prevents data loss on crash)

**mcp-client Implementation** (internal/cache/store.go):
```go
func (s *Store) putArtifact(digest string, data []byte, kind string) error {
    // Generate target path
    var path string
    if kind == "manifests" {
        path = s.manifestPath(digest)
    } else {
        path = s.bundlePath(digest)
    }

    // Create parent directory
    if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
        return err
    }

    // Write to temporary file in same directory (atomic rename)
    tmpFile, err := os.CreateTemp(filepath.Dir(path), "*.tmp")
    if err != nil {
        return err
    }
    tmpPath := tmpFile.Name()

    // Write data
    _, err = tmpFile.Write(data)
    if err != nil {
        tmpFile.Close()
        os.Remove(tmpPath)  // Clean up
        return err
    }

    // Sync to disk (ensure durability)
    if err := tmpFile.Sync(); err != nil {
        tmpFile.Close()
        os.Remove(tmpPath)
        return err
    }

    // Close before rename (required on Windows)
    if err := tmpFile.Close(); err != nil {
        os.Remove(tmpPath)
        return err
    }

    // Atomic rename (ensures atomic complete/fail)
    if err := os.Rename(tmpPath, path); err != nil {
        os.Remove(tmpPath)
        return err
    }

    return nil
}
```

**Locking for concurrent access** (internal/cache/locking.go):
```go
type Store struct {
    baseDir string
    lock    sync.RWMutex  // ✓ Protects concurrent access
}

// Read operation (RLock)
func (s *Store) GetManifest(digest string) ([]byte, error) {
    s.lock.RLock()
    defer s.lock.RUnlock()

    // Read from cache (multiple readers allowed)
    return os.ReadFile(s.manifestPath(digest))
}

// Write operation (Lock)
func (s *Store) PutManifest(digest string, data []byte) error {
    s.lock.Lock()
    defer s.lock.Unlock()

    // Write to cache (exclusive access)
    return s.putArtifact(digest, data, "manifests")
}
```

**Properties**:
- **Temp file in same dir**: Ensures same filesystem (rename is atomic)
- **Sync before close**: Ensures data reaches disk
- **RWMutex protection**: Multiple readers, single writer (no concurrent writes)

---

### 7. Race Condition Prevention (TOCTOU)
**Threat**: Check-Then-Use (TOCTOU) race allows attacker to modify file between check and use.

**Example**:
```go
// WRONG: TOCTOU race
if _, err := os.Stat(path); err == nil {
    // File exists at this point

    // ... context switch, attacker deletes/modifies file ...

    // Use file (but it's different now!)
    data, _ := os.ReadFile(path)
}
```

**Mitigation**:
- **Atomic operations**: Open file once, use result
- **Fail on missing**: Don't check beforehand, fail on use (simpler)
- **Inode comparison**: If must check, compare inode before and after

**mcp-client Implementation**:
```go
// GOOD: Atomic open + read (no TOCTOU)
func (s *Store) GetManifest(digest string) ([]byte, error) {
    path := s.manifestPath(digest)
    data, err := os.ReadFile(path)  // ✓ Atomic: open + read + close
    if err != nil {
        if os.IsNotExist(err) {
            return nil, fmt.Errorf("manifest not in cache: %s", digest)
        }
        return nil, fmt.Errorf("failed to read manifest: %w", err)
    }
    return data, nil
}

// WRONG: Separate check + read (TOCTOU)
func BadGetManifest(digest string) ([]byte, error) {
    path := s.manifestPath(digest)

    // Check 1: Stat (file exists)
    _, err := os.Stat(path)
    if err != nil {
        return nil, err
    }

    // RACE: File deleted here by attacker

    // Check 2: Read (but file is gone or different now!)
    data, _ := os.ReadFile(path)  // May fail or read different file
    return data, nil
}
```

---

### 8. Disk Space Checks
**Threat**: Extraction/write operations fail if disk is full, potentially leaving partial files.

**Scenarios**:
- Extract bundle when disk is full → partial extraction
- Write manifest when no space → corrupted cache
- Cascade: Process can't clean up → DoS

**Mitigation**:
- **Check available space**: Before starting operation
- **Plan for growth**: Require margin (e.g., 10% free space minimum)
- **Clean up on failure**: Ensure temp files are removed

**Implementation** (optional enhancement):
```go
import "golang.org/x/sys/unix"

func checkDiskSpace(path string, requiredBytes int64) error {
    var stat unix.Statfs_t
    if err := unix.Statfs(path, &stat); err != nil {
        return fmt.Errorf("failed to check disk space: %w", err)
    }

    // Available space = blocks available * block size
    availableBytes := int64(stat.Bavail) * int64(stat.Bsize)

    // Require 10% margin above needed space
    requiredWithMargin := requiredBytes + (requiredBytes / 10)

    if availableBytes < requiredWithMargin {
        return fmt.Errorf("insufficient disk space: need %d bytes, have %d bytes",
            requiredWithMargin, availableBytes)
    }

    return nil
}

// Usage in extraction:
const extractionLimit = 1024 * 1024 * 1024  // 1GB

if err := checkDiskSpace(tempDir, extractionLimit); err != nil {
    return fmt.Errorf("disk check failed: %w", err)
}
```

**Current mcp-client**: No explicit disk space check (relies on OS to fail if full)

---

### 9. Secure Deletion (Optional)
**Threat**: Sensitive data in memory or temp files can be recovered after deletion if not overwritten.

**Scenarios**:
- Delete temp bundle file → attacker recovers from disk with forensics
- Clear memory → data remains in RAM (swap file)

**Mitigation** (for high-security):
- **Overwrite before delete**: Use `secure-delete` package or manual overwrite
- **Volatile RAM**: Sensitive data in volatile RAM only (no swap)

**Implementation** (optional, for secrets):
```go
// Overwrite sensitive data before deletion
func secureDelete(filePath string) error {
    fi, err := os.Stat(filePath)
    if err != nil {
        return err
    }

    // Overwrite with zeros
    file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
    if err != nil {
        return err
    }

    // Write zeros to overwrite all data
    zeroBytes := make([]byte, fi.Size())
    if _, err := file.Write(zeroBytes); err != nil {
        file.Close()
        return err
    }

    file.Close()

    // Delete file
    return os.Remove(filePath)
}
```

**Current mcp-client**: No secure deletion (bundles are temporary, acceptable)

**Recommendation**: Not needed for mcp-client (bundles are re-downloadable), focus on access control instead.

---

## Safe Filesystem Operations Pattern

**Template for secure file ops**:
```go
package safe

import (
    "io"
    "os"
    "path/filepath"
    "strings"
)

// SafePathValidator validates and normalizes filesystem paths
type SafePathValidator struct {
    basePath string
}

// NewSafePathValidator creates a path validator for a base directory
func NewSafePathValidator(basePath string) (*SafePathValidator, error) {
    // Verify base path exists and is directory
    fi, err := os.Stat(basePath)
    if err != nil {
        return nil, err
    }
    if !fi.IsDir() {
        return nil, fmt.Errorf("base path is not directory: %s", basePath)
    }

    return &SafePathValidator{
        basePath: filepath.Clean(basePath),
    }, nil
}

// ValidatePath checks if path is safe and within basePath
func (v *SafePathValidator) ValidatePath(path string) (string, error) {
    // 1. Reject absolute paths
    if filepath.IsAbs(path) {
        return "", fmt.Errorf("absolute paths not allowed: %s", path)
    }

    // 2. Normalize path
    cleanPath := filepath.Clean(path)

    // 3. Reject traversal attempts
    if strings.HasPrefix(cleanPath, "..") {
        return "", fmt.Errorf("path traversal detected: %s", path)
    }

    // 4. Join and verify containment
    fullPath := filepath.Join(v.basePath, cleanPath)
    fullPath = filepath.Clean(fullPath)

    // 5. Check containment
    if !strings.HasPrefix(fullPath, v.basePath+string(filepath.Separator)) &&
       fullPath != v.basePath {
        return "", fmt.Errorf("path outside base directory: %s", path)
    }

    return fullPath, nil
}

// SafeFileWriter writes files atomically with restrictive permissions
type SafeFileWriter struct {
    validator *SafePathValidator
}

// NewSafeFileWriter creates a file writer
func NewSafeFileWriter(basePath string) (*SafeFileWriter, error) {
    validator, err := NewSafePathValidator(basePath)
    if err != nil {
        return nil, err
    }
    return &SafeFileWriter{validator}, nil
}

// WriteFile writes data to file atomically with 0o600 permissions
func (w *SafeFileWriter) WriteFile(relativePath string, data []byte) error {
    // 1. Validate path
    fullPath, err := w.validator.ValidatePath(relativePath)
    if err != nil {
        return err
    }

    // 2. Create parent directory if needed
    parentDir := filepath.Dir(fullPath)
    if err := os.MkdirAll(parentDir, 0o700); err != nil {
        return fmt.Errorf("failed to create parent directory: %w", err)
    }

    // 3. Write to temporary file
    tmpFile, err := os.CreateTemp(filepath.Dir(fullPath), "*.tmp")
    if err != nil {
        return fmt.Errorf("failed to create temp file: %w", err)
    }
    tmpPath := tmpFile.Name()

    // 4. Write data
    if _, err := tmpFile.Write(data); err != nil {
        tmpFile.Close()
        os.Remove(tmpPath)
        return fmt.Errorf("failed to write data: %w", err)
    }

    // 5. Sync to disk
    if err := tmpFile.Sync(); err != nil {
        tmpFile.Close()
        os.Remove(tmpPath)
        return fmt.Errorf("failed to sync file: %w", err)
    }

    // 6. Close file
    if err := tmpFile.Close(); err != nil {
        os.Remove(tmpPath)
        return fmt.Errorf("failed to close temp file: %w", err)
    }

    // 7. Atomic rename
    if err := os.Rename(tmpPath, fullPath); err != nil {
        os.Remove(tmpPath)
        return fmt.Errorf("failed to rename file: %w", err)
    }

    return nil
}

// ReadFile reads file safely, checking for symlinks
func (w *SafeFileWriter) ReadFile(relativePath string) ([]byte, error) {
    // 1. Validate path
    fullPath, err := w.validator.ValidatePath(relativePath)
    if err != nil {
        return nil, err
    }

    // 2. Check for symlinks (use Lstat, not Stat)
    fi, err := os.Lstat(fullPath)
    if err != nil {
        return nil, err
    }

    // 3. Reject symlinks
    if fi.Mode()&os.ModeSymlink != 0 {
        return nil, fmt.Errorf("symlinks not allowed: %s", relativePath)
    }

    // 4. Read file
    data, err := os.ReadFile(fullPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read file: %w", err)
    }

    return data, nil
}

// MakeDir creates directory with safe permissions
func (w *SafeFileWriter) MakeDir(relativePath string) error {
    fullPath, err := w.validator.ValidatePath(relativePath)
    if err != nil {
        return err
    }

    if err := os.MkdirAll(fullPath, 0o700); err != nil {
        return fmt.Errorf("failed to create directory: %w", err)
    }

    return nil
}
```

**Usage**:
```go
// Create writer for cache directory
writer, err := NewSafeFileWriter(cacheDir)
if err != nil {
    return err
}

// Write manifest safely
if err := writer.WriteFile("manifest.json", manifestData); err != nil {
    return err
}

// Read bundle safely (rejects symlinks)
bundleData, err := writer.ReadFile("bundle.tar.gz")
if err != nil {
    return err
}
```

---

## Testing Filesystem Security

### Unit Tests
```go
func TestSafePathValidator_RejectsTraversal(t *testing.T) {
    v := NewSafePathValidator("/tmp/safe")

    // Traversal attempts
    tests := []string{
        "../etc/passwd",
        "../../sensitive",
        "/etc/passwd",          // Absolute
        "a/../../b",            // Complex traversal
    }

    for _, test := range tests {
        _, err := v.ValidatePath(test)
        assert.Error(t, err, "should reject: %s", test)
    }
}

func TestSafePathValidator_AllowsValidPaths(t *testing.T) {
    v := NewSafePathValidator("/tmp/safe")

    tests := []string{
        "file.txt",
        "dir/file.txt",
        "a/b/c/file.txt",
        "./file.txt",
    }

    for _, test := range tests {
        _, err := v.ValidatePath(test)
        assert.NoError(t, err, "should allow: %s", test)
    }
}

func TestSafeFileWriter_RejectsSymlinks(t *testing.T) {
    tmpDir, _ := os.MkdirTemp("", "test-*")
    defer os.RemoveAll(tmpDir)

    writer, _ := NewSafeFileWriter(tmpDir)

    // Create symlink
    target := filepath.Join(tmpDir, "target.txt")
    os.WriteFile(target, []byte("data"), 0o600)

    link := filepath.Join(tmpDir, "link")
    os.Symlink(target, link)

    // Reading symlink should fail
    _, err := writer.ReadFile("link")
    assert.Error(t, err, "should reject symlinks")
}

func TestSafeFileWriter_AtomicWrite(t *testing.T) {
    tmpDir, _ := os.MkdirTemp("", "test-*")
    defer os.RemoveAll(tmpDir)

    writer, _ := NewSafeFileWriter(tmpDir)

    // Write file
    data := []byte("test data")
    writer.WriteFile("file.txt", data)

    // Verify no temp files left behind
    entries, _ := os.ReadDir(tmpDir)
    assert.Equal(t, 1, len(entries), "no temp files should remain")

    // Verify permissions
    fi, _ := os.Stat(filepath.Join(tmpDir, "file.txt"))
    assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestSafeFileWriter_DirectoryPermissions(t *testing.T) {
    tmpDir, _ := os.MkdirTemp("", "test-*")
    defer os.RemoveAll(tmpDir)

    writer, _ := NewSafeFileWriter(tmpDir)

    writer.MakeDir("a/b/c")

    // Verify all directories have 0o700
    for _, dir := range []string{"a", "a/b", "a/b/c"} {
        fullPath := filepath.Join(tmpDir, dir)
        fi, _ := os.Stat(fullPath)
        assert.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
    }
}
```

### Integration Tests
```bash
# Path traversal prevention
smcp run test/traversal@1.0.0 → FAIL (path traversal)

# Symlink safety
smcp run test/symlinks@1.0.0 → FAIL (symlinks not allowed)

# Permission enforcement
smcp run test/permissions@1.0.0 → SUCCESS
ls -la /tmp/extracted/ → drwx------ (0o700), -rw------- (0o600)
```

---

## Common Attacks & Defenses

### Attack 1: Directory Traversal
```bash
# Create: ../../etc/passwd
tar --transform 's,^,../../,S' -czf evil.tar.gz /etc/passwd
```
**Defense**: Path normalization + prefix check → BLOCKED

### Attack 2: Absolute Path
```bash
# Create: /etc/passwd
tar -czf evil.tar.gz /etc/passwd
```
**Defense**: Reject paths starting with `/` → BLOCKED

### Attack 3: Symlink Escape
```bash
# Create: link → /etc/passwd
ln -s /etc/passwd /tmp/evil/link
tar -czf evil.tar.gz /tmp/evil/link
```
**Defense**: Detect tar.TypeSymlink → BLOCKED

### Attack 4: Temp File Prediction
```bash
# Attacker creates /tmp/mcp-bundle-1 as symlink before tool runs
ln -s /etc/shadow /tmp/mcp-bundle-1
smcp run test@1.0.0
```
**Defense**: os.MkdirTemp generates random names → SAFE

### Attack 5: File Permission Escalation
```bash
# Archive contains executable (0o755), attacker modifies before execution
# Archive: file with 0o755
tar -czf evil.tar.gz file-with-execute-bit
```
**Defense**: Always extract with 0o600, explicitly chmod to execute if needed → SAFE

---

## Real Code: mcp-client Internal

### cache/store.go
```go
func (s *Store) putArtifact(digest string, data []byte, kind string) error {
    var path string
    if kind == "manifests" {
        path = s.manifestPath(digest)
    } else {
        path = s.bundlePath(digest)
    }

    // Create parent directory with restrictive perms
    if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
        return err
    }

    // Write to temp file
    tmpFile, err := os.CreateTemp(filepath.Dir(path), "*.tmp")
    if err != nil {
        return err
    }
    tmpPath := tmpFile.Name()

    // Write and sync
    if _, err := tmpFile.Write(data); err != nil {
        tmpFile.Close()
        os.Remove(tmpPath)
        return err
    }
    if err := tmpFile.Sync(); err != nil {
        tmpFile.Close()
        os.Remove(tmpPath)
        return err
    }
    if err := tmpFile.Close(); err != nil {
        os.Remove(tmpPath)
        return err
    }

    // Atomic rename
    if err := os.Rename(tmpPath, path); err != nil {
        os.Remove(tmpPath)
        return err
    }

    return nil
}
```

### cli/run.go
```go
func extractBundle(data []byte, destDir string) error {
    // ... (tar iteration)

    // Path validation
    cleanPath := filepath.Clean(header.Name)
    if strings.HasPrefix(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
        return fmt.Errorf("invalid tar path: %s", header.Name)
    }

    targetPath := filepath.Join(destDir, cleanPath)
    destDirClean := filepath.Clean(destDir)

    if !strings.HasPrefix(targetPath, destDirClean+string(filepath.Separator)) &&
       targetPath != destDirClean {
        return fmt.Errorf("tar path traversal detected: %s", header.Name)
    }

    // Directory with restrictive perms
    if err := os.MkdirAll(targetPath, 0o750); err != nil {
        return fmt.Errorf("failed to create directory: %w", err)
    }

    // File with restrictive perms (NOT executable)
    file, err := os.OpenFile(targetPath,
        os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
    if err != nil {
        return fmt.Errorf("failed to create file: %w", err)
    }
    defer file.Close()
}
```

---

## Security Invariants

1. **No path escapes basePath**: Ensured by filepath.Clean + prefix check
2. **No symlinks followed**: Use os.Lstat() to detect before following
3. **Temp files unpredictable**: os.CreateTemp generates random names
4. **Files not executable by default**: Always use 0o600 (or 0o755 only after validation)
5. **Directories owner-only**: Always use 0o700 for sensitive dirs
6. **Atomic writes**: Write to temp, sync, rename
7. **No TOCTOU races**: Open/read in single syscall (os.ReadFile)
8. **Concurrent writes prevented**: RWMutex protects cache operations

---

## Debugging Guide

### Verify Permissions
```bash
# Check cache directory
ls -la ~/.smcp/cache/
# Expected: drwx------ (0o700)

# Check cached files
ls -la ~/.smcp/cache/manifests/
# Expected: -rw------- (0o600)

# Check extracted bundle
ls -la /tmp/mcp-bundle-*/
# Expected: drwx------ for dirs, -rw------- for files
```

### Detect Symlinks
```bash
# List symlinks in directory
find /tmp/extracted -type l

# Check if specific path is symlink
[ -L /path/to/file ] && echo "is symlink" || echo "not symlink"

# Resolve symlink target
readlink /tmp/extracted/link
```

### Monitor File Operations (Linux)
```bash
# Trace file opens/creates
strace -e openat,open,mkdir,symlink ./smcp run test@1.0.0 2>&1 | \
  grep -E "bundle|cache|extracted"

# Verify all opens within allowed directory
strace -e openat ./smcp run test@1.0.0 2>&1 | \
  grep -v "/tmp/mcp-bundle" && echo "FAIL: writes outside bundle dir" || echo "PASS"
```

### Check Atomic Operations
```bash
# Monitor file system operations during extraction
(while true; do ls -l /tmp/mcp-bundle-*/; sleep 0.1; done) &
monitor_pid=$!
smcp run test@1.0.0
kill $monitor_pid

# Verify no orphaned temp files remain
ls /tmp/ | grep -E "\.tmp$|\.partial$"
# Should be empty
```

---

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [OWASP: Archive Extraction](https://owasp.org/www-community/attacks/Zip_Slip)
- [Go os package: FileMode](https://pkg.go.dev/os#FileMode)
- [Go filepath package](https://pkg.go.dev/path/filepath)
- [POSIX file permissions](https://pubs.opengroup.org/onlinepubs/9699919799/functions/chmod.html)
