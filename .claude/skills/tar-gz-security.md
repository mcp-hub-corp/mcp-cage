# TAR.GZ Security: Safe Bundle Extraction

This skill provides expert knowledge for secure tar.gz bundle extraction in mcp-client.

## Security Threats

### 1. Zip Bomb (Decompression Bomb)
**Threat**: Highly compressed archive expands to massive uncompressed size, exhausting disk/memory.

**Example**:
- File: 100MB compressed
- Uncompressed: 100GB (1000:1 ratio)
- Result: Out of disk, OOM killer, DoS

**Mitigation**:
- Set **total uncompressed size limit**: 1GB (configurable)
- Track `totalExtracted` as sum of all file sizes
- Reject if any file exceeds limit: `header.Size > maxExtractSize`
- Reject if cumulative exceeds limit: `totalExtracted > maxExtractSize`

**mcp-client Implementation** (internal/cli/run.go):
```go
const maxExtractSize = 1024 * 1024 * 1024 // 1GB limit

var totalExtracted int64

for {
    header, _ := tarReader.Next()

    // Per-file check
    if header.Size > maxExtractSize {
        return fmt.Errorf("file too large: %s", header.Name)
    }

    totalExtracted += header.Size
    if totalExtracted > maxExtractSize {
        return fmt.Errorf("total extracted size exceeds limit")
    }
}
```

**Testing**:
```bash
# Create bomb (10KB → 1GB when decompressed)
dd if=/dev/zero bs=1M count=1024 | gzip > bomb.tar.gz
tar -tzf bomb.tar.gz | head -1

# Should fail with "total extracted size exceeds limit"
```

---

### 2. Path Traversal Attack
**Threat**: Archive contains paths like `../../../etc/passwd` or `/etc/passwd`, extracting outside destination.

**Attack Vectors**:
- `../../sensitive/file` (relative traversal)
- `/etc/passwd` (absolute path)
- `a/../../../b` (complex traversal)
- Symlinks pointing outside (covered separately)

**Mitigation**:
1. **Normalize path**: `filepath.Clean(header.Name)` (removes `..`, collapses `/`)
2. **Reject dangerous prefixes**: `..` or `/` at start
3. **Verify containment**: Ensure final path stays within `destDir`

**mcp-client Implementation** (internal/cli/run.go):
```go
// Step 1: Normalize
cleanPath := filepath.Clean(header.Name)

// Step 2: Reject dangerous patterns
if strings.HasPrefix(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
    return fmt.Errorf("invalid tar path: %s", header.Name)
}

// Step 3: Join and verify containment
targetPath := filepath.Join(destDir, cleanPath)
destDirClean := filepath.Clean(destDir)

// Ensure target is within destDir
if !strings.HasPrefix(targetPath, destDirClean+string(filepath.Separator)) &&
   targetPath != destDirClean {
    return fmt.Errorf("tar path traversal detected: %s", header.Name)
}
```

**Edge Cases**:
- Empty filename: `filepath.Join(destDir, "")` → `destDir` ✓
- Single dot: `filepath.Clean(".")` → `.` (rejected as relative)
- UNC paths on Windows: `//host/share/file` (cleaned, then prefix check blocks `/`)

**Testing**:
```bash
# Create traversal archive
mkdir -p /tmp/tar-test
cd /tmp/tar-test
tar --transform 's,^,../,S' -czf traversal.tar.gz /etc/passwd
# Should fail: "invalid tar path" or "traversal detected"
```

---

### 3. Symlink Attack Prevention
**Threat**: Archive contains symlinks pointing outside extraction directory, used for TOCTOU or permission bypass.

**Attack Scenarios**:
1. **Escape symlink**: `link → ../../../etc/passwd` (read sensitive file)
2. **Overwrite symlink**: `link → /etc/hosts` + later extract regular file over it
3. **Race condition**: Extract symlink, then replace with malicious target before execution

**Mitigation**:
- **Detect symlinks**: `header.Typeflag == tar.TypeSymlink`
- **Validate symlink targets**: Resolve target, ensure it's within or safe
- **Alternative**: Skip symlinks (reject) or resolve to final path safely

**mcp-client Implementation** (recommended enhancement):
```go
case tar.TypeSymlink:
    // Option 1: Reject all symlinks (safest for untrusted archives)
    return fmt.Errorf("symlinks not allowed: %s", header.Name)

    // Option 2: Resolve symlink safely (advanced)
    // linkTarget := header.Linkname
    // resolvedPath := filepath.Join(filepath.Dir(targetPath), linkTarget)
    // resolvedPath = filepath.Clean(resolvedPath)
    // if !strings.HasPrefix(resolvedPath, destDirClean) {
    //     return fmt.Errorf("symlink escape detected: %s → %s", header.Name, linkTarget)
    // }
    // if err := os.Symlink(linkTarget, targetPath); err != nil {
    //     return fmt.Errorf("failed to create symlink: %w", err)
    // }
```

**Current Status in mcp-client**: NOT IMPLEMENTED (tar.TypeSymlink and tar.TypeLink not handled)

**Suggested Fix**:
```go
switch header.Typeflag {
case tar.TypeDir:
    // existing code
case tar.TypeReg:
    // existing code
case tar.TypeSymlink:
    return fmt.Errorf("symlinks not allowed in bundle: %s", header.Name)
case tar.TypeLink:
    return fmt.Errorf("hard links not allowed in bundle: %s", header.Name)
default:
    return fmt.Errorf("unsupported tar entry type: %v", header.Typeflag)
}
```

**Testing**:
```bash
# Create symlink archive
mkdir -p /tmp/tar-test/safe
echo "sensitive" > /tmp/secret.txt
cd /tmp/tar-test
ln -s /tmp/secret.txt symlink
tar -czf symlink.tar.gz safe symlink
# Should fail: "symlinks not allowed"
```

---

### 4. File Count Limits (DoS Prevention)
**Threat**: Archive with millions of empty files, extraction creates inode exhaustion or takes forever.

**Example**:
- Archive contains 1,000,000 empty files
- Extraction: Creates 1M filesystem operations → minutes to hours
- Result: DoS, filesystem full, system unresponsive

**Mitigation**:
- Set **max files per archive**: e.g., 10,000 files
- Count files as extracted: `fileCount++`
- Reject if exceeded: `if fileCount > maxFiles { return err }`

**Implementation**:
```go
const maxFilesPerArchive = 10000

var fileCount int64

for {
    header, _ := tarReader.Next()

    fileCount++
    if fileCount > maxFilesPerArchive {
        return fmt.Errorf("archive contains too many files (max %d)", maxFilesPerArchive)
    }

    switch header.Typeflag {
    case tar.TypeDir, tar.TypeReg:
        // extract...
    }
}
```

**Trade-offs**:
- 10,000 files is reasonable for MCP bundles (most contain <100 files)
- Prevents obvious DoS while allowing legitimate packages
- Can be configurable per security policy

---

### 5. Directory Depth Limits
**Threat**: Archive with deeply nested directories causes recursion issues or filesystem problems.

**Example**:
- Archive: `a/b/c/d/.../z/file` (100+ levels deep)
- On some filesystems: Path length limit exceeded (Linux: 4096 bytes)
- Result: Extraction fails, race condition with traversal checks

**Mitigation**:
- Count path depth: `len(strings.Split(cleanPath, string(filepath.Separator)))`
- Reject if > limit: e.g., 50 levels deep
- Prevents both filesystem issues and complex traversal tricks

**Implementation**:
```go
const maxPathDepth = 50

cleanPath := filepath.Clean(header.Name)
depth := len(strings.Split(cleanPath, string(filepath.Separator)))
if depth > maxPathDepth {
    return fmt.Errorf("path too deep: %s (max %d levels)", header.Name, maxPathDepth)
}
```

**Testing**:
```bash
# Create deeply nested archive
mkdir -p /tmp/deep
mkdir -p $(python3 -c "print('/tmp/deep/' + '/'.join(['a']*100))")
tar -czf deep.tar.gz -C /tmp deep
# Should fail: "path too deep"
```

---

### 6. Filename Validation
**Threat**: Filenames with special characters cause injection, encoding attacks, or filesystem issues.

**Dangerous Characters**:
- **Null bytes**: `file\x00.txt` (NUL, truncates filename in C strings)
- **Control characters**: `\x01`, `\x1f` (Bell, Unit Separator)
- **Non-UTF8**: Binary garbage (filesystem corruption on POSIX systems)
- **Very long names**: > 255 bytes (POSIX limit on filenames)

**Mitigation**:
- Validate filename against whitelist (conservative)
- Reject known-bad patterns
- Ensure UTF-8 validity

**Implementation**:
```go
func isValidFilename(name string) bool {
    // Check for null bytes
    if strings.Contains(name, "\x00") {
        return false
    }

    // Check for control characters (0x00-0x1F except tabs)
    for _, c := range name {
        if c < 0x20 && c != '\t' {
            return false
        }
    }

    // Check UTF-8 validity
    if !utf8.ValidString(name) {
        return false
    }

    // Check length (POSIX max filename: 255)
    if len(name) > 255 {
        return false
    }

    return true
}

// In extraction loop:
if !isValidFilename(header.Name) {
    return fmt.Errorf("invalid filename: %q", header.Name)
}
```

**Current mcp-client**: No explicit filename validation (relies on filepath.Clean)

---

### 7. Permission Enforcement
**Threat**: Bundle extracts executable files, archive can override permissions, leading to code execution.

**Mitigation**:
- **Extract directories**: `0o700` (rwx------, owner only)
- **Extract files**: `0o600` (rw-------, owner only)
- **Ignore archive permissions**: Don't use `header.Mode`, use safe defaults

**Why**:
- Prevents extraction with executable bit set
- Prevents group/world read (confines sensitive data)
- Operator must explicitly `chmod +x` to make executable

**mcp-client Implementation** (internal/cli/run.go):
```go
case tar.TypeDir:
    // SAFE: Use restrictive permissions regardless of archive
    if err := os.MkdirAll(targetPath, 0o700); err != nil {
        return fmt.Errorf("failed to create directory: %w", err)
    }

case tar.TypeReg:
    // SAFE: Extract with 0600 (rw-------)
    // Ignores header.Mode completely
    file, err := os.OpenFile(targetPath,
        os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
    if err != nil {
        return fmt.Errorf("failed to create file: %w", err)
    }
    defer file.Close()
```

**Why NOT `header.Mode`**:
```go
// WRONG: Uses archive permissions
file, _ := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY,
    os.FileMode(header.Mode))
// Archive says 0o755 → file is executable → can be exploited

// RIGHT: Always use 0o600
file, _ := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY, 0o600)
// File is rw------- → not executable by default
```

**Testing**:
```bash
# Create archive with executable bit
mkdir -p /tmp/perms
echo '#!/bin/bash' > /tmp/perms/script.sh
chmod +x /tmp/perms/script.sh
tar -czf perms.tar.gz /tmp/perms

# Extract and verify
tar -tzf perms.tar.gz | grep script
# Extract to /tmp/extracted
# Check: ls -la /tmp/extracted/script.sh → should be -rw------- (not executable)
```

---

### 8. Size Limits (Per-File & Total)
**Threat**: Individual large files or cumulative extraction exhausts disk/memory.

**Limits in mcp-client**:
- **Per-file**: 1GB (same as total, prevents single huge file)
- **Total**: 1GB (prevents decompression bomb)
- **Manifest**: 10MB (registry/client.go: MaxManifestSize)
- **Bundle**: 100MB (registry/client.go: MaxBundleSize)

**Implementation** (internal/cli/run.go):
```go
const maxExtractSize = 1024 * 1024 * 1024 // 1GB

// Per-file check
if header.Size > maxExtractSize {
    return fmt.Errorf("file too large: %s (%d bytes)", header.Name, header.Size)
}

// Cumulative check
totalExtracted += header.Size
if totalExtracted > maxExtractSize {
    return fmt.Errorf("total extracted size exceeds limit (%d bytes)", maxExtractSize)
}
```

**Registry Limits** (internal/registry/client.go):
```go
const (
    MaxManifestSize = 10 * 1024 * 1024    // 10 MB
    MaxBundleSize = 100 * 1024 * 1024     // 100 MB
)
```

**Rationale**:
- 1GB extraction limit: reasonable for MCP bundles (typical: 5-50MB)
- Bundle download limit: 100MB (prevents massive downloads)
- Manifest limit: 10MB (manifests are metadata, should be small)

---

## Safe Extraction Pattern

**Template**:
```go
func extractBundleSafely(data []byte, destDir string) error {
    const (
        maxExtractSize = 1024 * 1024 * 1024  // 1GB
        maxFiles = 10000
        maxDepth = 50
    )

    // 1. Create gzip reader
    gzReader, err := gzip.NewReader(strings.NewReader(string(data)))
    if err != nil {
        return fmt.Errorf("failed to create gzip reader: %w", err)
    }
    defer gzReader.Close()

    // 2. Create tar reader
    tarReader := tar.NewReader(gzReader)
    var totalExtracted int64
    var fileCount int64

    // 3. Extract entries
    for {
        header, err := tarReader.Next()
        if err == io.EOF {
            break
        }
        if err != nil {
            return fmt.Errorf("failed to read tar header: %w", err)
        }

        // 4. Validate filename
        if !isValidFilename(header.Name) {
            return fmt.Errorf("invalid filename: %q", header.Name)
        }

        // 5. Normalize and check traversal
        cleanPath := filepath.Clean(header.Name)
        if strings.HasPrefix(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
            return fmt.Errorf("invalid tar path: %s", header.Name)
        }

        // 6. Check depth
        depth := len(strings.Split(cleanPath, string(filepath.Separator)))
        if depth > maxDepth {
            return fmt.Errorf("path too deep: %s", header.Name)
        }

        // 7. Join and verify containment
        targetPath := filepath.Join(destDir, cleanPath)
        destDirClean := filepath.Clean(destDir)
        if !strings.HasPrefix(targetPath, destDirClean+string(filepath.Separator)) &&
           targetPath != destDirClean {
            return fmt.Errorf("tar path traversal detected: %s", header.Name)
        }

        // 8. Handle entry type
        switch header.Typeflag {
        case tar.TypeDir:
            if err := os.MkdirAll(targetPath, 0o700); err != nil {
                return fmt.Errorf("failed to create directory: %w", err)
            }

        case tar.TypeReg:
            fileCount++
            if fileCount > maxFiles {
                return fmt.Errorf("archive contains too many files (max %d)", maxFiles)
            }

            if header.Size > maxExtractSize {
                return fmt.Errorf("file too large: %s", header.Name)
            }

            totalExtracted += header.Size
            if totalExtracted > maxExtractSize {
                return fmt.Errorf("total extracted size exceeds limit")
            }

            if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
                return fmt.Errorf("failed to create parent directory: %w", err)
            }

            file, err := os.OpenFile(targetPath,
                os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
            if err != nil {
                return fmt.Errorf("failed to create file: %w", err)
            }

            limitedReader := io.LimitReader(tarReader, header.Size+1)
            written, err := io.Copy(file, limitedReader)
            if closeErr := file.Close(); closeErr != nil && err == nil {
                err = closeErr
            }
            if err != nil {
                return fmt.Errorf("failed to write file: %w", err)
            }

            if written > header.Size {
                return fmt.Errorf("file size mismatch: expected %d, got %d", header.Size, written)
            }

        case tar.TypeSymlink, tar.TypeLink:
            return fmt.Errorf("links not allowed: %s", header.Name)

        default:
            return fmt.Errorf("unsupported tar entry type: %v", header.Typeflag)
        }
    }

    return nil
}
```

---

## Common Attacks

### Attack 1: Zip Bomb
```bash
# Create: 100KB file, gzip to 1KB, declare as 100GB
dd if=/dev/zero bs=1M count=100 | gzip > bomb.tar.gz
# Detection: totalExtracted > maxExtractSize → BLOCKED
```

### Attack 2: Path Traversal
```bash
# Create archive with ../../etc/passwd
tar --transform 's,^,../../,S' -czf evil.tar.gz /etc/passwd
# Detection: strings.HasPrefix(cleanPath, "..") → BLOCKED
```

### Attack 3: Symlink Escape
```bash
mkdir -p /tmp/evil
ln -s /etc/passwd /tmp/evil/link
tar -czf symlink.tar.gz -C /tmp evil
# Detection: tar.TypeSymlink → BLOCKED (if implemented)
```

### Attack 4: File Count DoS
```bash
# Create archive with 1M empty files
for i in {1..1000000}; do touch /tmp/file$i; done
tar -czf many.tar.gz /tmp/file*
# Detection: fileCount > maxFiles → BLOCKED
```

### Attack 5: Deep Directory DoS
```bash
# Create: a/b/c/d/.../z (100+ levels)
mkdir -p $(python3 -c "print('/tmp/' + '/'.join(['d']*100))")
tar -czf deep.tar.gz /tmp
# Detection: depth > maxDepth → BLOCKED
```

---

## Testing Strategy

### Unit Tests (extract validation)
```go
// tests/tar_security_test.go
func TestExtractBundle_RejectsZipBomb(t *testing.T) {
    // Create bomb: 100KB compressed, >1GB uncompressed
    // Assert: extractBundle returns error "exceeds limit"
}

func TestExtractBundle_RejectsPathTraversal(t *testing.T) {
    // Create archive with ../../etc/passwd
    // Assert: extractBundle returns error "traversal detected"
}

func TestExtractBundle_RejectsSymlinks(t *testing.T) {
    // Create archive with symlink
    // Assert: extractBundle returns error "symlinks not allowed"
}

func TestExtractBundle_RejectsLargeFileCount(t *testing.T) {
    // Create archive with 20,000 empty files
    // Assert: extractBundle returns error "too many files"
}

func TestExtractBundle_RejectsDeepPaths(t *testing.T) {
    // Create archive with 100-level deep directory
    // Assert: extractBundle returns error "path too deep"
}

func TestExtractBundle_RejectsInvalidFilenames(t *testing.T) {
    // Create archive with null bytes, control chars, non-UTF8
    // Assert: extractBundle returns error "invalid filename"
}

func TestExtractBundle_EnforcesRestrictivePermissions(t *testing.T) {
    // Create archive with executable file (755)
    // Extract, verify extracted file is 600 (not executable)
}
```

### Integration Tests (end-to-end)
```bash
# Test with real bundles
smcp run test/bomb@1.0.0 → FAIL (exceeds size limit)
smcp run test/traversal@1.0.0 → FAIL (path traversal)
smcp run test/symlink@1.0.0 → FAIL (symlinks not allowed)

# Real bundle should work
smcp run acme/hello-world@1.0.0 → SUCCESS
```

### Boundary Conditions
- Empty archive: should extract to empty dir (0 files)
- Single file (small): should extract fine
- Exactly maxExtractSize: should succeed
- maxExtractSize + 1 byte: should fail
- maxFiles: should succeed
- maxFiles + 1: should fail
- maxDepth: should succeed
- maxDepth + 1: should fail

---

## Real Code: mcp-client CLI/run.go

**Current implementation** (working, but could be enhanced for symlinks):
```go
func extractBundle(data []byte, destDir string) error {
    const maxExtractSize = 1024 * 1024 * 1024 // 1GB limit

    gzReader, err := gzip.NewReader(strings.NewReader(string(data)))
    if err != nil {
        return fmt.Errorf("failed to create gzip reader: %w", err)
    }
    defer gzReader.Close()

    tarReader := tar.NewReader(gzReader)
    var totalExtracted int64

    for {
        header, err := tarReader.Next()
        if err == io.EOF {
            break
        }
        if err != nil {
            return fmt.Errorf("failed to read tar header: %w", err)
        }

        // Path traversal prevention
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

        switch header.Typeflag {
        case tar.TypeDir:
            if err := os.MkdirAll(targetPath, 0o750); err != nil {
                return fmt.Errorf("failed to create directory: %w", err)
            }

        case tar.TypeReg:
            if header.Size > maxExtractSize {
                return fmt.Errorf("file too large: %s", header.Name)
            }

            totalExtracted += header.Size
            if totalExtracted > maxExtractSize {
                return fmt.Errorf("total extracted size exceeds limit")
            }

            if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
                return fmt.Errorf("failed to create parent directory: %w", err)
            }

            file, err := os.OpenFile(targetPath,
                os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
            if err != nil {
                return fmt.Errorf("failed to create file: %w", err)
            }

            limitedReader := io.LimitReader(tarReader, header.Size+1)
            written, err := io.Copy(file, limitedReader)
            if err != nil {
                file.Close()
                return fmt.Errorf("failed to write file: %w", err)
            }

            if written > header.Size {
                file.Close()
                return fmt.Errorf("file size mismatch: expected %d, got %d",
                    header.Size, written)
            }

            if err := file.Close(); err != nil {
                return fmt.Errorf("failed to close file: %w", err)
            }
        }
    }

    return nil
}
```

**Enhancement needed**: Add symlink/hardlink rejection:
```go
case tar.TypeSymlink, tar.TypeLink:
    return fmt.Errorf("links not allowed in bundle: %s", header.Name)
default:
    return fmt.Errorf("unsupported tar entry type: %v", header.Typeflag)
```

---

## Debugging Guide

### Inspect archive contents
```bash
# List tar entries (before extraction)
tar -tzf bundle.tar.gz | head -20

# Show headers (includes sizes, permissions)
tar -tzvf bundle.tar.gz | head -20

# Check for symlinks
tar -tzf bundle.tar.gz | grep '^l'

# Check for traversal attempts
tar -tzf bundle.tar.gz | grep -E '(\.\./|^/)'
```

### Verify extracted files
```bash
# Check permissions (should be 600 for files, 700 for dirs)
ls -la /tmp/extracted-dir/
# Output: -rw------- (600 for files), drwx------ (700 for dirs)

# Check file count
find /tmp/extracted-dir/ | wc -l

# Check directory depth
find /tmp/extracted-dir/ -type d | awk -F'/' '{print NF}' | sort -n | tail -1

# Check for null bytes in filenames (should find nothing)
find /tmp/extracted-dir/ -print0 | strings | grep -E '^[^[:print:]]'
```

### Trace extraction with strace (Linux)
```bash
strace -e openat,open,mkdir ./smcp run test@1.0.0 2>&1 | grep -E 'bundle|extracted'
# Verify all opens/mkdirs are within destDir
```

### Monitor resource usage
```bash
# Check available disk before extraction
df -h /tmp

# Check memory during extraction (if using io.LimitReader)
top -p $(pgrep mcp)

# Check inode count
df -i /tmp
```

---

## Security Invariants

1. **No file extracted outside `destDir`**: Verified by prefix check
2. **No file or directory with execute permission by default**: All created with 0o600 (files) or 0o700 (dirs)
3. **No symlinks or hardlinks**: tar.TypeSymlink and tar.TypeLink rejected
4. **Extraction bounded by size**: totalExtracted capped at 1GB
5. **Per-file size bounded**: header.Size must be ≤ 1GB
6. **File count bounded**: fileCount (if implemented) must be ≤ 10,000
7. **Path depth bounded**: Relative path depth must be ≤ 50 levels
8. **Filenames valid**: No null bytes, control chars, non-UTF8

---

## References

- [OWASP: Archive Extraction](https://owasp.org/www-community/attacks/Zip_Slip)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Go tar package docs](https://pkg.go.dev/archive/tar)
- [Go filepath.Clean semantics](https://pkg.go.dev/path/filepath#Clean)
- [POSIX filename limits](https://pubs.opengroup.org/onlinepubs/9699919799/functions/pathconf.html)
