# Content Cache Skill

Expert knowledge for implementing content-addressable cache for manifests and bundles.

## Content-Addressable Design

### Core Principle

Files are stored by their content hash (digest), not by filename. This ensures:

1. **Immutability**: Same content always has same digest
2. **Deduplication**: Identical artifacts stored once
3. **Integrity**: Hash verification prevents corruption
4. **Security**: Digest pinning prevents substitution attacks

### Directory Structure

```
~/.smcp/cache/
├── manifests/
│   ├── sha256:abc123.../
│   │   ├── manifest.json
│   │   └── metadata.json
│   ├── sha256:def456.../
│   │   ├── manifest.json
│   │   └── metadata.json
│   └── ...
├── bundles/
│   ├── sha256:abc123.../
│   │   ├── bundle.tar.gz
│   │   └── metadata.json
│   ├── sha256:def456.../
│   │   ├── bundle.tar.gz
│   │   └── metadata.json
│   └── ...
└── locks/
    ├── sha256:abc123...
    ├── sha256:def456...
    └── ...
```

### Metadata File Structure

**~/.smcp/cache/manifests/sha256:abc123.../metadata.json:**
```json
{
  "digest": "sha256:abc123...",
  "size_bytes": 4096,
  "created_at": "2026-01-15T10:30:00Z",
  "last_accessed": "2026-01-18T15:45:00Z",
  "package": "acme/hello-world",
  "version": "1.0.0",
  "algorithm": "sha256"
}
```

**~/.smcp/cache/bundles/sha256:def456.../metadata.json:**
```json
{
  "digest": "sha256:def456...",
  "size_bytes": 12345678,
  "created_at": "2026-01-15T10:30:00Z",
  "last_accessed": "2026-01-18T15:45:00Z",
  "package": "acme/hello-world",
  "version": "1.0.0",
  "algorithm": "sha256",
  "extracted": true,
  "extracted_path": "/tmp/mcp-acme-hello-xyz"
}
```

---

## Store Interface

### Definition

```go
type Store interface {
    // Put writes artifact to cache, atomically
    Put(ctx context.Context, artifactType string, digest string, data []byte, metadata *Metadata) error

    // Get retrieves artifact from cache
    Get(ctx context.Context, artifactType string, digest string) ([]byte, error)

    // Exists checks if artifact is in cache
    Exists(ctx context.Context, artifactType string, digest string) bool

    // Delete removes artifact from cache
    Delete(ctx context.Context, artifactType string, digest string) error

    // List returns all cached artifacts of a type
    List(ctx context.Context, artifactType string) ([]CachedArtifact, error)

    // Size returns total cache size in bytes
    Size(ctx context.Context) (int64, error)

    // GetMetadata returns metadata for cached artifact
    GetMetadata(ctx context.Context, artifactType string, digest string) (*Metadata, error)

    // UpdateLastAccessed updates last access timestamp
    UpdateLastAccessed(ctx context.Context, artifactType string, digest string) error

    // Clean removes artifacts older than ttl
    Clean(ctx context.Context, ttl time.Duration) error
}
```

### Implementation

```go
type FileSystemStore struct {
    cacheDir string
    mu       *sync.RWMutex  // Global read-write lock
    lockers  map[string]*sync.Mutex  // Per-digest locks
}

func NewFileSystemStore(cacheDir string) (*FileSystemStore, error) {
    // Create cache directory structure
    dirs := []string{
        filepath.Join(cacheDir, "manifests"),
        filepath.Join(cacheDir, "bundles"),
        filepath.Join(cacheDir, "locks"),
    }

    for _, dir := range dirs {
        if err := os.MkdirAll(dir, 0700); err != nil {
            return nil, fmt.Errorf("failed to create cache dir: %w", err)
        }
    }

    return &FileSystemStore{
        cacheDir: cacheDir,
        mu:       &sync.RWMutex{},
        lockers:  make(map[string]*sync.Mutex),
    }, nil
}

func (s *FileSystemStore) artifactPath(artifactType, digest string) string {
    return filepath.Join(s.cacheDir, artifactType, digest)
}

func (s *FileSystemStore) metadataPath(artifactType, digest string) string {
    path := s.artifactPath(artifactType, digest)
    return filepath.Join(path, "metadata.json")
}

func (s *FileSystemStore) contentPath(artifactType, digest string) string {
    path := s.artifactPath(artifactType, digest)
    filename := "manifest.json"
    if artifactType == "bundles" {
        filename = "bundle.tar.gz"
    }
    return filepath.Join(path, filename)
}

func (s *FileSystemStore) getLock(digest string) *sync.Mutex {
    s.mu.Lock()
    defer s.mu.Unlock()

    if lock, ok := s.lockers[digest]; ok {
        return lock
    }

    lock := &sync.Mutex{}
    s.lockers[digest] = lock
    return lock
}
```

---

## Atomic Write Pattern

### Critical Rule: Never Write Directly to Final Location

Always use atomic write pattern to prevent corruption:

1. Write to temporary file in cache directory
2. Validate content (hash, size, permissions)
3. Atomically rename to final location
4. Clean up on failure

### Implementation

```go
func (s *FileSystemStore) Put(ctx context.Context, artifactType, digest string, data []byte, metadata *Metadata) error {
    // Get lock for this digest (prevent concurrent writes)
    lock := s.getLock(digest)
    lock.Lock()
    defer lock.Unlock()

    // Check if already cached
    if s.Exists(ctx, artifactType, digest) {
        return nil  // Already exists, no need to re-write
    }

    // Create artifact directory
    artifactPath := s.artifactPath(artifactType, digest)
    if err := os.MkdirAll(artifactPath, 0700); err != nil {
        return fmt.Errorf("failed to create artifact dir: %w", err)
    }

    // Write to temporary file
    tempFile := artifactPath + ".tmp"
    tmpf, err := os.Create(tempFile)
    if err != nil {
        return fmt.Errorf("failed to create temp file: %w", err)
    }
    defer os.Remove(tempFile)  // Clean up if we fail

    // Write content
    if _, err := tmpf.Write(data); err != nil {
        tmpf.Close()
        return fmt.Errorf("failed to write artifact: %w", err)
    }
    tmpf.Close()

    // Validate written content
    written, err := os.ReadFile(tempFile)
    if err != nil {
        return fmt.Errorf("failed to verify written content: %w", err)
    }

    // Verify digest
    if err := ValidateDigest(written, digest); err != nil {
        return fmt.Errorf("digest validation failed: %w", err)
    }

    // Verify size
    if metadata.SizeBytes > 0 && int64(len(written)) != metadata.SizeBytes {
        return fmt.Errorf("size mismatch: expected %d, got %d", metadata.SizeBytes, len(written))
    }

    // Atomic rename
    contentPath := s.contentPath(artifactType, digest)
    if err := os.Rename(tempFile, contentPath); err != nil {
        return fmt.Errorf("failed to move artifact to cache: %w", err)
    }

    // Write metadata
    metadata.CreatedAt = time.Now()
    metadata.LastAccessed = time.Now()
    metadataPath := s.metadataPath(artifactType, digest)

    metaData, err := json.MarshalIndent(metadata, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal metadata: %w", err)
    }

    if err := os.WriteFile(metadataPath, metaData, 0600); err != nil {
        return fmt.Errorf("failed to write metadata: %w", err)
    }

    // Set permissions
    if err := os.Chmod(contentPath, 0600); err != nil {
        return fmt.Errorf("failed to set permissions: %w", err)
    }

    return nil
}

func ValidateDigest(data []byte, digest string) error {
    parts := strings.Split(digest, ":")
    if len(parts) != 2 {
        return fmt.Errorf("invalid digest format: %s", digest)
    }

    algo, expectedHash := parts[0], strings.ToLower(parts[1])

    var h hash.Hash
    switch algo {
    case "sha256":
        h = sha256.New()
    case "sha512":
        h = sha512.New()
    default:
        return fmt.Errorf("unsupported digest algorithm: %s", algo)
    }

    h.Write(data)
    actualHash := hex.EncodeToString(h.Sum(nil))

    if actualHash != expectedHash {
        return fmt.Errorf("digest mismatch: expected %s:%s, got %s:%s", algo, expectedHash, algo, actualHash)
    }

    return nil
}
```

---

## Get Operation

### Implementation

```go
func (s *FileSystemStore) Get(ctx context.Context, artifactType, digest string) ([]byte, error) {
    // Get lock for reading
    lock := s.getLock(digest)
    lock.Lock()
    defer lock.Unlock()

    // Check context cancellation
    select {
    case <-ctx.Done():
        return nil, ctx.Err()
    default:
    }

    // Check if exists
    if !s.Exists(ctx, artifactType, digest) {
        return nil, fmt.Errorf("artifact not in cache: %s/%s", artifactType, digest)
    }

    // Read content
    contentPath := s.contentPath(artifactType, digest)
    data, err := os.ReadFile(contentPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read artifact: %w", err)
    }

    // Update last accessed timestamp (async to avoid blocking)
    go func() {
        _ = s.UpdateLastAccessed(context.Background(), artifactType, digest)
    }()

    return data, nil
}

func (s *FileSystemStore) GetMetadata(ctx context.Context, artifactType, digest string) (*Metadata, error) {
    lock := s.getLock(digest)
    lock.Lock()
    defer lock.Unlock()

    metadataPath := s.metadataPath(artifactType, digest)

    data, err := os.ReadFile(metadataPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read metadata: %w", err)
    }

    var metadata Metadata
    if err := json.Unmarshal(data, &metadata); err != nil {
        return nil, fmt.Errorf("failed to parse metadata: %w", err)
    }

    return &metadata, nil
}
```

---

## Exists Check

### Efficient Implementation

```go
func (s *FileSystemStore) Exists(ctx context.Context, artifactType, digest string) bool {
    lock := s.getLock(digest)
    lock.Lock()
    defer lock.Unlock()

    contentPath := s.contentPath(artifactType, digest)
    _, err := os.Stat(contentPath)
    return err == nil
}
```

### Batch Exists Check

```go
func (s *FileSystemStore) ExistsBatch(ctx context.Context, artifactType string, digests []string) map[string]bool {
    results := make(map[string]bool)
    var mu sync.Mutex

    // Use goroutines for parallel checking (max 10 concurrent)
    sem := make(chan struct{}, 10)
    var wg sync.WaitGroup

    for _, digest := range digests {
        wg.Add(1)
        go func(d string) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()

            exists := s.Exists(ctx, artifactType, d)
            mu.Lock()
            results[d] = exists
            mu.Unlock()
        }(digest)
    }

    wg.Wait()
    return results
}
```

---

## Delete Operation

### Implementation

```go
func (s *FileSystemStore) Delete(ctx context.Context, artifactType, digest string) error {
    lock := s.getLock(digest)
    lock.Lock()
    defer lock.Unlock()

    artifactPath := s.artifactPath(artifactType, digest)

    // Check if exists
    if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
        return nil  // Already deleted
    }

    // Remove entire directory
    if err := os.RemoveAll(artifactPath); err != nil {
        return fmt.Errorf("failed to delete artifact: %w", err)
    }

    return nil
}
```

---

## List Operation

### Implementation

```go
type CachedArtifact struct {
    Digest       string    `json:"digest"`
    Type         string    `json:"type"`
    SizeBytes    int64     `json:"size_bytes"`
    CreatedAt    time.Time `json:"created_at"`
    LastAccessed time.Time `json:"last_accessed"`
    Package      string    `json:"package"`
    Version      string    `json:"version"`
}

func (s *FileSystemStore) List(ctx context.Context, artifactType string) ([]CachedArtifact, error) {
    typePath := filepath.Join(s.cacheDir, artifactType)

    entries, err := os.ReadDir(typePath)
    if err != nil {
        return nil, fmt.Errorf("failed to read cache dir: %w", err)
    }

    var artifacts []CachedArtifact

    for _, entry := range entries {
        if !entry.IsDir() {
            continue
        }

        digest := entry.Name()

        metadata, err := s.GetMetadata(ctx, artifactType, digest)
        if err != nil {
            // Skip artifacts with invalid metadata
            continue
        }

        artifacts = append(artifacts, CachedArtifact{
            Digest:       digest,
            Type:         artifactType,
            SizeBytes:    metadata.SizeBytes,
            CreatedAt:    metadata.CreatedAt,
            LastAccessed: metadata.LastAccessed,
            Package:      metadata.Package,
            Version:      metadata.Version,
        })
    }

    // Sort by last accessed (newest first)
    sort.Slice(artifacts, func(i, j int) bool {
        return artifacts[i].LastAccessed.After(artifacts[j].LastAccessed)
    })

    return artifacts, nil
}
```

---

## Size Calculation

### Total Cache Size

```go
func (s *FileSystemStore) Size(ctx context.Context) (int64, error) {
    var totalSize int64

    for _, artifactType := range []string{"manifests", "bundles"} {
        artifacts, err := s.List(ctx, artifactType)
        if err != nil {
            continue  // Skip on error
        }

        for _, artifact := range artifacts {
            totalSize += artifact.SizeBytes
        }
    }

    return totalSize, nil
}

func (s *FileSystemStore) SizeByType(ctx context.Context, artifactType string) (int64, error) {
    var totalSize int64

    artifacts, err := s.List(ctx, artifactType)
    if err != nil {
        return 0, err
    }

    for _, artifact := range artifacts {
        totalSize += artifact.SizeBytes
    }

    return totalSize, nil
}
```

---

## Cache Invalidation Strategies

### Time-Based Eviction (TTL)

```go
func (s *FileSystemStore) Clean(ctx context.Context, ttl time.Duration) error {
    now := time.Now()
    cutoff := now.Add(-ttl)

    for _, artifactType := range []string{"manifests", "bundles"} {
        artifacts, err := s.List(ctx, artifactType)
        if err != nil {
            continue
        }

        for _, artifact := range artifacts {
            // Remove if not accessed recently
            if artifact.LastAccessed.Before(cutoff) {
                if err := s.Delete(ctx, artifactType, artifact.Digest); err != nil {
                    fmt.Printf("[WARN] Failed to delete expired artifact %s: %v\n", artifact.Digest, err)
                }
            }
        }
    }

    return nil
}
```

### LRU Eviction

```go
func (s *FileSystemStore) EvictLRU(ctx context.Context, maxSize int64) error {
    currentSize, _ := s.Size(ctx)

    if currentSize <= maxSize {
        return nil  // Nothing to evict
    }

    // Combine all artifacts and sort by last accessed
    var allArtifacts []CachedArtifact

    for _, artifactType := range []string{"manifests", "bundles"} {
        artifacts, err := s.List(ctx, artifactType)
        if err != nil {
            continue
        }
        allArtifacts = append(allArtifacts, artifacts...)
    }

    // Sort by last accessed (oldest first)
    sort.Slice(allArtifacts, func(i, j int) bool {
        return allArtifacts[i].LastAccessed.Before(allArtifacts[j].LastAccessed)
    })

    // Delete oldest artifacts until under limit
    for _, artifact := range allArtifacts {
        if currentSize <= maxSize {
            break
        }

        if err := s.Delete(ctx, artifact.Type, artifact.Digest); err != nil {
            fmt.Printf("[WARN] Failed to evict artifact %s: %v\n", artifact.Digest, err)
            continue
        }

        currentSize -= artifact.SizeBytes
    }

    return nil
}
```

### Size-Based Eviction

```go
func (s *FileSystemStore) EnforceMaxSize(ctx context.Context, maxSize int64) error {
    currentSize, _ := s.Size(ctx)

    if currentSize <= maxSize {
        return nil
    }

    needToFree := currentSize - maxSize
    fmt.Printf("[DEBUG] Cache size %d exceeds limit %d, need to free %d bytes\n",
        currentSize, maxSize, needToFree)

    return s.EvictLRU(ctx, maxSize)
}
```

---

## Thread-Safety and Concurrency

### RWMutex Pattern

```go
type SafeStore struct {
    store *FileSystemStore
    mu    *sync.RWMutex
}

func (ss *SafeStore) Get(ctx context.Context, artifactType, digest string) ([]byte, error) {
    ss.mu.RLock()  // Multiple readers can proceed simultaneously
    defer ss.mu.RUnlock()

    return ss.store.Get(ctx, artifactType, digest)
}

func (ss *SafeStore) Put(ctx context.Context, artifactType, digest string, data []byte, metadata *Metadata) error {
    ss.mu.Lock()  // Exclusive writer lock
    defer ss.mu.Unlock()

    return ss.store.Put(ctx, artifactType, digest, data, metadata)
}

func (ss *SafeStore) Clean(ctx context.Context, ttl time.Duration) error {
    ss.mu.Lock()  // Exclusive writer lock
    defer ss.mu.Unlock()

    return ss.store.Clean(ctx, ttl)
}
```

---

## File Locking

### Prevent Concurrent Corruption

```go
func (s *FileSystemStore) WithLock(digest string, fn func() error) error {
    lock := s.getLock(digest)
    lock.Lock()
    defer lock.Unlock()

    return fn()
}

// Usage:
err := store.WithLock(digest, func() error {
    return store.Put(ctx, "manifests", digest, data, metadata)
})
```

### Filesystem-Level Locking (Optional)

```go
func (s *FileSystemStore) AcquireFileLock(digest string) (func(), error) {
    lockFile := filepath.Join(s.cacheDir, "locks", digest)

    f, err := os.Create(lockFile)
    if err != nil {
        return nil, fmt.Errorf("failed to create lock file: %w", err)
    }

    // Try to acquire exclusive lock (platform-specific)
    if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
        f.Close()
        return nil, fmt.Errorf("failed to acquire file lock: %w", err)
    }

    // Return unlock function
    unlock := func() {
        syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
        f.Close()
        os.Remove(lockFile)
    }

    return unlock, nil
}
```

---

## CopyToPath Operation

### Extract/Link to Working Directory

```go
func (s *FileSystemStore) CopyToPath(ctx context.Context, artifactType, digest, destPath string) error {
    lock := s.getLock(digest)
    lock.Lock()
    defer lock.Unlock()

    contentPath := s.contentPath(artifactType, digest)

    // Verify artifact exists
    if !s.Exists(ctx, artifactType, digest) {
        return fmt.Errorf("artifact not in cache: %s/%s", artifactType, digest)
    }

    // For bundles: extract tar.gz
    if artifactType == "bundles" {
        return s.extractBundle(contentPath, destPath)
    }

    // For manifests: copy JSON
    data, err := os.ReadFile(contentPath)
    if err != nil {
        return err
    }

    return os.WriteFile(destPath, data, 0600)
}

func (s *FileSystemStore) extractBundle(bundlePath, destPath string) error {
    f, err := os.Open(bundlePath)
    if err != nil {
        return err
    }
    defer f.Close()

    gr, err := gzip.NewReader(f)
    if err != nil {
        return err
    }
    defer gr.Close()

    tr := tar.NewReader(gr)

    // Create destination directory
    if err := os.MkdirAll(destPath, 0700); err != nil {
        return err
    }

    for {
        hdr, err := tr.Next()
        if err == io.EOF {
            break
        }
        if err != nil {
            return err
        }

        // Skip absolute paths
        if filepath.IsAbs(hdr.Name) {
            continue
        }

        filePath := filepath.Join(destPath, hdr.Name)

        // Check for path traversal
        if !strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(destPath)) {
            continue
        }

        switch hdr.Typeflag {
        case tar.TypeDir:
            os.MkdirAll(filePath, 0700)

        case tar.TypeReg:
            f, _ := os.Create(filePath)
            if _, err := io.Copy(f, tr); err != nil {
                f.Close()
                return err
            }
            f.Close()

            // Set executable bit if needed
            if hdr.Mode&0111 != 0 {
                os.Chmod(filePath, 0755)
            }
        }
    }

    return nil
}
```

---

## Common Issues and Solutions

### Issue 1: Race Condition on Put

**Problem:** Two concurrent writes to same digest cause corruption.

**Solution:** Use per-digest locks + atomic write.

```go
func (s *FileSystemStore) Put(...) error {
    lock := s.getLock(digest)  // Get lock for this digest
    lock.Lock()
    defer lock.Unlock()

    // Atomic write (temp → rename)
}
```

---

### Issue 2: Partial Write on Disk Full

**Problem:** Write succeeds but disk is full, partial file remains.

**Solution:** Validate size before accepting, cleanup temp files.

```go
// Check disk space before writing
var stat syscall.Statfs_t
syscall.Statfs(s.cacheDir, &stat)
availableBytes := stat.Bavail * uint64(stat.Bsize)

if int64(len(data)) > int64(availableBytes) {
    return fmt.Errorf("insufficient disk space")
}

// Write to temp, validate, rename
```

---

### Issue 3: Corrupted Metadata File

**Problem:** Crash during metadata write leaves corrupt file.

**Solution:** Write metadata atomically too.

```go
metadataPath := s.metadataPath(artifactType, digest)
tempMetadata := metadataPath + ".tmp"

// Write to temp
_ = os.WriteFile(tempMetadata, metaData, 0600)

// Atomic rename
_ = os.Rename(tempMetadata, metadataPath)
```

---

### Issue 4: Cache Grows Unbounded

**Problem:** No eviction policy causes cache to fill disk.

**Solution:** Implement size limit + LRU eviction.

```go
const maxCacheSize = 10 * 1024 * 1024 * 1024  // 10 GB

err := store.Put(ctx, "bundles", digest, data, metadata)
if err == nil {
    // Trigger eviction if needed
    _ = store.EnforceMaxSize(ctx, maxCacheSize)
}
```

---

### Issue 5: Lost Last Access Metadata

**Problem:** Updates to last_accessed don't persist.

**Solution:** Async update, or write to separate journal.

```go
func (s *FileSystemStore) UpdateLastAccessed(ctx context.Context, artifactType, digest string) error {
    lock := s.getLock(digest)
    lock.Lock()
    defer lock.Unlock()

    metadata, err := s.GetMetadata(ctx, artifactType, digest)
    if err != nil {
        return err
    }

    metadata.LastAccessed = time.Now()

    // Write atomically
    metadataPath := s.metadataPath(artifactType, digest)
    tempPath := metadataPath + ".tmp"

    data, _ := json.Marshal(metadata)
    _ = os.WriteFile(tempPath, data, 0600)
    _ = os.Rename(tempPath, metadataPath)

    return nil
}
```

---

## Testing Patterns

### Unit Test: Atomic Write

```go
func TestAtomicWrite(t *testing.T) {
    store, tmpDir := setupTestStore(t)
    defer os.RemoveAll(tmpDir)

    digest := "sha256:abc123..."
    data := []byte("test data")
    metadata := &Metadata{
        Digest:    digest,
        SizeBytes: int64(len(data)),
        Package:   "test/pkg",
        Version:   "1.0.0",
    }

    // Put artifact
    if err := store.Put(context.Background(), "manifests", digest, data, metadata); err != nil {
        t.Fatal(err)
    }

    // Verify it's in cache
    if !store.Exists(context.Background(), "manifests", digest) {
        t.Fatal("artifact not in cache after put")
    }

    // Verify content
    retrieved, err := store.Get(context.Background(), "manifests", digest)
    if err != nil {
        t.Fatal(err)
    }

    if !bytes.Equal(retrieved, data) {
        t.Fatal("retrieved data doesn't match")
    }
}
```

### Test: Concurrent Access

```go
func TestConcurrentAccess(t *testing.T) {
    store, tmpDir := setupTestStore(t)
    defer os.RemoveAll(tmpDir)

    const goroutines = 10
    const iterations = 100

    var wg sync.WaitGroup
    errors := make(chan error, goroutines*iterations)

    for i := 0; i < goroutines; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()

            for j := 0; j < iterations; j++ {
                digest := fmt.Sprintf("sha256:digest%d_%d", id, j)
                data := []byte(fmt.Sprintf("data_%d_%d", id, j))
                metadata := &Metadata{
                    Digest:    digest,
                    SizeBytes: int64(len(data)),
                }

                if err := store.Put(context.Background(), "manifests", digest, data, metadata); err != nil {
                    errors <- err
                }

                if _, err := store.Get(context.Background(), "manifests", digest); err != nil {
                    errors <- err
                }
            }
        }(i)
    }

    wg.Wait()
    close(errors)

    if len(errors) > 0 {
        t.Fatalf("concurrent access failed: %v", <-errors)
    }
}
```

### Test: Eviction Policy

```go
func TestLRUEviction(t *testing.T) {
    store, tmpDir := setupTestStore(t)
    defer os.RemoveAll(tmpDir)

    maxSize := int64(10000)  // 10 KB

    // Add 5 artifacts, each 3 KB
    for i := 0; i < 5; i++ {
        digest := fmt.Sprintf("sha256:%064d", i)
        data := make([]byte, 3000)
        metadata := &Metadata{Digest: digest, SizeBytes: 3000}

        _ = store.Put(context.Background(), "manifests", digest, data, metadata)

        // Stagger last accessed times
        time.Sleep(10 * time.Millisecond)
    }

    // Enforce size limit
    _ = store.EnforceMaxSize(context.Background(), maxSize)

    // Verify oldest artifacts were evicted
    size, _ := store.Size(context.Background())
    if size > maxSize {
        t.Errorf("cache size %d exceeds limit %d after eviction", size, maxSize)
    }
}
```

---

## Integration Patterns

### With Registry Client

```go
type CachedRegistryClient struct {
    client *RegistryClient
    cache  *FileSystemStore
}

func (cc *CachedRegistryClient) ResolveAndCache(ctx context.Context, org, name, ref string) (*ResolveResponse, error) {
    resp, err := cc.client.Resolve(ctx, org, name, ref)
    if err != nil {
        return nil, err
    }

    // Pre-cache manifest digest for future lookups
    _ = cc.cache.Put(ctx, "manifests", resp.Resolved.Manifest.Digest, []byte("{}"), &Metadata{
        Digest:    resp.Resolved.Manifest.Digest,
        Package:   fmt.Sprintf("%s/%s", org, name),
        Version:   resp.Resolved.Version,
    })

    return resp, nil
}

func (cc *CachedRegistryClient) DownloadManifest(ctx context.Context, org, digest string) ([]byte, error) {
    // Check cache first
    if data, err := cc.cache.Get(ctx, "manifests", digest); err == nil {
        return data, nil
    }

    // Download from registry
    data, err := cc.client.DownloadManifest(ctx, org, digest)
    if err != nil {
        return nil, err
    }

    // Cache it
    _ = cc.cache.Put(ctx, "manifests", digest, data, &Metadata{
        Digest:    digest,
        SizeBytes: int64(len(data)),
    })

    return data, nil
}
```

---

## Debugging and Inspection

### Inspect Cache Contents

```bash
# List all cached manifests
find ~/.smcp/cache/manifests -name "manifest.json" | wc -l

# List all cached bundles with size
find ~/.smcp/cache/bundles -name "bundle.tar.gz" -exec du -h {} \;

# Check metadata for a digest
cat ~/.smcp/cache/manifests/sha256:abc123.../metadata.json | jq .

# Total cache size
du -sh ~/.smcp/cache/
```

### Debug Commands in Code

```go
func (s *FileSystemStore) DebugInfo(ctx context.Context) {
    manifests, _ := s.List(ctx, "manifests")
    bundles, _ := s.List(ctx, "bundles")
    totalSize, _ := s.Size(ctx)

    fmt.Printf("Cache Debug Info:\n")
    fmt.Printf("  Manifests: %d items\n", len(manifests))
    fmt.Printf("  Bundles: %d items\n", len(bundles))
    fmt.Printf("  Total Size: %d bytes (%.2f GB)\n", totalSize, float64(totalSize)/1024/1024/1024)

    fmt.Printf("\nRecent Artifacts:\n")
    for _, m := range manifests[:min(5, len(manifests))] {
        fmt.Printf("  %s: %s@%s (%d bytes, accessed %v)\n",
            m.Digest[:20], m.Package, m.Version, m.SizeBytes, m.LastAccessed)
    }
}
```

---

## Migration and Upgrade

### Schema Versioning

```go
const cacheSchemaVersion = 1

func (s *FileSystemStore) MigrateIfNeeded() error {
    versionFile := filepath.Join(s.cacheDir, "schema.version")

    // Read current version
    currentVersion := 0
    if data, err := os.ReadFile(versionFile); err == nil {
        fmt.Sscanf(string(data), "%d", &currentVersion)
    }

    // Run migrations
    for v := currentVersion; v < cacheSchemaVersion; v++ {
        switch v {
        case 0:
            // Migrate from v0 to v1
            if err := s.migrateV0ToV1(); err != nil {
                return err
            }
        }
    }

    // Write new version
    return os.WriteFile(versionFile, []byte(fmt.Sprintf("%d", cacheSchemaVersion)), 0600)
}
```
