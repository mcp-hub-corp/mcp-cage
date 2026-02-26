# Go Performance Optimization & Profiling

## Overview

This skill covers comprehensive Go performance optimization techniques, profiling methodologies, and best practices applied to the mcp-client project. Focuses on CPU profiling, memory optimization, benchmark analysis, and production profiling.

**Key Areas:**
- pprof profiling (CPU, memory, goroutines, mutex contention)
- Benchmark writing and interpretation
- Memory allocation optimization
- Goroutine leak detection
- Real-world optimization patterns

---

## 1. Profiling Fundamentals

### 1.1 Types of Profiling

#### CPU Profiling (CPU time)
Samples the call stack at fixed intervals (100Hz by default) to identify hot functions.

**Usage:**
```bash
# Run tests with CPU profile
go test -cpuprofile=cpu.prof -bench=. ./internal/cache

# Analyze with pprof
go tool pprof cpu.prof

# Web UI (requires graphviz)
go tool pprof -http=:8080 cpu.prof

# Flamegraph (requires go-torch or pprof)
go tool pprof -http=:8080 cpu.prof
```

#### Memory Profiling (Heap allocations)
Captures all heap allocations (sampling every 512KB by default).

**Usage:**
```bash
# Run tests with memory profile
go test -memprofile=mem.prof -bench=. ./internal/manifest

# Analyze
go tool pprof mem.prof
```

#### Goroutine Profiling
Captures all goroutine stack traces at moment of request.

**Usage:**
```bash
# Check goroutine profile
go tool pprof http://localhost:6060/debug/pprof/goroutine

# Export to file
go test -run TestRunCommand ./internal/cli -parallel 1 > /tmp/test.log 2>&1
curl http://localhost:6060/debug/pprof/goroutine > goroutine.prof
```

#### Block Profiling (Contention)
Measures time goroutines block on synchronization primitives (mutex, channel).

**Usage:**
```bash
# Enable block profiling in code
runtime.SetBlockProfileRate(1)

# Capture
curl http://localhost:6060/debug/pprof/block > block.prof
go tool pprof block.prof
```

#### Mutex Profiling (Contention)
Measures lock contention on mutexes.

**Usage:**
```bash
# Enable in code
runtime.SetMutexProfileFraction(1)

# Capture
curl http://localhost:6060/debug/pprof/mutex > mutex.prof
go tool pprof mutex.prof
```

### 1.2 pprof Interactive Commands

Common pprof CLI commands:

```
(pprof) top          # Show top functions by sample count
(pprof) top -cum     # Show top functions by cumulative time
(pprof) list FUNC    # Show annotated source for FUNC
(pprof) web          # Generate graph visualization
(pprof) pdf          # Generate PDF report
(pprof) png          # Generate PNG image
(pprof) trace        # Show execution trace
(pprof) callgrind    # Output in callgrind format
```

---

## 2. CPU Profiling in mcp-client

### 2.1 Real Example: Manifest Parsing

**Benchmark test location:** `/Users/cr0hn/Dropbox/Projects/mcp-client/internal/manifest/parser_bench_test.go`

```go
func BenchmarkParse(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(validManifestJSON)
	}
}

func BenchmarkJSONUnmarshal_Manifest(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var m Manifest
		_ = json.Unmarshal(validManifestJSON, &m)
	}
}

func BenchmarkFullManifestWorkflow(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manifest, err := Parse(validManifestJSON)
		if err != nil {
			b.Fatal(err)
		}
		if err := Validate(manifest); err != nil {
			b.Fatal(err)
		}
		_, err = SelectEntrypoint(manifest)
		if err != nil {
			b.Logf("SelectEntrypoint failed (expected on non-Linux): %v", err)
		}
	}
}
```

### 2.2 Profiling Manifest Parser

```bash
# Run with CPU profile
cd /Users/cr0hn/Dropbox/Projects/mcp-client
go test -cpuprofile=cpu.prof -bench=BenchmarkParse -benchtime=10s ./internal/manifest

# Analyze top functions
go tool pprof cpu.prof
(pprof) top
(pprof) list Parse

# Generate flamegraph
go tool pprof -http=:8080 cpu.prof
```

**Interpretation:**
- If `json.Unmarshal` dominates: consider using `json.Decoder` for streaming
- If `regex.Compile` is hot: pre-compile patterns in init()
- If validation dominates: optimize validation logic

### 2.3 Real Example: Cache Operations

**Benchmark location:** `/Users/cr0hn/Dropbox/Projects/mcp-client/internal/cache/cache_bench_test.go`

```go
func BenchmarkPutManifest_Small(b *testing.B) {
	store, _ := NewStore(b.TempDir())
	data := []byte(`{"schema_version":"1.0","package":{"id":"test/pkg"}}`)
	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.PutManifest(digest, data)
	}
}

func BenchmarkGetBundle_1MB(b *testing.B) {
	store, _ := NewStore(b.TempDir())
	data := make([]byte, 1*1024*1024)
	_, _ = rand.Read(data)
	digest := "sha256:def4567def4567def4567def4567def4567def4567def4567def4567def4567d"

	// Pre-populate
	_ = store.PutBundle(digest, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.GetBundle(digest)
	}
}

func BenchmarkList(b *testing.B) {
	store, _ := NewStore(b.TempDir())

	// Pre-populate with 100 artifacts
	for i := 0; i < 100; i++ {
		digestSuffix := fmt.Sprintf("%d", i)
		if len(digestSuffix) == 1 {
			digestSuffix = "0" + digestSuffix
		}
		digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd12" + digestSuffix
		if i%2 == 0 {
			_ = store.PutManifest(digest, []byte("manifest"))
		} else {
			_ = store.PutBundle(digest, []byte("bundle"))
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.List()
	}
}
```

### 2.4 Profiling Cache Operations

```bash
# Profile cache put operations
go test -cpuprofile=cpu-put.prof -bench=BenchmarkPutBundle_1MB -benchtime=10s ./internal/cache
go tool pprof -http=:8080 cpu-put.prof

# Profile cache list (potentially hot in large caches)
go test -cpuprofile=cpu-list.prof -bench=BenchmarkList -benchtime=10s ./internal/cache
go tool pprof -http=:8080 cpu-list.prof
```

---

## 3. Memory Profiling

### 3.1 Types of Memory Issues

**Excessive Allocations:**
```bash
# Identify hot allocation sites
go test -memprofile=mem.prof -bench=BenchmarkParse -benchtime=10s ./internal/manifest
go tool pprof -alloc_space mem.prof  # Total allocated
go tool pprof -alloc_objects mem.prof  # Number of allocations
go tool pprof -inuse_space mem.prof  # Current memory in use
```

**Interpreting Output:**
```
(pprof) top -cum
Showing nodes accounting for 2.5MB, 85.23% of 2.93MB total
Showing top 10 nodes out of 42
      flat  flat%   sum%        cum   cum%
    512KB 17.41% 17.41%    1.2MB 40.95%  encoding/json.Unmarshal
    256KB  8.74% 26.15%     256KB  8.74%  bytes.makeSlice
    128KB  4.37% 30.52%     128KB  4.37%  runtime.malg
```

- **flat**: Memory allocated by this function directly
- **cum**: Memory allocated by this function + callees
- **alloc_space**: Total allocated (useful for finding leak sources)
- **inuse_space**: Currently allocated (useful for peak memory)

### 3.2 Escape Analysis

Determine if variables escape to heap (causing allocations):

```bash
# See escape analysis output
go build -gcflags="-m" ./internal/manifest
go build -gcflags="-m -m" ./internal/manifest  # More verbose
```

Example output:
```
./parser.go:42:13: json.Unmarshal ... escapes to heap
./parser.go:55:9: data does not escape
```

### 3.3 Heap Profile in Code

Add pprof endpoint to mcp-client for runtime profiling:

```go
import _ "net/http/pprof"
import "net/http"

func init() {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()
}
```

Then capture memory profile:
```bash
# While smcp is running
curl http://localhost:6060/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

### 3.4 Memory Leaks

Detect goroutine/memory leaks:

```go
// In test setup
initialGoroutines := runtime.NumGoroutine()

// Run test code
runTestCommand()

// In test teardown
runtime.GC()  // Force garbage collection
finalGoroutines := runtime.NumGoroutine()

if finalGoroutines > initialGoroutines {
	t.Fatalf("goroutine leak: %d -> %d", initialGoroutines, finalGoroutines)
}
```

Goroutine profile:
```bash
curl http://localhost:6060/debug/pprof/goroutine > goroutine.prof
go tool pprof goroutine.prof
(pprof) top
(pprof) traces main  # Show all stack traces
```

---

## 4. Benchmark Writing

### 4.1 Proper Benchmark Setup

```go
func BenchmarkCopyToPath(b *testing.B) {
	store, _ := NewStore(b.TempDir())
	data := make([]byte, 100*1024) // 100 KB
	_, _ = rand.Read(data)
	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	_ = store.PutBundle(digest, data)

	b.ResetTimer()  // Exclude setup from timing
	for i := 0; i < b.N; i++ {
		dest := filepath.Join(b.TempDir(), "output")
		_ = store.CopyToPath(digest, "bundle", dest)
	}
}
```

**Key points:**
- `b.ResetTimer()`: Exclude setup overhead from measurements
- `b.StopTimer()` / `b.StartTimer()`: Exclude parts of test from timing
- `b.N`: Number of iterations (go test adjusts automatically)

### 4.2 Advanced Benchmark Patterns

**Benchmarking with parallelism:**
```go
func BenchmarkManifestParseParallel(b *testing.B) {
	data := []byte(`{"schema_version":"1.0",...}`)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = Parse(data)
		}
	})
}
```

**Benchmarking different input sizes:**
```go
func BenchmarkCacheGet(b *testing.B) {
	for _, bundleSize := range []int{1024, 1024*1024, 10*1024*1024} {
		b.Run(fmt.Sprintf("Size%d", bundleSize), func(b *testing.B) {
			store, _ := NewStore(b.TempDir())
			data := make([]byte, bundleSize)
			rand.Read(data)
			digest := "sha256:..."
			store.PutBundle(digest, data)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = store.GetBundle(digest)
			}
		})
	}
}
```

### 4.3 Benchmark Interpretation

Running benchmarks:
```bash
go test -bench=. -benchmem ./internal/cache
```

Output format:
```
BenchmarkPutManifest_Small      2000000    598 ns/op    256 B/op    2 allocs/op
BenchmarkGetManifest_Cached    10000000     98 ns/op      0 B/op    0 allocs/op
BenchmarkPutBundle_1MB            10000  102500 ns/op  1048600 B/op    1 allocs/op
```

**Interpretation:**
- **598 ns/op**: 598 nanoseconds per operation
- **256 B/op**: 256 bytes allocated per operation
- **2 allocs/op**: 2 allocations per operation (can be reduced!)

### 4.4 Comparing Benchmarks

Use `benchstat` for statistical comparison:

```bash
# Baseline
go test -bench=BenchmarkParse -benchtime=10s ./internal/manifest > old.txt

# After optimization
go test -bench=BenchmarkParse -benchtime=10s ./internal/manifest > new.txt

# Compare
benchstat old.txt new.txt
```

Output:
```
name     old time/op    new time/op    delta
Parse       2.50µs ± 3%    1.80µs ± 2%  -28.00%
Parse       2.1MB ± 0%     1.5MB ± 0%   -28.57%
```

---

## 5. Common Bottlenecks in mcp-client

### 5.1 JSON Parsing Bottleneck

**Problem:** `encoding/json.Unmarshal` is slow for large manifests.

**Optimization:** Use `json.Decoder` for streaming or cache parsed results:

```go
// Before: Unmarshals entire manifest each time
var manifest Manifest
json.Unmarshal(data, &manifest)

// After: Parse once and cache
cachedParsed[digest] = manifest  // Use internal cache
```

### 5.2 Allocation Optimization with sync.Pool

**Problem:** Creating many digest validators allocates memory.

**Optimization:**
```go
var hashPool = sync.Pool{
	New: func() interface{} {
		return sha256.New()
	},
}

func ValidateDigest(data []byte, expectedDigest string) bool {
	h := hashPool.Get().(hash.Hash)
	defer hashPool.Put(h)
	h.Reset()

	h.Write(data)
	actual := hex.EncodeToString(h.Sum(nil))
	return actual == expectedDigest
}
```

### 5.3 Buffer Pooling for I/O

**Problem:** Reading bundles allocates new buffers each time.

**Optimization:**
```go
var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)  // 32KB buffers
	},
}

func CopyBundle(src io.Reader, dst io.Writer) error {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

	_, err := io.CopyBuffer(dst, src, buf)
	return err
}
```

### 5.4 String Builder for Concatenation

**Problem:** Naive string concatenation in loops.

**Optimization:**
```go
// Before: O(n²) allocations
var result string
for _, digest := range digests {
	result += digest + "\n"
}

// After: O(n) allocations
var buf strings.Builder
for _, digest := range digests {
	buf.WriteString(digest)
	buf.WriteByte('\n')
}
result := buf.String()
```

---

## 6. Tools and Utilities

### 6.1 go tool pprof

```bash
# Interactive analysis
go tool pprof cpu.prof

# Web UI with flamegraph
go tool pprof -http=:8080 cpu.prof

# Text output
go tool pprof -text cpu.prof

# Top 5 functions
go tool pprof -top -nodecount=5 cpu.prof

# List specific function
go tool pprof -list=Parse cpu.prof

# Call graph
go tool pprof -callgrind cpu.prof > call.txt
kcachegrind call.txt  # Requires kcachegrind
```

### 6.2 go tool trace

Detailed execution trace (not in mcp-client yet):

```bash
# Generate trace
go test -trace=trace.out ./...

# Analyze
go tool trace trace.out
```

### 6.3 Memory Leak Detection

```bash
# goleak integration in tests
import "github.com/uber-go/goleak"

func TestNoLeaks(t *testing.T) {
	defer goleak.VerifyNone(t)

	runTestCommand()
}
```

### 6.4 benchstat

Statistical comparison of benchmarks:

```bash
go get golang.org/x/perf/cmd/benchstat

# Create baseline
go test -bench=. -benchtime=10s -benchmem ./internal/cache > baseline.txt

# Modify code and compare
go test -bench=. -benchtime=10s -benchmem ./internal/cache > optimized.txt

benchstat baseline.txt optimized.txt
```

---

## 7. Real Optimization Example: Cache Store

### 7.1 Profiling the Cache

```bash
cd /Users/cr0hn/Dropbox/Projects/mcp-client

# Benchmark all cache operations
go test -cpuprofile=cpu.prof -memprofile=mem.prof \
	-bench=. -benchtime=10s ./internal/cache

# Analyze CPU hotspots
go tool pprof cpu.prof

# Analyze memory allocations
go tool pprof -alloc_objects mem.prof

# Compare allocations
go tool pprof -inuse_space mem.prof
```

### 7.2 Optimization Checklist

**For cache store operations:**

1. **List() operation** (hot when cache is large):
   - Avoid reallocating slice repeatedly
   - Use pre-allocated slice with capacity
   - Cache directory scan results temporarily

2. **Get operations** (cache hits):
   - Zero-copy reads if possible
   - Lazy deserialization
   - Use memory pools for buffers

3. **Put operations** (disk I/O bound):
   - Async writes if safe
   - Buffer writes before flushing
   - Use atomic renames (TOCTOU safety)

4. **Digest validation** (CPU intensive):
   - Pre-compute digests where possible
   - Use hash.Sum() instead of separate Write/Sum calls
   - Consider BLAKE2 or BLAKE3 for parallel hashing

---

## 8. CI/CD Profiling

### 8.1 Regression Detection

Add to GitHub Actions:

```yaml
- name: Run benchmarks
  run: |
    go test -bench=. -benchmem -benchtime=10s \
      -out bench.json ./... | tee bench.txt

- name: Compare benchmarks
  uses: benchmark-action/github-action-benchmark@v1
  with:
    tool: 'go'
    output-file-path: bench.txt
    github-token: ${{ secrets.GITHUB_TOKEN }}
    auto-push: true
```

### 8.2 Memory Leak Tests

```bash
# Run with -race to detect data races
go test -race ./...

# Detect goroutine leaks in CI
go test -count=100 ./internal/cache  # Run multiple times
```

---

## 9. Profiling Checklist

When optimizing mcp-client:

- [ ] Enable CPU profiling for hot code paths
- [ ] Analyze memory allocations with `-memprofile`
- [ ] Check escape analysis with `go build -gcflags="-m"`
- [ ] Write benchmarks before and after optimization
- [ ] Use `benchstat` to quantify improvements
- [ ] Check for goroutine leaks in tests
- [ ] Profile with real data sizes (1MB, 100MB bundles)
- [ ] Run benchmarks multiple times for statistical confidence
- [ ] Use `-race` to detect data races
- [ ] Monitor in CI/CD for regressions

---

## 10. Common Profiling Commands Reference

```bash
# CPU profile
go test -cpuprofile=cpu.prof -bench=. ./...
go tool pprof cpu.prof

# Memory profile
go test -memprofile=mem.prof -bench=. ./...
go tool pprof -alloc_space mem.prof

# Goroutine profile
go test -run TestRunCommand ./...
curl http://localhost:6060/debug/pprof/goroutine > goroutine.prof

# Block profile (contention)
go tool pprof http://localhost:6060/debug/pprof/block

# Trace profile
go test -trace=trace.out ./...
go tool trace trace.out

# Multi-profile
go test -cpuprofile=cpu.prof -memprofile=mem.prof -trace=trace.out ./...

# Benchmark comparison
go test -bench=. -benchmem ./... > baseline.txt
# ... make changes ...
go test -bench=. -benchmem ./... > optimized.txt
benchstat baseline.txt optimized.txt
```

---

## 11. Key Takeaways

1. **Profile first, optimize second** - Data drives decisions
2. **Benchmark regularly** - Catch regressions early in CI/CD
3. **Allocations matter** - Reduce B/op to improve performance
4. **Contention kills performance** - Use profiling to find mutex/channel bottlenecks
5. **Real-world data** - Profile with actual bundle sizes (1MB-1GB)
6. **Measure twice** - Use benchstat for statistical confidence
7. **Track over time** - Monitor benchmarks in CI for regressions
