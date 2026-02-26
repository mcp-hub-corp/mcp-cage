# Production Debugging & Troubleshooting Guide

## Overview

This skill covers debugging mcp-client in production and development environments. Includes common error scenarios, diagnostic workflows, log analysis, and practical troubleshooting techniques.

**Key Areas:**
- Common error messages and interpretation
- Structured log analysis with jq
- Verbose/debug mode usage
- System call tracing (strace/dtrace)
- Network debugging
- Cache inspection
- Sandbox limit verification

---

## 1. Error Messages & Exit Codes

### 1.1 mcp-client Exit Codes

```bash
# Exit code 0: Success
smcp run acme/package@1.0.0  # Succeeded
echo $?  # Output: 0

# Exit code 1: Configuration error
smcp run invalid-ref  # Invalid reference format
echo $?  # Output: 1

# Exit code 2: Network/Registry error
smcp run acme/nonexistent@1.0.0  # Package not found in registry
echo $?  # Output: 2

# Exit code 3: Validation error
smcp run acme/package@1.0.0  # Digest mismatch after download
echo $?  # Output: 3

# Exit code 4: Execution error
smcp run acme/package@1.0.0  # MCP server process exited with error
echo $?  # Output: 4

# Exit code 5: Timeout
smcp run acme/package@1.0.0 --timeout 1s  # Process exceeded timeout
echo $?  # Output: 5

# Exit code 124: Signal (SIGTERM/SIGKILL)
smcp run acme/package@1.0.0  # Process killed by signal
echo $?  # Output: 124
```

### 1.2 Common Error Scenarios

#### Package Not Found (404)

**Error:**
```
[ERROR] Failed to resolve acme/hello-world@1.2.3: package not found (404)
[ERROR] Check: org/name is correct, version exists in registry
```

**Debugging:**
```bash
# Check if package exists
curl -s https://registry.example.com/v1/packages/acme/hello-world/resolve?ref=1.2.3 | jq .

# Check available versions
curl -s https://registry.example.com/v1/packages/acme/hello-world/versions | jq '.versions[]'

# Verify registry URL in config
cat ~/.smcp/config.yaml | grep registry

# Test registry connectivity
curl -I https://registry.example.com/v1/packages
```

#### Digest Mismatch

**Error:**
```
[ERROR] Digest validation failed for manifest
[ERROR] Expected: sha256:abc123...
[ERROR] Got:      sha256:xyz789...
[ERROR] Action: Bundle may be corrupted, try: smcp cache rm sha256:abc123... && mcp pull acme/pkg@1.0.0
```

**Debugging:**
```bash
# List cached artifacts
smcp cache ls

# Show specific artifact
smcp cache ls | grep "abc123"

# Verify digest manually
sha256sum ~/.smcp/cache/bundles/sha256:abc123.../bundle.tar.gz

# Force re-download
smcp cache rm sha256:abc123...
smcp pull acme/package@1.0.0 --no-cache
```

**Root causes:**
- Network corruption during download
- Cache corruption (rare)
- Registry changed artifact (misconfiguration)

#### Authentication Failure

**Error:**
```
[ERROR] Failed to authenticate with registry
[ERROR] Check: Token is valid and not expired
[ERROR] Status: 401 Unauthorized
```

**Debugging:**
```bash
# Check stored credentials
cat ~/.smcp/auth.json | jq .

# Check token expiration
cat ~/.smcp/auth.json | jq '.registries[] | .expires_at'

# Re-authenticate
smcp login --token $(cat /path/to/token.txt)

# Test with curl
curl -H "Authorization: Bearer $(cat ~/.smcp/auth.json | jq -r '.registries["https://registry"].token')" \
  https://registry.example.com/v1/packages/acme/test/resolve?ref=1.0.0
```

#### Timeout During Execution

**Error:**
```
[ERROR] Process killed by timeout (300s exceeded)
[ERROR] Action: Increase timeout with --timeout flag or check if server hangs
```

**Debugging:**
```bash
# Increase timeout
smcp run acme/package@1.0.0 --timeout 10m

# Check if server is hung
ps aux | grep mcp
strace -p <PID>  # See what process is doing

# Check resource limits
# See section on Sandbox Debugging below
```

#### Memory Exceeded

**Error:**
```
[ERROR] Process exceeded memory limit (512M)
[ERROR] Action: Increase limit with config or check for memory leak
```

**Debugging:**
```bash
# Monitor memory usage
while true; do
  ps aux | grep smcp-server | grep -v grep
  sleep 1
done

# Check resource limits applied
cat ~/.smcp/config.yaml | grep memory

# Increase in config
cat >> ~/.smcp/config.yaml << EOF
executor:
  max_memory: 2G
EOF

# Run with verbose to see limits
smcp run acme/package@1.0.0 --log-level debug 2>&1 | grep -i "limit\|memory"
```

#### Subprocess Not Allowed

**Error:**
```
[ERROR] Subprocess execution blocked (policy violation)
[ERROR] Action: Check manifest subprocess permissions or allow in config
```

**Debugging:**
```bash
# Check manifest permissions
smcp pull acme/package@1.0.0 --no-cache
cat ~/.smcp/cache/manifests/sha256:.../manifest.json | jq '.permissions_requested.subprocess'

# Check if package needs subprocess
# If true, ensure it's allowed:
cat >> ~/.smcp/config.yaml << EOF
security:
  subprocess:
    allow: true
EOF

# Or mark specific package as trusted
cat >> ~/.smcp/config.yaml << EOF
trusted_packages:
  - acme/package
EOF
```

#### Network Policy Violation

**Error:**
```
[ERROR] Network access denied to example.com (policy violation)
[ERROR] Check: Manifest allowlist of allowed domains
```

**Debugging:**
```bash
# Check manifest network allowlist
smcp pull acme/package@1.0.0
cat ~/.smcp/cache/manifests/sha256:.../manifest.json | jq '.permissions_requested.network'

# If allowlist is empty, network is default-deny (Linux)
# Check what domains package tries to access
smcp run acme/package@1.0.0 --log-level debug 2>&1 | grep -i "network\|connect"

# Temporarily disable network policy (dangerous!)
cat >> ~/.smcp/config.yaml << EOF
security:
  network:
    default_deny: false
EOF
```

---

## 2. Verbose/Debug Mode

### 2.1 Enable Debug Logging

```bash
# Enable debug level
smcp run acme/package@1.0.0 --log-level debug

# Or set environment variable
export MCP_LOG_LEVEL=debug
smcp run acme/package@1.0.0

# JSON-formatted debug logs (for parsing)
export MCP_LOG_FORMAT=json
smcp run acme/package@1.0.0 2>&1 | tee run.log
```

### 2.2 Debug Output Interpretation

**Example debug log:**
```
[DEBUG] Config loaded from /home/user/.mcp/config.yaml
[DEBUG] Registry URL: https://registry.example.com
[DEBUG] Cache directory: /home/user/.mcp/cache
[DEBUG] Resolving reference: acme/package@1.0.0
[DEBUG] Resolve request to https://registry.example.com/v1/packages/acme/package/resolve?ref=1.0.0
[DEBUG] Resolve response: manifest=sha256:abc123... bundle=sha256:def456...
[DEBUG] Checking cache for manifest sha256:abc123...
[DEBUG] Cache hit: manifest
[DEBUG] Checking cache for bundle sha256:def456...
[DEBUG] Cache miss: bundle, downloading
[DEBUG] Download URL: https://registry.example.com/bundles/sha256:def456
[DEBUG] Downloading 12.5 MB...
[DEBUG] Validating digest: sha256:def456...
[DEBUG] Digest validation: OK
[DEBUG] Parsing manifest
[DEBUG] Selecting entrypoint for linux/amd64
[DEBUG] Entrypoint: /bin/mcp-server --mode stdio
[DEBUG] Applying resource limits: CPU=1000ms/s Memory=512MB PIDs=10 FDs=100
[DEBUG] Applying network policy: allowlist=[*.example.com]
[DEBUG] Starting process: /bin/mcp-server --mode stdio (PID 12345)
[DEBUG] Process running
[DEBUG] Process exited with code 0
```

### 2.3 Filtering Debug Output

```bash
# Show only errors
smcp run acme/package@1.0.0 --log-level error

# Show info + errors
smcp run acme/package@1.0.0 --log-level info

# Show specific component debug logs
smcp run acme/package@1.0.0 --log-level debug 2>&1 | grep "registry\|cache\|sandbox"

# Filter with jq (if using JSON logs)
export MCP_LOG_FORMAT=json
smcp run acme/package@1.0.0 2>&1 | jq 'select(.level=="ERROR")'
```

---

## 3. Structured Log Analysis with jq

### 3.1 JSON Log Format

```bash
# Enable JSON logging
export MCP_LOG_FORMAT=json
smcp run acme/package@1.0.0 > run.log 2>&1

# View as JSON
jq . run.log

# Example output:
#{
#  "timestamp": "2026-01-18T10:30:00Z",
#  "level": "INFO",
#  "message": "Starting MCP server",
#  "package": "acme/package",
#  "version": "1.0.0",
#  "pid": 12345
#}
```

### 3.2 jq Commands for Log Analysis

```bash
# Count errors
jq 'select(.level=="ERROR")' run.log | wc -l

# Show all errors with timestamps
jq -r 'select(.level=="ERROR") | "\(.timestamp) \(.message)"' run.log

# Group by package
jq -s 'group_by(.package) | map({package: .[0].package, count: length})' run.log

# Find slowest operations
jq 'select(.duration_ms) | sort_by(.duration_ms) | reverse | .[0:5]' run.log

# Timeline of events
jq -r '.timestamp + " " + .level + " " + .message' run.log | head -20

# Extract audit trail
jq -r 'select(.event_type) | "\(.timestamp) \(.event_type) package=\(.package) version=\(.version)"' run.log
```

### 3.3 Common Log Queries

**Find all network-related logs:**
```bash
jq 'select(.component=="network" or .message | contains("network"))' run.log
```

**Find all digest validations:**
```bash
jq 'select(.message | contains("digest"))' run.log
```

**Timeline of cache operations:**
```bash
jq -r 'select(.component=="cache") | "\(.timestamp) \(.operation) \(.artifact_type) status=\(.status)"' run.log
```

**Find slow operations:**
```bash
jq 'select(.duration_ms > 1000) | {timestamp, message, duration_ms}' run.log
```

---

## 4. System Call Tracing

### 4.1 strace (Linux)

**Trace all system calls:**
```bash
strace -f -e trace=open,openat,read,write,connect smcp run  acme/package@1.0.0
```

**Output interpretation:**
```
openat(AT_FDCWD, "/home/user/.mcp/cache/bundles/sha256:...", O_RDONLY) = 4
read(4, "\x1f\x8b\x08\x00...", 32768) = 32768
close(4) = 0
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 5
connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_aton("10.0.0.1")}, 16) = 0
write(5, "GET /v1/packages/...", 200) = 200
read(5, "HTTP/1.1 200 OK\r\n", 32768) = 17
close(5) = 0
```

**Trace specific syscall:**
```bash
# Network connections only
strace -e network smcp run  acme/package@1.0.0

# File operations only
strace -e openat,read,write smcp run  acme/package@1.0.0

# Show time for each call
strace -t -e open,read,write smcp run  acme/package@1.0.0

# Count syscalls
strace -c smcp run  acme/package@1.0.0
```

**Output format:**
```
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 42.51    0.532742          42     12691      1234 read
 28.21    0.354118          65      5429           write
  8.92    0.112021          12      9347       234 openat
  ...
```

### 4.2 dtrace (macOS)

**Trace file access:**
```bash
sudo dtrace -n 'syscall:::entry /execname == "smcp"/ { @[execname] = count(); }' -c "smcp run acme/package@1.0.0"
```

**Trace network connections:**
```bash
sudo dtrace -n 'syscall:::entry /execname == "smcp" && (arg0 == "connect" || arg0 == "send")/ { trace(execname); }' -c "smcp run acme/package@1.0.0"
```

### 4.3 Process Inspection

**List open files:**
```bash
# Start smcp in background
smcp run acme/package@1.0.0 &
MCP_PID=$!

# List open files
lsof -p $MCP_PID

# Identify what's open:
# - /home/user/.mcp/cache/* (cache files)
# - /tmp/* (temporary files)
# - /dev/* (devices)
# - sockets/TCP connections
```

**Monitor resource usage:**
```bash
# Real-time monitoring
watch -n 0.1 'ps aux | grep smcp-server'

# Or use top
top -p $(pgrep mcp)
```

**Show process limits:**
```bash
# Check limits for running process
cat /proc/$(pgrep mcp)/limits

# Output:
# Limit             Soft Limit    Hard Limit    Units
# Max file size     unlimited     unlimited    bytes
# Max stack size    8388608       unlimited    bytes
# Max processes     1024          1024         processes
# ...
```

---

## 5. Network Debugging

### 5.1 Connection Debugging

**Test registry connectivity:**
```bash
# Basic connectivity
curl -I https://registry.example.com/v1/packages

# With authentication
curl -H "Authorization: Bearer $(cat ~/.smcp/auth.json | jq -r '.registries["https://registry"].token')" \
  https://registry.example.com/v1/packages

# Verbose output
curl -v https://registry.example.com/v1/packages/acme/test/resolve?ref=1.0.0

# Timing breakdown
curl -w "@curl-format.txt" -o /dev/null -s https://registry.example.com/...
```

Create `curl-format.txt`:
```
    time_namelookup:  %{time_namelookup}\n
       time_connect:  %{time_connect}\n
    time_appconnect:  %{time_appconnect}\n
   time_pretransfer:  %{time_pretransfer}\n
      time_redirect:  %{time_redirect}\n
 time_starttransfer:  %{time_starttransfer}\n
                    ----------\n
         time_total:  %{time_total}\n
```

### 5.2 Packet Capture

**Capture traffic (Linux):**
```bash
# Start capture in background
sudo tcpdump -i any -n dst registry.example.com -w capture.pcap &

# Run mcp
smcp run acme/package@1.0.0

# Stop capture
sudo pkill tcpdump

# Analyze with tcpdump
sudo tcpdump -r capture.pcap -A | head -100

# Analyze with wireshark
wireshark capture.pcap &
```

**Filter by protocol:**
```bash
# DNS lookups
sudo tcpdump -n 'udp port 53'

# HTTP/HTTPS
sudo tcpdump -n 'tcp port 443 or tcp port 80'

# All traffic to specific host
sudo tcpdump -n 'host registry.example.com'
```

### 5.3 DNS Debugging

**Test DNS resolution:**
```bash
# Resolve hostname
nslookup registry.example.com
dig registry.example.com

# Check which DNS server is used
cat /etc/resolv.conf

# Test with smcp verbose
export MCP_LOG_LEVEL=debug
smcp run acme/package@1.0.0 2>&1 | grep -i "dns\|resolv\|hostname"
```

---

## 6. Cache Inspection

### 6.1 List Cache Contents

```bash
# Show all artifacts
smcp cache ls

# Output:
# DIGEST                                          TYPE      SIZE     LAST USED
# sha256:abc123...                                manifest  4.2 KB   2 hours ago
# sha256:def456...                                bundle    12.5 MB  1 hour ago

# Get detailed info
smcp cache ls | grep -E "^sha256:abc123"

# Count artifacts
smcp cache ls | wc -l
```

### 6.2 Verify Artifact Integrity

```bash
# Manually verify digest
CACHE_PATH="$HOME/.mcp/cache/bundles/sha256:def456..."
sha256sum "$CACHE_PATH/bundle.tar.gz"

# Compare with expected
expected_digest="sha256:def456..."
actual=$(sha256sum "$CACHE_PATH/bundle.tar.gz" | cut -d' ' -f1)
if [[ "sha256:$actual" == "$expected_digest" ]]; then
  echo "✓ Digest matches"
else
  echo "✗ Digest mismatch!"
fi

# Extract and inspect bundle
tar -tzf "$CACHE_PATH/bundle.tar.gz" | head -20
```

### 6.3 Cache Cleanup

```bash
# Remove single artifact
smcp cache rm sha256:abc123...

# Remove multiple
smcp cache rm sha256:abc123... sha256:def456...

# Remove all (careful!)
smcp cache rm --all

# List before removal
smcp cache ls > old_cache.txt
smcp cache rm --all
smcp cache ls > new_cache.txt
```

### 6.4 Cache Corruption Detection

```bash
# Check all cached artifacts
for manifest in ~/.smcp/cache/manifests/*/manifest.json; do
  digest=$(dirname "$manifest" | xargs basename)
  sha256sum "$manifest" | awk '{print $1}' > /tmp/computed
  expected=$(echo "$digest" | sed 's/sha256://')
  if ! grep -q "^${expected}" /tmp/computed; then
    echo "✗ Corrupted: $digest"
  fi
done

# If corruption found, clean and re-download
smcp cache rm --all
smcp pull acme/package@1.0.0 --no-cache
```

---

## 7. Sandbox & Limits Debugging

### 7.1 Check Sandbox Capabilities

```bash
# Run doctor command
smcp doctor

# Output:
# [✓] OS: linux (amd64)
# [✓] Cgroups v2: available
# [✓] Network namespaces: available (requires CAP_NET_ADMIN)
# [✓] Seccomp: available
# [!] Running as non-root: network isolation limited
# [✓] Cache directory: /home/user/.mcp/cache (writable)

# Check specific capability
smcp doctor 2>&1 | grep "Cgroups"
```

### 7.2 Monitor Resource Limits

**Linux cgroups:**
```bash
# Find smcp cgroup
ps aux | grep smcp-server | grep -v grep
MCP_PID=12345

# Check cgroup membership
cat /proc/$MCP_PID/cgroup

# Check memory limit
cat /sys/fs/cgroup/memory/smcp/memory.limit_in_bytes

# Check current usage
cat /sys/fs/cgroup/memory/smcp/memory.usage_in_bytes

# Check CPU limit
cat /sys/fs/cgroup/cpu/smcp/cpu.cfs_quota_us
cat /sys/fs/cgroup/cpu/smcp/cpu.cfs_period_us
```

**macOS limits (rlimit):**
```bash
# Check process limits
cat /proc/<PID>/limits  # Not available on macOS

# Use process inspection
ps -eo pid,rss,vsz | grep smcp  # Memory

# Check with getrusage (in code or lldb)
```

### 7.3 Verify Network Isolation

**Linux:**
```bash
# Check network namespace
ip netns list  # Should see mcp's netns

# Verify isolation
sudo nsenter -t $MCP_PID -n netstat -tuln
# Should show only allowed connections

# Test network access
smcp run acme/package@1.0.0 --log-level debug 2>&1 | grep -i "network\|connection"
```

**macOS/Windows:**
```bash
# Network isolation not supported
# Check config
cat ~/.smcp/config.yaml | grep -A 5 "security:" | grep -A 3 "network:"

# Document limitation
echo "WARNING: Network isolation not available on this OS"
```

---

## 8. Troubleshooting Workflow

### 8.1 Generic Troubleshooting Steps

1. **Check exit code:**
   ```bash
   smcp run acme/package@1.0.0
   echo "Exit code: $?"
   ```

2. **Enable debug logging:**
   ```bash
   export MCP_LOG_LEVEL=debug
   export MCP_LOG_FORMAT=json
   smcp run acme/package@1.0.0 2>&1 | tee debug.log
   ```

3. **Analyze logs:**
   ```bash
   # Check for errors
   jq 'select(.level=="ERROR")' debug.log

   # Timeline
   jq -r '.timestamp + " " + .message' debug.log | head -20
   ```

4. **Test registry:**
   ```bash
   curl -v https://registry.example.com/v1/packages/acme/package/resolve?ref=1.0.0
   ```

5. **Check cache:**
   ```bash
   smcp cache ls
   ```

6. **Verify system capabilities:**
   ```bash
   smcp doctor
   ```

7. **Trace system calls:**
   ```bash
   strace -e trace=open,read,write,connect smcp run  acme/package@1.0.0
   ```

8. **Inspect process:**
   ```bash
   # In another terminal
   ps aux | grep mcp
   lsof -p $PID
   ```

### 8.2 Decision Tree

```
Issue: smcp run fails

├─ Exit code?
│  ├─ 1 → Configuration error → Check ~/.smcp/config.yaml, flags
│  ├─ 2 → Network/Registry error → Test: curl registry.example.com
│  ├─ 3 → Validation error → Check: smcp cache ls, digest mismatch
│  ├─ 4 → Execution error → Check: MCP server logs, stderr
│  ├─ 5 → Timeout → Increase: --timeout flag
│  └─ 124 → Signal → Process killed, check: resource limits
│
├─ Error in logs?
│  ├─ "package not found" → Verify: org/name, registry URL
│  ├─ "digest mismatch" → Try: smcp cache rm && mcp pull --no-cache
│  ├─ "auth failed" → Check: smcp login, token expiration
│  ├─ "timeout" → Increase: --timeout, check server logs
│  └─ "network denied" → Check: manifest, security policy
│
├─ Performance issue?
│  ├─ Slow download → Check: network (tcpdump, curl timing)
│  ├─ Slow startup → Profile: strace, --log-level debug
│  └─ High memory → Monitor: ps, top, cgroup limits
│
└─ Sandbox issue?
   ├─ Limits not applied → Check: smcp doctor, OS support
   ├─ Network not isolated → Check: OS (Linux only in v1)
   └─ Subprocess blocked → Check: manifest, security policy
```

---

## 9. Real-World Troubleshooting Examples

### 9.1 Example: Package Not Found

```bash
$ smcp run acme/hello-world@1.2.3
[ERROR] Failed to resolve acme/hello-world@1.2.3: package not found (404)

# Debug:
$ curl -v https://registry.example.com/v1/packages/acme/hello-world/resolve?ref=1.2.3
< HTTP/1.1 404 Not Found

# Check available versions:
$ curl -s https://registry.example.com/v1/packages/acme/hello-world/versions | jq '.versions'
[
  "1.0.0",
  "1.1.0",
  "1.2.0"
]

# Solution: Use correct version
$ smcp run acme/hello-world@1.2.0  # ✓ Works
```

### 9.2 Example: Digest Mismatch

```bash
$ smcp run acme/tool@1.0.0
[ERROR] Digest validation failed for bundle
[ERROR] Expected: sha256:abc123...
[ERROR] Got:      sha256:xyz789...

# Debug:
$ smcp cache ls | grep abc123
sha256:abc123...   bundle    12.5MB   5 mins ago

# Verify:
$ sha256sum ~/.smcp/cache/bundles/sha256:abc123.../bundle.tar.gz
xyz789... (doesn't match!)

# Solution: Clear cache and re-download
$ smcp cache rm sha256:abc123...
$ smcp pull acme/tool@1.0.0 --no-cache
$ smcp run acme/tool@1.0.0  # ✓ Works
```

### 9.3 Example: Timeout

```bash
$ smcp run acme/slow-server@1.0.0 --timeout 10s
[ERROR] Process killed by timeout (10s exceeded)
(Exit code 5)

# Debug: Check server performance
$ MCP_LOG_LEVEL=debug smcp run acme/slow-server@1.0.0 --timeout 30s 2>&1 | grep -i "start\|running\|exit"
[DEBUG] Starting process: /bin/slow-server --mode stdio (PID 12345)
[DEBUG] Process running (after 25s)
[DEBUG] Process exited with code 0 (after 35s)

# Solution: Increase timeout
$ smcp run acme/slow-server@1.0.0 --timeout 60s  # ✓ Works
```

### 9.4 Example: Memory Exceeded

```bash
$ smcp run acme/memory-hog@1.0.0
[ERROR] Process exceeded memory limit (512M)

# Check limit
$ grep max_memory ~/.smcp/config.yaml
max_memory: 512M

# Monitor actual usage (in another terminal)
$ watch -n 0.1 'ps aux | grep smcp-server'
MCP_SERVER 12345 25.3 600.0  ...  # Using 600MB (exceeded 512MB limit)

# Solution: Increase limit or check for memory leak
$ cat >> ~/.smcp/config.yaml << EOF
executor:
  max_memory: 1G
EOF

$ smcp run acme/memory-hog@1.0.0  # ✓ Works
```

---

## 10. Debugging Checklist

When troubleshooting mcp-client:

- [ ] Check exit code and error message
- [ ] Enable debug logging (`--log-level debug`)
- [ ] Save logs to file for analysis (`2>&1 | tee debug.log`)
- [ ] Test registry connectivity with curl
- [ ] Verify package exists with correct version
- [ ] Check cache for corruption (`smcp cache ls`)
- [ ] Inspect system capabilities (`smcp doctor`)
- [ ] Trace system calls with strace/dtrace
- [ ] Monitor resource usage with ps/top/lsof
- [ ] Check network with tcpdump/wireshark
- [ ] Parse JSON logs with jq
- [ ] Verify auth token is valid and not expired
- [ ] Check permission for ~/.smcp directory
- [ ] Verify registry URL and network access

---

## 11. Reference: Common Commands

```bash
# Basic debugging
smcp doctor                           # Check system capabilities
smcp --version                        # Check mcp-client version

# Logging
export MCP_LOG_LEVEL=debug          # Enable debug logs
export MCP_LOG_FORMAT=json          # Use JSON format
smcp run acme/pkg@1.0.0 2>&1 | tee run.log

# Cache inspection
smcp cache ls                          # List artifacts
smcp cache rm sha256:...               # Remove artifact
smcp cache rm --all                    # Clear cache

# Network testing
curl -v https://registry.example.com/...
curl -w "@curl-format.txt" https://...

# System tracing
strace -f smcp run  acme/pkg@1.0.0
lsof -p $(pgrep mcp)
ps aux | grep mcp

# Log analysis
jq 'select(.level=="ERROR")' run.log
jq -r '.timestamp + " " + .message' run.log

# Cache integrity
smcp cache ls | while read line; do
  digest=$(echo "$line" | awk '{print $1}')
  # Verify digest
done
```

---

## 12. Key Takeaways

1. **Exit codes tell story** - Check them first
2. **Debug logging is powerful** - Use `--log-level debug` and JSON format
3. **jq for log analysis** - Parse and query structured logs efficiently
4. **Test externally first** - Use curl before debugging mcp
5. **strace reveals truth** - See exactly what's happening at system level
6. **Check system capabilities** - Run `smcp doctor` to verify sandbox support
7. **Isolate variables** - Test registry, cache, and execution separately
8. **Save logs for analysis** - Capture full debug logs for troubleshooting
9. **Monitor in parallel** - Use another terminal to watch resource usage
10. **Document limitations** - Know your OS sandbox capabilities
