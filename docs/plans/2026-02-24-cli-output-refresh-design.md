# CLI Output Refresh Design

**Date:** 2026-02-24
**Status:** Approved

## Problem

The `mcp run` CLI output has visual issues:
- Box-drawing info card with fixed 50-char width causes misalignment
- Subprocess output (uv, pip) mixes with the UI
- Platform warnings (macOS cgroup limitation) are verbose log-style lines
- Step status/timing not aligned (hard to scan)
- Digest verification warnings shown as raw log lines

## Target

Docker Build style: clean, aligned steps with compact info card below, subprocess output hidden by default.

## Output (Before)

```
[+] Running cr0hn/mcp-schrodinger@commit-f3d3d1a-2026-02-24
 => [1/6] Resolving package ✓ (280ms)
 => [2/6] Checking policies ✓ (0ms)
 => [3/6] Fetching manifest ● cached (0ms)
 => [4/6] Fetching bundle ● cached (0ms)
 => [5/6] Extracting bundle ✓ (2ms)
⚠ could not verify entry script digest  path=/var/folders/...  error=open ...
 => [6/6] Preparing execution ✓ (0ms)
┌────────────────────────────────────────────────────┐
│ Score: 35/100 ●○○○○ | Cert 0 (Integrity Verified) │
│ Origin: community | SHA: f3d3d1a                  │
│ Format: hub                                       │
│ !! 0 critical, 1 high findings                    │
├────────────────────────────────────────────────────┤
│ CPU: 500m  Memory: 512M  Timeout: 5m 0s           │
│ PIDs: 256  FDs: 1024                              │
├────────────────────────────────────────────────────┤
│ Sandbox: darwin                                   │
│   ✗ CPU ✗ Mem ✗ PID                         │
│   ✗ FD ✓ Net ✓ FS                           │
│   ✓ sandbox-exec                                │
│ ! macOS does not support cgroups ...             │
│ ! Timeout is enforced by the executor ...        │
│ ! For strict resource limiting ...               │
└────────────────────────────────────────────────────┘

● MCP server listening (stdio) — Press Ctrl+C to stop
  starting STDIO executor  command=/opt/homebrew/bin/uv  workdir=...
Using CPython 3.11.14 interpreter at: ...
Creating virtual environment at: .venv
Installed 30 packages in 42ms
```

## Output (After)

```
[+] Running cr0hn/mcp-schrodinger@commit-f3d3d1a-2026-02-24
 => [1/6] Resolving package                  ✓ 280ms
 => [2/6] Checking policies                  ✓ 0ms
 => [3/6] Fetching manifest                  ● cached
 => [4/6] Fetching bundle                    ● cached
 => [5/6] Extracting bundle                  ✓ 2ms
 => [6/6] Preparing execution                ✓ 0ms

  Score 35/100 ●○○○○  Cert 0 (Integrity Verified)
  Origin: community  SHA: f3d3d1a  Format: hub
  ⚠ 1 high finding

  Sandbox: darwin  (net:✓ fs:✓ exec:✓)
  Limits: cpu=500m mem=512M timeout=5m pids=256
  ⚠ macOS: resource limits not enforced (no cgroups)

● MCP server listening (stdio) — Press Ctrl+C to stop
```

With `--verbose`:
```
● MCP server listening (stdio) — Press Ctrl+C to stop
  starting STDIO executor  command=uv  workdir=/tmp/mcp-bundle-...
  Using CPython 3.11.14
  Creating virtual environment at: .venv
  Installed 30 packages in 42ms
```

## Changes

### 1. Aligned Steps (progress.go)

Pad step descriptions to fixed width so status indicators and timing align in a column.

### 2. Compact Info Card (progress.go)

Replace box-drawing `infoCardTerm()` with indented text:
- Line 1: Score + bar + Cert level
- Line 2: Origin + SHA + Format (single line)
- Line 3: Findings warning (only if critical/high > 0)
- Blank line
- Line 4: Sandbox with inline capabilities (only show active ones)
- Line 5: Limits as key=value
- Line 6: Platform warnings condensed to single line

Remove `bline()`, `boxInnerWidth`, box-drawing borders.

### 3. Subprocess Output (executor.go + run.go)

- Add `SetStderr(w io.Writer)` to STDIOExecutor
- In `run.go`: pass `io.Discard` by default, `os.Stderr` when `verbose` is true
- Change executor "starting STDIO executor" log from Info to Debug

### 4. Tests (progress_test.go)

Update assertions to match new output format.

## Files Modified

| File | Change |
|------|--------|
| `internal/cli/progress.go` | Aligned steps, compact info card |
| `internal/cli/run.go` | Wire verbose to subprocess stderr |
| `internal/executor/executor.go` | Accept custom stderr, log level change |
| `internal/cli/progress_test.go` | Update to new format |
