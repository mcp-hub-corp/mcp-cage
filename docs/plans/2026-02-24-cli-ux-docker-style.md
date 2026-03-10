# Docker-style CLI UX for `mcp run` Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace plain slog output in `mcp run` with Docker-style step progress (spinners/checkmarks), always-visible sandbox controls, graceful SIGINT handling, and a "listening" banner.

**Architecture:** New `ProgressUI` struct handles all visual output to stderr using ANSI spinners and colors. The `runMCPServer` function is refactored to use `ProgressUI` steps instead of `slog.Info`. Signal handling wraps the executor to intercept Ctrl+C and show a clean shutdown message. The existing security summary box is replaced by an always-visible compact info card showing score, cert level, sandbox capabilities, and applied limits.

**Tech Stack:** Go stdlib (`os/signal`, `sync`, `time`), `golang.org/x/term` (already in go.mod) for terminal detection. No new dependencies.

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `internal/cli/progress.go` | CREATE | `ProgressUI` with spinner, step tracking, info card |
| `internal/cli/progress_test.go` | CREATE | Tests for `ProgressUI` rendering |
| `internal/cli/run.go` | MODIFY | Replace slog calls with ProgressUI, add signal handling, show sandbox always |
| `internal/cli/run.go` | MODIFY | Remove old `printSecurityBanner` / `printSecuritySummary` (replaced by ProgressUI card) |

---

### Task 1: Create `ProgressUI` struct with step rendering

**Files:**
- Create: `internal/cli/progress.go`
- Create: `internal/cli/progress_test.go`

**Step 1: Write the test for ProgressUI step rendering**

```go
// internal/cli/progress_test.go
package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProgressUI_StepSuccess(t *testing.T) {
	var buf bytes.Buffer
	ui := NewProgressUI(&buf, false) // non-terminal mode (no ANSI)

	ui.StepStart("Resolving package", "cr0hn/mcp-schrodinger")
	ui.StepDone("Resolving package", "cr0hn/mcp-schrodinger")

	output := buf.String()
	assert.Contains(t, output, "Resolving package")
	assert.Contains(t, output, "cr0hn/mcp-schrodinger")
}

func TestProgressUI_StepFail(t *testing.T) {
	var buf bytes.Buffer
	ui := NewProgressUI(&buf, false)

	ui.StepStart("Resolving package", "")
	ui.StepFail("Resolving package", "404 not found")

	output := buf.String()
	assert.Contains(t, output, "Resolving package")
	assert.Contains(t, output, "404 not found")
}

func TestProgressUI_MultipleSteps(t *testing.T) {
	var buf bytes.Buffer
	ui := NewProgressUI(&buf, false)

	steps := []struct{ name, detail string }{
		{"Resolving package", "cr0hn/test"},
		{"Downloading manifest", "sha256:abc123..."},
		{"Downloading bundle", "sha256:def456... (2.3 MB)"},
	}
	for _, s := range steps {
		ui.StepStart(s.name, s.detail)
		ui.StepDone(s.name, s.detail)
	}

	output := buf.String()
	for _, s := range steps {
		assert.Contains(t, output, s.name)
	}
	// Verify order
	idx1 := strings.Index(output, "Resolving")
	idx2 := strings.Index(output, "Downloading manifest")
	idx3 := strings.Index(output, "Downloading bundle")
	assert.Less(t, idx1, idx2)
	assert.Less(t, idx2, idx3)
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/cr0hn/Dropbox/Projects/mcp-hub-platform/mcp-cage && go test ./internal/cli/ -run TestProgressUI -v -count=1`
Expected: FAIL - `NewProgressUI` not defined

**Step 3: Implement `ProgressUI`**

```go
// internal/cli/progress.go
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// ANSI codes for progress display
const (
	pColorReset   = "\033[0m"
	pColorBold    = "\033[1m"
	pColorDim     = "\033[2m"
	pColorRed     = "\033[31m"
	pColorGreen   = "\033[32m"
	pColorYellow  = "\033[33m"
	pColorBlue    = "\033[34m"
	pColorCyan    = "\033[36m"
	pColorWhite   = "\033[37m"
	pClearLine    = "\033[2K\r"
)

// Braille spinner frames
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// ProgressUI renders Docker-style step progress to a writer (typically stderr).
type ProgressUI struct {
	w          io.Writer
	mu         sync.Mutex
	isTerminal bool
	spinning   bool
	stopCh     chan struct{}
}

// NewProgressUI creates a ProgressUI. If isTerm is explicitly set, it overrides detection.
// Pass isTerm=true for terminals, false for tests/pipes.
func NewProgressUI(w io.Writer, isTerm bool) *ProgressUI {
	isTerminal := isTerm
	if f, ok := w.(*os.File); ok {
		isTerminal = term.IsTerminal(int(f.Fd()))
	}
	return &ProgressUI{
		w:          w,
		isTerminal: isTerminal,
	}
}

// Header prints a package header line.
func (p *ProgressUI) Header(pkg, version string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isTerminal {
		fmt.Fprintf(p.w, "\n  %s%smcp run%s %s%s@%s%s\n\n", pColorBold, pColorCyan, pColorReset, pColorBold, pkg, version, pColorReset)
	} else {
		fmt.Fprintf(p.w, "\nmcp run %s@%s\n\n", pkg, version)
	}
}

// StepStart prints a step starting line. In terminal mode, shows a spinner.
func (p *ProgressUI) StepStart(name, detail string) {
	p.stopSpinner()
	p.mu.Lock()
	if p.isTerminal {
		line := p.formatStep("⠋", pColorCyan, name, detail)
		fmt.Fprint(p.w, line)
		p.mu.Unlock()
		p.startSpinner(name, detail)
	} else {
		fmt.Fprintf(p.w, "  - %s", name)
		if detail != "" {
			fmt.Fprintf(p.w, "  %s", detail)
		}
		p.mu.Unlock()
	}
}

// StepDone marks a step as completed with a green checkmark.
func (p *ProgressUI) StepDone(name, detail string) {
	p.stopSpinner()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isTerminal {
		fmt.Fprintf(p.w, "%s", pClearLine)
		line := p.formatStep("✓", pColorGreen, name, detail)
		fmt.Fprintln(p.w, line)
	} else {
		fmt.Fprintf(p.w, " ... done\n")
	}
}

// StepFail marks a step as failed with a red cross.
func (p *ProgressUI) StepFail(name, detail string) {
	p.stopSpinner()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isTerminal {
		fmt.Fprintf(p.w, "%s", pClearLine)
		line := p.formatStep("✗", pColorRed, name, detail)
		fmt.Fprintln(p.w, line)
	} else {
		fmt.Fprintf(p.w, " ... FAILED: %s\n", detail)
	}
}

// StepSkip marks a step as skipped (cached).
func (p *ProgressUI) StepSkip(name, detail string) {
	p.stopSpinner()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isTerminal {
		fmt.Fprintf(p.w, "%s", pClearLine)
		line := p.formatStep("●", pColorBlue, name, detail)
		fmt.Fprintln(p.w, line)
	} else {
		fmt.Fprintf(p.w, "  - %s  %s (cached)\n", name, detail)
	}
}

// formatStep builds a formatted step line with icon, color, name, and detail.
func (p *ProgressUI) formatStep(icon, color, name, detail string) string {
	const nameWidth = 30
	paddedName := name
	if len(paddedName) < nameWidth {
		paddedName += strings.Repeat(" ", nameWidth-len(paddedName))
	}
	if detail != "" {
		return fmt.Sprintf("  %s%s%s %s%s%s  %s%s%s",
			color, icon, pColorReset,
			pColorWhite, paddedName, pColorReset,
			pColorDim, detail, pColorReset)
	}
	return fmt.Sprintf("  %s%s%s %s%s%s",
		color, icon, pColorReset,
		pColorWhite, paddedName, pColorReset)
}

func (p *ProgressUI) startSpinner(name, detail string) {
	p.stopCh = make(chan struct{})
	p.spinning = true
	go func() {
		i := 0
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-p.stopCh:
				return
			case <-ticker.C:
				p.mu.Lock()
				frame := spinnerFrames[i%len(spinnerFrames)]
				line := p.formatStep(frame, pColorCyan, name, detail)
				fmt.Fprintf(p.w, "%s%s", pClearLine, line)
				p.mu.Unlock()
				i++
			}
		}
	}()
}

func (p *ProgressUI) stopSpinner() {
	if p.spinning && p.stopCh != nil {
		close(p.stopCh)
		p.spinning = false
		// Small delay to let goroutine exit
		time.Sleep(10 * time.Millisecond)
	}
}

// InfoCard renders the security + sandbox info box (always visible).
func (p *ProgressUI) InfoCard(info InfoCardData) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.isTerminal {
		p.printInfoCardPlain(info)
		return
	}
	p.printInfoCardColor(info)
}

// InfoCardData holds all data for the info card.
type InfoCardData struct {
	Org          string
	Name         string
	Version      string
	Origin       string
	Score        int
	CertLevel    int
	ToolCount    int
	CritFindings int
	HighFindings int
	// Limits
	MaxCPU    int
	MaxMemory string
	MaxPIDs   int
	MaxFDs    int
	Timeout   time.Duration
	// Sandbox
	SandboxName         string
	NoSandbox           bool
	CPULimit            bool
	MemoryLimit         bool
	PIDLimit            bool
	FDLimit             bool
	NetworkIsolation    bool
	FilesystemIsolation bool
	SupportsSandboxExec bool
	SupportsSeccomp     bool
	SupportsLandlock    bool
	Cgroups             bool
	Namespaces          bool
	ProcessIsolation    bool
	Warnings            []string
}

func (p *ProgressUI) printInfoCardColor(info InfoCardData) {
	w := p.w
	const boxW = 52
	border := strings.Repeat("─", boxW)

	// Score color
	scoreColor := pColorGreen
	if info.Score < 60 {
		scoreColor = pColorRed
	} else if info.Score < 80 {
		scoreColor = pColorYellow
	}

	fmt.Fprintf(w, "\n  %s┌%s┐%s\n", pColorCyan, border, pColorReset)

	// Security header
	scoreStr := fmt.Sprintf("Score: %s%d/100%s  |  Cert Level %d  |  %d tools",
		scoreColor, info.Score, pColorReset, info.CertLevel, info.ToolCount)
	fmt.Fprintf(w, "  %s│%s  🛡️  %s%s%s│%s\n", pColorCyan, pColorReset, scoreStr,
		strings.Repeat(" ", max(0, boxW-visualLen(scoreStr)-6)), pColorCyan, pColorReset)

	// Findings
	if info.CritFindings > 0 || info.HighFindings > 0 {
		findStr := fmt.Sprintf("%s%d critical%s, %d high findings",
			pColorRed, info.CritFindings, pColorReset, info.HighFindings)
		fmt.Fprintf(w, "  %s│%s       %s%s%s│%s\n", pColorCyan, pColorReset, findStr,
			strings.Repeat(" ", max(0, boxW-visualLen(findStr)-9)), pColorCyan, pColorReset)
	} else {
		noFind := fmt.Sprintf("%s0 critical findings%s", pColorGreen, pColorReset)
		fmt.Fprintf(w, "  %s│%s       %s%s%s│%s\n", pColorCyan, pColorReset, noFind,
			strings.Repeat(" ", max(0, boxW-visualLen(noFind)-9)), pColorCyan, pColorReset)
	}

	// Separator: Sandbox section
	fmt.Fprintf(w, "  %s├%s┤%s\n", pColorCyan, border, pColorReset)

	// Sandbox header
	if info.NoSandbox {
		sbHead := fmt.Sprintf("%s%sSandbox: DISABLED (--no-sandbox)%s", pColorBold, pColorYellow, pColorReset)
		fmt.Fprintf(w, "  %s│%s  %s%s%s│%s\n", pColorCyan, pColorReset, sbHead,
			strings.Repeat(" ", max(0, boxW-34)), pColorCyan, pColorReset)
	} else {
		sbHead := fmt.Sprintf("%sSandbox: %s%s", pColorBold, info.SandboxName, pColorReset)
		fmt.Fprintf(w, "  %s│%s  %s%s%s│%s\n", pColorCyan, pColorReset, sbHead,
			strings.Repeat(" ", max(0, boxW-visualLen(sbHead)-4)), pColorCyan, pColorReset)
	}

	// Limits with capability status
	printLimitLine := func(label string, value string, capable bool) {
		mark := fmt.Sprintf("%s✓%s", pColorGreen, pColorReset)
		if !capable {
			mark = fmt.Sprintf("%s✗%s", pColorRed, pColorReset)
		}
		content := fmt.Sprintf("  [%s] %-22s %s", mark, label, value)
		vis := 6 + len(label) + 24 - len(label) + len(value) // approximate
		pad := max(0, boxW-vis+2)
		fmt.Fprintf(w, "  %s│%s%s%s%s│%s\n", pColorCyan, pColorReset, content, strings.Repeat(" ", pad), pColorCyan, pColorReset)
	}

	printLimitLine("CPU Limit", fmt.Sprintf("%d millicores", info.MaxCPU), info.CPULimit)
	printLimitLine("Memory Limit", info.MaxMemory, info.MemoryLimit)
	printLimitLine("PID Limit", fmt.Sprintf("%d", info.MaxPIDs), info.PIDLimit)
	printLimitLine("FD Limit", fmt.Sprintf("%d", info.MaxFDs), info.FDLimit)
	printLimitLine("Network Isolation", boolToAvail(info.NetworkIsolation), info.NetworkIsolation)
	printLimitLine("Filesystem Isolation", boolToAvail(info.FilesystemIsolation), info.FilesystemIsolation)

	// Timeout line
	timeoutStr := fmt.Sprintf("    Timeout: %s", info.Timeout)
	fmt.Fprintf(w, "  %s│%s%s%s%s│%s\n", pColorCyan, pColorReset, timeoutStr,
		strings.Repeat(" ", max(0, boxW-len(timeoutStr))), pColorCyan, pColorReset)

	// Warnings
	if len(info.Warnings) > 0 || info.NoSandbox {
		fmt.Fprintf(w, "  %s├%s┤%s\n", pColorCyan, border, pColorReset)
		if info.NoSandbox {
			warnStr := fmt.Sprintf("    %s⚠  Sandbox disabled! No process isolation%s", pColorYellow, pColorReset)
			fmt.Fprintf(w, "  %s│%s%s%s%s│%s\n", pColorCyan, pColorReset, warnStr,
				strings.Repeat(" ", max(0, boxW-visualLen(warnStr))), pColorCyan, pColorReset)
		}
		for _, w2 := range info.Warnings {
			warnStr := fmt.Sprintf("    %s⚠  %s%s", pColorYellow, w2, pColorReset)
			fmt.Fprintf(w, "  %s│%s%s%s%s│%s\n", pColorCyan, pColorReset, warnStr,
				strings.Repeat(" ", max(0, boxW-visualLen(warnStr))), pColorCyan, pColorReset)
		}
	}

	fmt.Fprintf(w, "  %s└%s┘%s\n", pColorCyan, border, pColorReset)
}

func (p *ProgressUI) printInfoCardPlain(info InfoCardData) {
	w := p.w
	fmt.Fprintf(w, "\n  Score: %d/100 | Cert Level %d | %d tools | %d critical findings\n", info.Score, info.CertLevel, info.ToolCount, info.CritFindings)
	if info.NoSandbox {
		fmt.Fprintf(w, "  Sandbox: DISABLED\n")
	} else {
		fmt.Fprintf(w, "  Sandbox: %s\n", info.SandboxName)
	}
	fmt.Fprintf(w, "  Limits: CPU=%d mem=%s PIDs=%d FDs=%d timeout=%s\n", info.MaxCPU, info.MaxMemory, info.MaxPIDs, info.MaxFDs, info.Timeout)
}

// ListeningBanner prints the final "server started" message.
func (p *ProgressUI) ListeningBanner() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isTerminal {
		fmt.Fprintf(p.w, "\n  %s%sMCP server started and listening (stdio)%s\n", pColorBold, pColorGreen, pColorReset)
		fmt.Fprintf(p.w, "  %sPress Ctrl+C to stop%s\n\n", pColorDim, pColorReset)
	} else {
		fmt.Fprintf(p.w, "\nMCP server started and listening (stdio)\n")
	}
}

// ShutdownBanner prints the shutdown message.
func (p *ProgressUI) ShutdownBanner(duration time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isTerminal {
		fmt.Fprintf(p.w, "\n  %sShutting down MCP server...%s\n", pColorDim, pColorReset)
		fmt.Fprintf(p.w, "  %s✓%s MCP server stopped %s(ran for %s)%s\n\n", pColorGreen, pColorReset, pColorDim, formatDuration(duration), pColorReset)
	} else {
		fmt.Fprintf(p.w, "\nMCP server stopped (ran for %s)\n", formatDuration(duration))
	}
}

// ErrorBanner prints a prominent error.
func (p *ProgressUI) ErrorBanner(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isTerminal {
		fmt.Fprintf(p.w, "\n  %s%s✗ Error: %s%s\n\n", pColorBold, pColorRed, msg, pColorReset)
	} else {
		fmt.Fprintf(p.w, "\nError: %s\n", msg)
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if m >= 60 {
		h := m / 60
		m = m % 60
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	return fmt.Sprintf("%dm %ds", m, s)
}

func boolToAvail(b bool) string {
	if b {
		return "enabled"
	}
	return "not available"
}

// visualLen calculates the visual length of a string, ignoring ANSI escape codes.
func visualLen(s string) int {
	n := 0
	inEscape := false
	for _, r := range s {
		if r == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}
		n++
	}
	return n
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
```

**Step 4: Run tests to verify they pass**

Run: `cd /Users/cr0hn/Dropbox/Projects/mcp-hub-platform/mcp-cage && go test ./internal/cli/ -run TestProgressUI -v -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/cli/progress.go internal/cli/progress_test.go
git commit -m "feat(client): add ProgressUI with Docker-style step rendering"
```

---

### Task 2: Refactor `runMCPServer` to use ProgressUI and show sandbox info always

**Files:**
- Modify: `internal/cli/run.go`

This is the main refactor. The key changes are:

1. Replace all `logger.Info(...)` calls with `ui.StepStart/StepDone` calls
2. Move sandbox info card from `-v` only to always-visible
3. Add signal handling (SIGINT/SIGTERM) around the executor
4. Show "MCP server started and listening" banner before execution
5. Show clean shutdown/completion message
6. Remove old `printSecurityBanner` and `printSecuritySummary` functions (replaced by `InfoCard`)
7. Suppress child process stderr during SIGINT shutdown to hide Python tracebacks

**Step 1: Refactor `runMCPServer` to use ProgressUI**

Key changes in `runMCPServer`:

```go
// At top of runMCPServer, create the UI
ui := NewProgressUI(os.Stderr, false) // auto-detect terminal
ui.Header(fmt.Sprintf("%s/%s", org, name), version)

// Replace:  logger.Info("resolving package", ...)
// With:     ui.StepStart("Resolving package", fmt.Sprintf("%s/%s", org, name))
//           ... do the work ...
//           ui.StepDone("Resolving package", fmt.Sprintf("%s/%s", org, name))

// For cache hits, use:
//           ui.StepSkip("Downloading manifest", "cached")
```

Replace signal handling around executor:

```go
// Set up signal handling
sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
defer signal.Stop(sigCh)

// Show listening banner
ui.ListeningBanner()

// Run executor in a goroutine so we can catch signals
execDone := make(chan error, 1)
go func() {
    execDone <- stdioExec.Execute(ctx, ep, bundleRoot)
}()

// Wait for either completion or signal
select {
case execErr = <-execDone:
    // Normal completion
case sig := <-sigCh:
    // Graceful shutdown
    logger.Debug("received signal", slog.String("signal", sig.String()))
    cancel() // Cancel context to stop the process
    execErr = <-execDone // Wait for process to actually exit
    ui.ShutdownBanner(time.Since(startTime))
    return nil // Clean exit on signal
}
```

**Step 2: Build InfoCardData from existing variables and show always**

Replace the conditional `if verbose { printSecuritySummary(...) }` block:

```go
sb := sandbox.New()
caps := sb.Capabilities()

cardData := InfoCardData{
    Org: org, Name: name, Version: resolvedVersion, Origin: origin,
    Score: 0, CertLevel: certLevel, ToolCount: 0, CritFindings: 0,
    MaxCPU: limits.MaxCPU, MaxMemory: limits.MaxMemory,
    MaxPIDs: limits.MaxPIDs, MaxFDs: limits.MaxFDs, Timeout: limits.Timeout,
    SandboxName: sb.Name(), NoSandbox: runFlags.noSandbox,
    CPULimit: caps.CPULimit, MemoryLimit: caps.MemoryLimit,
    PIDLimit: caps.PIDLimit, FDLimit: caps.FDLimit,
    NetworkIsolation: caps.NetworkIsolation,
    FilesystemIsolation: caps.FilesystemIsolation,
    SupportsSandboxExec: caps.SupportsSandboxExec,
    SupportsSeccomp: caps.SupportsSeccomp,
    SupportsLandlock: caps.SupportsLandlock,
    Cgroups: caps.Cgroups, Namespaces: caps.Namespaces,
    ProcessIsolation: caps.ProcessIsolation,
    Warnings: caps.Warnings,
}

// Fill security meta if available
if mf.SecurityMeta != nil {
    cardData.Score = mf.SecurityMeta.Score
    if mf.SecurityMeta.Capabilities != nil {
        cardData.ToolCount = len(mf.SecurityMeta.Capabilities.Tools)
    }
    if mf.SecurityMeta.Findings != nil {
        cardData.CritFindings = mf.SecurityMeta.Findings.Critical
        cardData.HighFindings = mf.SecurityMeta.Findings.High
    }
}

ui.InfoCard(cardData)
```

**Step 3: Remove old functions**

Delete these functions from `run.go` (they are fully replaced by `ProgressUI.InfoCard`):
- `printSecurityBanner`
- `printSecuritySummary`
- `printField`
- `printSecCapability`
- `printWarning`
- The ANSI color constants block at line 628 (duplicated in `progress.go`)

**Step 4: Run all tests**

Run: `cd /Users/cr0hn/Dropbox/Projects/mcp-hub-platform/mcp-cage && go test ./internal/cli/ -v -count=1`
Expected: PASS (all existing tests + new tests)

**Step 5: Build and verify**

Run: `cd /Users/cr0hn/Dropbox/Projects/mcp-hub-platform/mcp-cage && go build -o mcp ./cmd/mcp/`
Expected: Binary builds successfully

**Step 6: Commit**

```bash
git add internal/cli/run.go
git commit -m "feat(client): Docker-style progress, always-visible sandbox info, graceful SIGINT"
```

---

### Task 3: Update CHANGELOG.md

**Files:**
- Modify: `CHANGELOG.md`

Add entry describing the new CLI UX improvements.

**Step 1: Add changelog entry**

```markdown
## [Unreleased] - 2026-02-24

### Changed
- `mcp run`: Docker-style step progress with spinners and checkmarks
- `mcp run`: Always show sandbox controls and applied limits (not just with -v)
- `mcp run`: Compact security info card with color-coded score
- `mcp run`: "MCP server started and listening" banner when ready
- `mcp run`: Graceful Ctrl+C handling with clean shutdown message (no Python tracebacks)
```

**Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs(client): changelog for Docker-style CLI UX"
```
