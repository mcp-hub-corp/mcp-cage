package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/security-mcp/mcp-client/internal/manifest"
	"github.com/security-mcp/mcp-client/internal/policy"
	"github.com/security-mcp/mcp-client/internal/sandbox"
	"golang.org/x/term"
)

// Additional ANSI constants not declared in prettylog.go
const (
	ansiBold  = "\033[1m"
	ansiGreen = "\033[32m"
	ansiCyan  = "\033[36m"
)

// stepDescWidth is the fixed column width for step descriptions so that
// status indicators and timings align vertically (Docker Build style).
const stepDescWidth = 34

// spinnerFrames are the braille-pattern frames used for the terminal spinner.
var spinnerFrames = [...]string{"\u280b", "\u2819", "\u2839", "\u2838", "\u283c", "\u2834", "\u2826", "\u2827", "\u2807", "\u280f"}

// ProgressUI renders Docker-style step progress to an io.Writer.
// In terminal mode it uses color, spinners, and aligned columns.
// In pipe mode it emits plain, machine-readable text.
type ProgressUI struct {
	w          io.Writer
	isTerm     bool
	totalSteps int
	mu         sync.Mutex
	stepStart  time.Time
	spinCancel chan struct{}
	spinDone   chan struct{}
}

// InfoCardData holds all the data rendered by InfoCard.
type InfoCardData struct {
	Org         string
	Name        string
	Version     string
	Origin      string
	CertLevel   int
	GitSHA      string
	Format      string
	Score       int // -1 means no security metadata
	Findings    *manifest.FindingsSummary
	Limits      *policy.ExecutionLimits
	SandboxName string
	SandboxCaps sandbox.Capabilities
	NoSandbox   bool
}

// NewProgressUI creates a ProgressUI that writes to w.
// Terminal detection uses golang.org/x/term on *os.File writers.
func NewProgressUI(w io.Writer, totalSteps int) *ProgressUI {
	isTerm := false
	if f, ok := w.(*os.File); ok {
		isTerm = term.IsTerminal(int(f.Fd()))
	}
	return &ProgressUI{
		w:          w,
		isTerm:     isTerm,
		totalSteps: totalSteps,
	}
}

// Header prints the run header line.
func (p *ProgressUI) Header(org, name, version string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ref := fmt.Sprintf("%s/%s@%s", org, name, version)
	if p.isTerm {
		fmt.Fprintf(p.w, "%s[+] Running %s%s\n", ansiBold, ref, ansiReset)
	} else {
		fmt.Fprintf(p.w, "[+] Running %s\n", ref)
	}
}

// StepStart begins a new step. In terminal mode it launches a background
// spinner goroutine. In pipe mode it is a no-op (output is deferred to StepDone).
func (p *ProgressUI) StepStart(step int, msg string) {
	p.mu.Lock()
	p.stepStart = time.Now()
	if !p.isTerm {
		p.mu.Unlock()
		return
	}
	p.spinCancel = make(chan struct{})
	p.spinDone = make(chan struct{})
	w := p.w
	prefix := fmt.Sprintf(" => [%d/%d] %-*s ", step, p.totalSteps, stepDescWidth, msg)
	p.mu.Unlock()

	go func() {
		defer close(p.spinDone)
		i := 0
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-p.spinCancel:
				// Clear spinner line
				fmt.Fprintf(w, "\r%s\r", strings.Repeat(" ", len(prefix)+4))
				return
			case <-ticker.C:
				frame := spinnerFrames[i%len(spinnerFrames)]
				fmt.Fprintf(w, "\r%s%s%s%s", ansiCyan, frame, ansiReset, prefix)
				i++
			}
		}
	}()
}

// stopSpinner stops the background spinner and waits for the goroutine to finish.
func (p *ProgressUI) stopSpinner() {
	if p.spinCancel != nil {
		close(p.spinCancel)
		<-p.spinDone
		p.spinCancel = nil
		p.spinDone = nil
	}
}

// StepDone finishes a step with a success marker.
func (p *ProgressUI) StepDone(step int, msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	elapsed := time.Since(p.stepStart)
	p.stopSpinner()
	if p.isTerm {
		fmt.Fprintf(p.w, " => [%d/%d] %-*s %s\u2713%s %s\n",
			step, p.totalSteps, stepDescWidth, msg, ansiGreen, ansiReset, fmtDuration(elapsed))
	} else {
		fmt.Fprintf(p.w, " => [%d/%d] %s done (%s)\n",
			step, p.totalSteps, msg, fmtDuration(elapsed))
	}
}

// StepSkip finishes a step that was skipped.
func (p *ProgressUI) StepSkip(step int, msg, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopSpinner()
	if p.isTerm {
		fmt.Fprintf(p.w, " => [%d/%d] %-*s %s\u25cf%s %s\n",
			step, p.totalSteps, stepDescWidth, msg, ansiYellow, ansiReset, reason)
	} else {
		fmt.Fprintf(p.w, " => [%d/%d] %s %s\n",
			step, p.totalSteps, msg, reason)
	}
}

// StepFail finishes a step with a failure marker.
func (p *ProgressUI) StepFail(step int, msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopSpinner()
	if p.isTerm {
		fmt.Fprintf(p.w, " => [%d/%d] %-*s %s\u2717 failed%s\n",
			step, p.totalSteps, stepDescWidth, msg, ansiRed, ansiReset)
	} else {
		fmt.Fprintf(p.w, " => [%d/%d] %s FAILED\n",
			step, p.totalSteps, msg)
	}
}

// InfoCard renders a security and sandbox information card.
func (p *ProgressUI) InfoCard(d InfoCardData) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isTerm {
		p.infoCardTerm(d)
	} else {
		p.infoCardPlain(d)
	}
}

// ListeningBanner prints the listening message.
func (p *ProgressUI) ListeningBanner(transport string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isTerm {
		fmt.Fprintf(p.w, "\n%s\u25cf MCP server listening (%s)%s %s\u2014 Press Ctrl+C to stop%s\n",
			ansiGreen, transport, ansiReset, ansiDim, ansiReset)
	} else {
		fmt.Fprintf(p.w, "MCP server listening (%s)\n", transport)
	}
}

// ShutdownBanner prints the shutdown message.
func (p *ProgressUI) ShutdownBanner(duration time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isTerm {
		fmt.Fprintf(p.w, "\n%s\u25cf Shutting down...%s done (ran for %s)\n",
			ansiDim, ansiReset, fmtDuration(duration))
	} else {
		fmt.Fprintf(p.w, "Shutting down... done (ran for %s)\n", fmtDuration(duration))
	}
}

// ErrorBanner prints a prominent error message.
func (p *ProgressUI) ErrorBanner(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isTerm {
		fmt.Fprintf(p.w, "\n%s\u2717 Error: %s%s\n", ansiRed, msg, ansiReset)
	} else {
		fmt.Fprintf(p.w, "Error: %s\n", msg)
	}
}

// ---------------------------------------------------------------------------
// Terminal info card (compact, no borders)
// ---------------------------------------------------------------------------

func (p *ProgressUI) infoCardTerm(d InfoCardData) {
	fmt.Fprintln(p.w)

	// Score + Cert line
	if d.Score >= 0 {
		sc := scoreColor(d.Score)
		bar := scoreBar(d.Score)
		certName := certLevelName(d.CertLevel)
		fmt.Fprintf(p.w, "  %sScore %d/100%s %s  Cert %d (%s)\n",
			sc, d.Score, ansiReset, bar, d.CertLevel, certName)
	} else {
		certName := certLevelName(d.CertLevel)
		fmt.Fprintf(p.w, "  Cert %d (%s)\n", d.CertLevel, certName)
	}

	// Origin + SHA + Format on single line
	sha := d.GitSHA
	if len(sha) > 7 {
		sha = sha[:7]
	}
	parts := []string{fmt.Sprintf("Origin: %s", d.Origin)}
	if sha != "" {
		parts = append(parts, fmt.Sprintf("SHA: %s", sha))
	}
	if d.Format != "" {
		parts = append(parts, fmt.Sprintf("Format: %s", d.Format))
	}
	fmt.Fprintf(p.w, "  %s\n", strings.Join(parts, "  "))

	// Findings warning (only if critical or high > 0)
	if d.Findings != nil && (d.Findings.Critical > 0 || d.Findings.High > 0) {
		var findingParts []string
		if d.Findings.Critical > 0 {
			findingParts = append(findingParts, fmt.Sprintf("%d critical", d.Findings.Critical))
		}
		if d.Findings.High > 0 {
			findingParts = append(findingParts, fmt.Sprintf("%d high", d.Findings.High))
		}
		color := ansiYellow
		if d.Findings.Critical > 0 {
			color = ansiRed
		}
		fmt.Fprintf(p.w, "  %s\u26a0 %s findings%s\n", color, strings.Join(findingParts, ", "), ansiReset)
	}

	fmt.Fprintln(p.w)

	// Sandbox
	if d.NoSandbox {
		fmt.Fprintf(p.w, "  %sSandbox: disabled%s\n", ansiRed, ansiReset)
	} else {
		caps := d.SandboxCaps
		var active []string
		if caps.CPULimit {
			active = append(active, fmt.Sprintf("cpu:%s\u2713%s", ansiGreen, ansiReset))
		}
		if caps.MemoryLimit {
			active = append(active, fmt.Sprintf("mem:%s\u2713%s", ansiGreen, ansiReset))
		}
		if caps.PIDLimit {
			active = append(active, fmt.Sprintf("pid:%s\u2713%s", ansiGreen, ansiReset))
		}
		if caps.FDLimit {
			active = append(active, fmt.Sprintf("fd:%s\u2713%s", ansiGreen, ansiReset))
		}
		if caps.NetworkIsolation {
			active = append(active, fmt.Sprintf("net:%s\u2713%s", ansiGreen, ansiReset))
		}
		if caps.FilesystemIsolation {
			active = append(active, fmt.Sprintf("fs:%s\u2713%s", ansiGreen, ansiReset))
		}
		if caps.SupportsSandboxExec {
			active = append(active, fmt.Sprintf("exec:%s\u2713%s", ansiGreen, ansiReset))
		}
		if caps.Cgroups {
			active = append(active, fmt.Sprintf("cgroups:%s\u2713%s", ansiGreen, ansiReset))
		}
		if caps.Namespaces {
			active = append(active, fmt.Sprintf("ns:%s\u2713%s", ansiGreen, ansiReset))
		}
		if caps.SupportsSeccomp {
			active = append(active, fmt.Sprintf("seccomp:%s\u2713%s", ansiGreen, ansiReset))
		}
		if caps.SupportsLandlock {
			active = append(active, fmt.Sprintf("landlock:%s\u2713%s", ansiGreen, ansiReset))
		}

		if len(active) > 0 {
			fmt.Fprintf(p.w, "  Sandbox: %s  (%s)\n", d.SandboxName, strings.Join(active, " "))
		} else {
			fmt.Fprintf(p.w, "  Sandbox: %s\n", d.SandboxName)
		}
	}

	// Limits
	if d.Limits != nil {
		fmt.Fprintf(p.w, "  Limits: cpu=%dm mem=%s timeout=%s pids=%d\n",
			d.Limits.MaxCPU, d.Limits.MaxMemory,
			fmtDuration(d.Limits.Timeout), d.Limits.MaxPIDs)
	}

	// Platform warnings
	if !d.NoSandbox {
		for _, w := range d.SandboxCaps.Warnings {
			fmt.Fprintf(p.w, "  %s\u26a0 %s%s\n", ansiYellow, w, ansiReset)
		}
	}
}

// ---------------------------------------------------------------------------
// Plain (pipe) info card
// ---------------------------------------------------------------------------

func (p *ProgressUI) infoCardPlain(d InfoCardData) {
	if d.Score >= 0 {
		certName := certLevelName(d.CertLevel)
		fmt.Fprintf(p.w, "Score: %d/100 | Cert: %d (%s) | Origin: %s\n",
			d.Score, d.CertLevel, certName, d.Origin)
	} else {
		fmt.Fprintf(p.w, "Cert: %d (%s) | Origin: %s\n",
			d.CertLevel, certLevelName(d.CertLevel), d.Origin)
	}

	if d.Limits != nil {
		fmt.Fprintf(p.w, "Limits: CPU=%dm Memory=%s PIDs=%d FDs=%d Timeout=%s\n",
			d.Limits.MaxCPU, d.Limits.MaxMemory,
			d.Limits.MaxPIDs, d.Limits.MaxFDs,
			fmtDuration(d.Limits.Timeout))
	}

	sandboxLine := d.SandboxName
	if d.NoSandbox {
		sandboxLine = "disabled"
	}
	if !d.NoSandbox {
		caps := d.SandboxCaps
		fmt.Fprintf(p.w, "Sandbox: %s (CPU=%s Mem=%s PID=%s FD=%s Net=%s FS=%s)\n",
			sandboxLine,
			yn(caps.CPULimit), yn(caps.MemoryLimit),
			yn(caps.PIDLimit), yn(caps.FDLimit),
			yn(caps.NetworkIsolation), yn(caps.FilesystemIsolation))
	} else {
		fmt.Fprintf(p.w, "Sandbox: %s\n", sandboxLine)
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// certLevelName maps a certification level (0-3) to its human-readable name.
func certLevelName(level int) string {
	switch level {
	case 0:
		return "Integrity Verified"
	case 1:
		return "Static Verified"
	case 2:
		return "Security Certified"
	case 3:
		return "Runtime Certified"
	default:
		return "Unknown"
	}
}

// scoreBar returns a 5-dot visual bar where filled dots represent the
// score in 20-point increments and empty dots fill the remainder.
func scoreBar(score int) string {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	filled := score / 20
	empty := 5 - filled
	return strings.Repeat("\u25cf", filled) + strings.Repeat("\u25cb", empty)
}

// scoreColor returns the ANSI color escape for a given score.
func scoreColor(score int) string {
	switch {
	case score >= 70:
		return ansiGreen
	case score >= 40:
		return ansiYellow
	default:
		return ansiRed
	}
}

// fmtDuration formats a duration in a human-friendly compact form.
func fmtDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	return fmt.Sprintf("%dm %ds", m, s)
}

// yn returns "yes" or "no" for a boolean.
func yn(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
