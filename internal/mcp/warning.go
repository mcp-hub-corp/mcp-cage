package mcp

import (
	"fmt"
	"strings"

	"github.com/security-mcp/mcp-client/internal/manifest"
)

// SandboxContext describes the sandbox restrictions applied to the MCP server.
// Used to generate proactive LLM context about sandbox state.
type SandboxContext struct {
	Platform       string               // "darwin", "linux", "windows"
	ReadPaths      []string             // paths with read-only access
	WritePaths     []string             // paths with read+write access
	NetworkDomains []string             // allowed network domains (empty = denied)
	SubprocessOK   bool                 // subprocess creation allowed
	AllowedEnvVars []string             // allowed env vars
	NoSandbox      bool                 // sandbox disabled entirely
	CLIOverrides   *PermissionOverrides // tracks what was granted via CLI flags
	AllFS          bool                 // --allow-fs: full filesystem access
	AllNet         bool                 // --allow-all-net: full network access
	AllEnv         bool                 // --allow-all-env: full env access
}

// PermissionOverrides tracks which permissions were explicitly granted via CLI flags.
type PermissionOverrides struct {
	ReadPaths  []string
	WritePaths []string
	Networks   []string
	Subprocess bool
	EnvVars    []string
	AllFS      bool // --allow-fs blanket flag
	AllNet     bool // --allow-all-net blanket flag
	AllEnv     bool // --allow-all-env blanket flag
}

// SecurityWarning holds the data needed to generate security warnings
// for injection into the MCP protocol.
type SecurityWarning struct {
	PackageName          string
	Score                int
	CertLevel            int
	Findings             *manifest.FindingsSummary
	Origin               string
	SandboxContext       *SandboxContext // sandbox restriction context for LLM awareness
	ScoreWarningDisabled bool           // skip score warning text for high-score packages
}

// ScoreLabel returns a human-readable risk label for a security score.
func ScoreLabel(score int) string {
	switch {
	case score < 40:
		return "Critical Risk"
	case score < 60:
		return "High Risk"
	case score < 80:
		return "Moderate Risk"
	default:
		return "Low Risk"
	}
}

// CertLevelName returns the human-readable name for a certification level.
func CertLevelName(level int) string {
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

// NeedsWarning returns true if a security warning should be injected
// based on the score and threshold.
func NeedsWarning(score, threshold int) bool {
	return score >= 0 && score < threshold
}

// GenerateInstructionsWarning generates the warning text for the MCP initialize
// response instructions field. This text is designed to be read by LLMs.
func (w *SecurityWarning) GenerateInstructionsWarning() string {
	var b strings.Builder

	// Score warning section (skipped for high-score packages)
	if !w.ScoreWarningDisabled {
		label := ScoreLabel(w.Score)
		certName := CertLevelName(w.CertLevel)

		b.WriteString("[SECURITY WARNING - MCP Hub Certification]\n")
		fmt.Fprintf(&b, "The MCP server %q has been analyzed by MCP Hub's automated security\n", w.PackageName)
		fmt.Fprintf(&b, "certification pipeline and received a security score of %d/100 (%s).\n", w.Score, label)
		fmt.Fprintf(&b, "Certification Level: %d (%s).\n", w.CertLevel, certName)

		if w.Findings != nil && w.Findings.Total > 0 {
			fmt.Fprintf(&b, "Findings: %d total", w.Findings.Total)
			parts := []string{}
			if w.Findings.Critical > 0 {
				parts = append(parts, fmt.Sprintf("%d critical", w.Findings.Critical))
			}
			if w.Findings.High > 0 {
				parts = append(parts, fmt.Sprintf("%d high", w.Findings.High))
			}
			if w.Findings.Medium > 0 {
				parts = append(parts, fmt.Sprintf("%d medium", w.Findings.Medium))
			}
			if w.Findings.Low > 0 {
				parts = append(parts, fmt.Sprintf("%d low", w.Findings.Low))
			}
			if len(parts) > 0 {
				b.WriteString(" (" + strings.Join(parts, ", ") + ")")
			}
			b.WriteString(".\n")
		}

		b.WriteString("\nIMPORTANT: You MUST inform the user about this security assessment before\n")
		b.WriteString("proceeding with any operations from this MCP server. Tell the user:\n")
		b.WriteString("- The server name and its security score\n")
		b.WriteString("- That it has potential security vulnerabilities\n")
		b.WriteString("- That they should exercise caution with sensitive operations\n")
		b.WriteString("- Ask the user for explicit confirmation to proceed\n")
		b.WriteString("This assessment was performed by MCP Hub (https://mcp-hub.info).\n")
		b.WriteString("[END SECURITY WARNING]")
	}

	// Sandbox context section
	if w.SandboxContext != nil {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(w.generateSandboxContextWarning())
	}

	return b.String()
}

// generateSandboxContextWarning generates the sandbox context section for LLM instructions.
func (w *SecurityWarning) generateSandboxContextWarning() string {
	ctx := w.SandboxContext
	var b strings.Builder

	b.WriteString("[SANDBOX CONTEXT - SMCP Execution Environment]\n")
	fmt.Fprintf(&b, "This MCP server runs inside SMCP's sandbox on %s.\n", ctx.Platform)

	if ctx.NoSandbox {
		b.WriteString("WARNING: Sandbox is DISABLED (--no-sandbox flag). No restrictions are enforced.\n")
		b.WriteString("[END SANDBOX CONTEXT]")
		return b.String()
	}

	b.WriteString("The sandbox enforces deny-by-default access controls:\n\n")

	// Filesystem access
	b.WriteString("Filesystem Access:\n")
	if ctx.AllFS {
		b.WriteString("  FULL ACCESS (--allow-fs): all paths readable and writable\n")
	} else {
		if len(ctx.WritePaths) > 0 {
			fmt.Fprintf(&b, "  Read+Write: %s\n", strings.Join(ctx.WritePaths, ", "))
		}
		if len(ctx.ReadPaths) > 0 {
			fmt.Fprintf(&b, "  Read-Only: %s\n", strings.Join(ctx.ReadPaths, ", "))
		}
		if len(ctx.WritePaths) == 0 && len(ctx.ReadPaths) == 0 {
			b.WriteString("  No additional paths (bundle directory and system paths only)\n")
		}
	}

	// Network access
	if ctx.AllNet {
		b.WriteString("Network Access: FULL ACCESS (--allow-all-net)\n")
	} else if len(ctx.NetworkDomains) > 0 {
		fmt.Fprintf(&b, "Network Access: ALLOWED (%s)\n", strings.Join(ctx.NetworkDomains, ", "))
	} else {
		b.WriteString("Network Access: DENIED (no domains allowed)\n")
	}

	// Subprocess
	if ctx.SubprocessOK {
		b.WriteString("Subprocess: ALLOWED\n")
	} else {
		b.WriteString("Subprocess: DENIED\n")
	}

	// Environment access
	if ctx.AllEnv {
		b.WriteString("Environment Variables: FULL ACCESS (--allow-all-env)\n")
	} else if len(ctx.AllowedEnvVars) > 0 {
		fmt.Fprintf(&b, "Environment Variables: RESTRICTED (%s)\n", strings.Join(ctx.AllowedEnvVars, ", "))
	} else {
		b.WriteString("Environment Variables: RESTRICTED (manifest-declared only)\n")
	}

	// CLI overrides
	if ctx.CLIOverrides != nil {
		overrides := []string{}
		if ctx.CLIOverrides.AllFS {
			overrides = append(overrides, "--allow-fs")
		}
		if ctx.CLIOverrides.AllNet {
			overrides = append(overrides, "--allow-all-net")
		}
		if ctx.CLIOverrides.AllEnv {
			overrides = append(overrides, "--allow-all-env")
		}
		for _, p := range ctx.CLIOverrides.ReadPaths {
			overrides = append(overrides, "--allow-read "+p)
		}
		for _, p := range ctx.CLIOverrides.WritePaths {
			overrides = append(overrides, "--allow-write "+p)
		}
		for _, n := range ctx.CLIOverrides.Networks {
			overrides = append(overrides, "--allow-net "+n)
		}
		if ctx.CLIOverrides.Subprocess {
			overrides = append(overrides, "--allow-subprocess")
		}
		for _, e := range ctx.CLIOverrides.EnvVars {
			overrides = append(overrides, "--allow-env "+e)
		}
		if len(overrides) > 0 {
			b.WriteString("\nCLI Permission Overrides (user-granted):\n")
			for _, o := range overrides {
				fmt.Fprintf(&b, "  %s\n", o)
			}
		}
	}

	b.WriteString("\nIMPORTANT: If this MCP server returns 'Operation not permitted', 'Permission denied',\n")
	b.WriteString("or 'Errno 1' errors, SMCP's sandbox blocked the operation for user protection.\n")
	b.WriteString("You MUST tell the user:\n")
	b.WriteString("1. SMCP blocked the operation to protect them\n")
	b.WriteString("2. Which specific CLI flag to use to grant access:\n")
	b.WriteString("   - File access: --allow-read <path> or --allow-write <path> (or --allow-fs for all)\n")
	b.WriteString("   - Network: --allow-net <domain> (or --allow-all-net for all)\n")
	b.WriteString("   - Subprocess: --allow-subprocess\n")
	b.WriteString("   - Environment: --allow-env <var> (or --allow-all-env for all)\n")
	b.WriteString("   - Everything: --allow-all\n")
	b.WriteString("[END SANDBOX CONTEXT]")

	return b.String()
}

// GenerateNotificationWarning generates a shorter warning text for the
// notifications/message notification. This is shown in the client UI.
func (w *SecurityWarning) GenerateNotificationWarning() string {
	label := ScoreLabel(w.Score)

	msg := fmt.Sprintf("Security Warning: %s scored %d/100 (%s).", w.PackageName, w.Score, label)

	if w.Findings != nil && w.Findings.Total > 0 {
		parts := []string{}
		if w.Findings.Critical > 0 {
			parts = append(parts, fmt.Sprintf("%d critical", w.Findings.Critical))
		}
		if w.Findings.High > 0 {
			parts = append(parts, fmt.Sprintf("%d high", w.Findings.High))
		}
		if len(parts) > 0 {
			msg += " " + strings.Join(parts, ", ") + " findings."
		}
	}

	msg += " Exercise caution."
	return msg
}
