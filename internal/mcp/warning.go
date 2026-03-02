package mcp

import (
	"fmt"
	"strings"

	"github.com/security-mcp/mcp-client/internal/manifest"
)

// SecurityWarning holds the data needed to generate security warnings
// for injection into the MCP protocol.
type SecurityWarning struct {
	PackageName string
	Score       int
	CertLevel   int
	Findings    *manifest.FindingsSummary
	Origin      string
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
	label := ScoreLabel(w.Score)
	certName := CertLevelName(w.CertLevel)

	var b strings.Builder
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
	b.WriteString("This assessment was performed by MCP Hub (https://mcp-hub.info).\n")
	b.WriteString("[END SECURITY WARNING]")

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
