package mcp

import (
	"testing"

	"github.com/security-mcp/mcp-client/internal/manifest"
	"github.com/stretchr/testify/assert"
)

func TestScoreLabel(t *testing.T) {
	tests := []struct {
		score int
		label string
	}{
		{0, "Critical Risk"},
		{10, "Critical Risk"},
		{39, "Critical Risk"},
		{40, "High Risk"},
		{50, "High Risk"},
		{59, "High Risk"},
		{60, "Moderate Risk"},
		{70, "Moderate Risk"},
		{79, "Moderate Risk"},
		{80, "Low Risk"},
		{90, "Low Risk"},
		{100, "Low Risk"},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			assert.Equal(t, tt.label, ScoreLabel(tt.score))
		})
	}
}

func TestCertLevelName(t *testing.T) {
	assert.Equal(t, "Integrity Verified", CertLevelName(0))
	assert.Equal(t, "Static Verified", CertLevelName(1))
	assert.Equal(t, "Security Certified", CertLevelName(2))
	assert.Equal(t, "Runtime Certified", CertLevelName(3))
	assert.Equal(t, "Unknown", CertLevelName(99))
}

func TestNeedsWarning(t *testing.T) {
	assert.True(t, NeedsWarning(50, 80))
	assert.True(t, NeedsWarning(79, 80))
	assert.False(t, NeedsWarning(80, 80))
	assert.False(t, NeedsWarning(90, 80))
	assert.True(t, NeedsWarning(0, 80))
	assert.False(t, NeedsWarning(-1, 80))
}

func TestGenerateInstructionsWarning_WithFindings(t *testing.T) {
	w := &SecurityWarning{
		PackageName: "acme/test-server",
		Score:       35,
		CertLevel:   0,
		Findings: &manifest.FindingsSummary{
			Total:    5,
			Critical: 2,
			High:     1,
			Medium:   1,
			Low:      1,
		},
		Origin: "community",
	}

	text := w.GenerateInstructionsWarning()
	assert.Contains(t, text, "[SECURITY WARNING")
	assert.Contains(t, text, "acme/test-server")
	assert.Contains(t, text, "35/100")
	assert.Contains(t, text, "Critical Risk")
	assert.Contains(t, text, "Certification Level: 0")
	assert.Contains(t, text, "Integrity Verified")
	assert.Contains(t, text, "5 total")
	assert.Contains(t, text, "2 critical")
	assert.Contains(t, text, "1 high")
	assert.Contains(t, text, "1 medium")
	assert.Contains(t, text, "1 low")
	assert.Contains(t, text, "MUST inform the user")
	assert.Contains(t, text, "[END SECURITY WARNING]")
}

func TestGenerateInstructionsWarning_NilFindings(t *testing.T) {
	w := &SecurityWarning{
		PackageName: "acme/test-server",
		Score:       55,
		CertLevel:   1,
		Findings:    nil,
		Origin:      "community",
	}

	text := w.GenerateInstructionsWarning()
	assert.Contains(t, text, "55/100")
	assert.Contains(t, text, "High Risk")
	assert.NotContains(t, text, "Findings:")
}

func TestGenerateInstructionsWarning_ZeroFindings(t *testing.T) {
	w := &SecurityWarning{
		PackageName: "acme/test-server",
		Score:       65,
		CertLevel:   1,
		Findings: &manifest.FindingsSummary{
			Total:    0,
			Critical: 0,
			High:     0,
			Medium:   0,
			Low:      0,
		},
	}

	text := w.GenerateInstructionsWarning()
	assert.Contains(t, text, "65/100")
	assert.Contains(t, text, "Moderate Risk")
	assert.NotContains(t, text, "Findings:")
}

func TestGenerateNotificationWarning(t *testing.T) {
	w := &SecurityWarning{
		PackageName: "acme/test-server",
		Score:       30,
		CertLevel:   0,
		Findings: &manifest.FindingsSummary{
			Total:    4,
			Critical: 3,
			High:     1,
		},
	}

	text := w.GenerateNotificationWarning()
	assert.Contains(t, text, "acme/test-server")
	assert.Contains(t, text, "30/100")
	assert.Contains(t, text, "Critical Risk")
	assert.Contains(t, text, "3 critical")
	assert.Contains(t, text, "1 high")
	assert.Contains(t, text, "Exercise caution")
}

func TestGenerateNotificationWarning_NoFindings(t *testing.T) {
	w := &SecurityWarning{
		PackageName: "acme/test-server",
		Score:       50,
		CertLevel:   1,
	}

	text := w.GenerateNotificationWarning()
	assert.Contains(t, text, "50/100")
	assert.Contains(t, text, "High Risk")
	assert.Contains(t, text, "Exercise caution")
	assert.NotContains(t, text, "critical")
}

func TestGenerateInstructionsWarning_Score0(t *testing.T) {
	w := &SecurityWarning{
		PackageName: "test/zero",
		Score:       0,
		CertLevel:   0,
	}

	text := w.GenerateInstructionsWarning()
	assert.Contains(t, text, "0/100")
	assert.Contains(t, text, "Critical Risk")
}

func TestGenerateInstructionsWarning_Score79(t *testing.T) {
	w := &SecurityWarning{
		PackageName: "test/boundary",
		Score:       79,
		CertLevel:   1,
	}

	text := w.GenerateInstructionsWarning()
	assert.Contains(t, text, "79/100")
	assert.Contains(t, text, "Moderate Risk")
}
