package cli

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/security-mcp/mcp-client/internal/manifest"
	"github.com/security-mcp/mcp-client/internal/policy"
	"github.com/security-mcp/mcp-client/internal/sandbox"
	"github.com/stretchr/testify/assert"
)

func TestHeader(t *testing.T) {
	var buf bytes.Buffer
	ui := NewProgressUI(&buf, 5)
	ui.Header("acme", "hello", "1.2.3")
	out := buf.String()
	assert.Contains(t, out, "[+] Running acme/hello@1.2.3")
}

func TestStepDone(t *testing.T) {
	var buf bytes.Buffer
	ui := NewProgressUI(&buf, 3)
	ui.StepStart(1, "Resolving")
	time.Sleep(10 * time.Millisecond)
	ui.StepDone(1, "Resolving")
	out := buf.String()
	assert.Contains(t, out, "done")
	assert.Contains(t, out, "[1/3]")
	// Should contain a time measurement (e.g. "10ms" or similar)
	assert.Regexp(t, `\d+ms`, out)
}

func TestStepSkip(t *testing.T) {
	var buf bytes.Buffer
	ui := NewProgressUI(&buf, 4)
	ui.StepStart(2, "Downloading")
	ui.StepSkip(2, "Downloading", "cached")
	out := buf.String()
	assert.Contains(t, out, "cached")
	assert.Contains(t, out, "[2/4]")
}

func TestStepFail(t *testing.T) {
	var buf bytes.Buffer
	ui := NewProgressUI(&buf, 3)
	ui.StepStart(3, "Validating")
	ui.StepFail(3, "Validating")
	out := buf.String()
	assert.Contains(t, out, "FAILED")
	assert.Contains(t, out, "[3/3]")
}

func TestInfoCardPlain(t *testing.T) {
	var buf bytes.Buffer
	ui := NewProgressUI(&buf, 5)
	ui.InfoCard(InfoCardData{
		Org:       "acme",
		Name:      "tool",
		Version:   "1.0.0",
		Origin:    "verified",
		CertLevel: 2,
		GitSHA:    "abc1234567890",
		Score:     85,
		Findings: &manifest.FindingsSummary{
			Total: 3, Critical: 0, High: 0, Medium: 2, Low: 1,
		},
		Limits: &policy.ExecutionLimits{
			MaxCPU:    1000,
			MaxMemory: "512M",
			MaxPIDs:   100,
			MaxFDs:    256,
			Timeout:   5 * time.Minute,
		},
		SandboxName: "darwin-seatbelt",
		SandboxCaps: sandbox.Capabilities{
			CPULimit:    true,
			MemoryLimit: true,
			PIDLimit:    true,
			FDLimit:     true,
		},
	})
	out := buf.String()
	assert.Contains(t, out, "Score: 85/100")
	assert.Contains(t, out, "Cert: 2")
	assert.Contains(t, out, "Security Certified")
	assert.Contains(t, out, "Limits:")
	assert.Contains(t, out, "CPU=1000m")
	assert.Contains(t, out, "Memory=512M")
	assert.Contains(t, out, "Sandbox: darwin-seatbelt")
}

func TestInfoCardNoScore(t *testing.T) {
	var buf bytes.Buffer
	ui := NewProgressUI(&buf, 5)
	ui.InfoCard(InfoCardData{
		Org:       "acme",
		Name:      "tool",
		Version:   "1.0.0",
		Origin:    "community",
		CertLevel: 0,
		Score:     -1,
		Limits: &policy.ExecutionLimits{
			MaxCPU:    500,
			MaxMemory: "256M",
			MaxPIDs:   50,
			MaxFDs:    128,
			Timeout:   1 * time.Minute,
		},
		SandboxName: "noop",
		NoSandbox:   true,
	})
	out := buf.String()
	assert.NotContains(t, out, "Score:")
	assert.Contains(t, out, "Cert: 0")
	assert.Contains(t, out, "Sandbox: disabled")
}

func TestListeningBanner(t *testing.T) {
	var buf bytes.Buffer
	ui := NewProgressUI(&buf, 1)
	ui.ListeningBanner("stdio")
	out := buf.String()
	assert.Contains(t, out, "MCP server listening")
	assert.Contains(t, out, "stdio")
}

func TestShutdownBanner(t *testing.T) {
	var buf bytes.Buffer
	ui := NewProgressUI(&buf, 1)
	ui.ShutdownBanner(2*time.Minute + 30*time.Second)
	out := buf.String()
	assert.Contains(t, out, "Shutting down")
	assert.Contains(t, out, "2m 30s")
}

func TestErrorBanner(t *testing.T) {
	var buf bytes.Buffer
	ui := NewProgressUI(&buf, 1)
	ui.ErrorBanner("connection refused")
	out := buf.String()
	assert.Contains(t, out, "connection refused")
	assert.Contains(t, out, "Error:")
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{500 * time.Millisecond, "500ms"},
		{3 * time.Second, "3.0s"},
		{90 * time.Second, "1m 30s"},
		{3661 * time.Second, "1h 1m 1s"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, fmtDuration(tt.d))
		})
	}
}

func TestScoreBar(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{0, "\u25cb\u25cb\u25cb\u25cb\u25cb"},
		{20, "\u25cf\u25cb\u25cb\u25cb\u25cb"},
		{100, "\u25cf\u25cf\u25cf\u25cf\u25cf"},
		{45, "\u25cf\u25cf\u25cb\u25cb\u25cb"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("score_%d", tt.score), func(t *testing.T) {
			assert.Equal(t, tt.want, scoreBar(tt.score))
		})
	}
}

func TestCertLevelName(t *testing.T) {
	tests := []struct {
		level int
		want  string
	}{
		{0, "Integrity Verified"},
		{1, "Static Verified"},
		{2, "Security Certified"},
		{3, "Runtime Certified"},
		{99, "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, certLevelName(tt.level))
		})
	}
}
