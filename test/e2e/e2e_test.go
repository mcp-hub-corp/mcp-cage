// +build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	registryURL = "http://localhost:8090"
	testOrg     = "e2etest"
	testPkg     = "hello-world"
	testVersion = "1.0.0"
)

var (
	mcpBinary = "../../smcp"
)

// TestMain ensures registry is available before running tests
func TestMain(m *testing.M) {
	// Check if mcp binary exists
	if _, err := os.Stat(mcpBinary); os.IsNotExist(err) {
		fmt.Println("Building smcp binary...")
		cmd := exec.Command("make", "build")
		cmd.Dir = "../.."
		if err := cmd.Run(); err != nil {
			fmt.Printf("Failed to build smcp: %v\n", err)
			os.Exit(1)
		}
	}

	// Verify registry is available
	resp, err := http.Get(registryURL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		fmt.Printf("Registry not available at %s\n", registryURL)
		fmt.Println("Start registry with: cd /tmp/mcp-registry && ./bin/mcp-registry -config /tmp/mcp-e2e-config.yaml")
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Run tests
	code := m.Run()
	os.Exit(code)
}

// Helper to run mcp command
func runMCP(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()

	fullArgs := append([]string{"--registry", registryURL}, args...)
	cmd := exec.Command(mcpBinary, fullArgs...)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	stdout = outBuf.String()
	stderr = errBuf.String()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	} else {
		exitCode = 0
	}

	return stdout, stderr, exitCode
}

// Helper to create test package
func createTestPackage(t *testing.T) (manifestDigest, bundleDigest string) {
	t.Helper()

	// Create simple manifest
	manifest := map[string]interface{}{
		"schema_version": "1.0",
		"package": map[string]string{
			"id":      testOrg + "/" + testPkg,
			"version": testVersion,
			"git_sha": "abc123def456",
		},
		"bundle": map[string]interface{}{
			"digest":     "sha256:0000000000000000000000000000000000000000000000000000000000000000", // Will update
			"size_bytes": 0,
		},
		"transport": map[string]string{
			"type": "stdio",
		},
		"entrypoints": []map[string]interface{}{
			{
				"os":      "linux",
				"arch":    "amd64",
				"command": "./hello",
				"args":    []string{},
			},
		},
	}

	// Create simple bundle (tar.gz with hello script)
	bundleDir := t.TempDir()
	scriptPath := filepath.Join(bundleDir, "hello")
	scriptContent := "#!/bin/sh\necho 'Hello from MCP E2E test'\n"
	err := os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	require.NoError(t, err)

	// Create tar.gz
	bundlePath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	cmd := exec.Command("tar", "czf", bundlePath, "-C", bundleDir, ".")
	err = cmd.Run()
	require.NoError(t, err)

	// Read bundle and compute digest
	bundleData, err := os.ReadFile(bundlePath)
	require.NoError(t, err)

	bundleHash := sha256.Sum256(bundleData)
	bundleDigest = "sha256:" + hex.EncodeToString(bundleHash[:])

	// Update manifest with correct bundle digest
	manifest["bundle"].(map[string]interface{})["digest"] = bundleDigest
	manifest["bundle"].(map[string]interface{})["size_bytes"] = len(bundleData)

	// Compute manifest digest
	manifestData, err := json.Marshal(manifest)
	require.NoError(t, err)

	manifestHash := sha256.Sum256(manifestData)
	manifestDigest = "sha256:" + hex.EncodeToString(manifestHash[:])

	// Publish to registry (would require auth, skip for now)
	// This is where we'd call POST /v1/org/{org}/mcps/{name}/publish
	// For now, we'll test with pre-existing packages or mock

	return manifestDigest, bundleDigest
}

func TestE2E_Doctor(t *testing.T) {
	stdout, stderr, exitCode := runMCP(t, "doctor")

	assert.Equal(t, 0, exitCode, "mcp doctor should succeed")
	assert.Contains(t, stdout, "MCP Client Diagnostics")
	assert.Contains(t, stdout, "System Information")
	assert.Empty(t, stderr)
}

func TestE2E_DoctorJSON(t *testing.T) {
	stdout, stderr, exitCode := runMCP(t, "doctor", "--json")

	assert.Equal(t, 0, exitCode)
	assert.Empty(t, stderr)

	// Parse JSON output
	var result map[string]interface{}
	err := json.Unmarshal([]byte(stdout), &result)
	require.NoError(t, err)

	assert.Contains(t, result, "OS")
	assert.Contains(t, result, "Arch")
	assert.Contains(t, result, "Capabilities")
}

func TestE2E_Version(t *testing.T) {
	stdout, _, exitCode := runMCP(t, "--version")

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout, "smcp version")
}

func TestE2E_Help(t *testing.T) {
	stdout, _, exitCode := runMCP(t, "--help")

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout, "Available Commands")
	assert.Contains(t, stdout, "run")
	assert.Contains(t, stdout, "pull")
	assert.Contains(t, stdout, "info")
}

func TestE2E_CacheLs_Empty(t *testing.T) {
	// Clean cache first
	cacheDir := t.TempDir()

	stdout, _, exitCode := runMCP(t, "cache", "ls", "--cache-dir", cacheDir)

	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stdout, "Cache is empty")
}

func TestE2E_RegistryHealth(t *testing.T) {
	// Verify registry is accessible
	resp, err := http.Get(registryURL + "/healthz")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Contains(t, string(body), "ok")
}

// TestE2E_Info tests package info retrieval
// This would require a published package in the registry
func TestE2E_Info_NotFound(t *testing.T) {
	t.Skip("Skipping until we can publish test packages to registry")

	_, stderr, exitCode := runMCP(t, "info", "nonexistent/package@1.0.0")

	assert.NotEqual(t, 0, exitCode, "Should fail for non-existent package")
	_ = stderr // Will verify error message when implemented
}

// TestE2E_Pull would test actual package pulling
// Requires published package in registry
func TestE2E_Pull_NotFound(t *testing.T) {
	t.Skip("Skipping until we can publish test packages to registry")

	cacheDir := t.TempDir()
	_, stderr, exitCode := runMCP(t, "pull", "nonexistent/package@1.0.0", "--cache-dir", cacheDir)

	assert.NotEqual(t, 0, exitCode)
	_ = stderr // Will check error message when implemented
}

// Benchmark E2E commands
func BenchmarkE2E_Doctor(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command(mcpBinary, "--registry", registryURL, "doctor")
		_ = cmd.Run()
	}
}

func BenchmarkE2E_CacheLs(b *testing.B) {
	cacheDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command(mcpBinary, "--registry", registryURL, "cache", "ls", "--cache-dir", cacheDir)
		_ = cmd.Run()
	}
}
