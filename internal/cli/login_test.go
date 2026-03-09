package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoginWithToken tests login using a token flag
func TestLoginWithToken(t *testing.T) {
	// Create temporary directory for token storage
	tmpDir := t.TempDir()

	// Create logger
	logger := createLogger("info")

	// Create token storage
	tokenStorage := registry.NewTokenStorage(tmpDir)

	// Test token (valid JWT format)
	testToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	registryURL := "https://registry.mcp-hub.info"

	// Test loginWithToken
	err := loginWithToken(logger, registryURL, testToken, tokenStorage)
	require.NoError(t, err)

	// Verify token was saved
	token, err := tokenStorage.Load()
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, testToken, token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, registryURL, token.Registry)
	assert.False(t, token.IsExpired())
}

// TestLoginWithInvalidToken tests login with invalid token format
func TestLoginWithInvalidToken(t *testing.T) {
	tmpDir := t.TempDir()
	logger := createLogger("info")
	tokenStorage := registry.NewTokenStorage(tmpDir)

	invalidToken := "not.a.valid.token.format" // Too many parts
	registryURL := "https://registry.mcp-hub.info"

	err := loginWithToken(logger, registryURL, invalidToken, tokenStorage)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token format")
}

// TestTokenStorage tests token storage operations
func TestTokenStorage(t *testing.T) {
	tmpDir := t.TempDir()
	storage := registry.NewTokenStorage(tmpDir)

	// Create a test token
	token := &registry.Token{
		AccessToken: "test-token-123",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Registry:    "https://test.example.com",
	}

	// Save token
	err := storage.Save("https://test.example.com", token)
	require.NoError(t, err)

	// Verify file has correct permissions (skip on Windows — NTFS uses ACLs, not mode bits)
	authPath := filepath.Join(tmpDir, "auth.json")
	fileInfo, err := os.Stat(authPath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), fileInfo.Mode()&os.FileMode(0o777))
	}

	// Load token
	loadedToken, err := storage.Load()
	require.NoError(t, err)
	require.NotNil(t, loadedToken)
	assert.Equal(t, token.AccessToken, loadedToken.AccessToken)
	assert.Equal(t, token.TokenType, loadedToken.TokenType)
	assert.Equal(t, token.Registry, loadedToken.Registry)
}

// TestTokenExpiration tests token expiration check
func TestTokenExpiration(t *testing.T) {
	// Test expired token
	expiredToken := &registry.Token{
		AccessToken: "expired",
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	}
	assert.True(t, expiredToken.IsExpired())

	// Test valid token
	validToken := &registry.Token{
		AccessToken: "valid",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
	assert.False(t, validToken.IsExpired())
}

// TestTokenStoragePermissions tests that token file has correct permissions
func TestTokenStoragePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	storage := registry.NewTokenStorage(tmpDir)

	token := &registry.Token{
		AccessToken: "secure-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}

	err := storage.Save("https://example.com", token)
	require.NoError(t, err)

	// Check permissions
	authPath := filepath.Join(tmpDir, "auth.json")
	fileInfo, err := os.Stat(authPath)
	require.NoError(t, err)

	// Verify permissions are 0600 (read-write for owner only)
	// Skip on Windows — NTFS uses ACLs, not mode bits
	if runtime.GOOS != "windows" {
		perms := fileInfo.Mode().Perm()
		assert.Equal(t, os.FileMode(0o600), perms, fmt.Sprintf("expected 0600, got %o", perms))
	}
}

// TestTokenStorageLoadNonExistent tests loading from non-existent file
func TestTokenStorageLoadNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	storage := registry.NewTokenStorage(tmpDir)

	// Try to load token that doesn't exist
	token, err := storage.Load()
	require.NoError(t, err)
	assert.Nil(t, token)
}
