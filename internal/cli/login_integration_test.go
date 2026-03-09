package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/config"
	"github.com/mcp-hub-corp/mcp-cage/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoginIntegrationTokenStorage tests the complete login workflow
func TestLoginIntegrationTokenStorage(t *testing.T) {
	tmpDir := t.TempDir()

	// Setup config
	cfg = &config.Config{
		RegistryURL: "https://test.registry.com",
		CacheDir:    tmpDir,
		LogLevel:    "info",
	}

	logger := createLogger("info")
	storage := registry.NewTokenStorage(tmpDir)

	// Test 1: No token stored initially
	token, err := storage.Load()
	require.NoError(t, err)
	assert.Nil(t, token)

	// Test 2: Save a token
	testToken := &registry.Token{
		AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Registry:    "https://test.registry.com",
	}
	err = storage.Save("https://test.registry.com", testToken)
	require.NoError(t, err)

	// Test 3: Verify file permissions (skip on Windows — NTFS uses ACLs)
	authPath := filepath.Join(tmpDir, "auth.json")
	fileInfo, err := os.Stat(authPath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), fileInfo.Mode()&os.FileMode(0o777))
	}

	// Test 4: Load stored token
	loadedToken, err := storage.Load()
	require.NoError(t, err)
	require.NotNil(t, loadedToken)
	assert.Equal(t, testToken.AccessToken, loadedToken.AccessToken)
	assert.Equal(t, testToken.TokenType, loadedToken.TokenType)
	assert.Equal(t, testToken.Registry, loadedToken.Registry)

	// Test 5: Token not expired
	assert.False(t, loadedToken.IsExpired())

	// Test 6: Delete token
	err = storage.Delete()
	require.NoError(t, err)

	// Test 7: Verify token is gone
	loadedToken, err = storage.Load()
	require.NoError(t, err)
	assert.Nil(t, loadedToken)

	logger.Info("integration test passed")
}

// TestLoginWithTokenFlag tests login with token flag
func TestLoginWithTokenFlag(t *testing.T) {
	tmpDir := t.TempDir()

	// Setup config
	cfg = &config.Config{
		RegistryURL: "https://registry.example.com",
		CacheDir:    tmpDir,
		LogLevel:    "info",
	}

	logger := createLogger("info")
	storage := registry.NewTokenStorage(tmpDir)

	// Valid JWT token
	validToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.H81jyH0wAXzBq0Gl6FjCFqFVBReBzGqwLEgWVJGYMVQ"

	// Test token login
	err := loginWithToken(logger, "https://registry.example.com", validToken, storage)
	require.NoError(t, err)

	// Verify token was saved
	token, err := storage.Load()
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, validToken, token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, "https://registry.example.com", token.Registry)
}

// TestMultipleRegistries tests storing tokens for multiple registries
func TestMultipleRegistries(t *testing.T) {
	tmpDir := t.TempDir()

	storage := registry.NewTokenStorage(tmpDir)

	// Note: The current implementation only stores one token per cache dir
	// This test documents the current behavior

	registry1 := "https://registry1.example.com"
	registry2 := "https://registry2.example.com"

	token1 := &registry.Token{
		AccessToken: "token1",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Registry:    registry1,
	}

	token2 := &registry.Token{
		AccessToken: "token2",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Registry:    registry2,
	}

	// Save token for registry 1
	err := storage.Save(registry1, token1)
	require.NoError(t, err)

	// Save token for registry 2 (overwrites token 1)
	err = storage.Save(registry2, token2)
	require.NoError(t, err)

	// Load and verify we get token 2
	loadedToken, err := storage.Load()
	require.NoError(t, err)
	require.NotNil(t, loadedToken)
	assert.Equal(t, "token2", loadedToken.AccessToken)
}

// TestTokenExpiration tests expiration time handling
func TestTokenExpirationHandling(t *testing.T) {
	tmpDir := t.TempDir()
	storage := registry.NewTokenStorage(tmpDir)

	// Create expired token
	expiredToken := &registry.Token{
		AccessToken: "expired-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	}

	err := storage.Save("https://example.com", expiredToken)
	require.NoError(t, err)

	// Load and verify expiration
	loadedToken, err := storage.Load()
	require.NoError(t, err)
	require.NotNil(t, loadedToken)
	assert.True(t, loadedToken.IsExpired())

	// Create valid token
	validToken := &registry.Token{
		AccessToken: "valid-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}

	err = storage.Save("https://example.com", validToken)
	require.NoError(t, err)

	// Load and verify non-expiration
	loadedToken, err = storage.Load()
	require.NoError(t, err)
	require.NotNil(t, loadedToken)
	assert.False(t, loadedToken.IsExpired())
}
