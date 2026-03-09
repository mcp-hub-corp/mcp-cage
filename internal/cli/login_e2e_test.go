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

// TestLoginLogoutFlow tests the complete login/logout workflow
func TestLoginLogoutFlow(t *testing.T) {
	tmpDir := t.TempDir()

	// Setup config
	cfg = &config.Config{
		RegistryURL: "https://registry.mcp-hub.info",
		CacheDir:    tmpDir,
		LogLevel:    "info",
		Timeout:     30 * time.Second,
	}

	storage := registry.NewTokenStorage(tmpDir)

	// Step 1: Verify no token exists initially
	token, err := storage.Load()
	require.NoError(t, err)
	assert.Nil(t, token, "should have no token initially")

	// Step 2: Save a token (simulate login)
	testToken := &registry.Token{
		AccessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwib3JnIjoib3JnMSIsImV4cCI6OTk5OTk5OTk5OX0.token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Registry:    cfg.RegistryURL,
	}
	err = storage.Save(cfg.RegistryURL, testToken)
	require.NoError(t, err, "should save token")

	// Step 3: Verify token file has correct permissions (skip on Windows — NTFS uses ACLs)
	authPath := filepath.Join(tmpDir, "auth.json")
	fileInfo, err := os.Stat(authPath)
	require.NoError(t, err, "token file should exist")
	if runtime.GOOS != "windows" {
		perms := fileInfo.Mode().Perm()
		assert.Equal(t, os.FileMode(0o600), perms, "token file should have 0600 permissions")
	}

	// Step 4: Load token and verify
	loadedToken, err := storage.Load()
	require.NoError(t, err, "should load token")
	require.NotNil(t, loadedToken, "token should not be nil")
	assert.Equal(t, testToken.AccessToken, loadedToken.AccessToken, "access token should match")
	assert.Equal(t, testToken.TokenType, loadedToken.TokenType, "token type should match")
	assert.Equal(t, cfg.RegistryURL, loadedToken.Registry, "registry should match")
	assert.False(t, loadedToken.IsExpired(), "token should not be expired")

	// Step 5: Delete token (simulate logout)
	err = storage.Delete()
	require.NoError(t, err, "should delete token")

	// Step 6: Verify token is gone
	loadedToken, err = storage.Load()
	require.NoError(t, err, "should not error when loading non-existent token")
	assert.Nil(t, loadedToken, "token should be nil after deletion")

	// Step 7: Verify auth file is gone
	_, err = os.Stat(authPath)
	assert.True(t, os.IsNotExist(err), "auth file should not exist after deletion")
}

// TestTokenSecureStorage tests that tokens are stored securely
func TestTokenSecureStorage(t *testing.T) {
	tmpDir := t.TempDir()

	storage := registry.NewTokenStorage(tmpDir)

	sensitiveToken := &registry.Token{
		AccessToken: "super-secret-token-123456789",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}

	err := storage.Save("https://example.com", sensitiveToken)
	require.NoError(t, err)

	// Verify permissions
	authPath := filepath.Join(tmpDir, "auth.json")
	fileInfo, err := os.Stat(authPath)
	require.NoError(t, err)

	// Verify permissions (skip on Windows — NTFS uses ACLs, not mode bits)
	if runtime.GOOS != "windows" {
		perms := fileInfo.Mode().Perm()
		// Ensure only owner can read/write (0600)
		assert.Equal(t, os.FileMode(0o600), perms, "token must be 0600 (read-write owner only)")

		// Verify others cannot read
		if os.Getuid() != 0 { // Skip if running as root
			otherCanRead := (perms & 0o044) != 0
			assert.False(t, otherCanRead, "others should not be able to read token file")
		}
	}
}

// TestTokenExpirationCalculation tests expiration time calculation
func TestTokenExpirationCalculation(t *testing.T) {
	now := time.Now()

	// Test 1: Future expiration
	futureToken := &registry.Token{
		AccessToken: "future-token",
		ExpiresAt:   now.Add(1 * time.Hour),
	}
	assert.False(t, futureToken.IsExpired(), "future token should not be expired")

	// Test 2: Already expired
	expiredToken := &registry.Token{
		AccessToken: "expired-token",
		ExpiresAt:   now.Add(-1 * time.Hour),
	}
	assert.True(t, expiredToken.IsExpired(), "past token should be expired")

	// Test 3: Just now (edge case — use slight past to avoid nanosecond race)
	nowToken := &registry.Token{
		AccessToken: "now-token",
		ExpiresAt:   now.Add(-time.Second),
	}
	assert.True(t, nowToken.IsExpired(), "token expiring in the past should be expired")

	// Test 4: Far future
	farFutureToken := &registry.Token{
		AccessToken: "far-future-token",
		ExpiresAt:   now.Add(365 * 24 * time.Hour),
	}
	assert.False(t, farFutureToken.IsExpired(), "far future token should not be expired")
}
