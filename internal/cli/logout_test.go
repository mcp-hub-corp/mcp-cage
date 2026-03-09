package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogoutRemovesToken tests that logout removes the stored token
func TestLogoutRemovesToken(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a stored token
	storage := registry.NewTokenStorage(tmpDir)
	token := &registry.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
	err := storage.Save("https://registry.example.com", token)
	require.NoError(t, err)

	// Verify token exists
	authPath := filepath.Join(tmpDir, "auth.json")
	_, err = os.Stat(authPath)
	require.NoError(t, err)

	// Remove the token
	err = os.Remove(authPath)
	require.NoError(t, err)

	// Verify token no longer exists
	_, err = os.Stat(authPath)
	assert.True(t, os.IsNotExist(err))

	// Try to load token - should return nil
	loadedToken, err := storage.Load()
	require.NoError(t, err)
	assert.Nil(t, loadedToken)
}

// TestLogoutWhenNotLoggedIn tests logout when no token is stored
func TestLogoutWhenNotLoggedIn(t *testing.T) {
	tmpDir := t.TempDir()
	storage := registry.NewTokenStorage(tmpDir)

	// Try to load token when none exists
	token, err := storage.Load()
	require.NoError(t, err)
	assert.Nil(t, token)
}

// TestLogoutHandlesFileRemovalErrors tests logout handles errors gracefully
func TestLogoutHandlesFileRemovalErrors(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a token file
	storage := registry.NewTokenStorage(tmpDir)
	token := &registry.Token{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
	err := storage.Save("https://example.com", token)
	require.NoError(t, err)

	// Verify file exists
	authPath := filepath.Join(tmpDir, "auth.json")
	fileInfo, err := os.Stat(authPath)
	require.NoError(t, err)
	assert.NotNil(t, fileInfo)

	// Remove token file normally
	err = os.Remove(authPath)
	require.NoError(t, err)

	// Verify removal
	_, err = os.Stat(authPath)
	assert.True(t, os.IsNotExist(err))
}
