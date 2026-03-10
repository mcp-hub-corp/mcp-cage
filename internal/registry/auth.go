package registry

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/config"
)

// TokenStorage handles token persistence
type TokenStorage struct {
	dir string
}

// Token represents a stored authentication token
type Token struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	TokenType   string    `json:"token_type,omitempty"`
	Registry    string    `json:"registry,omitempty"`
}

// NewTokenStorage creates a new token storage
func NewTokenStorage(cacheDir string) *TokenStorage {
	return &TokenStorage{
		dir: cacheDir,
	}
}

// Save saves a token to disk
func (ts *TokenStorage) Save(registry string, token *Token) error {
	if err := os.MkdirAll(ts.dir, 0o700); err != nil {
		return err
	}

	tokenPath := filepath.Join(ts.dir, "auth.json")
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(tokenPath, data, 0o600)
}

// Load loads a token from disk
func (ts *TokenStorage) Load() (*Token, error) {
	tokenPath := filepath.Join(ts.dir, "auth.json")
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}

	return &token, nil
}

// Delete removes the stored token from disk
func (ts *TokenStorage) Delete() error {
	tokenPath := filepath.Join(ts.dir, "auth.json")
	if err := os.Remove(tokenPath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already deleted, not an error
		}
		return err
	}
	return nil
}

// IsExpired checks if the token has expired
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// AuthenticatedRequest represents an HTTP request with authentication
type AuthenticatedRequest struct {
	client *http.Client
	token  string
	authed bool
}

// NewAuthenticatedRequest creates a new authenticated request builder
func NewAuthenticatedRequest(client *http.Client, token string) *AuthenticatedRequest {
	return &AuthenticatedRequest{
		client: client,
		token:  token,
		authed: token != "",
	}
}

// Do executes an HTTP request with authentication headers
func (ar *AuthenticatedRequest) Do(req *http.Request) (*http.Response, error) {
	// Add User-Agent header
	req.Header.Set("User-Agent", "mcp-cage/1.0.0")

	// Add authorization header if token is available
	if ar.authed && ar.token != "" {
		req.Header.Set("Authorization", "Bearer "+ar.token)
	}

	return ar.client.Do(req)
}

// AddBearerToken adds a bearer token to the request
func AddBearerToken(req *http.Request, token string) {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// AddAPIToken adds an API token to the request (token_id:secret format)
func AddAPIToken(req *http.Request, tokenID, tokenSecret string) {
	if tokenID != "" && tokenSecret != "" {
		token := tokenID + ":" + tokenSecret
		req.Header.Set("Authorization", "Token "+token)
	}
}

// AddBasicAuth adds basic authentication to the request
func AddBasicAuth(req *http.Request, username, password string) {
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}
}

// ExtractAuthError extracts authentication error information from a response
func ExtractAuthError(resp *http.Response) (string, error) {
	defer func() {
		_ = resp.Body.Close() //nolint:errcheck
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}

	_ = json.Unmarshal(body, &errResp) //nolint:errcheck

	if errResp.Error != "" {
		return errResp.Error, nil
	}
	if errResp.Message != "" {
		return errResp.Message, nil
	}

	return string(body), nil
}

// GetCacheDir returns the cache directory from config
func GetCacheDir() string {
	cfg, err := config.LoadConfig()
	if err != nil {
		// Fall back to default
		home, err := os.UserHomeDir()
		if err != nil {
			return "./.mcp"
		}
		return filepath.Join(home, ".mcp")
	}
	return cfg.CacheDir
}
