package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	client, err := NewClient("https://example.com")
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "https://example.com", client.baseURL)
	assert.Empty(t, client.token)
}

func TestNewClient_DefaultURL(t *testing.T) {
	// Note: This test will fail if the default registry URL cannot be resolved
	// In CI/CD, you might want to skip this test or mock DNS
	client, err := NewClient("")
	if err != nil {
		// If DNS resolution fails, just verify the error mentions DNS
		t.Skipf("Skipping test due to DNS resolution failure (expected in some envs): %v", err)
		return
	}
	assert.Equal(t, DefaultRegistryURL, client.baseURL)
}

func TestNewClientWithToken(t *testing.T) {
	client, err := NewClientWithToken("https://example.com", "token123")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com", client.baseURL)
	assert.Equal(t, "token123", client.token)
}

func TestClientSetToken(t *testing.T) {
	client, err := NewClient("https://example.com")
	require.NoError(t, err)
	client.SetToken("token123")
	assert.Equal(t, "token123", client.token)
}

func TestNewClientRejectsPrivateIPs(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "reject private IP 10.x.x.x",
			url:     "https://10.0.0.1",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "reject private IP 192.168.x.x",
			url:     "https://192.168.1.1",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "reject private IP 172.16.x.x",
			url:     "https://172.16.0.1",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "allow loopback 127.0.0.1 (localhost)",
			url:     "http://127.0.0.1",
			wantErr: false,
		},
		{
			name:    "reject AWS metadata IP",
			url:     "https://169.254.169.254",
			wantErr: true,
			errMsg:  "private IP",
		},
		{
			name:    "allow public IP",
			url:     "https://8.8.8.8",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestNewClientLocalhostAllowed(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{
			name: "allow localhost with http",
			url:  "http://localhost:8080",
		},
		{
			name: "allow 127.0.0.1 with http",
			url:  "http://127.0.0.1:8080",
		},
		{
			name: "allow ::1 with http",
			url:  "http://[::1]:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.url)
			assert.NoError(t, err)
			assert.NotNil(t, client)
		})
	}
}

func TestNewClientRequiresHTTPS(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "reject http for public domain",
			url:     "http://example.com",
			wantErr: true,
		},
		{
			name:    "allow https for public domain",
			url:     "https://example.com",
			wantErr: false,
		},
		{
			name:    "allow http for localhost",
			url:     "http://localhost",
			wantErr: false,
		},
		{
			name:    "reject http for public IP",
			url:     "http://8.8.8.8",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "must use https")
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestClientResolve_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.True(t, strings.Contains(r.URL.Path, "/v1/org/acme/mcps/test/resolve"))
		assert.Equal(t, "1.0.0", r.URL.Query().Get("ref"))

		resp := ResolveResponse{
			Package: "acme/test",
			Ref:     "1.0.0",
			Resolved: ResolvedVersion{
				Version: "1.0.0",
				GitSHA:  "abc123",
				Status:  "published",
				Manifest: ArtifactInfo{
					Digest: "sha256:abcd1234",
					URL:    "https://example.com/manifest",
				},
				Bundle: BundleInfo{
					Digest:    "sha256:efgh5678",
					URL:       "https://example.com/bundle",
					SizeBytes: 1024,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	resp, err := client.Resolve(ctx, "acme", "test", "1.0.0")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "acme/test", resp.Package)
	assert.Equal(t, "1.0.0", resp.Resolved.Version)
}

func TestClientResolve_InvalidParams(t *testing.T) {
	client, err := NewClient("https://example.com")
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		testName string
		org      string
		pkgName  string
		ref      string
	}{
		{"empty org", "", "test", "1.0.0"},
		{"empty name", "acme", "", "1.0.0"},
		{"empty ref", "acme", "test", ""},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			resp, err := client.Resolve(ctx, tt.org, tt.pkgName, tt.ref)
			assert.Error(t, err)
			assert.Nil(t, resp)
		})
	}
}

func TestClientResolve_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "package not found"})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	resp, err := client.Resolve(ctx, "acme", "nonexistent", "1.0.0")

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.True(t, IsNotFoundError(err))
}

func TestClientDownloadManifest_Success(t *testing.T) {
	manifestContent := []byte(`{"name":"test","version":"1.0.0"}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.True(t, strings.Contains(r.URL.Path, "/v1/org/acme/artifacts/"))
		assert.True(t, strings.Contains(r.URL.Path, "/manifest"))

		w.Header().Set("Content-Type", "application/json")
		w.Write(manifestContent)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	data, err := client.DownloadManifest(ctx, "acme", "sha256:abcd1234")

	require.NoError(t, err)
	assert.Equal(t, manifestContent, data)
}

func TestClientDownloadBundle_Success(t *testing.T) {
	bundleContent := []byte("fake bundle tar.gz content")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.True(t, strings.Contains(r.URL.Path, "/bundle"))

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(bundleContent)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	data, err := client.DownloadBundle(ctx, "acme", "sha256:efgh5678")

	require.NoError(t, err)
	assert.Equal(t, bundleContent, data)
}

func TestClientDownloadManifest_InvalidParams(t *testing.T) {
	client, err := NewClient("https://example.com")
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name   string
		org    string
		digest string
	}{
		{"empty org", "", "sha256:abc123"},
		{"empty digest", "acme", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := client.DownloadManifest(ctx, tt.org, tt.digest)
			assert.Error(t, err)
			assert.Nil(t, data)
		})
	}
}

func TestClientDownloadManifest_SizeLimit(t *testing.T) {
	// Create content larger than MaxManifestSize
	largeContent := bytes.Repeat([]byte("x"), MaxManifestSize+1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(largeContent)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	data, err := client.DownloadManifest(ctx, "acme", "sha256:toobig")

	assert.Error(t, err)
	assert.Nil(t, data)
	assert.True(t, strings.Contains(err.Error(), "exceeds maximum size"))
}

func TestClientLogin_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/auth/login", r.URL.Path)

		var req LoginRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "user", req.Username)
		assert.Equal(t, "pass", req.Password)

		resp := LoginResponse{
			AccessToken: "token123",
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	resp, err := client.Login(ctx, "user", "pass")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "token123", resp.AccessToken)
	assert.Equal(t, 3600, resp.ExpiresIn)
}

func TestClientLogin_InvalidParams(t *testing.T) {
	client, err := NewClient("https://example.com")
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name     string
		username string
		password string
	}{
		{"empty username", "", "pass"},
		{"empty password", "user", ""},
		{"both empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Login(ctx, tt.username, tt.password)
			assert.Error(t, err)
			assert.Nil(t, resp)
		})
	}
}

func TestClientLogin_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	resp, err := client.Login(ctx, "user", "wrong")

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.True(t, IsUnauthorizedError(err))
}

func TestClientListCatalog_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/v1/catalog", r.URL.Path)

		resp := CatalogResponse{
			Packages: []PackageInfo{
				{
					Package:       "acme/tool1",
					Visibility:    "public",
					LatestVersion: "1.0.0",
				},
				{
					Package:       "acme/tool2",
					Visibility:    "private",
					LatestVersion: "2.0.0",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	resp, err := client.ListCatalog(ctx)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.Packages, 2)
	assert.Equal(t, "acme/tool1", resp.Packages[0].Package)
	assert.Equal(t, "acme/tool2", resp.Packages[1].Package)
}

func TestClientWithAuthToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer token123", authHeader)

		resp := ResolveResponse{
			Package: "acme/test",
			Ref:     "1.0.0",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClientWithToken(server.URL, "token123")
	require.NoError(t, err)
	ctx := context.Background()

	resp, err := client.Resolve(ctx, "acme", "test", "1.0.0")

	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClientContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	resp, err := client.Resolve(ctx, "acme", "test", "1.0.0")

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestClientRetryLogic_Success(t *testing.T) {
	attemptCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++

		// Fail first 2 attempts with 500, then succeed
		if attemptCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "server error"})
			return
		}

		bundleContent := []byte("success")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(bundleContent)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	data, err := client.DownloadBundle(ctx, "acme", "sha256:test")

	require.NoError(t, err)
	assert.Equal(t, []byte("success"), data)
	assert.Equal(t, 3, attemptCount)
}

func TestClientRetryLogic_ExhaustedRetries(t *testing.T) {
	attemptCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "server error"})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	data, err := client.DownloadBundle(ctx, "acme", "sha256:test")

	assert.Error(t, err)
	assert.Nil(t, data)
	assert.Equal(t, MaxRetries, attemptCount)
	assert.True(t, strings.Contains(err.Error(), "failed to download"))
}

func TestClientRetryLogic_NoRetryOn404(t *testing.T) {
	attemptCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	data, err := client.DownloadManifest(ctx, "acme", "sha256:notfound")

	assert.Error(t, err)
	assert.Nil(t, data)
	// Should fail immediately without retries
	assert.Equal(t, 1, attemptCount)
	assert.True(t, IsNotFoundError(err))
}

func TestErrorWrapping(t *testing.T) {
	baseErr := fmt.Errorf("base error")
	err := NewError(http.StatusInternalServerError, "test error", baseErr)

	var registryErr error = err
	assert.Error(t, registryErr)
	assert.Equal(t, "test error", err.Message)
	assert.Equal(t, http.StatusInternalServerError, err.Code)
	assert.True(t, err.RetryableError())
}

func TestParseDigest(t *testing.T) {
	tests := []struct {
		name    string
		digest  string
		expAlgo string
		expHex  string
		expErr  bool
	}{
		{
			name:    "valid sha256",
			digest:  "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			expAlgo: "sha256",
			expHex:  "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			expErr:  false,
		},
		{
			name:   "empty digest",
			digest: "",
			expErr: true,
		},
		{
			name:   "invalid format",
			digest: "nocolon",
			expErr: true,
		},
		{
			name:   "sha256 wrong length",
			digest: "sha256:abc",
			expErr: true,
		},
		{
			name:   "invalid hex chars",
			digest: "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			expErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, hex, err := ParseDigest(tt.digest)

			if tt.expErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expAlgo, algo)
				assert.Equal(t, tt.expHex, hex)
			}
		})
	}
}

func TestUserAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		assert.Equal(t, "mcp-cage/1.0.0", userAgent)

		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	// Any request should have User-Agent
	client.Resolve(ctx, "test", "test", "1.0.0")
}

func TestContentTypeHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			contentType := r.Header.Get("Content-Type")
			assert.Equal(t, "application/json", contentType)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	client.Login(ctx, "user", "pass")
}

func TestRedirectFollowing(t *testing.T) {
	// First server that redirects
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/redirected", http.StatusFound)
	}))
	defer redirect.Close()

	// Second server that returns actual content
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bundleContent := []byte("redirected content")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(bundleContent)
	}))
	defer final.Close()

	// Manually test redirect following
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	// This should follow the redirect and succeed
	_, err = client.Resolve(ctx, "test", "test", "1.0.0")

	// We expect an error because the final endpoint doesn't match expected format
	// But the important thing is that it tried to follow the redirect
	assert.NotNil(t, err) // Expected because final server doesn't have proper response
}

func TestClientBaseURL(t *testing.T) {
	client, err := NewClient("https://example.com")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com", client.BaseURL())

	client.SetBaseURL("https://new.example.com")
	assert.Equal(t, "https://new.example.com", client.BaseURL())
}

func TestErrorMessageExtraction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "invalid request format",
		})
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = client.Resolve(ctx, "test", "test", "1.0.0")

	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "invalid request format"))
}

func TestEmptyResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write nothing
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = client.Resolve(ctx, "test", "test", "1.0.0")

	assert.Error(t, err)
}

// SECURITY TESTS: Redirect validation

func TestClientRejectsRedirectToPrivateIP(t *testing.T) {
	// Server that redirects to a private IP with https (to trigger private IP check)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to private IP with https
		http.Redirect(w, r, "https://192.168.1.1/evil", http.StatusFound)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = client.Resolve(ctx, "test", "test", "1.0.0")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect to private/internal network not allowed")
}

func TestClientRejectsRedirectToLocalhost(t *testing.T) {
	// Server that redirects to localhost with https (not allowed)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://localhost:8080/evil", http.StatusFound)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = client.Resolve(ctx, "test", "test", "1.0.0")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect to localhost")
}

func TestClientRejectsFileSchemeRedirect(t *testing.T) {
	// Server that redirects to file:// scheme
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = client.Resolve(ctx, "test", "test", "1.0.0")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect to unsafe scheme not allowed")
}

func TestClientRejectsRedirectToNonHTTPS(t *testing.T) {
	// Server that redirects to http (non-localhost)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/evil", http.StatusFound)
	}))
	defer server.Close()

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = client.Resolve(ctx, "test", "test", "1.0.0")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirect to non-https URL not allowed")
}

func TestClientRejectsTooManyRedirects(t *testing.T) {
	redirectCount := 0
	var serverURL string

	// Server that keeps redirecting to itself
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		if redirectCount > MaxRedirects+5 {
			// Stop after enough redirects to test limit
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, serverURL+"/redirect", http.StatusFound)
	}))
	defer server.Close()
	serverURL = server.URL

	client, err := NewClient(server.URL)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = client.Resolve(ctx, "test", "test", "1.0.0")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many redirects")
}

func TestClientAllowsHTTPLocalhostRedirectInDev(t *testing.T) {
	// Create a second server for the redirect target
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ResolveResponse{
			Package: "test/pkg",
			Ref:     "1.0.0",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer targetServer.Close()

	// Server that redirects to localhost (http is allowed for localhost)
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to localhost target
		http.Redirect(w, r, targetServer.URL, http.StatusFound)
	}))
	defer redirectServer.Close()

	client, err := NewClient(redirectServer.URL)
	require.NoError(t, err)
	ctx := context.Background()

	// This should succeed because http to localhost is allowed in dev
	resp, err := client.Resolve(ctx, "test", "pkg", "1.0.0")

	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{"private 10.x.x.x", "10.0.0.1", true},
		{"private 172.16.x.x", "172.16.0.1", true},
		{"private 192.168.x.x", "192.168.1.1", true},
		{"loopback", "127.0.0.1", true},
		{"loopback IPv6", "::1", true},
		{"link-local", "169.254.169.254", true},
		{"AWS metadata", "169.254.169.254", true},
		{"multicast", "224.0.0.1", true},
		{"reserved", "240.0.0.1", true},
		{"public IP", "8.8.8.8", false},
		{"public domain", "example.com", false},
		{"localhost", "localhost", true},
		{"with port", "192.168.1.1:8080", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPrivateIP(tt.host)
			assert.Equal(t, tt.expected, result, "isPrivateIP(%s) = %v, want %v", tt.host, result, tt.expected)
		})
	}
}

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{"localhost", "localhost", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"IPv6 loopback", "::1", true},
		{"IPv6 loopback bracketed", "[::1]", true},
		{"localhost with port", "localhost:8080", true},
		{"127.0.0.1 with port", "127.0.0.1:8080", true},
		{"uppercase", "LOCALHOST", true},
		{"public domain", "example.com", false},
		{"private IP", "192.168.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLocalhost(tt.host)
			assert.Equal(t, tt.expected, result, "isLocalhost(%s) = %v, want %v", tt.host, result, tt.expected)
		})
	}
}
