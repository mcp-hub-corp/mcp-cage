package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultRegistryURL is the default registry URL
	DefaultRegistryURL = "https://registry.mcp-hub.info"

	// DefaultAPITimeout is the default timeout for API calls
	DefaultAPITimeout = 30 * time.Second

	// DefaultDownloadTimeout is the default timeout for downloads
	DefaultDownloadTimeout = 5 * time.Minute

	// MaxRedirects is the maximum number of redirects to follow
	MaxRedirects = 10

	// MaxRetries is the maximum number of retries for 5xx errors
	MaxRetries = 3

	// MaxManifestSize is the maximum allowed manifest size (10 MB)
	MaxManifestSize = 10 * 1024 * 1024

	// MaxBundleSize is the maximum allowed bundle size (100 MB)
	MaxBundleSize = 100 * 1024 * 1024
)

// Client is the registry client
type Client struct {
	baseURL    string
	httpClient *http.Client
	apiClient  *http.Client
	token      string
	logger     *slog.Logger
}

// isPrivateIP checks if the given host is a private IP address or resolves to one
func isPrivateIP(host string) bool {
	// Remove port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Parse as IP address directly
	ip := net.ParseIP(host)
	if ip == nil {
		// Try to resolve the hostname
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			// SECURITY: Fail closed - unresolvable hosts are treated as suspicious
			return true
		}
		ip = ips[0]
	}

	// Check for private/internal IP ranges
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Additional checks for special ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 0.0.0.0/8 (current network)
		if ip4[0] == 0 {
			return true
		}
		// 169.254.0.0/16 (link-local, including AWS metadata)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// 224.0.0.0/4 (multicast)
		if ip4[0] >= 224 && ip4[0] <= 239 {
			return true
		}
		// 240.0.0.0/4 (reserved)
		if ip4[0] >= 240 {
			return true
		}
	}

	return false
}

// isLocalhost checks if the given host is localhost
func isLocalhost(host string) bool {
	// Remove port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

// validateRedirect validates that a redirect destination is safe
func validateRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= MaxRedirects {
		return fmt.Errorf("too many redirects (max %d)", MaxRedirects)
	}

	// SECURITY: Validate the redirect destination (req.URL is the destination we're about to be redirected to)
	u := req.URL
	host := u.Hostname()

	// Reject file:// and other dangerous schemes first
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("redirect to unsafe scheme not allowed: %s", u.Scheme)
	}

	// Check localhost separately (allow http localhost for dev, but not https localhost)
	if isLocalhost(host) {
		if u.Scheme == "https" {
			return fmt.Errorf("redirect to localhost with https not allowed: %s", u.Redacted())
		}
		// http localhost is allowed (for dev/testing)
		return nil
	}

	// Only allow https for non-localhost destinations
	if u.Scheme != "https" {
		return fmt.Errorf("redirect to non-https URL not allowed: %s", u.Redacted())
	}

	// Reject redirects to private IPs (but localhost was already handled above)
	if isPrivateIP(host) {
		return fmt.Errorf("redirect to private/internal network not allowed: %s", u.Redacted())
	}

	return nil
}

// NewClient creates a new registry client with default timeouts
func NewClient(baseURL string) (*Client, error) {
	if baseURL == "" {
		baseURL = DefaultRegistryURL
	}

	// SECURITY: Parse and validate registry URL
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid registry URL: %w", err)
	}

	host := u.Hostname()

	// SECURITY: Only allow https in production
	// Allow http only for localhost development
	if u.Scheme != "https" && !isLocalhost(host) {
		return nil, fmt.Errorf("registry URL must use https (got %s)", u.Scheme)
	}

	// SECURITY: Reject private IPs to prevent SSRF
	if isPrivateIP(host) && !isLocalhost(host) {
		return nil, fmt.Errorf("registry URL cannot be private IP: %s", host)
	}

	// SECURITY: DNS pinning to prevent DNS rebinding attacks
	// Only if not localhost
	if !isLocalhost(host) {
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve registry host: %w", err)
		}

		for _, ip := range ips {
			if isPrivateIP(ip.String()) {
				return nil, fmt.Errorf("registry resolves to private IP: %s", ip)
			}
		}
	}

	// API client for metadata operations
	apiClient := &http.Client{
		Timeout:       DefaultAPITimeout,
		CheckRedirect: validateRedirect,
	}

	// Download client for large file operations
	downloadClient := &http.Client{
		Timeout:       DefaultDownloadTimeout,
		CheckRedirect: validateRedirect,
	}

	logger := slog.Default()

	return &Client{
		baseURL:    baseURL,
		httpClient: downloadClient,
		apiClient:  apiClient,
		logger:     logger,
	}, nil
}

// NewClientWithToken creates a new registry client with an auth token
func NewClientWithToken(baseURL, token string) (*Client, error) {
	client, err := NewClient(baseURL)
	if err != nil {
		return nil, err
	}
	client.token = token
	return client, nil
}

// SetLogger sets the logger for the client
func (c *Client) SetLogger(logger *slog.Logger) {
	c.logger = logger
}

// SetToken sets the authentication token
func (c *Client) SetToken(token string) {
	c.token = token
}

// Resolve resolves a package reference to manifest and bundle information
// org: organization name
// name: package name
// ref: version reference (semver, git SHA, or digest)
func (c *Client) Resolve(ctx context.Context, org, name, ref string) (*ResolveResponse, error) {
	if org == "" || name == "" || ref == "" {
		return nil, fmt.Errorf("org, name, and ref cannot be empty")
	}

	path := fmt.Sprintf("/v1/org/%s/mcps/%s/resolve", url.QueryEscape(org), url.QueryEscape(name))
	endpoint := c.baseURL + path

	// Add ref query parameter
	q := url.Values{}
	q.Set("ref", ref)
	endpoint = endpoint + "?" + q.Encode()

	c.logger.Debug("resolving package", slog.String("endpoint", endpoint))

	resp, err := c.doRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close() //nolint:errcheck
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var resolveResp ResolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&resolveResp); err != nil {
		return nil, NewError(resp.StatusCode, "failed to decode resolve response", err)
	}

	c.logger.Debug("package resolved", slog.String("package", resolveResp.Package), slog.String("version", resolveResp.Resolved.Version))

	return &resolveResp, nil
}

// DownloadManifest downloads a manifest by digest
// org: organization name
// digest: SHA256 digest of the manifest
func (c *Client) DownloadManifest(ctx context.Context, org, digest string) ([]byte, error) {
	if org == "" || digest == "" {
		return nil, fmt.Errorf("org and digest cannot be empty")
	}

	return c.downloadArtifact(ctx, org, digest, "manifest", MaxManifestSize)
}

// DownloadBundle downloads a bundle by digest
// org: organization name
// digest: SHA256 digest of the bundle
func (c *Client) DownloadBundle(ctx context.Context, org, digest string) ([]byte, error) {
	if org == "" || digest == "" {
		return nil, fmt.Errorf("org and digest cannot be empty")
	}

	return c.downloadArtifact(ctx, org, digest, "bundle", MaxBundleSize)
}

// downloadArtifact downloads an artifact with retry logic
func (c *Client) downloadArtifact(ctx context.Context, org, digest, artifactType string, maxSize int64) ([]byte, error) {
	// Use PathEscape for path segments - it doesn't escape colons which are valid in sha256:xxx digests
	path := fmt.Sprintf("/v1/org/%s/artifacts/%s/%s", url.PathEscape(org), url.PathEscape(digest), artifactType)
	endpoint := c.baseURL + path

	c.logger.Debug("downloading artifact", slog.String("type", artifactType), slog.String("digest", digest))

	var lastErr error
	for attempt := 0; attempt < MaxRetries; attempt++ {
		data, err := c.doDownload(ctx, endpoint, maxSize)
		if err == nil {
			return data, nil
		}

		// Check if error is retryable
		if !IsRetryableError(err) {
			return nil, err
		}

		lastErr = err
		if attempt < MaxRetries-1 {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			c.logger.Warn("download failed, retrying", slog.String("artifact", artifactType), slog.Duration("backoff", backoff), slog.String("error", err.Error()))
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return nil, fmt.Errorf("failed to download %s after %d attempts: %w", artifactType, MaxRetries, lastErr)
}

// doDownload performs a single download request with size limit
func (c *Client) doDownload(ctx context.Context, endpoint string, maxSize int64) ([]byte, error) {
	resp, err := c.doRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close() //nolint:errcheck
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	// Limit response body size
	limitedReader := io.LimitReader(resp.Body, maxSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, NewError(resp.StatusCode, "failed to read response body", err)
	}

	if int64(len(data)) > maxSize {
		return nil, NewError(http.StatusBadRequest, fmt.Sprintf("artifact exceeds maximum size of %d bytes", maxSize), nil)
	}

	return data, nil
}

// Login authenticates with username and password
func (c *Client) Login(ctx context.Context, username, password string) (*LoginResponse, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("username and password cannot be empty")
	}

	endpoint := c.baseURL + "/v1/auth/login"

	loginReq := LoginRequest{
		Username: username,
		Password: password,
	}

	reqBody, err := json.Marshal(loginReq)
	if err != nil {
		return nil, NewError(http.StatusBadRequest, "failed to marshal login request", err)
	}

	c.logger.Debug("logging in", slog.String("username", username))

	resp, err := c.doRequest(ctx, "POST", endpoint, reqBody)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close() //nolint:errcheck
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var loginResp LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return nil, NewError(resp.StatusCode, "failed to decode login response", err)
	}

	c.logger.Debug("login successful", slog.String("username", username))

	return &loginResp, nil
}

// ListCatalog lists all packages in the catalog
func (c *Client) ListCatalog(ctx context.Context) (*CatalogResponse, error) {
	endpoint := c.baseURL + "/v1/catalog"

	c.logger.Debug("listing catalog")

	resp, err := c.doRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close() //nolint:errcheck
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp)
	}

	var catalogResp CatalogResponse
	if err := json.NewDecoder(resp.Body).Decode(&catalogResp); err != nil {
		return nil, NewError(resp.StatusCode, "failed to decode catalog response", err)
	}

	c.logger.Debug("catalog listed", slog.Int("packages", len(catalogResp.Packages)))

	return &catalogResp, nil
}

// doRequest performs an HTTP request with authentication and custom headers
func (c *Client) doRequest(ctx context.Context, method, endpoint string, body []byte) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return nil, NewError(http.StatusBadRequest, "failed to create request", err)
	}

	// Add standard headers
	req.Header.Set("User-Agent", "mcp-cage/1.0.0")
	if method == "POST" && body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add authentication header
	if c.token != "" {
		AddBearerToken(req, c.token)
	}

	// Use appropriate client based on timeout needs
	var httpClient *http.Client
	if method == "GET" && !bytes.Contains([]byte(endpoint), []byte("/resolve")) && !bytes.Contains([]byte(endpoint), []byte("/catalog")) {
		// Use download client for artifact downloads
		httpClient = c.httpClient
	} else {
		// Use API client for metadata operations
		httpClient = c.apiClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, NewError(http.StatusInternalServerError, "failed to execute request", err)
	}

	return resp, nil
}

// handleErrorResponse handles HTTP error responses
func (c *Client) handleErrorResponse(resp *http.Response) error {
	defer func() {
		_ = resp.Body.Close() //nolint:errcheck
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return NewError(resp.StatusCode, http.StatusText(resp.StatusCode), err)
	}

	// Try to unmarshal as JSON error response
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		Details string `json:"details"`
	}

	_ = json.Unmarshal(body, &errResp) //nolint:errcheck

	message := errResp.Message
	if message == "" {
		message = errResp.Error
	}
	if message == "" {
		message = string(body)
	}
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}

	return NewError(resp.StatusCode, message, nil)
}

// BaseURL returns the registry base URL
func (c *Client) BaseURL() string {
	return c.baseURL
}

// SetBaseURL sets the registry base URL
func (c *Client) SetBaseURL(baseURL string) {
	c.baseURL = baseURL
}

// Close closes the client and its underlying connections
func (c *Client) Close() error {
	// http.Client doesn't need explicit closing, but we can clear it
	return nil
}
