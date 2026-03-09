package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/cache"
	"github.com/mcp-hub-corp/mcp-cage/internal/registry"
	"github.com/spf13/cobra"
)

func init() {
	pullCmd.RunE = runPull
}

// runPull executes the pull command to pre-download a package
func runPull(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("expected exactly one argument")
	}

	ref := args[0]

	// Parse package reference (org/name@version, hub URL, or registry reference)
	org, name, version, refRegistryURL, err := parsePackageRef(ref)
	if err != nil {
		return fmt.Errorf("invalid package reference %q: %w", ref, err)
	}

	// Create logger
	logger := createLogger(cfg.LogLevel)

	// Use registry URL from the reference if provided, otherwise use config
	effectiveRegistryURL := cfg.RegistryURL
	if refRegistryURL != "" {
		effectiveRegistryURL = refRegistryURL
	}

	// Create registry client
	registryClient, err := registry.NewClient(effectiveRegistryURL)
	if err != nil {
		return fmt.Errorf("failed to create registry client: %w", err)
	}
	registryClient.SetLogger(logger)

	// Load stored authentication token
	tokenStorage := registry.NewTokenStorage(cfg.CacheDir)
	if token, loadErr := tokenStorage.Load(); loadErr == nil && token != nil && !token.IsExpired() {
		registryClient.SetToken(token.AccessToken)
		logger.Debug("loaded stored authentication token")
	}

	// Create cache store
	cacheStore, err := cache.NewStore(cfg.CacheDir)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}

	logger.Info("resolving package", slog.String("package", fmt.Sprintf("%s/%s", org, name)), slog.String("ref", version))

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	// Resolve package reference to get manifest and bundle info
	resolveResp, err := registryClient.Resolve(ctx, org, name, version)
	if err != nil {
		return fmt.Errorf("failed to resolve package: %w", err)
	}

	manifestDigest := resolveResp.Resolved.Manifest.Digest
	bundleDigest := resolveResp.Resolved.Bundle.Digest
	bundleSize := resolveResp.Resolved.Bundle.SizeBytes

	logger.Info("package resolved",
		slog.String("version", resolveResp.Resolved.Version),
		slog.String("manifest_digest", manifestDigest),
		slog.String("bundle_digest", bundleDigest),
		slog.Int64("bundle_size", bundleSize),
	)

	// Check if manifest is already in cache
	if cacheStore.Exists(manifestDigest, "manifest") {
		logger.Info("manifest already cached", slog.String("digest", manifestDigest))
	} else {
		logger.Info("downloading manifest", slog.String("digest", manifestDigest))
		manifestData, err := registryClient.DownloadManifest(ctx, org, manifestDigest)
		if err != nil {
			return fmt.Errorf("failed to download manifest: %w", err)
		}

		// Validate digest
		if err := registry.ValidateDigest(manifestData, manifestDigest); err != nil {
			return fmt.Errorf("manifest digest validation failed: %w", err)
		}

		// Store in cache
		if err := cacheStore.PutManifest(manifestDigest, manifestData); err != nil {
			return fmt.Errorf("failed to cache manifest: %w", err)
		}

		logger.Info("manifest cached successfully",
			slog.String("digest", manifestDigest),
			slog.Int("size", len(manifestData)),
		)
	}

	// Check if bundle is already in cache
	if cacheStore.Exists(bundleDigest, "bundle") {
		logger.Info("bundle already cached", slog.String("digest", bundleDigest))
		fmt.Printf("Pulling %s/%s@%s\n", org, name, resolveResp.Resolved.Version)
		fmt.Printf("Already cached: %s\n", bundleDigest[:19])
	} else {
		logger.Info("downloading bundle", slog.String("digest", bundleDigest), slog.Int64("size", bundleSize))
		fmt.Printf("Pulling %s/%s@%s\n", org, name, resolveResp.Resolved.Version)
		fmt.Printf("Downloading bundle: %s (%s)\n", bundleDigest[:19], formatSize(bundleSize))

		bundleData, err := registryClient.DownloadBundle(ctx, org, bundleDigest)
		if err != nil {
			return fmt.Errorf("failed to download bundle: %w", err)
		}

		// Validate digest
		if err := registry.ValidateDigest(bundleData, bundleDigest); err != nil {
			return fmt.Errorf("bundle digest validation failed: %w", err)
		}

		// Store in cache
		if err := cacheStore.PutBundle(bundleDigest, bundleData); err != nil {
			return fmt.Errorf("failed to cache bundle: %w", err)
		}

		logger.Info("bundle cached successfully",
			slog.String("digest", bundleDigest),
			slog.Int("size", len(bundleData)),
		)

		fmt.Printf("Downloaded and cached successfully\n")
	}

	fmt.Printf("Package ready: %s@%s\n", fmt.Sprintf("%s/%s", org, name), resolveResp.Resolved.Version)

	return nil
}

// parsePackageRef parses a package reference in one of three formats:
//
//  1. Standard:          org/name@version
//  2. Hub URL:           https://mcp-hub.info/mcp/{owner}/{name}
//  3. Registry reference: registry.mcp-hub.info/npm/{org}/{name}@{version}
//     or {host}/npm/{org}/{name}@{version}
//
// Returns org, name, version, registryURL (empty string means use default), and error.
func parsePackageRef(ref string) (org, name, version, registryURL string, err error) {
	// Format 2: Hub URL (starts with http:// or https://)
	if strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://") {
		return parseHubURL(ref)
	}

	// Format 3: Registry reference (contains a host with dot before /npm/)
	// e.g. registry.mcp-hub.info/npm/public/mcp-schrodinger@commit-f3d3d1a-2026-02-20
	if idx := strings.Index(ref, "/npm/"); idx > 0 {
		host := ref[:idx]
		// Verify it looks like a hostname (contains a dot)
		if strings.Contains(host, ".") {
			return parseRegistryRef(ref, host, ref[idx+len("/npm/"):])
		}
	}

	// Format 1: Standard org/name@version
	parts := strings.SplitN(ref, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", "", "", "", fmt.Errorf("expected format org/name@version, hub URL, or registry reference")
	}

	orgName := parts[0]
	version = parts[1]

	orgNameParts := strings.SplitN(orgName, "/", 2)
	if len(orgNameParts) != 2 {
		return "", "", "", "", fmt.Errorf("expected format org/name@version")
	}

	org = orgNameParts[0]
	name = orgNameParts[1]

	if org == "" || name == "" {
		return "", "", "", "", fmt.Errorf("org, name, and version cannot be empty")
	}

	return org, name, version, "", nil
}

// parseHubURL parses a Hub URL like https://mcp-hub.info/mcp/{owner}/{name}
// and queries the Hub API to resolve the latest certified version.
func parseHubURL(rawURL string) (org, name, version, registryURL string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", "", "", fmt.Errorf("parsing hub URL: %w", err)
	}

	// Expected path: /mcp/{owner}/{name}
	pathParts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(pathParts) != 3 || pathParts[0] != "mcp" {
		return "", "", "", "", fmt.Errorf("hub URL must have path /mcp/{owner}/{name}, got %s", u.Path)
	}

	owner := pathParts[1]
	slug := pathParts[2]

	if owner == "" || slug == "" {
		return "", "", "", "", fmt.Errorf("owner and name cannot be empty in hub URL")
	}

	// Query the Hub API to get the latest certified version
	hubBaseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	resolvedOrg, resolvedName, resolvedVersion, err := resolveHubMCP(hubBaseURL, owner, slug)
	if err != nil {
		return "", "", "", "", fmt.Errorf("resolving hub URL %s: %w", rawURL, err)
	}

	// Hub URL always uses the default registry
	return resolvedOrg, resolvedName, resolvedVersion, "", nil
}

// parseRegistryRef parses a registry reference like
// registry.mcp-hub.info/npm/{org}/{name}@{version}
func parseRegistryRef(fullRef, host, remainder string) (org, name, version, registryURL string, err error) {
	// remainder is e.g. "public/mcp-schrodinger@commit-f3d3d1a-2026-02-20"
	// Split by @ to separate name and version
	parts := strings.SplitN(remainder, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", "", "", "", fmt.Errorf("registry reference must include @version: %s", fullRef)
	}

	orgAndName := parts[0]
	version = parts[1]

	// Split org/name
	orgNameParts := strings.SplitN(orgAndName, "/", 2)
	if len(orgNameParts) != 2 {
		return "", "", "", "", fmt.Errorf("registry reference must have format {host}/npm/{org}/{name}@{version}: %s", fullRef)
	}

	org = orgNameParts[0]
	name = orgNameParts[1]

	if org == "" || name == "" {
		return "", "", "", "", fmt.Errorf("org and name cannot be empty in registry reference")
	}

	registryURL = "https://" + host

	return org, name, version, registryURL, nil
}

// hubMCPResponse represents the relevant fields from the Hub API response
// for GET /api/v1/mcps/{owner}/{slug}
type hubMCPResponse struct {
	Name          string            `json:"name"`
	LatestVersion *hubLatestVersion `json:"latest_version"`
}

// hubLatestVersion represents the latest_version object from the Hub API
type hubLatestVersion struct {
	CommitHash string `json:"commit_hash"`
	Status     string `json:"status"`
}

// hubVersionsResponse represents the response from GET /api/v1/mcps/{owner}/{slug}/versions
type hubVersionsResponse struct {
	Versions []hubMCPVersion `json:"versions"`
}

// hubMCPVersion represents a version entry from the Hub API /versions endpoint
type hubMCPVersion struct {
	VisibleVersion string `json:"visible_version"`
	CommitHash     string `json:"commit_hash"`
	GlobalScore    int    `json:"global_score"`
	Status         string `json:"status"`
}

// resolveHubMCP queries the Hub API to get the latest certified version info.
// It first tries the /versions endpoint for visible_version, then falls back
// to the main endpoint's latest_version.commit_hash to construct the version.
// Returns org (defaults to "community" for names without "/"), name, and version.
func resolveHubMCP(hubBaseURL, owner, slug string) (org, name, version string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step 1: Get MCP info for the name
	mcpURL := fmt.Sprintf("%s/api/v1/mcps/%s/%s",
		hubBaseURL,
		url.PathEscape(owner),
		url.PathEscape(slug),
	)

	mcpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, mcpURL, http.NoBody)
	if err != nil {
		return "", "", "", fmt.Errorf("creating hub API request: %w", err)
	}
	mcpReq.Header.Set("User-Agent", fmt.Sprintf("mcp-client/%s", Version))
	mcpReq.Header.Set("Accept", "application/json")

	mcpResp, err := http.DefaultClient.Do(mcpReq)
	if err != nil {
		return "", "", "", fmt.Errorf("querying hub API at %s: %w", mcpURL, err)
	}
	defer func() { _ = mcpResp.Body.Close() }()

	if mcpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(mcpResp.Body, 1024))
		return "", "", "", fmt.Errorf("hub API returned status %d for %s/%s: %s",
			mcpResp.StatusCode, owner, slug, string(body))
	}

	var mcpData hubMCPResponse
	if decodeErr := json.NewDecoder(mcpResp.Body).Decode(&mcpData); decodeErr != nil {
		return "", "", "", fmt.Errorf("decoding hub API response: %w", decodeErr)
	}

	// Step 2: Try to get version from /versions endpoint (has visible_version)
	versionsURL := fmt.Sprintf("%s/api/v1/mcps/%s/%s/versions",
		hubBaseURL,
		url.PathEscape(owner),
		url.PathEscape(slug),
	)

	versionsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, versionsURL, http.NoBody)
	if err != nil {
		return "", "", "", fmt.Errorf("creating hub versions request: %w", err)
	}
	versionsReq.Header.Set("User-Agent", fmt.Sprintf("mcp-client/%s", Version))
	versionsReq.Header.Set("Accept", "application/json")

	versionsResp, err := http.DefaultClient.Do(versionsReq)
	if err == nil && versionsResp.StatusCode == http.StatusOK {
		defer func() { _ = versionsResp.Body.Close() }()
		var versionsData hubVersionsResponse
		if decErr := json.NewDecoder(versionsResp.Body).Decode(&versionsData); decErr == nil {
			// Find best version by score, preferring PUBLISHED status
			var bestVersion *hubMCPVersion
			for i := range versionsData.Versions {
				v := &versionsData.Versions[i]
				if v.Status != "PUBLISHED" {
					continue
				}
				if bestVersion == nil || v.GlobalScore > bestVersion.GlobalScore {
					bestVersion = v
				}
			}
			if bestVersion != nil && bestVersion.VisibleVersion != "" {
				version = bestVersion.VisibleVersion
			} else if bestVersion != nil && bestVersion.CommitHash != "" {
				// Construct version from commit hash (same format as hub)
				version = "commit-" + bestVersion.CommitHash[:7] + "-" + time.Now().Format("2006-01-02")
			}
		}
	} else if versionsResp != nil {
		_ = versionsResp.Body.Close()
	}

	// Step 3: Fall back to latest_version from main endpoint
	if version == "" {
		if mcpData.LatestVersion == nil || mcpData.LatestVersion.CommitHash == "" {
			return "", "", "", fmt.Errorf("no certified version found for %s/%s", owner, slug)
		}
		// Construct version string from commit hash
		version = "commit-" + mcpData.LatestVersion.CommitHash[:7] + "-" + time.Now().Format("2006-01-02")
	}

	// Extract org and name from MCP name
	mcpName := mcpData.Name
	if mcpName == "" {
		mcpName = slug
	}

	if strings.Contains(mcpName, "/") {
		parts := strings.SplitN(mcpName, "/", 2)
		org = parts[0]
		name = parts[1]
	} else {
		org = "community"
		name = mcpName
	}

	return org, name, version, nil
}

// formatSize formats a byte size into a human-readable string
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB"}
	if exp > 0 && exp <= len(units) {
		return fmt.Sprintf("%.2f %s", float64(bytes)/float64(div), units[exp-1])
	}

	return fmt.Sprintf("%d B", bytes)
}

// createLogger creates a structured logger with the specified level
func createLogger(level string) *slog.Logger {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	handler := NewPrettyHandler(os.Stderr, opts)
	return slog.New(handler)
}
