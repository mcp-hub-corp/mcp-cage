package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/mcp-hub-corp/mcp-cage/internal/cache"
	"github.com/mcp-hub-corp/mcp-cage/internal/registry"
	"github.com/spf13/cobra"
)

func init() {
	infoCmd.RunE = runInfo
}

// PackageInfo represents package information for display
type PackageInfo struct {
	Package            string `json:"package"`
	Version            string `json:"version"`
	GitSHA             string `json:"git_sha"`
	Status             string `json:"status"`
	CertificationLevel int    `json:"certification_level"`
	ManifestDigest     string `json:"manifest_digest"`
	ManifestSize       int64  `json:"manifest_size,omitempty"`
	ManifestCached     bool   `json:"manifest_cached"`
	BundleDigest       string `json:"bundle_digest"`
	BundleSize         int64  `json:"bundle_size"`
	BundleCached       bool   `json:"bundle_cached"`
}

// runInfo executes the info command to display package information
func runInfo(cmd *cobra.Command, args []string) error {
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

	// Resolve package reference
	resolveResp, err := registryClient.Resolve(ctx, org, name, version)
	if err != nil {
		return fmt.Errorf("failed to resolve package: %w", err)
	}

	// Build package info
	pkgInfo := PackageInfo{
		Package:            resolveResp.Package,
		Version:            resolveResp.Resolved.Version,
		GitSHA:             resolveResp.Resolved.GitSHA,
		Status:             resolveResp.Resolved.Status,
		CertificationLevel: resolveResp.Resolved.CertificationLevel,
		ManifestDigest:     resolveResp.Resolved.Manifest.Digest,
		BundleDigest:       resolveResp.Resolved.Bundle.Digest,
		BundleSize:         resolveResp.Resolved.Bundle.SizeBytes,
		ManifestCached:     cacheStore.Exists(resolveResp.Resolved.Manifest.Digest, "manifest"),
		BundleCached:       cacheStore.Exists(resolveResp.Resolved.Bundle.Digest, "bundle"),
	}

	// If manifest is cached, get its size
	if pkgInfo.ManifestCached {
		manifestData, err := cacheStore.GetManifest(pkgInfo.ManifestDigest)
		if err == nil {
			pkgInfo.ManifestSize = int64(len(manifestData))
		}
	}

	// Output information
	if jsonOutput {
		return outputJSON(pkgInfo)
	}

	outputInfo(pkgInfo)
	return nil
}

// outputJSON outputs package information as JSON
func outputJSON(info PackageInfo) error {
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal to JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// outputInfo outputs package information in human-readable format
func outputInfo(info PackageInfo) {
	fmt.Println()
	fmt.Printf("  Package:              %s\n", info.Package)
	fmt.Printf("  Version:              %s\n", info.Version)
	fmt.Printf("  Git SHA:              %s\n", info.GitSHA)
	fmt.Printf("  Status:               %s\n", info.Status)
	fmt.Printf("  Certification Level:  %d\n", info.CertificationLevel)
	fmt.Println()

	fmt.Println("  Manifest:")
	fmt.Printf("    Digest:             %s\n", abbreviateDigest(info.ManifestDigest))
	fmt.Printf("    Cached:             %v\n", info.ManifestCached)
	if info.ManifestSize > 0 {
		fmt.Printf("    Size:               %s\n", formatSize(info.ManifestSize))
	}
	fmt.Println()

	fmt.Println("  Bundle:")
	fmt.Printf("    Digest:             %s\n", abbreviateDigest(info.BundleDigest))
	fmt.Printf("    Size:               %s\n", formatSize(info.BundleSize))
	fmt.Printf("    Cached:             %v\n", info.BundleCached)
	fmt.Println()
}

// abbreviateDigest returns a shortened digest for display
func abbreviateDigest(digest string) string {
	if len(digest) > 19 {
		return digest[:19]
	}
	return digest
}
