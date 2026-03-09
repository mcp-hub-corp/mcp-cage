package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/hub"
	"github.com/mcp-hub-corp/mcp-cage/internal/manifest"
	"github.com/mcp-hub-corp/mcp-cage/internal/packaging"
	"github.com/spf13/cobra"
)

var pushFlags struct {
	source  string
	hubURL  string
	token   string
	dryRun  bool
	verbose bool
}

// pushCmd publishes an MCP to the hub
var pushCmd = &cobra.Command{
	Use:   "push <org>/<name>@<version>",
	Short: "Publish an MCP to the hub",
	Long: `Package and publish an MCP to the hub for certification and distribution.

The push command:
1. Validates the source directory
2. Generates a manifest from the source
3. Creates a reproducible tar.gz bundle
4. Uploads the bundle to the hub
5. Queues the MCP for certification analysis

Example:
  mcp push acme/hello-world@1.0.0 --source ./my-mcp
  mcp push myorg/data-tool@2.1.0 --source . --hub-url https://hub.example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runPush,
}

func init() {
	pushCmd.Flags().StringVar(&pushFlags.source, "source", ".", "Source directory containing the MCP")
	pushCmd.Flags().StringVar(&pushFlags.hubURL, "hub-url", "", "Hub URL (defaults to config or env)")
	pushCmd.Flags().StringVar(&pushFlags.token, "token", "", "Authentication token (defaults to stored credentials)")
	pushCmd.Flags().BoolVar(&pushFlags.dryRun, "dry-run", false, "Validate and package without uploading")
	pushCmd.Flags().BoolVarP(&pushFlags.verbose, "verbose", "v", false, "Verbose output")

	//nolint:gocritic // Intentionally disabled: push command not in use currently
	// rootCmd.AddCommand(pushCmd)
}

// runPush executes the push command
func runPush(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Parse package reference: org/name@version (push only supports standard format)
	org, name, version, _, err := parsePackageRef(args[0])
	if err != nil {
		return fmt.Errorf("invalid package reference: %w", err)
	}

	// Validate source directory
	sourceDir, err := filepath.Abs(pushFlags.source)
	if err != nil {
		return fmt.Errorf("failed to resolve source directory: %w", err)
	}

	if _, statErr := os.Stat(sourceDir); statErr != nil {
		return fmt.Errorf("source directory does not exist: %w", statErr)
	}

	fmt.Printf("📦 Packaging %s/%s@%s\n", org, name, version)
	fmt.Printf("   Source: %s\n\n", sourceDir)

	// Step 1: Generate manifest
	if pushFlags.verbose {
		fmt.Println("→ Generating manifest...")
	}

	manifestObj, err := manifest.GenerateManifest(sourceDir, &manifest.PackageRef{
		Org:     org,
		Name:    name,
		Version: version,
	}, nil)
	if err != nil {
		return fmt.Errorf("failed to generate manifest: %w", err)
	}

	if pushFlags.verbose {
		fmt.Printf("  ✓ Manifest generated (schema version: %s)\n", manifestObj.SchemaVersion)
		fmt.Printf("    Transport: %s\n", manifestObj.Transport.Type)
		fmt.Printf("    Entrypoints: %d\n", len(manifestObj.Entrypoints))
	}

	// Step 2: Create bundle
	if pushFlags.verbose {
		fmt.Println("\n→ Creating bundle...")
	}

	// Create temp directory for build artifacts
	tempDir, err := os.MkdirTemp("", "mcp-push-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	bundlePath := filepath.Join(tempDir, "bundle.tar.gz")

	// Create bundler
	bundler := packaging.NewBundler()

	// Load .mcpignore if it exists
	ignoreFile := filepath.Join(sourceDir, ".mcpignore")
	if _, ignoreStatErr := os.Stat(ignoreFile); ignoreStatErr == nil {
		if loadErr := bundler.LoadIgnoreFile(ignoreFile); loadErr != nil {
			return fmt.Errorf("failed to load .mcpignore: %w", loadErr)
		}
		if pushFlags.verbose {
			fmt.Println("  ✓ Loaded .mcpignore")
		}
	}

	// Create bundle
	startTime := time.Now()
	bundleResult, err := bundler.Create(sourceDir, bundlePath)
	if err != nil {
		return fmt.Errorf("failed to create bundle: %w", err)
	}
	duration := time.Since(startTime)

	fmt.Printf("  ✓ Bundle created (%s in %s)\n", formatBytes(bundleResult.CompressedSize), duration.Round(time.Millisecond))
	if pushFlags.verbose {
		fmt.Printf("    Files: %d, Directories: %d\n", bundleResult.FileCount, bundleResult.DirCount)
		fmt.Printf("    Uncompressed: %s\n", formatBytes(bundleResult.UncompressedSize))
		fmt.Printf("    Digest: %s\n", bundleResult.SHA256)
	}

	// Update manifest with bundle digest and size
	manifestObj.Bundle.Digest = bundleResult.SHA256
	manifestObj.Bundle.SizeBytes = bundleResult.CompressedSize

	// Validate manifest
	if validateErr := manifest.Validate(manifestObj); validateErr != nil {
		return fmt.Errorf("manifest validation failed: %w", validateErr)
	}

	// Save manifest to temp file
	manifestPath := filepath.Join(tempDir, "manifest.json")
	if saveErr := manifest.SaveManifest(manifestObj, manifestPath); saveErr != nil {
		return fmt.Errorf("failed to save manifest: %w", saveErr)
	}

	// Calculate manifest digest
	manifestDigest, err := calculateFileDigest(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to calculate manifest digest: %w", err)
	}

	if pushFlags.verbose {
		fmt.Printf("\n  ✓ Manifest saved\n")
		fmt.Printf("    Digest: %s\n", manifestDigest)
	}

	// Dry run: stop here
	if pushFlags.dryRun {
		fmt.Println("\n✓ Dry run completed successfully")
		fmt.Println("\nGenerated files:")
		fmt.Printf("  Bundle: %s (%s)\n", bundlePath, formatBytes(bundleResult.CompressedSize))
		fmt.Printf("  Manifest: %s\n", manifestPath)
		fmt.Println("\nTo publish, run without --dry-run flag")
		return nil
	}

	// Step 3: Initialize upload with hub
	fmt.Println("\n→ Initializing upload...")

	// Get hub URL
	hubURL := pushFlags.hubURL
	if hubURL == "" {
		hubURL = os.Getenv("MCP_HUB_URL")
	}
	if hubURL == "" {
		if cfg != nil && cfg.RegistryURL != "" {
			// Derive hub URL from registry URL (replace "registry" with "hub")
			hubURL = strings.Replace(cfg.RegistryURL, "registry", "hub", 1)
		}
	}
	if hubURL == "" {
		return fmt.Errorf("hub URL not configured (use --hub-url flag or MCP_HUB_URL env var)")
	}

	// Get token
	token := pushFlags.token
	if token == "" {
		token = os.Getenv("MCP_HUB_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("authentication token required (use --token flag or MCP_HUB_TOKEN env var, or run 'mcp login' first)")
	}

	// Create hub client
	hubClient, hubErr := hub.NewClient(hubURL)
	if hubErr != nil {
		return fmt.Errorf("failed to create hub client: %w", hubErr)
	}
	hubClient.SetToken(token)

	// Initialize upload
	initReq := &hub.InitUploadRequest{
		MCPName:      fmt.Sprintf("%s/%s", org, name),
		MCPVersion:   version,
		BundleDigest: bundleResult.SHA256,
	}

	initResp, err := hubClient.InitUpload(ctx, initReq)
	if err != nil {
		return fmt.Errorf("failed to initialize upload: %w", err)
	}

	fmt.Printf("  ✓ Upload initialized (ID: %s)\n", initResp.UploadID)
	if pushFlags.verbose {
		fmt.Printf("    Expires: %s\n", initResp.URLExpiresAt)
	}

	// Step 4: Upload bundle
	fmt.Println("\n→ Uploading bundle...")

	uploadStartTime := time.Now()
	lastProgress := time.Now()
	var lastBytes int64

	err = hubClient.UploadFile(ctx, initResp.BundleUploadURL, bundlePath, func(uploaded, total int64) {
		// Update progress
		now := time.Now()
		if now.Sub(lastProgress) < 200*time.Millisecond && uploaded != total {
			return // Rate limit progress updates
		}

		percent := float64(uploaded) / float64(total) * 100
		speed := float64(uploaded-lastBytes) / now.Sub(lastProgress).Seconds()

		fmt.Printf("\r  Uploading... %.1f%% (%s / %s) at %s/s",
			percent,
			formatBytes(uploaded),
			formatBytes(total),
			formatBytes(int64(speed)))

		lastProgress = now
		lastBytes = uploaded

		if uploaded == total {
			fmt.Println() // New line after completion
		}
	})

	if err != nil {
		return fmt.Errorf("failed to upload bundle: %w", err)
	}

	uploadDuration := time.Since(uploadStartTime)
	fmt.Printf("  ✓ Bundle uploaded (%s)\n", uploadDuration.Round(time.Millisecond))

	// Step 5: Finalize upload
	fmt.Println("\n→ Finalizing upload...")

	finalizeResp, err := hubClient.FinalizeUpload(ctx, initResp.UploadID)
	if err != nil {
		return fmt.Errorf("failed to finalize upload: %w", err)
	}

	fmt.Printf("  ✓ Upload finalized\n")
	fmt.Printf("    Version ID: %s\n", finalizeResp.VersionID)
	fmt.Printf("    Status: %s\n", finalizeResp.Status)

	// Success message
	fmt.Println("\n✅ Successfully published!")
	fmt.Printf("\nYour MCP is now queued for certification analysis.\n")
	fmt.Printf("You can check the status at: %s/versions/%s\n", hubURL, finalizeResp.VersionID)

	if !pushFlags.verbose {
		fmt.Println("\nTip: Use --verbose flag for detailed output")
	}

	return nil
}

// calculateFileDigest calculates the SHA256 digest of a file
func calculateFileDigest(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}

// formatBytes formats bytes into human-readable format
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
