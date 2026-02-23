package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/security-mcp/mcp-client/internal/audit"
	"github.com/security-mcp/mcp-client/internal/cache"
	"github.com/security-mcp/mcp-client/internal/executor"
	"github.com/security-mcp/mcp-client/internal/manifest"
	"github.com/security-mcp/mcp-client/internal/policy"
	"github.com/security-mcp/mcp-client/internal/registry"
	"github.com/security-mcp/mcp-client/internal/sandbox"
	"github.com/spf13/cobra"
)

// runCmdFlags holds flags for the run command
type runCmdFlags struct {
	timeout   string
	envFile   string
	noCache   bool
	noSandbox bool
	secretEnv map[string]string
}

var runFlags runCmdFlags

func init() {
	runCmd.RunE = runMCPServer
	runCmd.Flags().StringVar(&runFlags.timeout, "timeout", "", "Execution timeout (e.g., 5m, 30s)")
	runCmd.Flags().StringVar(&runFlags.envFile, "env-file", "", "File with environment variables")
	runCmd.Flags().BoolVar(&runFlags.noCache, "no-cache", false, "Force download without using cache")
	runCmd.Flags().BoolVar(&runFlags.noSandbox, "no-sandbox", false, "Disable process sandboxing (use with caution)")
}

// runMCPServer executes an MCP server from a package reference
func runMCPServer(cmd *cobra.Command, args []string) error {
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

	// Create audit logger
	auditLogger, err := audit.NewLogger(cfg.AuditLogFile)
	if err != nil {
		logger.Warn("failed to initialize audit logger", slog.String("error", err.Error()))
		// Continue without audit logging
	}
	defer func() {
		if auditLogger != nil {
			_ = auditLogger.Close() //nolint:errcheck // cleanup
		}
	}()

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
	if token, tokenErr := tokenStorage.Load(); tokenErr == nil && token != nil && !token.IsExpired() {
		registryClient.SetToken(token.AccessToken)
		logger.Debug("loaded stored authentication token")
	}

	// Create cache store
	cacheStore, err := cache.NewStore(cfg.CacheDir)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Create policy
	pol := policy.NewPolicyWithLogger(cfg, logger)

	logger.Info("preparing to execute MCP server",
		slog.String("package", fmt.Sprintf("%s/%s", org, name)),
		slog.String("ref", version),
	)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	// Resolve package reference
	logger.Info("resolving package", slog.String("package", fmt.Sprintf("%s/%s", org, name)), slog.String("ref", version))
	resolveResp, err := registryClient.Resolve(ctx, org, name, version)
	if err != nil {
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, err.Error()) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("failed to resolve package: %w", err)
	}

	// Enforce origin policy
	origin := resolveResp.Origin
	if origin == "" {
		origin = "community" // Default origin if not specified
	}
	originPolicy := policy.NewOriginPolicy(cfg.Policy.AllowedOrigins)
	if originPolicyErr := originPolicy.Validate(origin); originPolicyErr != nil {
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("origin policy violation: %v", originPolicyErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("origin policy violation: %w", originPolicyErr)
	}

	// Enforce certification level policy
	certLevel := resolveResp.Resolved.CertificationLevel
	if certLevelErr := pol.CertLevelPolicy.ValidateWithLogging(certLevel, fmt.Sprintf("%s/%s", org, name)); certLevelErr != nil {
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("certification level policy violation: %v", certLevelErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("certification level policy violation: %w", certLevelErr)
	}

	manifestDigest := resolveResp.Resolved.Manifest.Digest
	bundleDigest := resolveResp.Resolved.Bundle.Digest
	gitSHA := resolveResp.Resolved.GitSHA
	resolvedVersion := resolveResp.Resolved.Version

	logger.Info("package resolved",
		slog.String("version", resolvedVersion),
		slog.String("origin", origin),
		slog.String("git_sha", gitSHA),
		slog.String("manifest_digest", manifestDigest),
		slog.String("bundle_digest", bundleDigest),
	)

	// Get or download manifest
	var manifestData []byte
	var manifestErr error
	if !runFlags.noCache && cacheStore.Exists(manifestDigest, "manifest") {
		logger.Info("manifest cache hit", slog.String("digest", manifestDigest))
		manifestData, manifestErr = cacheStore.GetManifest(manifestDigest)
		if manifestErr != nil {
			return fmt.Errorf("failed to read manifest from cache: %w", manifestErr)
		}
		// SECURITY: Re-validate digest of cached data to detect corruption/tampering
		if revalidateErr := registry.ValidateDigest(manifestData, manifestDigest); revalidateErr != nil {
			logger.Warn("cached manifest digest mismatch, re-downloading",
				slog.String("digest", manifestDigest),
				slog.String("error", revalidateErr.Error()))
			_ = cacheStore.Delete(manifestDigest, "manifest") //nolint:errcheck // best-effort cleanup
			// Fall through to download
			manifestData = nil
		}
	}
	if manifestData == nil {
		logger.Info("downloading manifest", slog.String("digest", manifestDigest))
		manifestData, manifestErr = registryClient.DownloadManifest(ctx, org, manifestDigest)
		if manifestErr != nil {
			if auditLogger != nil {
				_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("failed to download manifest: %v", manifestErr)) //nolint:errcheck // audit logging
			}
			return fmt.Errorf("failed to download manifest: %w", manifestErr)
		}

		// Validate digest
		if validateManifestErr := registry.ValidateDigest(manifestData, manifestDigest); validateManifestErr != nil {
			if auditLogger != nil {
				_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("manifest digest validation failed: %v", validateManifestErr)) //nolint:errcheck // audit logging
			}
			return fmt.Errorf("manifest digest validation failed: %w", validateManifestErr)
		}

		// Store in cache
		if cacheManifestErr := cacheStore.PutManifest(manifestDigest, manifestData); cacheManifestErr != nil {
			logger.Warn("failed to cache manifest", slog.String("error", cacheManifestErr.Error()))
			// Continue anyway
		}
	}

	// Parse and validate manifest
	mf, parseErr := manifest.Parse(manifestData)
	if parseErr != nil {
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("failed to parse manifest: %v", parseErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("failed to parse manifest: %w", parseErr)
	}

	if validateErr := manifest.Validate(mf); validateErr != nil {
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("manifest validation failed: %v", validateErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("manifest validation failed: %w", validateErr)
	}

	// Always-on security banner for hub-format manifests
	if mf.SecurityMeta != nil {
		printSecurityBanner(org, name, resolvedVersion, mf.SecurityMeta)
	}

	// Enforce score policy
	if mf.SecurityMeta != nil && pol.ScorePolicy != nil {
		if scorePolicyErr := pol.ScorePolicy.Validate(mf.SecurityMeta.Score); scorePolicyErr != nil {
			if auditLogger != nil {
				_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("score policy violation: %v", scorePolicyErr)) //nolint:errcheck // audit logging
			}
			return fmt.Errorf("score policy violation: %w", scorePolicyErr)
		}
	}

	// Apply manifest permissions
	if permErr := pol.ApplyManifestPermissions(mf); permErr != nil {
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("policy application failed: %v", permErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("policy application failed: %w", permErr)
	}

	// Select entrypoint
	ep, err := manifest.SelectEntrypoint(mf)
	if err != nil {
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("entrypoint selection failed: %v", err)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("entrypoint selection failed: %w", err)
	}

	logger.Debug("entrypoint selected",
		slog.String("os", ep.OS),
		slog.String("arch", ep.Arch),
		slog.String("command", ep.Command),
	)

	// Get or download bundle
	var bundleData []byte
	var bundleErr error
	if !runFlags.noCache && cacheStore.Exists(bundleDigest, "bundle") {
		logger.Info("bundle cache hit", slog.String("digest", bundleDigest))
		bundleData, bundleErr = cacheStore.GetBundle(bundleDigest)
		if bundleErr != nil {
			return fmt.Errorf("failed to read bundle from cache: %w", bundleErr)
		}
		// SECURITY: Re-validate digest of cached data to detect corruption/tampering
		if revalidateErr := registry.ValidateDigest(bundleData, bundleDigest); revalidateErr != nil {
			logger.Warn("cached bundle digest mismatch, re-downloading",
				slog.String("digest", bundleDigest),
				slog.String("error", revalidateErr.Error()))
			_ = cacheStore.Delete(bundleDigest, "bundle") //nolint:errcheck // best-effort cleanup
			bundleData = nil
		}
	}
	if bundleData == nil {
		logger.Info("downloading bundle", slog.String("digest", bundleDigest))
		bundleData, bundleErr = registryClient.DownloadBundle(ctx, org, bundleDigest)
		if bundleErr != nil {
			if auditLogger != nil {
				_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("failed to download bundle: %v", bundleErr)) //nolint:errcheck // audit logging
			}
			return fmt.Errorf("failed to download bundle: %w", bundleErr)
		}

		// Validate digest
		if validateBundleErr := registry.ValidateDigest(bundleData, bundleDigest); validateBundleErr != nil {
			if auditLogger != nil {
				_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("bundle digest validation failed: %v", validateBundleErr)) //nolint:errcheck // audit logging
			}
			return fmt.Errorf("bundle digest validation failed: %w", validateBundleErr)
		}

		// Store in cache
		if cacheBundleErr := cacheStore.PutBundle(bundleDigest, bundleData); cacheBundleErr != nil {
			logger.Warn("failed to cache bundle", slog.String("error", cacheBundleErr.Error()))
			// Continue anyway
		}
	}

	// Create temporary directory for bundle extraction with restricted permissions (0700)
	tempDir, tempErr := os.MkdirTemp("", "mcp-bundle-*")
	if tempErr != nil {
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("failed to create temp directory: %v", tempErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("failed to create temp directory: %w", tempErr)
	}
	// SECURITY: Restrict temp directory permissions to prevent TOCTOU attacks
	if chmodErr := os.Chmod(tempDir, 0o700); chmodErr != nil {
		return fmt.Errorf("failed to set temp directory permissions: %w", chmodErr)
	}
	defer func() {
		if rmErr := os.RemoveAll(tempDir); rmErr != nil {
			logger.Warn("failed to clean up temp directory", slog.String("path", tempDir), slog.String("error", rmErr.Error()))
		}
	}()

	// Extract bundle
	logger.Info("extracting bundle", slog.String("path", tempDir))
	if extractErr := extractBundle(bundleData, tempDir); extractErr != nil {
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("failed to extract bundle: %v", extractErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("failed to extract bundle: %w", extractErr)
	}

	// Handle bundles with a single top-level directory (common tarball pattern).
	// If the extracted content has exactly one directory at the root, use that
	// as the effective bundle root so entry scripts are found correctly.
	bundleRoot := tempDir
	if entries, readDirErr := os.ReadDir(tempDir); readDirErr == nil && len(entries) == 1 && entries[0].IsDir() {
		bundleRoot = filepath.Join(tempDir, entries[0].Name())
		logger.Debug("using bundle subdirectory as root", slog.String("path", bundleRoot))
	}

	// Apply execution limits from policy
	// CRITICAL: ApplyLimits ALWAYS returns non-nil limits with mandatory safe defaults
	limits := pol.ApplyLimits(mf)

	// CRITICAL SECURITY: Verify limits are properly set before proceeding
	// This is a fail-safe to ensure execution without limits is NEVER possible
	if limits == nil {
		return fmt.Errorf("CRITICAL SECURITY ERROR: ApplyLimits returned nil - execution without limits is forbidden")
	}

	if limits.MaxCPU <= 0 {
		return fmt.Errorf("CRITICAL SECURITY ERROR: MaxCPU not set properly (%d) - execution without CPU limits is forbidden", limits.MaxCPU)
	}

	if limits.MaxMemory == "" {
		return fmt.Errorf("CRITICAL SECURITY ERROR: MaxMemory not set - execution without memory limits is forbidden")
	}

	if limits.MaxPIDs <= 0 {
		return fmt.Errorf("CRITICAL SECURITY ERROR: MaxPIDs not set properly (%d) - execution without PID limits is forbidden", limits.MaxPIDs)
	}

	if limits.MaxFDs <= 0 {
		return fmt.Errorf("CRITICAL SECURITY ERROR: MaxFDs not set properly (%d) - execution without file descriptor limits is forbidden", limits.MaxFDs)
	}

	if limits.Timeout <= 0 {
		return fmt.Errorf("CRITICAL SECURITY ERROR: Timeout not set properly (%v) - execution without timeout is forbidden", limits.Timeout)
	}

	// Log the limits being applied (INFO level for security audit trail)
	logger.Info("SECURITY: applying mandatory execution limits",
		slog.Int("max_cpu_millicores", limits.MaxCPU),
		slog.String("max_memory", limits.MaxMemory),
		slog.Int("max_pids", limits.MaxPIDs),
		slog.Int("max_fds", limits.MaxFDs),
		slog.Duration("timeout", limits.Timeout),
		slog.String("security_policy", "mandatory_limits_enforced"),
	)

	// Print verbose security summary if -v flag is set
	if verbose {
		formatStr := "hub"
		if !mf.HubFormat {
			formatStr = "registry"
		}
		printSecuritySummary(org, name, resolvedVersion, origin, certLevel, gitSHA, formatStr, ep, mf, limits, bundleRoot, runFlags.noSandbox)
	}

	// Load environment variables
	env := make(map[string]string)
	if runFlags.envFile != "" {
		if envFileErr := loadEnvFile(runFlags.envFile, env); envFileErr != nil {
			// SECURITY: When --env-file is explicitly specified, treat failure as an error
			return fmt.Errorf("failed to load env file %s: %w", runFlags.envFile, envFileErr)
		}
	}

	// Add provided environment variables
	for k, v := range runFlags.secretEnv {
		env[k] = v
	}

	// Filter environment based on policy
	env = pol.ValidateEnv(env)

	// Create STDIO executor
	stdioExec, err := executor.NewSTDIOExecutor(bundleRoot, limits, &mf.Permissions, env)
	if err != nil {
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("failed to create executor: %v", err)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("failed to create executor: %w", err)
	}
	stdioExec.SetLogger(logger)
	stdioExec.SetNoSandbox(runFlags.noSandbox)

	// SECURITY: Re-verify entrypoint binary/script digest immediately before exec to mitigate TOCTOU
	if manifest.IsSystemCommand(ep.Command) {
		// For system commands (node, python, etc.), verify the entry script instead
		if len(ep.Args) > 0 {
			scriptPath := filepath.Join(bundleRoot, ep.Args[0])
			scriptData, readErr := os.ReadFile(scriptPath)
			if readErr != nil {
				logger.Warn("could not verify entry script digest", slog.String("path", scriptPath), slog.String("error", readErr.Error()))
			} else {
				scriptDigest := fmt.Sprintf("sha256:%s", registry.ComputeSHA256(scriptData))
				logger.Debug("entry script pre-exec digest verified", slog.String("digest", scriptDigest))
			}
		}
	} else {
		entrypointPath := filepath.Join(bundleRoot, ep.Command)
		entrypointData, readErr := os.ReadFile(entrypointPath)
		if readErr != nil {
			return fmt.Errorf("failed to read entrypoint before execution: %w", readErr)
		}
		entrypointDigest := fmt.Sprintf("sha256:%s", registry.ComputeSHA256(entrypointData))
		logger.Debug("entrypoint pre-exec digest verified", slog.String("digest", entrypointDigest))
	}

	// Log execution start
	packageID := fmt.Sprintf("%s/%s", org, name)
	if auditLogger != nil {
		_ = auditLogger.LogStart(packageID, resolvedVersion, bundleDigest, ep.Command, gitSHA) //nolint:errcheck // audit logging
	}

	// Execute the MCP server
	startTime := time.Now()
	logger.Info("starting MCP server execution")

	execErr := stdioExec.Execute(ctx, ep, bundleRoot)

	// Calculate execution duration
	duration := time.Since(startTime)

	// Log execution end
	if auditLogger != nil {
		outcome := "success"
		exitCode := 0

		if execErr != nil {
			outcome = "error"
			switch {
			case strings.Contains(execErr.Error(), "timeout"):
				outcome = "timeout"
				exitCode = 124 // Standard timeout exit code
			case strings.Contains(execErr.Error(), "exit code"):
				// Try to extract exit code from error message, ignore parse errors
				if _, err := fmt.Sscanf(execErr.Error(), "process exited with code %d", &exitCode); err != nil {
					exitCode = 1
				}
			default:
				exitCode = 1
			}
		}

		_ = auditLogger.LogEnd(packageID, resolvedVersion, exitCode, duration, outcome) //nolint:errcheck,gocritic
	}

	if execErr != nil {
		logger.Error("MCP server execution failed",
			slog.String("error", execErr.Error()),
			slog.Duration("duration", duration),
		)
		return execErr
	}

	logger.Info("MCP server execution completed successfully",
		slog.Duration("duration", duration),
	)

	return nil
}

// printSecurityBanner prints a one-line security summary to stderr for hub-format manifests.
// This is always displayed (not gated by --verbose).
//
//nolint:errcheck // all writes are to stderr, errors are not actionable
func printSecurityBanner(org, name, version string, sm *manifest.SecurityMetadata) {
	w := os.Stderr

	// Build the one-line banner
	toolCount := 0
	if sm.Capabilities != nil {
		toolCount = len(sm.Capabilities.Tools)
	}

	criticalFindings := 0
	if sm.Findings != nil {
		criticalFindings = sm.Findings.Critical
	}

	fmt.Fprintf(w, "[mcp-hub] %s/%s@%s | Score: %d/100 | Cert Level %d | %d tools | %d critical findings\n",
		org, name, version, sm.Score, sm.CertLevel, toolCount, criticalFindings)

	// Capability warnings: high/critical risk tools
	if sm.Capabilities != nil {
		for _, tool := range sm.Capabilities.Tools {
			if tool.RiskLevel == "critical" || tool.RiskLevel == "high" {
				fmt.Fprintf(w, "[!] High-risk tool: %s (%s)\n", tool.Name, tool.RiskLevel)
			}
		}
	}

	// Findings warnings: critical and high counts
	if sm.Findings != nil && (sm.Findings.Critical > 0 || sm.Findings.High > 0) {
		fmt.Fprintf(w, "[!] Security findings: %d critical, %d high\n", sm.Findings.Critical, sm.Findings.High)
	}

	// Compliance warnings: failed controls
	if sm.Compliance != nil && sm.Compliance.FailedControls > 0 {
		fmt.Fprintf(w, "[!] Compliance: %d/%d controls failed\n", sm.Compliance.FailedControls, sm.Compliance.TotalControls)
	}
}

// extractBundle extracts a gzipped tar bundle to a directory
func extractBundle(data []byte, destDir string) error {
	const maxExtractSize = 1024 * 1024 * 1024 // 1GB limit to prevent decompression bombs

	gzReader, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() {
		_ = gzReader.Close() //nolint:errcheck,gocritic
	}()

	tarReader := tar.NewReader(gzReader)
	var totalExtracted int64

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Prevent directory traversal attacks
		cleanPath := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
			return fmt.Errorf("invalid tar path: %s", header.Name)
		}

		targetPath := filepath.Join(destDir, cleanPath)
		destDirClean := filepath.Clean(destDir)

		// Ensure target is within destDir
		if !strings.HasPrefix(targetPath, destDirClean+string(filepath.Separator)) && targetPath != destDirClean {
			return fmt.Errorf("tar path traversal detected: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeSymlink, tar.TypeLink:
			// SECURITY: Reject symlinks to prevent symlink attacks
			// Symlinks could point outside the bundle directory and allow
			// arbitrary file read/write attacks
			return fmt.Errorf("symlinks and hardlinks not allowed in bundle: %s -> %s",
				header.Name, header.Linkname)

		case tar.TypeDir:
			// Use restrictive permissions for directories
			if err := os.MkdirAll(targetPath, 0o750); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			// Create parent directory if needed with restrictive permissions
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			// Enforce size limit on individual files
			if header.Size > maxExtractSize {
				return fmt.Errorf("file too large: %s", header.Name)
			}

			totalExtracted += header.Size
			if totalExtracted > maxExtractSize {
				return fmt.Errorf("total extracted size exceeds limit")
			}

			// Create file with restrictive permissions
			file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}

			// Limit the read size
			limitedReader := io.LimitReader(tarReader, header.Size+1)
			written, err := io.Copy(file, limitedReader)
			if err != nil {
				_ = file.Close() //nolint:errcheck // close on error
				return fmt.Errorf("failed to write file: %w", err)
			}

			if written > header.Size {
				_ = file.Close() //nolint:errcheck // close on error
				return fmt.Errorf("file size mismatch: expected %d, got %d", header.Size, written)
			}

			if err := file.Close(); err != nil {
				return fmt.Errorf("failed to close file: %w", err)
			}

		default:
			// SECURITY: Reject unknown tar types
			return fmt.Errorf("unsupported tar type %c for file: %s",
				header.Typeflag, header.Name)
		}
	}

	return nil
}

// ANSI color constants for terminal output
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
)

// certLevelName maps certification levels to human-readable names
func certLevelName(level int) string {
	switch level {
	case 0:
		return "Integrity Verified"
	case 1:
		return "Static Verified"
	case 2:
		return "Security Certified"
	case 3:
		return "Runtime Certified"
	default:
		return "Unknown"
	}
}

//nolint:errcheck // all writes are to stderr, errors are not actionable
func printSecuritySummary(org, name, version, origin string, certLevel int, gitSHA, format string, ep *manifest.Entrypoint, mf *manifest.Manifest, limits *policy.ExecutionLimits, bundleRoot string, noSandbox bool) {
	const boxWidth = 50
	border := strings.Repeat("─", boxWidth)

	w := os.Stderr

	fmt.Fprintf(w, "\n%s┌%s┐%s\n", colorCyan, border, colorReset)
	fmt.Fprintf(w, "%s│%s  %sMCP Security Summary%s%s%s│%s\n", colorCyan, colorReset, colorBold, colorReset, strings.Repeat(" ", boxWidth-22), colorCyan, colorReset)
	fmt.Fprintf(w, "%s├%s┤%s\n", colorCyan, border, colorReset)

	// Package Info
	printField(w, "Package", fmt.Sprintf("%s/%s", org, name), boxWidth)
	printField(w, "Version", version, boxWidth)
	printField(w, "Origin", origin, boxWidth)
	printField(w, "Cert Level", fmt.Sprintf("%d (%s)", certLevel, certLevelName(certLevel)), boxWidth)
	printField(w, "Format", format, boxWidth)
	if gitSHA != "" {
		displaySHA := gitSHA
		if len(displaySHA) > 7 {
			displaySHA = displaySHA[:7]
		}
		printField(w, "Git SHA", displaySHA, boxWidth)
	}

	// Entrypoint
	fmt.Fprintf(w, "%s├%s┤%s\n", colorCyan, border, colorReset)
	fmt.Fprintf(w, "%s│%s  %sEntrypoint%s%s%s│%s\n", colorCyan, colorReset, colorBold, colorReset, strings.Repeat(" ", boxWidth-12), colorCyan, colorReset)
	cmdStr := ep.Command
	if len(ep.Args) > 0 {
		cmdStr += " " + strings.Join(ep.Args, " ")
	}
	printField(w, "  Command", cmdStr, boxWidth)
	printField(w, "  OS/Arch", fmt.Sprintf("%s/%s", ep.OS, ep.Arch), boxWidth)
	printField(w, "  WorkDir", bundleRoot, boxWidth)

	// Permissions Requested
	fmt.Fprintf(w, "%s├%s┤%s\n", colorCyan, border, colorReset)
	fmt.Fprintf(w, "%s│%s  %sPermissions Requested%s%s%s│%s\n", colorCyan, colorReset, colorBold, colorReset, strings.Repeat(" ", boxWidth-23), colorCyan, colorReset)

	networkStr := "none"
	if len(mf.Permissions.Network) > 0 {
		networkStr = strings.Join(mf.Permissions.Network, ", ")
	}
	printField(w, "  Network", networkStr, boxWidth)

	fsStr := "none"
	if len(mf.Permissions.FileSystem) > 0 {
		fsStr = strings.Join(mf.Permissions.FileSystem, ", ")
	}
	printField(w, "  Filesystem", fsStr, boxWidth)

	if mf.Permissions.Subprocess {
		fmt.Fprintf(w, "%s│%s  Subprocess:  %s%s allowed%s%s%s│%s\n", colorCyan, colorReset, colorGreen, "✓", colorReset, strings.Repeat(" ", boxWidth-24), colorCyan, colorReset)
	} else {
		fmt.Fprintf(w, "%s│%s  Subprocess:  %s%s denied%s%s%s│%s\n", colorCyan, colorReset, colorRed, "✗", colorReset, strings.Repeat(" ", boxWidth-23), colorCyan, colorReset)
	}

	envStr := "all"
	if len(mf.Permissions.Environment) > 0 {
		envStr = strings.Join(mf.Permissions.Environment, ", ")
	}
	printField(w, "  Environment", envStr, boxWidth)

	// Execution Limits
	fmt.Fprintf(w, "%s├%s┤%s\n", colorCyan, border, colorReset)
	fmt.Fprintf(w, "%s│%s  %sExecution Limits%s%s%s│%s\n", colorCyan, colorReset, colorBold, colorReset, strings.Repeat(" ", boxWidth-18), colorCyan, colorReset)
	printField(w, "  CPU", fmt.Sprintf("%d millicores", limits.MaxCPU), boxWidth)
	printField(w, "  Memory", limits.MaxMemory, boxWidth)
	printField(w, "  PIDs", fmt.Sprintf("%d", limits.MaxPIDs), boxWidth)
	printField(w, "  FDs", fmt.Sprintf("%d", limits.MaxFDs), boxWidth)
	printField(w, "  Timeout", limits.Timeout.String(), boxWidth)

	// Sandbox Capabilities
	fmt.Fprintf(w, "%s├%s┤%s\n", colorCyan, border, colorReset)

	sb := sandbox.New()
	caps := sb.Capabilities()
	sbName := sb.Name()

	if noSandbox {
		fmt.Fprintf(w, "%s│%s  %s%sSandbox: DISABLED (--no-sandbox)%s%s%s│%s\n", colorCyan, colorReset, colorBold, colorYellow, colorReset, strings.Repeat(" ", boxWidth-35), colorCyan, colorReset)
	} else {
		fmt.Fprintf(w, "%s│%s  %sSandbox: %s%s%s%s│%s\n", colorCyan, colorReset, colorBold, sbName, colorReset, strings.Repeat(" ", boxWidth-12-len(sbName)), colorCyan, colorReset)
	}

	printSecCapability(w, "CPU Limiting", caps.CPULimit, boxWidth)
	printSecCapability(w, "Memory Limiting", caps.MemoryLimit, boxWidth)
	printSecCapability(w, "PID Limiting", caps.PIDLimit, boxWidth)
	printSecCapability(w, "FD Limiting", caps.FDLimit, boxWidth)
	printSecCapability(w, "Network Isolation", caps.NetworkIsolation, boxWidth)
	printSecCapability(w, "Filesystem Isolation", caps.FilesystemIsolation, boxWidth)
	if caps.Cgroups {
		printSecCapability(w, "cgroups", true, boxWidth)
	}
	if caps.Namespaces {
		printSecCapability(w, "Namespaces", true, boxWidth)
	}
	if caps.SupportsSeccomp {
		printSecCapability(w, "seccomp", true, boxWidth)
	}
	if caps.SupportsLandlock {
		printSecCapability(w, "Landlock", true, boxWidth)
	}
	if caps.SupportsSandboxExec {
		printSecCapability(w, "sandbox-exec (SBPL)", true, boxWidth)
	}
	if caps.ProcessIsolation {
		printSecCapability(w, "Process Isolation", true, boxWidth)
	}

	// Warnings
	if len(caps.Warnings) > 0 || noSandbox {
		fmt.Fprintf(w, "%s├%s┤%s\n", colorCyan, border, colorReset)
		fmt.Fprintf(w, "%s│%s  %sWarnings%s%s%s│%s\n", colorCyan, colorReset, colorBold, colorReset, strings.Repeat(" ", boxWidth-10), colorCyan, colorReset)
		if noSandbox {
			printWarning(w, "Sandbox is disabled! Process runs without isolation", boxWidth)
		}
		for _, warning := range caps.Warnings {
			printWarning(w, warning, boxWidth)
		}
	}

	fmt.Fprintf(w, "%s└%s┘%s\n\n", colorCyan, border, colorReset)
}

// printField prints a labeled field inside the box
//
//nolint:unparam // boxWidth kept as parameter for consistency with other print functions
func printField(w *os.File, label, value string, boxWidth int) {
	content := fmt.Sprintf("  %s: %s", label, value)
	// Truncate if too long
	if len(content) > boxWidth-2 {
		content = content[:boxWidth-5] + "..."
	}
	padding := boxWidth - len(content)
	if padding < 0 {
		padding = 0
	}
	_, _ = fmt.Fprintf(w, "%s│%s%s%s%s│%s\n", colorCyan, colorReset, content, strings.Repeat(" ", padding), colorCyan, colorReset)
}

// printSecCapability prints a sandbox capability with check/cross mark and color
//
//nolint:unparam // boxWidth kept as parameter for consistency with other print functions
func printSecCapability(w *os.File, name string, available bool, boxWidth int) {
	var mark, color string
	if available {
		mark = "✓"
		color = colorGreen
	} else {
		mark = "✗"
		color = colorRed
	}
	// Account for ANSI codes in visual width calculation
	visualLen := 4 + 1 + len(mark) + 2 + len(name) // "    [" + mark + "] " + name
	padding := boxWidth - visualLen
	if padding < 0 {
		padding = 0
	}
	_, _ = fmt.Fprintf(w, "%s│%s%s    [%s%s] %s%s%s%s│%s\n", colorCyan, colorReset, "", color, mark, name, colorReset, strings.Repeat(" ", padding), colorCyan, colorReset)
}

// printWarning prints a warning line inside the box
func printWarning(w *os.File, text string, boxWidth int) {
	// Truncate if too long (account for ANSI codes)
	if len(text) > boxWidth-10 {
		text = text[:boxWidth-13] + "..."
	}
	visualLen := 4 + 4 + len(text) // "    " + "[!] " + text
	padding := boxWidth - visualLen
	if padding < 0 {
		padding = 0
	}
	_, _ = fmt.Fprintf(w, "%s│%s    %s[!] %s%s%s%s│%s\n", colorCyan, colorReset, colorYellow, text, colorReset, strings.Repeat(" ", padding), colorCyan, colorReset)
}

// loadEnvFile loads environment variables from a file
func loadEnvFile(filePath string, env map[string]string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read env file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			env[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return nil
}
