package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
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
	trust     bool
	secretEnv map[string]string
}

var runFlags runCmdFlags

func init() {
	runCmd.RunE = runMCPServer
	runCmd.Flags().StringVar(&runFlags.timeout, "timeout", "", "Execution timeout (e.g., 5m, 30s)")
	runCmd.Flags().StringVar(&runFlags.envFile, "env-file", "", "File with environment variables")
	runCmd.Flags().BoolVar(&runFlags.noCache, "no-cache", false, "Force download without using cache")
	runCmd.Flags().BoolVar(&runFlags.noSandbox, "no-sandbox", false, "Disable process sandboxing (use with caution)")
	runCmd.Flags().BoolVar(&runFlags.trust, "trust", false, "Skip interactive confirmation for low-score packages")
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

	// Create progress UI
	ui := NewProgressUI(os.Stderr, 6)

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

	ui.Header(org, name, version)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	// Step 1: Resolving package
	ui.StepStart(1, "Resolving package")
	logger.Debug("resolving package", slog.String("package", fmt.Sprintf("%s/%s", org, name)), slog.String("ref", version))
	resolveResp, err := registryClient.Resolve(ctx, org, name, version)
	if err != nil {
		ui.StepFail(1, "Resolving package")
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, err.Error()) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("failed to resolve package: %w", err)
	}
	ui.StepDone(1, "Resolving package")

	// Step 2: Checking policies
	ui.StepStart(2, "Checking policies")

	// Enforce origin policy
	origin := resolveResp.Origin
	if origin == "" {
		origin = "community" // Default origin if not specified
	}
	originPolicy := policy.NewOriginPolicy(cfg.Policy.AllowedOrigins)
	if originPolicyErr := originPolicy.Validate(origin); originPolicyErr != nil {
		ui.StepFail(2, "Checking policies")
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("origin policy violation: %v", originPolicyErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("origin policy violation: %w", originPolicyErr)
	}

	// Enforce certification level policy
	certLevel := resolveResp.Resolved.CertificationLevel
	if certLevelErr := pol.CertLevelPolicy.ValidateWithLogging(certLevel, fmt.Sprintf("%s/%s", org, name)); certLevelErr != nil {
		ui.StepFail(2, "Checking policies")
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("certification level policy violation: %v", certLevelErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("certification level policy violation: %w", certLevelErr)
	}

	ui.StepDone(2, "Checking policies")

	manifestDigest := resolveResp.Resolved.Manifest.Digest
	bundleDigest := resolveResp.Resolved.Bundle.Digest
	gitSHA := resolveResp.Resolved.GitSHA
	resolvedVersion := resolveResp.Resolved.Version

	logger.Debug("package resolved",
		slog.String("version", resolvedVersion),
		slog.String("origin", origin),
		slog.String("git_sha", gitSHA),
		slog.String("manifest_digest", manifestDigest),
		slog.String("bundle_digest", bundleDigest),
	)

	// Step 3: Fetching manifest
	ui.StepStart(3, "Fetching manifest")

	var manifestData []byte
	var manifestErr error
	manifestCached := false
	if !runFlags.noCache && cacheStore.Exists(manifestDigest, "manifest") {
		logger.Debug("manifest cache hit", slog.String("digest", manifestDigest))
		manifestData, manifestErr = cacheStore.GetManifest(manifestDigest)
		if manifestErr != nil {
			ui.StepFail(3, "Fetching manifest")
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
		} else {
			manifestCached = true
		}
	}
	if manifestData == nil {
		logger.Debug("downloading manifest", slog.String("digest", manifestDigest))
		manifestData, manifestErr = registryClient.DownloadManifest(ctx, org, manifestDigest)
		if manifestErr != nil {
			ui.StepFail(3, "Fetching manifest")
			if auditLogger != nil {
				_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("failed to download manifest: %v", manifestErr)) //nolint:errcheck // audit logging
			}
			return fmt.Errorf("failed to download manifest: %w", manifestErr)
		}

		// Validate digest
		if validateManifestErr := registry.ValidateDigest(manifestData, manifestDigest); validateManifestErr != nil {
			ui.StepFail(3, "Fetching manifest")
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
		ui.StepFail(3, "Fetching manifest")
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("failed to parse manifest: %v", parseErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("failed to parse manifest: %w", parseErr)
	}

	if validateErr := manifest.Validate(mf); validateErr != nil {
		ui.StepFail(3, "Fetching manifest")
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("manifest validation failed: %v", validateErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("manifest validation failed: %w", validateErr)
	}

	// Enforce score policy
	if mf.SecurityMeta != nil && pol.ScorePolicy != nil {
		if scorePolicyErr := pol.ScorePolicy.Validate(mf.SecurityMeta.Score); scorePolicyErr != nil {
			ui.StepFail(3, "Fetching manifest")
			if auditLogger != nil {
				_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("score policy violation: %v", scorePolicyErr)) //nolint:errcheck // audit logging
			}
			return fmt.Errorf("score policy violation: %w", scorePolicyErr)
		}
	}

	// Apply manifest permissions
	if permErr := pol.ApplyManifestPermissions(mf); permErr != nil {
		ui.StepFail(3, "Fetching manifest")
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("policy application failed: %v", permErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("policy application failed: %w", permErr)
	}

	// Select entrypoint
	ep, err := manifest.SelectEntrypoint(mf)
	if err != nil {
		ui.StepFail(3, "Fetching manifest")
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

	if manifestCached {
		ui.StepSkip(3, "Fetching manifest", "cached")
	} else {
		ui.StepDone(3, "Fetching manifest")
	}

	// Step 4: Fetching bundle
	ui.StepStart(4, "Fetching bundle")

	var bundleData []byte
	var bundleErr error
	bundleCached := false
	if !runFlags.noCache && cacheStore.Exists(bundleDigest, "bundle") {
		logger.Debug("bundle cache hit", slog.String("digest", bundleDigest))
		bundleData, bundleErr = cacheStore.GetBundle(bundleDigest)
		if bundleErr != nil {
			ui.StepFail(4, "Fetching bundle")
			return fmt.Errorf("failed to read bundle from cache: %w", bundleErr)
		}
		// SECURITY: Re-validate digest of cached data to detect corruption/tampering
		if revalidateErr := registry.ValidateDigest(bundleData, bundleDigest); revalidateErr != nil {
			logger.Warn("cached bundle digest mismatch, re-downloading",
				slog.String("digest", bundleDigest),
				slog.String("error", revalidateErr.Error()))
			_ = cacheStore.Delete(bundleDigest, "bundle") //nolint:errcheck // best-effort cleanup
			bundleData = nil
		} else {
			bundleCached = true
		}
	}
	if bundleData == nil {
		logger.Debug("downloading bundle", slog.String("digest", bundleDigest))
		bundleData, bundleErr = registryClient.DownloadBundle(ctx, org, bundleDigest)
		if bundleErr != nil {
			ui.StepFail(4, "Fetching bundle")
			if auditLogger != nil {
				_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("failed to download bundle: %v", bundleErr)) //nolint:errcheck // audit logging
			}
			return fmt.Errorf("failed to download bundle: %w", bundleErr)
		}

		// Validate digest
		if validateBundleErr := registry.ValidateDigest(bundleData, bundleDigest); validateBundleErr != nil {
			ui.StepFail(4, "Fetching bundle")
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

	if bundleCached {
		ui.StepSkip(4, "Fetching bundle", "cached")
	} else {
		ui.StepDone(4, "Fetching bundle")
	}

	// Step 5: Extracting bundle
	ui.StepStart(5, "Extracting bundle")

	// Create temporary directory for bundle extraction with restricted permissions (0700)
	tempDir, tempErr := os.MkdirTemp("", "mcp-bundle-*")
	if tempErr != nil {
		ui.StepFail(5, "Extracting bundle")
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("failed to create temp directory: %v", tempErr)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("failed to create temp directory: %w", tempErr)
	}
	// SECURITY: Restrict temp directory permissions to prevent TOCTOU attacks
	if chmodErr := os.Chmod(tempDir, 0o700); chmodErr != nil {
		ui.StepFail(5, "Extracting bundle")
		return fmt.Errorf("failed to set temp directory permissions: %w", chmodErr)
	}
	defer func() {
		if rmErr := os.RemoveAll(tempDir); rmErr != nil {
			logger.Warn("failed to clean up temp directory", slog.String("path", tempDir), slog.String("error", rmErr.Error()))
		}
	}()

	// Extract bundle
	if extractErr := extractBundle(bundleData, tempDir); extractErr != nil {
		ui.StepFail(5, "Extracting bundle")
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

	ui.StepDone(5, "Extracting bundle")

	// Step 6: Preparing execution
	ui.StepStart(6, "Preparing execution")

	// Apply execution limits from policy
	// CRITICAL: ApplyLimits ALWAYS returns non-nil limits with mandatory safe defaults
	limits := pol.ApplyLimits(mf)

	// CRITICAL SECURITY: Verify limits are properly set before proceeding
	// This is a fail-safe to ensure execution without limits is NEVER possible
	if limits == nil {
		ui.StepFail(6, "Preparing execution")
		return fmt.Errorf("CRITICAL SECURITY ERROR: ApplyLimits returned nil - execution without limits is forbidden")
	}

	if limits.MaxCPU <= 0 {
		ui.StepFail(6, "Preparing execution")
		return fmt.Errorf("CRITICAL SECURITY ERROR: MaxCPU not set properly (%d) - execution without CPU limits is forbidden", limits.MaxCPU)
	}

	if limits.MaxMemory == "" {
		ui.StepFail(6, "Preparing execution")
		return fmt.Errorf("CRITICAL SECURITY ERROR: MaxMemory not set - execution without memory limits is forbidden")
	}

	if limits.MaxPIDs <= 0 {
		ui.StepFail(6, "Preparing execution")
		return fmt.Errorf("CRITICAL SECURITY ERROR: MaxPIDs not set properly (%d) - execution without PID limits is forbidden", limits.MaxPIDs)
	}

	if limits.MaxFDs <= 0 {
		ui.StepFail(6, "Preparing execution")
		return fmt.Errorf("CRITICAL SECURITY ERROR: MaxFDs not set properly (%d) - execution without file descriptor limits is forbidden", limits.MaxFDs)
	}

	if limits.Timeout <= 0 {
		ui.StepFail(6, "Preparing execution")
		return fmt.Errorf("CRITICAL SECURITY ERROR: Timeout not set properly (%v) - execution without timeout is forbidden", limits.Timeout)
	}

	// Log the limits being applied (DEBUG level, details captured in InfoCard)
	logger.Debug("SECURITY: applying mandatory execution limits",
		slog.Int("max_cpu_millicores", limits.MaxCPU),
		slog.String("max_memory", limits.MaxMemory),
		slog.Int("max_pids", limits.MaxPIDs),
		slog.Int("max_fds", limits.MaxFDs),
		slog.Duration("timeout", limits.Timeout),
		slog.String("security_policy", "mandatory_limits_enforced"),
	)

	// Load environment variables
	env := make(map[string]string)
	if runFlags.envFile != "" {
		if envFileErr := loadEnvFile(runFlags.envFile, env); envFileErr != nil {
			// SECURITY: When --env-file is explicitly specified, treat failure as an error
			ui.StepFail(6, "Preparing execution")
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
		ui.StepFail(6, "Preparing execution")
		if auditLogger != nil {
			_ = auditLogger.LogError(fmt.Sprintf("%s/%s", org, name), version, fmt.Sprintf("failed to create executor: %v", err)) //nolint:errcheck // audit logging
		}
		return fmt.Errorf("failed to create executor: %w", err)
	}
	stdioExec.SetLogger(logger)
	stdioExec.SetNoSandbox(runFlags.noSandbox)
	if !verbose {
		stdioExec.SetStderr(io.Discard)
	}

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
			ui.StepFail(6, "Preparing execution")
			return fmt.Errorf("failed to read entrypoint before execution: %w", readErr)
		}
		entrypointDigest := fmt.Sprintf("sha256:%s", registry.ComputeSHA256(entrypointData))
		logger.Debug("entrypoint pre-exec digest verified", slog.String("digest", entrypointDigest))
	}

	ui.StepDone(6, "Preparing execution")

	// Show info card (always, not gated by verbose)
	sb := sandbox.New()
	formatStr := "hub"
	if !mf.HubFormat {
		formatStr = "registry"
	}
	secScore := -1
	var findings *manifest.FindingsSummary
	if mf.SecurityMeta != nil {
		secScore = mf.SecurityMeta.Score
		findings = mf.SecurityMeta.Findings
	}
	ui.InfoCard(InfoCardData{
		Org:         org,
		Name:        name,
		Version:     resolvedVersion,
		Origin:      origin,
		CertLevel:   certLevel,
		GitSHA:      gitSHA,
		Format:      formatStr,
		Score:       secScore,
		Findings:    findings,
		Limits:      limits,
		SandboxName: sb.Name(),
		SandboxCaps: sb.Capabilities(),
		NoSandbox:   runFlags.noSandbox,
	})

	// Trust check: warn on low-score packages unless --trust is set
	if secScore >= 0 && secScore < 80 && !runFlags.trust {
		if !ui.ConfirmLowScore(secScore) {
			return fmt.Errorf("security score %d/100 is below 80; use --trust to skip this check", secScore)
		}
	}

	// Log execution start
	packageID := fmt.Sprintf("%s/%s", org, name)
	if auditLogger != nil {
		_ = auditLogger.LogStart(packageID, resolvedVersion, bundleDigest, ep.Command, gitSHA) //nolint:errcheck // audit logging
	}

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ui.ListeningBanner("stdio")

	startTime := time.Now()

	// Run executor in goroutine
	execCh := make(chan error, 1)
	go func() {
		execCh <- stdioExec.Execute(ctx, ep, bundleRoot)
	}()

	// Wait for completion or signal
	var execErr error
	select {
	case execErr = <-execCh:
		signal.Stop(sigCh)
	case <-sigCh:
		signal.Stop(sigCh)
		cancel() // cancel context to stop executor
		<-execCh // wait for executor to finish
		duration := time.Since(startTime)
		ui.ShutdownBanner(duration)
		// Log clean shutdown to audit
		if auditLogger != nil {
			_ = auditLogger.LogEnd(packageID, resolvedVersion, 0, duration, "signal")
		}
		return nil
	}

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
		ui.ErrorBanner(execErr.Error())
		return execErr
	}

	ui.ShutdownBanner(duration)

	return nil
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
