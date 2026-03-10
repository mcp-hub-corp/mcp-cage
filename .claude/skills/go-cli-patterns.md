# Go CLI Patterns with Cobra & Viper

## Overview

This skill covers best practices for building command-line interfaces in Go using Cobra (CLI framework) and Viper (configuration management). Tailored to the mcp-cage project: `smcp run`, `smcp pull`, `smcp cache`, etc.

---

## Cobra Framework Fundamentals

### Command Structure

```
├── Root Command (mcp)
│   ├── Persistent Flags (--verbose, --registry, --config)
│   ├── Subcommand: run
│   ├── Subcommand: pull
│   ├── Subcommand: cache
│   │   ├── Subcommand: ls
│   │   ├── Subcommand: rm
│   ├── Subcommand: login
│   ├── Subcommand: logout
│   ├── Subcommand: info
│   └── Subcommand: doctor
```

### Creating Commands

```go
package cli

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Root command
var rootCmd = &cobra.Command{
	Use:   "smcp",
	Short: "MCP Client - launcher for Model Context Protocol servers",
	Long: `mcp-cage is a launcher for MCP servers.

It resolves, downloads, and executes MCP packages from a registry.`,
	Version: "0.1.0",
}

// Run subcommand
var runCmd = &cobra.Command{
	Use:     "run <org/name@version>",
	Short:   "Execute an MCP server",
	Long:    "Download and execute an MCP server package.",
	Example: "smcp run acme/hello-world@1.2.3",
	Args:    cobra.ExactArgs(1), // Require exactly 1 argument
	RunE:    runCommand,          // Async error handling
}

// Pull subcommand
var pullCmd = &cobra.Command{
	Use:     "pull <org/name@version>",
	Short:   "Pre-download an MCP package",
	Long:    "Download package without executing (useful for CI/CD).",
	Example: "smcp pull acme/tool@1.0.0",
	Args:    cobra.ExactArgs(1),
	RunE:    pullCommand,
}

// Handler functions
func runCommand(cmd *cobra.Command, args []string) error {
	ref := args[0]
	verbose, _ := cmd.Flags().GetBool("verbose")

	if verbose {
		fmt.Println("Running:", ref)
	}

	// Implementation here
	return nil
}

func pullCommand(cmd *cobra.Command, args []string) error {
	ref := args[0]
	// Implementation here
	return nil
}

// Register commands
func init() {
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(pullCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
```

---

## Flags & Persistent Flags

### Global Persistent Flags

Persistent flags are inherited by all subcommands:

```go
func init() {
	// Global flags available to all commands
	rootCmd.PersistentFlags().String(
		"registry",
		"https://registry.mcp-hub.info",
		"URL of the MCP registry",
	)
	rootCmd.PersistentFlags().String(
		"cache-dir",
		"~/.smcp/cache",
		"Cache directory for manifests and bundles",
	)
	rootCmd.PersistentFlags().Bool(
		"verbose",
		false,
		"Enable verbose output",
	)
	rootCmd.PersistentFlags().Bool(
		"json",
		false,
		"Output in JSON format",
	)
	rootCmd.PersistentFlags().String(
		"log-level",
		"info",
		"Log level: debug, info, warn, error",
	)

	// Bind to viper for env var override
	viper.BindPFlag("registry", rootCmd.PersistentFlags().Lookup("registry"))
	viper.BindPFlag("cache_dir", rootCmd.PersistentFlags().Lookup("cache-dir"))
	viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))
}
```

### Command-Specific Flags

Flags specific to a command:

```go
func init() {
	// Flags only for 'run' command
	runCmd.Flags().Duration(
		"timeout",
		5*time.Minute,
		"Timeout for execution",
	)
	runCmd.Flags().String(
		"env-file",
		"",
		"Path to .env file with environment variables",
	)
	runCmd.Flags().StringToString(
		"secret",
		map[string]string{},
		"Secrets to pass (e.g., --secret API_KEY=value)",
	)
	runCmd.Flags().Bool(
		"no-cache",
		false,
		"Force download without using cache",
	)

	// Mark flags as required
	runCmd.MarkFlagRequired("registry") // Optional: mark as required

	// Flag value validation
	runCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		timeout, _ := cmd.Flags().GetDuration("timeout")
		if timeout <= 0 {
			return fmt.Errorf("timeout must be positive (got %v)", timeout)
		}
		return nil
	}

	rootCmd.AddCommand(runCmd)
}
```

---

## Viper Configuration Management

### Configuration File Support

Viper supports multiple formats: YAML, TOML, JSON, etc.

```go
package config

import (
	"github.com/spf13/viper"
	"path/filepath"
	"os"
)

// LoadConfig loads configuration from file, environment, and flags
func LoadConfig() (*Config, error) {
	// Set config file name and paths
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	// Add multiple config paths (searched in order)
	viper.AddConfigPath(".")                    // Current directory
	viper.AddConfigPath(expandHome("~/.smcp"))   // User home
	viper.AddConfigPath("/etc/mcp")             // System wide

	// Set environment variable prefix
	// MCP_REGISTRY_URL becomes viper key "registry.url"
	viper.SetEnvPrefix("MCP")
	viper.AutomaticEnv()

	// Set default values
	setDefaults()

	// Try to read config file (not required)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config: %w", err)
		}
		// Config file not found, that's OK (env vars will override defaults)
	}

	// Unmarshal into struct
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// Set default values
func setDefaults() {
	viper.SetDefault("registry.url", "https://registry.mcp-hub.info")
	viper.SetDefault("registry.timeout", "30s")
	viper.SetDefault("cache.dir", "~/.smcp/cache")
	viper.SetDefault("cache.max_size", "10GB")
	viper.SetDefault("executor.timeout", "5m")
	viper.SetDefault("executor.max_cpu", 1000)
	viper.SetDefault("executor.max_memory", "512M")
	viper.SetDefault("executor.max_pids", 10)
	viper.SetDefault("executor.max_fds", 100)
	viper.SetDefault("log.level", "info")
	viper.SetDefault("audit.enabled", true)
}

// Expand tilde in paths
func expandHome(path string) string {
	if path[:2] == "~/" {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}
```

### Configuration Priority Order

Lower to higher priority:
1. Defaults (in code)
2. Config file (YAML, TOML, etc.)
3. Environment variables
4. CLI flags

```go
// Example: User sets these in different ways
// 1. Default in code:
viper.SetDefault("registry", "https://default-registry.com")

// 2. In config file (~/.smcp/config.yaml):
// registry: https://file-registry.com

// 3. Environment variable:
// $ export MCP_REGISTRY=https://env-registry.com

// 4. CLI flag:
// $ smcp --registry https://flag-registry.com run ...

// Final value: https://flag-registry.com (CLI flag wins)
```

---

## Error Handling & Exit Codes

### Exit Code Conventions

```go
const (
	ExitSuccess       = 0   // Successful execution
	ExitConfigError   = 1   // Configuration problem
	ExitNetworkError  = 2   // Network/registry error
	ExitValidation    = 3   // Input validation failed
	ExitExecution     = 4   // Process execution failed
	ExitTimeout       = 5   // Timeout occurred
	ExitSignal        = 124 // Process killed by signal
)
```

### Error Handling in Commands

```go
func runCommand(cmd *cobra.Command, args []string) error {
	ref := args[0]
	registry := viper.GetString("registry")

	// Validate input
	if err := validateReference(ref); err != nil {
		return fmt.Errorf("invalid package reference: %w", err)
	}

	// Network operation
	manifest, err := client.ResolvePackage(ref)
	if err != nil {
		if isNetworkError(err) {
			os.Exit(ExitNetworkError)
		}
		return fmt.Errorf("failed to resolve package: %w", err)
	}

	// Execution
	if err := executor.Execute(manifest); err != nil {
		if isTimeoutError(err) {
			os.Exit(ExitTimeout)
		}
		return fmt.Errorf("execution failed: %w", err)
	}

	return nil
}

// In main()
func main() {
	if err := rootCmd.Execute(); err != nil {
		// Determine exit code based on error type
		if err == cobra.ErrSubCommandRequired {
			os.Exit(ExitConfigError)
		}
		// Default to config error for unknown errors
		os.Exit(ExitConfigError)
	}
}
```

### Custom Error Types

```go
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error on %s: %s", e.Field, e.Message)
}

func runCommand(cmd *cobra.Command, args []string) error {
	ref := args[0]

	// Return custom error
	if !isValidRef(ref) {
		return &ValidationError{
			Field:   "reference",
			Message: fmt.Sprintf("%q is not a valid package reference", ref),
		}
	}

	return nil
}

// Main can handle custom errors
func main() {
	if err := rootCmd.Execute(); err != nil {
		if _, ok := err.(*ValidationError); ok {
			os.Exit(ExitValidation)
		}
		os.Exit(ExitConfigError)
	}
}
```

---

## Structured Output

### Human-Readable Output

```go
func printPackageInfo(pkg *Package, verbose bool) {
	fmt.Printf("Package: %s\n", pkg.Name)
	fmt.Printf("Version: %s\n", pkg.Version)

	if verbose {
		fmt.Printf("Digest: %s\n", pkg.Digest)
		fmt.Printf("Size: %d bytes\n", pkg.SizeBytes)
		fmt.Printf("Created: %s\n", pkg.CreatedAt)
	}
}

// Example output:
// Package: acme/hello-world
// Version: 1.2.3
```

### Table Output

```go
import "github.com/rodaine/table"

func listCacheEntries(entries []CacheEntry) {
	tbl := table.New("DIGEST", "TYPE", "SIZE", "LAST USED")

	for _, entry := range entries {
		tbl.AddRow(
			entry.Digest[:16]+"...",
			entry.Type,
			formatBytes(entry.SizeBytes),
			formatTime(entry.LastUsed),
		)
	}

	tbl.Print()
}

// Example output:
// DIGEST            TYPE      SIZE     LAST USED
// sha256:abc123...  manifest  4.2 KB   2 hours ago
// sha256:def456...  bundle    12.5 MB  2 hours ago
```

### JSON Output

```go
import "encoding/json"

func runCommand(cmd *cobra.Command, args []string) error {
	// ... execution ...

	result := Result{
		PackageID: "acme/hello-world",
		Version:   "1.2.3",
		Status:    "success",
		StartTime: time.Now(),
	}

	if viper.GetBool("json") {
		// JSON output for machines
		json.NewEncoder(os.Stdout).Encode(result)
	} else {
		// Human-readable output
		fmt.Printf("Package: %s\n", result.PackageID)
		fmt.Printf("Status: %s\n", result.Status)
	}

	return nil
}

// Example JSON output:
// {"package_id":"acme/hello-world","version":"1.2.3","status":"success","start_time":"2026-01-18T10:30:00Z"}
```

---

## Progress Indication

### Logging Strategy

Log levels: DEBUG, INFO, WARN, ERROR

```go
import "log/slog"

func runCommand(cmd *cobra.Command, args []string) error {
	logLevel := viper.GetString("log.level")
	setupLogging(logLevel)

	log := slog.Default()

	// DEBUG: Internal operation details
	log.Debug("resolving reference", "ref", args[0])

	// INFO: User-relevant milestones
	log.Info("downloading manifest", "ref", args[0])

	// WARN: Recoverable issues
	log.Warn("cache miss", "digest", digest)

	// ERROR: Failures
	log.Error("validation failed", "reason", "digest mismatch")

	return nil
}

// Example output (info level):
// [2026-01-18T10:30:00Z] INFO Resolving acme/hello-world@1.2.3...
// [2026-01-18T10:30:01Z] INFO Resolved to sha256:abc123... (manifest), sha256:def456... (bundle)
// [2026-01-18T10:30:01Z] INFO Downloading manifest (4.2 KB)...
// [2026-01-18T10:30:02Z] INFO Downloading bundle (12.5 MB)...
// [2026-01-18T10:30:05Z] INFO Starting MCP server (STDIO)...
```

### Progress Bars for Long Operations

```go
import "github.com/schollz/progressbar/v3"

func downloadBundle(url string, sizeBytes int64) error {
	req, _ := http.NewRequest("GET", url, nil)
	resp, _ := http.Do(req)
	defer resp.Body.Close()

	// Create progress bar
	bar := progressbar.DefaultBytes(
		sizeBytes,
		"downloading bundle",
	)

	// Download with progress
	_, err := io.Copy(io.MultiWriter(outFile, bar), resp.Body)
	return err
}

// Example output:
// downloading bundle 100% |████████████████████| (12.5 MB/12.5 MB)
```

### Minimal Output for Piping

When `--json` or output is piped, minimize logging:

```go
func init() {
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		// Check if output is piped
		fileInfo, _ := os.Stdout.Stat()
		isStdoutPiped := (fileInfo.Mode() & os.ModeCharDevice) == 0

		if isStdoutPiped || viper.GetBool("json") {
			// Disable progress output for machines
			disableProgressBars()
			// Only show errors
			log.SetLevel(log.ErrorLevel)
		}
	}
}
```

---

## Help Text & Documentation

### Clear Help Text

```go
var runCmd = &cobra.Command{
	Use:     "run <org/name@version>",
	Short:   "Execute an MCP server",
	Long: `Execute a Model Context Protocol (MCP) server.

The command resolves a package reference, downloads the manifest and bundle,
validates their integrity, and starts the server.

Package references can be specified in three formats:
  - Semver: org/name@1.2.3
  - Git SHA: org/name@sha:abc123def456
  - Digest: org/name@digest:sha256:abc123...`,

	Example: `
  # Run with default registry
  smcp run acme/hello-world@1.2.3

  # Run with custom timeout
  smcp run acme/tool@latest --timeout 60s

  # Run with environment variables
  smcp run acme/tool@1.0.0 --env-file .env --secret API_KEY=secret

  # Force fresh download (skip cache)
  smcp run acme/tool@1.0.0 --no-cache`,

	Args: cobra.ExactArgs(1),
	RunE: runCommand,
}
```

### Flag Help Text

```go
func init() {
	runCmd.Flags().String(
		"env-file",
		"",
		"Path to .env file with environment variables to pass to the server",
	)
	runCmd.Flags().Bool(
		"no-cache",
		false,
		"Force download without checking local cache (useful for updates)",
	)
	runCmd.Flags().Duration(
		"timeout",
		5*time.Minute,
		"Timeout for server execution (0 = no timeout, not recommended)",
	)
}

// Generated help:
// Flags:
//   --env-file string      Path to .env file with environment variables to pass to the server
//   --no-cache            Force download without checking local cache (useful for updates)
//   --timeout duration    Timeout for server execution (0 = no timeout, not recommended) (default 5m0s)
```

### Usage Examples in Output

The `Example` field automatically appears in help:

```bash
$ smcp run --help
...
Examples:
  # Run with default registry
  smcp run acme/hello-world@1.2.3

  # Run with custom timeout
  smcp run acme/tool@latest --timeout 60s
```

---

## Version Information

### Version Injection

Version is typically injected at build time:

```bash
# Build with version
go build -ldflags="-X github.com/security-mcp/mcp-cage/cmd.Version=1.0.0" ./cmd/smcp
```

### Setting Version in Code

```go
package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var Version = "dev" // Set by build flags

var rootCmd = &cobra.Command{
	Use:     "smcp",
	Short:   "MCP Client",
	Version: Version,
}

func init() {
	// Enable --version flag
	rootCmd.CompletionOptions.DisableDefaultCmd = false
}

// In main.go
func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
```

### Using Version in Output

```bash
$ smcp --version
smcp version 0.1.0

$ smcp doctor
MCP Client v0.1.0
```

---

## Testing CLI Commands

### Testing with exec.Command()

```go
func TestRunCommand_SuccessfulExecution(t *testing.T) {
	// Run the CLI as a subprocess
	cmd := exec.Command(
		"go", "run", "cmd/smcp/main.go",
		"run", "acme/test@1.0.0",
	)

	// Capture output
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	// Run
	err := cmd.Run()

	// Check exit code
	if exitErr, ok := err.(*exec.ExitError); ok {
		assert.NotEqual(t, 0, exitErr.ExitCode())
	} else {
		assert.NoError(t, err)
	}

	// Check output
	output := out.String()
	assert.Contains(t, output, "acme/test@1.0.0")
}
```

### Testing Cobra Commands Directly

```go
func TestRootCommand(t *testing.T) {
	cmd := rootCmd
	cmd.SetArgs([]string{"--help"})

	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestRunCommand_ValidArguments(t *testing.T) {
	cmd := rootCmd
	cmd.SetArgs([]string{"run", "acme/test@1.0.0"})

	err := cmd.Execute()
	// Will fail without mock registry, but verifies CLI parsing works
	assert.Error(t, err)
}

func TestRunCommand_InvalidArguments(t *testing.T) {
	cmd := rootCmd
	cmd.SetArgs([]string{"run"}) // Missing package reference

	err := cmd.Execute()
	assert.Error(t, err) // Should fail due to missing args
}

func TestFlags_RegistryOverride(t *testing.T) {
	cmd := rootCmd
	cmd.SetArgs([]string{"--registry", "https://custom.com", "pull", "test@1.0.0"})

	// Execute command (will fail but validates flag parsing)
	cmd.Execute()

	// Verify flag was set
	registry := viper.GetString("registry")
	assert.Equal(t, "https://custom.com", registry)
}
```

---

## Common Anti-Patterns

### Anti-Pattern 1: Too Verbose Output

Bad:
```
Starting operation...
Setting up context...
Initializing components...
Loading configuration...
Parsing arguments...
Validating inputs...
...lots more...
Finally executing!
```

Good:
```
Resolving acme/hello-world@1.2.3...
Downloading bundle (12.5 MB)...
Starting MCP server...
```

Keep output concise and user-focused.

### Anti-Pattern 2: Unclear Error Messages

Bad:
```
Error: failed
```

Good:
```
Error: failed to validate digest: expected sha256:abc123, got sha256:def456
(Try --no-cache to force fresh download)
```

Include context and suggestions.

### Anti-Pattern 3: Missing Examples

Bad:
```go
var runCmd = &cobra.Command{
	Use: "run <ref>",
	Short: "Run a package",
}
```

Good:
```go
var runCmd = &cobra.Command{
	Use:     "run <org/name@version>",
	Short:   "Execute an MCP server",
	Example: "smcp run acme/hello-world@1.2.3\nsmcp run acme/tool@latest --timeout 60s",
}
```

Examples are crucial for usability.

### Anti-Pattern 4: Inconsistent Flag Names

Bad:
```go
runCmd.Flags().Bool("v", false, "Verbose")        // Short form
pullCmd.Flags().Bool("verbose", false, "Verbose") // Long form only
```

Good:
```go
runCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")
pullCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")
```

Use consistent naming across commands.

### Anti-Pattern 5: Not Handling Signals

Bad:
```go
executor.Run(manifest) // No signal handling
```

Good:
```go
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

go func() {
	sig := <-sigChan
	log.Info("received signal", "signal", sig)
	executor.Stop()
	os.Exit(ExitSignal)
}()

executor.Run(manifest)
```

Handle SIGINT/SIGTERM for graceful shutdown.

---

## Advanced Patterns

### Command Aliases

```go
var runCmd = &cobra.Command{
	Use:     "run <ref>",
	Aliases: []string{"exec", "execute"},
	Short:   "Execute an MCP server",
}

// Users can now type:
// smcp run acme/hello@1.0.0
// smcp exec acme/hello@1.0.0
// smcp execute acme/hello@1.0.0
```

### Hidden Commands

```go
var debugCmd = &cobra.Command{
	Use:    "debug",
	Short:  "Debug utilities",
	Hidden: true, // Not shown in help
}

// Useful for internal commands
```

### Command Hooks

```go
var runCmd = &cobra.Command{
	Use: "run <ref>",

	// Before execution validation
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := validateConfig(); err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}
		return nil
	},

	// Main execution
	RunE: runCommand,

	// Cleanup after execution
	PostRunE: func(cmd *cobra.Command, args []string) error {
		cleanup()
		return nil
	},
}
```

### Persistent PreRun for All Commands

```go
rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
	// Run for every command
	if err := setupLogging(); err != nil {
		return err
	}
	if err := loadConfig(); err != nil {
		return err
	}
	return nil
}
```

---

## Summary Checklist

- [ ] Use Cobra for command structure
- [ ] Define persistent flags for global options
- [ ] Use Viper for configuration (file, env, flags)
- [ ] Implement priority order: defaults → file → env → flags
- [ ] Define clear exit codes for different error types
- [ ] Use structured logging (DEBUG, INFO, WARN, ERROR)
- [ ] Provide JSON output option for scripts
- [ ] Include helpful examples in help text
- [ ] Validate inputs in PreRunE
- [ ] Handle signals (SIGINT, SIGTERM) gracefully
- [ ] Avoid verbose output unless --verbose flag
- [ ] Test CLI with both command execution and flag parsing
- [ ] Inject version at build time
- [ ] Keep error messages clear and actionable
