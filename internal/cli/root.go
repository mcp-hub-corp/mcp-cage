package cli

import (
	"fmt"

	"github.com/security-mcp/mcp-client/internal/config"
	"github.com/spf13/cobra"
)

var (
	// Version information (set via ldflags during build)
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"

	// Global flags
	registryURL string
	cacheDir    string
	verbose     bool
	jsonOutput  bool

	// Global config
	cfg *config.Config
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "smcp",
	Short: "Secure MCP Client - Launcher for MCP servers",
	Long: `smcp is a secure CLI tool for executing MCP (Model Context Protocol) servers.

It downloads, validates, executes and sandbox MCP packages from a MCP Hub registry - https://mcp-hub.info.

Examples:
  smcp run acme/hello-world@1.2.3
  smcp pull acme/hello-world@1.2.3
  smcp info acme/hello-world@1.2.3
  smcp cache ls
  smcp cache rm
  smcp doctor
`,
	Version: Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration
		var err error
		cfg, err = config.LoadConfig()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Override config with flags if provided
		if registryURL != "" {
			cfg.RegistryURL = registryURL
		}
		if cacheDir != "" {
			cfg.CacheDir = cacheDir
		}
		if verbose {
			cfg.LogLevel = "debug"
		}

		return nil
	},
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global persistent flags
	rootCmd.PersistentFlags().StringVar(&registryURL, "registry", "", "Registry URL (overrides config)")
	rootCmd.PersistentFlags().StringVar(&cacheDir, "cache-dir", "", "Cache directory (overrides config)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	// Version template
	rootCmd.SetVersionTemplate(fmt.Sprintf("smcp version %s\ncommit: %s\nbuilt: %s\n", Version, GitCommit, BuildDate))

	// Add subcommands
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(pullCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(cacheCmd)
	rootCmd.AddCommand(doctorCmd)

	// Cache subcommands
	cacheCmd.AddCommand(cacheLsCmd)
	cacheCmd.AddCommand(cacheRmCmd)

	// Doctor flags
	doctorCmd.Flags().BoolVar(&doctorFlags.jsonOutput, "json", false, "Output in JSON format")
}

// loginCmd handles authentication with the registry
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the MCP registry",
	Long: `Authenticate with the MCP registry using username/password or a token.

Examples:
  mcp login                                 # Interactive login with username/password
  mcp login --token eyJ...                  # Login with a pre-existing token`,
}

// logoutCmd handles logout from the registry
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from the MCP registry",
	Long:  `Remove authentication credentials for the MCP registry.`,
}

// pullCmd pre-downloads an MCP package
var pullCmd = &cobra.Command{
	Use:   "pull <package-ref>",
	Short: "Pre-download an MCP package",
	Long: `Pre-download an MCP package without executing it.
Example: mcp pull acme/hello-world@1.2.3`,
	Args: cobra.ExactArgs(1),
}

// runCmd executes an MCP server
var runCmd = &cobra.Command{
	Use:   "run <package-ref>",
	Short: "Execute an MCP server",
	Long: `Execute an MCP server from a package reference.
Example: mcp run acme/hello-world@1.2.3`,
	Args: cobra.ExactArgs(1),
}

// infoCmd displays information about a package
var infoCmd = &cobra.Command{
	Use:   "info <package-ref>",
	Short: "Display information about an MCP package",
	Long: `Display detailed information about an MCP package from the registry.
Example: mcp info acme/hello-world@1.2.3`,
	Args: cobra.ExactArgs(1),
}

// cacheCmd manages the local cache
var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage the local MCP cache",
	Long:  `Manage the local MCP cache (list, remove artifacts).`,
}

var cacheLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List cached artifacts",
	Long:  `List all artifacts stored in the local cache.`,
}

var cacheRmCmd = &cobra.Command{
	Use:   "rm [<digest>...]",
	Short: "Remove a cached artifact",
	Long:  `Remove an artifact from the local cache by digest, or use --all to clear the entire cache.`,
}

// doctorCmd diagnoses system capabilities
var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose system capabilities",
	Long:  `Diagnose system capabilities for running MCP servers (OS, cgroups, namespaces, etc.).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDoctor()
	},
}

var doctorFlags struct {
	jsonOutput bool
}
