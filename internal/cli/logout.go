package cli

import (
	"fmt"
	"log/slog"

	"github.com/mcp-hub-corp/mcp-cage/internal/registry"
	"github.com/spf13/cobra"
)

func init() {
	logoutCmd.RunE = runLogout
}

// runLogout executes the logout command
func runLogout(cmd *cobra.Command, args []string) error {
	logger := createLogger(cfg.LogLevel)

	// Create token storage
	tokenStorage := registry.NewTokenStorage(cfg.CacheDir)

	// Load existing token
	token, err := tokenStorage.Load()
	if err != nil {
		return fmt.Errorf("failed to load token: %w", err)
	}

	if token == nil {
		fmt.Println("Not logged in")
		return nil
	}

	// Remove token file
	if err := tokenStorage.Delete(); err != nil {
		return fmt.Errorf("failed to remove token: %w", err)
	}

	fmt.Printf("Logged out from registry: %s\n", cfg.RegistryURL)
	logger.Info("logout successful", slog.String("registry", cfg.RegistryURL))

	return nil
}
