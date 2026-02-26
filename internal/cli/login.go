package cli

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/security-mcp/mcp-client/internal/registry"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var loginFlags struct {
	token string
}

func init() {
	loginCmd.Flags().StringVar(&loginFlags.token, "token", "", "Authentication token (alternative to interactive login)")
	loginCmd.RunE = runLogin
}

// runLogin executes the login command
func runLogin(cmd *cobra.Command, args []string) error {
	logger := createLogger(cfg.LogLevel)

	// Create token storage
	tokenStorage := registry.NewTokenStorage(cfg.CacheDir)

	// Check if token was provided via flag
	if loginFlags.token != "" {
		return loginWithToken(logger, cfg.RegistryURL, loginFlags.token, tokenStorage)
	}

	// Interactive login
	return interactiveLogin(logger, cfg.RegistryURL, tokenStorage)
}

// loginWithToken performs login using a provided token
func loginWithToken(logger *slog.Logger, registryURL, token string, tokenStorage *registry.TokenStorage) error {
	logger.Debug("attempting token-based login", slog.String("registry", registryURL))

	// Validate token format (basic check for JWT structure)
	if !strings.Contains(token, ".") || len(strings.Split(token, ".")) != 3 {
		return fmt.Errorf("invalid token format: expected JWT token (header.payload.signature)")
	}

	// Default 24h expiration; server validates token on each API call
	expiresAt := time.Now().Add(24 * time.Hour)

	// Store the token
	authToken := &registry.Token{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresAt:   expiresAt,
		Registry:    registryURL,
	}

	if err := tokenStorage.Save(registryURL, authToken); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	fmt.Printf("Successfully authenticated with registry: %s\n", registryURL)
	fmt.Printf("Token expires at: %s\n", expiresAt.Format(time.RFC3339))

	logger.Info("login successful with token", slog.String("registry", registryURL), slog.Time("expires_at", expiresAt))

	return nil
}

// interactiveLogin performs interactive login with username and password
func interactiveLogin(logger *slog.Logger, registryURL string, tokenStorage *registry.TokenStorage) error {
	fmt.Printf("Authenticating with registry: %s\n\n", registryURL)

	// Read username
	username, err := readInput("Username: ")
	if err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	// Read password (hidden)
	password, err := readPassword("Password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	logger.Debug("attempting login", slog.String("username", username), slog.String("registry", registryURL))

	// Create registry client
	registryClient, err := registry.NewClient(registryURL)
	if err != nil {
		return fmt.Errorf("failed to create registry client: %w", err)
	}
	registryClient.SetLogger(logger)

	// Perform login
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	loginResp, err := registryClient.Login(ctx, username, password)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Calculate expiration time
	expiresAt := time.Now().Add(time.Duration(loginResp.ExpiresIn) * time.Second)

	// Store the token
	authToken := &registry.Token{
		AccessToken: loginResp.AccessToken,
		TokenType:   "Bearer",
		ExpiresAt:   expiresAt,
		Registry:    registryURL,
	}

	if err := tokenStorage.Save(registryURL, authToken); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	fmt.Printf("\nSuccessfully authenticated as %s\n", username)
	fmt.Printf("Token saved to: ~/.smcp/auth.json\n")
	fmt.Printf("Token expires at: %s\n", expiresAt.Format(time.RFC3339))

	logger.Info("login successful", slog.String("username", username), slog.String("registry", registryURL), slog.Time("expires_at", expiresAt))

	return nil
}

// readInput reads a line of input from stdin
func readInput(prompt string) (string, error) {
	fmt.Print(prompt)

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(input), nil
}

// readPassword reads a password from stdin without echoing
func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	// Check if stdin is a terminal
	if term.IsTerminal(int(os.Stdin.Fd())) {
		// Read from terminal with password masking
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		fmt.Println() // Print newline after password input
		return string(passwordBytes), nil
	}

	// Fallback: read from non-terminal input (for testing)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(input), nil
}
