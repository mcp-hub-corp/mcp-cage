package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCommand(t *testing.T) {
	// Test that root command exists and has expected properties
	assert.NotNil(t, rootCmd)
	assert.Equal(t, "smcp", rootCmd.Use)
	assert.Contains(t, rootCmd.Short, "MCP Client")
}

func TestSubcommands(t *testing.T) {
	// Test that all expected subcommands are registered
	expectedCommands := []string{
		"login",
		"logout",
		"pull",
		"run",
		"info",
		"cache",
		"doctor",
	}

	commands := rootCmd.Commands()
	commandNames := make([]string, len(commands))
	for i, cmd := range commands {
		commandNames[i] = cmd.Name()
	}

	for _, expected := range expectedCommands {
		assert.Contains(t, commandNames, expected, "Expected command %s to be registered", expected)
	}
}

func TestCacheSubcommands(t *testing.T) {
	// Test that cache command has ls and rm subcommands
	var cacheCommand *cobra.Command
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "cache" {
			cacheCommand = cmd
			break
		}
	}

	require.NotNil(t, cacheCommand, "cache command should exist")

	subcommands := cacheCommand.Commands()
	subcommandNames := make([]string, len(subcommands))
	for i, cmd := range subcommands {
		subcommandNames[i] = cmd.Name()
	}

	assert.Contains(t, subcommandNames, "ls")
	assert.Contains(t, subcommandNames, "rm")
}

func TestGlobalFlags(t *testing.T) {
	// Test that global flags are registered
	flags := rootCmd.PersistentFlags()

	assert.NotNil(t, flags.Lookup("registry"))
	assert.NotNil(t, flags.Lookup("cache-dir"))
	assert.NotNil(t, flags.Lookup("verbose"))
	assert.NotNil(t, flags.Lookup("json"))
}
