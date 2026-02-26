package main

import (
	"os"

	"github.com/security-mcp/mcp-client/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
