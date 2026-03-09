package main

import (
	"os"

	"github.com/mcp-hub-corp/mcp-cage/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
