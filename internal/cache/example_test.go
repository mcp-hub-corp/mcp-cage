package cache_test

import (
	"fmt"
	"log"
	"os"

	"github.com/mcp-hub-corp/mcp-cage/internal/cache"
)

// Example of creating and using a cache store
func ExampleNewStore() {
	// Create cache in temporary directory
	tmpDir, err := os.MkdirTemp("", "mcp-cache-*")
	if err != nil {
		log.Fatal(err)
	}

	store, err := cache.NewStore(tmpDir)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		log.Fatal(err)
	}

	// Store a manifest
	manifest := []byte(`{"schema_version": "1.0"}`)
	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	err = store.PutManifest(digest, manifest)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		log.Fatal(err)
	}

	// Check if it exists
	exists := store.Exists(digest, "manifest")
	fmt.Printf("Manifest cached: %v\n", exists)

	_ = os.RemoveAll(tmpDir)
	// Output: Manifest cached: true
}

// Example of checking cache contents
func ExampleStore_List() {
	tmpDir, _ := os.MkdirTemp("", "mcp-cache-*")

	store, _ := cache.NewStore(tmpDir)

	// Add some artifacts
	_ = store.PutManifest("sha256:abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1", []byte("manifest1"))
	_ = store.PutBundle("sha256:def456def456def456def456def456def456def456def456def456def456def4", []byte("bundle1"))

	// List all
	artifacts, _ := store.List()
	fmt.Printf("Cached artifacts: %d\n", len(artifacts))

	_ = os.RemoveAll(tmpDir)
	// Output: Cached artifacts: 2
}
