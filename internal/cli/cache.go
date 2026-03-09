package cli

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/mcp-hub-corp/mcp-cage/internal/cache"
	"github.com/spf13/cobra"
)

func init() {
	cacheLsCmd.RunE = runCacheLs
	cacheRmCmd.RunE = runCacheRm
	cacheGcCmd.RunE = runCacheGc
	cacheCmd.AddCommand(cacheGcCmd)
}

// cacheGcCmd garbage collects the cache
var cacheGcCmd = &cobra.Command{
	Use:   "gc",
	Short: "Garbage collect the cache",
	Long:  `Clean up unused cache entries (optional, can be extended in the future).`,
}

// runCacheLs lists all cached artifacts
func runCacheLs(cmd *cobra.Command, args []string) error {
	// Create logger
	logger := createLogger(cfg.LogLevel)

	// Create cache store
	cacheStore, err := cache.NewStore(cfg.CacheDir)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}

	logger.Debug("listing cache artifacts", slog.String("cache_dir", cfg.CacheDir))

	// List all artifacts
	artifacts, err := cacheStore.List()
	if err != nil {
		return fmt.Errorf("failed to list cache artifacts: %w", err)
	}

	if len(artifacts) == 0 {
		fmt.Println("Cache is empty")
		return nil
	}

	// Sort artifacts by modification time (most recent first)
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].ModTime.After(artifacts[j].ModTime)
	})

	// Calculate total size
	var totalSize int64
	for _, artifact := range artifacts {
		totalSize += artifact.SizeBytes
	}

	// Output table header
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "DIGEST\tTYPE\tSIZE\tLAST USED") //nolint:errcheck // output to stdout

	// Output artifacts
	for _, artifact := range artifacts {
		digestStr := abbreviateDigest(artifact.Digest)
		sizeStr := formatSize(artifact.SizeBytes)
		timeStr := formatTime(artifact.ModTime)

		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", digestStr, artifact.Type, sizeStr, timeStr) //nolint:errcheck // output to stdout
	}

	_ = w.Flush() //nolint:errcheck // best effort flush

	// Output summary
	fmt.Println()
	fmt.Printf("Total cached: %d artifacts, %s\n", len(artifacts), formatSize(totalSize))

	return nil
}

// runCacheRm removes a cached artifact by digest
func runCacheRm(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("expected at least one argument (digest)")
	}

	// Create logger
	logger := createLogger(cfg.LogLevel)

	// Create cache store
	cacheStore, err := cache.NewStore(cfg.CacheDir)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Check for --all flag
	removeAll, err := cmd.Flags().GetBool("all")
	if err != nil {
		return fmt.Errorf("failed to get --all flag: %w", err)
	}

	if removeAll {
		// Remove all artifacts
		artifacts, err := cacheStore.List()
		if err != nil {
			return fmt.Errorf("failed to list cache artifacts: %w", err)
		}

		for _, artifact := range artifacts {
			if err := cacheStore.Delete(artifact.Digest, artifact.Type); err != nil {
				logger.Warn("failed to delete artifact", slog.String("digest", artifact.Digest), slog.String("error", err.Error()))
				continue
			}
			fmt.Printf("Removed %s (%s)\n", abbreviateDigest(artifact.Digest), artifact.Type)
		}

		fmt.Printf("Cache cleared: %d artifacts removed\n", len(artifacts))
		return nil
	}

	// Remove specific artifact(s)
	removedCount := 0
	for _, arg := range args {
		digest := arg

		// Try to remove as manifest first
		err := cacheStore.Delete(digest, "manifest")
		if err == nil {
			fmt.Printf("Removed manifest %s\n", abbreviateDigest(digest))
			removedCount++
			continue
		}

		// Try to remove as bundle
		err = cacheStore.Delete(digest, "bundle")
		if err == nil {
			fmt.Printf("Removed bundle %s\n", abbreviateDigest(digest))
			removedCount++
			continue
		}

		logger.Warn("failed to remove artifact", slog.String("digest", digest), slog.String("error", err.Error()))
	}

	if removedCount == 0 {
		return fmt.Errorf("no artifacts were removed")
	}

	fmt.Printf("Removed %d artifact(s)\n", removedCount)
	return nil
}

// runCacheGc garbage collects the cache (placeholder for future implementation)
func runCacheGc(cmd *cobra.Command, args []string) error {
	// Create logger
	logger := createLogger(cfg.LogLevel)

	// Create cache store
	cacheStore, err := cache.NewStore(cfg.CacheDir)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}

	logger.Info("garbage collecting cache")

	// List all artifacts
	artifacts, err := cacheStore.List()
	if err != nil {
		return fmt.Errorf("failed to list cache artifacts: %w", err)
	}

	if len(artifacts) == 0 {
		fmt.Println("Cache is already clean")
		return nil
	}

	// Future: Implement cleanup policies like LRU, size limits, etc.
	// For now, just report cache status
	totalSize, err := cacheStore.Size()
	if err != nil {
		return fmt.Errorf("failed to calculate cache size: %w", err)
	}

	fmt.Printf("Cache status: %d artifacts, %s\n", len(artifacts), formatSize(totalSize))
	fmt.Println("No cleanup policies configured for this version")

	return nil
}

// formatTime formats a time for display
func formatTime(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	// Less than a minute
	if diff < time.Minute {
		return "just now"
	}

	// Less than an hour
	if diff < time.Hour {
		minutes := int(diff.Minutes())
		if minutes == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", minutes)
	}

	// Less than a day
	if diff < 24*time.Hour {
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	}

	// Less than a week
	if diff < 7*24*time.Hour {
		days := int(diff.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}

	// Return formatted date
	return t.Format("2006-01-02")
}

func init() {
	cacheRmCmd.Flags().BoolP("all", "a", false, "Remove all cached artifacts")
}
