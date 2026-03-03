//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/security-mcp/mcp-client/internal/manifest"
)

// generateSBPLProfile creates a Seatbelt Profile Language (SBPL) file
// for macOS sandbox-exec. The profile follows deny-by-default with
// explicit allowlists derived from the manifest permissions.
//
// Returns the path to the temporary profile file. Caller must delete it after use.
func generateSBPLProfile(commandPath string, perms *manifest.PermissionsInfo, workDir string) (string, error) {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n\n")

	// Allow basic process lifecycle (process-exec is controlled per-path below)
	sb.WriteString("; Allow basic process lifecycle\n")
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow signal)\n")
	sb.WriteString("(allow sysctl-read)\n")
	// Allow file metadata reads globally (stat/lstat only, not file content).
	// Needed for symlink traversal (/var -> /private/var, /tmp -> /private/tmp).
	sb.WriteString("(allow file-read-metadata)\n\n")

	// Allow reading system libraries, frameworks, and essential paths
	sb.WriteString("; System libraries and frameworks\n")
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (literal \"/\")\n")
	sb.WriteString("    (subpath \"/usr/lib\")\n")
	sb.WriteString("    (subpath \"/usr/share\")\n")
	sb.WriteString("    (subpath \"/System\")\n")
	sb.WriteString("    (subpath \"/Library/Frameworks\")\n")
	sb.WriteString("    (subpath \"/dev\")\n")
	sb.WriteString("    (subpath \"/private/etc\")\n")
	sb.WriteString("    (subpath \"/private/var/db\")\n")
	sb.WriteString(")\n\n")

	// Allow reading and executing the command binary and its bundle directory
	bundleDir := filepath.Dir(commandPath)
	sb.WriteString("; Command binary and bundle directory\n")
	fmt.Fprintf(&sb, "(allow file-read* (subpath \"%s\"))\n", escapeSBPLPath(bundleDir))
	fmt.Fprintf(&sb, "(allow file-read* (literal \"%s\"))\n", escapeSBPLPath(commandPath))
	fmt.Fprintf(&sb, "(allow process-exec (literal \"%s\"))\n\n", escapeSBPLPath(commandPath))

	// Allow execution of common runtime directories for system commands.
	// System commands like uv, node, python need to spawn subprocesses
	// (e.g., uv -> python -> mcp server) so we must allow their runtime paths.
	sb.WriteString("; Runtime binary directories (for system command chains)\n")
	for _, runtimeDir := range []string{
		"/opt/homebrew", // Homebrew on Apple Silicon
		"/usr/local",    // Homebrew on Intel / system installs
		"/usr/bin",      // System binaries
		"/usr/lib",      // System libraries (dylibs)
		"/Library/Frameworks",
	} {
		if _, statErr := os.Stat(runtimeDir); statErr == nil {
			fmt.Fprintf(&sb, "(allow file-read* (subpath \"%s\"))\n", escapeSBPLPath(runtimeDir))
			fmt.Fprintf(&sb, "(allow process-exec (subpath \"%s\"))\n", escapeSBPLPath(runtimeDir))
		}
	}
	sb.WriteString("\n")

	// Allow read/write to the work directory
	if workDir != "" {
		sb.WriteString("; Work directory (read-write)\n")
		fmt.Fprintf(&sb, "(allow file-read* file-write* (subpath \"%s\"))\n", escapeSBPLPath(workDir))
	}

	// Allow read/write to temp directories
	tmpDir := os.TempDir()
	fmt.Fprintf(&sb, "(allow file-read* file-write* (subpath \"%s\"))\n", escapeSBPLPath(tmpDir))
	sb.WriteString("(allow file-read* file-write* (subpath \"/private/tmp\"))\n\n")

	// Allow STDIO file descriptors
	sb.WriteString("; Standard I/O\n")
	sb.WriteString("(allow file-read* file-write* (literal \"/dev/tty\"))\n")
	sb.WriteString("(allow file-read* file-write* (literal \"/dev/fd\"))\n\n")

	// Mach/IPC (needed for basic process lifecycle)
	sb.WriteString("; Mach IPC basics\n")
	sb.WriteString("(allow mach-lookup (global-name \"com.apple.system.logger\"))\n")
	sb.WriteString("(allow mach-lookup (global-name \"com.apple.system.notification_center\"))\n\n")

	// Blanket filesystem access: allow all paths
	if perms != nil && perms.AllFS {
		sb.WriteString("\n; FULL FILESYSTEM ACCESS (--allow-fs)\n")
		sb.WriteString("(allow file-read* file-write*)\n")
	}

	// Network rules based on permissions.
	// KNOWN LIMITATION: macOS sandbox-exec does not support per-domain network filtering.
	// Any network permission (even a single domain) results in full network access.
	// True per-domain filtering requires a userspace proxy or packet filter, which is
	// beyond the scope of sandbox-exec SBPL profiles. Linux uses network namespaces instead.
	if perms != nil && (perms.AllNet || len(perms.Network) > 0) {
		sb.WriteString("; Network access (allowed by manifest/CLI)\n")
		sb.WriteString("(allow network*)\n")
	} else {
		sb.WriteString("; Network denied (no manifest network permissions)\n")
		sb.WriteString("(deny network*)\n")
	}
	sb.WriteString("\n")

	// Subprocess control: deny-default already blocks process-exec.
	// The specific allows above (command binary + runtime dirs) punch holes.
	// When subprocess is explicitly allowed in the manifest, open process-exec globally.
	// SECURITY: Default-deny — nil perms means no subprocess (not the opposite).
	if perms != nil && perms.Subprocess {
		sb.WriteString("; Subprocess creation allowed (manifest declares subprocess: true)\n")
		sb.WriteString("(allow process-exec)\n")
	} else {
		sb.WriteString("; Subprocess restricted: only command binary and runtime directories allowed\n")
	}
	sb.WriteString("\n")

	// User cache directories (uv, pip, node_modules cache, etc.)
	if homeDir, hErr := os.UserHomeDir(); hErr == nil && homeDir != "" {
		sb.WriteString("; User cache directories\n")
		fmt.Fprintf(&sb, "(allow file-read* file-write* (subpath \"%s/.cache\"))\n", escapeSBPLPath(homeDir))
		fmt.Fprintf(&sb, "(allow file-read* file-write* (subpath \"%s/Library/Caches\"))\n", escapeSBPLPath(homeDir))
		fmt.Fprintf(&sb, "(allow file-read* file-write* (subpath \"%s/.mcp\"))\n", escapeSBPLPath(homeDir))
		fmt.Fprintf(&sb, "(allow file-read* file-write* (subpath \"%s/.local\"))\n\n", escapeSBPLPath(homeDir))
	}

	// Filesystem rules based on permissions (read+write paths)
	if perms != nil && len(perms.FileSystem) > 0 {
		sb.WriteString("\n; Additional filesystem paths from manifest (read+write)\n")
		for _, path := range perms.FileSystem {
			cleanPath := filepath.Clean(path)
			fmt.Fprintf(&sb, "(allow file-read* file-write* (subpath \"%s\"))\n", escapeSBPLPath(cleanPath))
		}
	}

	// Read-only filesystem paths from manifest/CLI
	if perms != nil && len(perms.FileSystemRead) > 0 {
		sb.WriteString("\n; Read-only filesystem paths from manifest/CLI\n")
		for _, path := range perms.FileSystemRead {
			cleanPath := filepath.Clean(path)
			fmt.Fprintf(&sb, "(allow file-read* (subpath \"%s\"))\n", escapeSBPLPath(cleanPath))
		}
	}

	// Write profile to temp file
	profileFile, err := os.CreateTemp("", "mcp-sandbox-*.sb")
	if err != nil {
		return "", fmt.Errorf("failed to create sandbox profile: %w", err)
	}

	if _, writeErr := profileFile.WriteString(sb.String()); writeErr != nil {
		_ = profileFile.Close()
		_ = os.Remove(profileFile.Name())
		return "", fmt.Errorf("failed to write sandbox profile: %w", writeErr)
	}

	if closeErr := profileFile.Close(); closeErr != nil {
		_ = os.Remove(profileFile.Name())
		return "", fmt.Errorf("failed to close sandbox profile: %w", closeErr)
	}

	return profileFile.Name(), nil
}

// escapeSBPLPath escapes a filesystem path for use in SBPL profile strings.
// SBPL uses Scheme-like syntax where strings are double-quoted.
func escapeSBPLPath(path string) string {
	// Resolve symlinks for consistent path matching
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		path = resolved
	}
	// Escape backslashes and double quotes
	path = strings.ReplaceAll(path, "\\", "\\\\")
	path = strings.ReplaceAll(path, "\"", "\\\"")
	return path
}
