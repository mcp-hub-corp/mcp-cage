package executor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mcp-hub-corp/mcp-cage/internal/manifest"
	"github.com/mcp-hub-corp/mcp-cage/internal/mcp"
	"github.com/mcp-hub-corp/mcp-cage/internal/policy"
	"github.com/mcp-hub-corp/mcp-cage/internal/sandbox"
)

// Executor defines the interface for executing MCP servers
type Executor interface {
	Execute(ctx context.Context, entrypoint *manifest.Entrypoint, bundlePath string) error
}

// STDIOExecutor executes MCP servers using STDIO transport
type STDIOExecutor struct {
	workDir         string
	limits          *policy.ExecutionLimits
	perms           *manifest.PermissionsInfo
	env             map[string]string
	logger          *slog.Logger
	noSandbox       bool
	stderr          io.Writer
	securityWarning *mcp.SecurityWarning // nil = no proxy, direct passthrough
}

// NewSTDIOExecutor creates a new STDIO executor
// CRITICAL SECURITY: Validates that execution limits are properly set
// Returns error if limits are nil or incomplete (execution without limits is forbidden)
// perms may be nil if no manifest permissions are available.
func NewSTDIOExecutor(workDir string, limits *policy.ExecutionLimits, perms *manifest.PermissionsInfo, env map[string]string) (*STDIOExecutor, error) {
	if workDir == "" {
		return nil, fmt.Errorf("work directory cannot be empty")
	}

	// CRITICAL: Enforce non-nil limits (execution without limits is forbidden)
	if limits == nil {
		return nil, fmt.Errorf("CRITICAL: limits cannot be nil - execution without resource limits is forbidden")
	}

	// CRITICAL: Validate all mandatory limits are set
	// These checks prevent undefined behavior from incomplete limit configurations
	if limits.MaxCPU <= 0 {
		return nil, fmt.Errorf("CRITICAL: MaxCPU must be > 0 (got %d) - execution without CPU limits is forbidden", limits.MaxCPU)
	}

	if limits.MaxMemory == "" {
		return nil, fmt.Errorf("CRITICAL: MaxMemory must be set (got empty string) - execution without memory limits is forbidden")
	}

	if limits.MaxPIDs <= 0 {
		return nil, fmt.Errorf("CRITICAL: MaxPIDs must be > 0 (got %d) - execution without PID limits is forbidden", limits.MaxPIDs)
	}

	if limits.MaxFDs <= 0 {
		return nil, fmt.Errorf("CRITICAL: MaxFDs must be > 0 (got %d) - execution without file descriptor limits is forbidden", limits.MaxFDs)
	}

	if limits.Timeout <= 0 {
		return nil, fmt.Errorf("CRITICAL: Timeout must be > 0 (got %v) - execution without timeout is forbidden", limits.Timeout)
	}

	return &STDIOExecutor{
		workDir: workDir,
		limits:  limits,
		perms:   perms,
		env:     env,
		logger:  slog.Default(),
		stderr:  os.Stderr,
	}, nil
}

// SetLogger sets the logger
func (e *STDIOExecutor) SetLogger(logger *slog.Logger) {
	e.logger = logger
}

// SetNoSandbox disables sandbox restrictions
func (e *STDIOExecutor) SetNoSandbox(noSandbox bool) {
	e.noSandbox = noSandbox
}

// SetStderr sets the writer for subprocess stderr output.
// Use io.Discard to silence subprocess output in non-verbose mode.
func (e *STDIOExecutor) SetStderr(w io.Writer) {
	e.stderr = w
}

// SetSecurityWarning configures a security warning to inject into the MCP
// protocol via a STDIO proxy. When set, the executor creates pipes instead of
// connecting stdin/stdout directly, and runs an MCPProxy that intercepts the
// init handshake to inject the warning. After the handshake, the proxy
// switches to raw io.Copy for zero overhead.
func (e *STDIOExecutor) SetSecurityWarning(w *mcp.SecurityWarning) {
	e.securityWarning = w
}

// Execute starts the MCP server process via STDIO and waits for completion
func (e *STDIOExecutor) Execute(ctx context.Context, entrypoint *manifest.Entrypoint, bundlePath string) error {
	if entrypoint == nil {
		return fmt.Errorf("entrypoint cannot be nil")
	}
	if bundlePath == "" {
		return fmt.Errorf("bundle path cannot be empty")
	}

	// Build the full command path
	var commandPath string

	if manifest.IsSystemCommand(entrypoint.Command) {
		// System binary (node, python, etc.) - resolve from PATH
		systemPath, lookErr := exec.LookPath(entrypoint.Command)
		if lookErr != nil {
			return fmt.Errorf("system command %q not found on PATH: %w", entrypoint.Command, lookErr)
		}
		commandPath = systemPath
	} else {
		// Bundle-local binary - resolve within bundle directory
		commandPath = filepath.Join(bundlePath, entrypoint.Command)

		// SECURITY: Validate that the resolved command path is still within bundlePath
		// to prevent path traversal attacks (e.g., entrypoint.Command = "../../malicious")
		cleanCommand := filepath.Clean(commandPath)
		cleanBundle := filepath.Clean(bundlePath)
		relPath, err := filepath.Rel(cleanBundle, cleanCommand)
		if err != nil || strings.HasPrefix(relPath, "..") {
			return fmt.Errorf("path traversal detected: entrypoint %q escapes bundle directory", entrypoint.Command)
		}

		// Check if command exists and is executable
		if _, err := os.Stat(commandPath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("command not found: %s", commandPath)
			}
			return fmt.Errorf("failed to stat command: %w", err)
		}
	}

	e.logger.Debug("starting STDIO executor",
		slog.String("command", commandPath),
		slog.String("workdir", e.workDir),
		slog.Int("max_cpu", e.limits.MaxCPU),
		slog.String("max_memory", e.limits.MaxMemory),
		slog.Duration("timeout", e.limits.Timeout),
	)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, e.limits.Timeout)
	defer cancel()

	// Create command
	cmd := exec.CommandContext(ctx, commandPath, entrypoint.Args...)

	// Set working directory
	cmd.Dir = e.workDir

	// Set environment
	cmd.Env = e.buildEnv()

	// Connect STDIO — either direct passthrough or via proxy
	if e.securityWarning != nil {
		// Proxy mode: intercept STDIO to inject security warnings
		stdinPipe, stdinErr := cmd.StdinPipe()
		if stdinErr != nil {
			return fmt.Errorf("creating stdin pipe for proxy: %w", stdinErr)
		}
		stdoutPipe, stdoutErr := cmd.StdoutPipe()
		if stdoutErr != nil {
			return fmt.Errorf("creating stdout pipe for proxy: %w", stdoutErr)
		}
		stderrPipe, stderrErr := cmd.StderrPipe()
		if stderrErr != nil {
			return fmt.Errorf("creating stderr pipe for proxy: %w", stderrErr)
		}

		proxy := mcp.NewMCPProxy(os.Stdin, os.Stdout, stdoutPipe, stdinPipe, e.securityWarning, e.logger)
		proxy.SetStderr(stderrPipe, e.stderr)

		// Apply sandbox restrictions (unless --no-sandbox is set)
		sb := sandbox.New()
		if e.noSandbox {
			e.logger.Warn("SECURITY: sandbox disabled via --no-sandbox flag",
				slog.String("command", commandPath),
			)
		} else {
			if err := sb.Apply(cmd, e.limits, e.perms); err != nil {
				e.logger.Error("failed to apply sandbox restrictions",
					slog.String("error", err.Error()),
					slog.String("sandbox", sb.Name()),
				)
				return fmt.Errorf("sandbox apply failed (use --no-sandbox to bypass): %w", err)
			}
		}

		// Start the process
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start process: %w", err)
		}

		pid := cmd.Process.Pid
		e.logger.Debug("process started with proxy", slog.Int("pid", pid))

		// Apply post-spawn sandbox restrictions
		if !e.noSandbox {
			if err := sb.PostStart(pid, e.limits); err != nil {
				e.logger.Warn("failed to apply post-start sandbox restrictions",
					slog.String("error", err.Error()),
					slog.String("sandbox", sb.Name()),
				)
			}
		}

		// Start the proxy goroutine and track its completion.
		// CRITICAL: We must wait for the proxy to finish AFTER cmd.Wait().
		// Without this, Execute() returns immediately when the process exits,
		// the CLI exits, and the proxy goroutine is orphaned — losing any
		// in-flight data between client and server.
		var proxyWg sync.WaitGroup
		proxyWg.Add(1)
		go func() {
			defer proxyWg.Done()
			if proxyErr := proxy.Run(); proxyErr != nil {
				e.logger.Debug("mcp proxy finished", slog.String("error", proxyErr.Error()))
			}
		}()

		// Ensure cleanup of sandbox resources after process exits
		defer func() {
			if cleanupErr := sb.Cleanup(pid); cleanupErr != nil {
				e.logger.Debug("sandbox cleanup warning",
					slog.String("error", cleanupErr.Error()),
					slog.String("sandbox", sb.Name()),
				)
			}
		}()

		// Wait for process to complete or context to cancel
		err := cmd.Wait()

		// Wait for the proxy goroutine to drain remaining data.
		// cmd.Wait() closes the pipes, so the proxy's io.Copy loops will
		// see EOF and exit. This ensures no data is lost.
		proxyWg.Wait()

		if ctx.Err() == context.DeadlineExceeded {
			e.logger.Warn("process timeout exceeded", slog.Duration("timeout", e.limits.Timeout))
			return fmt.Errorf("execution timeout exceeded: %s", e.limits.Timeout)
		}

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				e.logger.Info("process exited with error",
					slog.Int("exit_code", exitErr.ExitCode()),
					slog.String("error", err.Error()),
				)
				return fmt.Errorf("process exited with code %d: %w", exitErr.ExitCode(), err)
			}
			return fmt.Errorf("process execution error: %w", err)
		}

		e.logger.Info("process completed successfully")
		return nil
	}

	// Direct passthrough mode (no proxy)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = e.stderr

	// Apply sandbox restrictions (unless --no-sandbox is set)
	sb := sandbox.New()
	if e.noSandbox {
		e.logger.Warn("SECURITY: sandbox disabled via --no-sandbox flag",
			slog.String("command", commandPath),
		)
	} else {
		if err := sb.Apply(cmd, e.limits, e.perms); err != nil {
			e.logger.Error("failed to apply sandbox restrictions",
				slog.String("error", err.Error()),
				slog.String("sandbox", sb.Name()),
			)
			return fmt.Errorf("sandbox apply failed (use --no-sandbox to bypass): %w", err)
		}
	}

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start process: %w", err)
	}

	pid := cmd.Process.Pid
	e.logger.Debug("process started", slog.Int("pid", pid))

	// Apply post-spawn sandbox restrictions (cgroups, Job Objects, etc.)
	if !e.noSandbox {
		if err := sb.PostStart(pid, e.limits); err != nil {
			e.logger.Warn("failed to apply post-start sandbox restrictions",
				slog.String("error", err.Error()),
				slog.String("sandbox", sb.Name()),
			)
		}
	}

	// Ensure cleanup of sandbox resources after process exits
	defer func() {
		if cleanupErr := sb.Cleanup(pid); cleanupErr != nil {
			e.logger.Debug("sandbox cleanup warning",
				slog.String("error", cleanupErr.Error()),
				slog.String("sandbox", sb.Name()),
			)
		}
	}()

	// Wait for process to complete or context to cancel
	err := cmd.Wait()

	if ctx.Err() == context.DeadlineExceeded {
		e.logger.Warn("process timeout exceeded", slog.Duration("timeout", e.limits.Timeout))
		return fmt.Errorf("execution timeout exceeded: %s", e.limits.Timeout)
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			e.logger.Info("process exited with error",
				slog.Int("exit_code", exitErr.ExitCode()),
				slog.String("error", err.Error()),
			)
			return fmt.Errorf("process exited with code %d: %w", exitErr.ExitCode(), err)
		}
		return fmt.Errorf("process execution error: %w", err)
	}

	e.logger.Info("process completed successfully")
	return nil
}

// buildEnv builds the environment for the process.
// SECURITY: Only passes through env vars explicitly provided by the caller.
// The caller (run.go) is responsible for filtering os.Environ() through the
// policy allowlist before passing env vars here. This prevents leaking the
// parent process's full environment (secrets, tokens, etc.) to MCP servers.
func (e *STDIOExecutor) buildEnv() []string {
	envSlice := make([]string, 0, len(e.env))
	for k, v := range e.env {
		envSlice = append(envSlice, k+"="+v)
	}
	return envSlice
}

// HTTPExecutor executes MCP servers using HTTP transport.
// Note: HTTP transport support is a future enhancement beyond v1.0.
// Currently, only STDIO transport is supported.
type HTTPExecutor struct{}

// NewHTTPExecutor creates a new HTTP executor.
// Note: This is a placeholder for future HTTP transport support.
func NewHTTPExecutor() *HTTPExecutor {
	return &HTTPExecutor{}
}

// Execute starts the MCP server process with HTTP transport.
// Note: HTTP executor implementation is deferred to a future version.
// Current implementation returns not-implemented error.
func (e *HTTPExecutor) Execute(ctx context.Context, entrypoint *manifest.Entrypoint, bundlePath string) error {
	return fmt.Errorf("HTTP executor not yet implemented (planned for future release)")
}

// Stop terminates the MCP server process.
// Note: Placeholder for future HTTP transport support.
func (e *HTTPExecutor) Stop() error {
	return nil
}
