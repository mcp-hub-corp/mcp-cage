package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// MCPProxy intercepts the MCP STDIO handshake to inject security warnings
// into the protocol. After the handshake completes, it either switches to
// raw io.Copy (zero overhead) or line-by-line scanning mode that detects
// sandbox errors and injects notifications/message alerts to the LLM.
//
// State machine:
//  1. Detect "initialize" request from client → save request ID
//  2. Detect response with matching ID from server → modify instructions → forward
//  3. Detect "notifications/initialized" from client → inject notifications/message → forward
//  4. Switch to raw io.Copy or error-scanning mode (based on SandboxContext)
type MCPProxy struct {
	// clientReader reads from the LLM client (original stdin)
	clientReader io.Reader
	// clientWriter writes to the LLM client (original stdout)
	clientWriter io.Writer
	// serverReader reads from the MCP server process stdout
	serverReader io.Reader
	// serverWriter writes to the MCP server process stdin
	serverWriter io.Writer

	// stderrReader reads from the MCP server process stderr (optional)
	stderrReader io.Reader
	// stderrForward forwards stderr lines to the original stderr writer (optional)
	stderrForward io.Writer

	warning *SecurityWarning
	logger  *slog.Logger

	// writeMu protects clientWriter when multiple goroutines inject notifications
	writeMu sync.Mutex

	// initTimeout is the maximum time to wait for the init handshake
	initTimeout time.Duration
}

// sandboxErrorPatterns are error strings that indicate a sandbox-blocked operation.
// Fast pre-check avoids JSON parsing on every message.
var sandboxErrorPatterns = []string{
	"Operation not permitted",
	"Permission denied",
	"[Errno 1]",
	"[Errno 13]",
	"EACCES",
	"EPERM",
}

// NewMCPProxy creates a proxy that intercepts the MCP init handshake.
func NewMCPProxy(
	clientReader io.Reader,
	clientWriter io.Writer,
	serverReader io.Reader,
	serverWriter io.Writer,
	warning *SecurityWarning,
	logger *slog.Logger,
) *MCPProxy {
	if logger == nil {
		logger = slog.Default()
	}
	return &MCPProxy{
		clientReader: clientReader,
		clientWriter: clientWriter,
		serverReader: serverReader,
		serverWriter: serverWriter,
		warning:      warning,
		logger:       logger,
		initTimeout:  30 * time.Second,
	}
}

// SetInitTimeout sets the timeout for the init handshake phase.
func (p *MCPProxy) SetInitTimeout(d time.Duration) {
	p.initTimeout = d
}

// SetStderr configures the proxy to scan MCP server stderr for sandbox error
// patterns. When a pattern is detected, a notifications/message is injected
// on stdout to alert the LLM. The forward writer receives all stderr lines
// for optional display (e.g., os.Stderr in verbose mode, io.Discard otherwise).
func (p *MCPProxy) SetStderr(reader io.Reader, forward io.Writer) {
	p.stderrReader = reader
	p.stderrForward = forward
}

// Run starts the proxy. It blocks until the connection closes or an error occurs.
// After the init handshake, it switches to raw io.Copy or error-scanning mode.
func (p *MCPProxy) Run() error {
	// Start stderr processing immediately to prevent pipe deadlock.
	// MCP servers write to stderr during startup, before the handshake completes.
	// If the OS pipe buffer (~64KB) fills, the server blocks on stderr write and
	// never sends the initialize response → deadlock.
	if p.stderrReader != nil {
		go p.processStderr()
	}

	clientBuf := bufio.NewReader(p.clientReader)
	serverBuf := bufio.NewReader(p.serverReader)

	// Phase 1: Intercept init handshake with timeout
	done := make(chan error, 1)
	go func() {
		done <- p.handleHandshake(clientBuf, serverBuf)
	}()

	handshakeCompleted := false
	select {
	case err := <-done:
		handshakeCompleted = true
		if err != nil {
			p.logger.Warn("handshake interception failed, switching to raw passthrough",
				slog.String("error", err.Error()))
		}
	case <-time.After(p.initTimeout):
		p.logger.Warn("handshake timeout, switching to raw passthrough",
			slog.Duration("timeout", p.initTimeout))
	}

	// Phase 2: Post-handshake
	if handshakeCompleted {
		// If sandbox context is set and sandbox is active, use error-scanning mode
		if p.warning != nil && p.warning.SandboxContext != nil && !p.warning.SandboxContext.NoSandbox {
			return p.rawCopyWithErrorScanning(clientBuf, serverBuf)
		}
		// Raw mode: zero overhead passthrough
		return p.rawCopy(clientBuf, serverBuf)
	}

	// Timeout: handshake goroutine still owns the buffered readers.
	// Use the raw underlying readers to avoid data race on bufio.Reader.
	return p.rawCopyDirect()
}

// handleHandshake manages the init handshake interception.
func (p *MCPProxy) handleHandshake(clientBuf, serverBuf *bufio.Reader) error {
	// Step 1: Read initialize request from client, forward to server
	var initID json.RawMessage
	for {
		line, err := readLine(clientBuf)
		if err != nil {
			return fmt.Errorf("reading client init request: %w", err)
		}

		// Forward the line as-is to server
		if _, writeErr := p.serverWriter.Write(appendNewline(line)); writeErr != nil {
			return fmt.Errorf("forwarding init request to server: %w", writeErr)
		}

		// Try to parse as JSON-RPC
		msg, parseErr := ParseMessage(line)
		if parseErr != nil {
			continue // Not JSON, forwarded as-is
		}

		if msg.IsRequest() && msg.Method == "initialize" {
			initID = msg.ID
			p.logger.Debug("intercepted initialize request", slog.String("id", string(initID)))
			break
		}
	}

	// Step 2: Read initialize response from server, modify instructions, forward to client
	for {
		line, err := readLine(serverBuf)
		if err != nil {
			return fmt.Errorf("reading server init response: %w", err)
		}

		msg, parseErr := ParseMessage(line)
		if parseErr != nil {
			// Not JSON — forward as-is
			if _, writeErr := p.writeToClient(appendNewline(line)); writeErr != nil {
				return fmt.Errorf("forwarding non-JSON server data: %w", writeErr)
			}
			continue
		}

		if msg.IsResponse() && IDsMatch(msg.ID, initID) {
			// Found the initialize response — inject warning into instructions
			modified, modErr := p.injectInstructions(line)
			if modErr != nil {
				p.logger.Warn("failed to inject instructions, forwarding original",
					slog.String("error", modErr.Error()))
				modified = line
			}
			if _, writeErr := p.writeToClient(appendNewline(modified)); writeErr != nil {
				return fmt.Errorf("forwarding modified init response: %w", writeErr)
			}
			p.logger.Debug("injected security warning into initialize response")
			break
		}

		// Not the init response — forward as-is
		if _, writeErr := p.writeToClient(appendNewline(line)); writeErr != nil {
			return fmt.Errorf("forwarding server data: %w", writeErr)
		}
	}

	// Step 3: Read notifications/initialized from client, then inject notifications/message
	for {
		line, err := readLine(clientBuf)
		if err != nil {
			return fmt.Errorf("reading client initialized notification: %w", err)
		}

		// Forward the line as-is to server
		if _, writeErr := p.serverWriter.Write(appendNewline(line)); writeErr != nil {
			return fmt.Errorf("forwarding initialized notification: %w", writeErr)
		}

		msg, parseErr := ParseMessage(line)
		if parseErr != nil {
			continue
		}

		if msg.IsNotification() && msg.Method == "notifications/initialized" {
			p.logger.Debug("intercepted notifications/initialized")

			// Inject notifications/message warning to client
			notification := p.buildNotification()
			notifBytes, marshalErr := json.Marshal(notification)
			if marshalErr != nil {
				p.logger.Warn("failed to marshal notification warning",
					slog.String("error", marshalErr.Error()))
			} else {
				if _, writeErr := p.writeToClient(appendNewline(notifBytes)); writeErr != nil {
					p.logger.Warn("failed to send notification warning",
						slog.String("error", writeErr.Error()))
				} else {
					p.logger.Debug("injected notifications/message warning")
				}
			}
			break
		}
	}

	return nil
}

// injectInstructions modifies the initialize response to prepend the security
// warning to the instructions field.
func (p *MCPProxy) injectInstructions(line []byte) ([]byte, error) {
	var msg JSONRPCMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, fmt.Errorf("parsing init response: %w", err)
	}

	var result InitializeResult
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		return nil, fmt.Errorf("parsing init result: %w", err)
	}

	// Prepend warning to existing instructions
	warningText := p.warning.GenerateInstructionsWarning()
	if result.Instructions != "" {
		result.Instructions = warningText + "\n\n" + result.Instructions
	} else {
		result.Instructions = warningText
	}

	// Re-marshal result
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshaling modified result: %w", err)
	}

	msg.Result = resultBytes
	return json.Marshal(msg)
}

// buildNotification creates a notifications/message JSON-RPC notification.
func (p *MCPProxy) buildNotification() JSONRPCMessage {
	params := NotificationParams{
		Level:  "warning",
		Logger: "mcp-hub-security",
		Data:   p.warning.GenerateNotificationWarning(),
	}
	paramsBytes, _ := json.Marshal(params) //nolint:errcheck // NotificationParams always marshals

	return JSONRPCMessage{
		JSONRPC: "2.0",
		Method:  "notifications/message",
		Params:  paramsBytes,
	}
}

// writeToClient writes data to the LLM client, protected by a mutex.
// This is needed when multiple goroutines (server→client, stderr→client)
// may inject notifications concurrently.
func (p *MCPProxy) writeToClient(data []byte) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return p.clientWriter.Write(data)
}

// rawCopyWithErrorScanning performs bidirectional copy with sandbox error
// detection on both the server→client direction and stderr. When a sandbox
// error pattern is detected in a JSON-RPC response or stderr line, a
// notifications/message is injected to alert the LLM.
//
// Client→Server: raw io.Copy (no interception needed)
// Server→Client: line-by-line scanning for sandbox error patterns
// Stderr→Client: line-by-line scanning for sandbox error patterns (optional)
func (p *MCPProxy) rawCopyWithErrorScanning(clientBuf, serverBuf *bufio.Reader) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(2)

	// Client → Server: raw copy (no interception needed)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(p.serverWriter, clientBuf); err != nil {
			errCh <- fmt.Errorf("client→server copy: %w", err)
		}
	}()

	// Server → Client: line-by-line scanning for sandbox errors
	go func() {
		defer wg.Done()
		for {
			line, err := readLine(serverBuf)
			if err != nil {
				if err != io.EOF {
					errCh <- fmt.Errorf("server→client read: %w", err)
				}
				return
			}

			// Always forward the original line first
			if _, writeErr := p.writeToClient(appendNewline(line)); writeErr != nil {
				errCh <- fmt.Errorf("server→client write: %w", writeErr)
				return
			}

			// Detect sandbox errors and inject notification AFTER the error response
			if notification := p.detectSandboxError(line); notification != nil {
				if _, writeErr := p.writeToClient(appendNewline(notification)); writeErr != nil {
					p.logger.Warn("failed to inject sandbox notification",
						slog.String("error", writeErr.Error()))
				}
			}
		}
	}()

	// Note: stderr goroutine is started in Run() before the handshake
	// to prevent pipe deadlock during MCP server startup.

	wg.Wait()
	close(errCh)

	for err := range errCh {
		return err
	}
	return nil
}

// processStderr reads from the MCP server's stderr pipe, forwards all lines
// to the configured stderr writer (preventing pipe deadlock), and optionally
// injects sandbox error notifications to the LLM client when sandbox is active.
//
// This method MUST be started before the handshake because MCP servers write
// startup logs to stderr during initialization. If the OS pipe buffer (~64KB)
// fills before anyone reads, the server blocks and never sends the initialize
// response, causing a deadlock.
func (p *MCPProxy) processStderr() {
	stderrBuf := bufio.NewReader(p.stderrReader)

	// Only inject notifications when sandbox is active
	injectNotifications := p.warning != nil &&
		p.warning.SandboxContext != nil &&
		!p.warning.SandboxContext.NoSandbox

	for {
		line, err := readLine(stderrBuf)
		if err != nil {
			if err != io.EOF {
				p.logger.Debug("stderr read finished", slog.String("error", err.Error()))
			}
			return
		}

		// Always forward stderr to the original writer (e.g., os.Stderr or io.Discard)
		if p.stderrForward != nil {
			_, _ = p.stderrForward.Write(appendNewline(line))
		}

		if !injectNotifications {
			continue
		}

		// Check for sandbox error patterns in stderr
		lineStr := string(line)
		found := false
		for _, pattern := range sandboxErrorPatterns {
			if strings.Contains(lineStr, pattern) {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		// Build suggestion from stderr error
		blockedPath := extractPathFromError(lineStr)
		var ctx *SandboxContext
		if p.warning != nil {
			ctx = p.warning.SandboxContext
		}
		suggestion := buildSandboxSuggestion(blockedPath, lineStr, ctx)
		notification := buildSandboxErrorNotification(suggestion)
		notifBytes, marshalErr := json.Marshal(notification)
		if marshalErr != nil {
			continue
		}

		p.logger.Debug("sandbox error detected in stderr, injecting notification",
			slog.String("blocked_path", blockedPath))

		if _, writeErr := p.writeToClient(appendNewline(notifBytes)); writeErr != nil {
			p.logger.Warn("failed to inject stderr sandbox notification",
				slog.String("error", writeErr.Error()))
		}
	}
}

// detectSandboxError checks if a line contains a sandbox error pattern.
// Uses a fast string pre-check to avoid JSON parsing on every message.
// Returns the notification bytes to inject, or nil if no sandbox error detected.
func (p *MCPProxy) detectSandboxError(line []byte) []byte {
	// Fast pre-check: any sandbox error pattern present?
	lineStr := string(line)
	found := false
	for _, pattern := range sandboxErrorPatterns {
		if strings.Contains(lineStr, pattern) {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	// Verify it's a JSON-RPC response (not random log output)
	var msg JSONRPCMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil
	}
	if !msg.IsResponse() {
		return nil
	}

	// Extract the blocked path from the error for a specific suggestion
	blockedPath := extractPathFromError(lineStr)

	// Pass sandbox context so suggestions don't recommend already-active flags
	var ctx *SandboxContext
	if p.warning != nil {
		ctx = p.warning.SandboxContext
	}
	suggestion := buildSandboxSuggestion(blockedPath, lineStr, ctx)

	// Build notifications/message notification
	notification := buildSandboxErrorNotification(suggestion)
	notifBytes, err := json.Marshal(notification)
	if err != nil {
		return nil
	}

	p.logger.Debug("sandbox error detected, injecting notification",
		slog.String("blocked_path", blockedPath))

	return notifBytes
}

// extractPathFromError extracts a filesystem path from sandbox error messages.
// Matches patterns like: "not permitted: '/path'" or "denied: '/path'"
func extractPathFromError(errText string) string {
	for _, marker := range []string{
		"not permitted: '", "denied: '",
		"not permitted: \"", "denied: \"",
	} {
		idx := strings.Index(errText, marker)
		if idx >= 0 {
			start := idx + len(marker)
			quote := marker[len(marker)-1]
			end := strings.IndexByte(errText[start:], quote)
			if end > 0 {
				return errText[start : start+end]
			}
		}
	}
	return ""
}

// buildSandboxSuggestion builds a human-readable suggestion based on
// the blocked path, error context, and current sandbox permissions.
// When blanket flags are already active, it avoids suggesting them again
// and provides more accurate diagnostics.
func buildSandboxSuggestion(blockedPath, errText string, ctx *SandboxContext) string {
	if blockedPath != "" {
		// If AllFS is already active, the error is likely from a different restriction
		if ctx != nil && ctx.AllFS {
			return fmt.Sprintf("The MCP server tried to access '%s'. Filesystem access is already "+
				"fully granted (--allow-fs). This error may be caused by another restriction "+
				"(e.g., network, subprocess, or OS-level protection).", blockedPath)
		}
		return fmt.Sprintf("The MCP server tried to access '%s' which is outside the sandbox.\n"+
			"Suggested fix: add --allow-write %s to the smcp run command "+
			"(or --allow-fs for full filesystem access).", blockedPath, blockedPath)
	}
	if strings.Contains(errText, "network") || strings.Contains(errText, "connect") {
		if ctx != nil && ctx.AllNet {
			return "The MCP server encountered a network error. Network access is already " +
				"fully granted (--allow-all-net). This may be a connectivity issue rather than a sandbox restriction."
		}
		return "The MCP server tried to make a network connection which is blocked.\n" +
			"Suggested fix: add --allow-net <domain> to the smcp run command " +
			"(or --allow-all-net for all domains)."
	}
	return "The MCP server tried to access a restricted resource."
}

// buildSandboxErrorNotification creates a JSON-RPC notifications/message
// that alerts the LLM about a sandbox-blocked operation.
func buildSandboxErrorNotification(suggestion string) JSONRPCMessage {
	var data strings.Builder
	data.WriteString("[SMCP SANDBOX ALERT] The previous error was caused by SMCP's security sandbox ")
	data.WriteString("blocking a restricted operation to protect the user's system.\n\n")

	if suggestion != "" {
		data.WriteString(suggestion)
		data.WriteString("\n\n")
	}

	data.WriteString("You MUST inform the user that:\n")
	data.WriteString("1. SMCP blocked this operation to protect their system\n")
	data.WriteString("2. They can grant access by adding the appropriate flag to the smcp command\n")
	data.WriteString("3. Available flags: --allow-read <path>, --allow-write <path>, --allow-fs (all files), ")
	data.WriteString("--allow-net <domain>, --allow-all-net, --allow-subprocess, --allow-all (everything)\n")

	params := NotificationParams{
		Level:  "warning",
		Logger: "mcp-hub-sandbox",
		Data:   data.String(),
	}
	paramsBytes, _ := json.Marshal(params) //nolint:errcheck // NotificationParams always marshals

	return JSONRPCMessage{
		JSONRPC: "2.0",
		Method:  "notifications/message",
		Params:  paramsBytes,
	}
}

// rawCopyDirect starts bidirectional raw copy using the underlying readers
// directly, bypassing the buffered readers. Used when the handshake goroutine
// timed out and still owns the bufio.Readers.
func (p *MCPProxy) rawCopyDirect() error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(2)

	// Client → Server
	go func() {
		defer wg.Done()
		if _, err := io.Copy(p.serverWriter, p.clientReader); err != nil {
			errCh <- fmt.Errorf("client→server copy: %w", err)
		}
	}()

	// Server → Client
	go func() {
		defer wg.Done()
		if _, err := io.Copy(p.clientWriter, p.serverReader); err != nil {
			errCh <- fmt.Errorf("server→client copy: %w", err)
		}
	}()

	wg.Wait()
	close(errCh)

	// Return first error if any
	for err := range errCh {
		return err
	}
	return nil
}

// rawCopy starts bidirectional raw copy between client and server.
// Uses the buffered readers to avoid losing any data already buffered.
func (p *MCPProxy) rawCopy(clientBuf, serverBuf *bufio.Reader) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(2)

	// Client → Server
	go func() {
		defer wg.Done()
		if _, err := io.Copy(p.serverWriter, clientBuf); err != nil {
			errCh <- fmt.Errorf("client→server copy: %w", err)
		}
	}()

	// Server → Client
	go func() {
		defer wg.Done()
		if _, err := io.Copy(p.clientWriter, serverBuf); err != nil {
			errCh <- fmt.Errorf("server→client copy: %w", err)
		}
	}()

	wg.Wait()
	close(errCh)

	// Return first error if any
	for err := range errCh {
		return err
	}
	return nil
}

// readLine reads a complete line from a bufio.Reader.
// It handles lines longer than the default buffer size by concatenating
// partial reads until a newline is found.
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		part, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, part...)
		if !isPrefix {
			break
		}
	}
	return line, nil
}

// appendNewline returns the data with a trailing newline appended.
func appendNewline(data []byte) []byte {
	result := make([]byte, len(data)+1)
	copy(result, data)
	result[len(data)] = '\n'
	return result
}
