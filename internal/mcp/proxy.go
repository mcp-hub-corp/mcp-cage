package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// MCPProxy intercepts the MCP STDIO handshake to inject security warnings
// into the protocol. After the handshake completes, it switches to raw
// bidirectional io.Copy for zero overhead.
//
// State machine:
//  1. Detect "initialize" request from client → save request ID
//  2. Detect response with matching ID from server → modify instructions → forward
//  3. Detect "notifications/initialized" from client → inject notifications/message → forward
//  4. Switch to raw io.Copy (bidirectional)
type MCPProxy struct {
	// clientReader reads from the LLM client (original stdin)
	clientReader io.Reader
	// clientWriter writes to the LLM client (original stdout)
	clientWriter io.Writer
	// serverReader reads from the MCP server process stdout
	serverReader io.Reader
	// serverWriter writes to the MCP server process stdin
	serverWriter io.Writer

	warning *SecurityWarning
	logger  *slog.Logger

	// initTimeout is the maximum time to wait for the init handshake
	initTimeout time.Duration
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

// Run starts the proxy. It blocks until the connection closes or an error occurs.
// After the init handshake, it switches to raw io.Copy for zero overhead.
func (p *MCPProxy) Run() error {
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

	// Phase 2: Raw bidirectional copy
	if handshakeCompleted {
		// Handshake goroutine has exited — safe to use buffered readers
		// (preserves any data already buffered during handshake).
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
			if _, writeErr := p.clientWriter.Write(appendNewline(line)); writeErr != nil {
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
			if _, writeErr := p.clientWriter.Write(appendNewline(modified)); writeErr != nil {
				return fmt.Errorf("forwarding modified init response: %w", writeErr)
			}
			p.logger.Debug("injected security warning into initialize response")
			break
		}

		// Not the init response — forward as-is
		if _, writeErr := p.clientWriter.Write(appendNewline(line)); writeErr != nil {
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
				if _, writeErr := p.clientWriter.Write(appendNewline(notifBytes)); writeErr != nil {
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
