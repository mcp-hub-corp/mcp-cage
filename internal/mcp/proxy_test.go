package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/security-mcp/mcp-client/internal/manifest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockMCPServer simulates a minimal MCP server that responds to initialize.
func mockMCPServer(serverInput io.Reader, serverOutput io.Writer, existingInstructions string) {
	scanner := newLineReader(serverInput)
	for scanner.Scan() {
		line := scanner.Bytes()
		msg, err := ParseMessage(line)
		if err != nil {
			continue
		}

		if msg.IsRequest() && msg.Method == "initialize" {
			result := InitializeResult{
				ProtocolVersion: "2024-11-05",
				Capabilities:    json.RawMessage(`{}`),
				ServerInfo:      json.RawMessage(`{"name":"test-server","version":"1.0.0"}`),
				Instructions:    existingInstructions,
			}
			resultBytes, _ := json.Marshal(result)
			resp := JSONRPCMessage{
				JSONRPC: "2.0",
				ID:      msg.ID,
				Result:  resultBytes,
			}
			respBytes, _ := json.Marshal(resp)
			_, _ = serverOutput.Write(appendNewline(respBytes))
		}

		if msg.IsNotification() && msg.Method == "notifications/initialized" {
			// Server acknowledged
			return
		}
	}
}

// lineReader wraps a reader to scan lines.
type lineReader struct {
	r    io.Reader
	buf  []byte
	data []byte
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: r, buf: make([]byte, 4096)}
}

func (l *lineReader) Scan() bool {
	for {
		if idx := bytes.IndexByte(l.data, '\n'); idx >= 0 {
			return true
		}
		n, err := l.r.Read(l.buf)
		if n > 0 {
			l.data = append(l.data, l.buf[:n]...)
		}
		if err != nil {
			return len(l.data) > 0
		}
	}
}

func (l *lineReader) Bytes() []byte {
	idx := bytes.IndexByte(l.data, '\n')
	if idx < 0 {
		result := l.data
		l.data = nil
		return result
	}
	result := l.data[:idx]
	l.data = l.data[idx+1:]
	return result
}

func TestProxy_HandshakeInjectsWarning(t *testing.T) {
	warning := &SecurityWarning{
		PackageName: "acme/test",
		Score:       35,
		CertLevel:   0,
		Findings: &manifest.FindingsSummary{
			Total:    3,
			Critical: 1,
			High:     2,
		},
	}

	// Pipes: client ↔ proxy ↔ server
	clientToProxyR, clientToProxyW := io.Pipe()
	proxyToClientR, proxyToClientW := io.Pipe()
	proxyToServerR, proxyToServerW := io.Pipe()
	serverToProxyR, serverToProxyW := io.Pipe()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(clientToProxyR, proxyToClientW, serverToProxyR, proxyToServerW, warning, logger)

	// Start mock server
	go mockMCPServer(proxyToServerR, serverToProxyW, "")

	// Start proxy
	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- proxy.Run()
	}()

	// Client sends initialize request
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}` + "\n"
	_, err := clientToProxyW.Write([]byte(initReq))
	require.NoError(t, err)

	// Read modified response from proxy
	var output bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 8192)
		for {
			n, readErr := proxyToClientR.Read(buf)
			if n > 0 {
				output.Write(buf[:n])
			}
			if readErr != nil || strings.Contains(output.String(), "notifications/message") {
				break
			}
		}
		close(readDone)
	}()

	// Client sends initialized notification
	time.Sleep(100 * time.Millisecond)
	initNotif := `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	_, err = clientToProxyW.Write([]byte(initNotif))
	require.NoError(t, err)

	// Wait for output
	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for proxy output")
	}

	// Verify the response contains the security warning in instructions
	outputStr := output.String()
	assert.Contains(t, outputStr, "SECURITY WARNING")
	assert.Contains(t, outputStr, "acme/test")
	assert.Contains(t, outputStr, "35/100")

	// Verify notifications/message was sent
	assert.Contains(t, outputStr, "notifications/message")
	assert.Contains(t, outputStr, "warning")

	// Cleanup
	clientToProxyW.Close()
	serverToProxyW.Close()
}

func TestProxy_PreservesExistingInstructions(t *testing.T) {
	warning := &SecurityWarning{
		PackageName: "acme/test",
		Score:       50,
		CertLevel:   1,
	}

	clientToProxyR, clientToProxyW := io.Pipe()
	proxyToClientR, proxyToClientW := io.Pipe()
	proxyToServerR, proxyToServerW := io.Pipe()
	serverToProxyR, serverToProxyW := io.Pipe()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(clientToProxyR, proxyToClientW, serverToProxyR, proxyToServerW, warning, logger)

	// Mock server with existing instructions
	go mockMCPServer(proxyToServerR, serverToProxyW, "Original server instructions here")

	go func() {
		_ = proxy.Run()
	}()

	// Send init
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"
	_, err := clientToProxyW.Write([]byte(initReq))
	require.NoError(t, err)

	// Read response
	var output bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 8192)
		for {
			n, readErr := proxyToClientR.Read(buf)
			if n > 0 {
				output.Write(buf[:n])
			}
			if readErr != nil || strings.Contains(output.String(), "\n") {
				break
			}
		}
		close(readDone)
	}()

	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	outputStr := output.String()

	// Parse the response to check instructions
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")
	require.NotEmpty(t, lines)

	var msg JSONRPCMessage
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &msg))

	var result InitializeResult
	require.NoError(t, json.Unmarshal(msg.Result, &result))

	// Warning should be prepended, original preserved
	assert.Contains(t, result.Instructions, "SECURITY WARNING")
	assert.Contains(t, result.Instructions, "Original server instructions here")

	// Warning comes first
	warningIdx := strings.Index(result.Instructions, "SECURITY WARNING")
	origIdx := strings.Index(result.Instructions, "Original server instructions")
	assert.Less(t, warningIdx, origIdx)

	clientToProxyW.Close()
	serverToProxyW.Close()
}

func TestProxy_TimeoutFallback(t *testing.T) {
	warning := &SecurityWarning{
		PackageName: "acme/test",
		Score:       50,
		CertLevel:   1,
	}

	clientToProxyR, clientToProxyW := io.Pipe()
	proxyToClientR, proxyToClientW := io.Pipe()
	proxyToServerR, proxyToServerW := io.Pipe()
	serverToProxyR, serverToProxyW := io.Pipe()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(clientToProxyR, proxyToClientW, serverToProxyR, proxyToServerW, warning, logger)
	proxy.SetInitTimeout(200 * time.Millisecond)

	done := make(chan error, 1)
	go func() {
		done <- proxy.Run()
	}()

	// Send init request but server never responds
	_, _ = clientToProxyW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"))

	// Wait for timeout to fire, then close all pipes to let proxy finish
	time.Sleep(400 * time.Millisecond)

	// Close pipes to unblock all goroutines
	clientToProxyW.Close()
	serverToProxyW.Close()
	proxyToServerR.Close()
	proxyToClientR.Close()

	select {
	case <-done:
		// Proxy finished after timeout and cleanup
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not finish after timeout and pipe close")
	}
}

func TestProxy_MalformedJSONForwarded(t *testing.T) {
	warning := &SecurityWarning{
		PackageName: "acme/test",
		Score:       50,
		CertLevel:   1,
	}

	clientToProxyR, clientToProxyW := io.Pipe()
	proxyToClientR, proxyToClientW := io.Pipe()
	proxyToServerR, proxyToServerW := io.Pipe()
	serverToProxyR, serverToProxyW := io.Pipe()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(clientToProxyR, proxyToClientW, serverToProxyR, proxyToServerW, warning, logger)

	// Server that echos non-JSON then responds to init
	go func() {
		scanner := newLineReader(proxyToServerR)
		for scanner.Scan() {
			line := scanner.Bytes()
			msg, err := ParseMessage(line)
			if err != nil {
				continue
			}
			if msg.IsRequest() && msg.Method == "initialize" {
				result := InitializeResult{ProtocolVersion: "2024-11-05"}
				resultBytes, _ := json.Marshal(result)
				resp := JSONRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: resultBytes}
				respBytes, _ := json.Marshal(resp)
				// Send some non-JSON first, then the response
				_, _ = serverToProxyW.Write([]byte("not json data here\n"))
				_, _ = serverToProxyW.Write(appendNewline(respBytes))
			}
			if msg.IsNotification() && msg.Method == "notifications/initialized" {
				return
			}
		}
	}()

	go func() {
		_ = proxy.Run()
	}()

	// Send non-JSON first, then init request
	_, err := clientToProxyW.Write([]byte("garbage line\n"))
	require.NoError(t, err)
	_, err = clientToProxyW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"))
	require.NoError(t, err)

	// Read output — should contain the non-JSON forwarded
	var output bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 8192)
		for {
			n, readErr := proxyToClientR.Read(buf)
			if n > 0 {
				output.Write(buf[:n])
			}
			if readErr != nil || strings.Contains(output.String(), "SECURITY WARNING") {
				break
			}
		}
		close(readDone)
	}()

	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}

	outputStr := output.String()
	assert.Contains(t, outputStr, "not json data here")
	assert.Contains(t, outputStr, "SECURITY WARNING")

	clientToProxyW.Close()
	serverToProxyW.Close()
}

func TestBuildNotification(t *testing.T) {
	warning := &SecurityWarning{
		PackageName: "acme/test",
		Score:       30,
		CertLevel:   0,
		Findings: &manifest.FindingsSummary{
			Total:    2,
			Critical: 1,
			High:     1,
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(nil, nil, nil, nil, warning, logger)
	notif := proxy.buildNotification()

	assert.Equal(t, "2.0", notif.JSONRPC)
	assert.Equal(t, "notifications/message", notif.Method)
	assert.Empty(t, notif.ID)

	var params NotificationParams
	require.NoError(t, json.Unmarshal(notif.Params, &params))
	assert.Equal(t, "warning", params.Level)
	assert.Equal(t, "mcp-hub-security", params.Logger)
	assert.Contains(t, params.Data, "acme/test")
	assert.Contains(t, params.Data, "30/100")
}

func TestInjectInstructions_EmptyOriginal(t *testing.T) {
	warning := &SecurityWarning{
		PackageName: "acme/test",
		Score:       50,
		CertLevel:   1,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(nil, nil, nil, nil, warning, logger)

	result := InitializeResult{
		ProtocolVersion: "2024-11-05",
		Instructions:    "",
	}
	resultBytes, _ := json.Marshal(result)
	msg := JSONRPCMessage{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: resultBytes}
	line, _ := json.Marshal(msg)

	modified, err := proxy.injectInstructions(line)
	require.NoError(t, err)

	var modMsg JSONRPCMessage
	require.NoError(t, json.Unmarshal(modified, &modMsg))
	var modResult InitializeResult
	require.NoError(t, json.Unmarshal(modMsg.Result, &modResult))

	assert.Contains(t, modResult.Instructions, "SECURITY WARNING")
	assert.NotContains(t, modResult.Instructions, "\n\n\n") // no double separator
}

func TestInjectInstructions_WithExisting(t *testing.T) {
	warning := &SecurityWarning{
		PackageName: "acme/test",
		Score:       50,
		CertLevel:   1,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(nil, nil, nil, nil, warning, logger)

	result := InitializeResult{
		ProtocolVersion: "2024-11-05",
		Instructions:    "Use this server to query data.",
	}
	resultBytes, _ := json.Marshal(result)
	msg := JSONRPCMessage{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: resultBytes}
	line, _ := json.Marshal(msg)

	modified, err := proxy.injectInstructions(line)
	require.NoError(t, err)

	var modMsg JSONRPCMessage
	require.NoError(t, json.Unmarshal(modified, &modMsg))
	var modResult InitializeResult
	require.NoError(t, json.Unmarshal(modMsg.Result, &modResult))

	assert.Contains(t, modResult.Instructions, "SECURITY WARNING")
	assert.Contains(t, modResult.Instructions, "Use this server to query data.")

	// Warning comes first
	warningIdx := strings.Index(modResult.Instructions, "SECURITY WARNING")
	origIdx := strings.Index(modResult.Instructions, "Use this server")
	assert.Less(t, warningIdx, origIdx)
}

func TestProxy_DetectsSandboxError(t *testing.T) {
	warning := &SecurityWarning{
		PackageName: "acme/test",
		Score:       85,
		CertLevel:   2,
		SandboxContext: &SandboxContext{
			Platform: "darwin",
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(nil, nil, nil, nil, warning, logger)

	// Build a JSON-RPC error response containing a sandbox error
	errMsg := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Error:   json.RawMessage(`{"code":-32000,"message":"[Errno 1] Operation not permitted: '/Users/cr0hn/.mcp_schrodinger'"}`),
	}
	errBytes, _ := json.Marshal(errMsg)

	notification := proxy.detectSandboxError(errBytes)
	require.NotNil(t, notification, "should detect sandbox error")

	// Verify the notification is valid JSON-RPC
	var notifMsg JSONRPCMessage
	require.NoError(t, json.Unmarshal(notification, &notifMsg))
	assert.Equal(t, "notifications/message", notifMsg.Method)

	var params NotificationParams
	require.NoError(t, json.Unmarshal(notifMsg.Params, &params))
	assert.Equal(t, "warning", params.Level)
	assert.Equal(t, "mcp-hub-sandbox", params.Logger)
	assert.Contains(t, params.Data, "SMCP SANDBOX ALERT")
	assert.Contains(t, params.Data, "--allow-write")
}

func TestProxy_DetectsSandboxError_PermissionDenied(t *testing.T) {
	warning := &SecurityWarning{
		PackageName: "acme/test",
		Score:       85,
		CertLevel:   2,
		SandboxContext: &SandboxContext{
			Platform: "linux",
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(nil, nil, nil, nil, warning, logger)

	errMsg := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Error:   json.RawMessage(`{"code":-32000,"message":"Permission denied: '/etc/secret'"}`),
	}
	errBytes, _ := json.Marshal(errMsg)

	notification := proxy.detectSandboxError(errBytes)
	require.NotNil(t, notification)

	var notifMsg JSONRPCMessage
	require.NoError(t, json.Unmarshal(notification, &notifMsg))
	var params NotificationParams
	require.NoError(t, json.Unmarshal(notifMsg.Params, &params))
	assert.Contains(t, params.Data, "/etc/secret")
}

func TestProxy_NoFalsePositives_NonJSON(t *testing.T) {
	warning := &SecurityWarning{
		PackageName: "acme/test",
		Score:       85,
		CertLevel:   2,
		SandboxContext: &SandboxContext{
			Platform: "darwin",
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(nil, nil, nil, nil, warning, logger)

	// Non-JSON line with sandbox error pattern should NOT trigger notification
	notification := proxy.detectSandboxError([]byte("Operation not permitted in some log"))
	assert.Nil(t, notification, "non-JSON should not trigger notification")
}

func TestProxy_NoFalsePositives_Request(t *testing.T) {
	warning := &SecurityWarning{
		PackageName: "acme/test",
		Score:       85,
		CertLevel:   2,
		SandboxContext: &SandboxContext{
			Platform: "darwin",
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(nil, nil, nil, nil, warning, logger)

	// JSON-RPC request (not response) with sandbox error pattern should NOT trigger
	reqMsg := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"test","args":{"text":"Operation not permitted"}}`),
	}
	reqBytes, _ := json.Marshal(reqMsg)
	notification := proxy.detectSandboxError(reqBytes)
	assert.Nil(t, notification, "request messages should not trigger notification")
}

func TestProxy_NoFalsePositives_NormalResponse(t *testing.T) {
	warning := &SecurityWarning{
		PackageName: "acme/test",
		Score:       85,
		CertLevel:   2,
		SandboxContext: &SandboxContext{
			Platform: "darwin",
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(nil, nil, nil, nil, warning, logger)

	// Normal success response should NOT trigger
	respMsg := JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  json.RawMessage(`{"content":[{"type":"text","text":"hello"}]}`),
	}
	respBytes, _ := json.Marshal(respMsg)
	notification := proxy.detectSandboxError(respBytes)
	assert.Nil(t, notification, "normal responses should not trigger notification")
}

func TestExtractPathFromError(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"single quoted path after not permitted",
			"[Errno 1] Operation not permitted: '/Users/cr0hn/.mcp_schrodinger'",
			"/Users/cr0hn/.mcp_schrodinger",
		},
		{
			"double quoted path after denied",
			`Permission denied: "/etc/secret"`,
			"/etc/secret",
		},
		{
			"single quoted path after denied",
			"Permission denied: '/var/data/config'",
			"/var/data/config",
		},
		{
			"no path present",
			"Operation not permitted",
			"",
		},
		{
			"empty string",
			"",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractPathFromError(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildSandboxSuggestion(t *testing.T) {
	t.Run("with blocked path", func(t *testing.T) {
		suggestion := buildSandboxSuggestion("/Users/test/.data", "Operation not permitted")
		assert.Contains(t, suggestion, "/Users/test/.data")
		assert.Contains(t, suggestion, "--allow-write")
	})

	t.Run("network error", func(t *testing.T) {
		suggestion := buildSandboxSuggestion("", "failed to connect to remote server")
		assert.Contains(t, suggestion, "--allow-net")
	})

	t.Run("generic error", func(t *testing.T) {
		suggestion := buildSandboxSuggestion("", "some generic error")
		assert.Contains(t, suggestion, "restricted resource")
	})
}

func TestBuildSandboxErrorNotification(t *testing.T) {
	notification := buildSandboxErrorNotification("Try --allow-write /tmp/test")

	assert.Equal(t, "2.0", notification.JSONRPC)
	assert.Equal(t, "notifications/message", notification.Method)
	assert.Empty(t, notification.ID)

	var params NotificationParams
	require.NoError(t, json.Unmarshal(notification.Params, &params))
	assert.Equal(t, "warning", params.Level)
	assert.Equal(t, "mcp-hub-sandbox", params.Logger)
	assert.Contains(t, params.Data, "SMCP SANDBOX ALERT")
	assert.Contains(t, params.Data, "Try --allow-write /tmp/test")
	assert.Contains(t, params.Data, "MUST inform the user")
}
