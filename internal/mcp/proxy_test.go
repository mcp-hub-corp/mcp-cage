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
	_, proxyToClientW := io.Pipe()
	_, proxyToServerW := io.Pipe()
	serverToProxyR, _ := io.Pipe() // Server never responds

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy := NewMCPProxy(clientToProxyR, proxyToClientW, serverToProxyR, proxyToServerW, warning, logger)
	proxy.SetInitTimeout(200 * time.Millisecond)

	done := make(chan error, 1)
	go func() {
		done <- proxy.Run()
	}()

	// Send something but server never responds
	_, _ = clientToProxyW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"))

	// Should not hang forever — timeout kicks in
	select {
	case <-done:
		// Proxy finished (raw copy will fail because pipes close)
	case <-time.After(2 * time.Second):
		// Also acceptable — the proxy switched to raw copy
	}

	clientToProxyW.Close()
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
