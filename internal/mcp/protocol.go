package mcp

import "encoding/json"

// JSONRPCMessage represents a JSON-RPC 2.0 message used in MCP protocol.
// Fields use json.RawMessage for lazy parsing — only the fields needed
// during the init handshake are fully decoded.
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// IsRequest returns true if the message is a JSON-RPC request (has method and id).
func (m *JSONRPCMessage) IsRequest() bool {
	return m.Method != "" && len(m.ID) > 0
}

// IsResponse returns true if the message is a JSON-RPC response (has result or error, and id).
func (m *JSONRPCMessage) IsResponse() bool {
	return (len(m.Result) > 0 || len(m.Error) > 0) && len(m.ID) > 0
}

// IsNotification returns true if the message is a JSON-RPC notification (has method, no id).
func (m *JSONRPCMessage) IsNotification() bool {
	return m.Method != "" && len(m.ID) == 0
}

// InitializeResult represents the result of an MCP initialize response.
// Only the fields we need to inspect/modify are fully typed.
type InitializeResult struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    json.RawMessage `json:"capabilities,omitempty"`
	ServerInfo      json.RawMessage `json:"serverInfo,omitempty"`
	Instructions    string          `json:"instructions,omitempty"`
}

// Content represents a content item in an MCP tool result.
type Content struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// CallToolResult represents the result of a tool execution.
type CallToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// JSONRPCError represents a JSON-RPC error object.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// NotificationParams represents the params for a notifications/message notification.
type NotificationParams struct {
	Level  string `json:"level"`
	Logger string `json:"logger,omitempty"`
	Data   string `json:"data"`
}

// ParseMessage parses a JSON line into a JSONRPCMessage.
// Returns an error if the JSON is malformed.
func ParseMessage(data []byte) (*JSONRPCMessage, error) {
	var msg JSONRPCMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// IDsMatch returns true if two JSON-RPC IDs are equal (byte comparison).
func IDsMatch(a, b json.RawMessage) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return string(a) == string(b)
}
