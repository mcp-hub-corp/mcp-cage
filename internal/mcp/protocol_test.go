package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMessage_Request(t *testing.T) {
	data := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`
	msg, err := ParseMessage([]byte(data))
	require.NoError(t, err)
	assert.Equal(t, "2.0", msg.JSONRPC)
	assert.Equal(t, "initialize", msg.Method)
	assert.True(t, msg.IsRequest())
	assert.False(t, msg.IsResponse())
	assert.False(t, msg.IsNotification())
}

func TestParseMessage_Response(t *testing.T) {
	data := `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{}}}`
	msg, err := ParseMessage([]byte(data))
	require.NoError(t, err)
	assert.True(t, msg.IsResponse())
	assert.False(t, msg.IsRequest())
	assert.False(t, msg.IsNotification())
}

func TestParseMessage_Notification(t *testing.T) {
	data := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	msg, err := ParseMessage([]byte(data))
	require.NoError(t, err)
	assert.True(t, msg.IsNotification())
	assert.False(t, msg.IsRequest())
	assert.False(t, msg.IsResponse())
}

func TestParseMessage_MalformedJSON(t *testing.T) {
	_, err := ParseMessage([]byte("not json"))
	assert.Error(t, err)
}

func TestParseMessage_EmptyObject(t *testing.T) {
	msg, err := ParseMessage([]byte("{}"))
	require.NoError(t, err)
	assert.False(t, msg.IsRequest())
	assert.False(t, msg.IsResponse())
	assert.False(t, msg.IsNotification())
}

func TestIDsMatch(t *testing.T) {
	tests := []struct {
		name  string
		a, b  json.RawMessage
		match bool
	}{
		{"same integer", json.RawMessage("1"), json.RawMessage("1"), true},
		{"different integer", json.RawMessage("1"), json.RawMessage("2"), false},
		{"same string", json.RawMessage(`"abc"`), json.RawMessage(`"abc"`), true},
		{"different string", json.RawMessage(`"abc"`), json.RawMessage(`"def"`), false},
		{"empty a", nil, json.RawMessage("1"), false},
		{"empty b", json.RawMessage("1"), nil, false},
		{"both empty", nil, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.match, IDsMatch(tt.a, tt.b))
		})
	}
}

func TestParseMessage_StringID(t *testing.T) {
	data := `{"jsonrpc":"2.0","id":"req-1","method":"tools/list"}`
	msg, err := ParseMessage([]byte(data))
	require.NoError(t, err)
	assert.True(t, msg.IsRequest())
	assert.Equal(t, "tools/list", msg.Method)
	assert.Equal(t, `"req-1"`, string(msg.ID))
}

func TestParseMessage_ErrorResponse(t *testing.T) {
	data := `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}`
	msg, err := ParseMessage([]byte(data))
	require.NoError(t, err)
	assert.True(t, msg.IsResponse())
	assert.False(t, msg.IsRequest())
}
