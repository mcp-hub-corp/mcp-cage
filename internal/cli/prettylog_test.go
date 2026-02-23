package cli

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrettyHandler_NonTerminalFormat(t *testing.T) {
	var buf bytes.Buffer
	h := NewPrettyHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})

	tests := []struct {
		name     string
		level    slog.Level
		msg      string
		contains string
	}{
		{"info", slog.LevelInfo, "test message", "[INFO] test message"},
		{"warn", slog.LevelWarn, "warning msg", "[WARN] warning msg"},
		{"error", slog.LevelError, "error msg", "[ERROR] error msg"},
		{"debug", slog.LevelDebug, "debug msg", "[DEBUG] debug msg"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			r := slog.NewRecord(time.Time{}, tt.level, tt.msg, 0)
			require.NoError(t, h.Handle(context.Background(), r))
			assert.Contains(t, buf.String(), tt.contains)
			// Non-terminal should NOT have ANSI codes
			assert.NotContains(t, buf.String(), "\033[")
		})
	}
}

func TestPrettyHandler_Attrs(t *testing.T) {
	var buf bytes.Buffer
	h := NewPrettyHandler(&buf, nil)

	r := slog.NewRecord(time.Time{}, slog.LevelInfo, "test", 0)
	r.AddAttrs(slog.String("key", "value"), slog.Int("count", 42))
	require.NoError(t, h.Handle(context.Background(), r))

	output := buf.String()
	assert.Contains(t, output, "key=value")
	assert.Contains(t, output, "count=42")
}

func TestPrettyHandler_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	h := NewPrettyHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})

	// INFO should be filtered
	assert.False(t, h.Enabled(context.Background(), slog.LevelInfo))
	// WARN should pass
	assert.True(t, h.Enabled(context.Background(), slog.LevelWarn))
	// ERROR should pass
	assert.True(t, h.Enabled(context.Background(), slog.LevelError))
}

func TestPrettyHandler_WithAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := NewPrettyHandler(&buf, nil)
	h2 := h.WithAttrs([]slog.Attr{slog.String("service", "mcp")})

	r := slog.NewRecord(time.Time{}, slog.LevelInfo, "test", 0)
	require.NoError(t, h2.Handle(context.Background(), r))

	assert.Contains(t, buf.String(), "service=mcp")
}
