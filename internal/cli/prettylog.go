package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"

	"golang.org/x/term"
)

// ANSI color codes
const (
	ansiReset  = "\033[0m"
	ansiDim    = "\033[2m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
)

// PrettyHandler is a slog.Handler that formats log output for CLI use.
// In terminal mode, it uses colors and icons. In non-terminal mode (piped),
// it uses plain text with level prefixes.
type PrettyHandler struct {
	w          io.Writer
	level      slog.Leveler
	attrs      []slog.Attr
	group      string
	mu         sync.Mutex
	isTerminal bool
}

// NewPrettyHandler creates a handler for human-friendly CLI output.
func NewPrettyHandler(w io.Writer, opts *slog.HandlerOptions) *PrettyHandler {
	h := &PrettyHandler{w: w}
	if opts != nil && opts.Level != nil {
		h.level = opts.Level
	} else {
		h.level = slog.LevelInfo
	}
	// Detect if output is a terminal
	if f, ok := w.(*os.File); ok {
		h.isTerminal = term.IsTerminal(int(f.Fd()))
	}
	return h
}

func (h *PrettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *PrettyHandler) Handle(_ context.Context, r slog.Record) error {
	var buf bytes.Buffer

	if h.isTerminal {
		// Terminal format with icons and colors
		switch {
		case r.Level >= slog.LevelError:
			fmt.Fprintf(&buf, "%s✗ %s", ansiRed, r.Message)
		case r.Level >= slog.LevelWarn:
			fmt.Fprintf(&buf, "%s⚠ %s", ansiYellow, r.Message)
		case r.Level <= slog.LevelDebug:
			fmt.Fprintf(&buf, "%s  %s", ansiDim, r.Message)
		default: // INFO
			fmt.Fprintf(&buf, "  %s", r.Message)
		}

		// Add pre-set attrs
		for _, a := range h.attrs {
			fmt.Fprintf(&buf, "  %s%s=%s%s", ansiDim, h.attrKey(a.Key), a.Value.String(), ansiReset)
		}

		// Add record attrs
		r.Attrs(func(a slog.Attr) bool {
			fmt.Fprintf(&buf, "  %s%s=%s%s", ansiDim, h.attrKey(a.Key), a.Value.String(), ansiReset)
			return true
		})

		buf.WriteString(ansiReset)
	} else {
		// Non-terminal: plain text with level prefix
		levelStr := r.Level.String()
		fmt.Fprintf(&buf, "[%s] %s", levelStr, r.Message)

		for _, a := range h.attrs {
			fmt.Fprintf(&buf, "  %s=%s", h.attrKey(a.Key), a.Value.String())
		}

		r.Attrs(func(a slog.Attr) bool {
			fmt.Fprintf(&buf, "  %s=%s", h.attrKey(a.Key), a.Value.String())
			return true
		})
	}

	buf.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(buf.Bytes())
	return err
}

func (h *PrettyHandler) attrKey(key string) string {
	if h.group != "" {
		return h.group + "." + key
	}
	return key
}

func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &PrettyHandler{
		w: h.w, level: h.level, attrs: newAttrs,
		group: h.group, isTerminal: h.isTerminal,
	}
}

func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	newGroup := name
	if h.group != "" {
		newGroup = h.group + "." + name
	}
	return &PrettyHandler{
		w: h.w, level: h.level, attrs: h.attrs,
		group: newGroup, isTerminal: h.isTerminal,
	}
}
