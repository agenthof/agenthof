// Package obs builds the operational logger: the process-level diagnostic
// stream (stderr in the CLI), distinct from the run ledger (the audit
// record) and from command results (stdout). The slog.Handler inside the
// returned logger is the seam another binary can replace with its own
// exporter; this package offers only the stdlib text and JSON handlers.
package obs

import (
	"io"
	"log/slog"
)

// Format selects the handler encoding New wraps.
type Format int

const (
	// FormatText renders key=value lines (slog.NewTextHandler). The default.
	FormatText Format = iota
	// FormatJSON renders one JSON object per line (slog.NewJSONHandler).
	FormatJSON
)

// New builds the operational logger over w at level. Callers pass the writer
// they were handed (the CLI's stderr writer), never os.Stderr directly, so
// tests and in-process callers can capture or discard the stream. An
// unrecognised format falls back to text.
func New(w io.Writer, level slog.Level, format Format) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if format == FormatJSON {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// Discard returns a logger that drops every record: the default for library
// callers that inject no logger, and for tests.
func Discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// OrDiscard returns l, or Discard() when l is nil — the one nil-guard every
// injection point uses, so none of them can diverge.
func OrDiscard(l *slog.Logger) *slog.Logger {
	if l == nil {
		return Discard()
	}
	return l
}
