package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewTextFiltersBelowLevel(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, slog.LevelInfo, FormatText)
	l.Debug("hidden", "k", "v")
	l.Info("shown", "run", "r-1")
	out := buf.String()
	if strings.Contains(out, "hidden") {
		t.Fatalf("a Debug record must be dropped at Info:\n%s", out)
	}
	if !strings.Contains(out, "msg=shown") || !strings.Contains(out, "run=r-1") {
		t.Fatalf("text handler must render msg and attrs as key=value:\n%s", out)
	}
}

func TestNewJSONEmitsOneObjectPerLine(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, slog.LevelDebug, FormatJSON)
	l.Debug("shown", "run", "r-1")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("JSON handler output is not one JSON object: %v\n%s", err, buf.String())
	}
	if rec["msg"] != "shown" || rec["run"] != "r-1" || rec["level"] != "DEBUG" {
		t.Fatalf("record = %v, want msg=shown run=r-1 level=DEBUG", rec)
	}
}

func TestNewDefaultsToTextForUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, slog.LevelInfo, Format(99))
	l.Info("x")
	if !strings.HasPrefix(buf.String(), "time=") {
		t.Fatalf("an out-of-range Format must fall back to text, got:\n%s", buf.String())
	}
}

func TestDiscardDropsEverything(t *testing.T) {
	l := Discard()
	if l.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("Discard logger must report Enabled == false at every level")
	}
	l.Error("dropped", "k", "v") // must not panic
}

func TestOrDiscardNilToDiscard(t *testing.T) {
	got := OrDiscard(nil)
	if got == nil {
		t.Fatal("OrDiscard(nil) must return a usable logger, not nil")
	}
	if got.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("OrDiscard(nil) must discard")
	}
	got.Error("dropped") // must not panic

	var buf bytes.Buffer
	l := New(&buf, slog.LevelInfo, FormatText)
	if OrDiscard(l) != l {
		t.Fatal("OrDiscard must return a non-nil logger unchanged")
	}
}
