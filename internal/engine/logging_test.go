package engine

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/obs"
)

func TestRunNilLoggerDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	ex := &fakeExec{fail: map[string]int{}}
	res, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), ex, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err != nil || res.Status != "succeeded" {
		t.Fatalf("status=%q err=%v", res.Status, err)
	}
}

func TestRunLifecycleIsDebugOnly(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	ex := &fakeExec{fail: map[string]int{}}
	opts := Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), Logger: obs.New(&buf, slog.LevelInfo, obs.FormatText)}
	if res, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x", identity.Static("dev@x"), ex, opts); err != nil || res.Status != "succeeded" {
		t.Fatalf("status=%q err=%v", res.Status, err)
	}
	if buf.Len() != 0 {
		t.Fatalf("a clean run must log nothing at Info (stdout already prints the result):\n%s", buf.String())
	}

	buf.Reset()
	opts.Logger = obs.New(&buf, slog.LevelDebug, obs.FormatText)
	ex = &fakeExec{fail: map[string]int{}}
	res, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x", identity.Static("dev@x"), ex, opts)
	if err != nil || res.Status != "succeeded" {
		t.Fatalf("status=%q err=%v", res.Status, err)
	}
	out := buf.String()
	for _, want := range []string{"run started", "step started", "step succeeded", "run finished", "run=" + res.RunID, "role=se", "workflow=fix-bug", "step=plan", "agent=planner", "status=succeeded"} {
		if !strings.Contains(out, want) {
			t.Errorf("Debug log missing %q:\n%s", want, out)
		}
	}
}

func TestRunBounceAndFailureAreWarn(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	// reviewer fails every time; MaxBounces is 1 for the review step, so the
	// run bounces back to code once and then fails.
	ex := &fakeExec{fail: map[string]int{"reviewer": 10}}
	opts := Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), Logger: obs.New(&buf, slog.LevelWarn, obs.FormatText)}
	res, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x", identity.Static("dev@x"), ex, opts)
	if err != nil || res.Status != "failed" {
		t.Fatalf("status=%q err=%v", res.Status, err)
	}
	out := buf.String()
	for _, want := range []string{"level=WARN msg=\"step failed\"", "step=review", "agent=reviewer", "step bounced back", "target=code", "run failed", "reason=\"bounces exhausted\""} {
		if !strings.Contains(out, want) {
			t.Errorf("Warn log missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "synthetic failure") {
		t.Fatalf("the executor's failure text belongs in the ledger, not the operational log:\n%s", out)
	}
}

func TestRunRefusedIsWarn(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	opts := Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), Logger: obs.New(&buf, slog.LevelWarn, obs.FormatText)}
	res, err := Run(context.Background(), engCfg(), "ghost", "fix-bug", "x", identity.Static("dev@x"), &fakeExec{}, opts)
	if err == nil || res.Status != "refused" {
		t.Fatalf("status=%q err=%v, want refused", res.Status, err)
	}
	if !strings.Contains(buf.String(), "run refused") || !strings.Contains(buf.String(), "role=ghost") {
		t.Fatalf("Warn log missing the refusal:\n%s", buf.String())
	}
}
