package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/obs"
)

func noEnv(string) string { return "" }

func TestResolveLogConfigDefaults(t *testing.T) {
	level, format, err := resolveLogConfig("", "", noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if level != slog.LevelInfo || format != obs.FormatText {
		t.Fatalf("level=%v format=%v, want info/text", level, format)
	}
}

func TestResolveLogConfigEnvFallback(t *testing.T) {
	env := map[string]string{envLogLevel: "debug", envLogFormat: "json"}
	level, format, err := resolveLogConfig("", "", func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if level != slog.LevelDebug || format != obs.FormatJSON {
		t.Fatalf("level=%v format=%v, want debug/json from env", level, format)
	}
}

func TestResolveLogConfigFlagBeatsEnv(t *testing.T) {
	env := map[string]string{envLogLevel: "debug", envLogFormat: "json"}
	level, format, err := resolveLogConfig("error", "text", func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if level != slog.LevelError || format != obs.FormatText {
		t.Fatalf("level=%v format=%v, want the flag values error/text over env", level, format)
	}
}

func TestResolveLogConfigAcceptsAllLevelsCaseInsensitively(t *testing.T) {
	want := map[string]slog.Level{"debug": slog.LevelDebug, "INFO": slog.LevelInfo, "Warn": slog.LevelWarn, "error": slog.LevelError}
	for in, lvl := range want {
		level, _, err := resolveLogConfig(in, "", noEnv)
		if err != nil || level != lvl {
			t.Errorf("%q: level=%v err=%v, want %v", in, level, err, lvl)
		}
	}
}

func TestResolveLogConfigRejectsUnknownValues(t *testing.T) {
	cases := []struct{ level, format string }{
		{"loud", ""}, {"warning", ""}, {"", "yaml"}, {"", "JSONL"},
	}
	for _, c := range cases {
		if _, _, err := resolveLogConfig(c.level, c.format, noEnv); err == nil {
			t.Errorf("level=%q format=%q: want an error", c.level, c.format)
		}
	}
	// An unknown value from the environment is rejected the same way.
	env := map[string]string{envLogLevel: "loud"}
	if _, _, err := resolveLogConfig("", "", func(k string) string { return env[k] }); err == nil {
		t.Error("an invalid AGENTHOF_LOG_LEVEL must be rejected, not silently defaulted")
	}
}

func TestRunRejectsInvalidLogLevelToStdout(t *testing.T) {
	t.Chdir(t.TempDir())
	root := writeSample(t)
	var out, errBuf bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com",
		"--config", root, "--log-dir", t.TempDir(), "--log-level", "loud"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (usage error)\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), `invalid log level "loud"`) {
		t.Fatalf("stdout must name the bad value:\n%s", out.String())
	}
	if errBuf.Len() != 0 {
		t.Fatalf("usage errors go to stdout like every other usage error; stderr got:\n%s", errBuf.String())
	}
}

func TestRunLogsToStderrNotStdout(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(envLogLevel, "")
	t.Setenv(envLogFormat, "")
	root := writeSample(t)
	var out, errBuf bytes.Buffer
	code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com",
		"--config", root, "--log-dir", t.TempDir(), "--artifact-dir", t.TempDir(),
		"--log-level", "debug", "--log-format", "json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("run: %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "finished: succeeded") {
		t.Fatalf("stdout must still carry the result line:\n%s", out.String())
	}
	if strings.Contains(out.String(), `"level"`) {
		t.Fatalf("stdout must not carry log lines:\n%s", out.String())
	}
	sawInvoked := false
	for _, line := range strings.Split(strings.TrimSpace(errBuf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("stderr line is not JSON: %v\n%s", err, line)
		}
		if rec["msg"] == "run invoked" {
			sawInvoked = true
			if rec["role"] != "software-engineer" || rec["workflow"] != "fix-bug" {
				t.Fatalf("run invoked must carry role and workflow: %v", rec)
			}
		}
	}
	if !sawInvoked {
		t.Fatalf("stderr must carry the Debug 'run invoked' line at --log-level debug:\n%s", errBuf.String())
	}
}

func TestRunFlagOverridesEnvLogLevel(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv(envLogLevel, "debug")
	t.Setenv(envLogFormat, "")
	root := writeSample(t)
	base := []string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com",
		"--config", root, "--log-dir", t.TempDir(), "--artifact-dir", t.TempDir()}

	var out, errBuf bytes.Buffer
	if code := cmdRun(append(append([]string{}, base...), "--log-level", "error"), &out, &errBuf); code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	if errBuf.Len() != 0 {
		t.Fatalf("--log-level error must win over AGENTHOF_LOG_LEVEL=debug; stderr got:\n%s", errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := cmdRun(base, &out, &errBuf); code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	if !strings.Contains(errBuf.String(), "run invoked") {
		t.Fatalf("AGENTHOF_LOG_LEVEL=debug alone must enable the Debug line; stderr got:\n%s", errBuf.String())
	}
}
