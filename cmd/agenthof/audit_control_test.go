package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuditControlMissingLogExitsOne covers the honest missing-log
// message: a control log that has never been written to must be reported
// plainly, not as a raw os.Open error, and the process must exit nonzero.
func TestAuditControlMissingLogExitsOne(t *testing.T) {
	controlLog := filepath.Join(t.TempDir(), "never-written.jsonl")

	var out bytes.Buffer
	code := cmdAuditControl([]string{"--control-log", controlLog}, &out)
	if code != 1 {
		t.Fatalf("exit = %d, want 1: %s", code, out.String())
	}
	want := "no control ledger at " + controlLog + " — nothing recorded yet\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

// TestAuditControlTornExitsOneWithRenderedPrefix covers the torn-chain
// path: cmdAuditControl must still render whatever valid prefix
// ReadVerify recovered, plus the integrity line naming the failure, and
// exit nonzero.
func TestAuditControlTornExitsOneWithRenderedPrefix(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	var applyOut bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &applyOut); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, applyOut.String())
	}

	// Append a torn tail: a line with no trailing newline (internal/ledger:
	// the final record must be newline-terminated to be complete).
	f, err := os.OpenFile(controlLog, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open control log to append torn tail: %v", err)
	}
	if _, err := f.WriteString(`{"v":"control/1","seq":2,"prev":""`); err != nil {
		t.Fatalf("write torn tail: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close control log: %v", err)
	}

	var out bytes.Buffer
	code := cmdAuditControl([]string{"--control-log", controlLog}, &out)
	if code != 1 {
		t.Fatalf("exit = %d, want 1: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "config applied") {
		t.Fatalf("torn render must still show the recovered valid prefix: %s", out.String())
	}
	if !strings.Contains(out.String(), "TORN — last record incomplete") {
		t.Fatalf("missing TORN integrity line: %s", out.String())
	}
}

// TestAuditControlCleanExitsZero covers the happy path end to end: apply
// followed by disable/enable produces a clean chain that audit control
// renders with the derived labels, invoker, and a "verified" integrity
// line, exiting 0.
func TestAuditControlCleanExitsZero(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	var buf bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, buf.String())
	}
	buf.Reset()
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 0 {
		t.Fatalf("disable: exit %d\n%s", code, buf.String())
	}
	buf.Reset()
	if code := cmdRegistry([]string{"enable", "coder", "--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 0 {
		t.Fatalf("enable: exit %d\n%s", code, buf.String())
	}

	var out bytes.Buffer
	code := cmdAuditControl([]string{"--control-log", controlLog}, &out)
	if code != 0 {
		t.Fatalf("exit = %d, want 0: %s", code, out.String())
	}
	for _, want := range []string{
		"config applied", "disabled agent coder", "enabled agent coder",
		"dana@example.com (asserted)",
		"control ledger integrity: verified (3 events)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, out.String())
		}
	}
}

// TestAuditControlShowsInstalledMatch: after an apply, audit control reports
// that the installed pointer names the last recorded apply.
func TestAuditControlShowsInstalledMatch(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	var buf bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &buf); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, buf.String())
	}
	var out bytes.Buffer
	if code := cmdAuditControl([]string{"--control-log", controlLog}, &out); code != 0 {
		t.Fatalf("exit = %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "config applied (bootstrap) — dana@example.com (asserted)") {
		t.Fatalf("bootstrap label missing: %s", out.String())
	}
	if !strings.HasSuffix(out.String(), "installed config: sha256:"+strings.TrimPrefix(readPointer(t, controlLog), "sha256:")+" — matches the last recorded apply\n") {
		t.Fatalf("installed line must follow the integrity line: %s", out.String())
	}
}

// TestAuditControlFlagsUnrecordedInstall: an install whose success append
// never landed (the crash hook) is visible — the pointer does not match the
// last recorded apply — and audit control still exits 0 (it renders).
func TestAuditControlFlagsUnrecordedInstall(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	args := []string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}
	var buf bytes.Buffer
	if code := cmdApply(args, &buf); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, buf.String())
	}
	if err := os.WriteFile(filepath.Join(root, "agents", "planner.yaml"), []byte("name: planner\nmodel: fast\ninstruction: plan harder\noutput: plan\nendpoint: http://127.0.0.1:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_install_before_append")
	buf.Reset()
	if code := cmdApply(args, &buf); code == 0 {
		t.Fatalf("crash hook must exit nonzero: %s", buf.String())
	}
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	var out bytes.Buffer
	if code := cmdAuditControl([]string{"--control-log", controlLog}, &out); code != 0 {
		t.Fatalf("exit = %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "does NOT match the last recorded apply") {
		t.Fatalf("mismatch not flagged: %s", out.String())
	}
}

// TestAuditControlNoStoreNoLine: a control root where nothing was ever
// installed (only a refused flip on record) prints no installed line.
func TestAuditControlNoStoreNoLine(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	var buf bytes.Buffer
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", controlLog, "--as", "mallory@example.com", "--groups", "finance"}, &buf); code != 1 {
		t.Fatalf("disable: exit %d\n%s", code, buf.String())
	}
	var out bytes.Buffer
	if code := cmdAuditControl([]string{"--control-log", controlLog}, &out); code != 0 {
		t.Fatalf("exit = %d: %s", code, out.String())
	}
	if strings.Contains(out.String(), "installed config:") {
		t.Fatalf("no store, no line: %s", out.String())
	}
}
