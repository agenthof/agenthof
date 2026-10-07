package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
)

// TestAuditVerifyControlCleanExitsZero covers the happy path: a clean
// control ledger (produced by apply) verifies with exit 0 and prints the
// control head line.
func TestAuditVerifyControlCleanExitsZero(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	var applyOut bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &applyOut); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, applyOut.String())
	}

	var out bytes.Buffer
	code := cmdAuditVerify([]string{"control", "--control-log", controlLog}, &out)
	if code != 0 {
		t.Fatalf("exit = %d, want 0: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "control head: seq=1 sha256=") {
		t.Fatalf("missing control head line: %s", out.String())
	}
}

// TestAuditVerifyControlExpectHeadMatchExitsZero covers a matching
// --expect-head: it must not change the clean exit code.
func TestAuditVerifyControlExpectHeadMatchExitsZero(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	var applyOut bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &applyOut); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, applyOut.String())
	}

	var headOut bytes.Buffer
	if code := cmdAuditVerify([]string{"control", "--control-log", controlLog}, &headOut); code != 0 {
		t.Fatalf("exit = %d, want 0: %s", code, headOut.String())
	}
	line := headOut.String()
	const prefix = "control head: seq=1 sha256="
	idx := strings.Index(line, prefix)
	if idx == -1 {
		t.Fatalf("missing control head line: %s", line)
	}
	rest := line[idx+len(prefix):]
	if nl := strings.IndexByte(rest, '\n'); nl != -1 {
		rest = rest[:nl]
	}
	hash := strings.TrimSpace(rest)

	var out bytes.Buffer
	code := cmdAuditVerify([]string{"control", "--control-log", controlLog, "--expect-head", hash}, &out)
	if code != 0 {
		t.Fatalf("exit = %d, want 0: %s", code, out.String())
	}
}

// TestAuditVerifyControlExpectHeadMismatchExitsFour covers a mismatched
// --expect-head against an otherwise-clean chain: exit 4.
func TestAuditVerifyControlExpectHeadMismatchExitsFour(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	root := writeSample(t)
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	var applyOut bytes.Buffer
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com", "--groups", "platform-eng"}, &applyOut); code != 0 {
		t.Fatalf("apply: exit %d\n%s", code, applyOut.String())
	}

	var out bytes.Buffer
	code := cmdAuditVerify([]string{"control", "--control-log", controlLog, "--expect-head", "deadbeef"}, &out)
	if code != 4 {
		t.Fatalf("exit = %d, want 4: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "expect-head mismatch") {
		t.Fatalf("missing expect-head mismatch message: %s", out.String())
	}
}

// TestAuditVerifyControlMissingLogExitsOne covers a control log that has
// never been written to: reported plainly, exit 1.
func TestAuditVerifyControlMissingLogExitsOne(t *testing.T) {
	controlLog := filepath.Join(t.TempDir(), "never-written.jsonl")

	var out bytes.Buffer
	code := cmdAuditVerify([]string{"control", "--control-log", controlLog}, &out)
	if code != 1 {
		t.Fatalf("exit = %d, want 1: %s", code, out.String())
	}
	want := "no control ledger at " + controlLog + " — nothing recorded yet\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

// TestAuditVerifyControlTornExitsOne covers a torn control log: exit 1,
// regardless of taint (torn/broken takes precedence in the checked
// order, and there is no repair record here anyway).
func TestAuditVerifyControlTornExitsOne(t *testing.T) {
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	const torn = `{"v":"control/1","seq":1,"prev":""`
	if err := os.WriteFile(controlLog, []byte(torn), 0o644); err != nil {
		t.Fatalf("seed torn control log: %v", err)
	}

	var out bytes.Buffer
	code := cmdAuditVerify([]string{"control", "--control-log", controlLog}, &out)
	if code != 1 {
		t.Fatalf("exit = %d, want 1: %s", code, out.String())
	}
}

// TestAuditVerifyControlTaintedExitsThree covers the taint verdict: a
// control log carrying a "repair" record (appended directly with
// control.Append so the chain is otherwise clean, isolating the taint
// check from the torn-tail recovery of `audit repair control`) must
// verify but exit 3, taking precedence over any --expect-head check.
func TestAuditVerifyControlTaintedExitsThree(t *testing.T) {
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")

	inv := identity.Invoker{Subject: "dana@example.com", Issuer: "static", Method: "static"}
	if _, err := control.Append(controlLog, control.Event{
		Action:  "apply",
		Outcome: "success",
		Invoker: inv,
		Witness: control.CaptureWitness(),
	}); err != nil {
		t.Fatalf("append apply event: %v", err)
	}
	if _, err := control.Append(controlLog, control.Event{
		Action:  "repair",
		Outcome: "success",
		Invoker: inv,
		Witness: control.CaptureWitness(),
	}); err != nil {
		t.Fatalf("append repair event: %v", err)
	}

	var out bytes.Buffer
	code := cmdAuditVerify([]string{"control", "--control-log", controlLog}, &out)
	if code != 3 {
		t.Fatalf("exit = %d, want 3: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "control head: seq=2 sha256=") {
		t.Fatalf("missing control head line: %s", out.String())
	}

	// Taint must take precedence over an expect-head mismatch.
	out.Reset()
	code = cmdAuditVerify([]string{"control", "--control-log", controlLog, "--expect-head", "deadbeef"}, &out)
	if code != 3 {
		t.Fatalf("exit = %d, want 3 (taint precedes expect-head mismatch): %s", code, out.String())
	}
}

// TestAuditVerifyControlUnrecordedInstallExitsFive: the installed pointer
// not matching the last recorded apply is its own, lowest-precedence exit
// code, printed after the head line.
func TestAuditVerifyControlUnrecordedInstallExitsFive(t *testing.T) {
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
	_ = cmdApply(args, &buf)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	var out bytes.Buffer
	code := cmdAuditVerify([]string{"control", "--control-log", controlLog}, &out)
	if code != exitInstalledMismatch {
		t.Fatalf("exit = %d, want %d: %s", code, exitInstalledMismatch, out.String())
	}
	if !strings.Contains(out.String(), "control head: seq=1 sha256=") || !strings.Contains(out.String(), "does NOT match the last recorded apply") {
		t.Fatalf("output: %s", out.String())
	}
}

// TestAuditVerifyControlFlipAfterApplyIsNotAMismatch: the kill switch rewrites
// the config directory and records the directory's new hash; that must never
// read as an unrecorded install — only apply records are compared.
func TestAuditVerifyControlFlipAfterApplyIsNotAMismatch(t *testing.T) {
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
	var out bytes.Buffer
	if code := cmdAuditVerify([]string{"control", "--control-log", controlLog}, &out); code != 0 {
		t.Fatalf("exit = %d, want 0: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "matches the last recorded apply") {
		t.Fatalf("output: %s", out.String())
	}
}

// TestAuditVerifyControlTaintPrecedesInstalledMismatch: the installed
// verdict is the lowest-precedence check — a tainted chain still exits 3.
func TestAuditVerifyControlTaintPrecedesInstalledMismatch(t *testing.T) {
	t.Setenv("AGENTHOF_TOKEN", "")
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	inv := identity.Static("dana@example.com")
	if _, err := control.Append(controlLog, control.Event{Action: "repair", Outcome: "success", Invoker: inv, Witness: control.CaptureWitness(), FragmentLen: 1, FragmentSHA: "ab"}); err != nil {
		t.Fatal(err)
	}
	store := installedStore(controlLog)
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "current"), []byte("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := cmdAuditVerify([]string{"control", "--control-log", controlLog}, &out); code != 3 {
		t.Fatalf("exit = %d, want 3 (taint first): %s", code, out.String())
	}
	if !strings.Contains(out.String(), "no successful apply on record") {
		t.Fatalf("the installed line is still printed: %s", out.String())
	}
}
