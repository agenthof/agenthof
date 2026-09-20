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
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com"}, &applyOut); code != 0 {
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
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com"}, &applyOut); code != 0 {
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
	hash := strings.TrimSpace(line[idx+len(prefix):])

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
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com"}, &applyOut); code != 0 {
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
// control log carrying a "repair" record (built directly with
// control.Append, since Task 10's `audit repair control` is not built
// yet) must verify (chain is otherwise clean) but exit 3, taking
// precedence over any --expect-head check.
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
