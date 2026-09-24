package main

import (
	"bytes"
	"path/filepath"
	"regexp"
	"testing"
)

// TestAuditRunConfigJoinShowsApply covers spec §2: `audit <run-id>` prints an
// extra config-join line naming the apply that put the config the run
// executed under, when the control ledger has a matching successful apply
// at or before the run's workflow_started time.
func TestAuditRunConfigJoinShowsApply(t *testing.T) {
	root := writeSample(t)
	logs := t.TempDir()
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer

	// apply FIRST so the apply's time precedes the run's workflow_started
	// time (spec §2 requires apply.Time <= run.Time).
	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com"}, &out); code != 0 {
		t.Fatalf("apply: %d\n%s", code, out.String())
	}
	out.Reset()

	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com", "--config", root, "--log-dir", logs, "--artifact-dir", t.TempDir()}, &out); code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]+) finished`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("could not find run id in output: %s", out.String())
	}
	runID := m[1]
	out.Reset()

	code := cmdAudit([]string{runID, "--log-dir", logs, "--control-log", controlLog}, &out)
	if code != 0 {
		t.Fatalf("audit: %d\n%s", code, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("config sha256:")) {
		t.Fatalf("expected config join line with a config hash, got: %s", out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("applied by dana@example.com")) {
		t.Fatalf("expected config join line naming the applier, got: %s", out.String())
	}
}

// TestAuditRunConfigJoinNoRegressionWhenControlMissing covers spec §2's
// no-regression rule: a missing/unavailable control ledger must never
// change `audit <run-id>`'s exit code, even though the join line still
// reports the ledger as unavailable.
func TestAuditRunConfigJoinNoRegressionWhenControlMissing(t *testing.T) {
	root := writeSample(t)
	logs := t.TempDir()
	controlLog := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer

	if code := cmdApply([]string{"--config", root, "--control-log", controlLog, "--as", "dana@example.com"}, &out); code != 0 {
		t.Fatalf("apply: %d\n%s", code, out.String())
	}
	out.Reset()

	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com", "--config", root, "--log-dir", logs, "--artifact-dir", t.TempDir()}, &out); code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]+) finished`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("could not find run id in output: %s", out.String())
	}
	runID := m[1]
	out.Reset()

	// Point at a control-log path that was never written (missing ledger).
	missingControlLog := filepath.Join(t.TempDir(), "control.jsonl")
	code := cmdAudit([]string{runID, "--log-dir", logs, "--control-log", missingControlLog}, &out)
	if code != 0 {
		t.Fatalf("exit code must be unchanged by control-log health, got %d\n%s", code, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("control ledger unavailable")) {
		t.Fatalf("expected control-ledger-unavailable wording, got: %s", out.String())
	}
}
