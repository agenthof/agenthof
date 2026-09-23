package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestInvestigateJSONEnvelope checks that `investigate --json` prints the
// investigate/1 JSON contract: valid JSON with the expected envelope
// version.
func TestInvestigateJSONEnvelope(t *testing.T) {
	root := writeSample(t)
	logs := t.TempDir()
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer

	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com"}, &out); code != 0 {
		t.Fatalf("apply: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com",
		"--config", root, "--log-dir", logs,
		"--artifact-dir", t.TempDir()}, &out); code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}

	out.Reset()
	code := cmdInvestigate([]string{"--log-dir", logs, "--control-log", ctl, "--json"}, &out)
	if code != 0 {
		t.Fatalf("investigate --json: want 0, got %d\n%s", code, out.String())
	}

	var env map[string]any
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("investigate --json did not produce valid JSON: %v\n%s", err, out.String())
	}
	if v, _ := env["v"].(string); v != "investigate/1" {
		t.Fatalf("want v=investigate/1, got %v\n%s", env["v"], out.String())
	}
}

// TestInvestigateAgentFilterNarrows checks that --agent coder narrows the
// timeline to coder's events only — a planner event must not appear. The run
// must succeed (both steps execute) before coder is disabled: a run against
// an already-disabled coder is refused outright (see TestApplyOKAndFailure)
// and never reaches the step events this test needs.
func TestInvestigateAgentFilterNarrows(t *testing.T) {
	root := writeSample(t)
	logs := t.TempDir()
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer

	if code := cmdApply([]string{"--config", root, "--control-log", ctl, "--as", "dana@example.com"}, &out); code != 0 {
		t.Fatalf("apply: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com",
		"--config", root, "--log-dir", logs,
		"--artifact-dir", t.TempDir()}, &out); code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := cmdRegistry([]string{"disable", "coder", "--config", root, "--control-log", ctl, "--as", "dana@example.com"}, &out); code != 0 {
		t.Fatalf("disable: %d\n%s", code, out.String())
	}

	out.Reset()
	code := cmdInvestigate([]string{"--log-dir", logs, "--control-log", ctl, "--agent", "coder"}, &out)
	if code != 0 {
		t.Fatalf("investigate --agent coder: want exit 0, got %d\n%s", code, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "agent=coder") {
		t.Fatalf("--agent coder must include coder's events:\n%s", got)
	}
	if strings.Contains(got, "agent=planner") {
		t.Fatalf("--agent coder must not include planner events:\n%s", got)
	}
}

// TestInvestigateRunFilterShowsRefusal checks that a run refused for an
// unknown role shows up under --run <id>.
func TestInvestigateRunFilterShowsRefusal(t *testing.T) {
	root := writeSample(t)
	logs := t.TempDir()
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer

	code := cmdRun([]string{"ghost", "fix-bug", "--input", "x", "--as", "dev@x",
		"--config", root, "--log-dir", logs}, &out)
	if code == 0 || !strings.Contains(out.String(), "refused") {
		t.Fatalf("expected a refused run, code=%d out=%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]+) refused`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no refused run id in: %s", out.String())
	}
	runID := m[1]

	out.Reset()
	code = cmdInvestigate([]string{"--log-dir", logs, "--control-log", ctl, "--run", runID}, &out)
	if code != 0 {
		t.Fatalf("investigate --run <refused-run>: want exit 0, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "run_refused") {
		t.Fatalf("investigate --run %s must show the refusal:\n%s", runID, out.String())
	}
}

// TestInvestigateOutcomeFilterShowsRefusal checks that a run refused for an
// unknown role shows up under --outcome refused (normalizeRun maps a
// run_refused event's Outcome to "refused").
func TestInvestigateOutcomeFilterShowsRefusal(t *testing.T) {
	root := writeSample(t)
	logs := t.TempDir()
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer

	code := cmdRun([]string{"ghost", "fix-bug", "--input", "x", "--as", "dev@x",
		"--config", root, "--log-dir", logs}, &out)
	if code == 0 || !strings.Contains(out.String(), "refused") {
		t.Fatalf("expected a refused run, code=%d out=%s", code, out.String())
	}

	out.Reset()
	code = cmdInvestigate([]string{"--log-dir", logs, "--control-log", ctl, "--outcome", "refused"}, &out)
	if code != 0 {
		t.Fatalf("investigate --outcome refused: want exit 0, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "run_refused") {
		t.Fatalf("investigate --outcome refused must show the refusal:\n%s", out.String())
	}
}

// TestInvestigateCorruptedRunLogExitsNonZero checks that a torn run log
// makes `investigate` exit nonzero and, under --json, report
// integrity.ok == false.
func TestInvestigateCorruptedRunLogExitsNonZero(t *testing.T) {
	root := writeSample(t)
	logs := t.TempDir()
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer

	if code := cmdRun([]string{"software-engineer", "fix-bug", "--input", "x", "--as", "dana@example.com",
		"--config", root, "--log-dir", logs,
		"--artifact-dir", t.TempDir()}, &out); code != 0 {
		t.Fatalf("run: %d\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]+) finished`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no run id in: %s", out.String())
	}
	id := m[1]

	// Truncate the run log mid-line: a torn tail, like
	// TestAuditTornExitsOne in main_test.go.
	path := filepath.Join(logs, id+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("{torn")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	code := cmdInvestigate([]string{"--log-dir", logs, "--control-log", ctl}, &out)
	if code == 0 {
		t.Fatalf("a torn run log must exit nonzero, got 0:\n%s", out.String())
	}

	out.Reset()
	code = cmdInvestigate([]string{"--log-dir", logs, "--control-log", ctl, "--json"}, &out)
	if code == 0 {
		t.Fatalf("--json must not change the exit code, got 0:\n%s", out.String())
	}
	var env struct {
		Integrity struct {
			OK bool `json:"ok"`
		} `json:"integrity"`
	}
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("investigate --json did not produce valid JSON: %v\n%s", err, out.String())
	}
	if env.Integrity.OK {
		t.Fatalf("integrity.ok must be false for a torn source:\n%s", out.String())
	}
}

// TestInvestigateBadSinceExitsUsageError checks that a --since value that is
// neither a valid duration nor an RFC3339 timestamp is a usage error (exit
// 2), not a silent no-op filter.
func TestInvestigateBadSinceExitsUsageError(t *testing.T) {
	logs := t.TempDir()
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	var out bytes.Buffer
	code := cmdInvestigate([]string{"--log-dir", logs, "--control-log", ctl, "--since", "not-a-time"}, &out)
	if code != 2 {
		t.Fatalf("bad --since must exit 2, got %d\n%s", code, out.String())
	}
}
