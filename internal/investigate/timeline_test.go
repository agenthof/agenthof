package investigate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
)

// writeRun creates a fresh run log at <dir>/<runID>.jsonl containing events,
// using the real ledger-backed writer (engine.OpenLog/Append) so the file is
// a genuine chained log, not a hand-rolled fixture.
func writeRun(t *testing.T, dir, runID string, events []engine.Event) {
	t.Helper()
	log, err := engine.OpenLog(dir, runID)
	if err != nil {
		t.Fatalf("OpenLog(%s): %v", runID, err)
	}
	for _, e := range events {
		if err := log.Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestTimelineMergeDeterministic proves the merge sorts on RunID, not on
// file-enumeration order: two DIFFERENT runs share an identical Time and
// identical line index (pos), so only RunID can break the tie. The file
// names ("r-0a", "r-0b") are deliberately ordered the OPPOSITE of their
// Binding.RunID values ("r-zz", "r-aa") — os.ReadDir visits files
// alphabetically, so if the merge ever dropped the RunID tiebreak and fell
// back to insertion order, this test would observe r-zz before r-aa and
// fail. It runs the query several times to demonstrate the order is
// reproducible, not incidental.
func TestTimelineMergeDeterministic(t *testing.T) {
	dir := t.TempDir()
	tm := time.Now().Add(-48 * time.Hour)

	writeRun(t, dir, "r-0a", []engine.Event{
		{Time: tm, Type: "workflow_started", Binding: engine.Binding{RunID: "r-zz", Invoker: identity.Static("dana@example.com")}},
	})
	writeRun(t, dir, "r-0b", []engine.Event{
		{Time: tm, Type: "workflow_started", Binding: engine.Binding{RunID: "r-aa", Invoker: identity.Static("dana@example.com")}},
	})
	missingControl := filepath.Join(t.TempDir(), "control.jsonl")

	for i := 0; i < 3; i++ {
		res, err := Timeline(dir, missingControl, Filter{})
		if err != nil {
			t.Fatalf("run %d: Timeline: %v", i, err)
		}
		if len(res.Events) != 2 {
			t.Fatalf("run %d: want 2 events, got %d: %+v", i, len(res.Events), res.Events)
		}
		if res.Events[0].RunID != "r-aa" || res.Events[1].RunID != "r-zz" {
			t.Fatalf("run %d: order = %s, %s; want r-aa, r-zz (sorted by RunID, not file enumeration order)",
				i, res.Events[0].RunID, res.Events[1].RunID)
		}
	}
}

// TestTimelineMergeControlBeforeRunAtTiedTime proves that at a tied Time,
// "control" sorts before "run" in the merge.
func TestTimelineMergeControlBeforeRunAtTiedTime(t *testing.T) {
	dir := t.TempDir()
	controlPath := filepath.Join(dir, "control.jsonl")

	inv := identity.Static("dana@example.com")
	if _, err := control.Append(controlPath, control.Event{
		Action: "apply", Outcome: "success", Invoker: inv,
		Witness: control.CaptureWitness(), ConfigHash: "sha256:aaa",
	}); err != nil {
		t.Fatalf("control.Append: %v", err)
	}
	events, verdict, ok := LoadControl(controlPath)
	if !ok || verdict != "verified" || len(events) != 1 {
		t.Fatalf("LoadControl setup: verdict=%q ok=%v events=%+v", verdict, ok, events)
	}
	// Use the control event's own persisted Time so the run event ties
	// with it exactly (byte-identical instant, not just close).
	tiedTime := events[0].Time

	writeRun(t, dir, "r-aaa", []engine.Event{
		{Time: tiedTime, Type: "workflow_started", Binding: engine.Binding{RunID: "r-aaa"}},
	})

	res, err := Timeline(dir, controlPath, Filter{})
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("want 2 events, got %d: %+v", len(res.Events), res.Events)
	}
	if res.Events[0].Source != "control" || res.Events[1].Source != "run" {
		t.Fatalf("order = %s, %s; want control, run at a tied time",
			res.Events[0].Source, res.Events[1].Source)
	}
}

// TestTimelineFilters checks that --agent, --outcome (a real run Status
// literal, not one of control's outcome literals), --invoker (exact
// subject), and the [Since, Until) time window each select correctly.
func TestTimelineFilters(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-48 * time.Hour)
	t0, t1, t2 := base, base.Add(time.Hour), base.Add(2*time.Hour)

	dana := identity.Static("dana@example.com")
	ops := identity.Static("ops@example.com")

	writeRun(t, dir, "r-1", []engine.Event{
		{Time: t0, Type: "step_started", Agent: "coder", Binding: engine.Binding{RunID: "r-1", Invoker: dana}},
		{Time: t1, Type: "step_started", Agent: "reviewer", Binding: engine.Binding{RunID: "r-1", Invoker: ops}},
		{Time: t2, Type: "workflow_finished", Status: "failed", Binding: engine.Binding{RunID: "r-1", Invoker: dana}},
	})
	missingControl := filepath.Join(t.TempDir(), "control.jsonl")

	t.Run("agent", func(t *testing.T) {
		res, err := Timeline(dir, missingControl, Filter{Agent: "coder"})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Events) != 1 || res.Events[0].Agent != "coder" {
			t.Fatalf("got %+v", res.Events)
		}
	})

	t.Run("outcome", func(t *testing.T) {
		res, err := Timeline(dir, missingControl, Filter{Outcome: "failed"})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Events) != 1 || res.Events[0].Outcome != "failed" {
			t.Fatalf("got %+v", res.Events)
		}
	})

	t.Run("invoker", func(t *testing.T) {
		res, err := Timeline(dir, missingControl, Filter{Invoker: "ops@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Events) != 1 || res.Events[0].Invoker.Subject != "ops@example.com" {
			t.Fatalf("got %+v", res.Events)
		}
	})

	t.Run("time window since inclusive until exclusive", func(t *testing.T) {
		since, until := t1, t2
		res, err := Timeline(dir, missingControl, Filter{Since: &since, Until: &until})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Events) != 1 || !res.Events[0].Time.Equal(t1) {
			t.Fatalf("got %+v, want exactly the t1 event (Since inclusive, Until exclusive)", res.Events)
		}
	})
}

// TestTimelineTornRunContributesValidPrefix checks that a run log with a
// torn tail contributes its valid prefix and lists Source.Integrity ==
// "torn" with Count == the valid-prefix length (spec §5).
func TestTimelineTornRunContributesValidPrefix(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-48 * time.Hour)

	writeRun(t, dir, "r-torn", []engine.Event{
		{Time: base, Type: "workflow_started", Binding: engine.Binding{RunID: "r-torn"}},
		{Time: base.Add(time.Minute), Type: "step_started", Step: "plan", Binding: engine.Binding{RunID: "r-torn"}},
	})
	path := filepath.Join(dir, "r-torn.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	// A final line with no trailing newline is the ledger's "torn" case
	// (internal/ledger's matrix): the write looks interrupted mid-record.
	if _, err := f.WriteString(`{"time":"broken`); err != nil {
		t.Fatalf("write torn tail: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	missingControl := filepath.Join(t.TempDir(), "control.jsonl")
	res, err := Timeline(dir, missingControl, Filter{})
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}

	count := 0
	for _, e := range res.Events {
		if e.RunID == "r-torn" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("want 2 valid-prefix events from the torn run, got %d: %+v", count, res.Events)
	}

	var got *Source
	for i := range res.Sources {
		if res.Sources[i].Path == path {
			got = &res.Sources[i]
		}
	}
	if got == nil {
		t.Fatalf("expected r-torn listed in Sources, got %+v", res.Sources)
	}
	if got.Integrity != "torn" {
		t.Fatalf("integrity = %q, want torn", got.Integrity)
	}
	if got.Count != 2 {
		t.Fatalf("count = %d, want 2 (valid-prefix count)", got.Count)
	}
}

// TestTimelineMtimePrefilterSinceOnly checks that a run file whose mtime is
// old is skipped (absent from Sources) when Since is recent.
func TestTimelineMtimePrefilterSinceOnly(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-48 * time.Hour)

	writeRun(t, dir, "r-old", []engine.Event{
		{Time: old, Type: "workflow_started", Binding: engine.Binding{RunID: "r-old"}},
	})
	path := filepath.Join(dir, "r-old.jsonl")
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	since := time.Now().Add(-1 * time.Hour) // recent Since; file mtime is 48h old.
	missingControl := filepath.Join(t.TempDir(), "control.jsonl")
	res, err := Timeline(dir, missingControl, Filter{Since: &since})
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	for _, s := range res.Sources {
		if s.Path == path {
			t.Fatalf("expected r-old to be mtime-prefiltered out of Sources, got %+v", s)
		}
	}
	if len(res.Events) != 0 {
		t.Fatalf("expected no events, got %+v", res.Events)
	}
}

// TestTimelineMtimeAfterUntilStillContributes checks that a run whose file
// mtime is AFTER Until still contributes its pre-Until events — the mtime
// prefilter is Since-only (spec §4) and must never skip based on Until, or
// evidence would be silently dropped.
func TestTimelineMtimeAfterUntilStillContributes(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-48 * time.Hour)

	writeRun(t, dir, "r-late", []engine.Event{
		{Time: base, Type: "workflow_started", Binding: engine.Binding{RunID: "r-late"}},
	})
	path := filepath.Join(dir, "r-late.jsonl")
	future := time.Now().Add(1 * time.Hour) // mtime AFTER Until, set below.
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	since := base.Add(-1 * time.Hour) // well before mtime; must not itself cause a skip.
	until := base.Add(1 * time.Hour)  // cutoff long before the future mtime.
	missingControl := filepath.Join(t.TempDir(), "control.jsonl")
	res, err := Timeline(dir, missingControl, Filter{Since: &since, Until: &until})
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}

	found := false
	for _, e := range res.Events {
		if e.RunID == "r-late" {
			found = true
		}
	}
	if !found {
		t.Fatalf("run with mtime after Until must still contribute its pre-Until events; got %+v", res.Events)
	}
	hasSource := false
	for _, s := range res.Sources {
		if s.Path == path {
			hasSource = true
		}
	}
	if !hasSource {
		t.Fatalf("expected r-late listed in Sources, got %+v", res.Sources)
	}
}

// TestTimelineMissingControlLogOmitted checks that a missing control-log
// path yields no control entry in Sources, and no error (spec §5).
func TestTimelineMissingControlLogOmitted(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(t.TempDir(), "nope-control.jsonl")

	res, err := Timeline(dir, missing, Filter{})
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	for _, s := range res.Sources {
		if s.Kind == "control" {
			t.Fatalf("a missing control log must not appear in Sources, got %+v", s)
		}
	}
}

// TestTimelineMissingLogDirReturnsEmptyResult checks that a missing runs
// directory (nothing has run yet) is not an error.
func TestTimelineMissingLogDirReturnsEmptyResult(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "does-not-exist")
	missingControl := filepath.Join(t.TempDir(), "control.jsonl")

	res, err := Timeline(missingDir, missingControl, Filter{})
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	if len(res.Events) != 0 || len(res.Sources) != 0 {
		t.Fatalf("want empty result, got %+v", res)
	}
}

// TestTimelineMissingLogDirStillLoadsControl checks that a missing runs
// directory means zero run sources, not an empty timeline: a control log
// that already has recorded events must still surface in both Events and
// Sources. This is the realistic layout where a config was applied before
// any run ever happened.
func TestTimelineMissingLogDirStillLoadsControl(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "does-not-exist")
	controlPath := filepath.Join(t.TempDir(), "control.jsonl")

	inv := identity.Static("dana@example.com")
	if _, err := control.Append(controlPath, control.Event{
		Action: "apply", Outcome: "success", Invoker: inv,
		Witness: control.CaptureWitness(), ConfigHash: "sha256:aaa",
	}); err != nil {
		t.Fatalf("control.Append: %v", err)
	}

	res, err := Timeline(missingDir, controlPath, Filter{})
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	if len(res.Events) != 1 || res.Events[0].Source != "control" {
		t.Fatalf("want the control event surfaced, got %+v", res.Events)
	}
	if len(res.Sources) != 1 || res.Sources[0].Kind != "control" {
		t.Fatalf("want exactly one control source and no run sources, got %+v", res.Sources)
	}
}
