package completeness

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
)

// writeLedger writes events as a run ledger under dir with the binding
// (and, for a child, the parent linkage) stamped on every event.
func writeLedger(t *testing.T, dir, runID string, parent *engine.Binding, events ...engine.Event) {
	t.Helper()
	log, err := engine.OpenLog(dir, runID)
	if err != nil {
		t.Fatal(err)
	}
	b := engine.Binding{Invoker: identity.Static("dana@example.com"), Role: "r", Workflow: "w", RunID: runID}
	if parent != nil {
		b.ParentRunID, b.Depth = parent.RunID, parent.Depth+1
	}
	for i, e := range events {
		e.Time, e.Binding = time.Unix(int64(i), 0).UTC(), b
		if err := log.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
}

func spawn(child, status string, depth int) engine.Event {
	e := ev("spawn")
	e.ChildRunID, e.Status, e.Depth = child, status, depth
	return e
}

func rootBinding(id string) *engine.Binding { return &engine.Binding{RunID: id} }

func verify(t *testing.T, dir, id string) Tree {
	t.Helper()
	events, _, verr := engine.ReadLog(dir, id)
	return VerifyTree(dir, id, events, verr)
}

func TestVerifyTreeLinkedChildIsComplete(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-child", rootBinding("r-root"), started(), stepStart("c"), door("model_call"), stepOK("c", 1), finished("succeeded"))
	writeLedger(t, dir, "r-root", nil, started(), stepStart("a"), spawn("r-child", "succeeded", 1), stepOK("a", 1), finished("succeeded"))
	tr := verify(t, dir, "r-root")
	if tr.Root.Report.Verdict != Complete || len(tr.Children) != 1 || tr.Children[0].RunID != "r-child" || tr.Children[0].Report.Verdict != Complete {
		t.Fatalf("%+v", tr)
	}
	if ExitCode(tr) != 0 {
		t.Fatalf("exit %d", ExitCode(tr))
	}
	if want := "subtree: run r-child — integrity verified, completeness complete\n"; tr.SubtreeLines() != want {
		t.Fatalf("%q", tr.SubtreeLines())
	}
}

// A cancelled child is reported failed by the parent's spawn event: the
// vocabularies differ by design and no status equality is checked.
func TestVerifyTreeCancelledChildReportedFailedIsComplete(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-child", rootBinding("r-root"), started(), stepStart("c"), stepFail("c", 0), finished("cancelled"))
	writeLedger(t, dir, "r-root", nil, started(), stepStart("a"), spawn("r-child", "failed", 1), stepOK("a", 1), finished("succeeded"))
	if tr := verify(t, dir, "r-root"); ExitCode(tr) != 0 {
		t.Fatalf("%+v", tr)
	}
}

// A refused spawn with no child id names no ledger; a refused spawn WITH a
// child id names a refused-only ledger (complete by shape).
func TestVerifyTreeRefusedSpawns(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-refused", rootBinding("r-root"), refused())
	noChild := spawn("", "refused", 1)
	writeLedger(t, dir, "r-root", nil, started(), stepStart("a"), noChild, spawn("r-refused", "refused", 1), stepOK("a", 2), finished("succeeded"))
	tr := verify(t, dir, "r-root")
	if ExitCode(tr) != 0 || len(tr.Children) != 1 || tr.Children[0].Report.Verdict != Complete {
		t.Fatalf("%+v", tr)
	}
}

func TestVerifyTreeMissingChildIsGap(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-root", nil, started(), stepStart("a"), spawn("r-gone", "succeeded", 1), stepOK("a", 1), finished("succeeded"))
	tr := verify(t, dir, "r-root")
	if tr.Root.Report.Verdict != Gap || tr.Root.Report.Detail != "spawn names child r-gone: no ledger under the log directory" || ExitCode(tr) != 11 {
		t.Fatalf("%+v exit %d", tr.Root.Report, ExitCode(tr))
	}
}

func TestVerifyTreeWrongParentOrDepthIsGap(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-child", rootBinding("r-other"), started(), stepStart("c"), stepOK("c", 0), finished("succeeded"))
	writeLedger(t, dir, "r-root", nil, started(), stepStart("a"), spawn("r-child", "succeeded", 1), stepOK("a", 1), finished("succeeded"))
	if tr := verify(t, dir, "r-root"); tr.Root.Report.Detail != `child r-child names parent "r-other", not this run` {
		t.Fatalf("%+v", tr.Root.Report)
	}
	dir2 := t.TempDir()
	writeLedger(t, dir2, "r-child", rootBinding("r-root"), started(), stepStart("c"), stepOK("c", 0), finished("succeeded"))
	writeLedger(t, dir2, "r-root", nil, started(), stepStart("a"), spawn("r-child", "succeeded", 2), stepOK("a", 1), finished("succeeded"))
	if tr := verify(t, dir2, "r-root"); tr.Root.Report.Detail != "child r-child is at depth 1, spawn says 2" {
		t.Fatalf("%+v", tr.Root.Report)
	}
}

// The reverse check: a child naming a terminated parent that no spawn
// event names is a gap; under a parent still running it is normal.
func TestVerifyTreeUnnamedChild(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-child", rootBinding("r-root"), started(), stepStart("c"), stepOK("c", 0), finished("succeeded"))
	writeLedger(t, dir, "r-root", nil, started(), stepStart("a"), stepOK("a", 0), finished("succeeded"))
	tr := verify(t, dir, "r-root")
	if tr.Root.Report.Verdict != Gap || tr.Root.Report.Detail != "child r-child names this run as its parent; no spawn event names it" {
		t.Fatalf("%+v", tr.Root.Report)
	}
	live := t.TempDir()
	writeLedger(t, live, "r-child", rootBinding("r-root"), started(), stepStart("c"), stepOK("c", 0), finished("succeeded"))
	writeLedger(t, live, "r-root", nil, started(), stepStart("a"))
	if tr := verify(t, live, "r-root"); tr.Root.Report.Verdict != Unterminated || ExitCode(tr) != 12 {
		t.Fatalf("a live parent is unterminated, not gap: %+v exit %d", tr.Root.Report, ExitCode(tr))
	}
}

// Forward recursion runs on an unterminated parent into children already
// named; a child's gap under a live parent is not hidden behind 12.
func TestVerifyTreeChildGapUnderLiveParentExits11(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-child", rootBinding("r-root"), started(), stepStart("c"), stepOK("c", 3), finished("succeeded"))
	writeLedger(t, dir, "r-root", nil, started(), stepStart("a"), spawn("r-child", "succeeded", 1))
	tr := verify(t, dir, "r-root")
	if tr.Root.Report.Verdict != Unterminated || len(tr.Children) != 1 || tr.Children[0].Report.Verdict != Gap || ExitCode(tr) != 11 {
		t.Fatalf("%+v exit %d", tr, ExitCode(tr))
	}
}

func TestVerifyTreeTornChildExits1(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-child", rootBinding("r-root"), started(), stepStart("c"), stepOK("c", 0), finished("succeeded"))
	f, _ := os.OpenFile(filepath.Join(dir, "r-child.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"time":"2026-`)
	_ = f.Close()
	writeLedger(t, dir, "r-root", nil, started(), stepStart("a"), spawn("r-child", "succeeded", 1), stepOK("a", 1), finished("succeeded"))
	tr := verify(t, dir, "r-root")
	if tr.ChildIntegrityFailure() != "torn" || ExitCode(tr) != 1 || !strings.Contains(tr.SubtreeLines(), "integrity torn, completeness not judged") {
		t.Fatalf("%+v exit %d lines %q", tr, ExitCode(tr), tr.SubtreeLines())
	}
}

func TestVerifyTreeNoClaimRootWalksNoChildren(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-root", nil, oldStarted(), unstamped("step_started", "a"), spawn("r-gone", "succeeded", 1), unstamped("step_succeeded", "a"), finished("succeeded"))
	if tr := verify(t, dir, "r-root"); tr.Root.Report.Verdict != NoClaim || len(tr.Children) != 0 || ExitCode(tr) != 0 {
		t.Fatalf("an old ledger is judged on integrity alone: %+v", tr)
	}
}

func TestVerifyTreeCycleTerminates(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-a", rootBinding("r-b"), started(), stepStart("x"), spawn("r-b", "succeeded", 1), stepOK("x", 1), finished("succeeded"))
	writeLedger(t, dir, "r-b", rootBinding("r-a"), started(), stepStart("y"), spawn("r-a", "succeeded", 1), stepOK("y", 1), finished("succeeded"))
	done := make(chan Tree, 1)
	go func() { done <- verify(t, dir, "r-a") }()
	select {
	case tr := <-done:
		if len(tr.Children) != 1 {
			t.Fatalf("each run is walked once: %+v", tr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cyclic parent_run_id must not hang the walk")
	}
}

func TestParents(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-root", nil, started())
	writeLedger(t, dir, "r-child", rootBinding("r-root"), started())
	if err := os.WriteFile(filepath.Join(dir, "r-blank.jsonl"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, skip := range []string{"control.jsonl", "control.jsonl.torn-1", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, skip), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Parents(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got["r-root"] != "" || got["r-child"] != "r-root" || got["r-blank"] != "" {
		t.Fatalf("%v", got)
	}
}

// TestSidecarFilesBesideALedgerChangeNothing pins that an anchor sidecar (and
// its stray temp and lock) sitting beside run ledgers is invisible to the
// completeness judgement: only <id>.jsonl files are runs.
func TestSidecarFilesBesideALedgerChangeNothing(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-child", rootBinding("r-root"), started(), stepStart("c"), stepOK("c", 0), finished("succeeded"))
	writeLedger(t, dir, "r-root", nil, started(), stepStart("a"), spawn("r-child", "succeeded", 1), stepOK("a", 1), finished("succeeded"))

	snap := func() (Tree, map[string]string, Report) {
		events, _, verr := engine.ReadLog(dir, "r-root")
		parents, err := Parents(dir)
		if err != nil {
			t.Fatal(err)
		}
		return VerifyTree(dir, "r-root", events, verr), parents, Check(events)
	}
	tree0, parents0, check0 := snap()

	line := `{"time":"2026-10-27T00:00:00Z","run_id":"r-root","seq":5,"hash":"` + strings.Repeat("ab", 32) + `"}` + "\n"
	for _, name := range []string{"r-root.anchor", "r-root.anchor.tmp-x", "r-child.anchor", ".anchor.lock"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tree1, parents1, check1 := snap()
	if !reflect.DeepEqual(tree0, tree1) || !reflect.DeepEqual(parents0, parents1) || !reflect.DeepEqual(check0, check1) {
		t.Fatalf("a sidecar beside the ledgers changed the verdict:\ntree %+v -> %+v\nparents %v -> %v\ncheck %+v -> %+v", tree0, tree1, parents0, parents1, check0, check1)
	}
	if len(parents1) != 2 || parents1["r-root"] != "" || parents1["r-child"] != "r-root" {
		t.Fatalf("Parents = %v, want exactly r-root and r-child", parents1)
	}
	if tree1.Root.Report.Verdict != Complete {
		t.Fatalf("%+v", tree1.Root.Report)
	}
}

func TestSubtreeLinesWithSuffix(t *testing.T) {
	dir := t.TempDir()
	writeLedger(t, dir, "r-c1", rootBinding("r-root"), started(), stepStart("c"), stepOK("c", 0), finished("succeeded"))
	writeLedger(t, dir, "r-c2", rootBinding("r-root"), started(), stepStart("c"), stepOK("c", 0), finished("succeeded"))
	writeLedger(t, dir, "r-root", nil, started(), stepStart("a"), spawn("r-c1", "succeeded", 1), spawn("r-c2", "succeeded", 1), stepOK("a", 2), finished("succeeded"))
	tr := verify(t, dir, "r-root")
	if len(tr.Children) != 2 {
		t.Fatalf("%+v", tr)
	}
	plain := tr.SubtreeLines()
	want := "subtree: run r-c1 — integrity verified, completeness complete\nsubtree: run r-c2 — integrity verified, completeness complete\n"
	if plain != want {
		t.Fatalf("SubtreeLines = %q", plain)
	}
	if got := tr.SubtreeLinesWith(nil); got != plain {
		t.Fatalf("nil suffix = %q, want SubtreeLines' %q", got, plain)
	}
	got := tr.SubtreeLinesWith(func(Node) string { return ", anchor verified" })
	if strings.Count(got, ", anchor verified\n") != 2 || !strings.HasPrefix(got, "subtree: run r-c1 — integrity verified, completeness complete, anchor verified\n") {
		t.Fatalf("%q", got)
	}
	if empty := (Tree{}).SubtreeLinesWith(func(Node) string { return "x" }); empty != "" {
		t.Fatalf("no children = %q", empty)
	}
}
