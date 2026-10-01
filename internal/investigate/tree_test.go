package investigate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
)

func treeEvents(runID, parent string, depth int, at time.Time) []engine.Event {
	bind := engine.Binding{Invoker: identity.Static("dana"), Role: "r", Workflow: "wf", RunID: runID, ParentRunID: parent, Depth: depth}
	return []engine.Event{
		{Time: at, Type: "workflow_started", Binding: bind},
		{Time: at.Add(time.Second), Type: "workflow_finished", Status: "succeeded", Binding: bind},
	}
}

func runIDs(res Result) map[string]int {
	out := map[string]int{}
	for _, e := range res.Events {
		out[e.RunID]++
	}
	return out
}

func TestNormalizeRunCarriesLinkage(t *testing.T) {
	e := treeEvents("r-child", "r-root", 1, time.Unix(10, 0).UTC())[0]
	r := normalizeRun(e, 0)
	if r.ParentRunID != "r-root" || r.Depth != 1 {
		t.Fatalf("%+v", r)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"parent_run_id":"r-root"`) || !strings.Contains(string(data), `"depth":1`) {
		t.Fatalf("json: %s", data)
	}
	root := normalizeRun(treeEvents("r-root", "", 0, time.Unix(10, 0).UTC())[0], 0)
	data, _ = json.Marshal(root)
	if strings.Contains(string(data), "parent_run_id") || strings.Contains(string(data), `"depth"`) {
		t.Fatalf("a root record must not carry linkage keys: %s", data)
	}
}

func TestTimelineRunFilterExpandsToDescendants(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Unix(100, 0).UTC()
	writeRun(t, dir, "r-root", treeEvents("r-root", "", 0, t0))
	writeRun(t, dir, "r-child", treeEvents("r-child", "r-root", 1, t0.Add(2*time.Second)))
	writeRun(t, dir, "r-gc", treeEvents("r-gc", "r-child", 2, t0.Add(4*time.Second)))
	writeRun(t, dir, "r-other", treeEvents("r-other", "", 0, t0.Add(6*time.Second)))

	res, err := Timeline(dir, dir+"/control.jsonl", Filter{Run: "r-root"})
	if err != nil {
		t.Fatal(err)
	}
	got := runIDs(res)
	if len(got) != 3 || got["r-root"] != 2 || got["r-child"] != 2 || got["r-gc"] != 2 {
		t.Fatalf("--run r-root selected %v, want the root and its two descendants", got)
	}
	if len(res.Sources) != 3 {
		t.Fatalf("sources = %d, want only the selected runs listed", len(res.Sources))
	}
	res, err = Timeline(dir, dir+"/control.jsonl", Filter{Run: "r-child"})
	if err != nil {
		t.Fatal(err)
	}
	if got := runIDs(res); len(got) != 2 || got["r-child"] != 2 || got["r-gc"] != 2 {
		t.Fatalf("--run r-child selected %v, want the child and the grandchild", got)
	}
	res, err = Timeline(dir, dir+"/control.jsonl", Filter{Run: "r-other"})
	if err != nil {
		t.Fatal(err)
	}
	if got := runIDs(res); len(got) != 1 || got["r-other"] != 2 {
		t.Fatalf("--run r-other selected %v, want only itself", got)
	}
	res, err = Timeline(dir, dir+"/control.jsonl", Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if got := runIDs(res); len(got) != 4 {
		t.Fatalf("no filter selected %v, want all four", got)
	}
}

func TestTimelineOrphanChildSelectsUnderMissingParent(t *testing.T) {
	dir := t.TempDir()
	writeRun(t, dir, "r-child", treeEvents("r-child", "r-gone", 1, time.Unix(100, 0).UTC()))
	res, err := Timeline(dir, dir+"/control.jsonl", Filter{Run: "r-gone"})
	if err != nil {
		t.Fatal(err)
	}
	if got := runIDs(res); len(got) != 1 || got["r-child"] != 2 {
		t.Fatalf("a child whose parent ledger was pruned must still show under its parent's id, got %v", got)
	}
}

func TestSelectRunsTerminatesOnLoopingChain(t *testing.T) {
	// Corrupt or hand-edited data: a points at b and b at a. The walk must
	// end, and neither selects under an unrelated root.
	runs := []runLog{
		{id: "r-a", records: []Record{{RunID: "r-a", ParentRunID: "r-b"}}},
		{id: "r-b", records: []Record{{RunID: "r-b", ParentRunID: "r-a"}}},
	}
	sel := selectRuns(runs, "r-x")
	if len(sel) != 1 || !sel["r-x"] {
		t.Fatalf("selected = %v, want only the requested id", sel)
	}
	if sel := selectRuns(runs, "r-a"); !sel["r-a"] || !sel["r-b"] {
		t.Fatalf("selected = %v, want both nodes of the loop under r-a", sel)
	}
	if selectRuns(runs, "") != nil {
		t.Fatal("no --run means no selection")
	}
}

func TestRenderTextShowsTheTree(t *testing.T) {
	res := Result{Events: []Record{
		{Time: time.Unix(100, 0).UTC(), Source: "run", RunID: "r-root", Kind: "workflow_started", Invoker: Invoker{Subject: "dana", Method: "asserted"}},
		{Time: time.Unix(101, 0).UTC(), Source: "run", RunID: "r-child", Kind: "workflow_started", Invoker: Invoker{Subject: "dana", Method: "asserted"}, ParentRunID: "r-root", Depth: 1},
		{Time: time.Unix(102, 0).UTC(), Source: "run", RunID: "r-gc", Kind: "workflow_started", Invoker: Invoker{Subject: "dana", Method: "asserted"}, ParentRunID: "r-child", Depth: 2},
	}}
	out := RenderText(res)
	for _, want := range []string{
		"\n1970-01-01T00:01:40Z run workflow_started — dana (asserted)\n",
		"\n  1970-01-01T00:01:41Z run workflow_started — dana (asserted) [parent=r-root]\n",
		"\n    1970-01-01T00:01:42Z run workflow_started — dana (asserted) [parent=r-child]\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
