package apiclient

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/engine"
)

func roundTrip[T any](t *testing.T, in T) T {
	t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip changed the value:\n in=%+v\nout=%+v\njson=%s", in, out, data)
	}
	return out
}

func TestWireTypesRoundTrip(t *testing.T) {
	fin := time.Date(2026, 10, 6, 12, 0, 1, 0, time.UTC)
	roundTrip(t, RunRequest{Role: "se", Workflow: "fix-bug", Input: "x"})
	roundTrip(t, RunAccepted{RunID: "r-0123456789abcdef", Status: StatusRefused, Reason: "why"})
	roundTrip(t, RunStatus{RunID: "r-0123456789abcdef", Status: "succeeded", Started: fin.Add(-time.Second), Finished: &fin, OutputSHA: "ab", OutputPreview: "p"})
	roundTrip(t, RunList{Runs: []RunSummary{{RunID: "r-1", Status: StatusRunning}}})
	roundTrip(t, RunEvents{Events: []engine.Event{{Type: "workflow_started", Time: fin}}, Head: Head{Hash: "h", Count: 1}, Integrity: IntegrityBroken, BrokenLine: 3})
	roundTrip(t, InvestigateQuery{Since: "2026-10-06T00:00:00Z", Run: "r-1"})
}

// TestWireKeysArePinned is the contract: a renamed key breaks every client.
func TestWireKeysArePinned(t *testing.T) {
	started := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	data, err := json.Marshal(RunStatus{RunID: "r-1", Status: StatusRunning, Started: started})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"run_id":"r-1","status":"running","started":"2026-10-06T12:00:00Z"}`
	if string(data) != want {
		t.Fatalf("RunStatus json = %s, want %s", data, want)
	}
	data, _ = json.Marshal(RunEvents{Events: []engine.Event{}, Head: Head{}, Integrity: IntegrityVerified})
	want = `{"events":[],"head":{"hash":"","count":0},"integrity":"verified"}`
	if string(data) != want {
		t.Fatalf("RunEvents json = %s, want %s", data, want)
	}
}

func TestInvestigateQueryValuesRoundTrip(t *testing.T) {
	q := InvestigateQuery{Since: "2026-10-06T00:00:00Z", Until: "2026-10-07T00:00:00Z", Invoker: "dana@example.com", Agent: "a", Outcome: "o", Run: "r-1", ConfigHash: "h"}
	got := InvestigateQueryFrom(q.Values())
	if got != q {
		t.Fatalf("got %+v, want %+v", got, q)
	}
	if v := (InvestigateQuery{}).Values(); len(v) != 0 {
		t.Fatalf("an empty query must encode no parameters, got %v", v)
	}
}
