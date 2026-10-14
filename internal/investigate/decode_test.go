package investigate

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
)

func TestDecodeJSONRoundTripsRenderJSON(t *testing.T) {
	dir := t.TempDir()
	runID := "r-decode01"
	log, err := engine.OpenLog(dir, runID)
	if err != nil {
		t.Fatal(err)
	}
	bind := engine.Binding{Invoker: identity.Static("dev@x"), Role: "se", Workflow: "w", RunID: runID}
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for _, e := range []engine.Event{
		{Time: now, Type: "workflow_started", ConfigHash: "abc", Binding: bind},
		{Time: now.Add(time.Second), Type: "workflow_finished", Status: "succeeded", Binding: bind},
	} {
		if err := log.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	_ = log.Close()
	res, err := Timeline(dir, filepath.Join(dir, "control.jsonl"), Filter{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := RenderJSON(res, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if RenderText(back) != RenderText(res) {
		t.Fatalf("text after decode differs:\n%s\n---\n%s", RenderText(back), RenderText(res))
	}
	if ExitCode(back) != ExitCode(res) {
		t.Fatalf("exit code after decode = %d, want %d", ExitCode(back), ExitCode(res))
	}
}

func TestDecodeJSONRejectsOtherVersions(t *testing.T) {
	if _, err := DecodeJSON([]byte(`{"v":"investigate/2","events":[],"sources":[]}`)); err == nil {
		t.Fatal("an unknown document version must be rejected")
	}
}

// TestDecodeJSONRoundTripsAnchors: a client holding only the document
// renders the same text — the trailer included, derived from the events —
// derives the same exit, and sees the same anchor objects.
func TestDecodeJSONRoundTripsAnchors(t *testing.T) {
	tm := time.Date(2026, 10, 14, 6, 0, 3, 0, time.UTC)
	inv := Invoker{Subject: "dana@example.com", Issuer: "local", Method: "asserted"}
	res := Result{
		Events: []Record{
			{Time: tm, Source: "control", Kind: "apply", Invoker: inv, Outcome: "success", ConfigHash: "sha256:abc", Seq: 1},
			{Time: tm.Add(time.Second), Source: "control", Kind: "anchor", Invoker: inv, Outcome: "success", Seq: 2,
				Anchor: &Anchor{Seq: 1, Hash: strings.Repeat("ab", 32), Kind: "tlog", BackendKind: "transparency-log", Backend: "https://rekor.example", Ref: strings.Repeat("0", 80), BackendKeyID: strings.Repeat("cd", 32), Verdict: "verified"}},
			{Time: tm.Add(2 * time.Second), Source: "control", Kind: "anchor", Invoker: inv, Outcome: "success", Seq: 3,
				Anchor: &Anchor{Verdict: "mismatch", Cause: "anchor record without coverage"}},
			{Time: tm.Add(3 * time.Second), Source: "control", Kind: "anchor", Invoker: inv, Outcome: "error", Reason: "status 503 from rekor.example", Seq: 4,
				Anchor: &Anchor{Seq: 1, Hash: strings.Repeat("ab", 32), Kind: "tlog", BackendKind: "transparency-log", Backend: "https://rekor.example"}},
		},
		Sources: []Source{{Path: "/logs/control.jsonl", Kind: "control", Integrity: "verified", Count: 4}},
	}
	doc, err := RenderJSON(res, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeJSON([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if RenderText(back) != RenderText(res) || !strings.Contains(RenderText(back), "\nanchors: 2 (1 verified, 1 mismatch, 0 unverifiable)\n") {
		t.Fatalf("text after decode differs:\n%s\n---\n%s", RenderText(back), RenderText(res))
	}
	if ExitCode(back) != ExitCode(res) {
		t.Fatalf("exit %d, want %d", ExitCode(back), ExitCode(res))
	}
	for i := range res.Events {
		if !reflect.DeepEqual(back.Events[i].Anchor, res.Events[i].Anchor) {
			t.Fatalf("event %d anchor: %+v, want %+v", i, back.Events[i].Anchor, res.Events[i].Anchor)
		}
	}
}
