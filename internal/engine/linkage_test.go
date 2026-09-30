package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/agenthof/agenthof/internal/identity"
)

func TestRunAppliesParentLinkage(t *testing.T) {
	dir := t.TempDir()
	parent := &Binding{Invoker: identity.Static("dev@x"), Role: "lead", Workflow: "parent-wf", RunID: "r-parent", Depth: 1}
	id, status, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), &fakeExec{fail: map[string]int{}},
		Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), Parent: parent})
	if err != nil || status != "succeeded" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	events, _, err := ReadLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("no events")
	}
	for _, e := range events {
		if e.Binding.RunID != id {
			t.Fatalf("event %s carries run %q, want the child's own id %q", e.Type, e.Binding.RunID, id)
		}
		if e.Binding.ParentRunID != "r-parent" || e.Binding.Depth != 2 {
			t.Fatalf("event %s binding = %+v, want parent r-parent at depth 2", e.Type, e.Binding)
		}
		if e.Binding.Invoker.Subject != "dev@x" {
			t.Fatalf("event %s lost the invoker: %+v", e.Type, e.Binding.Invoker)
		}
	}
}

func TestRunRefusedChildStillRecordsLinkage(t *testing.T) {
	dir := t.TempDir()
	parent := &Binding{Invoker: identity.Static("dev@x"), Role: "lead", Workflow: "parent-wf", RunID: "r-parent"}
	id, status, err := Run(context.Background(), engCfg(), "ghost", "fix-bug", "x",
		identity.Static("dev@x"), &fakeExec{}, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), Parent: parent})
	if err == nil || status != "refused" {
		t.Fatalf("status=%q err=%v, want a refusal", status, err)
	}
	events, _, err := ReadLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" {
		t.Fatalf("events: %+v", events)
	}
	if events[0].Binding.ParentRunID != "r-parent" || events[0].Binding.Depth != 1 {
		t.Fatalf("refused child binding = %+v, want parent r-parent at depth 1", events[0].Binding)
	}
}

func TestRefuseAppliesParentLinkage(t *testing.T) {
	dir := t.TempDir()
	parent := &Binding{Invoker: identity.Static("dev@x"), Role: "lead", Workflow: "parent-wf", RunID: "r-parent"}
	id, err := Refuse(dir, "fin", "simple", identity.Static("dev@x"), "nope", parent)
	if err != nil {
		t.Fatal(err)
	}
	events, _, err := ReadLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" || events[0].Reason != "nope" {
		t.Fatalf("events: %+v", events)
	}
	if events[0].Binding.ParentRunID != "r-parent" || events[0].Binding.Depth != 1 || events[0].Binding.RunID != id {
		t.Fatalf("binding = %+v, want parent r-parent depth 1 run %s", events[0].Binding, id)
	}
	// A nil parent is a root: no linkage keys at all.
	rootID, err := Refuse(dir, "fin", "simple", identity.Static("dev@x"), "nope", nil)
	if err != nil {
		t.Fatal(err)
	}
	rootEvents, _, err := ReadLog(dir, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if rootEvents[0].Binding.ParentRunID != "" || rootEvents[0].Binding.Depth != 0 {
		t.Fatalf("root refusal carries linkage: %+v", rootEvents[0].Binding)
	}
}

// TestRootEventSerializesWithoutLinkageKeys pins the additive schema: a root
// run's events must not grow a single key, so every ledger written before
// this change still verifies and reads back byte-for-byte.
func TestRootEventSerializesWithoutLinkageKeys(t *testing.T) {
	data, err := json.Marshal(Event{Type: "workflow_started",
		Binding: Binding{Invoker: identity.Static("dev@x"), Role: "se", Workflow: "wf", RunID: "r-1"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"parent_run_id", "depth", "child_run_id", "child_role", "child_workflow"} {
		if bytes.Contains(data, []byte(`"`+key+`"`)) {
			t.Fatalf("root event carries %q: %s", key, data)
		}
	}
}
