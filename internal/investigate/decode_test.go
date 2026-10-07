package investigate

import (
	"path/filepath"
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
	res, err := Timeline(dir, filepath.Join(dir, "control.jsonl"), Filter{})
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
