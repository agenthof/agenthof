package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
)

func TestRunIDShape(t *testing.T) {
	a, b := NewRunID(), NewRunID()
	if !strings.HasPrefix(a, "r-") || len(a) != 10 {
		t.Fatalf("shape: %q", a)
	}
	if a == b {
		t.Fatal("ids must differ")
	}
}

func TestLogRoundTrip(t *testing.T) {
	dir := t.TempDir()
	id := NewRunID()
	log, err := OpenLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	bind := Binding{Invoker: identity.Static("dev@x"), Role: "se", Workflow: "fix-bug", RunID: id}
	events := []Event{
		{Time: time.Now().UTC(), Type: "workflow_started", Binding: bind},
		{Time: time.Now().UTC(), Type: "step_started", Step: "plan", Agent: "planner", Binding: bind},
		{Time: time.Now().UTC(), Type: "workflow_finished", Status: "succeeded", Binding: bind},
	}
	for _, e := range events {
		if err := log.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := ReadLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[1].Step != "plan" || got[2].Status != "succeeded" {
		t.Fatalf("%+v", got)
	}
	if got[0].Binding.Invoker.Subject != "dev@x" || got[0].Binding.RunID != id {
		t.Fatal("binding must survive the round trip")
	}
}

func TestReadLogMissing(t *testing.T) {
	if _, err := ReadLog(t.TempDir(), "r-00000000"); err == nil {
		t.Fatal("missing run must error")
	}
}
