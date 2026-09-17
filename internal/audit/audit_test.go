package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
)

func ts(s int) time.Time { return time.Date(2026, 9, 17, 12, 4, s, 0, time.UTC) }

func TestRenderFullRun(t *testing.T) {
	bind := engine.Binding{Invoker: identity.Static("dana@example.com"), Role: "software-engineer", Workflow: "fix-bug", RunID: "r-1a2b3c4d"}
	events := []engine.Event{
		{Time: ts(5), Type: "workflow_started", Binding: bind},
		{Time: ts(5), Type: "step_started", Step: "plan", Agent: "planner", Binding: bind},
		{Time: ts(6), Type: "step_succeeded", Step: "plan", Agent: "planner", Artifact: "[planner] fix", Binding: bind},
		{Time: ts(6), Type: "step_failed", Step: "code", Agent: "coder", Reason: "synthetic", Binding: bind},
		{Time: ts(6), Type: "bounced_back", Step: "code", Status: "plan", Binding: bind},
		{Time: ts(7), Type: "workflow_finished", Status: "succeeded", Binding: bind},
	}
	out := Render(events)
	for _, want := range []string{
		"run r-1a2b3c4d — fix-bug (role software-engineer)",
		"invoked by dana@example.com (asserted, issuer local)",
		"status: succeeded",
		"12:04:05  workflow started",
		"step plan (agent planner) started",
		"step plan succeeded — artifact: [planner] fix",
		"step code (agent coder) failed — synthetic",
		"bounced back to plan",
		"workflow finished: succeeded",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderRefusedAndEmpty(t *testing.T) {
	bind := engine.Binding{Invoker: identity.Static("dev@x"), Role: "se", Workflow: "fix-bug", RunID: "r-ffffffff"}
	out := Render([]engine.Event{{Time: ts(5), Type: "run_refused", Reason: "role \"se\" is not in the registry", Binding: bind}})
	if !strings.Contains(out, "status: refused") || !strings.Contains(out, "not in the registry") {
		t.Fatalf("refusal render:\n%s", out)
	}
	if Render(nil) != "no events for this run\n" {
		t.Fatal("empty render contract")
	}
}
