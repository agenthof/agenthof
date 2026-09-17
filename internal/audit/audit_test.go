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
		{Time: ts(6), Type: "step_succeeded", Step: "plan", Agent: "planner", Artifact: "[planner] fix", ArtifactSHA: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd", Binding: bind},
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
		"step plan succeeded — artifact 01234567: [planner] fix",
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

func TestRenderLedgerIntegrityVerified(t *testing.T) {
	dir := t.TempDir()
	id := "r-1a2b3c4d"
	log, err := engine.OpenLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	bind := engine.Binding{Invoker: identity.Static("dana@example.com"), Role: "software-engineer", Workflow: "fix-bug", RunID: id}
	events := []engine.Event{
		{Time: ts(5), Type: "workflow_started", Binding: bind},
		{Time: ts(6), Type: "step_started", Step: "plan", Agent: "planner", Binding: bind},
		{Time: ts(7), Type: "workflow_finished", Status: "succeeded", Binding: bind},
	}
	for _, e := range events {
		if err := log.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := engine.ReadLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	out := Render(got)
	if !strings.Contains(out, "ledger integrity: verified (3 events)") {
		t.Fatalf("missing verified integrity line in:\n%s", out)
	}
}

func TestRenderRefuseHelper(t *testing.T) {
	dir := t.TempDir()
	inv := identity.Invoker{Subject: "dev@x", Groups: []string{"engineering"}}
	id, err := engine.Refuse(dir, "fin", "simple", inv, `role "fin" does not allow the invoker: allowed groups [finance]`)
	if err != nil {
		t.Fatal(err)
	}
	events, err := engine.ReadLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" {
		t.Fatalf("Refuse must write exactly one run_refused event: %+v", events)
	}
	if err := engine.VerifyChain(events); err != nil {
		t.Fatalf("Refuse's single event must form a valid chain: %v", err)
	}
	out := Render(events)
	if !strings.Contains(out, "status: refused") {
		t.Fatalf("missing refused status in:\n%s", out)
	}
	if !strings.Contains(out, "ledger integrity: verified (1 events)") {
		t.Fatalf("missing verified integrity line in:\n%s", out)
	}
}

func TestRenderLedgerIntegrityBroken(t *testing.T) {
	bind := engine.Binding{Invoker: identity.Static("dana@example.com"), Role: "software-engineer", Workflow: "fix-bug", RunID: "r-1a2b3c4d"}
	// Hand-built events without valid Prev chaining.
	events := []engine.Event{
		{Time: ts(5), Type: "workflow_started", Binding: bind},
		{Time: ts(6), Type: "step_started", Step: "plan", Agent: "planner", Binding: bind},
		{Time: ts(7), Type: "workflow_finished", Status: "succeeded", Binding: bind},
	}
	out := Render(events)
	if !strings.Contains(out, "ledger integrity: BROKEN at event") {
		t.Fatalf("missing broken integrity line in:\n%s", out)
	}
}
