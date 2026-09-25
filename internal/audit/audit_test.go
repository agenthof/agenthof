package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
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
	out := Render(events, ledger.Head{Count: len(events)}, nil)
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

func TestRenderExecAttested(t *testing.T) {
	exit := 0
	bind := engine.Binding{Invoker: identity.Static("dana@example.com"), Role: "software-engineer", Workflow: "fix-bug", RunID: "r-exec1"}
	events := []engine.Event{
		{Type: "exec", Status: "succeeded", Command: []string{"true"}, ExitCode: &exit, Mode: "attested",
			Time: time.Unix(0, 0).UTC(), Binding: bind},
	}
	out := Render(events, ledger.Head{Count: len(events)}, nil)
	if !strings.Contains(out, "exec true — exit 0 (attested)") {
		t.Fatalf("exec not rendered:\n%s", out)
	}
}

func TestRenderExecRefused(t *testing.T) {
	bind := engine.Binding{Invoker: identity.Static("dana@example.com"), Role: "software-engineer", Workflow: "fix-bug", RunID: "r-exec2"}
	events := []engine.Event{
		{Type: "exec", Status: "refused", Command: []string{"rm", "-rf", "/"},
			Reason: "command is not on the exec allowlist", Time: time.Unix(0, 0).UTC(), Binding: bind},
	}
	out := Render(events, ledger.Head{Count: len(events)}, nil)
	if !strings.Contains(out, "exec rm -rf / refused — command is not on the exec allowlist") {
		t.Fatalf("refused exec not rendered:\n%s", out)
	}
}

func TestRenderModelCallSucceeded(t *testing.T) {
	pt, ct := 11, 5
	events := []engine.Event{{
		Type: "model_call", Status: "succeeded", Model: "fast",
		PromptTokens: &pt, CompletionTokens: &ct, Time: time.Unix(0, 0).UTC(),
	}}
	out := Render(events, ledger.Head{Count: len(events)}, nil)
	if !strings.Contains(out, "model fast — 11 prompt / 5 completion tokens") {
		t.Fatalf("model_call not rendered:\n%s", out)
	}
}

func TestRenderModelCallRefused(t *testing.T) {
	events := []engine.Event{{
		Type: "model_call", Status: "refused", Model: "gpt-9",
		Reason: `model "gpt-9" is not allowed for this agent`, Time: time.Unix(0, 0).UTC(),
	}}
	out := Render(events, ledger.Head{Count: len(events)}, nil)
	if !strings.Contains(out, `model gpt-9 refused — model "gpt-9" is not allowed for this agent`) {
		t.Fatalf("refused model_call not rendered:\n%s", out)
	}
}

func TestRenderRefusedAndEmpty(t *testing.T) {
	bind := engine.Binding{Invoker: identity.Static("dev@x"), Role: "se", Workflow: "fix-bug", RunID: "r-ffffffff"}
	out := Render([]engine.Event{{Time: ts(5), Type: "run_refused", Reason: "role \"se\" is not in the registry", Binding: bind}}, ledger.Head{Count: 1}, nil)
	if !strings.Contains(out, "status: refused") || !strings.Contains(out, "not in the registry") {
		t.Fatalf("refusal render:\n%s", out)
	}
	if Render(nil, ledger.Head{}, nil) != "no events for this run\n" {
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
	got, head, err := engine.ReadLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	out := Render(got, head, err)
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
	events, head, err := engine.ReadLog(dir, id)
	if err != nil {
		t.Fatalf("Refuse's single event must form a valid chain: %v", err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" {
		t.Fatalf("Refuse must write exactly one run_refused event: %+v", events)
	}
	out := Render(events, head, err)
	if !strings.Contains(out, "status: refused") {
		t.Fatalf("missing refused status in:\n%s", out)
	}
	if !strings.Contains(out, "ledger integrity: verified (1 events)") {
		t.Fatalf("missing verified integrity line in:\n%s", out)
	}
}

func TestRenderLedgerIntegrityTorn(t *testing.T) {
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
	}
	for _, e := range events {
		if err := log.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash mid-write: append an incomplete trailing record with
	// no terminating newline — a torn tail, not a broken chain.
	path := filepath.Join(dir, id+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(`{"type":"workflow_finished","prev":"`)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	got, head, rerr := engine.ReadLog(dir, id)
	out := Render(got, head, rerr)
	if !strings.Contains(out, "ledger integrity: TORN — last record incomplete") {
		t.Fatalf("missing torn integrity line in:\n%s", out)
	}
	if !strings.Contains(out, "workflow started") || !strings.Contains(out, "step plan (agent planner) started") {
		t.Fatalf("torn render must still show the valid prefix:\n%s", out)
	}
}

func TestRenderLedgerIntegrityBroken(t *testing.T) {
	dir := t.TempDir()
	id := "r-1a2b3c4d"
	log, err := engine.OpenLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	bind := engine.Binding{Invoker: identity.Static("dana@example.com"), Role: "software-engineer", Workflow: "fix-bug", RunID: id}
	for i, typ := range []string{"workflow_started", "step_started", "workflow_finished"} {
		e := engine.Event{Time: ts(5 + i), Type: typ, Binding: bind}
		if typ == "step_started" {
			e.Step, e.Agent = "plan", "planner"
		}
		if err := log.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	// Tamper with the on-disk second line's content, leaving its own
	// "prev" field untouched, so the chain breaks one line later — see
	// the identical technique in internal/engine/events_test.go.
	path := filepath.Join(dir, id+".jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	tampered := strings.Replace(lines[1], `"step":"plan"`, `"step":"tampered"`, 1)
	if tampered == lines[1] {
		t.Fatal("tamper substring not found; test fixture drifted")
	}
	lines[1] = tampered
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	events, head, rerr := engine.ReadLog(dir, id)
	out := Render(events, head, rerr)
	if !strings.Contains(out, "ledger integrity: BROKEN at event") {
		t.Fatalf("missing broken integrity line in:\n%s", out)
	}
}
