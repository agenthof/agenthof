package engine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
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
	got, _, err := ReadLog(dir, id)
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
	if _, _, err := ReadLog(t.TempDir(), "r-00000000"); err == nil {
		t.Fatal("missing run must error")
	}
}

func TestReadLogValidChainHasEmptyGenesisPrev(t *testing.T) {
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
	got, head, err := ReadLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || head.Count != 3 {
		t.Fatalf("expected 3 events, got %d (head=%+v)", len(got), head)
	}
	if got[0].Prev != "" {
		t.Fatalf("genesis event Prev must be empty, got %q", got[0].Prev)
	}
}

func TestReadLogTamperedChainReturnsBrokenErrorWithValidPrefix(t *testing.T) {
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

	// Tamper with the on-disk second line's content, leaving its own
	// "prev" field untouched: the line still passes its own prev check,
	// but its hash no longer matches what the following line's "prev"
	// recorded, so the ledger surfaces the break one line later.
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

	got, head, err := ReadLog(dir, id)
	var broken *ledger.ChainBrokenError
	if !errors.As(err, &broken) {
		t.Fatalf("error must be a *ledger.ChainBrokenError, got: %T (%v)", err, err)
	}
	if broken.Line != 3 {
		t.Fatalf("error must name broken line 3, got: %d", broken.Line)
	}
	if len(got) != 2 || head.Count != 2 {
		t.Fatalf("must return the valid prefix (2 events): got=%d head=%+v", len(got), head)
	}
	if got[0].Type != "workflow_started" {
		t.Fatalf("valid prefix must include the untampered genesis event: %+v", got[0])
	}
}

func TestChainCompatWithPreArtifactSHALogs(t *testing.T) {
	// A ledger written before ArtifactSHA existed must still verify:
	// empty ArtifactSHA is omitted on re-marshal, so bytes match.
	dir := t.TempDir()
	id := NewRunID()
	log, err := OpenLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	bind := Binding{Invoker: identity.Static("x@y"), Role: "r", Workflow: "w", RunID: id}
	for _, typ := range []string{"workflow_started", "step_started", "workflow_finished"} {
		if err := log.Append(Event{Time: time.Now().UTC(), Type: typ, Binding: bind}); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	events, head, err := ReadLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if head.Count != len(events) {
		t.Fatalf("head.Count must match event count: head=%+v events=%d", head, len(events))
	}
	for _, e := range events {
		if e.ArtifactSHA != "" {
			t.Fatal("no event should carry a sha here")
		}
	}

	// Events without an execution tier must marshal without the "execution"
	// key too, so old ledger lines (written before Execution existed) stay
	// byte-compatible the same way pre-ArtifactSHA ones do.
	for _, e := range events {
		if e.Execution != "" {
			t.Fatalf("no event should carry an execution tier here: %+v", e)
		}
	}
	data, err := json.Marshal(events[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "\"execution\"") {
		t.Fatal("empty Execution must be omitted from marshaled JSON")
	}
}

// TestOpenLogRejectsRunIDCollision is a regression test for a bug where
// OpenLog, via ledger.Open, RESUMED an existing run-log file instead of
// refusing it: a colliding run ID (e.g. from a weak RunID source, or a
// caller reusing an ID) would chain a second run's events onto the first
// run's log, and audit would misattribute them to one run. OpenLog must
// refuse to open a run-id whose file already has events.
func TestOpenLogRejectsRunIDCollision(t *testing.T) {
	dir := t.TempDir()
	id := NewRunID()
	bind := Binding{Invoker: identity.Static("dev@x"), Role: "se", Workflow: "fix-bug", RunID: id}

	log, err := OpenLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Append(Event{Time: time.Now().UTC(), Type: "workflow_started", Binding: bind}); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenLog(dir, id); err == nil {
		t.Fatal("OpenLog on a run-id whose file already has events must error")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error must say the run already exists, got: %v", err)
	}
}

func TestToolCallEventRoundTrip(t *testing.T) {
	dir := t.TempDir()
	log, err := OpenLog(dir, "r-toolcall")
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	want := Event{
		Type:             "tool_call",
		Agent:            "coder",
		Status:           "succeeded",
		AuthMode:         "static_env",
		ResourcesTouched: []string{"github"},
	}
	if err := log.Append(want); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	events, _, err := ReadLog(dir, "r-toolcall")
	if err != nil {
		t.Fatalf("ReadLog: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	got := events[0]
	if got.Type != "tool_call" || got.AuthMode != "static_env" ||
		len(got.ResourcesTouched) != 1 || got.ResourcesTouched[0] != "github" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestEventOmitsReservedFieldsWhenEmpty(t *testing.T) {
	data, err := json.Marshal(Event{Type: "step_started", Agent: "coder"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, k := range []string{"auth_mode", "resources_touched", "actor", "principal"} {
		if strings.Contains(string(data), k) {
			t.Fatalf("empty event must omit %q; got %s", k, data)
		}
	}
}

// TestReadLogUnmarshalFailurePreservesHeadCountInvariant is a regression
// test for a bug where, if a record was valid per the ledger's hash chain
// but failed to decode as an Event (e.g. a malformed "time" field), and a
// later record in the same file was ALSO ledger-valid, ReadLog returned
// ledger.ReadVerify's full chain Head — whose Count could exceed
// len(events) — instead of a Head scoped to what was actually decoded.
// Every other ReadLog return path holds head.Count == len(events); this
// asserts the same invariant on the undecodable-record path.
func TestReadLogUnmarshalFailurePreservesHeadCountInvariant(t *testing.T) {
	dir := t.TempDir()
	id := NewRunID()
	path := filepath.Join(dir, id+".jsonl")
	c, err := ledger.Open(path, ledger.Unlocked)
	if err != nil {
		t.Fatal(err)
	}

	first := []byte(`{"time":"2026-09-19T00:00:00Z","type":"workflow_started","binding":{"invoker":{"subject":"x","issuer":"local","method":"asserted"},"role":"r","workflow":"w","run_id":"` + id + `"},"prev":""}`)
	if err := c.Append(first); err != nil {
		t.Fatal(err)
	}
	// Ledger-valid (correct "prev", well-formed JSON) but NOT decodable as
	// an Event: "time" is a bare number, and time.Time.UnmarshalJSON
	// requires a quoted string.
	second := []byte(`{"time":123,"type":"step_started","binding":{"invoker":{"subject":"x","issuer":"local","method":"asserted"},"role":"r","workflow":"w","run_id":"` + id + `"},"prev":"` + c.Prev() + `"}`)
	if err := c.Append(second); err != nil {
		t.Fatal(err)
	}
	// A third, fully valid record after the undecodable one: this is what
	// makes ledger.ReadVerify's own Head.Count (3, chain-valid throughout)
	// diverge from the number of Events ReadLog can actually decode (1).
	third := []byte(`{"time":"2026-09-19T00:00:02Z","type":"workflow_finished","status":"succeeded","binding":{"invoker":{"subject":"x","issuer":"local","method":"asserted"},"role":"r","workflow":"w","run_id":"` + id + `"},"prev":"` + c.Prev() + `"}`)
	if err := c.Append(third); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	events, head, err := ReadLog(dir, id)
	var broken *ledger.ChainBrokenError
	if !errors.As(err, &broken) {
		t.Fatalf("error must be a *ledger.ChainBrokenError, got: %T (%v)", err, err)
	}
	if broken.Line != 2 {
		t.Fatalf("error must name the undecodable record's line (2), got: %d", broken.Line)
	}
	if len(events) != 1 {
		t.Fatalf("only the first record decodes as an Event, got %d", len(events))
	}
	if head.Count != len(events) {
		t.Fatalf("head.Count must match len(events) even when a later ledger-valid record fails to decode: head=%+v events=%d", head, len(events))
	}
}

func TestEventToolFieldsRoundTrip(t *testing.T) {
	e := Event{Type: "tool_call", Tool: "echo", ArgsSHA: "deadbeef"}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"tool":"echo"`) || !strings.Contains(string(data), `"args_sha":"deadbeef"`) {
		t.Fatalf("expected tool/args_sha in JSON, got %s", data)
	}
	var got Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Tool != "echo" || got.ArgsSHA != "deadbeef" {
		t.Fatalf("round-trip lost fields: %+v", got)
	}
	// omitempty: a non-tool_call event carries neither key.
	empty, _ := json.Marshal(Event{Type: "step"})
	if strings.Contains(string(empty), `"tool":`) || strings.Contains(string(empty), `"args_sha":`) {
		t.Fatalf("omitempty violated: %s", empty)
	}
}

func TestEventExecFieldsRoundTrip(t *testing.T) {
	zero := 0
	e := Event{Type: "exec", Command: []string{"go", "test"}, ExitCode: &zero, OutputSHA: "abc", Mode: "attested"}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// exit 0 must be PRESENT (pointer), not omitted.
	if !strings.Contains(string(data), `"exit_code":0`) {
		t.Fatalf("exit 0 should be present: %s", data)
	}
	if !strings.Contains(string(data), `"command":["go","test"]`) || !strings.Contains(string(data), `"mode":"attested"`) {
		t.Fatalf("exec fields missing: %s", data)
	}
	var got Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ExitCode == nil || *got.ExitCode != 0 || len(got.Command) != 2 || got.Mode != "attested" || got.OutputSHA != "abc" {
		t.Fatalf("round-trip lost fields: %+v", got)
	}
	// omitempty: a non-exec event carries none of them.
	empty, _ := json.Marshal(Event{Type: "step"})
	for _, k := range []string{`"command":`, `"exit_code":`, `"output_sha":`, `"mode":`} {
		if strings.Contains(string(empty), k) {
			t.Fatalf("omitempty violated for %s: %s", k, empty)
		}
	}
}
