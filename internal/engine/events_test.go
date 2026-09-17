package engine

import (
	"encoding/json"
	"errors"
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

func TestVerifyChainValid(t *testing.T) {
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
	if len(got) != 3 {
		t.Fatalf("expected 3 events, got %d", len(got))
	}
	if got[0].Prev != "" {
		t.Fatalf("genesis event Prev must be empty, got %q", got[0].Prev)
	}
	if err := VerifyChain(got); err != nil {
		t.Fatalf("VerifyChain on valid chain: %v", err)
	}

	// Corrupt the middle event; the successor's Prev no longer matches.
	got[1].Reason = "tampered"
	err = VerifyChain(got)
	if err == nil {
		t.Fatal("VerifyChain must fail on tampered chain")
	}
	var broken *ChainBrokenError
	if !errors.As(err, &broken) {
		t.Fatalf("error must be a *ChainBrokenError, got: %T (%v)", err, err)
	}
	if broken.Index != 2 {
		t.Fatalf("error must name broken index 2, got: %d", broken.Index)
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
	events, err := ReadLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.ArtifactSHA != "" {
			t.Fatal("no event should carry a sha here")
		}
	}
	if err := VerifyChain(events); err != nil {
		t.Fatalf("chain must verify with omitted artifact_sha: %v", err)
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
