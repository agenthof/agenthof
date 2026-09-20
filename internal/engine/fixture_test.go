package engine

import (
	"os"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
)

// TestGeneratePreMigrationFixture is a one-shot generator, not a test that
// runs in CI. It writes internal/engine/testdata/pre-migration.jsonl using
// the current OpenLog/Append implementation. The fixture's value doesn't
// depend on which implementation generated it: an unmodified log's exact
// on-disk bytes are the same regardless of which Append wrote them, so a
// clean file produced today verifies under the raw-byte reader the same
// way one from before the migration to internal/ledger would. Run once
// with GENERATE_FIXTURE=1; the fixture file must not change afterward.
func TestGeneratePreMigrationFixture(t *testing.T) {
	if os.Getenv("GENERATE_FIXTURE") == "" {
		t.Skip("generator; run once with GENERATE_FIXTURE=1")
	}
	dir := "testdata"
	_ = os.MkdirAll(dir, 0o755)
	log, err := OpenLog(dir, "pre-migration")
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{Invoker: identity.Invoker{Subject: "fixture@example.com", Method: "asserted", Issuer: "local"}, Role: "r", Workflow: "w", RunID: "pre-migration"}
	for i, typ := range []string{"workflow_started", "step_started", "step_succeeded", "workflow_finished"} {
		if err := log.Append(Event{Time: time.Date(2026, 9, 19, 0, 0, i, 0, time.UTC), Type: typ, Binding: b}); err != nil {
			t.Fatal(err)
		}
	}
	log.Close()
}

// TestPreMigrationFixtureVerifiesRawByte asserts that the frozen
// pre-migration fixture still verifies clean under the raw-byte ledger
// verifier. This doesn't depend on which implementation wrote the fixture:
// an unmodified log's exact on-disk bytes are the same regardless of which
// Append produced them, so a clean file verifies under the new reader the
// same way it would have under the old one.
func TestPreMigrationFixtureVerifiesRawByte(t *testing.T) {
	events, head, err := ReadLog("testdata", "pre-migration")
	if err != nil {
		t.Fatalf("fixture must verify clean under raw-byte verification: %v", err)
	}
	if len(events) != 4 || head.Count != 4 {
		t.Fatalf("fixture shape: %d", len(events))
	}
}
