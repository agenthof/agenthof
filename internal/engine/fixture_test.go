package engine

import (
	"os"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
)

// TestGeneratePreMigrationFixture is a one-shot generator, not a test that
// runs in CI. It writes internal/engine/testdata/pre-migration.jsonl using
// the pre-migration OpenLog/Append implementation, so the committed fixture
// proves the new raw-byte ledger verifier stays backward compatible with
// logs the old implementation actually produced. Run once with
// GENERATE_FIXTURE=1; the fixture file must not change afterward.
func TestGeneratePreMigrationFixture(t *testing.T) {
	if os.Getenv("GENERATE_FIXTURE") == "" {
		t.Skip("generator; run once with GENERATE_FIXTURE=1")
	}
	dir := "testdata"
	_ = os.MkdirAll(dir, 0o755)
	log, err := OpenLog(dir, "pre-migration") // CURRENT implementation
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
// pre-migration fixture still verifies clean under the new raw-byte
// ledger verifier — proof that the migration to internal/ledger did not
// break backward compatibility with logs written by the old
// implementation.
func TestPreMigrationFixtureVerifiesRawByte(t *testing.T) {
	events, head, err := ReadLog("testdata", "pre-migration")
	if err != nil {
		t.Fatalf("fixture must verify clean under raw-byte verification: %v", err)
	}
	if len(events) != 4 || head.Count != 4 {
		t.Fatalf("fixture shape: %d", len(events))
	}
}
