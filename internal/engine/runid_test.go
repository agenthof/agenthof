package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/agenthof/agenthof/internal/identity"
)

func TestRunUsesTheGivenRunID(t *testing.T) {
	dir := t.TempDir()
	id := NewRunID()
	res, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), &fakeExec{fail: map[string]int{}}, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), RunID: id})
	if err != nil || res.RunID != id {
		t.Fatalf("res=%+v err=%v, want the run recorded under %s", res, err, id)
	}
	events, _, err := ReadLog(dir, id)
	if err != nil || len(events) == 0 || events[0].Binding.RunID != id {
		t.Fatalf("events under %s: %v %+v", id, err, events)
	}
	// A refusal under a given id records under it too.
	res, _ = Run(context.Background(), engCfg(), "nobody", "fix-bug", "x",
		identity.Static("dev@x"), &fakeExec{fail: map[string]int{}}, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), RunID: "r-given01"})
	if res.Status != "refused" || res.RunID != "r-given01" {
		t.Fatalf("res=%+v, want refused under r-given01", res)
	}
}
