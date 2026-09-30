package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/identity"
)

func TestRunReportsFinalArtifact(t *testing.T) {
	dir := t.TempDir()
	res, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), &fakeExec{fail: map[string]int{}}, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err != nil || res.Status != "succeeded" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	sum := sha256.Sum256([]byte("artifact-from-reviewer"))
	if res.OutputSHA != hex.EncodeToString(sum[:]) {
		t.Fatalf("OutputSHA = %q, want the sha of the LAST step's artifact", res.OutputSHA)
	}
	if res.OutputPreview != "artifact-from-reviewer" {
		t.Fatalf("OutputPreview = %q", res.OutputPreview)
	}
	if res.RunID == "" {
		t.Fatal("no run id")
	}
}

func TestRunFailedReportsNoArtifact(t *testing.T) {
	dir := t.TempDir()
	res, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), &fakeExec{fail: map[string]int{"planner": 5}}, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err != nil || res.Status != "failed" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if res.OutputSHA != "" || res.OutputPreview != "" {
		t.Fatalf("a failed run must report no artifact: %+v", res)
	}
}

// cancelExec cancels the run's own context from inside the first step, the
// way a parent's teardown reaches a spawned child mid-run.
type cancelExec struct{ cancel context.CancelFunc }

func (c cancelExec) Execute(_ context.Context, _ Binding, _ config.AgentDef, _ string, _ map[string]string) (StepResult, error) {
	c.cancel()
	return StepResult{Success: true, Artifact: "a"}, nil
}

func TestRunExitsEarlyWhenContextCancelled(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res, err := Run(ctx, engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), cancelExec{cancel: cancel}, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err != nil || res.Status != "cancelled" {
		t.Fatalf("res=%+v err=%v, want status cancelled and no error", res, err)
	}
	events, _, err := ReadLog(dir, res.RunID)
	if err != nil {
		t.Fatal(err)
	}
	started := 0
	for _, e := range events {
		if e.Type == "step_started" {
			started++
		}
	}
	if started != 1 {
		t.Fatalf("%d steps started after the context was cancelled, want the loop to stop after the first", started)
	}
	last := events[len(events)-1]
	if last.Type != "workflow_finished" || last.Status != "cancelled" || last.Reason != "run cancelled" {
		t.Fatalf("last event = %+v, want workflow_finished cancelled / run cancelled", last)
	}
}
