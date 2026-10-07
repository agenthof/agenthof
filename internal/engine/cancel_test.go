package engine

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/identity"
)

// cancelThenFailExec cancels the run's own context from inside the step and
// reports the step failed with a transport-shaped error — what a fronted
// adapter returns when the run is cancelled under it mid-request.
type cancelThenFailExec struct{ cancel context.CancelFunc }

func (c cancelThenFailExec) Execute(_ context.Context, _ Binding, _ config.AgentDef, _ string, _ map[string]string) (StepResult, error) {
	c.cancel()
	return StepResult{}, errors.New(`Post "http://agent/run": context canceled`)
}

func TestRunCancelledMidStepRecordsCancelledNotFailed(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res, err := Run(ctx, engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), cancelThenFailExec{cancel: cancel}, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err != nil || res.Status != "cancelled" {
		t.Fatalf("res=%+v err=%v, want status cancelled and no error", res, err)
	}
	events, _, err := ReadLog(dir, res.RunID)
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, e := range events {
		types = append(types, e.Type)
	}
	want := []string{"workflow_started", "step_started", "step_failed", "workflow_finished"}
	if !slices.Equal(types, want) {
		t.Fatalf("events = %v, want %v (step_failed still precedes the cancelled finish; no fail-back)", types, want)
	}
	last := events[len(events)-1]
	if last.Status != "cancelled" || last.Reason != "run cancelled" {
		t.Fatalf("last = %+v, want workflow_finished cancelled / run cancelled", last)
	}
}

// slowExec blocks until the STEP context ends and reports the step failed:
// a step timeout with the run context still live.
type slowExec struct{}

func (slowExec) Execute(ctx context.Context, _ Binding, _ config.AgentDef, _ string, _ map[string]string) (StepResult, error) {
	<-ctx.Done()
	return StepResult{}, ctx.Err()
}

func TestStepTimeoutWithLiveRunContextStillFails(t *testing.T) {
	dir := t.TempDir()
	res, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), slowExec{}, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), StepTimeout: 20 * time.Millisecond})
	if err != nil || res.Status != "failed" {
		t.Fatalf("res=%+v err=%v, want failed: a step deadline is not a run cancellation", res, err)
	}
	events, _, _ := ReadLog(dir, res.RunID)
	last := events[len(events)-1]
	if last.Type != "workflow_finished" || last.Status != "failed" || !strings.Contains(last.Reason, "deadline exceeded") {
		t.Fatalf("last = %+v, want workflow_finished failed with the step's deadline reason", last)
	}
}
