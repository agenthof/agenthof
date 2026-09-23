package agentrt

import (
	"context"
	"errors"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

// fakeExecutor records whether it was called and returns a fixed result.
type fakeExecutor struct {
	called bool
	result engine.StepResult
	err    error
}

func (f *fakeExecutor) Execute(ctx context.Context, _ engine.Binding, a config.AgentDef, input string, artifacts map[string]string) (engine.StepResult, error) {
	f.called = true
	return f.result, f.err
}

// TestMuxExecutor_Execute_Contained proves an explicit "contained" tier
// still dispatches to Contained. Validation rejects that tier; the arm
// remains until the mux itself is removed.
func TestMuxExecutor_Execute_Contained(t *testing.T) {
	contained := &fakeExecutor{result: engine.StepResult{Success: true, Artifact: "contained out"}}
	fronted := &fakeExecutor{result: engine.StepResult{Success: true, Artifact: "fronted out"}}
	mux := MuxExecutor{Contained: contained, Fronted: fronted}

	agentDef := config.AgentDef{Name: "a", Execution: "contained"}
	res, err := mux.Execute(context.Background(), engine.Binding{}, agentDef, "in", nil)
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if !contained.called {
		t.Errorf("contained executor was not called")
	}
	if fronted.called {
		t.Errorf("fronted executor should not have been called")
	}
	if res.Artifact != "contained out" {
		t.Errorf("Artifact = %q, want %q", res.Artifact, "contained out")
	}
}

// TestMuxExecutor_Execute_Fronted proves the "fronted" execution tier
// dispatches to Fronted and never touches Contained.
func TestMuxExecutor_Execute_Fronted(t *testing.T) {
	contained := &fakeExecutor{result: engine.StepResult{Success: true, Artifact: "contained out"}}
	fronted := &fakeExecutor{result: engine.StepResult{Success: true, Artifact: "fronted out"}}
	mux := MuxExecutor{Contained: contained, Fronted: fronted}

	agentDef := config.AgentDef{Name: "a", Execution: "fronted"}
	res, err := mux.Execute(context.Background(), engine.Binding{}, agentDef, "in", nil)
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	if contained.called {
		t.Errorf("contained executor should not have been called")
	}
	if !fronted.called {
		t.Errorf("fronted executor was not called")
	}
	if res.Artifact != "fronted out" {
		t.Errorf("Artifact = %q, want %q", res.Artifact, "fronted out")
	}
}

// TestMuxExecutor_Execute_UnknownTier proves an execution tier outside
// {"", "contained", "fronted"} — which validation should already reject,
// but the mux must still defend against — surfaces as an
// engine.ErrStepConfig-wrapping error, and calls neither executor.
func TestMuxExecutor_Execute_UnknownTier(t *testing.T) {
	contained := &fakeExecutor{result: engine.StepResult{Success: true}}
	fronted := &fakeExecutor{result: engine.StepResult{Success: true}}
	mux := MuxExecutor{Contained: contained, Fronted: fronted}

	agentDef := config.AgentDef{Name: "a", Execution: "weird"}
	_, err := mux.Execute(context.Background(), engine.Binding{}, agentDef, "in", nil)
	if err == nil {
		t.Fatalf("Execute: want error for unknown execution tier, got nil")
	}
	if !errors.Is(err, engine.ErrStepConfig) {
		t.Errorf("Execute error = %v, want it to wrap engine.ErrStepConfig", err)
	}
	if contained.called || fronted.called {
		t.Errorf("neither executor should be called for an unknown tier")
	}
}

// bindingCapture records the binding it was given.
type bindingCapture struct {
	got engine.Binding
}

func (b *bindingCapture) Execute(_ context.Context, binding engine.Binding, _ config.AgentDef, _ string, _ map[string]string) (engine.StepResult, error) {
	b.got = binding
	return engine.StepResult{Success: true}, nil
}

func TestMuxExecutor_ForwardsBinding(t *testing.T) {
	contained := &bindingCapture{}
	mux := MuxExecutor{Contained: contained, Fronted: &fakeExecutor{}}
	want := engine.Binding{Role: "se", Workflow: "wf", RunID: "run-1"}

	_, err := mux.Execute(context.Background(), want, config.AgentDef{Name: "a", Execution: "contained"}, "in", nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if contained.got.Role != want.Role || contained.got.Workflow != want.Workflow || contained.got.RunID != want.RunID {
		t.Errorf("forwarded binding = %+v, want %+v", contained.got, want)
	}
}

// TestMuxExecutor_ForwardsBinding_Fronted proves the "fronted" tier receives
// the binding the mux was given, exactly as the contained tier does.
func TestMuxExecutor_ForwardsBinding_Fronted(t *testing.T) {
	fronted := &bindingCapture{}
	mux := MuxExecutor{Contained: &fakeExecutor{}, Fronted: fronted}
	want := engine.Binding{Role: "se", Workflow: "wf", RunID: "run-1"}

	_, err := mux.Execute(context.Background(), want, config.AgentDef{Name: "a", Execution: "fronted"}, "in", nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if fronted.got.Role != want.Role || fronted.got.Workflow != want.Workflow || fronted.got.RunID != want.RunID {
		t.Errorf("forwarded binding = %+v, want %+v", fronted.got, want)
	}
}
