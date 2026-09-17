package engine

import (
	"context"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/registry"
)

type fakeExec struct {
	calls []string
	fail  map[string]int // agent name -> number of times to fail before succeeding
	seen  []map[string]string
}

func (f *fakeExec) Execute(ctx context.Context, agent config.AgentDef, input string, artifacts map[string]string) (StepResult, error) {
	f.calls = append(f.calls, agent.Name)
	cp := map[string]string{}
	for k, v := range artifacts {
		cp[k] = v
	}
	f.seen = append(f.seen, cp)
	if n := f.fail[agent.Name]; n > 0 {
		f.fail[agent.Name] = n - 1
		return StepResult{Success: false, Reason: "synthetic failure"}, nil
	}
	return StepResult{Success: true, Artifact: "artifact-from-" + agent.Name}, nil
}

func engCfg() *registry.Registry {
	cfg := config.Config{
		Agents: []config.AgentDef{
			{Name: "planner", Model: "fast", Output: "plan", SourceFile: "a"},
			{Name: "coder", Model: "fast", Output: "patch", SourceFile: "b"},
			{Name: "reviewer", Model: "fast", Output: "review", SourceFile: "c"},
		},
		Workflows: []config.WorkflowDef{{
			Name: "fix-bug", SourceFile: "w",
			Steps: []config.Step{
				{Name: "plan", Agent: "planner"},
				{Name: "code", Agent: "coder", OnFailure: "plan"},
				{Name: "review", Agent: "reviewer", OnFailure: "code", MaxBounces: 1},
			},
		}},
		Roles: []config.RoleDef{{Name: "se", Workflows: []string{"fix-bug"}, SourceFile: "r"}},
		Gateway: config.GatewayConfig{Models: map[string]config.ModelRoute{
			"fast": {Endpoint: "https://x/v1", Model: "m", APIKeyEnv: "K"},
		}},
	}
	reg, errs := registry.Build(cfg)
	if reg == nil {
		panic(errs)
	}
	return reg
}

func TestRunHappyPath(t *testing.T) {
	dir := t.TempDir()
	ex := &fakeExec{fail: map[string]int{}}
	id, status, err := Run(context.Background(), engCfg(), "se", "fix-bug", "fix the login bug",
		identity.Static("dev@x"), ex, Options{LogDir: dir})
	if err != nil || status != "succeeded" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	if len(ex.calls) != 3 || ex.calls[0] != "planner" || ex.calls[2] != "reviewer" {
		t.Fatalf("calls: %v", ex.calls)
	}
	if ex.seen[1]["plan"] != "artifact-from-planner" {
		t.Fatalf("coder must receive the planner's artifact: %v", ex.seen[1])
	}
	events, err := ReadLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, e := range events {
		types = append(types, e.Type)
		if e.Binding.Invoker.Subject != "dev@x" {
			t.Fatal("every event must carry the invoker")
		}
	}
	want := []string{"workflow_started", "step_started", "step_succeeded", "step_started", "step_succeeded", "step_started", "step_succeeded", "workflow_finished"}
	if len(types) != len(want) {
		t.Fatalf("types: %v", types)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("event %d = %s, want %s (%v)", i, types[i], want[i], types)
		}
	}
}

func TestRunRefusals(t *testing.T) {
	dir := t.TempDir()
	ex := &fakeExec{fail: map[string]int{}}
	cases := []struct{ role, wf string }{
		{"ghost", "fix-bug"},
		{"se", "ghost"},
	}
	for _, c := range cases {
		id, status, err := Run(context.Background(), engCfg(), c.role, c.wf, "x",
			identity.Static("dev@x"), ex, Options{LogDir: dir})
		if err == nil || status != "refused" {
			t.Fatalf("%v: status=%q err=%v", c, status, err)
		}
		events, rerr := ReadLog(dir, id)
		if rerr != nil || len(events) != 1 || events[0].Type != "run_refused" {
			t.Fatalf("%v: refusals must be ledgered as exactly one run_refused event: %v %v", c, events, rerr)
		}
	}
	if len(ex.calls) != 0 {
		t.Fatal("refusal must happen before any execution")
	}
}
