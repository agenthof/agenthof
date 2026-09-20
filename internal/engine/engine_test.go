package engine

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	maps.Copy(cp, artifacts)
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
		identity.Static("dev@x"), ex, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err != nil || status != "succeeded" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	if len(ex.calls) != 3 || ex.calls[0] != "planner" || ex.calls[2] != "reviewer" {
		t.Fatalf("calls: %v", ex.calls)
	}
	if ex.seen[1]["plan"] != "artifact-from-planner" {
		t.Fatalf("coder must receive the planner's artifact: %v", ex.seen[1])
	}
	events, _, err := ReadLog(dir, id)
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
			identity.Static("dev@x"), ex, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
		if err == nil || status != "refused" {
			t.Fatalf("%v: status=%q err=%v", c, status, err)
		}
		events, _, rerr := ReadLog(dir, id)
		if rerr != nil || len(events) != 1 || events[0].Type != "run_refused" {
			t.Fatalf("%v: refusals must be ledgered as exactly one run_refused event: %v %v", c, events, rerr)
		}
	}
	if len(ex.calls) != 0 {
		t.Fatal("refusal must happen before any execution")
	}
}

func TestRunFailBackThenSucceed(t *testing.T) {
	dir := t.TempDir()
	ex := &fakeExec{fail: map[string]int{"coder": 1}} // coder fails once, then succeeds
	id, status, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), ex, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err != nil || status != "succeeded" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	// planner, coder(fail), planner(again), coder, reviewer
	want := []string{"planner", "coder", "planner", "coder", "reviewer"}
	if len(ex.calls) != len(want) {
		t.Fatalf("calls: %v", ex.calls)
	}
	events, _, _ := ReadLog(dir, id)
	var bounced *Event
	for i := range events {
		if events[i].Type == "bounced_back" {
			bounced = &events[i]
		}
	}
	if bounced == nil || bounced.Step != "code" || bounced.Status != "plan" {
		t.Fatalf("bounced_back must record failing step and target: %+v", bounced)
	}
}

func TestRunBounceExhaustion(t *testing.T) {
	dir := t.TempDir()
	ex := &fakeExec{fail: map[string]int{"reviewer": 99}} // reviewer max_bounces: 1
	id, status, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), ex, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err != nil || status != "failed" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	events, _, _ := ReadLog(dir, id)
	last := events[len(events)-1]
	if last.Type != "workflow_finished" || last.Status != "failed" || !strings.Contains(last.Reason, "review") {
		t.Fatalf("exhaustion must fail honestly naming the step: %+v", last)
	}
}

func TestRunFirstStepFailureFails(t *testing.T) {
	dir := t.TempDir()
	ex := &fakeExec{fail: map[string]int{"planner": 99}}
	_, status, _ := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), ex, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if status != "failed" {
		t.Fatalf("first-step failure with no fail-back target must fail, got %q", status)
	}
}

type hangExec struct{}

func (hangExec) Execute(ctx context.Context, agent config.AgentDef, input string, artifacts map[string]string) (StepResult, error) {
	<-ctx.Done()
	return StepResult{}, ctx.Err()
}

func TestRunStepTimeout(t *testing.T) {
	dir := t.TempDir()
	_, status, _ := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), hangExec{}, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), StepTimeout: 50 * time.Millisecond})
	if status != "failed" {
		t.Fatalf("timeout must fail the run, got %q", status)
	}
}

func TestRunStoresArtifactsOutOfLedger(t *testing.T) {
	dir := t.TempDir()
	arts := filepath.Join(dir, "arts")
	ex := &fakeExec{fail: map[string]int{}}
	id, status, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), ex, Options{LogDir: dir, ArtifactDir: arts})
	if err != nil || status != "succeeded" {
		t.Fatalf("%q %v", status, err)
	}
	events, _, _ := ReadLog(dir, id)
	var succ []Event
	for _, e := range events {
		if e.Type == "step_succeeded" {
			succ = append(succ, e)
		}
	}
	if len(succ) != 3 {
		t.Fatalf("succ: %d", len(succ))
	}
	for _, e := range succ {
		if len(e.ArtifactSHA) != 64 {
			t.Fatalf("sha missing: %+v", e)
		}
		if strings.Contains(e.Artifact, "\n") {
			t.Fatal("ledger artifact must be a preview")
		}
		body, err := os.ReadFile(filepath.Join(arts, e.ArtifactSHA))
		if err != nil {
			t.Fatalf("body not stored: %v", err)
		}
		if !strings.HasPrefix(string(body), "artifact-from-") {
			t.Fatalf("body: %s", body)
		}
	}
	if _, _, err := ReadLog(dir, id); err != nil {
		t.Fatalf("chain: %v", err)
	}
	// full bodies still flow to later steps in memory
	if ex.seen[1]["plan"] != "artifact-from-planner" {
		t.Fatalf("in-memory chain broke: %v", ex.seen[1])
	}
}

func rbacCfg() *registry.Registry {
	cfg := config.Config{
		Agents: []config.AgentDef{
			{Name: "planner", Model: "fast", Output: "plan", SourceFile: "a"},
		},
		Workflows: []config.WorkflowDef{{
			Name: "simple", SourceFile: "w",
			Steps: []config.Step{{Name: "plan", Agent: "planner"}},
		}},
		Roles: []config.RoleDef{{Name: "fin", Workflows: []string{"simple"}, AllowedGroups: []string{"finance"}, SourceFile: "r"}},
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

func TestRunRBACRefusesWrongGroup(t *testing.T) {
	dir := t.TempDir()
	ex := &fakeExec{fail: map[string]int{}}
	inv := identity.Invoker{Subject: "dev@x", Groups: []string{"engineering"}}
	id, status, err := Run(context.Background(), rbacCfg(), "fin", "simple", "x", inv, ex,
		Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err == nil || status != "refused" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	events, _, rerr := ReadLog(dir, id)
	if rerr != nil || len(events) != 1 || events[0].Type != "run_refused" {
		t.Fatalf("RBAC refusal must be ledgered as exactly one run_refused event: %v %v", events, rerr)
	}
	reason := events[0].Reason
	if !strings.Contains(reason, "fin") {
		t.Fatalf("reason must name the role: %q", reason)
	}
	if !strings.Contains(reason, "allowed groups") {
		t.Fatalf("reason must mention allowed groups: %q", reason)
	}
	if strings.Contains(reason, "engineering") {
		t.Fatalf("reason must never leak the invoker's groups: %q", reason)
	}
	if len(ex.calls) != 0 {
		t.Fatal("RBAC refusal must happen before any execution")
	}
}

func TestRunRBACAllowsMatchingGroup(t *testing.T) {
	dir := t.TempDir()
	ex := &fakeExec{fail: map[string]int{}}
	inv := identity.Invoker{Subject: "dev@x", Groups: []string{"finance"}}
	_, status, err := Run(context.Background(), rbacCfg(), "fin", "simple", "x", inv, ex,
		Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err != nil || status != "succeeded" {
		t.Fatalf("status=%q err=%v", status, err)
	}
}

func TestRunRBACEmptyAllowedGroupsAllowsAnyInvoker(t *testing.T) {
	dir := t.TempDir()
	ex := &fakeExec{fail: map[string]int{}}
	// engCfg's "se" role has nil AllowedGroups: backward compat, any invoker runs.
	_, status, err := Run(context.Background(), engCfg(), "se", "fix-bug", "fix the login bug",
		identity.Static("dev@x"), ex, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err != nil || status != "succeeded" {
		t.Fatalf("status=%q err=%v", status, err)
	}
}

// configErrExec fails the "coder" step with an error wrapping ErrStepConfig,
// and records every call so the test can assert the fail-back step ("plan")
// was never re-attempted.
type configErrExec struct {
	calls []string
}

func (f *configErrExec) Execute(_ context.Context, agent config.AgentDef, _ string, _ map[string]string) (StepResult, error) {
	f.calls = append(f.calls, agent.Name)
	if agent.Name == "coder" {
		return StepResult{}, fmt.Errorf("no route: %w", ErrStepConfig)
	}
	return StepResult{Success: true, Artifact: "artifact-from-" + agent.Name}, nil
}

func TestRunStepConfigErrorFailsWithoutBouncing(t *testing.T) {
	dir := t.TempDir()
	ex := &configErrExec{}
	id, status, err := Run(context.Background(), engCfg(), "se", "fix-bug", "x",
		identity.Static("dev@x"), ex, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err != nil || status != "failed" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	if len(ex.calls) != 2 || ex.calls[0] != "planner" || ex.calls[1] != "coder" {
		t.Fatalf("fail-back step must not be re-attempted after a config error: %v", ex.calls)
	}
	events, _, _ := ReadLog(dir, id)
	var types []string
	for _, e := range events {
		types = append(types, e.Type)
		if e.Type == "bounced_back" {
			t.Fatal("config errors must not burn bounces")
		}
	}
	want := []string{"workflow_started", "step_started", "step_succeeded", "step_started", "step_failed", "workflow_finished"}
	if len(types) != len(want) {
		t.Fatalf("types: %v", types)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("event %d = %s, want %s (%v)", i, types[i], want[i], types)
		}
	}
	last := events[len(events)-1]
	if last.Status != "failed" || !strings.Contains(last.Reason, "no route") {
		t.Fatalf("workflow_finished must fail honestly naming the config error: %+v", last)
	}
}

func TestWorkflowStartedCarriesConfigHash(t *testing.T) {
	dir := t.TempDir()
	ex := &fakeExec{fail: map[string]int{}}
	id, status, err := Run(context.Background(), engCfg(), "se", "fix-bug", "fix the login bug",
		identity.Static("dev@x"), ex, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts"), ConfigHash: "sha256:deadbeef"})
	if err != nil || status != "succeeded" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	events, _, _ := ReadLog(dir, id)
	found := false
	for _, e := range events {
		if e.Type == "workflow_started" {
			found = true
			if e.ConfigHash != "sha256:deadbeef" {
				t.Fatalf("workflow_started config_hash = %q", e.ConfigHash)
			}
		} else if e.ConfigHash != "" {
			t.Fatalf("%s must not carry config_hash", e.Type)
		}
	}
	if !found {
		t.Fatal("workflow_started event not found in log")
	}
}

func TestRunEventsCarryExecutionTier(t *testing.T) {
	dir := t.TempDir()
	ex := &fakeExec{fail: map[string]int{}}
	id, status, err := Run(context.Background(), engCfg(), "se", "fix-bug", "fix the login bug",
		identity.Static("dev@x"), ex, Options{LogDir: dir, ArtifactDir: filepath.Join(dir, "arts")})
	if err != nil || status != "succeeded" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	events, _, _ := ReadLog(dir, id)
	seen := 0
	for _, e := range events {
		if e.Type == "step_started" || e.Type == "step_succeeded" {
			seen++
			// engCfg's agents have no execution field set, so
			// EffectiveExecution() must normalize to "contained".
			if e.Execution != "contained" {
				t.Fatalf("event %+v must carry execution tier %q", e, "contained")
			}
		}
	}
	if seen != 6 { // 3 steps x (started, succeeded)
		t.Fatalf("expected 6 step events, saw %d", seen)
	}
}
