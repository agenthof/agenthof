package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/agenthof/agenthof/internal/artifact"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/registry"
	"github.com/agenthof/agenthof/internal/rungateway"
)

// askCfg is an orchestrator that may spawn the classifier and one leaf, with
// both targets present in the registry.
func askCfg() config.Config {
	return config.Config{
		Agents: []config.AgentDef{
			{Name: orchestratorAgent, Endpoint: "https://x", SourceFile: "a/orch.yaml",
				MaySpawn: []config.SpawnTarget{
					{Role: routerRole, Workflow: routerWorkflow},
					{Role: "dev", Workflow: "generic-chat"},
				}},
			{Name: "router", Endpoint: "https://x", SourceFile: "a/router.yaml"},
			{Name: "chat", Description: "a general chat agent", Endpoint: "https://x", SourceFile: "a/chat.yaml"},
		},
		Workflows: []config.WorkflowDef{
			{Name: "ask", SourceFile: "w/ask.yaml", Steps: []config.Step{{Name: "s", Agent: orchestratorAgent}}},
			{Name: routerWorkflow, Description: "classifies a request", SourceFile: "w/router.yaml", Steps: []config.Step{{Name: "s", Agent: "router"}}},
			{Name: "generic-chat", Description: "answers general questions", SourceFile: "w/chat.yaml", Steps: []config.Step{{Name: "s", Agent: "chat"}}},
		},
		Roles: []config.RoleDef{
			{Name: "orchestrator", Workflows: []string{"ask"}, AllowedGroups: []string{"*"}, SourceFile: "r/orch.yaml"},
			{Name: routerRole, Workflows: []string{routerWorkflow}, AllowedGroups: []string{"*"}, SourceFile: "r/router.yaml"},
			{Name: "dev", Workflows: []string{"generic-chat"}, AllowedGroups: []string{"*"}, SourceFile: "r/dev.yaml"},
		},
		Gateway: config.GatewayConfig{Spawn: config.SpawnPolicy{MaxDepth: 2, MaxParallel: 2, MaxTotalSpawns: 4}, SpawnSupervisor: "unix:///run/agenthof-spawn/refspawn.sock"},
	}
}

// answerSpawner is a stub Spawner: it records the input it was given and
// answers with a body stored in the artifact store, as a real child does.
type answerSpawner struct {
	store  *artifact.Store
	answer string
	mu     sync.Mutex
	input  string
	role   string
	wf     string
}

func (s *answerSpawner) Spawn(_ context.Context, role, workflow, input string, _ engine.Binding) (rungateway.SpawnResult, error) {
	s.mu.Lock()
	s.input, s.role, s.wf = input, role, workflow
	s.mu.Unlock()
	sha, prev, err := s.store.Put(s.answer)
	if err != nil {
		return rungateway.SpawnResult{}, err
	}
	return rungateway.SpawnResult{ChildRunID: "r-child", Status: "succeeded", OutputSHA: sha, OutputPreview: prev, Provisioned: true}, nil
}

func newAskFixture(t *testing.T, answer string) (*rungateway.Gateway, *answerSpawner, config.AgentDef, *registry.Registry, *artifact.Store) {
	t.Helper()
	cfg := askCfg()
	reg, errs := registry.Build(cfg)
	if len(errs) > 0 {
		t.Fatalf("registry: %v", errs)
	}
	store, err := artifact.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sp := &answerSpawner{store: store, answer: answer}
	gw := rungateway.New(cfg.Gateway, ".", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "").WithSpawner(sp)
	orch, ok := reg.Agent(orchestratorAgent)
	if !ok {
		t.Fatal("no orchestrator agent")
	}
	return gw, sp, orch, reg, store
}

func classifyFor(t *testing.T, answer, prompt string) (role, wf string, matched bool, sp *answerSpawner) {
	t.Helper()
	gw, sp, orch, reg, store := newAskFixture(t, answer)
	bind := engine.Binding{Role: orchestratorRole, Workflow: askWorkflow, RunID: "r-orch"}
	var events []engine.Event
	role, wf, matched, err := classify(context.Background(), gw, bind, orch, projectMenu(orch, reg), prompt, store,
		func(e engine.Event) { events = append(events, e) }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if len(events) != 1 || events[0].Type != "spawn" || events[0].ChildRole != routerRole {
		t.Fatalf("want one parent spawn event for the classifier, got %+v", events)
	}
	return role, wf, matched, sp
}

func TestProjectMenuFromMaySpawn(t *testing.T) {
	_, _, orch, reg, _ := newAskFixture(t, "null")
	got := projectMenu(orch, reg)
	want := []menuEntry{{Role: "dev", Workflow: "generic-chat", Description: "answers general questions"}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("menu = %+v, want %+v (the classifier itself is not a menu choice)", got, want)
	}
}

func TestClassifyInputEnvelopeIsFrozenShape(t *testing.T) {
	_, _, _, sp := classifyFor(t, "null", "what is a goroutine?")
	if sp.role != routerRole || sp.wf != routerWorkflow {
		t.Fatalf("spawned %s/%s, want the classifier", sp.role, sp.wf)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(sp.input), &top); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	if len(top) != 2 {
		t.Fatalf("envelope keys = %v, want exactly menu and utterance", top)
	}
	var utterance string
	if err := json.Unmarshal(top["utterance"], &utterance); err != nil || utterance != "what is a goroutine?" {
		t.Fatalf("utterance = %q (%v)", utterance, err)
	}
	var menu []map[string]string
	if err := json.Unmarshal(top["menu"], &menu); err != nil {
		t.Fatal(err)
	}
	if len(menu) != 1 || len(menu[0]) != 3 ||
		menu[0]["role"] != "dev" || menu[0]["workflow"] != "generic-chat" || menu[0]["description"] != "answers general questions" {
		t.Fatalf("menu = %v", menu)
	}
}

func TestClassifyParsesPickAndNull(t *testing.T) {
	role, wf, matched, _ := classifyFor(t, `{"role":"dev","workflow":"generic-chat"}`, "hi")
	if !matched || role != "dev" || wf != "generic-chat" {
		t.Fatalf("pick = %v %q %q", matched, role, wf)
	}
	_, _, matched, _ = classifyFor(t, "null", "hi")
	if matched {
		t.Fatal("null must be no match")
	}
}

func TestClassifyMalformedAnswerIsAnError(t *testing.T) {
	gw, _, orch, reg, store := newAskFixture(t, `{"role":"dev"}`)
	_, _, matched, err := classify(context.Background(), gw, engine.Binding{RunID: "r-orch"}, orch, projectMenu(orch, reg), "hi", store,
		func(engine.Event) {}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || matched {
		t.Fatalf("a pick missing its workflow must be an error, got matched=%v err=%v", matched, err)
	}
}

// stubSpawner returns a fixed outcome, for the fail-closed paths.
type stubSpawner struct {
	res rungateway.SpawnResult
	err error
}

func (s stubSpawner) Spawn(context.Context, string, string, string, engine.Binding) (rungateway.SpawnResult, error) {
	return s.res, s.err
}

func TestClassifyFailsClosed(t *testing.T) {
	missing := "0000000000000000000000000000000000000000000000000000000000000000"
	cases := []struct {
		name string
		sp   stubSpawner
	}{
		{"spawner error", stubSpawner{res: rungateway.SpawnResult{Status: "succeeded", OutputSHA: missing}, err: errors.New("boom")}},
		{"failed status", stubSpawner{res: rungateway.SpawnResult{Status: "failed", Provisioned: true}}},
		{"empty output sha", stubSpawner{res: rungateway.SpawnResult{Status: "succeeded", Provisioned: true}}},
		{"store miss", stubSpawner{res: rungateway.SpawnResult{Status: "succeeded", OutputSHA: missing, Provisioned: true}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, orch, reg, store := newAskFixture(t, "null")
			gw := rungateway.New(askCfg().Gateway, ".", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "").WithSpawner(c.sp)
			role, wf, matched, err := classify(context.Background(), gw, engine.Binding{RunID: "r-orch"}, orch, projectMenu(orch, reg), "hi", store,
				func(engine.Event) {}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err == nil || matched || role != "" || wf != "" {
				t.Fatalf("want an error and no pick, got %q %q matched=%v err=%v", role, wf, matched, err)
			}
		})
	}
}

// dispatchFor runs the gate for a pick against a fixture whose leaf agent has
// the given grounding, returning the output, exit code and the stub spawner.
func dispatchFor(t *testing.T, grounding, role, wf string, matched bool, yes bool, input string, answer string) (string, int, *answerSpawner, *artifact.Store) {
	t.Helper()
	cfg := askCfg()
	for i := range cfg.Agents {
		if cfg.Agents[i].Name == "chat" {
			cfg.Agents[i].Grounding = grounding
		}
	}
	reg, errs := registry.Build(cfg)
	if len(errs) > 0 {
		t.Fatalf("registry: %v", errs)
	}
	store, err := artifact.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sp := &answerSpawner{store: store, answer: answer}
	gw := rungateway.New(cfg.Gateway, ".", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "").WithSpawner(sp)
	orch, _ := reg.Agent(orchestratorAgent)
	var out strings.Builder
	_, _, code := dispatchPick(context.Background(), gw, engine.Binding{RunID: "r-orch"}, orch, reg, projectMenu(orch, reg),
		role, wf, matched, "hello", store, yes, strings.NewReader(input), &out, "r-orch",
		func(engine.Event) {}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return out.String(), code, sp, store
}

func TestGateConfirmsGenerated(t *testing.T) {
	out, code, sp, _ := dispatchFor(t, "generated", "dev", "generic-chat", true, false, "y\n", "the answer")
	if code != 0 || sp.role != "dev" || !strings.Contains(out, "the answer") {
		t.Fatalf("y must proceed: code=%d role=%q out=%q", code, sp.role, out)
	}
	out, code, sp, _ = dispatchFor(t, "generated", "dev", "generic-chat", true, false, "n\n", "the answer")
	if code == 0 || sp.role != "" || strings.Contains(out, "the answer") {
		t.Fatalf("n must abort with nothing spawned: code=%d role=%q out=%q", code, sp.role, out)
	}
}

func TestGateAutoRunsGrounded(t *testing.T) {
	out, code, sp, _ := dispatchFor(t, "grounded", "dev", "generic-chat", true, false, "", "grounded answer")
	if code != 0 || sp.role != "dev" || strings.Contains(out, "[y/N]") || !strings.Contains(out, "grounded answer") {
		t.Fatalf("grounded must run without a prompt: code=%d out=%q", code, out)
	}
}

func TestYesSkipsPrompt(t *testing.T) {
	out, code, sp, _ := dispatchFor(t, "generated", "dev", "generic-chat", true, true, "", "yes answer")
	if code != 0 || sp.role != "dev" || strings.Contains(out, "[y/N]") {
		t.Fatalf("--yes must proceed without asking: code=%d out=%q", code, out)
	}
}

func TestNonInteractiveWithoutYesRefuses(t *testing.T) {
	out, code, sp, _ := dispatchFor(t, "", "dev", "generic-chat", true, false, "", "x")
	if code == 0 || sp.role != "" || !strings.Contains(out, "--yes") {
		t.Fatalf("empty input without --yes must refuse cleanly: code=%d role=%q out=%q", code, sp.role, out)
	}
}

func TestAnswerReadFromStoreBySHA(t *testing.T) {
	out, code, sp, store := dispatchFor(t, "grounded", "dev", "generic-chat", true, false, "", "stored body")
	sha, _, err := store.Put(sp.answer)
	if err != nil {
		t.Fatal(err)
	}
	want, err := store.Get(sha)
	if err != nil || code != 0 || !strings.Contains(out, want) {
		t.Fatalf("printed answer must be the stored body %q: code=%d out=%q err=%v", want, code, out, err)
	}
}

func TestPickOutsideMaySpawnRefused(t *testing.T) {
	for _, p := range [][2]string{{routerRole, routerWorkflow}, {"dev", "nope"}, {"other", "generic-chat"}} {
		out, code, sp, _ := dispatchFor(t, "grounded", p[0], p[1], true, true, "", "x")
		if sp.role != "" || !strings.Contains(out, "Here is what I can do") || !strings.Contains(out, "dev/generic-chat") || strings.Contains(out, routerRole+"/") || code != 0 {
			t.Fatalf("pick %v must list the menu and spawn nothing: code=%d role=%q out=%q", p, code, sp.role, out)
		}
	}
	out, _, sp, _ := dispatchFor(t, "grounded", "", "", false, true, "", "x")
	if sp.role != "" || !strings.Contains(out, "Here is what I can do") {
		t.Fatalf("no match must list the menu: %q", out)
	}
}

func TestEmptyOrMissingAnswer(t *testing.T) {
	missing := "0000000000000000000000000000000000000000000000000000000000000000"
	for name, res := range map[string]rungateway.SpawnResult{
		"empty sha":  {Status: "succeeded", Provisioned: true},
		"store miss": {Status: "succeeded", OutputSHA: missing, Provisioned: true},
		"failed":     {Status: "failed", Provisioned: true},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, orch, reg, store := newAskFixture(t, "null")
			gw := rungateway.New(askCfg().Gateway, ".", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "").WithSpawner(stubSpawner{res: res})
			var out strings.Builder
			_, _, code := dispatchPick(context.Background(), gw, engine.Binding{RunID: "r-orch"}, orch, reg, projectMenu(orch, reg),
				"dev", "generic-chat", true, "hello", store, true, strings.NewReader(""), &out, "r-orch",
				func(engine.Event) {}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if code == 0 || strings.TrimSpace(out.String()) == "" {
				t.Fatalf("want a message and non-zero exit, got code=%d out=%q", code, out.String())
			}
		})
	}
}
