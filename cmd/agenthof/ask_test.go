package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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
