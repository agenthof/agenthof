package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/artifact"
	"github.com/agenthof/agenthof/internal/completeness"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
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

// askSpawn wraps a gateway as the orchestrator's spawnFunc for tests, without
// the door counting or fail-closed latch cmdAsk layers on in production.
func askSpawn(gw *rungateway.Gateway, bind engine.Binding, orch config.AgentDef, appendEvent func(engine.Event)) spawnFunc {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return func(ctx context.Context, role, workflow, input string) (rungateway.SpawnResult, error) {
		return gw.AuthorizeAndSpawn(ctx, bind, orch, role, workflow, input, appendEvent, logger)
	}
}

func classifyFor(t *testing.T, answer, prompt string) (role, wf string, matched bool, sp *answerSpawner) {
	t.Helper()
	gw, sp, orch, reg, store := newAskFixture(t, answer)
	bind := engine.Binding{Role: orchestratorRole, Workflow: askWorkflow, RunID: "r-orch"}
	var events []engine.Event
	spawn := askSpawn(gw, bind, orch, func(e engine.Event) { events = append(events, e) })
	role, wf, matched, err := classify(context.Background(), spawn, projectMenu(orch, reg), prompt, store)
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
	spawn := askSpawn(gw, engine.Binding{RunID: "r-orch"}, orch, func(engine.Event) {})
	_, _, matched, err := classify(context.Background(), spawn, projectMenu(orch, reg), "hi", store)
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
			spawn := askSpawn(gw, engine.Binding{RunID: "r-orch"}, orch, func(engine.Event) {})
			role, wf, matched, err := classify(context.Background(), spawn, projectMenu(orch, reg), "hi", store)
			if err == nil || matched || role != "" || wf != "" {
				t.Fatalf("want an error and no pick, got %q %q matched=%v err=%v", role, wf, matched, err)
			}
		})
	}
}

// pickEnv is a dispatch fixture: stdout and stderr are captured apart.
type pickEnv struct {
	out, msg strings.Builder
	code     int
	sp       *answerSpawner
	store    *artifact.Store
	served   servedLeaf
}

// runPick dispatches a pick against a fixture whose "chat" agent has the given
// grounding. interactive says whether stdin counts as a terminal.
func runPick(t *testing.T, grounding, role, wf string, matched, yes, interactive bool, input, answer string) *pickEnv {
	t.Helper()
	return runPickTools(t, grounding, nil, role, wf, matched, yes, interactive, input, answer)
}

// runPickTools is runPick with tool grants on the "chat" agent.
func runPickTools(t *testing.T, grounding string, tools []config.ToolGrant, role, wf string, matched, yes, interactive bool, input, answer string) *pickEnv {
	t.Helper()
	cfg := askCfg()
	if len(tools) > 0 {
		cfg.Gateway.Tools = map[string]config.ToolResource{
			"memory": {Kind: "mcp", URL: "https://mcp.example.com/", CredentialSource: "static_env", TokenEnv: "T",
				ReadOnlyTools: []string{"memory_search"}},
		}
	}
	for i := range cfg.Agents {
		if cfg.Agents[i].Name == "chat" {
			cfg.Agents[i].Grounding = grounding
			cfg.Agents[i].Tools = tools
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
	e := &pickEnv{sp: &answerSpawner{store: store, answer: answer}, store: store}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	orch, _ := reg.Agent(orchestratorAgent)
	gw := rungateway.New(cfg.Gateway, ".", nil, logger, "").WithSpawner(e.sp)
	menu := projectMenu(orch, reg)
	_, _, e.code = dispatchPick(context.Background(), pickRun{
		spawn: askSpawn(gw, engine.Binding{RunID: "r-orch"}, orch, func(engine.Event) {}),
		reg:   reg, menu: menu, admitted: menu,
		prompt: "hello", store: store, yes: yes, interactive: interactive,
		in: strings.NewReader(input), out: &e.out, msg: &e.msg, runID: "r-orch",
		logger: logger, served: &e.served,
	}, role, wf, matched)
	return e
}

func TestGateConfirmsGenerated(t *testing.T) {
	e := runPick(t, "generated", "dev", "generic-chat", true, false, true, "y\n", "the answer")
	if e.code != 0 || e.sp.role != "dev" || strings.TrimSpace(e.out.String()) != "the answer" {
		t.Fatalf("y must proceed: code=%d role=%q out=%q", e.code, e.sp.role, e.out.String())
	}
	e = runPick(t, "generated", "dev", "generic-chat", true, false, true, "n\n", "the answer")
	if e.code == 0 || e.sp.role != "" || e.out.Len() != 0 {
		t.Fatalf("n must abort with nothing spawned: code=%d role=%q out=%q", e.code, e.sp.role, e.out.String())
	}
}

func TestGateAutoRunsGrounded(t *testing.T) {
	e := runPick(t, "grounded", "dev", "generic-chat", true, false, true, "", "grounded answer")
	if e.code != 0 || e.sp.role != "dev" || strings.Contains(e.msg.String(), "[y/N]") || strings.TrimSpace(e.out.String()) != "grounded answer" {
		t.Fatalf("grounded must run without a prompt: code=%d msg=%q out=%q", e.code, e.msg.String(), e.out.String())
	}
}

func TestYesSkipsPrompt(t *testing.T) {
	e := runPick(t, "generated", "dev", "generic-chat", true, true, false, "", "yes answer")
	if e.code != 0 || e.sp.role != "dev" || strings.Contains(e.msg.String(), "[y/N]") {
		t.Fatalf("--yes must proceed without asking: code=%d msg=%q", e.code, e.msg.String())
	}
}

func TestNonInteractiveWithoutYesRefuses(t *testing.T) {
	// A non-terminal stdin is never read as consent, even when it says "y".
	for _, input := range []string{"", "y\n"} {
		e := runPick(t, "", "dev", "generic-chat", true, false, false, input, "x")
		if e.code == 0 || e.sp.role != "" || !strings.Contains(e.msg.String(), "--yes") || e.out.Len() != 0 {
			t.Fatalf("non-terminal without --yes must refuse (input %q): code=%d role=%q msg=%q", input, e.code, e.sp.role, e.msg.String())
		}
	}
	// A terminal that yields nothing is a refusal too, not a hang.
	e := runPick(t, "", "dev", "generic-chat", true, false, true, "", "x")
	if e.code == 0 || e.sp.role != "" || !strings.Contains(e.msg.String(), "--yes") {
		t.Fatalf("empty terminal input must refuse: code=%d msg=%q", e.code, e.msg.String())
	}
}

func TestConfirmCancelledByContext(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var ok bool
	var err error
	go func() {
		ok, err = confirm(ctx, io.Discard, pr, false, "run?")
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("confirm stayed blocked after cancellation")
	}
	if ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled prompt must decline with the context error, got ok=%v err=%v", ok, err)
	}
}

func TestAnswerReadFromStoreBySHA(t *testing.T) {
	store, err := artifact.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := askCfg()
	// The spawner points at a known body while a decoy sits under another digest.
	e := &pickEnv{}
	reg, _ := registry.Build(cfg)
	orch, _ := reg.Agent(orchestratorAgent)
	known, _, err := store.Put("the known answer")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Put("a decoy body"); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sp := stubSpawner{res: rungateway.SpawnResult{Status: "succeeded", OutputSHA: known, Provisioned: true}}
	gw := rungateway.New(cfg.Gateway, ".", nil, logger, "").WithSpawner(sp)
	menu := projectMenu(orch, reg)
	_, _, code := dispatchPick(context.Background(), pickRun{
		spawn: askSpawn(gw, engine.Binding{RunID: "r-orch"}, orch, func(engine.Event) {}),
		reg:   reg, menu: menu, admitted: menu,
		prompt: "hello", store: store, yes: true, in: strings.NewReader(""), out: &e.out, msg: &e.msg,
		runID: "r-orch", logger: logger,
	}, "dev", "generic-chat", true)
	if code != 0 || e.out.String() != "the known answer\n" {
		t.Fatalf("printed answer must be exactly the body under the returned digest: code=%d out=%q", code, e.out.String())
	}
}

func TestPickOutsideMaySpawnRefused(t *testing.T) {
	for _, p := range [][2]string{{routerRole, routerWorkflow}, {"dev", "nope"}, {"other", "generic-chat"}} {
		e := runPick(t, "grounded", p[0], p[1], true, true, false, "", "x")
		m := e.msg.String()
		if e.sp.role != "" || !strings.Contains(m, "Here is what I can do") || !strings.Contains(m, "dev/generic-chat") || strings.Contains(m, routerRole+"/") || e.code != 0 || e.out.Len() != 0 {
			t.Fatalf("pick %v must list the menu and spawn nothing: code=%d role=%q msg=%q", p, e.code, e.sp.role, m)
		}
	}
	e := runPick(t, "grounded", "", "", false, true, false, "", "x")
	if e.sp.role != "" || !strings.Contains(e.msg.String(), "Here is what I can do") {
		t.Fatalf("no match must list the menu: %q", e.msg.String())
	}
}

func TestFailedSpawnNeverPrintsBody(t *testing.T) {
	cases := map[string]func(sha string) stubSpawner{
		"failed status with a stored answer": func(sha string) stubSpawner {
			return stubSpawner{res: rungateway.SpawnResult{Status: "failed", Reason: "boom", OutputSHA: sha, Provisioned: true}}
		},
		"spawner error with a stored answer": func(sha string) stubSpawner {
			return stubSpawner{res: rungateway.SpawnResult{Status: "succeeded", OutputSHA: sha}, err: errors.New("boom")}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := askCfg()
			reg, _ := registry.Build(cfg)
			orch, _ := reg.Agent(orchestratorAgent)
			st, err := artifact.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			sha, _, err := st.Put("SECRET BODY")
			if err != nil {
				t.Fatal(err)
			}
			e := &pickEnv{}
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			gw := rungateway.New(cfg.Gateway, ".", nil, logger, "").WithSpawner(mk(sha))
			menu := projectMenu(orch, reg)
			_, _, code := dispatchPick(context.Background(), pickRun{
				spawn: askSpawn(gw, engine.Binding{RunID: "r-orch"}, orch, func(engine.Event) {}),
				reg:   reg, menu: menu, admitted: menu,
				prompt: "hello", store: st, yes: true, in: strings.NewReader(""), out: &e.out, msg: &e.msg,
				runID: "r-orch", logger: logger,
			}, "dev", "generic-chat", true)
			if code != 1 || strings.Contains(e.out.String()+e.msg.String(), "SECRET BODY") {
				t.Fatalf("a failed spawn must exit 1 and print no body: code=%d out=%q msg=%q", code, e.out.String(), e.msg.String())
			}
		})
	}
}

func TestEmptyOrMissingAnswer(t *testing.T) {
	missing := "0000000000000000000000000000000000000000000000000000000000000000"
	cases := map[string]struct {
		body string // stored and returned when non-empty
		res  rungateway.SpawnResult
		want string
	}{
		"empty sha":  {res: rungateway.SpawnResult{Status: "succeeded", Provisioned: true}, want: "no answer"},
		"store miss": {res: rungateway.SpawnResult{Status: "succeeded", OutputSHA: missing, Provisioned: true}, want: "missing from the artifact store"},
		"empty body": {body: "  \n", want: "empty answer"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := askCfg()
			reg, _ := registry.Build(cfg)
			orch, _ := reg.Agent(orchestratorAgent)
			st, err := artifact.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			res := c.res
			if c.body != "" {
				sha, _, err := st.Put(c.body)
				if err != nil {
					t.Fatal(err)
				}
				res = rungateway.SpawnResult{Status: "succeeded", OutputSHA: sha, Provisioned: true}
			}
			e := &pickEnv{}
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			gw := rungateway.New(cfg.Gateway, ".", nil, logger, "").WithSpawner(stubSpawner{res: res})
			menu := projectMenu(orch, reg)
			_, _, code := dispatchPick(context.Background(), pickRun{
				spawn: askSpawn(gw, engine.Binding{RunID: "r-orch"}, orch, func(engine.Event) {}),
				reg:   reg, menu: menu, admitted: menu,
				prompt: "hello", store: st, yes: true, in: strings.NewReader(""), out: &e.out, msg: &e.msg,
				runID: "r-orch", logger: logger,
			}, "dev", "generic-chat", true)
			if code != 1 || !strings.Contains(e.msg.String(), c.want) || e.out.Len() != 0 {
				t.Fatalf("want exit 1 and %q, got code=%d msg=%q out=%q", c.want, code, e.msg.String(), e.out.String())
			}
		})
	}
}

func TestNeedsConfirmAnyStepOrUnknown(t *testing.T) {
	cfg := askCfg()
	cfg.Agents = append(cfg.Agents,
		config.AgentDef{Name: "g1", Endpoint: "https://x", Grounding: "grounded", SourceFile: "a/g1.yaml"},
		config.AgentDef{Name: "g2", Endpoint: "https://x", Grounding: "generated", SourceFile: "a/g2.yaml"})
	cfg.Workflows = append(cfg.Workflows,
		config.WorkflowDef{Name: "two-step", SourceFile: "w/two.yaml", Steps: []config.Step{{Name: "a", Agent: "g1"}, {Name: "b", Agent: "g2"}}},
		config.WorkflowDef{Name: "all-grounded", SourceFile: "w/ag.yaml", Steps: []config.Step{{Name: "a", Agent: "g1"}}})
	reg, errs := registry.Build(cfg)
	if len(errs) > 0 {
		t.Fatalf("registry: %v", errs)
	}
	if !needsConfirm(reg, "two-step") {
		t.Fatal("a workflow whose second agent is ungrounded must need confirmation")
	}
	if needsConfirm(reg, "all-grounded") {
		t.Fatal("an all-grounded workflow must not need confirmation")
	}
	if !needsConfirm(reg, "no-such-workflow") {
		t.Fatal("an unknown workflow must need confirmation")
	}
}

// receiptTools is the tool configuration the receipt fixtures classify
// against: on "memory", memory_search is read-only and anything else writes.
var receiptTools = map[string]config.ToolResource{
	"memory": {Kind: "mcp", ReadOnlyTools: []string{"memory_search"}},
}

// Door events as the leaf's doors record them, for the fixtures below. The
// leaf agent is "chat".
func chatCall(status string) engine.Event {
	return engine.Event{Type: "model_call", Agent: "chat", CallKind: "chat", Status: status, Model: "m"}
}

func embedCall(status string) engine.Event {
	return engine.Event{Type: "model_call", Agent: "chat", CallKind: "embeddings", Status: status, Model: "e"}
}

func toolCall(tool, status string) engine.Event {
	return engine.Event{Type: "tool_call", Agent: "chat", Tool: tool, Status: status, ResourcesTouched: []string{"memory"}}
}

// receiptLedgers writes the ledgers of an answered ask run with a plain chat
// leaf (one succeeded chat call). It returns the log dir.
func receiptLedgers(t *testing.T) string {
	t.Helper()
	return receiptLedgersAs(t, identity.Invoker{Subject: "dana@example.com", Method: "asserted"})
}

func receiptLedgersAs(t *testing.T, inv identity.Invoker) string {
	t.Helper()
	return receiptLedgersWith(t, inv, []engine.Event{chatCall("succeeded")})
}

// receiptLedgersWith writes an orchestrator ledger whose parent spawn events
// carry each child's containment tier, the classifier's child ledger (one
// succeeded chat call of its own — which must never count as the leaf's), and
// the leaf's child ledger with the given door events. It returns the log dir.
func receiptLedgersWith(t *testing.T, inv identity.Invoker, leafDoors []engine.Event) string {
	t.Helper()
	dir := t.TempDir()
	write := func(runID string, evs []engine.Event) {
		l, err := engine.OpenLog(dir, runID)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }()
		for _, e := range evs {
			e.Time = time.Now().UTC()
			if err := l.Append(e); err != nil {
				t.Fatal(err)
			}
		}
	}
	orch := engine.Binding{Invoker: inv, Role: orchestratorRole, Workflow: askWorkflow, RunID: "r-orch"}
	router := engine.Binding{Invoker: inv, Role: routerRole, Workflow: routerWorkflow, RunID: "r-router", ParentRunID: "r-orch", Depth: 1}
	child := engine.Binding{Invoker: inv, Role: "dev", Workflow: "generic-chat", RunID: "r-leaf", ParentRunID: "r-orch", Depth: 1}
	// Every ledger carries the step-window shape a real run writes (the
	// orchestrator's own from runOrchestration), so every door event sits
	// inside a step and the receipt reports completeness, not a gap.
	one, two, n := 1, 2, len(leafDoors)
	write("r-orch", []engine.Event{
		{Type: "workflow_started", Binding: orch, DoorAccounting: engine.DoorAccountingAdmission},
		{Type: "step_started", Binding: orch, Step: orchestrateStep, Agent: orchestratorAgent},
		{Type: "spawn", Binding: orch, ChildRunID: "r-router", ChildRole: routerRole, ChildWorkflow: routerWorkflow, Depth: 1,
			ChildConfiner: "podman", ChildConfinerOpts: []string{"userns"}},
		{Type: "spawn", Binding: orch, Status: "succeeded", ChildRunID: "r-leaf", ChildRole: "dev", ChildWorkflow: "generic-chat", Depth: 1,
			OutputSHA: "0a1b", ChildConfiner: "podman", ChildConfinerOpts: []string{"userns"}},
		{Type: "step_succeeded", Binding: orch, Step: orchestrateStep, DoorCalls: &two},
		{Type: "workflow_finished", Binding: orch, Status: "succeeded"},
	})
	write("r-router", []engine.Event{
		{Type: "workflow_started", Binding: router, DoorAccounting: engine.DoorAccountingAdmission},
		{Type: "step_started", Binding: router, Step: "s", Agent: routerRole},
		{Type: "model_call", Binding: router, Agent: routerRole, CallKind: "chat", Status: "succeeded", Model: "m"},
		{Type: "step_succeeded", Binding: router, Step: "s", DoorCalls: &one},
		{Type: "workflow_finished", Binding: router, Status: "succeeded"},
	})
	leaf := []engine.Event{
		{Type: "workflow_started", Binding: child, DoorAccounting: engine.DoorAccountingAdmission},
		{Type: "step_started", Binding: child, Step: "s", Agent: "chat"},
	}
	for _, d := range leafDoors {
		d.Binding = child
		leaf = append(leaf, d)
	}
	leaf = append(leaf,
		engine.Event{Type: "step_succeeded", Binding: child, Step: "s", DoorCalls: &n},
		engine.Event{Type: "workflow_finished", Binding: child, Status: "succeeded"})
	write("r-leaf", leaf)
	return dir
}

// leafOf is the answering leaf the fixtures describe: run r-leaf, agent
// "chat" with the given grounding stamp.
func leafOf(grounding string) servedLeaf {
	return servedLeaf{answered: true, runID: "r-leaf", agents: []config.AgentDef{{Name: "chat", Grounding: grounding}}}
}

func receiptFor(t *testing.T, grounding string) string {
	t.Helper()
	var b strings.Builder
	renderReceipt(&b, receiptLedgers(t), "r-orch", leafOf(grounding), receiptTools)
	return b.String()
}

// receiptWith renders the receipt of a leaf stamped grounding whose ledger
// recorded doors, split at the agent-asserted heading.
func receiptWith(t *testing.T, grounding string, doors ...engine.Event) (enforced, asserted string) {
	t.Helper()
	var b strings.Builder
	dir := receiptLedgersWith(t, identity.Invoker{Subject: "dana@example.com", Method: "asserted"}, doors)
	renderReceipt(&b, dir, "r-orch", leafOf(grounding), receiptTools)
	enforced, asserted, ok := strings.Cut(b.String(), "agent-asserted (")
	if !ok {
		t.Fatalf("no agent-asserted section:\n%s", b.String())
	}
	return enforced, asserted
}

// leafBlock returns the answering leaf's own lines of the enforced section:
// its "run r-leaf:" line and the indented facts under it, and nothing of any
// other run's (the classifier's block prints the same kinds of line).
func leafBlock(t *testing.T, enforced string) string {
	t.Helper()
	var b strings.Builder
	in := false
	for _, l := range strings.Split(enforced, "\n") {
		switch {
		case strings.Contains(l, " run r-leaf: "):
			in = true
		case in && !strings.HasPrefix(l, "    "):
			return b.String()
		}
		if in {
			b.WriteString(l + "\n")
		}
	}
	if !in {
		t.Fatalf("no block for run r-leaf:\n%s", enforced)
	}
	return b.String()
}

// provenanceLine returns the leaf agent's line in the agent-asserted
// section, or "" when the receipt prints none.
func provenanceLine(asserted string) string {
	for _, l := range strings.Split(asserted, "\n") {
		if strings.HasPrefix(l, "  chat: ") {
			return l
		}
	}
	return ""
}

// An ingest leaf writes and never generates: the receipt counts its succeeded
// writes from the ledger and prints no provenance line — whatever its stamp,
// and although the classifier beside it made a succeeded chat call.
func TestReceiptIngestWriteLineNoProvenance(t *testing.T) {
	doors := []engine.Event{embedCall("succeeded"), embedCall("succeeded"),
		toolCall("memory_upsert", "succeeded"), toolCall("memory_upsert", "succeeded"), toolCall("memory_upsert", "failed")}
	for _, stamp := range []string{"", "generated", "grounded", "mixed"} {
		enforced, asserted := receiptWith(t, stamp, doors...)
		if !strings.Contains(leafBlock(t, enforced), "write-tool calls succeeded: 2 (memory_upsert on memory ×2)") {
			t.Errorf("stamp %q: missing the ledger-counted write line:\n%s", stamp, enforced)
		}
		// It printed an output; an output alone is not a provenance signal.
		if !strings.Contains(leafBlock(t, enforced), "    output: artifact 0a1b\n") {
			t.Errorf("stamp %q: missing the recorded output:\n%s", stamp, enforced)
		}
		if l := provenanceLine(asserted); l != "" {
			t.Errorf("stamp %q: a leaf with no chat call must print no provenance line, got %q", stamp, l)
		}
		for _, bad := range []string{"your data", "notes and the model", "own knowledge", "retrieval observed", "no provenance declared"} {
			if strings.Contains(enforced+asserted, bad) {
				t.Errorf("stamp %q: receipt of a write-only leaf must not say %q:\n%s%s", stamp, bad, enforced, asserted)
			}
		}
	}
}

// The write count is the ledger's, never the grant's: a leaf that holds a
// read-write grant but recorded no succeeded write shows zero.
func TestReceiptWriteCountIsFromLedgerNotGrant(t *testing.T) {
	var b strings.Builder
	dir := receiptLedgersWith(t, identity.Invoker{Subject: "dana@example.com", Method: "asserted"},
		[]engine.Event{toolCall("memory_upsert", "refused"), toolCall("memory_upsert", "failed"), toolCall("memory_search", "succeeded")})
	leaf := leafOf("")
	leaf.agents[0].Tools = []config.ToolGrant{{Resource: "memory", Tools: []string{"memory_upsert"}, Mode: "read-write"}}
	renderReceipt(&b, dir, "r-orch", leaf, receiptTools)
	block := leafBlock(t, b.String())
	if !strings.Contains(block, "write-tool calls succeeded: 0\n") || strings.Contains(block, "memory_upsert on memory") {
		t.Errorf("a refused, a failed and a read call are not writes, whatever the grant:\n%s", block)
	}
	if !strings.Contains(block, "tool resource memory: attempted ×3 (succeeded ×1)\n") {
		t.Errorf("the leaf's three tool calls must be counted as attempts:\n%s", block)
	}
}

func TestReceiptRetrieveGroundedWithObservedRetrieval(t *testing.T) {
	enforced, asserted := receiptWith(t, "grounded", embedCall("succeeded"), toolCall("memory_search", "succeeded"), chatCall("succeeded"))
	l := provenanceLine(asserted)
	for _, want := range []string{"from your data", "retrieval observed (read-tool call ×1)"} {
		if !strings.Contains(l, want) {
			t.Errorf("grounded retrieve line missing %q: %q", want, l)
		}
	}
	if strings.Contains(l, "no retrieval observed") || strings.Contains(enforced, "from your data") {
		t.Errorf("grounded retrieve mislabelled: line=%q\nenforced:\n%s", l, enforced)
	}
	if block := leafBlock(t, enforced); !strings.Contains(block, "write-tool calls succeeded: 0\n") || !strings.Contains(block, "tool resource memory: attempted ×1 (succeeded ×1)\n") {
		t.Errorf("a read-only retrieve must count its read and zero writes:\n%s", block)
	}
}

func TestReceiptResearchMixedWithObservedRetrieval(t *testing.T) {
	_, asserted := receiptWith(t, "mixed", embedCall("succeeded"), toolCall("memory_search", "succeeded"), toolCall("memory_search", "succeeded"), chatCall("succeeded"))
	l := provenanceLine(asserted)
	for _, want := range []string{"notes and the model", "retrieval observed (read-tool call ×2)"} {
		if !strings.Contains(l, want) {
			t.Errorf("mixed research line missing %q: %q", want, l)
		}
	}
	if strings.Contains(l, "not your data") || strings.Contains(l, "from your data") {
		t.Errorf("mixed must be neither grounded nor generated: %q", l)
	}
}

// A streamed answer records its chat call once, as started, and never as
// succeeded; it is still a generation and still gets its provenance line.
func TestReceiptStreamedChatKeepsProvenance(t *testing.T) {
	enforced, asserted := receiptWith(t, "grounded", toolCall("memory_search", "succeeded"), chatCall("started"))
	if l := provenanceLine(asserted); !strings.Contains(l, "from your data") || !strings.Contains(l, "retrieval observed (read-tool call ×1)") {
		t.Errorf("a streamed chat call must keep the provenance line, got %q", l)
	}
	if !strings.Contains(leafBlock(t, enforced), "model chat: attempted ×1 (succeeded ×0), streaming ×1") {
		t.Errorf("a streamed call is attempted, not succeeded, and shown as streaming:\n%s", enforced)
	}
	_, asserted = receiptWith(t, "generated", chatCall("started"))
	if l := provenanceLine(asserted); !strings.Contains(l, "generated from the model's own knowledge — not your data; no retrieval observed in the run ledger") {
		t.Errorf("a streamed generated answer must keep its label, got %q", l)
	}
}

// The stamp is the agent's word; the retrieval is the evidence. A stamp with
// no succeeded read-classified call behind it is printed as a mismatch.
func TestReceiptStampWithoutRetrievalEvidence(t *testing.T) {
	cases := map[string][]engine.Event{
		"no tool call":         {chatCall("succeeded")},
		"search failed":        {toolCall("memory_search", "failed"), chatCall("succeeded")},
		"search refused":       {toolCall("memory_search", "refused"), chatCall("succeeded")},
		"only a write":         {toolCall("memory_upsert", "succeeded"), chatCall("succeeded")},
		"only embeddings":      {embedCall("succeeded"), chatCall("succeeded")},
		"unknown resource":     {{Type: "tool_call", Agent: "chat", Tool: "memory_search", Status: "succeeded", ResourcesTouched: []string{"elsewhere"}}, chatCall("succeeded")},
		"no resource recorded": {{Type: "tool_call", Agent: "chat", Tool: "memory_search", Status: "succeeded"}, chatCall("succeeded")},
		"another agent's read": {{Type: "tool_call", Agent: "other", Tool: "memory_search", Status: "succeeded", ResourcesTouched: []string{"memory"}}, chatCall("succeeded")},
	}
	for name, doors := range cases {
		_, asserted := receiptWith(t, "grounded", doors...)
		l := provenanceLine(asserted)
		if !strings.Contains(l, "declared grounded; no retrieval observed") {
			t.Errorf("%s: want the stamp-vs-evidence line, got %q", name, l)
		}
		if strings.Contains(l, "from your data") || strings.Contains(l, "retrieval observed (") {
			t.Errorf("%s: an unevidenced stamp must not read as grounded: %q", name, l)
		}
		_, asserted = receiptWith(t, "mixed", doors...)
		l = provenanceLine(asserted)
		if !strings.Contains(l, "declared mixed; no retrieval observed") || strings.Contains(l, "notes and the model") {
			t.Errorf("%s: an unevidenced mixed stamp must not read as from your notes: %q", name, l)
		}
	}
}

// Only a chat call that succeeded or was streamed is a generation: an
// embeddings call, or a chat call that failed or was refused, is not, and the
// classifier's own chat call never counts for the leaf.
func TestReceiptNoProvenanceWithoutChatEvidence(t *testing.T) {
	cases := map[string][]engine.Event{
		"embeddings only": {embedCall("succeeded"), toolCall("memory_search", "succeeded")},
		"chat failed":     {toolCall("memory_search", "succeeded"), chatCall("failed")},
		"chat refused":    {toolCall("memory_search", "succeeded"), chatCall("refused")},
		"kind unrecorded": {{Type: "model_call", Agent: "chat", Status: "succeeded"}},
		"other agent":     {{Type: "model_call", Agent: "other", CallKind: "chat", Status: "succeeded"}},
		"no doors":        nil,
	}
	for name, doors := range cases {
		for _, stamp := range []string{"", "generated", "grounded", "mixed"} {
			_, asserted := receiptWith(t, stamp, doors...)
			if l := provenanceLine(asserted); l != "" {
				t.Errorf("%s, stamp %q: no chat evidence must mean no provenance line, got %q", name, stamp, l)
			}
		}
	}
	// With no leaf run named, nothing is evidence for it.
	var b strings.Builder
	leaf := leafOf("grounded")
	leaf.runID = ""
	renderReceipt(&b, receiptLedgers(t), "r-orch", leaf, receiptTools)
	if _, asserted, _ := strings.Cut(b.String(), "agent-asserted ("); provenanceLine(asserted) != "" {
		t.Errorf("a leaf with no recorded run must print no provenance line:\n%s", asserted)
	}
}

func TestReceiptDoorSummarySplitsModelCallsByKind(t *testing.T) {
	enforced, _ := receiptWith(t, "grounded", embedCall("succeeded"), embedCall("succeeded"), embedCall("succeeded"), embedCall("failed"),
		toolCall("memory_search", "succeeded"), chatCall("succeeded"))
	if !strings.Contains(leafBlock(t, enforced), "door calls: model_call chat x1, embeddings x4, tool_call x1\n") {
		t.Errorf("door summary must split model_call by call kind:\n%s", enforced)
	}
}

// What went out the door is worded as attempts and successes per call kind
// and resource — never as sent, which the ledger cannot evidence.
func TestReceiptAttemptedSucceededWording(t *testing.T) {
	enforced, asserted := receiptWith(t, "grounded", embedCall("succeeded"), embedCall("failed"), embedCall("refused"),
		toolCall("memory_search", "succeeded"), toolCall("memory_upsert", "refused"), chatCall("succeeded"))
	for _, want := range []string{
		"model chat: attempted ×1 (succeeded ×1)\n",
		"model embeddings: attempted ×3 (succeeded ×1)\n",
		"tool resource memory: attempted ×2 (succeeded ×1)\n",
		"refused model or tool calls: 2 (model embeddings ×1, tool resource memory ×1)\n",
	} {
		if block := leafBlock(t, enforced); !strings.Contains(block, want) {
			t.Errorf("leaf block missing %q:\n%s", want, block)
		}
	}
	all := strings.ToLower(enforced + asserted)
	for _, bad := range []string{"sent", "left the machine"} {
		if strings.Contains(all, bad) {
			t.Errorf("receipt must not claim %q:\n%s", bad, all)
		}
	}
}

// The ledger facts sit in the enforced section and the agent's declaration in
// the asserted one; the ledger-derived retrieval note is marked as such.
func TestReceiptKeepsLedgerFactsAndDeclarationsApart(t *testing.T) {
	enforced, asserted := receiptWith(t, "grounded", toolCall("memory_search", "succeeded"), toolCall("memory_upsert", "succeeded"), chatCall("succeeded"))
	block := leafBlock(t, enforced)
	for _, want := range []string{"door calls: model_call chat x1, tool_call x2\n", "tool resource memory: attempted ×2 (succeeded ×2)\n", "write-tool calls succeeded: 1 (memory_upsert on memory ×1)\n", "refused model or tool calls: 0\n"} {
		if !strings.Contains(block, want) || strings.Contains(asserted, want) {
			t.Errorf("%q belongs in the enforced section only:\nenforced:\n%s\nasserted:\n%s", want, enforced, asserted)
		}
	}
	if strings.Contains(enforced, "grounded") || strings.Contains(enforced, "your data") {
		t.Errorf("the declared stamp leaked into the enforced section:\n%s", enforced)
	}
	if l := provenanceLine(asserted); !strings.Contains(l, "retrieval observed (read-tool call ×1) in the run ledger") {
		t.Errorf("the retrieval note must be marked as the ledger's: %q", l)
	}
}

// A succeeded tool call whose resource the configuration does not know is
// neither a read nor a write: it is counted apart, never dropped.
func TestReceiptUnclassifiedToolCall(t *testing.T) {
	enforced, _ := receiptWith(t, "", engine.Event{Type: "tool_call", Agent: "chat", Tool: "x", Status: "succeeded", ResourcesTouched: []string{"elsewhere"}})
	block := leafBlock(t, enforced)
	if !strings.Contains(block, "write-tool calls succeeded: 0\n") || !strings.Contains(block, "tool resource elsewhere: attempted ×1 (succeeded ×1)\n") ||
		!strings.Contains(block, "tool calls succeeded on a resource this configuration does not define: 1 (not classified as read or write)") {
		t.Errorf("an unclassifiable call must be counted apart:\n%s", block)
	}
}

// A leaf with no grounding stamp made no declaration: the receipt says so
// and never prints the "generated" claim nobody made.
func TestReceiptUnstampedDeclaresNoProvenance(t *testing.T) {
	cases := map[string]struct {
		doors []engine.Event
		want  string
	}{
		"chat succeeded, no read": {[]engine.Event{chatCall("succeeded")}, "chat: no provenance declared; no retrieval observed in the run ledger"},
		"chat succeeded, read":    {[]engine.Event{toolCall("memory_search", "succeeded"), chatCall("succeeded")}, "chat: no provenance declared; retrieval observed (read-tool call ×1) in the run ledger"},
		"chat streamed, no read":  {[]engine.Event{chatCall("started")}, "chat: no provenance declared; no retrieval observed in the run ledger"},
		"chat streamed, read":     {[]engine.Event{toolCall("memory_search", "succeeded"), chatCall("started")}, "chat: no provenance declared; retrieval observed (read-tool call ×1) in the run ledger"},
	}
	for name, c := range cases {
		enforced, asserted := receiptWith(t, "", c.doors...)
		if l := provenanceLine(asserted); l != "  "+c.want {
			t.Errorf("%s: got %q, want %q", name, l, c.want)
		}
		for _, bad := range []string{"own knowledge", "not your data", "from your data", "notes and the model"} {
			if strings.Contains(enforced+asserted, bad) {
				t.Errorf("%s: an unstamped leaf's receipt must not say %q:\n%s%s", name, bad, enforced, asserted)
			}
		}
	}
	// An explicit generated stamp is a declaration and keeps its wording,
	// beside what the ledger observed either way.
	_, asserted := receiptWith(t, "generated", chatCall("succeeded"))
	if l := provenanceLine(asserted); l != "  chat: agent-asserted: generated from the model's own knowledge — not your data; no retrieval observed in the run ledger" {
		t.Errorf("generated without retrieval: %q", l)
	}
	_, asserted = receiptWith(t, "generated", toolCall("memory_search", "succeeded"), chatCall("succeeded"))
	if l := provenanceLine(asserted); l != "  chat: agent-asserted: generated from the model's own knowledge — not your data; retrieval observed (read-tool call ×1) in the run ledger" {
		t.Errorf("generated with retrieval: %q", l)
	}
}

// A provenance line rests on the leaf ledger's records. When that ledger's
// chain does not verify, the line carries the qualification itself.
func TestReceiptQualifiesProvenanceOnUnverifiedLeafLedger(t *testing.T) {
	dir := receiptLedgersWith(t, identity.Invoker{Subject: "dana@example.com", Method: "asserted"},
		[]engine.Event{toolCall("memory_search", "succeeded"), chatCall("succeeded")})
	path := filepath.Join(dir, "r-leaf.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Edit the step terminal, after the calls: the records before the break
	// are still read, and the chain no longer verifies.
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	i := len(lines) - 2
	edited := strings.Replace(lines[i], `"step":"s"`, `"step":"t"`, 1)
	if edited == lines[i] {
		t.Fatal("fixture edit did not apply")
	}
	lines[i] = edited
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	renderReceipt(&b, dir, "r-orch", leafOf("grounded"), receiptTools)
	enforced, asserted, _ := strings.Cut(b.String(), "agent-asserted (")
	if strings.Contains(enforced, "ledger r-leaf: chain verified") {
		t.Fatalf("the edited leaf ledger must not verify:\n%s", enforced)
	}
	if l := provenanceLine(asserted); l != "  chat: grounded — declared to answer from your data; retrieval observed (read-tool call ×1) in the run ledger (leaf ledger integrity not verified)" {
		t.Errorf("a provenance line over an unverified leaf ledger must be qualified, got %q\n%s", l, b.String())
	}
}

// Exec and spawn calls are counted as doors, but their refusals are not in
// the refused count; the receipt says so wherever such a call is present.
func TestReceiptDisclosesUncountedExecAndSpawnRefusals(t *testing.T) {
	const note = "exec and spawn refusals are not counted here"
	enforced, _ := receiptWith(t, "", engine.Event{Type: "exec", Agent: "chat", Status: "refused"}, chatCall("succeeded"))
	block := leafBlock(t, enforced)
	if !strings.Contains(block, "refused model or tool calls: 0\n    "+note+"\n") {
		t.Errorf("an exec call must bring the scope note under the refusal line:\n%s", block)
	}
	enforced, _ = receiptWith(t, "", chatCall("succeeded"))
	if strings.Contains(enforced, note) {
		t.Errorf("no exec or spawn call, no note:\n%s", enforced)
	}
}

func TestReceiptComposesSubtree(t *testing.T) {
	got := receiptFor(t, "generated")
	// The tier is on the parent's spawn event; the door is in the child's ledger.
	for _, want := range []string{"dana@example.com", "ledger r-orch: chain verified", "ledger r-leaf: chain verified"} {
		if !strings.Contains(got, want) {
			t.Errorf("receipt missing %q:\n%s", want, got)
		}
	}
	leaf := leafBlock(t, got)
	for _, want := range []string{"containment tier podman (userns)", "door calls: model_call chat x1\n"} {
		if !strings.Contains(leaf, want) {
			t.Errorf("leaf block missing %q:\n%s", want, leaf)
		}
	}
}

func TestReceiptLabelsProvenance(t *testing.T) {
	got := receiptFor(t, "generated")
	enforced, asserted, ok := strings.Cut(got, "agent-asserted (")
	if !ok {
		t.Fatalf("no agent-asserted section:\n%s", got)
	}
	if !strings.Contains(asserted, "agent-asserted: generated from the model's own knowledge — not your data; no retrieval observed in the run ledger") {
		t.Errorf("missing generated label:\n%s", asserted)
	}
	if strings.Contains(enforced, "not your data") || !strings.Contains(enforced, "containment tier") {
		t.Errorf("the asserted claim leaked into the enforced section:\n%s", enforced)
	}
	// This leaf made a chat call and no retrieval: its grounded stamp is shown
	// as declared, without the unqualified "from your data".
	if g := receiptFor(t, "grounded"); !strings.Contains(g, "declared grounded; no retrieval observed") || strings.Contains(g, "not your data") || strings.Contains(g, "from your data") {
		t.Errorf("grounded leaf mislabelled:\n%s", g)
	}
}

func TestReceiptHonestWording(t *testing.T) {
	got := strings.ToLower(receiptFor(t, "generated"))
	for _, bad := range []string{"tamper-proof", "sandboxed"} {
		if strings.Contains(got, bad) {
			t.Errorf("receipt must not claim %q", bad)
		}
	}
	if !strings.Contains(got, "enforced by construction") || !strings.Contains(got, "agent-asserted (") {
		t.Errorf("enforced-vs-asserted split not explicit:\n%s", got)
	}
}

func TestReceiptInvokerHonesty(t *testing.T) {
	render := func(inv identity.Invoker) (enforced, asserted string) {
		var b strings.Builder
		renderReceipt(&b, receiptLedgersAs(t, inv), "r-orch", servedLeaf{}, nil)
		enforced, asserted, _ = strings.Cut(b.String(), "agent-asserted (")
		return
	}
	enf, asr := render(identity.Invoker{Subject: "ci", Method: "asserted"})
	if strings.Contains(enf, "invoker:") || !strings.Contains(asr, "invoker: ci (asserted by the caller, not verified)") {
		t.Errorf("an asserted invoker must not sit under enforced:\nenforced=%s\nasserted=%s", enf, asr)
	}
	enf, asr = render(identity.Invoker{Subject: "dana", Issuer: "https://idp", Method: "oidc"})
	if !strings.Contains(enf, "invoker: dana (oidc, verified)") || strings.Contains(asr, "invoker:") {
		t.Errorf("an oidc invoker belongs under enforced:\nenforced=%s\nasserted=%s", enf, asr)
	}
}

func TestReceiptMissingChildLedger(t *testing.T) {
	dir := receiptLedgers(t)
	if err := os.Remove(filepath.Join(dir, "r-leaf.jsonl")); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	renderReceipt(&b, dir, "r-orch", servedLeaf{}, nil)
	if !strings.Contains(b.String(), "no ledger found for this run") || strings.Contains(b.String(), "door calls: none") {
		t.Errorf("a missing child ledger must not read as no doors:\n%s", b.String())
	}
}

func TestReceiptUnreadableLedgerIsUnavailable(t *testing.T) {
	var b strings.Builder
	renderReceipt(&b, t.TempDir(), "r-absent", servedLeaf{}, nil)
	if !strings.Contains(b.String(), "receipt unavailable") {
		t.Errorf("want an unavailable line, got %q", b.String())
	}
}

// The receipt gates a leaf's provenance on that leaf's own ledger, so the
// answered pick must hand it the child run the spawn gate reported.
func TestAnsweredPickRecordsLeafRun(t *testing.T) {
	e := runPick(t, "grounded", "dev", "generic-chat", true, true, false, "", "the answer")
	if !e.served.answered || e.served.runID != "r-child" || len(e.served.agents) != 1 || e.served.agents[0].Name != "chat" {
		t.Fatalf("an answered pick must record the leaf's run and agents, got %+v", e.served)
	}
	e = runPick(t, "generated", "dev", "generic-chat", true, false, true, "n\n", "the answer")
	if e.served.answered || e.served.runID != "" {
		t.Fatalf("a declined pick answered nothing, got %+v", e.served)
	}
}

func TestAnswerStaysOnStdout(t *testing.T) {
	e := runPick(t, "grounded", "dev", "generic-chat", true, true, false, "", "the answer")
	if e.out.String() != "the answer\n" || strings.Contains(e.msg.String(), "the answer") {
		t.Errorf("answer must be the only stdout content: out=%q msg=%q", e.out.String(), e.msg.String())
	}
}

func TestSanitizeForTerminalKeepsTextDropsEscapes(t *testing.T) {
	// The ESC (0x1b) and the carriage return (0x0d) are dropped; the "[2J"
	// left behind is inert text once its ESC is gone. Non-ASCII spaces (NBSP,
	// the ideographic space) and CJK text survive — IsGraphic, not IsPrint.
	got := sanitizeForTerminal("line one\n\tindented\x1b[2Jcleared\rpast café　日本語")
	if want := "line one\n\tindented[2Jclearedpast café　日本語"; got != want {
		t.Fatalf("sanitize = %q, want %q", got, want)
	}
}

func TestDispatchPrintsRawWhenPipedSanitizedOnTerminal(t *testing.T) {
	// The leaf answer carries an escape sequence. Piped (outIsTerminal false)
	// it is byte-exact; on a terminal it is stripped to inert text.
	answer := "answer\x1b[31m!"
	for _, tc := range []struct {
		name     string
		terminal bool
		want     string
	}{
		{"piped keeps raw bytes", false, answer + "\n"},
		{"terminal strips the escape", true, "answer[31m!\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := askCfg()
			reg, _ := registry.Build(cfg)
			orch, _ := reg.Agent(orchestratorAgent)
			store, err := artifact.NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			sha, _, err := store.Put(answer)
			if err != nil {
				t.Fatal(err)
			}
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			gw := rungateway.New(cfg.Gateway, ".", nil, logger, "").WithSpawner(stubSpawner{res: rungateway.SpawnResult{Status: "succeeded", OutputSHA: sha, Provisioned: true}})
			menu := projectMenu(orch, reg)
			var out, msg strings.Builder
			_, _, code := dispatchPick(context.Background(), pickRun{
				spawn: askSpawn(gw, engine.Binding{RunID: "r-orch"}, orch, func(engine.Event) {}),
				reg:   reg, menu: menu, admitted: menu, prompt: "hi", store: store,
				yes: true, outIsTerminal: tc.terminal,
				in: strings.NewReader(""), out: &out, msg: &msg, runID: "r-orch", logger: logger,
			}, "dev", "generic-chat", true)
			if code != 0 || out.String() != tc.want {
				t.Fatalf("code=%d out=%q, want %q", code, out.String(), tc.want)
			}
		})
	}
}

func TestAdmittedMenuFiltersByInvoker(t *testing.T) {
	// The orchestrator may spawn generic-chat, owned by role "dev" whose
	// allowed_groups is restricted to "eng". An invoker outside that group is
	// not offered it in the listing; one inside is.
	cfg := askCfg()
	for i := range cfg.Roles {
		if cfg.Roles[i].Name == "dev" {
			cfg.Roles[i].AllowedGroups = []string{"eng"}
		}
	}
	reg, errs := registry.Build(cfg)
	if len(errs) > 0 {
		t.Fatalf("registry: %v", errs)
	}
	orch, _ := reg.Agent(orchestratorAgent)
	menu := projectMenu(orch, reg)
	if got := admittedMenu(reg, menu, identity.Invoker{Subject: "mallory", Groups: []string{"other"}}); len(got) != 0 {
		t.Fatalf("an invoker outside the role's groups must be offered nothing, got %+v", got)
	}
	if got := admittedMenu(reg, menu, identity.Invoker{Subject: "dana", Groups: []string{"eng"}}); len(got) != 1 || got[0].Workflow != "generic-chat" {
		t.Fatalf("an invoker in the role's groups must be offered generic-chat, got %+v", got)
	}
}

// scriptSpawner answers each spawn by the child's ROLE: a stored body for a
// role in byRole, a fixed non-succeeded result for a role in fail. It records
// a real child answer the way a leaf does, so the full orchestrate ledger can
// be written and checked.
type scriptSpawner struct {
	store  *artifact.Store
	byRole map[string]string
	fail   map[string]rungateway.SpawnResult
}

func (s *scriptSpawner) Spawn(_ context.Context, role, _, _ string, _ engine.Binding) (rungateway.SpawnResult, error) {
	if r, ok := s.fail[role]; ok {
		return r, nil
	}
	sha, prev, err := s.store.Put(s.byRole[role])
	if err != nil {
		return rungateway.SpawnResult{}, err
	}
	return rungateway.SpawnResult{ChildRunID: "r-" + role, Status: "succeeded", OutputSHA: sha, OutputPreview: prev, Provisioned: true}, nil
}

// orchResult is what runOrchestrationFixture reports: the whole orchestrator
// ledger it wrote, the exit code, and the captured streams.
type orchResult struct {
	events   []engine.Event
	code     int
	out, msg string
	answered bool
}

// runOrchestrationFixture drives runOrchestration against a scripted spawner
// over a real on-disk log, then reads the ledger back — so each test asserts
// completeness against the bytes the production path wrote, not a hand-built
// shape.
func runOrchestrationFixture(t *testing.T, sp *scriptSpawner, yes bool) orchResult {
	t.Helper()
	cfg := askCfg()
	reg, errs := registry.Build(cfg)
	if len(errs) > 0 {
		t.Fatalf("registry: %v", errs)
	}
	orch, _ := reg.Agent(orchestratorAgent)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gw := rungateway.New(cfg.Gateway, ".", nil, logger, "").WithSpawner(sp)
	dir := t.TempDir()
	runID := engine.NewRunID()
	log, err := engine.OpenLog(dir, runID)
	if err != nil {
		t.Fatal(err)
	}
	menu := projectMenu(orch, reg)
	var served servedLeaf
	var out, msg strings.Builder
	code := runOrchestration(context.Background(), orchestration{
		gw: gw, bind: engine.Binding{Role: orchestratorRole, Workflow: askWorkflow, RunID: runID},
		orch: orch, reg: reg, menu: menu, admitted: menu, prompt: "hi", store: sp.store,
		log: log, logger: logger, yes: yes, interactive: false,
		in: strings.NewReader(""), out: &out, msg: &msg, served: &served,
	})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	events, _, err := engine.ReadLog(dir, runID)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return orchResult{events: events, code: code, out: out.String(), msg: msg.String(), answered: served.answered}
}

func TestOrchestrationLedgerAccountsForItself(t *testing.T) {
	pick := `{"role":"dev","workflow":"generic-chat"}`
	cases := map[string]struct {
		sp         *scriptSpawner
		yes        bool
		wantCode   int
		wantAnswer bool
	}{
		"answered": {
			sp: func() *scriptSpawner {
				s, _ := newStore(t)
				return &scriptSpawner{store: s, byRole: map[string]string{routerRole: pick, "dev": "the answer"}}
			}(),
			yes:        true,
			wantCode:   0,
			wantAnswer: true,
		},
		"no match lists the menu": {
			sp: func() *scriptSpawner {
				s, _ := newStore(t)
				return &scriptSpawner{store: s, byRole: map[string]string{routerRole: "null"}}
			}(),
			yes:      true,
			wantCode: 0,
		},
		"not confirmed": {
			sp: func() *scriptSpawner {
				s, _ := newStore(t)
				return &scriptSpawner{store: s, byRole: map[string]string{routerRole: pick, "dev": "x"}}
			}(),
			yes:      false,
			wantCode: 1,
		},
		"classifier fails": {
			sp: func() *scriptSpawner {
				s, _ := newStore(t)
				return &scriptSpawner{store: s, fail: map[string]rungateway.SpawnResult{routerRole: {Status: "failed", Reason: "boom", Provisioned: true}}}
			}(),
			yes:      true,
			wantCode: 1,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := runOrchestrationFixture(t, c.sp, c.yes)
			if r.code != c.wantCode {
				t.Fatalf("code = %d, want %d (msg=%q)", r.code, c.wantCode, r.msg)
			}
			if rep := completeness.Check(r.events); rep.Verdict != completeness.Complete {
				t.Fatalf("ledger must be complete, got %s — %s", rep.Verdict, rep.Detail)
			}
			if r.answered != c.wantAnswer {
				t.Fatalf("answered = %v, want %v", r.answered, c.wantAnswer)
			}
			if c.wantAnswer && strings.TrimSpace(r.out) != "the answer" {
				t.Fatalf("answer = %q", r.out)
			}
		})
	}
}

func newStore(t *testing.T) (*artifact.Store, error) {
	t.Helper()
	return artifact.NewStore(t.TempDir())
}

// countingSpawner fails the test if ever asked to spawn; it proves the
// orchestrator did not start a child.
type countingSpawner struct{ calls int }

func (s *countingSpawner) Spawn(context.Context, string, string, string, engine.Binding) (rungateway.SpawnResult, error) {
	s.calls++
	return rungateway.SpawnResult{Status: "succeeded", Provisioned: true}, nil
}

func TestOrchestrationFailsClosedOnLedgerWriteError(t *testing.T) {
	// A log that cannot be appended (closed before use) must stop the run
	// before the first spawn: no child started, nothing on stdout, exit 1.
	cfg := askCfg()
	reg, _ := registry.Build(cfg)
	orch, _ := reg.Agent(orchestratorAgent)
	store, err := artifact.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sp := &countingSpawner{}
	gw := rungateway.New(cfg.Gateway, ".", nil, logger, "").WithSpawner(sp)
	dir := t.TempDir()
	runID := engine.NewRunID()
	log, err := engine.OpenLog(dir, runID)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil { // closed: every Append now fails
		t.Fatal(err)
	}
	menu := projectMenu(orch, reg)
	var out, msg strings.Builder
	code := runOrchestration(context.Background(), orchestration{
		gw: gw, bind: engine.Binding{Role: orchestratorRole, Workflow: askWorkflow, RunID: runID},
		orch: orch, reg: reg, menu: menu, admitted: menu, prompt: "hi", store: store,
		log: log, logger: logger, yes: true, in: strings.NewReader(""), out: &out, msg: &msg, served: &servedLeaf{},
	})
	if code != 1 || sp.calls != 0 || out.Len() != 0 {
		t.Fatalf("a ledger write failure must fail closed: code=%d spawns=%d out=%q", code, sp.calls, out.String())
	}
}

func TestReceiptReportsCompleteness(t *testing.T) {
	got := receiptFor(t, "generated")
	if !strings.Contains(got, "completeness complete") {
		t.Fatalf("receipt must report completeness, not a gap:\n%s", got)
	}
}

func TestGroundedWriterStillConfirms(t *testing.T) {
	rw := []config.ToolGrant{{Resource: "memory", Tools: []string{"memory_upsert"}, Mode: "read-write"}}
	ro := []config.ToolGrant{{Resource: "memory", Tools: []string{"memory_search"}, Mode: "read-only"}}

	// Non-terminal: refused, with write-aware wording.
	e := runPickTools(t, "grounded", rw, "dev", "generic-chat", true, false, false, "", "x")
	msg := e.msg.String()
	if e.code == 0 || e.sp.role != "" || !strings.Contains(msg, "write") || !strings.Contains(msg, "cannot be undone") || !strings.Contains(msg, "--yes") {
		t.Fatalf("grounded writer without a terminal must refuse with write wording: code=%d role=%q msg=%q", e.code, e.sp.role, msg)
	}
	// Terminal: prompted with write wording; n aborts.
	e = runPickTools(t, "grounded", rw, "dev", "generic-chat", true, false, true, "n\n", "x")
	if e.code == 0 || e.sp.role != "" || !strings.Contains(e.msg.String(), "write to your store") {
		t.Fatalf("grounded writer must prompt with write wording: code=%d msg=%q", e.code, e.msg.String())
	}
	// Grounded read-only still auto-runs.
	e = runPickTools(t, "grounded", ro, "dev", "generic-chat", true, false, true, "", "ok")
	if e.code != 0 || strings.Contains(e.msg.String(), "[y/N]") {
		t.Fatalf("grounded read-only must not confirm: code=%d msg=%q", e.code, e.msg.String())
	}
	// Ungrounded read-only keeps the provenance wording.
	e = runPickTools(t, "generated", ro, "dev", "generic-chat", true, false, false, "", "x")
	if !strings.Contains(e.msg.String(), "not grounded") || strings.Contains(e.msg.String(), "write") {
		t.Fatalf("ungrounded reader keeps provenance wording: %q", e.msg.String())
	}
}
