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

// pickEnv is a dispatch fixture: stdout and stderr are captured apart.
type pickEnv struct {
	out, msg strings.Builder
	code     int
	sp       *answerSpawner
	store    *artifact.Store
}

// runPick dispatches a pick against a fixture whose "chat" agent has the given
// grounding. interactive says whether stdin counts as a terminal.
func runPick(t *testing.T, grounding, role, wf string, matched, yes, interactive bool, input, answer string) *pickEnv {
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
	e := &pickEnv{sp: &answerSpawner{store: store, answer: answer}, store: store}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	orch, _ := reg.Agent(orchestratorAgent)
	_, _, e.code = dispatchPick(context.Background(), pickRun{
		gw:   rungateway.New(cfg.Gateway, ".", nil, logger, "").WithSpawner(e.sp),
		bind: engine.Binding{RunID: "r-orch"}, orch: orch, reg: reg, menu: projectMenu(orch, reg),
		prompt: "hello", store: store, yes: yes, interactive: interactive,
		in: strings.NewReader(input), out: &e.out, msg: &e.msg, runID: "r-orch",
		appendEvent: func(engine.Event) {}, logger: logger,
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
	_, _, code := dispatchPick(context.Background(), pickRun{
		gw:   rungateway.New(cfg.Gateway, ".", nil, logger, "").WithSpawner(sp),
		bind: engine.Binding{RunID: "r-orch"}, orch: orch, reg: reg, menu: projectMenu(orch, reg),
		prompt: "hello", store: store, yes: true, in: strings.NewReader(""), out: &e.out, msg: &e.msg,
		runID: "r-orch", appendEvent: func(engine.Event) {}, logger: logger,
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
			_, _, code := dispatchPick(context.Background(), pickRun{
				gw:   rungateway.New(cfg.Gateway, ".", nil, logger, "").WithSpawner(mk(sha)),
				bind: engine.Binding{RunID: "r-orch"}, orch: orch, reg: reg, menu: projectMenu(orch, reg),
				prompt: "hello", store: st, yes: true, in: strings.NewReader(""), out: &e.out, msg: &e.msg,
				runID: "r-orch", appendEvent: func(engine.Event) {}, logger: logger,
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
			_, _, code := dispatchPick(context.Background(), pickRun{
				gw:   rungateway.New(cfg.Gateway, ".", nil, logger, "").WithSpawner(stubSpawner{res: res}),
				bind: engine.Binding{RunID: "r-orch"}, orch: orch, reg: reg, menu: projectMenu(orch, reg),
				prompt: "hello", store: st, yes: true, in: strings.NewReader(""), out: &e.out, msg: &e.msg,
				runID: "r-orch", appendEvent: func(engine.Event) {}, logger: logger,
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

// receiptLedgers writes an orchestrator ledger whose parent spawn event for
// the leaf carries a containment tier, plus the leaf's own child ledger with
// the doors it fired. It returns the log dir.
func receiptLedgers(t *testing.T) string {
	t.Helper()
	return receiptLedgersAs(t, identity.Invoker{Subject: "dana@example.com", Method: "asserted"})
}

func receiptLedgersAs(t *testing.T, inv identity.Invoker) string {
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
	child := engine.Binding{Invoker: inv, Role: "dev", Workflow: "generic-chat", RunID: "r-leaf", ParentRunID: "r-orch", Depth: 1}
	write("r-orch", []engine.Event{
		{Type: "workflow_started", Binding: orch, DoorAccounting: engine.DoorAccountingAdmission},
		{Type: "spawn", Binding: orch, ChildRunID: "r-leaf", ChildRole: "dev", ChildWorkflow: "generic-chat", Depth: 1,
			ChildConfiner: "podman", ChildConfinerOpts: []string{"userns"}},
		{Type: "workflow_finished", Binding: orch, Status: "succeeded"},
	})
	write("r-leaf", []engine.Event{
		{Type: "workflow_started", Binding: child, DoorAccounting: engine.DoorAccountingAdmission},
		{Type: "model_call", Binding: child, Model: "m"},
		{Type: "workflow_finished", Binding: child, Status: "succeeded"},
	})
	return dir
}

func receiptFor(t *testing.T, grounding string) string {
	t.Helper()
	var b strings.Builder
	renderReceipt(&b, receiptLedgers(t), "r-orch", []config.AgentDef{{Name: "chat", Grounding: grounding}})
	return b.String()
}

func TestReceiptComposesSubtree(t *testing.T) {
	got := receiptFor(t, "generated")
	// The tier is on the parent's spawn event; the door is in the child's ledger.
	for _, want := range []string{"containment tier podman (userns)", "model_call x1", "dana@example.com", "ledger r-orch: chain verified", "ledger r-leaf: chain verified"} {
		if !strings.Contains(got, want) {
			t.Errorf("receipt missing %q:\n%s", want, got)
		}
	}
}

func TestReceiptLabelsProvenance(t *testing.T) {
	got := receiptFor(t, "generated")
	enforced, asserted, ok := strings.Cut(got, "agent-asserted (")
	if !ok {
		t.Fatalf("no agent-asserted section:\n%s", got)
	}
	if !strings.Contains(asserted, "agent-asserted: generated from the model's own knowledge — not your data") {
		t.Errorf("missing generated label:\n%s", asserted)
	}
	if strings.Contains(enforced, "not your data") || !strings.Contains(enforced, "containment tier") {
		t.Errorf("the asserted claim leaked into the enforced section:\n%s", enforced)
	}
	if g := receiptFor(t, "grounded"); !strings.Contains(g, "grounded — declared") || strings.Contains(g, "not your data") {
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
		renderReceipt(&b, receiptLedgersAs(t, inv), "r-orch", nil)
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
	renderReceipt(&b, dir, "r-orch", nil)
	if !strings.Contains(b.String(), "no ledger found for this run") || strings.Contains(b.String(), "doors fired: none") {
		t.Errorf("a missing child ledger must not read as no doors:\n%s", b.String())
	}
}

func TestReceiptUnreadableLedgerIsUnavailable(t *testing.T) {
	var b strings.Builder
	renderReceipt(&b, t.TempDir(), "r-absent", nil)
	if !strings.Contains(b.String(), "receipt unavailable") {
		t.Errorf("want an unavailable line, got %q", b.String())
	}
}

func TestAnswerStaysOnStdout(t *testing.T) {
	e := runPick(t, "grounded", "dev", "generic-chat", true, true, false, "", "the answer")
	if e.out.String() != "the answer\n" || strings.Contains(e.msg.String(), "the answer") {
		t.Errorf("answer must be the only stdout content: out=%q msg=%q", e.out.String(), e.msg.String())
	}
}
