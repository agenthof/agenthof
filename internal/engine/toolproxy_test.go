package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/registry"
)

// spyProxy records Start/Stop and returns fixed coordinates.
type spyProxy struct {
	started  int
	stopped  int
	gotAgent string
}

func (s *spyProxy) Start(_ Binding, agent config.AgentDef, _ func(Event)) (string, string, error) {
	s.started++
	s.gotAgent = agent.Name
	return "http://127.0.0.1:12345/mcp", "tok-abc", nil
}
func (s *spyProxy) Stop() { s.stopped++ }

// failProxy fails Start, so Run must fail the step without ever calling Stop.
type failProxy struct{ stopped int }

func (f *failProxy) Start(_ Binding, _ config.AgentDef, _ func(Event)) (string, string, error) {
	return "", "", errors.New("upstream unreachable")
}
func (f *failProxy) Stop() { f.stopped++ }

// urlLeakProxy fails Start with a transport-derived error that wraps a
// *url.Error carrying the tool resource URL (query string included), the way a
// real upstream-connect failure does. Used to prove the ledger reason never
// echoes it.
type urlLeakProxy struct{}

func (urlLeakProxy) Start(_ Binding, _ config.AgentDef, _ func(Event)) (string, string, error) {
	return "", "", fmt.Errorf("connect upstream %q: %w", "github",
		&url.Error{Op: "Get", URL: "https://mcp/x?key=SUPERSECRET", Err: errors.New("connection refused")})
}
func (urlLeakProxy) Stop() {}

// coordExec captures the proxy coordinates it sees in ctx during Execute.
type coordExec struct {
	url, token string
	ok         bool
}

func (c *coordExec) Execute(ctx context.Context, _ Binding, _ config.AgentDef, _ string, _ map[string]string) (StepResult, error) {
	c.url, c.token, c.ok = ProxyCoordinatesFrom(ctx)
	return StepResult{Success: true, Artifact: "ok"}, nil
}

// ftCfg builds a registry with a role/workflow whose single step is a FRONTED
// agent ("fe") that declares tools against a well-formed gateway tool
// resource, so registry.Build accepts it.
func ftCfg() *registry.Registry {
	cfg := config.Config{
		Agents: []config.AgentDef{
			{Name: "fe", Output: "out", SourceFile: "a", Execution: "fronted", Endpoint: "https://x", Tools: []config.ToolGrant{{Resource: "github"}}},
		},
		Workflows: []config.WorkflowDef{{
			Name: "wf", SourceFile: "w",
			Steps: []config.Step{
				{Name: "step1", Agent: "fe"},
			},
		}},
		Roles: []config.RoleDef{{Name: "se", Workflows: []string{"wf"}, AllowedGroups: []string{"*"}, SourceFile: "r"}},
		Gateway: config.GatewayConfig{
			Tools: map[string]config.ToolResource{
				"github": {Kind: "mcp", URL: "https://mcp/x", CredentialSource: "static_env", TokenEnv: "T"},
			},
		},
	}
	reg, errs := registry.Build(cfg)
	if reg == nil {
		panic(errs)
	}
	return reg
}

func staticInvoker() identity.Invoker { return identity.Static("dev@x") }

func TestProxyCoordinatesRoundTripCtx(t *testing.T) {
	ctx := WithProxyCoordinates(context.Background(), "http://x/mcp", "tok")
	url, token, ok := ProxyCoordinatesFrom(ctx)
	if !ok || url != "http://x/mcp" || token != "tok" {
		t.Fatalf("got %q %q %v", url, token, ok)
	}
	if _, _, ok := ProxyCoordinatesFrom(context.Background()); ok {
		t.Fatal("bare ctx must report ok=false")
	}
}

func TestRunStartsListenerForFrontedAgentWithoutTools(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		Agents: []config.AgentDef{
			{Name: "fe", Output: "out", SourceFile: "a", Execution: "fronted", Endpoint: "https://x", Model: "planner-model"},
		},
		Workflows: []config.WorkflowDef{{
			Name: "wf", SourceFile: "w",
			Steps: []config.Step{{Name: "step1", Agent: "fe"}},
		}},
		Roles: []config.RoleDef{{Name: "se", Workflows: []string{"wf"}, AllowedGroups: []string{"*"}, SourceFile: "r"}},
	}
	reg, errs := registry.Build(cfg)
	if reg == nil {
		t.Fatal(errs)
	}
	sp := &spyProxy{}
	ce := &coordExec{}
	_, status, err := Run(context.Background(), reg, "se", "wf", "x",
		staticInvoker(), ce, Options{LogDir: dir, ArtifactDir: dir + "/a", NewGateway: func() ToolProxy { return sp }})
	if err != nil || status != "succeeded" {
		t.Fatalf("run: status=%q err=%v", status, err)
	}
	if sp.started != 1 || sp.stopped != 1 {
		t.Fatalf("proxy bracket: started=%d stopped=%d, want 1/1", sp.started, sp.stopped)
	}
	if !ce.ok || ce.token != "tok-abc" {
		t.Fatalf("executor coords: %q %q %v", ce.url, ce.token, ce.ok)
	}
}

func TestRunBracketsFrontedToolStepWithProxy(t *testing.T) {
	dir := t.TempDir()
	sp := &spyProxy{}
	ce := &coordExec{}
	// ftCfg: a role/workflow whose single step is a FRONTED agent with tools.
	_, status, err := Run(context.Background(), ftCfg(), "se", "wf", "x",
		staticInvoker(), ce, Options{LogDir: dir, ArtifactDir: dir + "/a", NewGateway: func() ToolProxy { return sp }})
	if err != nil || status != "succeeded" {
		t.Fatalf("run: status=%q err=%v", status, err)
	}
	if sp.started != 1 || sp.stopped != 1 {
		t.Fatalf("proxy bracket: started=%d stopped=%d, want 1/1", sp.started, sp.stopped)
	}
	if sp.gotAgent != "fe" {
		t.Fatalf("proxy given agent %q, want fe", sp.gotAgent)
	}
	if !ce.ok || ce.url != "http://127.0.0.1:12345/mcp" || ce.token != "tok-abc" {
		t.Fatalf("executor coords: %q %q %v", ce.url, ce.token, ce.ok)
	}
}

func TestToolProxyStartFailureKeepsURLOutOfLedger(t *testing.T) {
	dir := t.TempDir()
	id, status, err := Run(context.Background(), ftCfg(), "se", "wf", "x",
		staticInvoker(), &coordExec{}, Options{LogDir: dir, ArtifactDir: dir + "/a", NewGateway: func() ToolProxy { return urlLeakProxy{} }})
	if err != nil || status != "failed" {
		t.Fatalf("run: status=%q err=%v", status, err)
	}
	events, _, rerr := ReadLog(dir, id)
	if rerr != nil {
		t.Fatal(rerr)
	}
	// Article III: nothing in the ledger — any field of any event — may echo
	// the resource URL or its secret.
	for _, e := range events {
		raw, merr := json.Marshal(e)
		if merr != nil {
			t.Fatal(merr)
		}
		if strings.Contains(string(raw), "SUPERSECRET") || strings.Contains(string(raw), "mcp/x?key=") {
			t.Fatalf("ledger event leaked the tool URL/secret: %s", raw)
		}
	}
	// The reason is the fixed, secret-free string on both failure events.
	var sawStep, sawFinished bool
	for _, e := range events {
		if e.Type == "step_failed" && e.Reason == "tool proxy start failed" {
			sawStep = true
		}
		if e.Type == "workflow_finished" && e.Reason == "tool proxy start failed" {
			sawFinished = true
		}
	}
	if !sawStep || !sawFinished {
		t.Fatalf("want fixed 'tool proxy start failed' reason on step_failed and workflow_finished; events=%+v", events)
	}
}

func TestRunFailsStepWhenToolProxyStartErrors(t *testing.T) {
	dir := t.TempDir()
	fp := &failProxy{}
	ce := &coordExec{}
	id, status, err := Run(context.Background(), ftCfg(), "se", "wf", "x",
		staticInvoker(), ce, Options{LogDir: dir, ArtifactDir: dir + "/a", NewGateway: func() ToolProxy { return fp }})
	if err != nil || status != "failed" {
		t.Fatalf("run: status=%q err=%v", status, err)
	}
	if fp.stopped != 0 {
		t.Fatalf("Stop must not be called when Start fails, got %d", fp.stopped)
	}
	if ce.ok {
		t.Fatal("executor must never run when the tool proxy fails to start")
	}
	events, _, rerr := ReadLog(dir, id)
	if rerr != nil {
		t.Fatal(rerr)
	}
	var stepFailed *Event
	for i := range events {
		if events[i].Type == "step_failed" {
			stepFailed = &events[i]
		}
	}
	if stepFailed == nil || stepFailed.Reason != "tool proxy start failed" {
		t.Fatalf("step_failed must carry the fixed tool-proxy reason: %+v", stepFailed)
	}
	last := events[len(events)-1]
	if last.Type != "workflow_finished" || last.Status != "failed" {
		t.Fatalf("workflow must finish failed: %+v", last)
	}
}
