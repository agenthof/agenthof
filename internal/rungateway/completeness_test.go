package rungateway

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/completeness"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

// runOneStepThroughGateway writes a run ledger the way the engine does
// around one fronted step — workflow_started with the marker, step_started,
// the gateway's door events, Stop's count on step_succeeded, and
// workflow_finished — making two tool calls through the real inbound
// session. dropFirstToolCall simulates a door event whose write was lost.
func runOneStepThroughGateway(t *testing.T, dropFirstToolCall bool) []engine.Event {
	t.Helper()
	t.Setenv("GITHUB_TOKEN", "upstream-secret-xyz")
	ts, _ := newStubUpstream(t, "upstream-secret-xyz")
	defer ts.Close()
	dir := t.TempDir()
	bind := testBinding()
	log, err := engine.OpenLog(dir, bind.RunID)
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Now().UTC() }
	emit := func(e engine.Event) {
		e.Time, e.Binding = now(), bind
		if err := log.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	dropped := false
	appendEvent := func(e engine.Event) {
		mu.Lock()
		defer mu.Unlock()
		if dropFirstToolCall && !dropped && e.Type == "tool_call" {
			dropped = true // the write "failed": nothing lands, the gateway never knows
			return
		}
		e.Time, e.Binding = now(), bind
		_ = log.Append(e)
	}
	emit(engine.Event{Type: "workflow_started", DoorAccounting: engine.DoorAccountingAdmission})
	emit(engine.Event{Type: "step_started", Step: "call", Agent: "fe", Execution: "fronted"})
	p := New(config.GatewayConfig{Tools: map[string]config.ToolResource{
		"github": {Kind: "mcp", URL: ts.URL, CredentialSource: "static_env", TokenEnv: "GITHUB_TOKEN"},
	}}, "", broker.StaticEnv{}, nil, "")
	proxyURL, token, err := p.Start(context.Background(), bind, testAgentDef("github"), appendEvent)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := stubAgentSession(context.Background(), proxyURL, token)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "x"}}); err != nil {
			t.Fatal(err)
		}
	}
	n := p.Stop()
	emit(engine.Event{Type: "step_succeeded", Step: "call", Agent: "fe", Execution: "fronted", DoorCalls: &n})
	emit(engine.Event{Type: "workflow_finished", Status: "succeeded"})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	events, _, err := engine.ReadLog(dir, bind.RunID)
	if err != nil {
		t.Fatalf("the chain itself must verify either way: %v", err)
	}
	return events
}

func TestDroppedDoorEventReadsGap(t *testing.T) {
	if r := completeness.Check(runOneStepThroughGateway(t, false)); r.Verdict != completeness.Complete || r.DoorCalls != 2 {
		t.Fatalf("nothing dropped: %+v, want complete with 2 door calls", r)
	}
	r := completeness.Check(runOneStepThroughGateway(t, true))
	if r.Verdict != completeness.Gap || r.Detail != "step call: 2 door call(s) admitted, 1 recorded" {
		t.Fatalf("one dropped: %+v, want a gap naming the step and both numbers", r)
	}
}
