package toolproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
)

// EchoArgs is the stub upstream tool's argument shape.
type EchoArgs struct {
	Text string `json:"text"`
}

// newStubUpstream stands up an in-process MCP server exposing one tool,
// echo(text) -> text, that records every Authorization header it receives and
// rejects calls that don't carry the expected upstream bearer token.
func newStubUpstream(t *testing.T, wantToken string) (*httptest.Server, func() string) {
	t.Helper()
	var mu sync.Mutex
	var lastAuth string

	server := mcp.NewServer(&mcp.Implementation{Name: "upstream-stub", Version: "v0.1.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "echo back the given text"}, func(ctx context.Context, req *mcp.CallToolRequest, args EchoArgs) (*mcp.CallToolResult, any, error) {
		var auth string
		if req.Extra != nil && req.Extra.Header != nil {
			auth = req.Extra.Header.Get("Authorization")
		}
		mu.Lock()
		lastAuth = auth
		mu.Unlock()
		if auth != "Bearer "+wantToken {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: "unauthorized"}},
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: args.Text}},
		}, nil, nil
	})

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	readLastAuth := func() string {
		mu.Lock()
		defer mu.Unlock()
		return lastAuth
	}
	return ts, readLastAuth
}

// stubAgentSession connects to the proxy as a fronted agent would: it
// presents ONLY a run token and never sees the upstream credential.
func stubAgentSession(ctx context.Context, proxyURL, runToken string) (*mcp.ClientSession, error) {
	httpClient := &http.Client{Transport: &injectingTransport{base: http.DefaultTransport, token: runToken}}
	client := mcp.NewClient(&mcp.Implementation{Name: "agent-stub", Version: "v0.1.0"}, nil)
	return client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: proxyURL, HTTPClient: httpClient}, nil)
}

func testAgentDef(tools ...string) config.AgentDef {
	return config.AgentDef{Name: "fe", Execution: "fronted", Endpoint: "https://x", Tools: tools}
}

func testBinding() engine.Binding {
	return engine.Binding{Invoker: identity.Static("dev@x"), Role: "se", Workflow: "wf", RunID: "r-test"}
}

func TestProxyRoundTripNoPassthrough(t *testing.T) {
	const upstreamToken = "upstream-secret-xyz"
	t.Setenv("GITHUB_TOKEN", upstreamToken)

	ts, lastAuth := newStubUpstream(t, upstreamToken)

	tools := map[string]config.ToolResource{
		"github": {Kind: "mcp", URL: ts.URL, CredentialSource: "static_env", TokenEnv: "GITHUB_TOKEN"},
	}
	p := New(tools, broker.StaticEnv{})

	var mu sync.Mutex
	var events []engine.Event
	appendEvent := func(e engine.Event) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}

	bind := testBinding()
	agent := testAgentDef("github")
	url, runToken, err := p.Start(bind, agent, appendEvent)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	if runToken == "" {
		t.Fatal("Start returned an empty run token")
	}

	ctx := context.Background()
	sess, err := stubAgentSession(ctx, url, runToken)
	if err != nil {
		t.Fatalf("agent connect: %v", err)
	}
	defer func() { _ = sess.Close() }()

	result, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"text": "hello from agent"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("CallTool returned an error result: %+v", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "hello from agent" {
		t.Fatalf("unexpected echo result: %+v", result.Content)
	}

	// No-passthrough: the upstream must have seen the INJECTED credential,
	// never the agent's run token.
	got := lastAuth()
	if got != "Bearer "+upstreamToken {
		t.Fatalf("upstream saw Authorization %q, want the injected upstream token", got)
	}
	if got == "Bearer "+runToken {
		t.Fatal("upstream saw the run token — no-passthrough violated")
	}

	// Only allowlisted resources' tools are exposed at all: a name that was
	// never mirrored onto the inbound server must fail at the MCP layer.
	if _, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "not-a-real-tool", Arguments: map[string]any{}}); err == nil {
		t.Fatal("expected calling an unmirrored tool name to fail")
	}

	_ = sess.Close()
	p.Stop() // Stop must be safe to call more than once, and synchronous either way.

	mu.Lock()
	defer mu.Unlock()
	var tc *engine.Event
	for i := range events {
		if events[i].Type == "tool_call" {
			tc = &events[i]
		}
	}
	if tc == nil {
		t.Fatal("no tool_call event appended")
	}
	if tc.Status != "succeeded" {
		t.Fatalf("tool_call.Status = %q, want succeeded", tc.Status)
	}
	if tc.AuthMode != "static_env" {
		t.Fatalf("tool_call.AuthMode = %q, want static_env", tc.AuthMode)
	}
	if tc.Agent != "fe" {
		t.Fatalf("tool_call.Agent = %q, want fe", tc.Agent)
	}
	if len(tc.ResourcesTouched) != 1 || tc.ResourcesTouched[0] != "github" {
		t.Fatalf("tool_call.ResourcesTouched = %v, want [github]", tc.ResourcesTouched)
	}
	if !reflect.DeepEqual(tc.Binding, bind) {
		t.Fatalf("tool_call.Binding = %+v, want %+v", tc.Binding, bind)
	}
	if tc.ArtifactSHA == "" {
		t.Fatal("tool_call.ArtifactSHA is empty, want a result hash")
	}
	if !strings.Contains(tc.Artifact, "hello from agent") {
		t.Fatalf("tool_call.Artifact preview = %q, want it to contain the result text", tc.Artifact)
	}
	if strings.Contains(tc.Artifact, upstreamToken) || strings.Contains(tc.Artifact, runToken) {
		t.Fatal("tool_call.Artifact preview must never contain a credential")
	}
}

func TestProxyRejectsBadRunToken(t *testing.T) {
	const upstreamToken = "upstream-secret-xyz"
	t.Setenv("GITHUB_TOKEN", upstreamToken)

	ts, _ := newStubUpstream(t, upstreamToken)
	tools := map[string]config.ToolResource{
		"github": {Kind: "mcp", URL: ts.URL, CredentialSource: "static_env", TokenEnv: "GITHUB_TOKEN"},
	}
	p := New(tools, broker.StaticEnv{})

	url, _, err := p.Start(testBinding(), testAgentDef("github"), func(engine.Event) {})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	ctx := context.Background()
	_, err = stubAgentSession(ctx, url, "totally-wrong-token")
	if err == nil {
		t.Fatal("expected connect with a bad run token to fail, got nil error")
	}
}

// TestProxyForwardDeniesNonAllowlistedResource exercises the forwarder's
// defense-in-depth allowlist check directly: a resource that is not in the
// agent's allowlist must be denied at call time (an IsError result) and must
// append a "refused" tool_call event, independent of what got mirrored onto
// the inbound server at Start time.
func TestProxyForwardDeniesNonAllowlistedResource(t *testing.T) {
	tools := map[string]config.ToolResource{
		"github": {Kind: "mcp", URL: "http://unused.invalid", CredentialSource: "static_env", TokenEnv: "GITHUB_TOKEN"},
	}
	p := New(tools, broker.StaticEnv{})

	var events []engine.Event
	appendEvent := func(e engine.Event) { events = append(events, e) }

	bind := testBinding()
	agent := testAgentDef("github")
	allow := map[string]bool{} // "github" deliberately absent

	handler := p.forward(bind, agent, "github", allow, nil, appendEvent)
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "echo", Arguments: json.RawMessage(`{"text":"x"}`)}}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("forward: unexpected transport error %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("expected a deny IsError result for a non-allowlisted resource, got %+v", result)
	}

	if len(events) != 1 {
		t.Fatalf("expected exactly one tool_call event, got %d: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Type != "tool_call" || ev.Status != "refused" {
		t.Fatalf("event = %+v, want Type=tool_call Status=refused", ev)
	}
	if ev.AuthMode != "static_env" {
		t.Fatalf("event.AuthMode = %q, want static_env", ev.AuthMode)
	}
	if len(ev.ResourcesTouched) != 1 || ev.ResourcesTouched[0] != "github" {
		t.Fatalf("event.ResourcesTouched = %v, want [github]", ev.ResourcesTouched)
	}
	if !reflect.DeepEqual(ev.Binding, bind) {
		t.Fatalf("event.Binding = %+v, want %+v", ev.Binding, bind)
	}
	if ev.Reason == "" {
		t.Fatal("event.Reason must be set on a refused tool_call")
	}
}

// TestProxyStopWaitsForInFlightForward confirms Stop() does not return until
// a forward call already in flight (and its appendEvent) has completed, and
// that it then tears down the listener and upstream session — no lingering
// appendEvent call can race the engine's log.Close() right after Stop()
// returns.
//
// It invokes the same forward handler Start wires onto the inbound server,
// but calls it directly against an upstream tool that blocks on a
// test-controlled channel, so the assertion does not depend on how (or
// whether) closing the inbound HTTP listener propagates cancellation to an
// in-flight request's context — Stop's own bookkeeping is what's under test.
func TestProxyStopWaitsForInFlightForward(t *testing.T) {
	const upstreamToken = "upstream-secret-xyz"
	t.Setenv("GITHUB_TOKEN", upstreamToken)

	entered := make(chan struct{})
	release := make(chan struct{})

	blocking := mcp.NewServer(&mcp.Implementation{Name: "upstream-blocking-stub", Version: "v0.1.0"}, nil)
	mcp.AddTool(blocking, &mcp.Tool{Name: "block", Description: "blocks until released"}, func(ctx context.Context, req *mcp.CallToolRequest, args EchoArgs) (*mcp.CallToolResult, any, error) {
		close(entered)
		<-release
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: args.Text}}}, nil, nil
	})
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return blocking }, nil))
	defer ts.Close()

	tools := map[string]config.ToolResource{
		"github": {Kind: "mcp", URL: ts.URL, CredentialSource: "static_env", TokenEnv: "GITHUB_TOKEN"},
	}
	p := New(tools, broker.StaticEnv{})

	var mu sync.Mutex
	appendCount := 0
	appendEvent := func(engine.Event) {
		mu.Lock()
		appendCount++
		mu.Unlock()
	}

	bind := testBinding()
	agent := testAgentDef("github")
	if _, _, err := p.Start(bind, agent, appendEvent); err != nil {
		t.Fatalf("Start: %v", err)
	}

	p.mu.Lock()
	sess := p.sessions[0]
	p.mu.Unlock()
	handler := p.forward(bind, agent, "github", map[string]bool{"github": true}, sess, appendEvent)

	callDone := make(chan struct{})
	go func() {
		defer close(callDone)
		req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "block", Arguments: json.RawMessage(`{"text":"x"}`)}}
		// A ctx independent of any HTTP request, so nothing outside this test
		// can cancel it — the block below is the only thing releasing it.
		_, _ = handler(context.Background(), req)
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("forward call never reached the upstream handler")
	}

	stopDone := make(chan struct{})
	go func() {
		p.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		t.Fatal("Stop() returned while a forward call was still in flight")
	case <-time.After(200 * time.Millisecond):
		// Expected: Stop is blocked on the in-flight call.
	}

	close(release)

	select {
	case <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return after the in-flight call finished")
	}
	<-callDone

	mu.Lock()
	got := appendCount
	mu.Unlock()
	if got != 1 {
		t.Fatalf("appendEvent called %d times by the time Stop() returned, want exactly 1", got)
	}

	// A second Stop() (the engine never issues one, but defense in depth)
	// must not panic or hang.
	p.Stop()
}

// TestProxyForwardSetsReasonOnUpstreamFailure exercises forward's "failed"
// path directly: an upstream call that comes back IsError must produce a
// tool_call event with Status "failed" and a non-empty Reason describing the
// failure (spec §3g: Reason on refusal/failure), same as the "refused" path.
func TestProxyForwardSetsReasonOnUpstreamFailure(t *testing.T) {
	const upstreamToken = "upstream-secret-xyz"
	ts, _ := newStubUpstream(t, upstreamToken)

	// Connect the upstream session with the WRONG credential so the stub
	// upstream's own auth check returns an IsError result — the same shape a
	// real upstream tool failure would produce.
	httpClient := &http.Client{Transport: &injectingTransport{base: http.DefaultTransport, token: "wrong-token"}}
	client := mcp.NewClient(&mcp.Implementation{Name: "toolproxy-test", Version: "v0.1.0"}, nil)
	upstream, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL, HTTPClient: httpClient}, nil)
	if err != nil {
		t.Fatalf("connect upstream: %v", err)
	}
	defer func() { _ = upstream.Close() }()

	tools := map[string]config.ToolResource{
		"github": {Kind: "mcp", URL: ts.URL, CredentialSource: "static_env", TokenEnv: "GITHUB_TOKEN"},
	}
	p := New(tools, broker.StaticEnv{})

	var events []engine.Event
	appendEvent := func(e engine.Event) { events = append(events, e) }

	bind := testBinding()
	agent := testAgentDef("github")
	allow := map[string]bool{"github": true}

	handler := p.forward(bind, agent, "github", allow, upstream, appendEvent)
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "echo", Arguments: json.RawMessage(`{"text":"x"}`)}}

	result, err := handler(context.Background(), req)
	if err != nil {
		t.Fatalf("forward: unexpected transport error %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("expected an IsError result from the failing upstream call, got %+v", result)
	}

	if len(events) != 1 {
		t.Fatalf("expected exactly one tool_call event, got %d: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Type != "tool_call" || ev.Status != "failed" {
		t.Fatalf("event = %+v, want Type=tool_call Status=failed", ev)
	}
	if ev.Reason == "" {
		t.Fatal("event.Reason must be set on a failed tool_call")
	}
}
