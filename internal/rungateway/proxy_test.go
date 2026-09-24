package rungateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// bearerTransport sets a fixed bearer token on every outbound request. It
// stands in for whatever presents a static credential in these tests — the
// agent's run token, or a test dialing an upstream directly — a concern
// separate from injectingTransport, which resolves a resource credential
// through the broker on the proxy's own upstream leg.
type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(req)
}

// stubAgentSession connects to the proxy as a fronted agent would: it
// presents ONLY a run token and never sees the upstream credential.
func stubAgentSession(ctx context.Context, proxyURL, runToken string) (*mcp.ClientSession, error) {
	httpClient := &http.Client{Transport: &bearerTransport{base: http.DefaultTransport, token: runToken}}
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
	p := New(config.GatewayConfig{Tools: tools}, "", broker.StaticEnv{})

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
		if events[i].Type == "tool_call" && events[i].Status == "succeeded" {
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
	p := New(config.GatewayConfig{Tools: tools}, "", broker.StaticEnv{})

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
	p := New(config.GatewayConfig{Tools: tools}, "", broker.StaticEnv{})

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
	p := New(config.GatewayConfig{Tools: tools}, "", broker.StaticEnv{})

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
	httpClient := &http.Client{Transport: &bearerTransport{base: http.DefaultTransport, token: "wrong-token"}}
	client := mcp.NewClient(&mcp.Implementation{Name: "rungateway-test", Version: "v0.1.0"}, nil)
	upstream, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL, HTTPClient: httpClient}, nil)
	if err != nil {
		t.Fatalf("connect upstream: %v", err)
	}
	defer func() { _ = upstream.Close() }()

	tools := map[string]config.ToolResource{
		"github": {Kind: "mcp", URL: ts.URL, CredentialSource: "static_env", TokenEnv: "GITHUB_TOKEN"},
	}
	p := New(config.GatewayConfig{Tools: tools}, "", broker.StaticEnv{})

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

// TestProxyClientCredentialsMintsSeparateUpstreamToken exercises the
// client_credentials grant end-to-end: the proxy mints an upstream token from
// a fake OAuth token endpoint and injects THAT into the upstream call, never
// the agent's inbound run token (no-passthrough) — and the tool_call event
// records AuthMode "client_credentials".
func TestProxyClientCredentialsMintsSeparateUpstreamToken(t *testing.T) {
	const upstreamToken = "minted-upstream"
	// Fake OAuth token endpoint mints upstreamToken.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + upstreamToken + `","token_type":"Bearer","expires_in":3600}`))
	}))
	defer tokenSrv.Close()
	t.Setenv("CC_ID", "client-abc")
	t.Setenv("CC_SECRET", "client-secret")

	// Upstream MCP stub requires Authorization: Bearer <upstreamToken>.
	ts, lastAuth := newStubUpstream(t, upstreamToken)
	defer ts.Close()

	res := config.ToolResource{
		Kind: "mcp", URL: ts.URL, CredentialSource: "static_env",
		GrantType: "client_credentials", ClientAuth: "client_secret_basic",
		Issuer: "https://id.example.com", TokenEndpoint: tokenSrv.URL,
		ClientIDEnv: "CC_ID", ClientSecretEnv: "CC_SECRET",
	}
	b := broker.Dispatch{StaticEnv: broker.StaticEnv{}, ClientCredentials: broker.NewClientCredentials(nil)}
	p := New(config.GatewayConfig{Tools: map[string]config.ToolResource{"up": res}}, "", b)

	var events []engine.Event
	proxyURL, runToken, err := p.Start(testBinding(), testAgentDef("up"), func(e engine.Event) {
		events = append(events, e)
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	ctx := context.Background()
	sess, err := stubAgentSession(ctx, proxyURL, runToken)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if _, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	if got := lastAuth(); got != "Bearer "+upstreamToken {
		t.Fatalf("upstream Authorization = %q, want the minted token", got)
	}
	if lastAuth() == "Bearer "+runToken {
		t.Fatal("no-passthrough violated: upstream saw the inbound run token")
	}
	var found bool
	for _, e := range events {
		if e.Type == "tool_call" {
			found = true
			if e.AuthMode != "client_credentials" {
				t.Fatalf("AuthMode = %q, want client_credentials", e.AuthMode)
			}
		}
	}
	if !found {
		t.Fatal("no tool_call event recorded")
	}
}

// TestProxyDirectBearerRegression confirms the direct-bearer (static_env)
// path still injects the env value as-is and still logs AuthMode
// "static_env".
func TestProxyDirectBearerRegression(t *testing.T) {
	const upstreamToken = "direct-bearer"
	t.Setenv("UP_TOKEN", upstreamToken)

	ts, lastAuth := newStubUpstream(t, upstreamToken)
	defer ts.Close()

	res := config.ToolResource{Kind: "mcp", URL: ts.URL, CredentialSource: "static_env", TokenEnv: "UP_TOKEN"}
	p := New(config.GatewayConfig{Tools: map[string]config.ToolResource{"up": res}}, "", broker.StaticEnv{})

	var events []engine.Event
	proxyURL, runToken, err := p.Start(testBinding(), testAgentDef("up"), func(e engine.Event) {
		events = append(events, e)
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	ctx := context.Background()
	sess, err := stubAgentSession(ctx, proxyURL, runToken)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if _, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	if got := lastAuth(); got != "Bearer "+upstreamToken {
		t.Fatalf("upstream Authorization = %q, want %q", got, "Bearer "+upstreamToken)
	}

	var found bool
	for _, e := range events {
		if e.Type == "tool_call" {
			found = true
			if e.AuthMode != "static_env" {
				t.Fatalf("AuthMode = %q, want static_env", e.AuthMode)
			}
		}
	}
	if !found {
		t.Fatal("no tool_call event recorded")
	}
}

func TestProxyForwardRecordsToolAndArgsSHA(t *testing.T) {
	const upstreamToken = "up-tok"
	ts, _ := newStubUpstream(t, upstreamToken)
	defer ts.Close()
	t.Setenv("UP_TOKEN", upstreamToken)

	res := config.ToolResource{Kind: "mcp", URL: ts.URL, CredentialSource: "static_env", TokenEnv: "UP_TOKEN"}
	p := New(config.GatewayConfig{Tools: map[string]config.ToolResource{"up": res}}, "", broker.StaticEnv{})

	var events []engine.Event
	proxyURL, runToken, err := p.Start(testBinding(), testAgentDef("up"), func(e engine.Event) { events = append(events, e) })
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	ctx := context.Background()
	sess, err := stubAgentSession(ctx, proxyURL, runToken)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if _, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	var tc *engine.Event
	for i := range events {
		if events[i].Type == "tool_call" {
			tc = &events[i]
		}
	}
	if tc == nil {
		t.Fatal("no tool_call event")
	}
	if tc.Tool != "echo" {
		t.Fatalf("Tool = %q, want echo", tc.Tool)
	}
	// The wire arguments are the JSON encoding of map[string]any{"text":"hi"};
	// encoding/json marshals a single-key map deterministically, so the exact
	// wire bytes (and therefore ArgsSHA) are stable — assert the precise
	// value, not just its shape, so a change to what actually reaches the
	// upstream (not merely its length) fails this test.
	wantArgs := []byte(`{"text":"hi"}`)
	wantSum := sha256.Sum256(wantArgs)
	wantSHA := hex.EncodeToString(wantSum[:])
	if tc.ArgsSHA != wantSHA {
		t.Fatalf("ArgsSHA = %q, want %q (sha256 of %s)", tc.ArgsSHA, wantSHA, wantArgs)
	}
}

func TestProxyDeniedToolRecordsRefusedEvent(t *testing.T) {
	const upstreamToken = "up-tok"
	ts, _ := newStubUpstream(t, upstreamToken) // exposes only "echo"
	defer ts.Close()
	t.Setenv("UP_TOKEN", upstreamToken)

	res := config.ToolResource{Kind: "mcp", URL: ts.URL, CredentialSource: "static_env", TokenEnv: "UP_TOKEN"}
	p := New(config.GatewayConfig{Tools: map[string]config.ToolResource{"up": res}}, "", broker.StaticEnv{})

	var events []engine.Event
	proxyURL, runToken, err := p.Start(testBinding(), testAgentDef("up"), func(e engine.Event) { events = append(events, e) })
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	ctx := context.Background()
	sess, err := stubAgentSession(ctx, proxyURL, runToken)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	defer func() { _ = sess.Close() }()

	// A tool the proxy does NOT expose: the call must error AND be recorded.
	// The argument carries a distinctive marker so we can assert below that
	// the raw argument value never enters the recorded event — only its hash.
	const marker = "zzz-marker-9137"
	if _, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "not-a-real-tool", Arguments: map[string]any{"secretish": marker}}); err == nil {
		t.Fatal("expected an error calling an unexposed tool")
	}

	var refused *engine.Event
	for i := range events {
		if events[i].Type == "tool_call" && events[i].Status == "refused" {
			refused = &events[i]
		}
	}
	if refused == nil {
		t.Fatal("denied attempt left no refused tool_call event")
	}
	if refused.Tool != "not-a-real-tool" {
		t.Fatalf("refused.Tool = %q, want not-a-real-tool", refused.Tool)
	}
	if refused.ArgsSHA == "" {
		t.Fatal("refused event should carry an args fingerprint")
	}

	marshaled, err := json.Marshal(refused)
	if err != nil {
		t.Fatalf("marshal refused event: %v", err)
	}
	if strings.Contains(string(marshaled), marker) {
		t.Fatalf("refused event carries the raw argument value: %s", marshaled)
	}
}

func TestProxyExposedToolEmitsExactlyOneEvent(t *testing.T) {
	const upstreamToken = "up-tok"
	ts, _ := newStubUpstream(t, upstreamToken)
	defer ts.Close()
	t.Setenv("UP_TOKEN", upstreamToken)

	res := config.ToolResource{Kind: "mcp", URL: ts.URL, CredentialSource: "static_env", TokenEnv: "UP_TOKEN"}
	p := New(config.GatewayConfig{Tools: map[string]config.ToolResource{"up": res}}, "", broker.StaticEnv{})

	var events []engine.Event
	proxyURL, runToken, err := p.Start(testBinding(), testAgentDef("up"), func(e engine.Event) { events = append(events, e) })
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	ctx := context.Background()
	sess, err := stubAgentSession(ctx, proxyURL, runToken)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if _, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	n := 0
	for _, e := range events {
		if e.Type == "tool_call" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("exposed-tool call produced %d tool_call events, want exactly 1 (middleware must not double-emit)", n)
	}
}

func execPost(t *testing.T, base, path, runToken, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+runToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("exec post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func startExecProxy(t *testing.T, allow []config.ExecEntry, record func(engine.Event)) (string, string, func()) {
	t.Helper()
	agent := config.AgentDef{Name: "builder", Execution: "fronted", Endpoint: "https://x/run",
		Exec: config.ExecConfig{Mode: "attested", Allow: allow}}
	p := New(config.GatewayConfig{}, "", broker.StaticEnv{})
	url, token, err := p.Start(testBinding(), agent, record)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return url, token, p.Stop
}

func TestExecAuthorizeAllows(t *testing.T) {
	var ev []engine.Event
	base, token, stop := startExecProxy(t, []config.ExecEntry{{Exe: "go", ArgsPrefix: []string{"test"}}}, func(e engine.Event) { ev = append(ev, e) })
	defer stop()
	code, body := execPost(t, base, "exec/authorize", token, `{"command":["go","test","./..."]}`)
	if code != 200 || !strings.Contains(body, `"allowed":true`) {
		t.Fatalf("authorize allow: code=%d body=%s", code, body)
	}
	for _, e := range ev {
		if e.Type == "exec" {
			t.Fatalf("an allowed authorize must emit no event, got %+v", e)
		}
	}
}

func TestExecAuthorizeDeniesAndRecords(t *testing.T) {
	var ev []engine.Event
	base, token, stop := startExecProxy(t, []config.ExecEntry{{Exe: "go", ArgsPrefix: []string{"test"}}}, func(e engine.Event) { ev = append(ev, e) })
	defer stop()
	code, body := execPost(t, base, "exec/authorize", token, `{"command":["rm","-rf","/"]}`)
	if code != 200 || !strings.Contains(body, `"allowed":false`) {
		t.Fatalf("authorize deny: code=%d body=%s", code, body)
	}
	var refused *engine.Event
	for i := range ev {
		if ev[i].Type == "exec" && ev[i].Status == "refused" {
			refused = &ev[i]
		}
	}
	if refused == nil || len(refused.Command) == 0 || refused.Command[0] != "rm" || refused.Mode != "attested" {
		t.Fatalf("expected a refused exec event naming the command, got %+v", refused)
	}
}

func TestExecAttestRecords(t *testing.T) {
	var ev []engine.Event
	base, token, stop := startExecProxy(t, []config.ExecEntry{{Exe: "go"}}, func(e engine.Event) { ev = append(ev, e) })
	defer stop()
	code, _ := execPost(t, base, "exec/attest", token, `{"command":["go","test"],"exit":0,"output_sha":"deadbeef"}`)
	if code != 204 {
		t.Fatalf("attest code=%d", code)
	}
	var rec *engine.Event
	for i := range ev {
		if ev[i].Type == "exec" && ev[i].Status == "succeeded" {
			rec = &ev[i]
		}
	}
	if rec == nil || rec.ExitCode == nil || *rec.ExitCode != 0 || rec.OutputSHA != "deadbeef" || rec.Mode != "attested" {
		t.Fatalf("attest event wrong: %+v", rec)
	}
}

func TestExecAttestRequiresExit(t *testing.T) {
	var ev []engine.Event
	base, token, stop := startExecProxy(t, []config.ExecEntry{{Exe: "go"}}, func(e engine.Event) { ev = append(ev, e) })
	defer stop()
	code, body := execPost(t, base, "exec/attest", token, `{"command":["go","test"],"output_sha":"deadbeef"}`)
	if code != 400 {
		t.Fatalf("attest missing exit: code=%d body=%s", code, body)
	}
	for _, e := range ev {
		if e.Type == "exec" {
			t.Fatalf("a missing exit must record no exec event, got %+v", e)
		}
	}
}

func TestExecEndpointRejectsBadRunToken(t *testing.T) {
	base, _, stop := startExecProxy(t, []config.ExecEntry{{Exe: "go"}}, func(engine.Event) {})
	defer stop()
	req, _ := http.NewRequest(http.MethodPost, base+"exec/authorize", strings.NewReader(`{"command":["go"]}`))
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 401 {
		t.Fatalf("bad token exec code=%d, want 401", resp.StatusCode)
	}
}

func TestExecAndToolCallRecordInCallOrder(t *testing.T) {
	const upstreamToken = "up-tok"
	ts, _ := newStubUpstream(t, upstreamToken)
	defer ts.Close()
	t.Setenv("UP_TOKEN", upstreamToken)

	res := config.ToolResource{Kind: "mcp", URL: ts.URL, CredentialSource: "static_env", TokenEnv: "UP_TOKEN"}
	p := New(config.GatewayConfig{Tools: map[string]config.ToolResource{"up": res}}, "", broker.StaticEnv{})
	agent := config.AgentDef{
		Name: "builder", Execution: "fronted", Endpoint: "https://x/run",
		Tools: []string{"up"},
		Exec:  config.ExecConfig{Mode: "attested", Allow: []config.ExecEntry{{Exe: "go"}}},
	}
	var mu sync.Mutex
	var ev []engine.Event
	base, token, err := p.Start(testBinding(), agent, func(e engine.Event) {
		mu.Lock()
		ev = append(ev, e)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	if code, body := execPost(t, base, "exec/attest", token, `{"command":["go","test"],"exit":0,"output_sha":"aa"}`); code != 204 {
		t.Fatalf("first attest: code=%d body=%s", code, body)
	}
	ctx := context.Background()
	sess, err := stubAgentSession(ctx, base, token)
	if err != nil {
		t.Fatalf("agent session: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if _, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if code, body := execPost(t, base, "exec/attest", token, `{"command":["go","test"],"exit":1,"output_sha":"bb"}`); code != 204 {
		t.Fatalf("second attest: code=%d body=%s", code, body)
	}

	mu.Lock()
	defer mu.Unlock()
	var kinds []string
	for _, e := range ev {
		if e.Type == "exec" || e.Type == "tool_call" {
			kinds = append(kinds, e.Type)
		}
	}
	want := []string{"exec", "tool_call", "exec"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("event order = %v, want %v", kinds, want)
	}
}

func TestExecStopWaitsForInFlightAttest(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	appendEvent := func(engine.Event) {
		close(entered)
		<-release
	}
	agent := config.AgentDef{Name: "builder", Execution: "fronted", Endpoint: "https://x/run",
		Exec: config.ExecConfig{Mode: "attested", Allow: []config.ExecEntry{{Exe: "go"}}}}
	p := New(config.GatewayConfig{}, "", broker.StaticEnv{})
	base, token, err := p.Start(testBinding(), agent, appendEvent)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	callDone := make(chan struct{})
	go func() {
		defer close(callDone)
		req, _ := http.NewRequest(http.MethodPost, base+"exec/attest", strings.NewReader(`{"command":["go","test"],"exit":0,"output_sha":"aa"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("attest never reached the ledger append")
	}

	stopDone := make(chan struct{})
	go func() {
		p.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
		t.Fatal("Stop() returned while an attest append was still in flight")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)

	select {
	case <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return after the in-flight attest finished")
	}
	<-callDone
	p.Stop()
}

// modelUpstream is a stub OpenAI-compatible provider. It records the request
// the proxy forwarded and answers in one of a few modes.
type modelUpstream struct {
	mu      sync.Mutex
	calls   int
	auth    string
	model   string
	body    []byte
	headers http.Header
	mode    string
}

func (u *modelUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req map[string]any
	_ = json.Unmarshal(body, &req)
	model, _ := req["model"].(string)
	u.mu.Lock()
	u.calls++
	u.auth = r.Header.Get("Authorization")
	u.model = model
	u.body = body
	u.headers = r.Header.Clone()
	mode := u.mode
	u.mu.Unlock()

	switch mode {
	case "429":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"SECRET-UPSTREAM-BODY budget exceeded"}}`))
	case "stream":
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
	case "huge":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(make([]byte, (10<<20)+1))
	default:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":12,"completion_tokens":0}}`))
	}
}

func (u *modelUpstream) snapshot() (calls int, auth, model string, body []byte, headers http.Header) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls, u.auth, u.model, append([]byte(nil), u.body...), u.headers.Clone()
}

func startModelGateway(t *testing.T, up *modelUpstream, agent config.AgentDef, keyRoot string) (*Gateway, string, string, *[]engine.Event) {
	t.Helper()
	ts := httptest.NewServer(up)
	t.Cleanup(ts.Close)
	gw := config.GatewayConfig{
		Models: map[string]config.ModelRoute{
			"planner-model": {Endpoint: ts.URL, Model: "gpt-4o", APIKeyEnv: "MODEL_KEY"},
		},
	}
	gw.Defaults.Model = "planner-model"
	p := New(gw, keyRoot, broker.StaticEnv{})
	var mu sync.Mutex
	var events []engine.Event
	base, token, err := p.Start(testBinding(), agent, func(e engine.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Stop)
	return p, base, token, &events
}

func postModel(t *testing.T, base, token, body string, extra http.Header) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestModelProxyInjectsKeyRewritesModelAndStripsPassthrough(t *testing.T) {
	const marker = "DISTINCTIVE-PROMPT-MARKER-9f3a"
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{}
	agent := config.AgentDef{Name: "planner", Execution: "fronted", Endpoint: "https://x", Model: "planner-model"}
	_, base, token, events := startModelGateway(t, up, agent, t.TempDir())

	extra := http.Header{}
	extra.Set("X-Agenthof-Foo", "leak")
	extra.Set("Cookie", "session=secret")
	resp := postModel(t, base, token, `{"model":"planner-model","messages":[{"role":"user","content":"`+marker+`"}]}`, extra)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	calls, auth, model, body, hdr := up.snapshot()
	if calls != 1 {
		t.Fatalf("upstream calls = %d", calls)
	}
	if auth != "Bearer sk-provider" || strings.Contains(auth, token) {
		t.Fatalf("upstream auth = %q, want the provider key and not the run token", auth)
	}
	if model != "gpt-4o" {
		t.Fatalf("forwarded model = %q", model)
	}
	if strings.Contains(string(body), "include_usage") || strings.Contains(string(body), "stream_options") {
		t.Fatalf("proxy injected stream_options: %s", body)
	}
	for k := range hdr {
		if strings.HasPrefix(k, "X-Agenthof-") {
			t.Fatalf("upstream saw %s", k)
		}
	}
	if hdr.Get("Cookie") != "" {
		t.Fatalf("upstream saw Cookie: %q", hdr.Get("Cookie"))
	}

	if len(*events) != 1 {
		t.Fatalf("events = %+v", *events)
	}
	ev := (*events)[0]
	if ev.Type != "model_call" || ev.Model != "planner-model" || ev.Status != "succeeded" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.PromptTokens == nil || *ev.PromptTokens != 12 || ev.CompletionTokens == nil || *ev.CompletionTokens != 0 {
		t.Fatalf("usage = %v %v", ev.PromptTokens, ev.CompletionTokens)
	}
	raw, _ := json.Marshal(*events)
	if strings.Contains(string(raw), marker) {
		t.Fatalf("prompt leaked into the ledger: %s", raw)
	}
}

func TestModelProxyRefusesUndeclaredModel(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{}
	agent := config.AgentDef{Name: "planner", Execution: "fronted", Endpoint: "https://x", Model: "planner-model"}
	_, base, token, events := startModelGateway(t, up, agent, t.TempDir())

	resp := postModel(t, base, token, `{"model":"other","messages":[]}`, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if calls, _, _, _, _ := up.snapshot(); calls != 0 {
		t.Fatalf("upstream was called %d times", calls)
	}
	if len(*events) != 1 || (*events)[0].Status != "refused" || (*events)[0].Model != "other" {
		t.Fatalf("events = %+v", *events)
	}
}

func TestModelProxyUsesDefaultsModel(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{}
	agent := config.AgentDef{Name: "planner", Execution: "fronted", Endpoint: "https://x"}
	_, base, token, events := startModelGateway(t, up, agent, t.TempDir())

	resp := postModel(t, base, token, `{"model":"planner-model","messages":[]}`, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if _, _, model, _, _ := up.snapshot(); model != "gpt-4o" {
		t.Fatalf("forwarded model = %q", model)
	}
	if len(*events) != 1 || (*events)[0].Status != "succeeded" {
		t.Fatalf("events = %+v", *events)
	}
}

func TestModelProxyBudgetRefusalDoesNotEchoBody(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "429"}
	agent := config.AgentDef{Name: "planner", Execution: "fronted", Endpoint: "https://x", Model: "planner-model"}
	_, base, token, events := startModelGateway(t, up, agent, t.TempDir())

	resp := postModel(t, base, token, `{"model":"planner-model","messages":[]}`, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 relayed", resp.StatusCode)
	}
	if len(*events) != 1 || (*events)[0].Status != "refused" || (*events)[0].Reason != "budget" {
		t.Fatalf("events = %+v", *events)
	}
	raw, _ := json.Marshal(*events)
	if strings.Contains(string(raw), "SECRET-UPSTREAM-BODY") {
		t.Fatalf("upstream body leaked into the ledger: %s", raw)
	}
}

func TestModelProxyRelaysStreamWithoutUsage(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "stream"}
	agent := config.AgentDef{Name: "planner", Execution: "fronted", Endpoint: "https://x", Model: "planner-model"}
	_, base, token, events := startModelGateway(t, up, agent, t.TempDir())

	resp := postModel(t, base, token, `{"model":"planner-model","stream":true,"messages":[{"role":"user","content":"DISTINCTIVE-PROMPT-MARKER-9f3a"}]}`, nil)
	defer func() { _ = resp.Body.Close() }()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(got), `"content":"hi"`) {
		t.Fatalf("status %d body %s", resp.StatusCode, got)
	}
	if len(*events) != 1 || (*events)[0].Status != "started" || (*events)[0].PromptTokens != nil || (*events)[0].CompletionTokens != nil {
		t.Fatalf("events = %+v", *events)
	}
	raw, _ := json.Marshal(*events)
	if strings.Contains(string(raw), "DISTINCTIVE-PROMPT-MARKER-9f3a") {
		t.Fatalf("prompt leaked: %s", raw)
	}
}

func TestModelProxyPrefersProvisionedRoleKey(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	root := t.TempDir()
	dir := filepath.Join(root, ".agenthof", "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "se.key"), []byte("sk-role\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	up := &modelUpstream{}
	agent := config.AgentDef{Name: "planner", Execution: "fronted", Endpoint: "https://x", Model: "planner-model"}
	_, base, token, _ := startModelGateway(t, up, agent, root)

	resp := postModel(t, base, token, `{"model":"planner-model","messages":[]}`, nil)
	defer func() { _ = resp.Body.Close() }()
	if _, auth, _, _, _ := up.snapshot(); auth != "Bearer sk-role" {
		t.Fatalf("upstream auth = %q, want the provisioned role key", auth)
	}
}

func TestModelProxyOversizedResponseFails(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{mode: "huge"}
	agent := config.AgentDef{Name: "planner", Execution: "fronted", Endpoint: "https://x", Model: "planner-model"}
	_, base, token, events := startModelGateway(t, up, agent, t.TempDir())

	resp := postModel(t, base, token, `{"model":"planner-model","messages":[]}`, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if len(*events) != 1 || (*events)[0].Status != "failed" || (*events)[0].Reason != "upstream response too large" {
		t.Fatalf("events = %+v", *events)
	}
}

func TestModelProxyStopWaitsForInFlightAppend(t *testing.T) {
	t.Setenv("MODEL_KEY", "sk-provider")
	up := &modelUpstream{}
	ts := httptest.NewServer(up)
	defer ts.Close()
	p := New(config.GatewayConfig{
		Models: map[string]config.ModelRoute{
			"planner-model": {Endpoint: ts.URL, Model: "gpt-4o", APIKeyEnv: "MODEL_KEY"},
		},
	}, t.TempDir(), broker.StaticEnv{})
	agent := config.AgentDef{Name: "planner", Execution: "fronted", Endpoint: "https://x", Model: "planner-model"}

	entered := make(chan struct{})
	release := make(chan struct{})
	base, token, err := p.Start(testBinding(), agent, func(engine.Event) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	callDone := make(chan struct{})
	go func() {
		defer close(callDone)
		req, err := http.NewRequest(http.MethodPost, base+"v1/chat/completions", strings.NewReader(`{"model":"planner-model","messages":[]}`))
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("model_call append never started")
	}
	stopDone := make(chan struct{})
	go func() {
		p.Stop()
		close(stopDone)
	}()
	select {
	case <-stopDone:
		t.Fatal("Stop() returned while a model_call append was in flight")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return after the in-flight model_call finished")
	}
	<-callDone
}
