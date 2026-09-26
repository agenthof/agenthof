package engine_test

// TestOperationalLogCarriesNoSecret is the Article III guard for the
// operational log: at Debug, in text and JSON, across the success and
// failure branches of all three doors, no injected provider key, resource
// credential, minted token, client secret, query-string secret, or run token
// appears in any form — raw, base64(id:secret) as the Basic header carries
// it, or an 8-character prefix. No partial, hashed, or truncated rendering of
// a secret is acceptable.

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/obs"
	"github.com/agenthof/agenthof/internal/registry"
	"github.com/agenthof/agenthof/internal/rungateway"
)

// Alphanumeric test secrets: JSON escaping cannot alter them, so a substring
// match is exact in both text and JSON output. Each starts with "zq9" so its
// 8-character prefix is never a dictionary word that a legitimate log
// message (e.g. "provider") could contain by accident.
const (
	providerKey = "zq9providerkeyAAAA1111"
	toolBearer  = "zq9toolbearerBBBB2222"
	ccClientID  = "zq9clientidCCCC3333"
	ccSecret    = "zq9clientsecretDDDD4444"
	mintedToken = "zq9mintedtokenEEEE5555"
	querySecret = "zq9querysecretFFFF6666"
)

// lockedBuffer is the capture sink. slog handlers serialize their own Write
// calls, but the test reads the buffer after Run returns while a model-door
// handler goroutine may still be finishing, so the read is locked too.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// closedAddr returns a loopback host:port nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// doorExec is the fronted step: it receives the proxy coordinates, records
// the run token for the absence check, and drives the scenario's door call.
type doorExec struct {
	call   func(ctx context.Context, url, token string) error
	mu     sync.Mutex
	tokens []string
}

func (d *doorExec) Execute(ctx context.Context, _ engine.Binding, _ config.AgentDef, _ string, _ map[string]string) (engine.StepResult, error) {
	url, token, ok := engine.ProxyCoordinatesFrom(ctx)
	if !ok {
		return engine.StepResult{Success: false, Reason: "no proxy coordinates"}, nil
	}
	d.mu.Lock()
	d.tokens = append(d.tokens, token)
	d.mu.Unlock()
	if err := d.call(ctx, url, token); err != nil {
		return engine.StepResult{Success: false, Reason: "door call failed"}, nil
	}
	return engine.StepResult{Success: true, Artifact: "ok"}, nil
}

func (d *doorExec) seenTokens() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.tokens...)
}

// bearerRT presents the run token on the agent-side MCP leg.
type bearerRT struct {
	base  http.RoundTripper
	token string
}

func (b *bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// callEcho drives the tool door as a fronted agent: connect to the proxy with
// the run token and call echo.
func callEcho(ctx context.Context, proxyURL, token string) error {
	client := mcp.NewClient(&mcp.Implementation{Name: "agent-stub", Version: "v0.1.0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   proxyURL,
		HTTPClient: &http.Client{Transport: &bearerRT{base: http.DefaultTransport, token: token}},
	}, nil)
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi"}})
	if err != nil {
		return err
	}
	if res.IsError {
		return errors.New("tool reported error")
	}
	return nil
}

// callExec drives the exec door: an allowed authorize, a refused authorize,
// and an attest.
func callExec(ctx context.Context, proxyURL, token string) error {
	post := func(path, body string) (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+path, strings.NewReader(body))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := post("exec/authorize", `{"command":["ls"]}`); err != nil || code != http.StatusOK {
		return fmt.Errorf("authorize allowed: code=%d err=%v", code, err)
	}
	if code, err := post("exec/authorize", `{"command":["rm","-rf","/"]}`); err != nil || code != http.StatusOK {
		return fmt.Errorf("authorize refused: code=%d err=%v", code, err) // refusal is a 200 with allowed:false
	}
	if code, err := post("exec/attest", `{"command":["ls"],"exit":0,"output_sha":"abc"}`); err != nil || code != http.StatusNoContent {
		return fmt.Errorf("attest: code=%d err=%v", code, err)
	}
	return nil
}

// stubMCP is an upstream MCP server exposing echo(text) that requires the
// given bearer on the injected upstream leg.
func stubMCP(t *testing.T, wantBearer string) *httptest.Server {
	t.Helper()
	type echoArgs struct {
		Text string `json:"text"`
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "upstream-stub", Version: "v0.1.0"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "echo", Description: "echo back text"},
		func(_ context.Context, req *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
			var auth string
			if req.Extra != nil && req.Extra.Header != nil {
				auth = req.Extra.Header.Get("Authorization")
			}
			if auth != "Bearer "+wantBearer {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "unauthorized"}}}, nil, nil
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: args.Text}}}, nil, nil
		})
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil))
	t.Cleanup(ts.Close)
	return ts
}

func modelUpstream(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

func modelOK(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
}

func model401(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "invalid api key "+providerKey, http.StatusUnauthorized) // an upstream that echoes the key back
}

func modelHuge(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	chunk := bytes.Repeat([]byte("x"), 1<<20)
	for i := 0; i < 11; i++ { // 11 MiB > the door's 10 MiB cap
		_, _ = w.Write(chunk)
	}
}

func tokenEndpoint(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func staticTool(url string) config.ToolResource {
	return config.ToolResource{Kind: "mcp", URL: url, CredentialSource: "static_env", TokenEnv: "TOOL_BEARER"}
}

func ccTool(url, tokenURL string) config.ToolResource {
	return config.ToolResource{
		Kind: "mcp", URL: url, CredentialSource: "static_env",
		GrantType: "client_credentials", ClientAuth: "client_secret_basic",
		Issuer: "https://id.example", TokenEndpoint: tokenURL,
		ClientIDEnv: "CC_ID", ClientSecretEnv: "CC_SECRET",
	}
}

type doorScenario struct {
	name       string
	gateway    config.GatewayConfig
	agent      config.AgentDef // Model / Tools / Exec only; the rest is filled in
	call       func(ctx context.Context, url, token string) error
	wantStatus string
	// wantLine is the log line that proves THIS scenario's branch was
	// captured: the listener line for scenarios that reach it, the connect
	// failure for the two that fail inside Start before the listener binds.
	wantLine string
}

const (
	lineListener = "gateway listener started"
	lineConnect  = "upstream connect failed"
)

func buildRegistry(t *testing.T, s doorScenario) *registry.Registry {
	t.Helper()
	agent := s.agent
	agent.Name, agent.Output, agent.SourceFile = "fe", "out", "a"
	agent.Execution, agent.Endpoint = "fronted", "https://agent.example"
	cfg := config.Config{
		Agents:    []config.AgentDef{agent},
		Workflows: []config.WorkflowDef{{Name: "wf", SourceFile: "w", Steps: []config.Step{{Name: "step1", Agent: "fe"}}}},
		Roles:     []config.RoleDef{{Name: "se", Workflows: []string{"wf"}, AllowedGroups: []string{"*"}, SourceFile: "r"}},
		Gateway:   s.gateway,
	}
	reg, errs := registry.Build(cfg)
	if reg == nil {
		t.Fatalf("%s: registry: %v", s.name, errs)
	}
	return reg
}

func TestOperationalLogCarriesNoSecret(t *testing.T) {
	t.Setenv("MODEL_KEY", providerKey)
	t.Setenv("TOOL_BEARER", toolBearer)
	t.Setenv("CC_ID", ccClientID)
	t.Setenv("CC_SECRET", ccSecret)

	refusedAddr := closedAddr(t)
	modelRoute := func(endpoint string) config.GatewayConfig {
		return config.GatewayConfig{Models: map[string]config.ModelRoute{"fast": {Endpoint: endpoint, Model: "gpt-test", APIKeyEnv: "MODEL_KEY"}}}
	}
	toolCfg := func(res config.ToolResource) config.GatewayConfig {
		return config.GatewayConfig{Tools: map[string]config.ToolResource{"up": res}}
	}
	toolGrant := config.AgentDef{Tools: []config.ToolGrant{{Resource: "up"}}}
	basicPair := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(ccClientID) + ":" + url.QueryEscape(ccSecret)))

	scenarios := []doorScenario{
		{name: "model success", gateway: modelRoute(modelUpstream(t, modelOK).URL), agent: config.AgentDef{Model: "fast"}, call: postModel, wantStatus: "succeeded", wantLine: lineListener},
		{name: "model upstream 401 echoing the key", gateway: modelRoute(modelUpstream(t, model401).URL), agent: config.AgentDef{Model: "fast"}, call: postModel, wantStatus: "failed", wantLine: lineListener},
		{name: "model upstream connection refused with query secret", gateway: modelRoute("http://" + refusedAddr + "/v1?key=" + querySecret), agent: config.AgentDef{Model: "fast"}, call: postModel, wantStatus: "failed", wantLine: lineListener},
		{name: "model upstream oversized body", gateway: modelRoute(modelUpstream(t, modelHuge).URL), agent: config.AgentDef{Model: "fast"}, call: postModel, wantStatus: "failed", wantLine: lineListener},
		{name: "tool static bearer success", gateway: toolCfg(staticTool(stubMCP(t, toolBearer).URL)), agent: toolGrant, call: callEcho, wantStatus: "succeeded", wantLine: lineListener},
		{name: "tool upstream rejects credential", gateway: toolCfg(staticTool(stubMCP(t, "somethingelse").URL)), agent: toolGrant, call: callEcho, wantStatus: "failed", wantLine: lineListener},
		{name: "tool upstream connection refused with query secret", gateway: toolCfg(staticTool("http://" + refusedAddr + "/?key=" + querySecret)), agent: toolGrant, call: callEcho, wantStatus: "failed", wantLine: lineConnect},
		{name: "tool client_credentials success", gateway: toolCfg(ccTool(stubMCP(t, mintedToken).URL, tokenEndpoint(t, http.StatusOK, `{"access_token":"`+mintedToken+`","token_type":"Bearer","expires_in":3600}`).URL)), agent: toolGrant, call: callEcho, wantStatus: "succeeded", wantLine: lineListener},
		{name: "tool client_credentials token endpoint rejects and echoes the secret", gateway: toolCfg(ccTool(stubMCP(t, mintedToken).URL, tokenEndpoint(t, http.StatusUnauthorized, `{"error":"invalid_client","error_description":"secret `+ccSecret+` rejected for `+ccClientID+`"}`).URL)), agent: toolGrant, call: callEcho, wantStatus: "failed", wantLine: lineConnect},
		{name: "exec allowed, refused, attested", gateway: config.GatewayConfig{}, agent: config.AgentDef{Exec: config.ExecConfig{Mode: "attested", Allow: []config.ExecEntry{{Exe: "ls"}}}}, call: callExec, wantStatus: "succeeded", wantLine: lineListener},
	}

	formats := []struct {
		name   string
		format obs.Format
	}{{"text", obs.FormatText}, {"json", obs.FormatJSON}}

	for _, s := range scenarios {
		for _, f := range formats {
			t.Run(s.name+"/"+f.name, func(t *testing.T) {
				reg := buildRegistry(t, s)
				sink := &lockedBuffer{}
				logger := obs.New(sink, slog.LevelDebug, f.format)
				keyRoot := t.TempDir()
				dir := t.TempDir()
				b := broker.Dispatch{StaticEnv: broker.StaticEnv{}, ClientCredentials: broker.NewClientCredentials(&http.Client{Timeout: 5 * time.Second})}
				ex := &doorExec{call: s.call}
				opts := engine.Options{
					LogDir: dir, ArtifactDir: dir + "/a", StepTimeout: 20 * time.Second, Logger: logger,
					NewGateway: func() engine.ToolProxy { return rungateway.New(s.gateway, keyRoot, b, logger) },
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_, status, err := engine.Run(ctx, reg, "se", "wf", "x", identity.Static("dev@x"), ex, opts)
				if err != nil {
					t.Fatalf("Run returned an error (only refusals and ledger failures do): %v", err)
				}
				if status != s.wantStatus {
					t.Fatalf("status = %q, want %q\nlog:\n%s", status, s.wantStatus, sink.String())
				}

				out := sink.String()
				// A vacuous pass is a failure: the capture must have seen the
				// engine start the step (logged before any door is touched)
				// AND this scenario's own branch, or nothing below proves
				// anything. The two connect-failure scenarios never reach the
				// listener, so the listener line cannot be the sentinel.
				if !strings.Contains(out, "step started") {
					t.Fatalf("capture missed the engine's step line — check the level, format, or sink:\n%s", out)
				}
				if !strings.Contains(out, s.wantLine) {
					t.Fatalf("capture missed this scenario's branch line %q:\n%s", s.wantLine, out)
				}

				secrets := map[string]string{
					"provider key":        providerKey,
					"tool bearer":         toolBearer,
					"client secret":       ccSecret,
					"minted token":        mintedToken,
					"query-string secret": querySecret,
					"basic id:secret":     basicPair,
				}
				for i, tok := range ex.seenTokens() {
					secrets[fmt.Sprintf("run token %d", i)] = tok
				}
				for name, secret := range secrets {
					assertAbsent(t, out, name, secret)
				}
			})
		}
	}
}

// assertAbsent fails if secret appears in out raw or as its first 8
// characters. No partial, hashed, or truncated rendering of a secret is
// acceptable — a key[:6]+"…" preview would pass a raw check while leaking.
func assertAbsent(t *testing.T, out, name, secret string) {
	t.Helper()
	if strings.Contains(out, secret) {
		t.Errorf("%s leaked into the operational log (raw):\n%s", name, out)
	}
	if len(secret) >= 8 && strings.Contains(out, secret[:8]) {
		t.Errorf("%s leaked into the operational log (8-char prefix %q):\n%s", name, secret[:8], out)
	}
}
