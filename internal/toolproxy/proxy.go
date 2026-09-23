// Package toolproxy is Agenthof's enforced inbound MCP proxy: a
// credential-starved agent reaches a declared tool/MCP resource only through
// here, which authenticates the step (a per-step run token), authorizes
// against the agent's allowlist, injects a resource credential the agent
// never sees (no-passthrough), forwards the call to the upstream MCP server,
// and appends a tool_call event per call.
package toolproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

// connectTimeout bounds an upstream connect/list-tools call at Start time so a
// hung upstream fails the step instead of hanging Start indefinitely.
const connectTimeout = 30 * time.Second

// Proxy implements engine.ToolProxy: for one fronted step it mints a run
// token, connects to each of the agent's allowlisted tool resources as an MCP
// client (with a broker-injected credential the agent never sees), mirrors
// their tools onto an inbound MCP server gated by the run token, and forwards
// calls, appending a tool_call event per call.
type Proxy struct {
	tools  map[string]config.ToolResource
	broker broker.Broker

	mu       sync.Mutex
	srv      *http.Server
	sessions []*mcp.ClientSession
	closing  bool
	// inflight counts forward calls currently running, so Stop can wait for
	// them to finish independent of how the underlying HTTP server treats
	// in-flight connections when closed.
	inflight sync.WaitGroup
}

// New builds a Proxy over the gateway's declared tool resources, resolving
// upstream credentials through b.
func New(tools map[string]config.ToolResource, b broker.Broker) *Proxy {
	return &Proxy{tools: tools, broker: b}
}

// Start serves one fronted step. It mints a run token, connects to each of
// agent.Tools' resources as an upstream MCP client, mirrors their tools onto
// an inbound MCP server gated by that token, and binds an ephemeral localhost
// listener. It returns the URL the agent must call and the token it must
// present — the token travels only in the HTTP Authorization header, never on
// Binding or the ledger.
func (p *Proxy) Start(bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event)) (string, string, error) {
	token, err := mintToken()
	if err != nil {
		return "", "", fmt.Errorf("mint run token: %w", err)
	}

	allow := map[string]bool{}
	for _, id := range agent.Tools {
		allow[id] = true
	}

	inbound := mcp.NewServer(&mcp.Implementation{Name: "agenthof-tool-proxy", Version: "v0.1.0"}, nil)

	var sessions []*mcp.ClientSession
	closeSessions := func() {
		for _, s := range sessions {
			_ = s.Close()
		}
	}

	// Mirror in agent.Tools' declared order (not map iteration order) so a
	// name collision between two allowlisted resources' tools is resolved
	// deterministically rather than by map-order luck — and rejected outright
	// rather than silently letting the last one registered shadow the first.
	seenResource := map[string]bool{}
	mirroredBy := map[string]string{} // upstream tool name -> resource id that mirrored it
	for _, id := range agent.Tools {
		if seenResource[id] {
			continue
		}
		seenResource[id] = true

		res, ok := p.tools[id]
		if !ok {
			// Registry validation guarantees every declared agent.Tools entry
			// names a gateway resource; skip defensively rather than fail the
			// step over a state that should be unreachable.
			continue
		}

		sess, err := p.connectUpstream(id, res)
		if err != nil {
			closeSessions()
			return "", "", fmt.Errorf("connect upstream %q: %w", id, err)
		}
		sessions = append(sessions, sess)

		listCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		list, err := sess.ListTools(listCtx, nil)
		cancel()
		if err != nil {
			closeSessions()
			return "", "", fmt.Errorf("list tools for %q: %w", id, err)
		}
		for _, tool := range list.Tools {
			if owner, dup := mirroredBy[tool.Name]; dup {
				closeSessions()
				return "", "", fmt.Errorf("tool %q is exposed by both resource %q and %q", tool.Name, owner, id)
			}
			mirroredBy[tool.Name] = id
			inbound.AddTool(tool, p.forward(bind, agent, id, allow, sess, appendEvent))
		}
	}

	inbound.AddReceivingMiddleware(p.refusedTraceMiddleware(mirroredBy, bind, agent, appendEvent))

	handler := authMiddleware(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return inbound }, nil), token)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		closeSessions()
		return "", "", fmt.Errorf("listen: %w", err)
	}

	srv := &http.Server{Handler: handler}

	p.mu.Lock()
	p.srv = srv
	p.sessions = sessions
	p.closing = false
	p.mu.Unlock()

	go func() { _ = srv.Serve(ln) }()

	return "http://" + ln.Addr().String() + "/", token, nil
}

// Stop tears down the inbound listener and closes every upstream session. It
// is synchronous: it waits for every forward call already in flight to finish
// (and so for any appendEvent call it made to return) before it returns —
// the caller can safely close the run's ledger immediately after. The wait is
// tracked by the proxy's own bookkeeping (inflight), not by however the HTTP
// server happens to treat an in-flight connection when closed.
func (p *Proxy) Stop() {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	p.closing = true
	srv := p.srv
	sessions := p.sessions
	p.srv = nil
	p.sessions = nil
	p.mu.Unlock()

	if srv != nil {
		_ = srv.Close() // cut connections now; forward()'s own bookkeeping (not this) is what Stop waits on
	}
	p.inflight.Wait()

	for _, s := range sessions {
		_ = s.Close()
	}
}

// forward returns the ToolHandler mirrored onto the inbound server for one
// upstream tool of resource resourceID. It re-checks resourceID against allow
// at call time (defense in depth, independent of what Start already filtered
// at mirror time), forwards the call to upstream with the arguments passed
// through raw (never touching the run token), and appends a tool_call event
// recording only a result hash + short preview — never the call body or any
// credential.
func (p *Proxy) forward(bind engine.Binding, agent config.AgentDef, resourceID string, allow map[string]bool, upstream *mcp.ClientSession, appendEvent func(engine.Event)) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		p.mu.Lock()
		if p.closing {
			p.mu.Unlock()
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: "tool proxy is shutting down"}},
			}, nil
		}
		p.inflight.Add(1)
		p.mu.Unlock()
		defer p.inflight.Done()

		// Defense-in-depth: only allowlisted resources are ever mirrored, so
		// the receiving middleware (refusedTraceMiddleware) is the real denial
		// path and this branch is unreachable in normal operation. It stays as
		// a per-resource second gate in case mirroring logic ever changes.
		if !allow[resourceID] {
			denyReason := fmt.Sprintf("tool %q on resource %q is not allowlisted for this run", req.Params.Name, resourceID)
			appendEvent(engine.Event{
				Type:             "tool_call",
				Agent:            agent.Name,
				AuthMode:         authModeFor(p.tools[resourceID]),
				Status:           "refused",
				Reason:           denyReason,
				Tool:             req.Params.Name,
				ArgsSHA:          argsSHA(req.Params.Arguments),
				ResourcesTouched: []string{resourceID},
				Binding:          bind,
			})
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: denyReason}},
			}, nil
		}

		result, callErr := upstream.CallTool(ctx, &mcp.CallToolParams{
			Name:      req.Params.Name,
			Arguments: req.Params.Arguments, // raw passthrough — never the run token
		})

		status := "succeeded"
		var reason string
		if callErr != nil {
			status = "failed"
			reason = callErr.Error()
		} else if result != nil && result.IsError {
			status = "failed"
			reason = resultErrorText(result)
		}
		sha, preview := hashResult(result, callErr)

		appendEvent(engine.Event{
			Type:             "tool_call",
			Agent:            agent.Name,
			AuthMode:         authModeFor(p.tools[resourceID]),
			Status:           status,
			Reason:           reason,
			Tool:             req.Params.Name,
			ArgsSHA:          argsSHA(req.Params.Arguments),
			ResourcesTouched: []string{resourceID},
			Binding:          bind,
			ArtifactSHA:      sha,
			Artifact:         preview,
		})

		if callErr != nil {
			return nil, callErr
		}
		return result, nil
	}
}

// connectUpstream connects to res as an MCP client. The resource's credential
// is resolved per outbound request by injectingTransport (the broker caches),
// not once here — a client_credentials token is short-lived and a step may run
// for minutes, so a token captured at connect could expire mid-step.
func (p *Proxy) connectUpstream(id string, res config.ToolResource) (*mcp.ClientSession, error) {
	ref := broker.CredentialRef{
		ResourceID:      id,
		Source:          res.CredentialSource,
		Grant:           res.GrantType,
		ClientAuth:      res.ClientAuth,
		Issuer:          res.Issuer,
		TokenURL:        res.TokenEndpoint,
		Scope:           res.Scope,
		TokenEnv:        res.TokenEnv,
		ClientIDEnv:     res.ClientIDEnv,
		ClientSecretEnv: res.ClientSecretEnv,
	}
	httpClient := &http.Client{Transport: &injectingTransport{base: http.DefaultTransport, broker: p.broker, ref: ref}}
	client := mcp.NewClient(&mcp.Implementation{Name: "agenthof-tool-proxy", Version: "v0.1.0"}, nil)

	// The connect context only bounds the initialize/discover handshake, not
	// the resulting session's lifetime — the SDK's own keepalive/reconnect
	// loops run detached from it — so a bounded context here cannot cut a
	// session short later.
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	return client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   res.URL,
		HTTPClient: httpClient,
	}, nil)
}

// injectingTransport resolves the resource's credential through the broker on
// every outbound request and sets it as the bearer. It is the no-passthrough
// seam: the credential it carries is never the agent's run token, and the
// agent-facing side of the proxy never has access to it. Resolving per request
// (the broker caches) lets a short-lived minted token be refreshed mid-step.
type injectingTransport struct {
	base   http.RoundTripper
	broker broker.Broker
	ref    broker.CredentialRef
}

func (t *injectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cred, err := t.broker.Resolve(req.Context(), t.ref)
	if err != nil {
		return nil, err
	}
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+cred)
	return t.base.RoundTrip(req)
}

// authMiddleware gates the inbound MCP handler behind the run token: a
// missing or mismatched Authorization header is rejected before any MCP
// message is parsed. The comparison is constant-time, so a wrong token
// cannot be distinguished from a right one by how long the check takes.
func authMiddleware(next http.Handler, expectedToken string) http.Handler {
	want := "Bearer " + expectedToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
			http.Error(w, "unauthorized: missing or invalid run token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// mintToken returns a fresh 32-byte run token, hex-encoded.
func mintToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashResult computes the tool_call event's result hash + preview, mirroring
// how the artifact store hashes step outputs (sha256 + a single-line preview
// capped at 200 runes): the ledger carries only this, never the raw result
// body, which may contain upstream data outside Agenthof's control.
func hashResult(result *mcp.CallToolResult, callErr error) (sha, preview string) {
	var body []byte
	switch {
	case callErr != nil:
		body = []byte(callErr.Error())
	case result != nil:
		body, _ = json.Marshal(result)
	}

	sum := sha256.Sum256(body)
	sha = hex.EncodeToString(sum[:])

	preview = strings.Join(strings.Fields(strings.ReplaceAll(string(body), "\n", " ")), " ")
	if r := []rune(preview); len(r) > 200 {
		preview = string(r[:200])
	}
	return sha, preview
}

// mcpMethodToolsCall is the MCP method name for a tool invocation.
const mcpMethodToolsCall = "tools/call"

// refusedTraceMiddleware records a tool_call the proxy does not expose as a
// refused event. Off-allowlist tools are never mirrored onto the inbound
// server, so the server would reject them as "unknown tool" with no ledger
// trace; this middleware runs before dispatch, names the attempted tool, and
// records it — turning a previously-invisible denial into first-hand evidence.
// It only ADDS a refused event for unexposed tools; exposed tools pass through
// untouched (forward emits their event), so there is no double emit.
//
// It is a method on *Proxy (not a free function) so its appendEvent call can
// share forward's closing/inflight bookkeeping: without that, an in-flight
// appendEvent here could run after Stop() returns and race the run's
// log.Close(), violating Stop()'s documented invariant.
func (p *Proxy) refusedTraceMiddleware(mirrored map[string]string, bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event)) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == mcpMethodToolsCall {
				if params, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok {
					if _, exposed := mirrored[params.Name]; !exposed {
						// Bracket the ledger append with the same closing/inflight
						// bookkeeping forward uses, so Stop() waits for it and no
						// append races the run's log.Close() after teardown. If the
						// proxy is already closing, skip the emit and still delegate.
						p.mu.Lock()
						if p.closing {
							p.mu.Unlock()
						} else {
							p.inflight.Add(1)
							p.mu.Unlock()
							appendEvent(engine.Event{
								Type:    "tool_call",
								Agent:   agent.Name,
								Status:  "refused",
								Reason:  "tool is not available to this run",
								Tool:    params.Name,
								ArgsSHA: argsSHA(params.Arguments),
								Binding: bind,
							})
							p.inflight.Done()
						}
					}
				}
			}
			return next(ctx, method, req)
		}
	}
}

// argsSHA returns the hex sha256 of a tool call's raw arguments, a fingerprint
// of what a call tried without ever putting the arguments (which may carry data
// outside Agenthof's control) into the ledger. A nil/empty message hashes the
// empty input; no special-casing.
func argsSHA(raw json.RawMessage) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// authModeFor reports the ledger AuthMode string for a resource: the grant used
// to obtain the upstream credential. Kept in lockstep with the broker's grants.
func authModeFor(res config.ToolResource) string {
	if res.GrantType == "client_credentials" {
		return "client_credentials"
	}
	return "static_env"
}

// resultErrorText extracts a short failure message from an upstream
// CallToolResult flagged IsError, for the tool_call event's Reason. It
// carries no Agenthof credential — the text comes from the upstream MCP
// server's own error content, no more than the preview hashResult already
// puts in the ledger.
func resultErrorText(result *mcp.CallToolResult) string {
	var parts []string
	for _, c := range result.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	text := strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
	if text == "" {
		return "upstream tool call reported an error"
	}
	if r := []rune(text); len(r) > 200 {
		text = string(r[:200])
	}
	return text
}
