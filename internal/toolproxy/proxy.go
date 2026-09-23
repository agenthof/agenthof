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
		return "", "", fmt.Errorf("tool proxy: mint run token: %w", err)
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

		sess, err := p.connectUpstream(res)
		if err != nil {
			closeSessions()
			return "", "", fmt.Errorf("tool proxy: connect upstream %q: %w", id, err)
		}
		sessions = append(sessions, sess)

		listCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		list, err := sess.ListTools(listCtx, nil)
		cancel()
		if err != nil {
			closeSessions()
			return "", "", fmt.Errorf("tool proxy: list tools for %q: %w", id, err)
		}
		for _, tool := range list.Tools {
			if owner, dup := mirroredBy[tool.Name]; dup {
				closeSessions()
				return "", "", fmt.Errorf("tool proxy: tool %q is exposed by both resource %q and %q", tool.Name, owner, id)
			}
			mirroredBy[tool.Name] = id
			inbound.AddTool(tool, p.forward(bind, agent, id, allow, sess, appendEvent))
		}
	}

	handler := authMiddleware(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return inbound }, nil), token)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		closeSessions()
		return "", "", fmt.Errorf("tool proxy: listen: %w", err)
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

		if !allow[resourceID] {
			appendEvent(engine.Event{
				Type:             "tool_call",
				Agent:            agent.Name,
				AuthMode:         "static_env",
				Status:           "refused",
				ResourcesTouched: []string{resourceID},
				Binding:          bind,
			})
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{
					Text: fmt.Sprintf("tool %q on resource %q is not allowlisted for this run", req.Params.Name, resourceID),
				}},
			}, nil
		}

		result, callErr := upstream.CallTool(ctx, &mcp.CallToolParams{
			Name:      req.Params.Name,
			Arguments: req.Params.Arguments, // raw passthrough — never the run token
		})

		status := "succeeded"
		if callErr != nil || (result != nil && result.IsError) {
			status = "failed"
		}
		sha, preview := hashResult(result, callErr)

		appendEvent(engine.Event{
			Type:             "tool_call",
			Agent:            agent.Name,
			AuthMode:         "static_env",
			Status:           status,
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

// connectUpstream connects to res as an MCP client, injecting the resource's
// broker-resolved credential into every outbound request via a RoundTripper.
// The credential is resolved once at connect time and never logged; only the
// env-var NAME (res.TokenEnv) ever appears in an error.
func (p *Proxy) connectUpstream(res config.ToolResource) (*mcp.ClientSession, error) {
	cred, err := p.broker.Resolve(context.Background(), broker.CredentialRef{
		Mode:   "static_env",
		EnvVar: res.TokenEnv,
	})
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{Transport: &injectingTransport{base: http.DefaultTransport, token: cred}}
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

// injectingTransport sets a bearer credential on every outbound request. It
// is the no-passthrough seam: the credential it carries is never the agent's
// run token, and the agent-facing side of the proxy never has access to it.
type injectingTransport struct {
	base  http.RoundTripper
	token string
}

func (t *injectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(req)
}

// authMiddleware gates the inbound MCP handler behind the run token: a
// missing or mismatched Authorization header is rejected before any MCP
// message is parsed.
func authMiddleware(next http.Handler, expectedToken string) http.Handler {
	want := "Bearer " + expectedToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
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
