// Package rungateway is Agenthof's enforced inbound MCP proxy: a
// credential-starved agent reaches a declared tool/MCP resource only through
// here, which authenticates the step (a per-step run token), authorizes
// against the agent's allowlist, injects a resource credential the agent
// never sees (no-passthrough), forwards the call to the upstream MCP server,
// and appends a tool_call event per call.
package rungateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/gateway"
)

// connectTimeout bounds an upstream connect/list-tools call at Start time so a
// hung upstream fails the step instead of hanging Start indefinitely.
const connectTimeout = 30 * time.Second

// Gateway implements engine.ToolProxy: for one fronted step it mints a run
// token, connects to each tool resource the agent's grants name as an MCP
// client (with a broker-injected credential the agent never sees), mirrors
// the granted tools — every tool of a bare grant, only the named tools of a
// restricted one — onto an inbound MCP server gated by the run token, and
// forwards calls, appending a tool_call event per call.
type Gateway struct {
	tools   map[string]config.ToolResource
	broker  broker.Broker
	gwcfg   config.GatewayConfig
	keyRoot string

	mu       sync.Mutex
	srv      *http.Server
	sessions []*mcp.ClientSession
	closing  bool
	// sockPath is set when this step's listener is a Unix socket. Stop removes
	// it explicitly so the unlink is synchronous with Stop returning: srv.Close
	// also unlinks (via Serve's deferred listener Close), but that runs in
	// another goroutine, so without this a caller — or a test — could observe
	// Stop return before the socket file is gone.
	sockPath string
	// inflight counts forward calls currently running, so Stop can wait for
	// them to finish independent of how the underlying HTTP server treats
	// in-flight connections when closed.
	inflight sync.WaitGroup
}

// New builds a Gateway over the gateway config. Tool resources come from
// gw.Tools. keyRoot is the working directory gateway provision writes role
// keys under (".", the same root as EnsureRoleKey), not the --config directory.
func New(gw config.GatewayConfig, keyRoot string, b broker.Broker) *Gateway {
	return &Gateway{tools: gw.Tools, broker: b, gwcfg: gw, keyRoot: keyRoot}
}

// allowedTools is what Start derives from the agent's tool grants: resource
// id → the tool names the agent may see. A PRESENT key with a nil set is a
// bare grant (every tool the resource exposes); an ABSENT key is a resource
// the agent was not granted at all. allows is the only reader, so the
// present-vs-nil distinction cannot be confused with "not granted".
type allowedTools map[string]map[string]struct{}

// allows reports whether tool on resourceID is within the agent's grant.
func (a allowedTools) allows(resourceID, tool string) bool {
	names, granted := a[resourceID]
	if !granted {
		return false
	}
	if names == nil {
		return true // bare grant: every tool
	}
	_, ok := names[tool]
	return ok
}

// Start serves one fronted step. It mints a run token, connects to each
// resource the agent's tool grants name as an upstream MCP client, mirrors
// their tools onto an inbound MCP server gated by that token, and binds an
// ephemeral localhost listener. It returns the URL the agent must call and
// the token it must present — the token travels only in the HTTP
// Authorization header, never on Binding or the ledger.
func (p *Gateway) Start(bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event)) (string, string, error) {
	token, err := mintToken()
	if err != nil {
		return "", "", fmt.Errorf("mint run token: %w", err)
	}

	// Build the per-resource allowlist. Registry validation already rejects
	// a resource granted twice when either grant is restricted, but Start is
	// reachable without the registry, so it fails closed on that shape too
	// rather than letting merge order decide what the agent may see.
	allow := allowedTools{}
	for _, grant := range agent.Tools {
		prev, seen := allow[grant.Resource]
		if seen && (grant.Restricted() || prev != nil) {
			return "", "", fmt.Errorf("resource %q is granted more than once and at least one grant restricts tools", grant.Resource)
		}
		if !grant.Restricted() {
			allow[grant.Resource] = nil // present, nil: every tool
			continue
		}
		names := make(map[string]struct{}, len(grant.Tools))
		for _, name := range grant.Tools {
			names[name] = struct{}{}
		}
		allow[grant.Resource] = names
	}

	inbound := mcp.NewServer(&mcp.Implementation{Name: "agenthof-tool-proxy", Version: "v0.1.0"}, nil)

	var sessions []*mcp.ClientSession
	closeSessions := func() {
		for _, s := range sessions {
			_ = s.Close()
		}
	}

	// Mirror in the grants' declared order (not map iteration order) so a
	// name collision between two allowlisted resources' tools is resolved
	// deterministically rather than by map-order luck — and rejected outright
	// rather than silently letting the last one registered shadow the first.
	seenResource := map[string]bool{}
	mirroredBy := map[string]string{} // upstream tool name -> resource id that mirrored it
	for _, grant := range agent.Tools {
		id := grant.Resource
		if seenResource[id] {
			continue
		}
		seenResource[id] = true

		res, ok := p.tools[id]
		if !ok {
			// Registry validation guarantees every tool grant names a
			// gateway resource; skip defensively rather than fail the
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
		// Filter FIRST, then collision-check: a tool the grant leaves out
		// never enters mirroredBy, so it cannot manufacture a phantom
		// cross-resource collision — and allowlisting a name away is a way
		// to resolve a real one.
		exposed := map[string]bool{}
		for _, tool := range list.Tools {
			exposed[tool.Name] = true
			if !allow.allows(id, tool.Name) {
				continue
			}
			if owner, dup := mirroredBy[tool.Name]; dup {
				closeSessions()
				return "", "", fmt.Errorf("tool %q is exposed by both resource %q and %q", tool.Name, owner, id)
			}
			mirroredBy[tool.Name] = id
			inbound.AddTool(tool, p.forward(bind, agent, id, allow, sess, appendEvent))
		}
		// An allowlisted name the upstream does not expose (a typo, or a
		// tool the upstream since removed) fails the step loudly: a fronted
		// agent never reports ListTools to the operator, so silently
		// mirroring nothing would be indistinguishable from an
		// off-allowlist attempt. Declared order makes the reported name
		// deterministic.
		for _, name := range grant.Tools {
			if !exposed[name] {
				closeSessions()
				return "", "", fmt.Errorf("resource %q does not expose allowlisted tool %q", id, name)
			}
		}
	}

	inbound.AddReceivingMiddleware(p.refusedTraceMiddleware(mirroredBy, bind, agent, appendEvent))

	mux := http.NewServeMux()
	mux.Handle("/", mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return inbound }, nil))
	mux.HandleFunc("/exec/authorize", p.execAuthorizeHandler(bind, agent, appendEvent))
	mux.HandleFunc("/exec/attest", p.execAttestHandler(bind, agent, appendEvent))
	mux.HandleFunc("/v1/chat/completions", p.modelHandler(bind, agent, appendEvent))
	handler := authMiddleware(mux, token)

	var ln net.Listener
	var proxyURL string
	if p.gwcfg.RefboxSocketDir != "" {
		ln, proxyURL, err = listenGateway(p.gwcfg.RefboxSocketDir, bind.RunID)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			proxyURL = "http://" + ln.Addr().String() + "/"
		}
	}
	if err != nil {
		closeSessions()
		return "", "", fmt.Errorf("listen: %w", err)
	}

	srv := &http.Server{Handler: handler}

	p.mu.Lock()
	p.srv = srv
	p.sessions = sessions
	p.closing = false
	p.sockPath = ""
	if path, ok := strings.CutPrefix(proxyURL, config.UnixScheme); ok {
		p.sockPath = path
	}
	p.mu.Unlock()

	go func() { _ = srv.Serve(ln) }()

	return proxyURL, token, nil
}

// guardedAppend appends a ledger event under the same closing/inflight
// bookkeeping forward uses, so Stop() waits for it and no append races the
// run's log.Close() after teardown. If the proxy is already closing, the event
// is dropped rather than racing the close.
func (p *Gateway) guardedAppend(appendEvent func(engine.Event), e engine.Event) {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	p.inflight.Add(1)
	p.mu.Unlock()
	appendEvent(e)
	p.inflight.Done()
}

func (p *Gateway) execAuthorizeHandler(bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command []string `json:"command"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		allowed := agent.Exec.Allows(req.Command)
		if !allowed {
			p.guardedAppend(appendEvent, engine.Event{
				Type: "exec", Agent: agent.Name, Status: "refused",
				Reason:  "command is not on the exec allowlist",
				Command: req.Command,
				Mode:    "attested", Binding: bind,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"allowed": allowed})
	}
}

func (p *Gateway) execAttestHandler(bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command   []string `json:"command"`
			Exit      *int     `json:"exit"`
			OutputSHA string   `json:"output_sha"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Exit == nil {
			http.Error(w, "exit is required", http.StatusBadRequest)
			return
		}
		status := "succeeded"
		if *req.Exit != 0 {
			status = "failed"
		}
		exit := *req.Exit
		p.guardedAppend(appendEvent, engine.Event{
			Type: "exec", Agent: agent.Name, Status: status,
			Command: req.Command, ExitCode: &exit, OutputSHA: req.OutputSHA,
			Mode: "attested", Binding: bind,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// Stop tears down the inbound listener and closes every upstream session. It
// is synchronous: it waits for every forward call already in flight to finish
// (and so for any appendEvent call it made to return) before it returns —
// the caller can safely close the run's ledger immediately after. The wait is
// tracked by the proxy's own bookkeeping (inflight), not by however the HTTP
// server happens to treat an in-flight connection when closed.
func (p *Gateway) Stop() {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	p.closing = true
	srv := p.srv
	sessions := p.sessions
	sockPath := p.sockPath
	p.srv = nil
	p.sessions = nil
	p.sockPath = ""
	p.mu.Unlock()

	if srv != nil {
		_ = srv.Close() // cut connections now; forward()'s own bookkeeping (not this) is what Stop waits on
	}
	if sockPath != "" {
		_ = os.Remove(sockPath)
	}
	p.inflight.Wait()

	for _, s := range sessions {
		_ = s.Close()
	}
}

// forward returns the ToolHandler mirrored onto the inbound server for one
// upstream tool of resource resourceID. It re-checks the (resource, tool)
// pair against allow at call time (defense in depth, independent of what
// Start already filtered at mirror time), forwards the call to upstream with
// the arguments passed through raw (never touching the run token), and
// appends a tool_call event recording only a result hash + short preview —
// never the call body or any credential.
func (p *Gateway) forward(bind engine.Binding, agent config.AgentDef, resourceID string, allow allowedTools, upstream *mcp.ClientSession, appendEvent func(engine.Event)) mcp.ToolHandler {
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

		// Defense-in-depth: only allowlisted tools are ever mirrored, so the
		// receiving middleware (refusedTraceMiddleware) is the real denial
		// path and this branch is unreachable in normal operation. It stays
		// as a per-tool second gate independent of the mirroring logic.
		if !allow.allows(resourceID, req.Params.Name) {
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
func (p *Gateway) connectUpstream(id string, res config.ToolResource) (*mcp.ClientSession, error) {
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

// capRunes truncates s to at most n runes. It is the one place the ledger
// caps agent- or upstream-controlled text before it enters an event, so
// hashResult's preview, resultErrorText's failure text, and the model door's
// echoed model name all share the same bound.
func capRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
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

	preview = capRunes(strings.Join(strings.Fields(strings.ReplaceAll(string(body), "\n", " ")), " "), 200)
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
// It is a method on *Gateway (not a free function) so its appendEvent call can
// share forward's closing/inflight bookkeeping: without that, an in-flight
// appendEvent here could run after Stop() returns and race the run's
// log.Close(), violating Stop()'s documented invariant.
func (p *Gateway) refusedTraceMiddleware(mirrored map[string]string, bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event)) mcp.Middleware {
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
	return capRunes(text, 200)
}

// modelHandler is the OpenAI-compatible door on the per-run listener. The
// agent authenticates with the run token; the proxy authorizes the logical
// model, injects the per-role provider key, and never forwards the run token
// or any X-Agenthof-* header.
func (p *Gateway) modelHandler(bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Decode into json.RawMessage per field rather than map[string]any: an
		// any-decode + re-marshal round-trips every JSON number through
		// float64, silently losing precision above 2^53 (e.g. a seed). Raw
		// bytes for every field but "model" are preserved untouched; only
		// "model" is parsed and later replaced.
		var req map[string]json.RawMessage
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var logical string
		if raw, ok := req["model"]; ok {
			_ = json.Unmarshal(raw, &logical) // non-string "model" leaves logical "", matching the old .(string) assertion
		}

		effective := agent.Model
		if effective == "" {
			effective = p.gwcfg.Defaults.Model
		}
		if logical == "" || logical != effective {
			// logical is agent-supplied and, on this path, unvalidated — cap it
			// before it enters the ledger (same 200-rune bound as hashResult /
			// resultErrorText) so an oversized "model" value can't bloat the
			// event.
			echoed := capRunes(logical, 200)
			p.guardedAppend(appendEvent, engine.Event{
				Type: "model_call", Agent: agent.Name, Status: "refused",
				Reason: fmt.Sprintf("model %q is not allowed for this agent", echoed),
				Model:  echoed, Binding: bind,
			})
			http.Error(w, "model not allowed", http.StatusForbidden)
			return
		}

		// keyRoot is the working dir gateway provision writes keys under
		// (".", per main), not --config. Reading from --config would miss
		// provisioned keys and fall back to the unbudgeted env key.
		roleKey := gateway.LoadRoleKey(p.keyRoot, bind.Role)
		route, err := gateway.Resolve(p.gwcfg, logical, roleKey)
		if err != nil {
			p.guardedAppend(appendEvent, engine.Event{
				Type: "model_call", Agent: agent.Name, Status: "failed",
				Reason: "model route not resolved", Model: logical, Binding: bind,
			})
			http.Error(w, "model route not resolved", http.StatusBadGateway)
			return
		}

		modelRaw, err := json.Marshal(route.Model)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req["model"] = modelRaw
		newBody, err := json.Marshal(req)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		target, err := url.Parse(route.Endpoint)
		if err != nil || target.Scheme == "" || target.Host == "" {
			http.Error(w, "bad route", http.StatusBadGateway)
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(newBody))
		r.ContentLength = int64(len(newBody))
		r.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
		r.Header.Set("Content-Type", "application/json")
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(newBody)), nil
		}

		const maxResp = 10 << 20

		// recorded tracks whether this request already appended a model_call
		// event from inside ModifyResponse before returning an error from it.
		// ReverseProxy calls ErrorHandler both when RoundTrip itself fails
		// (upstream unreachable — no event yet) AND when ModifyResponse
		// returns a non-nil error (which, on every path below, has already
		// appended its own event) — without this guard ErrorHandler would
		// double-record the latter. record() is the only way ModifyResponse
		// appends, so no future branch can forget to set it. It is local to
		// this handler invocation (a fresh closure per request), and
		// Rewrite/ModifyResponse/ErrorHandler all run synchronously on the
		// request's own goroutine, so no lock is needed.
		var recorded bool
		record := func(e engine.Event) {
			recorded = true
			p.guardedAppend(appendEvent, e)
		}

		rp := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme, pr.Out.URL.Host = target.Scheme, target.Host
				pr.Out.Host = target.Host
				pr.Out.URL.Path = singleJoiningSlash(target.Path, "/v1/chat/completions")
				pr.Out.URL.RawQuery = ""
				pr.Out.Header.Set("Authorization", "Bearer "+route.APIKey)
				for k := range pr.Out.Header {
					if strings.HasPrefix(k, "X-Agenthof-") {
						pr.Out.Header.Del(k)
					}
				}
				pr.Out.Header.Del("Cookie")
				// Deleting (not merely leaving empty) lets http.Transport
				// negotiate its own gzip and transparently decode the
				// response: Transport only auto-adds "Accept-Encoding: gzip"
				// and auto-decompresses when the outbound request carries no
				// Accept-Encoding at all. The agent's own HTTP client sets
				// one; forwarding it verbatim would leave ModifyResponse
				// reading raw compressed bytes, so parseUsage would silently
				// fail and the 10 MiB cap would measure compressed size.
				pr.Out.Header.Del("Accept-Encoding")
			},
			ModifyResponse: func(resp *http.Response) error {
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					// The numeric code + a fixed status text, never the
					// upstream's own reason phrase (resp.Status), which is
					// upstream-controlled text that could carry anything.
					reason := fmt.Sprintf("upstream %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
					if resp.StatusCode == http.StatusTooManyRequests {
						reason = "budget"
					}
					record(engine.Event{
						Type: "model_call", Agent: agent.Name, Status: "refused",
						Reason: reason, Model: logical, Binding: bind,
					})
					return nil
				}
				if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
					record(engine.Event{
						Type: "model_call", Agent: agent.Name, Status: "started",
						Model: logical, Binding: bind,
					})
					return nil
				}
				rb, err := io.ReadAll(io.LimitReader(resp.Body, maxResp+1))
				_ = resp.Body.Close()
				if err != nil {
					record(engine.Event{
						Type: "model_call", Agent: agent.Name, Status: "failed",
						Reason: "upstream read failed", Model: logical, Binding: bind,
					})
					return err
				}
				if len(rb) > maxResp {
					record(engine.Event{
						Type: "model_call", Agent: agent.Name, Status: "failed",
						Reason: "upstream response too large", Model: logical, Binding: bind,
					})
					return fmt.Errorf("upstream response too large")
				}
				resp.Body = io.NopCloser(bytes.NewReader(rb))
				resp.ContentLength = int64(len(rb))
				resp.Header.Set("Content-Length", strconv.Itoa(len(rb)))
				pt, ct := parseUsage(rb)
				record(engine.Event{
					Type: "model_call", Agent: agent.Name, Status: "succeeded",
					Model: logical, PromptTokens: pt, CompletionTokens: ct, Binding: bind,
				})
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
				// ReverseProxy calls ErrorHandler in exactly two cases: (a) a
				// Transport.RoundTrip failure (connection refused, DNS,
				// timeout — ModifyResponse never ran, nothing recorded yet),
				// or (b) a non-nil return from ModifyResponse (already
				// recorded via record() above). It is NOT reached for a
				// mid-stream response-copy failure — that aborts the handler
				// via the recovered http.ErrAbortHandler panic, bypassing
				// ErrorHandler entirely. The reason is kept deliberately
				// generic rather than "upstream unreachable" (which would be
				// wrong for case (b), e.g. an oversized or unreadable body)
				// — it covers both without claiming more than is known. Only
				// append here when nothing has been recorded yet, so case (a)
				// still leaves a ledger line (Article III: no action without
				// an event) without double-recording case (b), which already
				// appended its own. The error itself is never echoed — it
				// can carry the upstream URL or a wrapped secret — a fixed
				// reason is enough.
				if !recorded {
					p.guardedAppend(appendEvent, engine.Event{
						Type: "model_call", Agent: agent.Name, Status: "failed",
						Reason: "model call did not complete", Model: logical, Binding: bind,
					})
				}
				http.Error(w, "upstream error", http.StatusBadGateway)
			},
		}
		rp.ServeHTTP(w, r)
	}
}

func parseUsage(body []byte) (*int, *int) {
	var parsed struct {
		Usage struct {
			PromptTokens     *int `json:"prompt_tokens"`
			CompletionTokens *int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil
	}
	return parsed.Usage.PromptTokens, parsed.Usage.CompletionTokens
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
