// Package rungateway is Agenthof's per-run listener: the doors a fronted,
// credential-starved agent reaches during one step. The tool door is an
// enforced inbound MCP proxy (authenticate the step by its run token,
// authorize against the agent's allowlist, inject a resource credential the
// agent never sees, forward upstream, append a tool_call per call — carrying
// a trusted runtime's attestation when the resource declares one); the exec
// and model doors ride the same listener; and the spawn door starts a
// governed child run through a Spawner. Every door records what it did on
// the run's ledger.
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
	"log/slog"
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
	"github.com/agenthof/agenthof/internal/obs"
)

// connectTimeout bounds an upstream connect/list-tools call at Start time so a
// hung upstream fails the step instead of hanging Start indefinitely.
const connectTimeout = 30 * time.Second

// Gateway implements engine.ToolProxy: for one fronted step it mints a run
// token, connects to each tool resource the agent's grants name as an MCP
// client (with a broker-injected credential the agent never sees), mirrors
// the granted tools — every tool of an all-tools grant, the resource's
// read_only_tools under mode: read-only, only the named tools of a named
// grant — onto an inbound MCP server gated by the run token, and forwards
// calls, appending a tool_call event per call (carrying a trusted runtime's
// attestation when the resource declares one).
type Gateway struct {
	tools   map[string]config.ToolResource
	broker  broker.Broker
	gwcfg   config.GatewayConfig
	keyRoot string
	// subjectToken is the invoker's verified inbound token for this run —
	// the RFC 8693 subject token. Per run, never per step: it is handed to
	// New once, never placed on engine.Binding (forwarded, rides every step
	// header) or Start, and reaches a broker only on the ref of a
	// token_exchange resource. Empty when the invoker was not OIDC-verified.
	subjectToken string

	// logger is the operational logger New was given (never nil — New
	// applies obs.OrDiscard). stepLogger is logger scoped to the current
	// step's run id and agent: Start sets it under mu so Stop, which has no
	// binding of its own, logs with the same identifiers.
	logger     *slog.Logger
	stepLogger *slog.Logger

	mu       sync.Mutex
	srv      *http.Server
	sessions []upstream
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
	// spawner runs a child run for the spawn door; nil means the door
	// refuses (fail-closed). Set once by WithSpawner, before the first Start.
	spawner Spawner
	// spawnInflight and spawnTotal are the spawn door's cap accounting, under
	// mu. They live for the whole run: Start does NOT reset them, because
	// max_total_spawns bounds a run's whole life, not one step.
	spawnInflight int
	spawnTotal    int
	// execURL, when set, is the first-hand exec runtime the exec door dials
	// in place of every agent's exec.url: a spawned child's agents are
	// served by the child's own refexec, so the per-child gateway carries
	// it. Set once by WithExecURL, before the first Start.
	execURL string
}

// New builds a Gateway over the gateway config. Tool resources come from
// gw.Tools. keyRoot is the working directory gateway provision writes role
// keys under (".", the same root as EnsureRoleKey), not the --config directory.
// logger receives operational diagnostics (never ledger events); nil means
// discard. subjectToken is the invoker's verified inbound token, exchanged
// per user for each token_exchange resource; "" when the invoker has none
// (cmdRun refuses an OBO workflow before it gets here in that case).
func New(gw config.GatewayConfig, keyRoot string, b broker.Broker, logger *slog.Logger, subjectToken string) *Gateway {
	l := obs.OrDiscard(logger)
	return &Gateway{tools: gw.Tools, broker: b, gwcfg: gw, keyRoot: keyRoot, logger: l, stepLogger: l, subjectToken: subjectToken}
}

// allowedTools is what Start derives from the agent's tool grants: resource
// id → the tool names the agent may see. A PRESENT key with a nil set is a
// config.ScopeAll grant, mode: all (every tool the resource exposes); an
// ABSENT key is a resource the agent was not granted at all; a present key
// with an EMPTY set grants nothing. A read-only grant resolves to the
// resource's read_only_tools, so it arrives here as an ordinary non-nil set.
// allows is the only reader, so the present-vs-nil distinction cannot be
// confused with "not granted".
type allowedTools map[string]map[string]struct{}

// allows reports whether tool on resourceID is within the agent's grant.
func (a allowedTools) allows(resourceID, tool string) bool {
	names, granted := a[resourceID]
	if !granted {
		return false
	}
	if names == nil {
		return true // all-tools grant: every tool
	}
	_, ok := names[tool]
	return ok
}

// readOnlySet is the resource's read_only_tools as a set. It is the one place
// the operator's classification is turned into a lookup, so the allow-build
// and the hint check cannot disagree about what "classified read-only" means.
func readOnlySet(res config.ToolResource) map[string]struct{} {
	names := make(map[string]struct{}, len(res.ReadOnlyTools))
	for _, name := range res.ReadOnlyTools {
		names[name] = struct{}{}
	}
	return names
}

// Start serves one fronted step. It mints a run token, connects to each
// resource the agent's tool grants name as an upstream MCP client, mirrors
// their tools onto an inbound MCP server gated by that token, and binds an
// ephemeral localhost listener. ctx is the step's context; the spawn door
// derives each child run's context from it, so the step's deadline or
// cancel tears the children down. It returns the URL the agent must call
// and the token it must present — the token travels only in the HTTP
// Authorization header, never on Binding or the ledger.
func (p *Gateway) Start(ctx context.Context, bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event)) (string, string, error) {
	token, err := mintToken()
	if err != nil {
		return "", "", fmt.Errorf("mint run token: %w", err)
	}

	logger := p.logger.With("run", bind.RunID, "agent", agent.Name)

	// Registry validation already rejects an exec block that is not first-hand
	// (runtime: refexec) or lacks a unix:// url or a timeout, but Start is
	// reachable without the registry, so it fails closed on all three rather
	// than dialing nowhere, forever, or running a command the runtime then
	// disowns at attestation.
	if agent.Exec.Declared() && (agent.Exec.Runtime != "refexec" || !strings.HasPrefix(p.execURLFor(agent), config.UnixScheme) || agent.Exec.Timeout <= 0) {
		logger.Error("gateway start refused", "reason", "exec must be first-hand (runtime: refexec) with a unix:// url and a positive timeout")
		return "", "", fmt.Errorf("exec runtime %q must be refexec with a unix:// url and a positive timeout", agent.Exec.Runtime)
	}

	// Build the per-resource allowlist. Registry validation already rejects
	// a grant with neither tools nor a mode, a resource granted twice when
	// either grant limits tools, a mode it does not implement, and mode: all
	// alongside a tools list — but Start is reachable without the registry,
	// so it fails closed on all four rather than letting merge order decide
	// what the agent may see. The no-scope check runs first so a pair of
	// such grants is reported as what it is, not as a duplicate.
	allow := allowedTools{}
	for _, grant := range agent.Tools {
		if grant.Mode == "" && len(grant.Tools) == 0 {
			logger.Error("gateway start refused", "reason", "tool grant names no tools and sets no mode", "resource", grant.Resource)
			return "", "", fmt.Errorf("resource %q grant names no tools and sets no mode; list tools or set mode: all", grant.Resource)
		}
		prev, seen := allow[grant.Resource]
		scope := grant.Scope()
		if seen && (scope != config.ScopeAll || prev != nil) {
			logger.Error("gateway start refused", "reason", "resource granted more than once with a limited grant", "resource", grant.Resource)
			return "", "", fmt.Errorf("resource %q is granted more than once and at least one grant restricts tools", grant.Resource)
		}
		if grant.Mode != "" && grant.Mode != "all" && grant.Mode != "read-only" {
			logger.Error("gateway start refused", "reason", "tool grant mode not implemented", "resource", grant.Resource)
			return "", "", fmt.Errorf("resource %q grant has mode %q", grant.Resource, grant.Mode)
		}
		if grant.Mode == "all" && len(grant.Tools) > 0 {
			logger.Error("gateway start refused", "reason", "mode all with a tools list", "resource", grant.Resource)
			return "", "", fmt.Errorf("resource %q grant sets mode all and a tools list", grant.Resource)
		}
		if scope == config.ScopeAll {
			allow[grant.Resource] = nil // present, nil: every tool
			continue
		}
		res := p.tools[grant.Resource]
		// A read-only grant that also names tools narrows the operator's
		// classification; it can never widen it, so a name outside
		// read_only_tools is refused before the list is trusted.
		if scope == config.ScopeReadOnly && len(grant.Tools) > 0 {
			classified := readOnlySet(res)
			for _, name := range grant.Tools {
				if _, ok := classified[name]; !ok {
					logger.Error("gateway start refused", "reason", "tool is not classified read-only", "resource", grant.Resource, "tool", name)
					return "", "", fmt.Errorf("resource %q tool %q is not classified read-only", grant.Resource, name)
				}
			}
		}
		src := grant.Tools
		if scope == config.ScopeReadOnly && len(grant.Tools) == 0 {
			src = res.ReadOnlyTools
		}
		names := make(map[string]struct{}, len(src))
		for _, name := range src {
			names[name] = struct{}{}
		}
		allow[grant.Resource] = names
	}

	inbound := mcp.NewServer(&mcp.Implementation{Name: "agenthof-tool-proxy", Version: "v0.1.0"}, nil)

	var sessions []upstream
	closeSessions := func() {
		for _, s := range sessions {
			s.close()
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

		up, err := p.connectUpstream(id, res)
		if err != nil {
			logger.Error("upstream connect failed", "resource", id, "class", errClass(err))
			closeSessions()
			return "", "", fmt.Errorf("connect upstream %q: %w", id, err)
		}
		sessions = append(sessions, up)
		sess := up.sess

		listCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
		list, err := sess.ListTools(listCtx, nil)
		cancel()
		if err != nil {
			logger.Error("upstream list tools failed", "resource", id, "class", errClass(err))
			closeSessions()
			return "", "", fmt.Errorf("list tools for %q: %w", id, err)
		}
		classified := readOnlySet(res)
		// Filter FIRST, then collision-check: a tool the grant leaves out
		// never enters mirroredBy, so it cannot manufacture a phantom
		// cross-resource collision — and allowlisting a name away is a way
		// to resolve a real one.
		exposed := map[string]bool{}
		for _, tool := range list.Tools {
			exposed[tool.Name] = true
			if !allow.allows(id, tool.Name) {
				logger.Debug("tool left out by grant", "resource", id, "tool", tool.Name)
				continue
			}
			if owner, dup := mirroredBy[tool.Name]; dup {
				logger.Error("gateway start refused", "reason", "tool exposed by two resources", "tool", tool.Name, "resource", id, "other", owner)
				closeSessions()
				return "", "", fmt.Errorf("tool %q is exposed by both resource %q and %q", tool.Name, owner, id)
			}
			// The upstream's own readOnlyHint is a hint from a party
			// Agenthof does not control, so it never gates the mirror — it
			// can only surface that the operator's classification and the
			// tool disagree. A resource that sends no annotations at all
			// says nothing, so it is not a disagreement.
			if _, ro := classified[tool.Name]; ro && tool.Annotations != nil && !tool.Annotations.ReadOnlyHint {
				logger.Warn("operator-classified read-only tool reports itself mutating", "resource", id, "tool", tool.Name)
			}
			mirroredBy[tool.Name] = id
			logger.Debug("tool mirrored", "resource", id, "tool", tool.Name)
			inbound.AddTool(tool, p.forward(bind, agent, id, allow, sess, appendEvent, logger))
		}
		// What a missing name means depends on where it came from. A name
		// the OPERATOR classified read-only is a standing list, not a claim
		// about this upstream's current tools, so one that is gone is
		// warned and skipped — but a read-only grant that would mirror
		// nothing at all fails, since a fronted agent never reports
		// ListTools to the operator and an empty tool set would be
		// indistinguishable from an off-allowlist attempt. A name the GRANT
		// itself lists (named, or read-only narrowed to specific tools) is
		// an explicit request, so any one of them missing — a typo, or a
		// tool the upstream since removed — fails the step loudly.
		// Declared order makes the reported name deterministic.
		if grant.Scope() == config.ScopeReadOnly && len(grant.Tools) == 0 {
			matched := 0
			for _, name := range res.ReadOnlyTools {
				if exposed[name] {
					matched++
					continue
				}
				logger.Warn("read-only tool absent upstream", "resource", id, "tool", name)
			}
			if matched == 0 {
				logger.Error("read-only grant matched no upstream tool", "resource", id)
				closeSessions()
				return "", "", fmt.Errorf("resource %q read-only grant matches no exposed tool", id)
			}
		} else {
			for _, name := range grant.Tools {
				if !exposed[name] {
					logger.Error("gateway start refused", "reason", "allowlisted tool not exposed by upstream", "resource", id, "tool", name)
					closeSessions()
					return "", "", fmt.Errorf("resource %q does not expose allowlisted tool %q", id, name)
				}
			}
		}
	}

	inbound.AddReceivingMiddleware(p.refusedTraceMiddleware(mirroredBy, bind, agent, appendEvent, logger))

	mux := http.NewServeMux()
	mux.Handle("/", mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return inbound }, nil))
	mux.HandleFunc("/exec/authorize", p.execAssertedHandler(bind, agent, appendEvent))
	mux.HandleFunc("/exec/attest", p.execAssertedHandler(bind, agent, appendEvent))
	mux.HandleFunc("/exec/run", p.execRunHandler(bind, agent, appendEvent, logger))
	mux.HandleFunc("/v1/chat/completions", p.modelHandler(bind, agent, appendEvent, logger))
	mux.HandleFunc("/spawn", p.spawnHandler(ctx, bind, agent, appendEvent, logger))
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
		logger.Error("gateway listen failed", "class", errClass(err))
		closeSessions()
		return "", "", fmt.Errorf("listen: %w", err)
	}

	srv := &http.Server{Handler: handler}

	p.mu.Lock()
	p.srv = srv
	p.sessions = sessions
	p.closing = false
	p.sockPath = ""
	p.stepLogger = logger
	if path, ok := strings.CutPrefix(proxyURL, config.UnixScheme); ok {
		p.sockPath = path
	}
	p.mu.Unlock()

	go func() { _ = srv.Serve(ln) }()
	logger.Info("gateway listener started", "network", ln.Addr().Network())

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
	logger := p.stepLogger
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
		s.close()
	}
	if srv != nil {
		logger.Info("gateway listener stopped")
	}
}

// forward returns the ToolHandler mirrored onto the inbound server for one
// upstream tool of resource resourceID. It re-checks the (resource, tool)
// pair against allow at call time (defense in depth, independent of what
// Start already filtered at mirror time), forwards the call to upstream with
// the arguments passed through raw (never touching the run token), and
// appends a tool_call event recording only a result hash + short preview —
// never the call body or any credential. When the resource declares a
// trusted runtime, the runtime's attestation is taken from the result's
// _meta and recorded with the event; see attestation.go.
func (p *Gateway) forward(bind engine.Binding, agent config.AgentDef, resourceID string, allow allowedTools, upstream *mcp.ClientSession, appendEvent func(engine.Event), logger *slog.Logger) mcp.ToolHandler {
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
			logger.Warn("tool call refused", "resource", resourceID, "tool", req.Params.Name)
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

		logger.Debug("tool call routed", "resource", resourceID, "tool", req.Params.Name)
		result, callErr := upstream.CallTool(ctx, &mcp.CallToolParams{
			Name:      req.Params.Name,
			Arguments: req.Params.Arguments, // raw passthrough — never the run token
		})

		// A trusted runtime's first-hand attestation rides on the result's
		// _meta. It is taken out before anything else sees the result: the
		// agent never gets it and the hash below covers the tool's own answer.
		// A JSON-RPC failure has no result and so no attestation — recorded
		// failed as before. A declared runtime that answered without one has
		// broken its contract, so the call fails with a fixed reason rather
		// than being recorded as a plain success (fail clearly, never
		// recover silently); an undeclared resource's claim is dropped.
		var attestation *engine.RuntimeAttestation
		if callErr == nil {
			att, dropped, attErr := takeRuntimeAttestation(result, p.tools[resourceID].Runtime)
			switch {
			case attErr != nil:
				logger.Error("runtime attestation rejected", "resource", resourceID, "tool", req.Params.Name, "reason", attErr.Error())
				result = &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: attErr.Error()}}}
			case dropped:
				logger.Warn("runtime attestation from an undeclared resource dropped", "resource", resourceID, "tool", req.Params.Name)
			}
			attestation = att
		}

		status := "succeeded"
		var reason string
		if callErr != nil {
			status = "failed"
			reason = capRunes(callErr.Error(), 200)
			// Class only: callErr can wrap a *url.Error carrying the upstream URL.
			logger.Warn("tool call failed", "resource", resourceID, "tool", req.Params.Name, "class", errClass(callErr))
		} else if result != nil && result.IsError {
			status = "failed"
			reason = resultErrorText(result)
			logger.Warn("tool call reported error", "resource", resourceID, "tool", req.Params.Name)
		}
		sha, preview := hashResult(result, callErr)

		appendEvent(engine.Event{
			Type:               "tool_call",
			Agent:              agent.Name,
			AuthMode:           authModeFor(p.tools[resourceID]),
			Status:             status,
			Reason:             reason,
			Tool:               req.Params.Name,
			ArgsSHA:            argsSHA(req.Params.Arguments),
			ResourcesTouched:   []string{resourceID},
			Binding:            bind,
			ArtifactSHA:        sha,
			Artifact:           preview,
			RuntimeAttestation: attestation,
		})

		if callErr != nil {
			return nil, callErr
		}
		return result, nil
	}
}

// upstreamTransport selects the base transport for a tool resource's url. A
// unix://<path> resource — a refbridge-fronted stdio server, reachable over a
// Unix socket only Agenthof can see — is dialed through a transport whose
// DialContext opens that socket, and the Streamable endpoint becomes the
// fixed placeholder http://agenthof/ (the host is ignored; the route is the
// resource's root, as for the adapter's agent socket). Keep-alives stay ON:
// unlike the adapter's per-call client, this transport backs one MCP session
// per step with a long-lived Streamable/SSE stream, so the POST connection is
// pooled and reused across calls instead of re-dialed per request. That pool
// is what the returned closeIdle releases: closing the MCP session cancels
// the SSE GET but returns the last POST/DELETE connection to the pool, and
// nothing else ever drains a per-step Transport — without closeIdle, every
// step would leave one open socket and its two transport goroutines behind
// for the life of the process. IdleConnTimeout bounds the damage if a close
// path is ever missed. Any other url dials the shared http.DefaultTransport
// unchanged, and its closeIdle is a no-op: the shared pool is never drained
// on one step's behalf.
func upstreamTransport(rawURL string) (base http.RoundTripper, endpoint string, closeIdle func()) {
	if path, ok := strings.CutPrefix(rawURL, config.UnixScheme); ok {
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			},
			IdleConnTimeout: 90 * time.Second,
		}
		return tr, "http://agenthof/", tr.CloseIdleConnections
	}
	return http.DefaultTransport, rawURL, func() {}
}

// upstream is one connected tool resource: the MCP session plus the release
// of the transport pool behind it. close is the only way a session is torn
// down, so the pool cannot be forgotten on any path.
type upstream struct {
	sess      *mcp.ClientSession
	closeIdle func()
}

// close ends the MCP session (DELETE, cancel the SSE stream) and then drains
// the transport's idle pool, so the connection the DELETE rode back on is
// closed rather than parked forever.
func (u upstream) close() {
	_ = u.sess.Close()
	u.closeIdle()
}

// connectUpstream connects to res as an MCP client. The resource's credential
// is resolved per outbound request by injectingTransport (the broker caches),
// not once here — a client_credentials token is short-lived and a step may run
// for minutes, so a token captured at connect could expire mid-step. A unix://
// url is dialed through upstreamTransport; the credential injection is the
// same either way. The returned upstream owns the transport pool: on a failed
// connect it is drained here, on success it is drained by upstream.close.
func (p *Gateway) connectUpstream(id string, res config.ToolResource) (upstream, error) {
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
	// The invoker's token travels only on a token_exchange ref, and so does
	// the audience it is exchanged for. Every other grant resolves without
	// either, so no other broker can see them.
	if res.GrantType == "token_exchange" {
		ref.SubjectToken = p.subjectToken
		ref.Audience = res.Audience
	}
	base, endpoint, closeIdle := upstreamTransport(res.URL)
	httpClient := &http.Client{Transport: &injectingTransport{base: base, broker: p.broker, ref: ref}}
	client := mcp.NewClient(&mcp.Implementation{Name: "agenthof-tool-proxy", Version: "v0.1.0"}, nil)

	// The connect context only bounds the initialize/discover handshake, not
	// the resulting session's lifetime — the SDK's own keepalive/reconnect
	// loops run detached from it — so a bounded context here cannot cut a
	// session short later.
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: httpClient,
	}, nil)
	if err != nil {
		closeIdle() // a half-done handshake can still have parked a connection
		return upstream{}, err
	}
	return upstream{sess: sess, closeIdle: closeIdle}, nil
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
// hashResult's preview, resultErrorText's failure text, a tool call's error
// text, and the model door's echoed model name all share the same bound.
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
func (p *Gateway) refusedTraceMiddleware(mirrored map[string]string, bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event), logger *slog.Logger) mcp.Middleware {
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
							logger.Warn("tool call refused", "tool", capRunes(params.Name, 200), "reason", "tool is not available to this run")
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

// authModeFor reports the ledger AuthMode string for a resource: the grant
// used to obtain the upstream credential. A fail-closed switch kept in
// lockstep with the broker's grants: a grant this function does not know is
// recorded as configured, never mislabeled static_env.
func authModeFor(res config.ToolResource) string {
	switch res.GrantType {
	case "":
		return "static_env"
	case "client_credentials":
		return "client_credentials"
	case "token_exchange":
		return "token_exchange"
	default:
		return res.GrantType
	}
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
func (p *Gateway) modelHandler(bind engine.Binding, agent config.AgentDef, appendEvent func(engine.Event), logger *slog.Logger) http.HandlerFunc {
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
			logger.Warn("model call refused", "model", echoed)
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
			// Resolve's error names an env VARIABLE, never a value, but the
			// message stays fixed anyway: one rule for the whole door.
			logger.Error("model route not resolved", "model", logical)
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
					logger.Warn("model upstream returned error status", "model", logical, "status", resp.StatusCode)
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
					logger.Error("model upstream read failed", "model", logical, "class", errClass(err))
					record(engine.Event{
						Type: "model_call", Agent: agent.Name, Status: "failed",
						Reason: "upstream read failed", Model: logical, Binding: bind,
					})
					return err
				}
				if len(rb) > maxResp {
					logger.Error("model upstream response too large", "model", logical)
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
				logger.Debug("model call routed", "model", logical)
				record(engine.Event{
					Type: "model_call", Agent: agent.Name, Status: "succeeded",
					Model: logical, PromptTokens: pt, CompletionTokens: ct, Binding: bind,
				})
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
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
				// The operational log follows the same dedupe: case (b) already
				// logged its own Error from ModifyResponse. It gets a fixed
				// message plus an error class — never err.Error(), for the same
				// reason the ledger reason is fixed.
				if !recorded {
					logger.Error("model call did not complete", "model", logical, "class", errClass(err))
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
