package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// spawnTimeout bounds one child's start + initialize, and separately its
// tools/list. Agenthof's own tools/list budget is 30 seconds per resource
// and a lazy spawn (start, initialize, list) happens inside it, so the two
// bounds together must stay under 30 seconds.
const spawnTimeout = 10 * time.Second

var (
	errSessionEnded  = errors.New("refbridge: session ended")
	errBridgeClosing = errors.New("refbridge: bridge is closing")
)

// runtimeAttestationMetaKey is the _meta key the gateway reads the bridge's
// attestation from (internal/rungateway/attestation.go). Pinned wire
// contract; nothing is imported across the internal/ boundary.
const runtimeAttestationMetaKey = "agenthof.dev/runtime-attestation"

// attestation is what the bridge knows FIRST-HAND about the child that
// answers a call: it built the environment, spawned the process, and relays
// the call. Names, ids and argv only — never the credential's value.
type attestation struct {
	session         string
	command         []string
	pid             int
	spawn           int // 1-based generation of the child within the session
	credentialEnv   string
	envNames        []string
	materialization string
}

// meta is the wire form: exactly the keys internal/rungateway decodes.
func (a attestation) meta() map[string]any {
	return map[string]any{
		"runtime":         "refbridge",
		"session":         a.session,
		"command":         a.command,
		"pid":             a.pid,
		"spawn":           a.spawn,
		"credential_env":  a.credentialEnv,
		"env_names":       a.envNames,
		"materialization": a.materialization,
	}
}

// bridge fronts one stdio MCP server command over Streamable HTTP. Each MCP
// session Agenthof opens gets its own child process — never pooled, never
// shared across sessions — spawned with a clean environment plus the
// credential Agenthof injected on the request, and torn down when the
// session ends.
type bridge struct {
	cfg     bridgeConfig
	logger  *slog.Logger
	environ func() []string // refbridge's OWN environment: the pass-through source

	mu       sync.Mutex
	sessions map[*mcp.ServerSession]*session
	closing  bool           // set by close(); no session is admitted afterwards
	wg       sync.WaitGroup // one Add per admitted session, Done at teardown
	spawns   atomic.Int64   // children started over the bridge's life (tests read it)
}

func newBridge(cfg bridgeConfig, logger *slog.Logger) *bridge {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &bridge{cfg: cfg, logger: logger, environ: os.Environ, sessions: map[*mcp.ServerSession]*session{}}
}

// handler serves the Streamable HTTP MCP endpoint at "/". It is STATEFUL:
// the SDK client only sends the DELETE that ends a session when a session id
// was established, and SessionTimeout is the reaper for a client that never
// sends one (an Agenthof that crashed). The timer pauses only while a POST is
// in flight, not for the standalone SSE stream, so the idle timeout must be
// longer than the longest gap between an agent's tool calls within a step.
func (b *bridge) handler() http.Handler {
	return mcp.NewStreamableHTTPHandler(b.getServer, &mcp.StreamableHTTPOptions{
		SessionTimeout: b.cfg.IdleTimeout,
		Logger:         b.logger,
	})
}

// getServer is called by the SDK on EVERY request (a protocol-version lookup)
// and again when a session is created, so it must be cheap and free of side
// effects: a fresh, empty server whose middleware does the per-session work.
func (b *bridge) getServer(*http.Request) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "refbridge", Version: "v0.1.0"}, nil)
	srv.AddReceivingMiddleware(b.middleware(srv))
	return srv
}

// middleware admits a session under the concurrency cap at initialize and,
// on the first tools/* request — the first moment a credential is in hand —
// spawns the child and mirrors its tools onto srv. A tools/* request with no
// bearer is refused outright: no child is ever spawned without a credential.
func (b *bridge) middleware(srv *mcp.Server) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			ss, _ := req.GetSession().(*mcp.ServerSession)
			switch {
			case method == "initialize":
				if err := b.admit(ss, srv); err != nil {
					return nil, err
				}
			case strings.HasPrefix(method, "tools/"):
				s := b.lookup(ss)
				if s == nil {
					return nil, errors.New("refbridge: session was not admitted")
				}
				bearer, ok := bearerOf(req.GetExtra())
				if !ok {
					return nil, errors.New("refbridge: request carries no credential to materialize")
				}
				if err := s.ensure(bearer); err != nil {
					return nil, err
				}
			}
			return next(ctx, method, req)
		}
	}
}

// bearerOf extracts the injected tool credential. It is the credential to
// MATERIALIZE, not proof of who is calling: who may call is settled by the
// socket's directory permissions (the bridge is not an OAuth resource server).
func bearerOf(extra *mcp.RequestExtra) (string, bool) {
	if extra == nil || extra.Header == nil {
		return "", false
	}
	tok, ok := strings.CutPrefix(extra.Header.Get("Authorization"), "Bearer ")
	return tok, ok && tok != ""
}

// admit registers a session under the cap and arms its teardown: a goroutine
// waits for the session to end — DELETE, the idle reaper, or the
// max-lifetime timer — then tears the child down and releases the slot. A
// closing bridge admits nothing, so no wg.Add can race close()'s wg.Wait.
func (b *bridge) admit(ss *mcp.ServerSession, srv *mcp.Server) error {
	if ss == nil {
		return errors.New("refbridge: initialize without a session")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closing {
		return errBridgeClosing
	}
	if _, dup := b.sessions[ss]; dup {
		return nil
	}
	if len(b.sessions) >= b.cfg.MaxSessions {
		b.logger.Warn("session refused", "reason", "session cap reached", "cap", b.cfg.MaxSessions)
		return fmt.Errorf("refbridge: session cap %d reached", b.cfg.MaxSessions)
	}
	s := &session{b: b, ss: ss, server: srv}
	s.lifetime = time.AfterFunc(b.cfg.MaxLifetime, func() {
		b.logger.Info("session max lifetime reached", "session", ss.ID())
		_ = ss.Close()
	})
	b.sessions[ss] = s
	b.wg.Add(1)
	go func() {
		_ = ss.Wait()
		s.teardown()
	}()
	b.logger.Info("session admitted", "session", ss.ID(), "live", len(b.sessions))
	return nil
}

func (b *bridge) lookup(ss *mcp.ServerSession) *session {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sessions[ss]
}

func (b *bridge) liveSessions() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.sessions)
}

// close ends every session and waits until every child has been torn down.
// It is safe to call more than once.
func (b *bridge) close() {
	b.mu.Lock()
	b.closing = true
	all := make([]*session, 0, len(b.sessions))
	for _, s := range b.sessions {
		all = append(all, s)
	}
	b.mu.Unlock()
	for _, s := range all {
		_ = s.ss.Close()
	}
	b.wg.Wait()
}

// childEnv builds the child's environment: ONLY the allowlisted names, copied
// from refbridge's own environment, plus the credential. The result is never
// nil — exec treats a nil Env as "inherit everything", the one outcome this
// function exists to make impossible.
func (b *bridge) childEnv(bearer string) []string {
	own := map[string]string{}
	for _, kv := range b.environ() {
		if name, value, ok := strings.Cut(kv, "="); ok {
			own[name] = value
		}
	}
	env := make([]string, 0, len(b.cfg.EnvPassthrough)+1)
	for _, name := range b.cfg.EnvPassthrough {
		if value, ok := own[name]; ok {
			env = append(env, name+"="+value)
		}
	}
	return append(env, b.cfg.CredentialEnv+"="+bearer)
}

// session is one MCP session from Agenthof and the child it owns.
type session struct {
	b        *bridge
	ss       *mcp.ServerSession
	server   *mcp.Server
	lifetime *time.Timer

	mu         sync.Mutex
	ended      bool               // teardown ran; nothing may spawn afterwards
	bearer     string             // the credential the current child was spawned with
	child      *mcp.ClientSession // nil until the first tools/* request
	pid        int                // the current child's process id
	generation int                // children spawned in this session so far; the current child's 1-based spawn
	envNames   []string           // the current child's environment, NAMES only, sorted
	mirrored   bool               // the child's tools have been added to server
}

// ensure spawns the child if there is none and mirrors its tools once.
func (s *session) ensure(bearer string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return errSessionEnded
	}
	if s.child != nil {
		return nil
	}
	child, pid, names, err := s.spawn(bearer)
	if err != nil {
		return err
	}
	s.child, s.bearer, s.pid, s.envNames = child, bearer, pid, names
	s.generation++
	if s.mirrored {
		return nil
	}
	if err := s.mirror(child); err != nil {
		s.b.closeChild(child, pid)
		s.child = nil
		return err
	}
	s.mirrored = true
	return nil
}

// mirror lists the child's tools and adds each to the session's server with
// forward as its handler. A tool the server refuses fails this session's
// request; a misbehaving child must fail its own session, never the bridge.
func (s *session) mirror(child *mcp.ClientSession) error {
	ctx, cancel := context.WithTimeout(context.Background(), spawnTimeout)
	defer cancel()
	list, err := child.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("refbridge: list child tools: %w", err)
	}
	for _, tool := range list.Tools {
		if err := addTool(s.server, tool, s.forward); err != nil {
			return err
		}
	}
	s.b.logger.Info("child tools mirrored", "session", s.ss.ID(), "tools", len(list.Tools))
	return nil
}

// addTool registers one mirrored tool. The SDK's AddTool panics on a tool it
// will not serve (a non-object input schema, a malformed x-mcp-header
// annotation, ...) and it runs here on a connection goroutine with no
// recovery above it, so the panic is converted into the returned error: the
// child chose the schema, and only the child's session pays for it. The
// panic text names the tool and its schema shape, never the credential.
func addTool(srv *mcp.Server, tool *mcp.Tool, h mcp.ToolHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("refbridge: child tool %q rejected: %v", tool.Name, r)
		}
	}()
	srv.AddTool(tool, h)
	return nil
}

// spawn starts one child with a clean environment and connects to it over
// stdio. The child's stderr is refbridge's stderr (its diagnostics reach the
// operator's log); its stdout is the MCP stream. The connect context bounds
// only the handshake; the child lives until the session ends or, under
// respawn-on-rotation, until the credential changes. It returns the child's
// pid and the sorted NAMES of the environment it was given: what the bridge
// attests about it.
func (s *session) spawn(bearer string) (child *mcp.ClientSession, pid int, envNames []string, err error) {
	argv := s.b.cfg.Command
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = s.b.childEnv(bearer)
	envNames = namesOf(cmd.Env)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // its own group, so teardown reaps what it started
	client := mcp.NewClient(&mcp.Implementation{Name: "refbridge", Version: "v0.1.0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), spawnTimeout)
	defer cancel()
	child, err = client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("refbridge: spawn %s: %w", argv[0], err)
	}
	s.b.spawns.Add(1)
	s.b.logger.Info("child spawned", "session", s.ss.ID(), "command", argv[0], "pid", cmd.Process.Pid, "credential_env", s.b.cfg.CredentialEnv)
	return child, cmd.Process.Pid, envNames, nil
}

// namesOf lists the variable NAMES of an environment, sorted: what the
// bridge attests it gave the child — never the values.
func namesOf(env []string) []string {
	names := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// forward relays one tools/call to the child, arguments passed through raw.
// It is the call boundary at which respawn-on-rotation acts, and where the
// bridge attaches its first-hand attestation to the result.
func (s *session) forward(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	bearer, ok := bearerOf(req.Extra)
	if !ok {
		return nil, errors.New("refbridge: call carries no credential to materialize")
	}
	child, att, err := s.childFor(bearer)
	if err != nil {
		return nil, err
	}
	var args any
	if len(req.Params.Arguments) > 0 {
		args = req.Params.Arguments
	}
	res, err := child.CallTool(ctx, &mcp.CallToolParams{Name: req.Params.Name, Arguments: args})
	if err != nil {
		return nil, err // a JSON-RPC failure carries no result and so no attestation
	}
	// The bridge's account of this call, error result or not. It overwrites
	// anything the child put under the key: only the bridge's word leaves here.
	if res.Meta == nil {
		res.Meta = mcp.Meta{}
	}
	res.Meta[runtimeAttestationMetaKey] = att.meta()
	return res, nil
}

// childFor returns the child to forward to, with the attestation for it
// taken under the same lock, so a respawn and the account of which child
// answered cannot race. Under respawn-on-rotation a bearer that differs from
// the one the child was spawned with replaces the child first (the child's
// MCP state resets — the documented cost); under env-at-spawn the bearer at
// spawn is the one the child keeps.
func (s *session) childFor(bearer string) (*mcp.ClientSession, attestation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return nil, attestation{}, errSessionEnded
	}
	if s.child == nil {
		return nil, attestation{}, errors.New("refbridge: no child for this session")
	}
	if bearer != s.bearer && s.b.cfg.Materialization == matRespawnOnRotation {
		s.b.logger.Info("credential rotated; respawning child", "session", s.ss.ID())
		old, oldPID := s.child, s.pid
		s.child = nil
		s.b.closeChild(old, oldPID)
		fresh, pid, names, err := s.spawn(bearer)
		if err != nil {
			return nil, attestation{}, err
		}
		s.child, s.bearer, s.pid, s.envNames = fresh, bearer, pid, names
		s.generation++
	}
	att := attestation{
		session:         s.ss.ID(),
		command:         s.b.cfg.Command,
		pid:             s.pid,
		spawn:           s.generation,
		credentialEnv:   s.b.cfg.CredentialEnv,
		envNames:        s.envNames,
		materialization: s.b.cfg.Materialization,
	}
	return s.child, att, nil
}

// closeChild ends a child. Closing the client session first marks it
// closing and lets any in-flight call finish; only once the session is
// idle does the transport close the child's stdin, then wait for exit, then
// SIGTERM and finally kill it. Stdin is never closed under a pending
// response — the child's stdio transport would drop it. Then whatever is
// left of the child's process group (anything it started and did not wait
// for) is killed, best effort: the group is the one spawn created with the
// child as leader, never the bridge's own. A process that moved itself to
// another group is out of reach.
func (b *bridge) closeChild(child *mcp.ClientSession, pid int) {
	_ = child.Close()
	if pid <= 1 || pid == syscall.Getpgrp() {
		return
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		b.logger.Warn("child process group not reaped", "pgid", pid, "error", err)
	}
}

// teardown runs once, when the session has ended: it marks the session
// ended so nothing spawns afterwards, stops the lifetime timer, closes the
// child, and releases the cap slot. Repeated calls are no-ops.
func (s *session) teardown() {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	child, pid := s.child, s.pid
	s.child = nil
	s.mu.Unlock()
	s.lifetime.Stop()
	if child != nil {
		s.b.closeChild(child, pid)
	}
	s.b.mu.Lock()
	delete(s.b.sessions, s.ss)
	live := len(s.b.sessions)
	s.b.mu.Unlock()
	s.b.logger.Info("session ended; child torn down", "session", s.ss.ID(), "live", live)
	s.b.wg.Done()
}
