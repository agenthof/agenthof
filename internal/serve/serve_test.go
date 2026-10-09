package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/obs"
	"github.com/agenthof/agenthof/internal/registry"
)

const goodToken = "good-token-0123456789"

var testInvoker = identity.Invoker{Subject: "dana@example.com", Issuer: "https://idp.test", Method: "oidc", Groups: []string{"engineering"}}

// fakeAuth accepts exactly goodToken, or fails every call with err.
type fakeAuth struct{ err error }

func (f fakeAuth) Authenticate(_ context.Context, raw string) (identity.Invoker, error) {
	if f.err != nil {
		return identity.Invoker{}, f.err
	}
	if raw != goodToken {
		return identity.Invoker{}, errors.New("oidc verify: signature invalid (claims: evil@attacker)")
	}
	return testInvoker, nil
}

// fakeHost is a RunHost whose Prepare counts calls, can fail, whose Admit
// can refuse, and whose Run is whatever the test supplies (default: an
// immediate success with no ledger — tests that need a ledger use engineRun).
type fakeHost struct {
	prepared    atomic.Int32
	prepErr     error
	admitReason string
	run         func(ctx context.Context, runID string, origin *engine.Origin) (engine.Result, error)
}

func (h *fakeHost) Prepare(_ identity.Invoker, _ string) (Prepared, error) {
	h.prepared.Add(1)
	if h.prepErr != nil {
		return nil, h.prepErr
	}
	return h, nil
}

func (h *fakeHost) Admit(_, _ string, _ identity.Invoker) (string, bool) {
	if h.admitReason != "" {
		return h.admitReason, false
	}
	return "", true
}

func (h *fakeHost) Run(ctx context.Context, runID, _, _, _ string, _ identity.Invoker, origin *engine.Origin) (engine.Result, error) {
	if h.run != nil {
		return h.run(ctx, runID, origin)
	}
	return engine.Result{RunID: runID, Status: "succeeded"}, nil
}

// testRegistry is a one-step workflow for runs that must write a real ledger.
func testRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	cfg := config.Config{
		Agents:    []config.AgentDef{{Name: "planner", Model: "fast", Output: "plan", Endpoint: "https://example.test/run", SourceFile: "a"}},
		Workflows: []config.WorkflowDef{{Name: "fix-bug", SourceFile: "w", Steps: []config.Step{{Name: "plan", Agent: "planner"}}}},
		Roles:     []config.RoleDef{{Name: "se", Workflows: []string{"fix-bug"}, AllowedGroups: []string{"*"}, SourceFile: "r"}},
		Gateway:   config.GatewayConfig{Models: map[string]config.ModelRoute{"fast": {Endpoint: "https://x/v1", Model: "m", APIKeyEnv: "K"}}},
	}
	reg, errs := registry.Build(cfg)
	if reg == nil {
		t.Fatal(errs)
	}
	return reg
}

// gateExec blocks each step on release, then succeeds. Tests use it to
// hold a run in flight.
type gateExec struct{ release chan struct{} }

func (g gateExec) Execute(ctx context.Context, _ engine.Binding, _ config.AgentDef, _ string, _ map[string]string) (engine.StepResult, error) {
	select {
	case <-g.release:
		return engine.StepResult{Success: true, Artifact: "plan-text"}, nil
	case <-ctx.Done():
		return engine.StepResult{}, ctx.Err()
	}
}

// engineRun is a fakeHost.run that executes a real engine.Run under logDir.
func engineRun(t *testing.T, logDir string, exec engine.StepExecutor) func(ctx context.Context, runID string, origin *engine.Origin) (engine.Result, error) {
	reg := testRegistry(t)
	return func(ctx context.Context, runID string, origin *engine.Origin) (engine.Result, error) {
		return engine.Run(ctx, reg, "se", "fix-bug", "x", testInvoker, exec,
			engine.Options{LogDir: logDir, ArtifactDir: filepath.Join(logDir, "arts"), RunID: runID, Origin: origin})
	}
}

// fakeConfigHost records every Apply and Pull call and answers with result
// (Apply) or pull (Pull); when block is non-nil, Apply waits on it first (to
// hold an apply in flight).
type fakeConfigHost struct {
	mu     sync.Mutex
	calls  []fakeApplyCall
	pulls  []identity.Invoker
	result apiclient.ApplyResult
	pull   PullResult
	block  chan struct{}
}

type fakeApplyCall struct {
	inv   identity.Invoker
	files map[string][]byte
	pre   apiclient.Precondition
	via   *engine.Origin
}

func (h *fakeConfigHost) Apply(inv identity.Invoker, files map[string][]byte, pre apiclient.Precondition, via *engine.Origin) apiclient.ApplyResult {
	h.mu.Lock()
	h.calls = append(h.calls, fakeApplyCall{inv: inv, files: files, pre: pre, via: via})
	res := h.result
	h.mu.Unlock()
	if h.block != nil {
		<-h.block
	}
	return res
}

func (h *fakeConfigHost) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.calls)
}

func (h *fakeConfigHost) last() fakeApplyCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls[len(h.calls)-1]
}

func (h *fakeConfigHost) Pull(inv identity.Invoker) PullResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pulls = append(h.pulls, inv)
	return h.pull
}

func (h *fakeConfigHost) pullCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.pulls)
}

func (h *fakeConfigHost) lastPull() identity.Invoker {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pulls[len(h.pulls)-1]
}

type testServer struct {
	srv    *Server
	http   *httptest.Server
	logDir string
	logs   *bytes.Buffer
	host   *fakeHost
	config *fakeConfigHost
}

func newTestServer(t *testing.T, host *fakeHost, auth Authenticator, maxRuns int) *testServer {
	t.Helper()
	logDir := filepath.Join(t.TempDir(), "runs")
	logs := &bytes.Buffer{}
	cfgHost := &fakeConfigHost{}
	srv, err := New(Config{
		Auth: auth, Host: host, Config: cfgHost, LogDir: logDir, ControlLog: filepath.Join(filepath.Dir(logDir), "control.jsonl"),
		MaxConcurrentRuns: maxRuns, ServerHost: "127.0.0.1:0", Logger: obs.New(logs, slog.LevelDebug, obs.FormatText),
	})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return &testServer{srv: srv, http: hs, logDir: logDir, logs: logs, host: host, config: cfgHost}
}

// do sends one request with the bearer (empty = no Authorization header)
// and returns the response and its body.
func (ts *testServer) do(t *testing.T, method, path, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.http.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

func decode[T any](t *testing.T, data []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	return v
}
