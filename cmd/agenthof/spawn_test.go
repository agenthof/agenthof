package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/agentrt"
	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/refspawn"
	"github.com/agenthof/agenthof/internal/registry"
	"github.com/agenthof/agenthof/internal/rungateway"
)

// shortDir is a 0700 directory with a short path: Unix socket paths have a
// small OS length limit, which t.TempDir would exceed.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// fakeSupervisor speaks refspawn's wire contract on a Unix socket in a
// private directory and "provisions" a child as host processes: one
// listener per requested agent in a fresh child dir, each served by
// handler (the in-test agent), and a listening exec socket in a sibling
// dir served by execHandler. It holds each provision open until the
// gateway closes the body, then removes the child's directories — the
// real lifecycle, without podman.
type fakeSupervisor struct {
	root        string
	sock        string
	handler     http.HandlerFunc
	execHandler http.HandlerFunc
	// nestExecInFirstChild makes every provision after the first put its
	// exec directory INSIDE the first child's socket directory: the
	// misplacement only a nested spawn can catch, since that directory is
	// mounted into the compartments doing the asking but is nothing special
	// to the root.
	nestExecInFirstChild bool

	mu            sync.Mutex
	provisions    [][]string // the agents asked for, per provision
	ids           []string
	released      int
	firstChildDir string
	nestedExecDir string
}

func newFakeSupervisor(t *testing.T, handler, execHandler http.HandlerFunc) *fakeSupervisor {
	t.Helper()
	root := shortDir(t)
	f := &fakeSupervisor{root: root, sock: filepath.Join(root, "refspawn.sock"), handler: handler, execHandler: execHandler}
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(f.serve)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f *fakeSupervisor) url() string { return "unix://" + f.sock }

func (f *fakeSupervisor) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChildRunID string   `json:"child_run_id"`
		Agents     []string `json:"agents"`
	}
	if r.Method != http.MethodPost || r.URL.Path != "/provision" || json.NewDecoder(r.Body).Decode(&req) != nil || req.ChildRunID == "" || len(req.Agents) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	_, _ = io.Copy(io.Discard, r.Body)
	childDir := filepath.Join(f.root, req.ChildRunID)
	execDir := filepath.Join(f.root, req.ChildRunID+"-exec")
	f.mu.Lock()
	f.provisions = append(f.provisions, append([]string{}, req.Agents...))
	f.ids = append(f.ids, req.ChildRunID)
	if f.firstChildDir == "" {
		f.firstChildDir = childDir
	} else if f.nestExecInFirstChild {
		execDir = filepath.Join(f.firstChildDir, req.ChildRunID+"-exec")
		f.nestedExecDir = execDir
	}
	f.mu.Unlock()
	for _, d := range []string{childDir, execDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			http.Error(w, "mkdir", http.StatusBadGateway)
			return
		}
	}
	var servers []*http.Server
	sockets := map[string]string{}
	serveOn := func(path string, h http.Handler) bool {
		ln, err := net.Listen("unix", path)
		if err != nil {
			return false
		}
		srv := &http.Server{Handler: h}
		servers = append(servers, srv)
		go func() { _ = srv.Serve(ln) }()
		return true
	}
	for _, a := range req.Agents {
		sockets[a] = filepath.Join(childDir, a+".sock")
		if !serveOn(sockets[a], f.handler) {
			http.Error(w, "listen", http.StatusBadGateway)
			return
		}
	}
	execSock := filepath.Join(execDir, "refexec.sock")
	if !serveOn(execSock, f.execHandler) {
		http.Error(w, "listen", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	line, _ := json.Marshal(map[string]any{"child_dir": childDir, "agent_sockets": sockets, "exec_socket": execSock})
	_, _ = w.Write(append(line, '\n'))
	w.(http.Flusher).Flush()
	<-r.Context().Done() // the gateway released the lease
	for _, s := range servers {
		_ = s.Close()
	}
	_ = os.RemoveAll(childDir)
	_ = os.RemoveAll(execDir)
	f.mu.Lock()
	f.released++
	f.mu.Unlock()
}

func (f *fakeSupervisor) seen() (provisions [][]string, ids []string, released int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.provisions, f.ids, f.released
}

// nested reports the exec directory the nesting layout handed back, and the
// first child's socket directory it was placed inside.
func (f *fakeSupervisor) nested() (execDir, firstChildDir string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nestedExecDir, f.firstChildDir
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// fakeRefexec answers /run like refexec: exit 0, "hi\n", a matching hash and
// a first-hand attestation naming exactly the argv it was asked.
func fakeRefexec(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Command []string `json:"command"`
	}
	if r.URL.Path != "/run" || json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256([]byte("hi\n"))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"exit_code": 0, "output": "hi\n", "output_sha": hex.EncodeToString(sum[:]), "truncated": false, "output_bytes": 3,
		"runtime_attestation": map[string]any{"runtime": "refexec", "session": "refexec-0a1b2c3d", "command": req.Command,
			"pid": 4242, "spawn": 1, "credential_env": "", "env_names": []string{}, "materialization": ""},
	})
}

// stubProvisioner answers Provision from a script: err, or a lease built
// over a pipe the test controls (closing pw ends the lease).
type stubProvisioner struct {
	lease *refspawn.Lease
	err   error
	mu    sync.Mutex
	calls int
}

func (s *stubProvisioner) Provision(context.Context, string, []string) (*refspawn.Lease, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.lease, s.err
}

func (s *stubProvisioner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// spawnTestConfig is a lead that may spawn worker/child-wf (one agent),
// worker/pair-wf (two agents, one of them first-hand exec), a locked role
// nobody is in, and the spawn caps. Child endpoints are placeholders: under
// spawn the supervisor's sockets win.
func spawnTestConfig() config.Config {
	ep := "https://example.test/run"
	return config.Config{
		Agents: []config.AgentDef{
			{Name: "lead", Endpoint: ep, SourceFile: "a", MaySpawn: []config.SpawnTarget{{Role: "worker", Workflow: "child-wf"}, {Role: "worker", Workflow: "pair-wf"}, {Role: "locked", Workflow: "locked-wf"}}},
			{Name: "child", Endpoint: ep, SourceFile: "a"},
			{Name: "runner", Endpoint: ep, SourceFile: "a", Exec: config.ExecConfig{Runtime: "refexec", URL: "unix:///run/agenthof-exec/ignored.sock", Timeout: 30 * time.Second, Allow: []config.ExecEntry{{Exe: "cat"}}}},
		},
		Workflows: []config.WorkflowDef{
			{Name: "lead-wf", SourceFile: "w", Steps: []config.Step{{Name: "s", Agent: "lead"}}},
			{Name: "child-wf", SourceFile: "w", Steps: []config.Step{{Name: "s", Agent: "child"}}},
			{Name: "pair-wf", SourceFile: "w", Steps: []config.Step{{Name: "one", Agent: "child"}, {Name: "two", Agent: "runner"}, {Name: "three", Agent: "child"}}},
			{Name: "locked-wf", SourceFile: "w", Steps: []config.Step{{Name: "s", Agent: "child"}}},
		},
		Roles: []config.RoleDef{
			{Name: "lead-role", Workflows: []string{"lead-wf"}, AllowedGroups: []string{"*"}, SourceFile: "r"},
			{Name: "worker", Workflows: []string{"child-wf", "pair-wf"}, AllowedGroups: []string{"*"}, SourceFile: "r"},
			{Name: "locked", Workflows: []string{"locked-wf"}, AllowedGroups: []string{"nobody"}, SourceFile: "r"},
		},
		Gateway: config.GatewayConfig{
			Models:          map[string]config.ModelRoute{"fast": {Endpoint: "https://x/v1", Model: "m", APIKeyEnv: "K"}},
			Spawn:           config.SpawnPolicy{MaxDepth: 2, MaxParallel: 2, MaxTotalSpawns: 4},
			SpawnSupervisor: "unix:///run/agenthof-spawn/refspawn.sock",
		},
	}
}

func buildDeps(t *testing.T, cfg config.Config, dir string, sup refspawn.Provisioner) *runDeps {
	t.Helper()
	reg, errs := registry.Build(cfg)
	if reg == nil {
		t.Fatal(errs)
	}
	return newRunDeps(cfg, reg, broker.StaticEnv{}, nil, dir+"/runs", dir+"/arts", "sha256:test", "", sup)
}

// liveDeps is buildDeps over a fake supervisor whose agents answer with
// echoCompatHandler, through the real refspawn client.
func liveDeps(t *testing.T, cfg config.Config, dir string) (*runDeps, *fakeSupervisor) {
	t.Helper()
	fake := newFakeSupervisor(t, echoCompatHandler, fakeRefexec)
	client, err := refspawn.New(fake.url(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return buildDeps(t, cfg, dir, client), fake
}

func parentBinding() engine.Binding {
	return engine.Binding{Invoker: identity.Static("dev@x"), Role: "lead-role", Workflow: "lead-wf", RunID: "r-parent"}
}

func TestRunDepsOneTimeoutKnob(t *testing.T) {
	cfg := spawnTestConfig()
	cfg.Gateway.StepTimeout = 7 * time.Minute
	deps := buildDeps(t, cfg, t.TempDir(), nil)
	if deps.executor().Timeout != 7*time.Minute {
		t.Fatalf("adapter timeout = %v, want the step_timeout knob (7m); otherwise the adapter's own default caps every step", deps.executor().Timeout)
	}
	if deps.options(nil).StepTimeout != 7*time.Minute {
		t.Fatalf("engine step timeout = %v, want 7m", deps.options(nil).StepTimeout)
	}
	parent := engine.Binding{RunID: "r-parent"}
	if deps.options(&parent).StepTimeout != 7*time.Minute || deps.options(&parent).Parent != &parent {
		t.Fatal("a child's options must carry the same knob and the parent linkage")
	}
	unset := buildDeps(t, spawnTestConfig(), t.TempDir(), nil)
	if unset.executor().Timeout != config.DefaultStepTimeout || unset.options(nil).StepTimeout != config.DefaultStepTimeout {
		t.Fatalf("an unset knob must mean %v on both sides, got adapter %v engine %v", config.DefaultStepTimeout, unset.executor().Timeout, unset.options(nil).StepTimeout)
	}
}

func TestPreRunRefusalReproducesTheOBOGate(t *testing.T) {
	cfg := oboTestConfig("obo")
	reg, errs := registry.Build(cfg)
	if reg == nil {
		t.Fatal(errs)
	}
	if reason, refused := preRunRefusal(cfg, reg, "with-planner", identity.Static("dev@x")); !refused || reason != oboRefusalReason {
		t.Fatalf("a --as invoker on an OBO workflow must be refused with the fixed reason, got %q %v", reason, refused)
	}
	oidc := identity.Invoker{Subject: "u-dana", Issuer: "https://idp", Method: "oidc"}
	if _, refused := preRunRefusal(cfg, reg, "with-planner", oidc); refused {
		t.Fatal("a verified invoker passes the gate")
	}
	if _, refused := preRunRefusal(cfg, reg, "coder-only", identity.Static("dev@x")); refused {
		t.Fatal("a workflow without an OBO resource needs no token")
	}
}

func TestChildExecutorRewritesEndpointAndFailsUnmappedAgent(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, "child.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Get("X-Agenthof-Agent")
		mu.Unlock()
		echoCompatHandler(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	exec := childExecutor{sockets: map[string]string{"child": sock}, inner: agentrtExecutor(5 * time.Second)}
	agent := config.AgentDef{Name: "child", Endpoint: "https://never.dialed.example/"}
	res, err := exec.Execute(context.Background(), parentBinding(), agent, "hello", nil)
	if err != nil || !res.Success || res.Artifact != "[child] hello" {
		t.Fatalf("res=%+v err=%v: the step must have been served over the mapped socket", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen != "child" {
		t.Fatalf("the socket saw agent %q", seen)
	}
	// An agent the supervisor gave no socket for cannot be served anywhere:
	// a configuration error the engine must fail outright, never bounce.
	_, err = exec.Execute(context.Background(), parentBinding(), config.AgentDef{Name: "ghost", Endpoint: "https://x/"}, "x", nil)
	if !errors.Is(err, engine.ErrStepConfig) {
		t.Fatalf("err = %v, want ErrStepConfig", err)
	}
}

func TestDistinctStepAgents(t *testing.T) {
	wf := config.WorkflowDef{Steps: []config.Step{{Agent: "b"}, {Agent: "a"}, {Agent: "b"}, {Agent: "c"}}}
	got := distinctStepAgents(wf)
	if !sort.StringsAreSorted(got) || strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("got %v, want a,b,c (distinct, sorted)", got)
	}
}

func TestCheckPlacement(t *testing.T) {
	lease := func(childDir, execSock string) *refspawn.Lease {
		return refspawn.NewLease(childDir, map[string]string{"a": childDir + "/a.sock"}, execSock, io.NopCloser(strings.NewReader("")))
	}
	for _, c := range []struct {
		name, rootDir, childDir, execSock string
		bad                               bool
	}{
		{"sibling exec dir", "/run/agenthof", "/run/sp/r-1", "/run/sp/r-1-exec/refexec.sock", false},
		{"no root socket dir", "", "/run/sp/r-1", "/run/sp/r-1-exec/refexec.sock", false},
		{"exec socket inside the child dir", "", "/run/sp/r-1", "/run/sp/r-1/refexec.sock", true},
		{"exec socket below the child dir", "", "/run/sp/r-1", "/run/sp/r-1/x/refexec.sock", true},
		{"child dir inside refbox_socket_dir", "/run/agenthof", "/run/agenthof/r-1", "/run/sp/r-1-exec/refexec.sock", true},
		{"exec socket inside refbox_socket_dir", "/run/agenthof", "/run/sp/r-1", "/run/agenthof/refexec.sock", true},
	} {
		err := checkPlacement(c.rootDir, lease(c.childDir, c.execSock))
		if (err != nil) != c.bad {
			t.Errorf("%s: err = %v, want bad=%v", c.name, err, c.bad)
		}
	}
}

func TestSpawnWithoutSupervisorIsRefusedUnprovisioned(t *testing.T) {
	deps := buildDeps(t, spawnTestConfig(), t.TempDir(), nil)
	res, err := deps.Spawn(context.Background(), "worker", "child-wf", "x", parentBinding())
	if err != nil || res.Status != "refused" || res.Reason != reasonCompartmentUnavailable || res.ChildRunID != "" || res.Provisioned {
		t.Fatalf("res=%+v err=%v, want the fixed fail-closed refusal, no child, nothing provisioned", res, err)
	}
}

func TestSpawnProvisionFailureIsRefusedUnprovisioned(t *testing.T) {
	stub := &stubProvisioner{err: refspawn.ErrUnavailable}
	deps := buildDeps(t, spawnTestConfig(), t.TempDir(), stub)
	res, err := deps.Spawn(context.Background(), "worker", "child-wf", "x", parentBinding())
	if err != nil || res.Status != "refused" || res.Reason != reasonCompartmentUnavailable || res.ChildRunID != "" || res.Provisioned {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if stub.count() != 1 {
		t.Fatalf("provision calls = %d, want 1", stub.count())
	}
	if entries, _ := os.ReadDir(deps.logDir); len(entries) != 0 {
		t.Fatal("a child that was never provisioned writes no ledger (the parent's spawn event is the record)")
	}
}

func TestSpawnPreRunRefusalProvisionsNothing(t *testing.T) {
	cfg := oboTestConfig("obo")
	cfg.Agents[0].MaySpawn = []config.SpawnTarget{{Role: "se", Workflow: "with-planner"}}
	cfg.Gateway.Spawn = config.SpawnPolicy{MaxDepth: 2, MaxParallel: 2, MaxTotalSpawns: 4}
	cfg.Gateway.SpawnSupervisor = "unix:///run/agenthof-spawn/refspawn.sock"
	stub := &stubProvisioner{err: errors.New("must not be called")}
	dir := t.TempDir()
	deps := buildDeps(t, cfg, dir, stub)
	parent := engine.Binding{Invoker: identity.Static("dev@x"), Role: "se", Workflow: "coder-only", RunID: "r-parent"}
	res, err := deps.Spawn(context.Background(), "se", "with-planner", "x", parent)
	if err != nil || res.Status != "refused" || res.Reason != oboRefusalReason || res.ChildRunID == "" || res.Provisioned {
		t.Fatalf("res=%+v err=%v, want the fixed OBO refusal with a child run id and nothing provisioned", res, err)
	}
	if stub.count() != 0 {
		t.Fatal("the pre-run gate runs BEFORE provisioning: an OBO-refused child provisions nothing")
	}
	events, _, err := engine.ReadLog(dir+"/runs", res.ChildRunID)
	if err != nil || len(events) != 1 || events[0].Type != "run_refused" || events[0].Reason != oboRefusalReason || events[0].Binding.ParentRunID != "r-parent" {
		t.Fatalf("child events = %+v (%v)", events, err)
	}
}

func TestSpawnPlacementViolationIsRefused(t *testing.T) {
	dir := shortDir(t)
	childDir := filepath.Join(dir, "r-x")
	if err := os.Mkdir(childDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	closed := make(chan struct{})
	stub := &stubProvisioner{lease: refspawn.NewLease(childDir, map[string]string{"child": filepath.Join(childDir, "child.sock")},
		filepath.Join(childDir, "refexec.sock"), // INSIDE the mounted dir: an agent could dial it directly
		closeNotifier{ReadCloser: pr, closed: closed})}
	deps := buildDeps(t, spawnTestConfig(), t.TempDir(), stub)
	res, err := deps.Spawn(context.Background(), "worker", "child-wf", "x", parentBinding())
	if err != nil || res.Status != "refused" || res.Reason != reasonCompartmentUnavailable || res.ChildRunID != "" || res.Provisioned {
		t.Fatalf("res=%+v err=%v: a misplaced exec socket must be refused before anything runs", res, err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the lease must be released on refusal")
	}
}

// closeNotifier reports when the lease's body is closed.
type closeNotifier struct {
	io.ReadCloser
	closed chan struct{}
}

func (c closeNotifier) Close() error {
	close(c.closed)
	return c.ReadCloser.Close()
}

func TestSpawnLeaseEndCancelsChild(t *testing.T) {
	dir := shortDir(t)
	childDir, execDir := filepath.Join(dir, "r-x"), filepath.Join(dir, "r-x-exec")
	for _, d := range []string{childDir, execDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The child's one agent: hangs on every step until the step is cancelled.
	stepStarted := make(chan struct{}, 1)
	ln, err := net.Listen("unix", filepath.Join(childDir, "child.sock"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case stepStarted <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	pr, pw := io.Pipe()
	stub := &stubProvisioner{lease: refspawn.NewLease(childDir, map[string]string{"child": filepath.Join(childDir, "child.sock")}, filepath.Join(execDir, "refexec.sock"), pr)}
	cfg := spawnTestConfig()
	cfg.Gateway.StepTimeout = 2 * time.Minute // far longer than this test may take
	deps := buildDeps(t, cfg, t.TempDir(), stub)
	type outcome struct {
		res rungateway.SpawnResult
		err error
	}
	got := make(chan outcome, 1)
	go func() {
		res, err := deps.Spawn(context.Background(), "worker", "child-wf", "x", parentBinding())
		got <- outcome{res, err}
	}()
	select {
	case <-stepStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("the child's step never reached its agent")
	}
	_ = pw.Close() // the supervisor ended the set
	select {
	case o := <-got:
		if o.err != nil || o.res.Status != "failed" || !o.res.Provisioned || o.res.ChildRunID == "" {
			t.Fatalf("res=%+v err=%v, want a failed, provisioned child", o.res, o.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the lease ended but the child kept running: a dead compartment must cancel the child, not wait for step_timeout")
	}
}

func TestSpawnRefusedChildHasOwnLedgerLinkedToParent(t *testing.T) {
	dir := t.TempDir()
	deps, fake := liveDeps(t, spawnTestConfig(), dir)
	res, err := deps.Spawn(context.Background(), "locked", "locked-wf", "x", parentBinding())
	if err != nil || res.Status != "refused" || res.ChildRunID == "" || !res.Provisioned {
		t.Fatalf("res=%+v err=%v, want a refused, provisioned child with its own run id and no error", res, err)
	}
	events, _, err := engine.ReadLog(dir+"/runs", res.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "run_refused" {
		t.Fatalf("child events = %+v", events)
	}
	b := events[0].Binding
	if b.ParentRunID != "r-parent" || b.Depth != 1 || b.Invoker.Subject != "dev@x" || b.Role != "locked" {
		t.Fatalf("child binding = %+v", b)
	}
	if res.Reason == "" {
		t.Fatal("the refusal reason must come back so the parent's spawn event can carry it")
	}
	// The set was provisioned under the child's own run id, and released.
	waitFor(t, "the lease to be released", func() bool { _, _, released := fake.seen(); return released == 1 })
	provisions, ids, _ := fake.seen()
	if len(provisions) != 1 || strings.Join(provisions[0], ",") != "child" || ids[0] != res.ChildRunID {
		t.Fatalf("provisions = %v ids = %v, want one for agent child under %s", provisions, ids, res.ChildRunID)
	}
}

func TestSpawnLedgerFailureIsAnError(t *testing.T) {
	deps, _ := liveDeps(t, spawnTestConfig(), t.TempDir())
	deps.logDir = "/dev/null/not-a-dir" // no ledger can be opened here
	_, err := deps.Spawn(context.Background(), "worker", "child-wf", "x", parentBinding())
	if err == nil {
		t.Fatal("a child whose ledger cannot be opened is an internal failure, not a quiet outcome")
	}
}

func TestSpawnProvisionsDistinctStepAgentsAndReleases(t *testing.T) {
	dir := t.TempDir()
	deps, fake := liveDeps(t, spawnTestConfig(), dir)
	res, err := deps.Spawn(context.Background(), "worker", "pair-wf", "hello", parentBinding())
	if err != nil || res.Status != "succeeded" || !res.Provisioned {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	waitFor(t, "the lease to be released", func() bool { _, _, released := fake.seen(); return released == 1 })
	provisions, _, _ := fake.seen()
	if len(provisions) != 1 || strings.Join(provisions[0], ",") != "child,runner" {
		t.Fatalf("provisions = %v, want the two DISTINCT step agents of pair-wf (child appears twice in the steps)", provisions)
	}
	events, _, err := engine.ReadLog(dir+"/runs", res.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	steps := 0
	for _, e := range events {
		if e.Type == "step_succeeded" {
			steps++
		}
	}
	if steps != 3 {
		t.Fatalf("%d steps succeeded, want all three served over the child's sockets", steps)
	}
}

// writeSpawnSample writes a config whose root agent is a TCP stub and whose
// children are served by a fake supervisor; it returns the config dir and
// that supervisor. refbox_socket_dir is set to a private directory of its
// own, as a deployment that spawns has it: the root run's gateway listens
// there, and it is the directory a root run's children are placed against.
func writeSpawnSample(t *testing.T) (string, *fakeSupervisor) {
	t.Helper()
	stub := httptest.NewServer(http.HandlerFunc(echoCompatHandler))
	t.Cleanup(stub.Close)
	fake := newFakeSupervisor(t, echoCompatHandler, fakeRefexec)
	ep := "endpoint: " + stub.URL + "\n"
	root := t.TempDir()
	files := map[string]string{
		"agents/lead.yaml":        "name: lead\nmodel: fast\ninstruction: lead\noutput: out\n" + ep + "may_spawn:\n  - role: worker\n    workflow: child-wf\n  - role: worker\n    workflow: exec-wf\n  - role: locked\n    workflow: locked-wf\n",
		"agents/child.yaml":       "name: child\nmodel: fast\ninstruction: child\noutput: out\n" + ep + "may_spawn:\n  - role: worker\n    workflow: child-wf\n",
		"agents/runner.yaml":      "name: runner\nmodel: fast\ninstruction: runner\noutput: out\n" + ep + "exec:\n  runtime: refexec\n  url: unix:///run/agenthof-exec/ignored.sock\n  timeout: 30s\n  allow:\n    - exe: cat\n",
		"workflows/lead-wf.yaml":  "name: lead-wf\nsteps:\n  - name: s\n    agent: lead\n",
		"workflows/child-wf.yaml": "name: child-wf\nsteps:\n  - name: s\n    agent: child\n",
		"workflows/exec-wf.yaml":  "name: exec-wf\nsteps:\n  - name: s\n    agent: runner\n",
		"workflows/locked.yaml":   "name: locked-wf\nsteps:\n  - name: s\n    agent: child\n",
		"roles/lead.yaml":         "name: lead-role\nworkflows: [lead-wf]\nallowed_groups: [\"*\"]\n",
		"roles/worker.yaml":       "name: worker\nworkflows: [child-wf, exec-wf]\nallowed_groups: [\"*\"]\n",
		"roles/locked.yaml":       "name: locked\nworkflows: [locked-wf]\nallowed_groups: [nobody]\n",
		"gateway.yaml":            "models:\n  fast:\n    endpoint: https://example.test/v1\n    model: m\n    api_key_env: K\nrefbox_socket_dir: " + shortDir(t) + "\nspawn:\n  max_depth: 2\n  max_parallel: 2\n  max_total_spawns: 4\nspawn_supervisor: " + fake.url() + "\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, fake
}

// rootSocketDir reads refbox_socket_dir back out of a written sample.
func rootSocketDir(t *testing.T, root string) string {
	t.Helper()
	gw, err := os.ReadFile(filepath.Join(root, "gateway.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^refbox_socket_dir: (.*)$`).FindSubmatch(gw)
	if m == nil {
		t.Fatalf("no refbox_socket_dir in:\n%s", gw)
	}
	return string(m[1])
}

func runLead(t *testing.T, root, input string) (string, string, []engine.Event) {
	t.Helper()
	logDir := filepath.Join(root, "runs")
	var out bytes.Buffer
	code := cmdRun([]string{"lead-role", "lead-wf", "--input", input, "--as", "dana@example.com", "--groups", "eng",
		"--config", root, "--log-dir", logDir, "--artifact-dir", filepath.Join(root, "arts")}, &out, io.Discard)
	if code != 0 {
		t.Fatalf("run exited %d:\n%s", code, out.String())
	}
	m := regexp.MustCompile(`run (r-[0-9a-f]+) finished: succeeded`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no run id in:\n%s", out.String())
	}
	events, _, err := engine.ReadLog(logDir, m[1])
	if err != nil {
		t.Fatal(err)
	}
	return m[1], logDir, events
}

func onlySpawn(t *testing.T, events []engine.Event) engine.Event {
	t.Helper()
	var spawns []engine.Event
	for _, e := range events {
		if e.Type == "spawn" {
			spawns = append(spawns, e)
		}
	}
	if len(spawns) != 1 {
		t.Fatalf("spawn events = %d, want 1: %+v", len(spawns), spawns)
	}
	return spawns[0]
}

func TestRunSpawnsGovernedChild(t *testing.T) {
	root, _ := writeSpawnSample(t)
	parentID, logDir, events := runLead(t, root, "spawn:worker/child-wf:hello")
	sp := onlySpawn(t, events)
	if sp.Status != "succeeded" || sp.ChildRunID == "" || sp.ChildRole != "worker" || sp.ChildWorkflow != "child-wf" || sp.Depth != 1 || sp.OutputSHA == "" {
		t.Fatalf("spawn event = %+v", sp)
	}
	child, _, err := engine.ReadLog(logDir, sp.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	if child[0].Type != "workflow_started" || child[len(child)-1].Type != "workflow_finished" || child[len(child)-1].Status != "succeeded" {
		t.Fatalf("child events: %+v", child)
	}
	for _, e := range child {
		if e.Binding.ParentRunID != parentID || e.Binding.Depth != 1 || e.Binding.Invoker.Subject != "dana@example.com" || e.Binding.Role != "worker" {
			t.Fatalf("child %s binding = %+v", e.Type, e.Binding)
		}
	}
	var parentArtifact string
	for _, e := range events {
		if e.Type == "step_succeeded" {
			parentArtifact = e.Artifact
		}
	}
	if !strings.Contains(parentArtifact, "spawn succeeded "+sp.ChildRunID+" [child] hello") {
		t.Fatalf("parent artifact = %q, want the child's preview reported back", parentArtifact)
	}
}

func TestRunNestedSpawnStopsAtMaxDepth(t *testing.T) {
	root, _ := writeSpawnSample(t)
	_, logDir, events := runLead(t, root, "spawn:worker/child-wf:spawn:worker/child-wf:spawn:worker/child-wf:deep")
	sp := onlySpawn(t, events) // depth 1, succeeded
	child, _, err := engine.ReadLog(logDir, sp.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	gsp := onlySpawn(t, child) // depth 2, succeeded — asked through the child's unix:// gateway
	if gsp.Status != "succeeded" || gsp.Depth != 2 {
		t.Fatalf("grandchild spawn = %+v", gsp)
	}
	grandchild, _, err := engine.ReadLog(logDir, gsp.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	ggsp := onlySpawn(t, grandchild) // depth 3 > max_depth 2: refused, no child
	if ggsp.Status != "refused" || ggsp.ChildRunID != "" || ggsp.Depth != 3 || ggsp.Reason != "spawn would exceed max_depth" {
		t.Fatalf("great-grandchild spawn = %+v", ggsp)
	}
	if grandchild[len(grandchild)-1].Status != "succeeded" {
		t.Fatalf("the grandchild reports the refusal and still succeeds: %+v", grandchild[len(grandchild)-1])
	}
}

func TestRunNestedSpawnPlacementChecksTheSpawningChildsSocketDir(t *testing.T) {
	// The directory mounted into a CHILD's compartments is that child's own
	// socket directory, not the root deployment's refbox_socket_dir. So a
	// grandchild whose exec socket lands inside it is reachable from the
	// compartments that asked for it — the governed exec door bypassed — and
	// must be refused, even though the same answer is nowhere near the root's
	// directory, which is all the root run can check.
	root, fake := writeSpawnSample(t)
	fake.nestExecInFirstChild = true
	_, logDir, events := runLead(t, root, "spawn:worker/child-wf:spawn:worker/child-wf:x")
	sp := onlySpawn(t, events)
	if sp.Status != "succeeded" {
		t.Fatalf("the child itself is placed correctly and must run: %+v", sp)
	}
	child, _, err := engine.ReadLog(logDir, sp.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	gsp := onlySpawn(t, child)
	if gsp.Status != "refused" || gsp.Reason != reasonCompartmentUnavailable || gsp.ChildRunID != "" || gsp.Depth != 2 {
		t.Fatalf("grandchild spawn = %+v, want refused with the fixed compartment reason and no child", gsp)
	}
	// And the contrast, on the very paths the supervisor handed back: that
	// answer passes against the root's configured directory — which is what
	// every run in the tree would be measured against if the spawning run's
	// own directory were not threaded through.
	nestedExecDir, childSocketDir := fake.nested()
	if nestedExecDir == "" {
		t.Fatal("the supervisor never handed back a nested exec directory")
	}
	answer := refspawn.NewLease(filepath.Join(filepath.Dir(childSocketDir), "r-grandchild"),
		map[string]string{"child": filepath.Join(childSocketDir, "child.sock")},
		filepath.Join(nestedExecDir, "refexec.sock"), io.NopCloser(strings.NewReader("")))
	if err := checkPlacement(rootSocketDir(t, root), answer); err != nil {
		t.Fatalf("against the root's dir this answer passes (%v); the refusal above can only come from the child's own dir", err)
	}
	if err := checkPlacement(childSocketDir, answer); err == nil {
		t.Fatal("against the spawning child's own socket dir the same answer must fail")
	}
}

func TestRunSpawnRefusals(t *testing.T) {
	root, _ := writeSpawnSample(t)
	// Not on may_spawn: refused, nothing started.
	_, logDir, events := runLead(t, root, "spawn:lead-role/lead-wf:x")
	sp := onlySpawn(t, events)
	if sp.Status != "refused" || sp.ChildRunID != "" || sp.Reason != "spawn target is not on the agent's may_spawn list" {
		t.Fatalf("spawn event = %+v", sp)
	}
	// RBAC denies the child role: the WIRE reason is the fixed classifying
	// string — it must NOT disclose the role's groups — while the child's own
	// run_refused ledger keeps the FULL engine reason, linked to the parent.
	parentID, _, events := runLead(t, root, "spawn:locked/locked-wf:x")
	sp = onlySpawn(t, events)
	if sp.Status != "refused" || sp.ChildRunID == "" || sp.Reason != reasonChildRefusedByPolicy {
		t.Fatalf("spawn event = %+v", sp)
	}
	if strings.Contains(sp.Reason, "allowed groups") {
		t.Fatalf("the wire reason must not disclose the role's groups: %q", sp.Reason)
	}
	child, _, err := engine.ReadLog(logDir, sp.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(child) != 1 || child[0].Type != "run_refused" || child[0].Binding.ParentRunID != parentID {
		t.Fatalf("child events = %+v", child)
	}
	if !strings.Contains(child[0].Reason, "allowed groups") {
		t.Fatalf("the child ledger must keep the full reason: %+v", child[0])
	}
}

func TestRunSpawnedChildExecGoesToTheChildsRuntime(t *testing.T) {
	// The runner agent's configured exec.url names nothing that listens; the
	// child's gateway dials the supervisor's exec socket instead.
	root, _ := writeSpawnSample(t)
	_, logDir, events := runLead(t, root, "spawn:worker/exec-wf:exec-run:cat /work/x")
	sp := onlySpawn(t, events)
	if sp.Status != "succeeded" {
		t.Fatalf("spawn event = %+v", sp)
	}
	child, _, err := engine.ReadLog(logDir, sp.ChildRunID)
	if err != nil {
		t.Fatal(err)
	}
	var execs []engine.Event
	for _, e := range child {
		if e.Type == "exec" {
			execs = append(execs, e)
		}
	}
	if len(execs) != 1 || execs[0].Status != "succeeded" || execs[0].Mode != "runtime" || execs[0].RuntimeAttestation == nil || execs[0].RuntimeAttestation.Runtime != "refexec" {
		t.Fatalf("child exec events = %+v, want one first-hand exec served by the child's runtime", execs)
	}
}

func TestRunSpawnWithDeadSupervisorIsRefusedAndNotCounted(t *testing.T) {
	root, _ := writeSpawnSample(t)
	dead := shortDir(t)
	gw, err := os.ReadFile(filepath.Join(root, "gateway.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^spawn_supervisor: .*$`)
	if err := os.WriteFile(filepath.Join(root, "gateway.yaml"), re.ReplaceAll(gw, []byte("spawn_supervisor: unix://"+filepath.Join(dead, "nobody.sock"))), 0o644); err != nil {
		t.Fatal(err)
	}
	// max_total_spawns is 4: five attempts (spawn-many, the in-test agent's
	// sequential-spawn directive), all refused fail-closed, the fifth still
	// with the compartment reason — not the total cap, which an unprovisioned
	// child must not consume.
	_, _, events := runLead(t, root, "spawn-many:5:worker/child-wf:x")
	var spawns []engine.Event
	for _, e := range events {
		if e.Type == "spawn" {
			spawns = append(spawns, e)
		}
	}
	if len(spawns) != 5 {
		t.Fatalf("spawn events = %d, want 5", len(spawns))
	}
	for _, e := range spawns {
		if e.Status != "refused" || e.Reason != reasonCompartmentUnavailable || e.ChildRunID != "" {
			t.Fatalf("spawn event = %+v, want refused with the fixed compartment reason and no child", e)
		}
	}
}

// agentrtExecutor is the fronted adapter under timeout, as runDeps builds it.
func agentrtExecutor(timeout time.Duration) agentrt.AdapterExecutor {
	return agentrt.AdapterExecutor{Timeout: timeout}
}
