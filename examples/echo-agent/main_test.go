package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func unixClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
}

func TestServesEchoOverUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ea")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")

	ln, err := listenUnix(sock)
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}
	srv := &http.Server{Handler: newMux("")}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	body, err := json.Marshal(request{Input: "hello", Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := unixClient(sock).Post("http://agenthof/", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Success || out.Artifact != "hello" {
		t.Fatalf("got %+v, want echo of 'hello'", out)
	}
}

// TestPlainStepNeedsNoGateway: a plain step echoes with no gateway probe. The
// retired probe POSTed /exec/authorize, which now answers a recorded 403 on
// every agent; probing /exec/run instead would record a refused exec per
// plain step of an exec-less agent. The model call is the gateway-reach
// evidence; the echo agent makes none.
func TestPlainStepNeedsNoGateway(t *testing.T) {
	asrv := httptestUnix(t, newMux(""))
	body, err := json.Marshal(request{Input: "hi", Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://agenthof/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Agenthof-Proxy-URL", "unix:///tmp/does-not-exist.sock")
	req.Header.Set("X-Agenthof-Run-Token", "tok")
	resp, err := unixClient(asrv.sock).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Success || out.Artifact != "hi" {
		t.Fatalf("got %+v, want the echo with no gateway reached", out)
	}
}

type unixSrv struct{ sock string }

func httptestUnix(t *testing.T, h http.Handler) unixSrv {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "u")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	ln, err := listenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return unixSrv{sock: sock}
}

func TestHandleStepRejectsGET(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://agenthof/", nil)
	rec := httptest.NewRecorder()
	newMux("").ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", rec.Code)
	}
}

func TestHandleStepRejectsBadJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://agenthof/", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()
	newMux("").ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad-JSON status = %d, want 400", rec.Code)
	}
}

// fakeGateway serves the gateway's routes on a Unix socket: /exec/run answers
// a fixed exit and output (or a status) after checking the run token and the
// argv; /spawn answers a child's outcome.
type fakeGateway struct {
	sock      string
	runStatus int
	runExit   int
	runOutput string
	mu        sync.Mutex
	lastArgv  []string
	lastRoute string

	spawnStatus int           // 0 means 200
	spawnDelay  time.Duration // how long each /spawn takes to answer
	lastSpawn   []string      // role, workflow, input of the last /spawn
	spawns      int
}

func newFakeGateway(t *testing.T, g *fakeGateway) *fakeGateway {
	t.Helper()
	// Zero statuses mean "the door's normal answer".
	if g.runStatus == 0 {
		g.runStatus = http.StatusOK
	}
	dir, err := os.MkdirTemp("/tmp", "eg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	g.sock = filepath.Join(dir, "gw.sock")
	ln, err := listenUnix(g.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Command  []string `json:"command"`
			Role     string   `json:"role"`
			Workflow string   `json:"workflow"`
			Input    string   `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		g.mu.Lock()
		g.lastArgv, g.lastRoute = req.Command, r.URL.Path
		g.mu.Unlock()
		switch r.URL.Path {
		case "/exec/run":
			if g.runStatus != http.StatusOK {
				http.Error(w, "refused", g.runStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"exit": g.runExit, "output": g.runOutput, "truncated": false})
		case "/spawn":
			g.mu.Lock()
			g.lastSpawn = []string{req.Role, req.Workflow, req.Input}
			g.spawns++
			g.mu.Unlock()
			time.Sleep(g.spawnDelay)
			w.Header().Set("Content-Type", "application/json")
			if g.spawnStatus != 0 && g.spawnStatus != http.StatusOK {
				w.WriteHeader(g.spawnStatus)
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "refused", "reason": "spawn would exceed max_parallel"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "succeeded", "child_run_id": "r-child",
				"output_sha": "abc", "output_preview": "[" + req.Role + "/" + req.Workflow + "] " + req.Input})
		default:
			http.Error(w, "no", http.StatusNotFound)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return g
}

// step posts one step with the given input to an agent mux over a Unix
// socket and returns the decoded response.
func step(t *testing.T, mux *http.ServeMux, gwSock, input string) response {
	t.Helper()
	asrv := httptestUnix(t, mux)
	body, err := json.Marshal(request{Input: input, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://agenthof/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Agenthof-Proxy-URL", "unix://"+gwSock)
	req.Header.Set("X-Agenthof-Run-Token", "tok123")
	resp, err := unixClient(asrv.sock).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestScriptWritesNoteAndRunsExec(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{runStatus: http.StatusOK, runExit: 0, runOutput: "hello-1\n"})
	ws := t.TempDir()
	out := step(t, newMux(ws), gw.sock, "write:hello-1; exec-run:cat /work/agent-note.txt")
	if !out.Success || out.Artifact != "hello-1\n" {
		t.Fatalf("got %+v, want the command's output as the artifact", out)
	}
	note, err := os.ReadFile(filepath.Join(ws, "agent-note.txt"))
	if err != nil || string(note) != "hello-1\n" {
		t.Fatalf("note = %q err = %v", note, err)
	}
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.lastRoute != "/exec/run" || len(gw.lastArgv) != 2 || gw.lastArgv[0] != "cat" || gw.lastArgv[1] != "/work/agent-note.txt" {
		t.Fatalf("gateway saw %s %v", gw.lastRoute, gw.lastArgv)
	}
}

func TestExecRunNonZeroExitFailsStep(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{runStatus: http.StatusOK, runExit: 1, runOutput: "no\n"})
	out := step(t, newMux(t.TempDir()), gw.sock, "exec-run:false")
	if out.Success || !strings.Contains(out.Reason, "exec-run: false exited 1") {
		t.Fatalf("got %+v, want a failed step naming the exit", out)
	}
}

func TestExecRunRefusalFailsStepWithStatus(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{runStatus: http.StatusForbidden})
	out := step(t, newMux(t.TempDir()), gw.sock, "exec-run:rm -rf /")
	if out.Success || !strings.Contains(out.Reason, "exec-run: gateway returned 403") {
		t.Fatalf("got %+v", out)
	}
}

func TestExecRunEmptyCommandFailsStep(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{runStatus: http.StatusOK})
	out := step(t, newMux(t.TempDir()), gw.sock, "exec-run:  ")
	if out.Success || !strings.Contains(out.Reason, "exec-run: no command") {
		t.Fatalf("got %+v", out)
	}
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.lastRoute != "" {
		t.Fatalf("an empty command must not reach the gateway; it saw %s", gw.lastRoute)
	}
}

func TestUnknownDirectiveFailsStep(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{runStatus: http.StatusOK})
	out := step(t, newMux(t.TempDir()), gw.sock, "exec-run:true; explode:now")
	if out.Success || !strings.Contains(out.Reason, `unknown directive "explode:now"`) {
		t.Fatalf("got %+v", out)
	}
}

func TestSpawnDirectiveReportsChildOutcome(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{})
	out := step(t, newMux(t.TempDir()), gw.sock, "spawn:worker/child-wf:hello: with colons")
	if !out.Success || out.Artifact != "spawn succeeded r-child [worker/child-wf] hello: with colons" {
		t.Fatalf("got %+v", out)
	}
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.lastRoute != "/spawn" || len(gw.lastSpawn) != 3 || gw.lastSpawn[0] != "worker" || gw.lastSpawn[1] != "child-wf" || gw.lastSpawn[2] != "hello: with colons" {
		t.Fatalf("gateway saw %s %v", gw.lastRoute, gw.lastSpawn)
	}
}

func TestSpawnRefusalIsAnAnswerNotAFailedStep(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{spawnStatus: http.StatusForbidden})
	out := step(t, newMux(t.TempDir()), gw.sock, "spawn:worker/child-wf:x")
	if !out.Success || out.Artifact != "spawn refused - spawn would exceed max_parallel" {
		t.Fatalf("got %+v, want the refusal reported in the artifact", out)
	}
}

func TestSpawnDirectiveRejectsBadSpec(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{})
	for _, input := range []string{"spawn:worker:x", "spawn:/child-wf:x", "spawn:worker/child-wf"} {
		out := step(t, newMux(t.TempDir()), gw.sock, input)
		if out.Success || !strings.Contains(out.Reason, "spawn: want <role>/<workflow>:<input>") {
			t.Fatalf("%q: got %+v", input, out)
		}
	}
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.spawns != 0 {
		t.Fatal("a bad spec must not reach the gateway")
	}
}

func TestSpawnParallelRunsConcurrently(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{spawnDelay: 300 * time.Millisecond})
	start := time.Now()
	out := step(t, newMux(t.TempDir()), gw.sock, "spawn-parallel:3:worker/child-wf:x")
	elapsed := time.Since(start)
	if !out.Success {
		t.Fatalf("got %+v", out)
	}
	lines := strings.Split(out.Artifact, "\n")
	if len(lines) != 3 {
		t.Fatalf("artifact = %q, want three lines", out.Artifact)
	}
	for _, l := range lines {
		if l != "spawn succeeded r-child [worker/child-wf] x" {
			t.Fatalf("line %q", l)
		}
	}
	if elapsed > 800*time.Millisecond {
		t.Fatalf("three 300ms spawns took %v: they ran one after another, not in parallel", elapsed)
	}
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if gw.spawns != 3 {
		t.Fatalf("gateway saw %d spawns, want 3", gw.spawns)
	}
}

func TestSpawnParallelRejectsBadCount(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{})
	for _, input := range []string{"spawn-parallel:0:worker/child-wf:x", "spawn-parallel:33:worker/child-wf:x", "spawn-parallel:two:worker/child-wf:x"} {
		out := step(t, newMux(t.TempDir()), gw.sock, input)
		if out.Success || !strings.Contains(out.Reason, "spawn-parallel: want <n>:<role>/<workflow>:<input>") {
			t.Fatalf("%q: got %+v", input, out)
		}
	}
}

func TestSleepDirective(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{})
	out := step(t, newMux(t.TempDir()), gw.sock, "sleep:0")
	if !out.Success || out.Artifact != "slept 0s" {
		t.Fatalf("got %+v", out)
	}
	out = step(t, newMux(t.TempDir()), gw.sock, "sleep:-1")
	if out.Success || !strings.Contains(out.Reason, "sleep: want a whole number of seconds") {
		t.Fatalf("got %+v", out)
	}
	// A cancelled request ends the sleep early with the context's error.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := runScript(ctx, stepEnv{proxyURL: "unix://" + gw.sock, token: "tok123", workspace: t.TempDir()}, "sleep:30")
	if err == nil || !strings.Contains(err.Error(), "sleep: context deadline exceeded") {
		t.Fatalf("err = %v, want the context's error", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the sleep outlived its context")
	}
}

func TestFileDirectives(t *testing.T) {
	ws := t.TempDir()
	ctx := context.Background()
	env := stepEnv{workspace: ws, agent: "writer", runID: "r-0a0b0c0d"}
	if got, err := runScript(ctx, env, "read:"); err != nil || got != "absent" {
		t.Fatalf("read on an empty workspace = %q, %v; want absent", got, err)
	}
	if got, err := runScript(ctx, env, "write:hello; read:"); err != nil || got != "hello" {
		t.Fatalf("write then read = %q, %v; want hello", got, err)
	}
	if got, err := runScript(ctx, env, "touch-run:; ls:"); err != nil || got != "agent-note.txt,r-0a0b0c0d.txt" {
		t.Fatalf("touch-run then ls = %q, %v", got, err)
	}
	if got, err := runScript(ctx, stepEnv{workspace: t.TempDir()}, "ls:"); err != nil || got != "empty" {
		t.Fatalf("ls on an empty workspace = %q, %v; want empty", got, err)
	}
	if _, err := runScript(ctx, stepEnv{workspace: ws}, "touch-run:"); err == nil {
		t.Fatal("touch-run without a run id must fail, not write an unnamed file")
	}
	for _, bad := range []string{"../escape", "a/b", "..", "."} {
		if _, err := runScript(ctx, stepEnv{workspace: ws, runID: bad}, "touch-run:"); err == nil {
			t.Errorf("touch-run with run id %q must fail, not write outside the workspace", bad)
		}
	}
}

func TestOnlyDirectiveRunsForTheNamedAgent(t *testing.T) {
	ws := t.TempDir()
	ctx := context.Background()
	writer, reader := stepEnv{workspace: ws, agent: "writer"}, stepEnv{workspace: ws, agent: "reader"}
	script := "only:writer:write:shared; only:reader:read:"
	if got, err := runScript(ctx, writer, script); err != nil || got != "skipped" {
		t.Fatalf("writer's artifact = %q, %v; want skipped (its last directive is the reader's)", got, err)
	}
	if got, err := runScript(ctx, reader, script); err != nil || got != "shared" {
		t.Fatalf("reader's artifact = %q, %v; want the writer's note", got, err)
	}
	for _, bad := range []string{"only:writer", "only::read:", "only:writer:"} {
		if _, err := runScript(ctx, writer, bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestSpawnTranslatesTheChildSeparator(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "ea")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "gw.sock")
	ln, err := listenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen map[string]string
	gw := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		seen = body
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "succeeded", "child_run_id": "r-1", "output_preview": "ok"})
	})}
	go func() { _ = gw.Serve(ln) }()
	t.Cleanup(func() { _ = gw.Close() })
	line, err := spawnOne(context.Background(), "unix://"+sock, "tok", "worker/pair-wf:only:writer:write:x | only:reader:read:")
	if err != nil || line != "spawn succeeded r-1 ok" {
		t.Fatalf("line = %q, %v", line, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["role"] != "worker" || seen["workflow"] != "pair-wf" || seen["input"] != "only:writer:write:x ; only:reader:read:" {
		t.Fatalf("the door saw %v: the child's | separator must arrive as ;", seen)
	}
}
