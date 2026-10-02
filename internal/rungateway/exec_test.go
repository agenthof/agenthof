package rungateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

// refexecStub serves refexec's wire contract on a Unix socket in a private
// (0700) directory, as the real runtime would; respond builds the answer.
type refexecStub struct {
	url   string
	dir   string
	calls atomic.Int32
}

func newRefexecStub(t *testing.T, respond http.HandlerFunc) *refexecStub {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rxs") // short: Unix socket path length limit; MkdirTemp makes it 0700
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "exec.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	s := &refexecStub{url: config.UnixScheme + sock, dir: dir}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		respond(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

// goodExecResponse is exactly what refexec returns for argv.
func goodExecResponse(argv []string, exit int, output string) map[string]any {
	sum := sha256.Sum256([]byte(output))
	return map[string]any{
		"exit_code": exit, "output": output, "output_sha": hex.EncodeToString(sum[:]),
		"truncated": false, "output_bytes": len(output),
		"runtime_attestation": map[string]any{
			"runtime": "refexec", "session": "refexec-0a1b2c3d", "command": argv,
			"pid": 4242, "spawn": 1, "credential_env": "", "env_names": []string{"PATH"}, "materialization": "",
		},
	}
}

func respondJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// echoRefexec answers like a runtime that ran argv: exit 0 and "hi\n", or
// exit 1 and "no\n" for `false`.
func echoRefexec(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Command []string `json:"command"`
	}
	if r.URL.Path != "/run" || r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Command[0] == "false" {
		respondJSON(w, goodExecResponse(req.Command, 1, "no\n"))
		return
	}
	respondJSON(w, goodExecResponse(req.Command, 0, "hi\n"))
}

type eventRecorder struct {
	mu sync.Mutex
	ev []engine.Event
}

func (r *eventRecorder) record(e engine.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ev = append(r.ev, e)
}

func (r *eventRecorder) execs() []engine.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []engine.Event
	for _, e := range r.ev {
		if e.Type == "exec" {
			out = append(out, e)
		}
	}
	return out
}

func firstHandAgent(url string, timeout time.Duration, allow ...config.ExecEntry) config.AgentDef {
	return config.AgentDef{Name: "builder", Execution: "fronted", Endpoint: "https://x/run",
		Exec: config.ExecConfig{Runtime: "refexec", URL: url, Timeout: timeout, Allow: allow}}
}

func startAgentProxy(t *testing.T, agent config.AgentDef, rec *eventRecorder) (base, token string, p *Gateway) {
	t.Helper()
	p = New(config.GatewayConfig{}, "", broker.StaticEnv{}, nil, "")
	base, token, err := p.Start(context.Background(), testBinding(), agent, rec.record)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Stop)
	return base, token, p
}

func onlyExec(t *testing.T, rec *eventRecorder) engine.Event {
	t.Helper()
	ev := rec.execs()
	if len(ev) != 1 {
		t.Fatalf("recorded %d exec events, want 1: %+v", len(ev), ev)
	}
	return ev[0]
}

func TestExecRunRecordsFirstHandExec(t *testing.T) {
	stub := newRefexecStub(t, echoRefexec)
	rec := &eventRecorder{}
	base, token, _ := startAgentProxy(t, firstHandAgent(stub.url, 5*time.Second, config.ExecEntry{Exe: "cat"}), rec)

	code, body := execPost(t, base, "exec/run", token, `{"command":["cat","/work/agent-note.txt"]}`)
	if code != 200 || !strings.Contains(body, `"exit":0`) || !strings.Contains(body, `"output":"hi\n"`) || !strings.Contains(body, `"truncated":false`) {
		t.Fatalf("code=%d body=%s", code, body)
	}
	if strings.Contains(body, "runtime_attestation") {
		t.Fatal("the agent must never see the attestation")
	}
	e := onlyExec(t, rec)
	sum := sha256.Sum256([]byte("hi\n"))
	if e.Status != "succeeded" || e.Mode != "runtime" || e.ExitCode == nil || *e.ExitCode != 0 || e.OutputSHA != hex.EncodeToString(sum[:]) ||
		len(e.Command) != 2 || e.Command[1] != "/work/agent-note.txt" || e.RuntimeAttestation == nil || e.RuntimeAttestation.Runtime != "refexec" || e.RuntimeAttestation.PID != 4242 {
		t.Fatalf("event = %+v", e)
	}
	b, _ := json.Marshal(e)
	if !strings.Contains(string(b), `"mode":"runtime"`) || !strings.Contains(string(b), `"runtime_attestation":{"runtime":"refexec","session":"refexec-0a1b2c3d","command":["cat","/work/agent-note.txt"],"pid":4242,"spawn":1,"credential_env":"","env_names":["PATH"],"materialization":""}`) {
		t.Fatalf("ledger JSON shape:\n%s", b)
	}
	if strings.Contains(string(b), "hi\\n") {
		t.Fatalf("the output body must never enter the ledger:\n%s", b)
	}
}

func TestExecRunNonZeroExitIsFailedWithAttestation(t *testing.T) {
	stub := newRefexecStub(t, echoRefexec)
	rec := &eventRecorder{}
	base, token, _ := startAgentProxy(t, firstHandAgent(stub.url, 5*time.Second, config.ExecEntry{Exe: "false"}), rec)
	code, body := execPost(t, base, "exec/run", token, `{"command":["false"]}`)
	if code != 200 || !strings.Contains(body, `"exit":1`) {
		t.Fatalf("code=%d body=%s", code, body)
	}
	e := onlyExec(t, rec)
	if e.Status != "failed" || e.Reason != "" || e.ExitCode == nil || *e.ExitCode != 1 || e.RuntimeAttestation == nil {
		t.Fatalf("event = %+v", e)
	}
}

func TestExecRunOffAllowlistIsRefusedNotDialed(t *testing.T) {
	stub := newRefexecStub(t, echoRefexec)
	rec := &eventRecorder{}
	base, token, _ := startAgentProxy(t, firstHandAgent(stub.url, 5*time.Second, config.ExecEntry{Exe: "cat"}), rec)
	code, _ := execPost(t, base, "exec/run", token, `{"command":["rm","-rf","/"]}`)
	if code != 403 {
		t.Fatalf("code=%d, want 403", code)
	}
	e := onlyExec(t, rec)
	if e.Status != "refused" || e.Reason != reasonExecNotAllowlisted || e.Mode != "runtime" || e.Command[0] != "rm" || e.RuntimeAttestation != nil {
		t.Fatalf("event = %+v", e)
	}
	if stub.calls.Load() != 0 {
		t.Fatal("refexec must not be asked to run an off-allowlist command")
	}
}

func TestExecRunUnrecordableCommandIsRefusedNotDialed(t *testing.T) {
	stub := newRefexecStub(t, echoRefexec)
	rec := &eventRecorder{}
	base, token, _ := startAgentProxy(t, firstHandAgent(stub.url, 5*time.Second, config.ExecEntry{Exe: "cat"}), rec)
	// Allowlisted (cat), but an argument past the ledger's 200-rune bound: the
	// command must be refused BEFORE it runs, so the ledger never carries a
	// false failure of a completed action.
	code, _ := execPost(t, base, "exec/run", token, `{"command":["cat","`+strings.Repeat("x", 201)+`"]}`)
	if code != 403 {
		t.Fatalf("code=%d, want 403", code)
	}
	e := onlyExec(t, rec)
	if e.Status != "refused" || e.Reason != reasonExecCommandUnrecordable || e.RuntimeAttestation != nil {
		t.Fatalf("event = %+v", e)
	}
	if stub.calls.Load() != 0 {
		t.Fatal("refexec must not be asked to run a command the ledger cannot carry")
	}
}

func TestExecRunRefusedWhenNotDeclared(t *testing.T) {
	rec := &eventRecorder{}
	noExec := config.AgentDef{Name: "builder", Execution: "fronted", Endpoint: "https://x/run"}
	base, token, _ := startAgentProxy(t, noExec, rec)
	code, _ := execPost(t, base, "exec/run", token, `{"command":["cat","x"]}`)
	if code != 403 {
		t.Fatalf("code=%d, want 403", code)
	}
	if e := onlyExec(t, rec); e.Status != "refused" || e.Reason != reasonExecRunNotDeclared {
		t.Fatalf("event = %+v", e)
	}
}

// TestAssertedRoutesRefusedWithoutExec: exec is first-hand only, so the
// retired agent-asserted routes answer a RECORDED 403 on every agent, one
// that declares no exec included — never a fall-through to the MCP handler
// at / with no ledger line.
func TestAssertedRoutesRefusedWithoutExec(t *testing.T) {
	rec := &eventRecorder{}
	noExec := config.AgentDef{Name: "builder", Execution: "fronted", Endpoint: "https://x/run"}
	base, token, _ := startAgentProxy(t, noExec, rec)
	if code, body := execPost(t, base, "exec/authorize", token, `{"command":["true"]}`); code != 403 || !strings.Contains(body, reasonExecFirstHandOnly) {
		t.Fatalf("authorize code=%d body=%q, want 403 with the fixed reason", code, body)
	}
	if code, _ := execPost(t, base, "exec/attest", token, `{"command":["true"],"exit":0,"output_sha":"aa"}`); code != 403 {
		t.Fatalf("attest code=%d, want 403", code)
	}
	ev := rec.execs()
	if len(ev) != 2 {
		t.Fatalf("want two refused events, got %+v", ev)
	}
	for _, e := range ev {
		if e.Status != "refused" || e.Reason != reasonExecFirstHandOnly || e.Mode != "runtime" || e.ExitCode != nil || len(e.Command) != 1 || e.Command[0] != "true" {
			t.Fatalf("event = %+v", e)
		}
	}
}

func TestAssertedRoutesRefusedOnFirstHandAgent(t *testing.T) {
	stub := newRefexecStub(t, echoRefexec)
	rec := &eventRecorder{}
	base, token, _ := startAgentProxy(t, firstHandAgent(stub.url, 5*time.Second, config.ExecEntry{Exe: "cat"}), rec)
	if code, _ := execPost(t, base, "exec/authorize", token, `{"command":["cat","x"]}`); code != 403 {
		t.Fatalf("authorize code=%d, want 403", code)
	}
	if code, _ := execPost(t, base, "exec/attest", token, `{"command":["cat","x"],"exit":0,"output_sha":"aa"}`); code != 403 {
		t.Fatalf("attest code=%d, want 403", code)
	}
	ev := rec.execs()
	if len(ev) != 2 {
		t.Fatalf("want two refused events, got %+v", ev)
	}
	for _, e := range ev {
		if e.Status != "refused" || e.Reason != reasonExecFirstHandOnly || e.Mode != "runtime" || e.ExitCode != nil {
			t.Fatalf("event = %+v", e)
		}
	}
}

func TestExecRunRequiresPrivateSocketDir(t *testing.T) {
	stub := newRefexecStub(t, echoRefexec)
	if err := os.Chmod(stub.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &eventRecorder{}
	base, token, _ := startAgentProxy(t, firstHandAgent(stub.url, 5*time.Second, config.ExecEntry{Exe: "cat"}), rec)
	code, _ := execPost(t, base, "exec/run", token, `{"command":["cat","x"]}`)
	if code != 502 {
		t.Fatalf("code=%d, want 502", code)
	}
	if e := onlyExec(t, rec); e.Status != "failed" || e.Reason != reasonExecSocketDir {
		t.Fatalf("event = %+v", e)
	}
	if stub.calls.Load() != 0 {
		t.Fatal("a socket in a non-private directory must not be dialed")
	}
}

func TestExecRunRuntimeUnreachable(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "rxu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	rec := &eventRecorder{}
	base, token, _ := startAgentProxy(t, firstHandAgent(config.UnixScheme+filepath.Join(dir, "absent.sock"), 5*time.Second, config.ExecEntry{Exe: "cat"}), rec)
	code, _ := execPost(t, base, "exec/run", token, `{"command":["cat","x"]}`)
	if code != 502 {
		t.Fatalf("code=%d, want 502", code)
	}
	if e := onlyExec(t, rec); e.Status != "failed" || e.Reason != reasonExecUnreachable {
		t.Fatalf("event = %+v", e)
	}
}

func TestExecRunFailureModes(t *testing.T) {
	argv := []string{"cat", "x"}
	cases := map[string]struct {
		respond http.HandlerFunc
		reason  string
	}{
		"error status":   {func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) }, reasonExecErrorStatus},
		"malformed body": {func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) }, reasonExecResponseMalformed},
		"no exit code": {func(w http.ResponseWriter, _ *http.Request) {
			m := goodExecResponse(argv, 0, "hi\n")
			delete(m, "exit_code")
			respondJSON(w, m)
		}, reasonExecResponseMalformed},
		"oversized": {func(w http.ResponseWriter, _ *http.Request) {
			m := goodExecResponse(argv, 0, strings.Repeat("x", maxExecRunResponse+1))
			respondJSON(w, m)
		}, reasonExecResponseTooLarge},
		"attestation missing": {func(w http.ResponseWriter, _ *http.Request) {
			m := goodExecResponse(argv, 0, "hi\n")
			delete(m, "runtime_attestation")
			respondJSON(w, m)
		}, "runtime attestation missing"},
		"attestation from another runtime": {func(w http.ResponseWriter, _ *http.Request) {
			m := goodExecResponse(argv, 0, "hi\n")
			m["runtime_attestation"].(map[string]any)["runtime"] = "refbridge"
			respondJSON(w, m)
		}, "runtime attestation malformed"},
		"command mismatch": {func(w http.ResponseWriter, _ *http.Request) {
			respondJSON(w, goodExecResponse([]string{"cat", "y"}, 0, "hi\n"))
		}, reasonExecCommandMismatch},
		"output hash mismatch": {func(w http.ResponseWriter, _ *http.Request) {
			m := goodExecResponse(argv, 0, "hi\n")
			m["output"] = "tampered\n"
			respondJSON(w, m)
		}, reasonExecOutputHash},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			stub := newRefexecStub(t, tc.respond)
			rec := &eventRecorder{}
			base, token, _ := startAgentProxy(t, firstHandAgent(stub.url, 5*time.Second, config.ExecEntry{Exe: "cat"}), rec)
			code, _ := execPost(t, base, "exec/run", token, `{"command":["cat","x"]}`)
			if code != 502 {
				t.Fatalf("code=%d, want 502", code)
			}
			e := onlyExec(t, rec)
			if e.Status != "failed" || e.Reason != tc.reason || e.Mode != "runtime" || e.RuntimeAttestation != nil || e.ExitCode != nil {
				t.Fatalf("event = %+v, want failed with reason %q and no attestation", e, tc.reason)
			}
		})
	}
}

func TestExecRunTimesOutAndRecords(t *testing.T) {
	stub := newRefexecStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // drained, so a closed connection cancels r.Context()
		select {
		case <-r.Context().Done(): // the gateway hung up at its deadline
		case <-time.After(5 * time.Second):
		}
	})
	rec := &eventRecorder{}
	base, token, _ := startAgentProxy(t, firstHandAgent(stub.url, 200*time.Millisecond, config.ExecEntry{Exe: "sleep"}), rec)
	start := time.Now()
	code, _ := execPost(t, base, "exec/run", token, `{"command":["sleep","30"]}`)
	if code != 502 || time.Since(start) > 3*time.Second {
		t.Fatalf("code=%d after %v, want 502 at the 200ms deadline", code, time.Since(start))
	}
	if e := onlyExec(t, rec); e.Status != "failed" || e.Reason != reasonExecTimedOut {
		t.Fatalf("event = %+v", e)
	}
}

func TestExecRunStopWaitsAndRecordsCancelledCall(t *testing.T) {
	stub := newRefexecStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // drained, so a closed connection cancels r.Context()
		<-r.Context().Done()               // hold the call until the gateway's connection is cut
	})
	rec := &eventRecorder{}
	base, token, p := startAgentProxy(t, firstHandAgent(stub.url, time.Minute, config.ExecEntry{Exe: "sleep"}), rec)

	callDone := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, base+"exec/run", strings.NewReader(`{"command":["sleep","30"]}`))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			callDone <- -1
			return
		}
		_ = resp.Body.Close()
		callDone <- resp.StatusCode
	}()
	deadline := time.Now().Add(5 * time.Second)
	for stub.calls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the call never reached the stub")
		}
		time.Sleep(10 * time.Millisecond)
	}

	p.Stop() // cuts the connection: the handler's context is cancelled, the call fails, the event is appended, THEN Stop returns
	if e := onlyExec(t, rec); e.Status != "failed" || e.Reason != reasonExecCancelled {
		t.Fatalf("after Stop the cancelled call must already be recorded: %+v", e)
	}
	<-callDone
}

func TestStartRefusesFirstHandAgentWithoutTimeoutOrUnixURL(t *testing.T) {
	notRefexec := firstHandAgent("unix:///tmp/x.sock", time.Minute, config.ExecEntry{Exe: "cat"})
	notRefexec.Exec.Runtime = "podman" // valid url + timeout, but not the first-hand runtime
	emptyRuntime := firstHandAgent("unix:///tmp/x.sock", time.Minute, config.ExecEntry{Exe: "cat"})
	emptyRuntime.Exec.Runtime = ""
	for name, agent := range map[string]config.AgentDef{
		"no timeout":    firstHandAgent("unix:///tmp/x.sock", 0, config.ExecEntry{Exe: "cat"}),
		"https url":     firstHandAgent("https://exec.example/run", time.Minute, config.ExecEntry{Exe: "cat"}),
		"wrong runtime": notRefexec,
		"empty runtime": emptyRuntime,
	} {
		t.Run(name, func(t *testing.T) {
			p := New(config.GatewayConfig{}, "", broker.StaticEnv{}, nil, "")
			if _, _, err := p.Start(context.Background(), testBinding(), agent, func(engine.Event) {}); err == nil || !strings.Contains(err.Error(), "must be refexec with a unix:// url and a positive timeout") {
				t.Fatalf("Start err = %v, want the fail-closed refusal", err)
			}
		})
	}
}

func TestExecRunDialsTheOverrideRuntime(t *testing.T) {
	// A spawned child's agents are served by the CHILD's refexec: the
	// per-child gateway overrides every agent's configured exec.url.
	stub := newRefexecStub(t, echoRefexec)
	rec := &eventRecorder{}
	agent := firstHandAgent(config.UnixScheme+"/nonexistent/dir/refexec.sock", 5*time.Second, config.ExecEntry{Exe: "cat"})
	p := New(config.GatewayConfig{}, "", broker.StaticEnv{}, nil, "").WithExecURL(stub.url)
	base, token, err := p.Start(context.Background(), testBinding(), agent, rec.record)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Stop)
	code, body := execPost(t, base, "exec/run", token, `{"command":["cat","/work/x"]}`)
	if code != 200 || !strings.Contains(body, `"exit":0`) {
		t.Fatalf("code=%d body=%s: the override runtime was not dialed", code, body)
	}
	if stub.calls.Load() != 1 {
		t.Fatalf("override runtime calls = %d, want 1", stub.calls.Load())
	}
	if e := onlyExec(t, rec); e.Status != "succeeded" || e.Mode != "runtime" {
		t.Fatalf("event = %+v", e)
	}
}

func TestStartChecksTheOverrideNotTheConfiguredExecURL(t *testing.T) {
	// With an override, the configured exec.url is not consulted at all — not
	// even for the Start-time unix:// check.
	agent := firstHandAgent("https://not-a-socket", 5*time.Second, config.ExecEntry{Exe: "cat"})
	p := New(config.GatewayConfig{}, "", broker.StaticEnv{}, nil, "").WithExecURL(config.UnixScheme + "/tmp/x/refexec.sock")
	if _, _, err := p.Start(context.Background(), testBinding(), agent, func(engine.Event) {}); err != nil {
		t.Fatalf("Start with a unix:// override must pass: %v", err)
	}
	p.Stop()
	bare := New(config.GatewayConfig{}, "", broker.StaticEnv{}, nil, "").WithExecURL("https://not-a-socket")
	if _, _, err := bare.Start(context.Background(), testBinding(), firstHandAgent(config.UnixScheme+"/tmp/x/refexec.sock", 5*time.Second), func(engine.Event) {}); err == nil {
		t.Fatal("a non-unix override must fail Start exactly as a non-unix exec.url does")
	}
}
