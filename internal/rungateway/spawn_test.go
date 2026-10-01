package rungateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/broker"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/engine"
)

type stubSpawnCall struct {
	role, workflow, input string
	parent                engine.Binding
}

// stubSpawner records every call and answers a canned result. When block is
// set, Spawn waits on it — or on ctx, in which case it answers a failed
// child with reason "cancelled" — so a test can hold children in flight.
type stubSpawner struct {
	mu     sync.Mutex
	calls  []stubSpawnCall
	block  chan struct{}
	result SpawnResult
	err    error
}

func (s *stubSpawner) Spawn(ctx context.Context, role, workflow, input string, parent engine.Binding) (SpawnResult, error) {
	s.mu.Lock()
	s.calls = append(s.calls, stubSpawnCall{role, workflow, input, parent})
	block, result, err := s.block, s.result, s.err
	s.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return SpawnResult{ChildRunID: "r-child", Status: "failed", Reason: "cancelled", Provisioned: true}, nil
		}
	}
	return result, err
}

func (s *stubSpawner) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func spawnAgent(targets ...config.SpawnTarget) config.AgentDef {
	return config.AgentDef{Name: "lead", Execution: "fronted", Endpoint: "https://x", MaySpawn: targets}
}

func spawnPolicy(depth, parallel, total int) config.GatewayConfig {
	return config.GatewayConfig{Spawn: config.SpawnPolicy{MaxDepth: depth, MaxParallel: parallel, MaxTotalSpawns: total}}
}

var workerChild = config.SpawnTarget{Role: "worker", Workflow: "child-wf"}

// startSpawnGateway starts a gateway for agent with sp as its Spawner and
// the given binding, recording events into rec. It returns the base URL and
// run token.
func startSpawnGateway(t *testing.T, ctx context.Context, gw config.GatewayConfig, bind engine.Binding, agent config.AgentDef, sp Spawner, rec *eventRecorder) (string, string, *Gateway) {
	t.Helper()
	p := New(gw, "", broker.StaticEnv{}, nil, "")
	if sp != nil {
		p.WithSpawner(sp)
	}
	base, token, err := p.Start(ctx, bind, agent, rec.record)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Stop)
	return base, token, p
}

// postSpawn POSTs body to /spawn and returns the status code and decoded
// answer. It reports a transport failure with t.Errorf (never FailNow), so
// it is safe to call from the goroutines the concurrency tests start; a
// failure then shows as code 0 and the test's own assertions name it.
func postSpawn(t *testing.T, ctx context.Context, base, token string, body any) (int, spawnResponse) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Errorf("marshal: %v", err)
		return 0, spawnResponse{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"spawn", bytes.NewReader(b))
	if err != nil {
		t.Errorf("new request: %v", err)
		return 0, spawnResponse{}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("POST /spawn: %v", err)
		return 0, spawnResponse{}
	}
	defer func() { _ = resp.Body.Close() }()
	var out spawnResponse
	_ = json.NewDecoder(resp.Body).Decode(&out) // non-JSON answers (405, 503) leave it zero
	return resp.StatusCode, out
}

func spawnEvents(rec *eventRecorder) []engine.Event {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	var out []engine.Event
	for _, e := range rec.ev {
		if e.Type == "spawn" {
			out = append(out, e)
		}
	}
	return out
}

func spawnBody(role, workflow, input string) map[string]string {
	return map[string]string{"role": role, "workflow": workflow, "input": input}
}

func TestSpawnHappyPathRecordsChildOutcome(t *testing.T) {
	sp := &stubSpawner{result: SpawnResult{ChildRunID: "r-child", Status: "succeeded", OutputSHA: "abc123", OutputPreview: "hello back"}}
	rec := &eventRecorder{}
	base, token, _ := startSpawnGateway(t, context.Background(), spawnPolicy(3, 2, 4), testBinding(), spawnAgent(workerChild), sp, rec)
	code, out := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "do it"))
	if code != http.StatusOK || out.Status != "succeeded" || out.ChildRunID != "r-child" || out.OutputSHA != "abc123" || out.OutputPreview != "hello back" {
		t.Fatalf("code=%d out=%+v", code, out)
	}
	ev := spawnEvents(rec)
	if len(ev) != 1 {
		t.Fatalf("spawn events = %d, want 1", len(ev))
	}
	e := ev[0]
	if e.Status != "succeeded" || e.Agent != "lead" || e.ChildRunID != "r-child" || e.ChildRole != "worker" || e.ChildWorkflow != "child-wf" || e.Depth != 1 || e.OutputSHA != "abc123" || e.Reason != "" {
		t.Fatalf("event = %+v", e)
	}
	if e.Artifact != "" {
		t.Fatal("the child's preview must not be recorded on the parent's event; only its hash")
	}
	if !reflect.DeepEqual(e.Binding, testBinding()) {
		t.Fatalf("event binding = %+v, want the parent's", e.Binding)
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if len(sp.calls) != 1 || sp.calls[0].role != "worker" || sp.calls[0].workflow != "child-wf" || sp.calls[0].input != "do it" || !reflect.DeepEqual(sp.calls[0].parent, testBinding()) {
		t.Fatalf("spawner saw %+v", sp.calls)
	}
}

func TestSpawnRefusedWhenNotOnMaySpawn(t *testing.T) {
	sp := &stubSpawner{result: SpawnResult{ChildRunID: "r-child", Status: "succeeded"}}
	rec := &eventRecorder{}
	base, token, _ := startSpawnGateway(t, context.Background(), spawnPolicy(3, 2, 4), testBinding(), spawnAgent(workerChild), sp, rec)
	for _, body := range []map[string]string{spawnBody("lead", "child-wf", "x"), spawnBody("worker", "lead-wf", "x"), spawnBody("", "", "x")} {
		code, out := postSpawn(t, context.Background(), base, token, body)
		if code != http.StatusForbidden || out.Status != "refused" || out.Reason != reasonSpawnNotAllowed || out.ChildRunID != "" {
			t.Fatalf("code=%d out=%+v", code, out)
		}
	}
	ev := spawnEvents(rec)
	if len(ev) != 3 {
		t.Fatalf("spawn events = %d, want 3 refusals", len(ev))
	}
	for _, e := range ev {
		if e.Status != "refused" || e.Reason != reasonSpawnNotAllowed || e.ChildRunID != "" {
			t.Fatalf("event = %+v", e)
		}
	}
	if sp.callCount() != 0 {
		t.Fatal("a may_spawn refusal must not reach the spawner")
	}
}

func TestSpawnRefusedWithoutSpawner(t *testing.T) {
	rec := &eventRecorder{}
	base, token, _ := startSpawnGateway(t, context.Background(), spawnPolicy(3, 2, 4), testBinding(), spawnAgent(workerChild), nil, rec)
	code, out := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x"))
	if code != http.StatusForbidden || out.Reason != reasonSpawnUnavailable {
		t.Fatalf("code=%d out=%+v", code, out)
	}
	if ev := spawnEvents(rec); len(ev) != 1 || ev[0].Status != "refused" || ev[0].Reason != reasonSpawnUnavailable {
		t.Fatalf("events = %+v", ev)
	}
}

func TestSpawnDepthBoundary(t *testing.T) {
	sp := &stubSpawner{result: SpawnResult{ChildRunID: "r-child", Status: "succeeded"}}
	// max_depth 2: a run at depth 1 may spawn (its child sits at 2)...
	rec := &eventRecorder{}
	bind := testBinding()
	bind.Depth = 1
	base, token, _ := startSpawnGateway(t, context.Background(), spawnPolicy(2, 2, 4), bind, spawnAgent(workerChild), sp, rec)
	if code, out := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x")); code != http.StatusOK || out.Status != "succeeded" {
		t.Fatalf("depth 1 -> 2 under max_depth 2: code=%d out=%+v", code, out)
	}
	if ev := spawnEvents(rec); len(ev) != 1 || ev[0].Depth != 2 {
		t.Fatalf("events = %+v, want depth 2", ev)
	}
	// ...and a run at depth 2 may not.
	rec2 := &eventRecorder{}
	bind.Depth = 2
	base2, token2, _ := startSpawnGateway(t, context.Background(), spawnPolicy(2, 2, 4), bind, spawnAgent(workerChild), sp, rec2)
	code, out := postSpawn(t, context.Background(), base2, token2, spawnBody("worker", "child-wf", "x"))
	if code != http.StatusForbidden || out.Reason != reasonSpawnDepth {
		t.Fatalf("depth 2 -> 3 under max_depth 2: code=%d out=%+v", code, out)
	}
	if ev := spawnEvents(rec2); len(ev) != 1 || ev[0].Status != "refused" || ev[0].Reason != reasonSpawnDepth || ev[0].Depth != 3 {
		t.Fatalf("events = %+v", ev)
	}
	if sp.callCount() != 1 {
		t.Fatalf("spawner calls = %d, want only the allowed one", sp.callCount())
	}
}

func TestSpawnParallelCapIsAtomic(t *testing.T) {
	sp := &stubSpawner{block: make(chan struct{}), result: SpawnResult{ChildRunID: "r-child", Status: "succeeded", Provisioned: true}}
	rec := &eventRecorder{}
	base, token, p := startSpawnGateway(t, context.Background(), spawnPolicy(3, 2, 10), testBinding(), spawnAgent(workerChild), sp, rec)
	const n = 5
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _ = postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x"))
		}(i)
	}
	// Exactly two children get in; the other three are refused while those
	// two are still in flight.
	waitFor(t, "two children in flight", func() bool { return sp.callCount() == 2 })
	waitFor(t, "three refusals recorded", func() bool {
		refused := 0
		for _, e := range spawnEvents(rec) {
			if e.Status == "refused" && e.Reason == reasonSpawnParallel {
				refused++
			}
		}
		return refused == 3
	})
	close(sp.block)
	wg.Wait()
	ok, forbidden := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusForbidden:
			forbidden++
		}
	}
	if ok != 2 || forbidden != 3 {
		t.Fatalf("codes = %v, want exactly 2×200 and 3×403", codes)
	}
	p.mu.Lock()
	total, inflight := p.spawnTotal, p.spawnInflight
	p.mu.Unlock()
	if total != 2 || inflight != 0 {
		t.Fatalf("spawnTotal=%d spawnInflight=%d, want 2 and 0: refused attempts must not count", total, inflight)
	}
}

func TestSpawnTotalCapSurvivesStartStop(t *testing.T) {
	sp := &stubSpawner{result: SpawnResult{ChildRunID: "r-child", Status: "succeeded", Provisioned: true}}
	rec := &eventRecorder{}
	p := New(spawnPolicy(3, 5, 2), "", broker.StaticEnv{}, nil, "").WithSpawner(sp)
	agent := spawnAgent(workerChild)
	// Step 1: two children, then a may_spawn-denied attempt that must not
	// consume the third slot.
	base, token, err := p.Start(context.Background(), testBinding(), agent, rec.record)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if code, _ := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x")); code != http.StatusOK {
			t.Fatalf("code=%d", code)
		}
	}
	if code, out := postSpawn(t, context.Background(), base, token, spawnBody("nope", "child-wf", "x")); code != http.StatusForbidden || out.Reason != reasonSpawnNotAllowed {
		t.Fatalf("code=%d out=%+v", code, out)
	}
	p.Stop()
	// Step 2 of the same run: Start resets the listener, not the run's total.
	base, token, err = p.Start(context.Background(), testBinding(), agent, rec.record)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Stop)
	code, out := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x"))
	if code != http.StatusForbidden || out.Reason != reasonSpawnTotal {
		t.Fatalf("third child of a run capped at 2: code=%d out=%+v", code, out)
	}
	if sp.callCount() != 2 {
		t.Fatalf("spawner calls = %d, want 2", sp.callCount())
	}
	if ev := spawnEvents(rec); len(ev) != 4 || ev[3].Status != "refused" || ev[3].Reason != reasonSpawnTotal {
		t.Fatalf("events = %+v", ev)
	}
}

func TestSpawnRefusedChildRecordsChildRunIDAndCounts(t *testing.T) {
	sp := &stubSpawner{result: SpawnResult{ChildRunID: "r-refused", Status: "refused", Reason: `role "worker" requires membership in one of its allowed groups (finance); the invoker's groups don't qualify`, Provisioned: true}}
	rec := &eventRecorder{}
	base, token, p := startSpawnGateway(t, context.Background(), spawnPolicy(3, 2, 4), testBinding(), spawnAgent(workerChild), sp, rec)
	code, out := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x"))
	if code != http.StatusForbidden || out.Status != "refused" || out.ChildRunID != "r-refused" || !strings.Contains(out.Reason, "allowed groups") {
		t.Fatalf("code=%d out=%+v", code, out)
	}
	ev := spawnEvents(rec)
	if len(ev) != 1 || ev[0].Status != "refused" || ev[0].ChildRunID != "r-refused" || !strings.Contains(ev[0].Reason, "allowed groups") {
		t.Fatalf("events = %+v", ev)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.spawnTotal != 1 {
		t.Fatalf("spawnTotal = %d: a child that got its own ledger counts", p.spawnTotal)
	}
}

func TestSpawnClosingIsNotRecorded(t *testing.T) {
	sp := &stubSpawner{result: SpawnResult{ChildRunID: "r-child", Status: "succeeded"}}
	rec := &eventRecorder{}
	p := New(spawnPolicy(3, 2, 4), "", broker.StaticEnv{}, nil, "").WithSpawner(sp)
	h := p.spawnHandler(context.Background(), testBinding(), spawnAgent(workerChild), rec.record, slog.New(slog.DiscardHandler))
	p.mu.Lock()
	p.closing = true
	p.mu.Unlock()
	b, _ := json.Marshal(spawnBody("worker", "child-wf", "x"))
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/spawn", bytes.NewReader(b)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rr.Code)
	}
	if ev := spawnEvents(rec); len(ev) != 0 {
		t.Fatalf("a spawn arriving after close must not be recorded (it would race the run's log.Close): %+v", ev)
	}
	if sp.callCount() != 0 {
		t.Fatal("a spawn arriving after close must start nothing")
	}
}

func TestSpawnStopCutsTheConnectionAndStillRecords(t *testing.T) {
	sp := &stubSpawner{block: make(chan struct{})}
	rec := &eventRecorder{}
	p := New(spawnPolicy(3, 2, 4), "", broker.StaticEnv{}, nil, "").WithSpawner(sp)
	base, token, err := p.Start(context.Background(), testBinding(), spawnAgent(workerChild), rec.record)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b, _ := json.Marshal(spawnBody("worker", "child-wf", "x"))
		req, _ := http.NewRequest(http.MethodPost, base+"spawn", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	waitFor(t, "the child to be in flight", func() bool { return sp.callCount() == 1 })
	// Stop cuts the agent's connection; that cancels r.Context(), which
	// cancels the child, which lets the handler record and return — so
	// Stop's inflight wait ends and the event is on the ledger before Stop
	// returns.
	p.Stop()
	ev := spawnEvents(rec)
	if len(ev) != 1 || ev[0].Status != "failed" || ev[0].ChildRunID != "r-child" || ev[0].Reason != "cancelled" {
		t.Fatalf("after Stop, events = %+v, want one failed spawn for r-child (the stub's cancelled answer)", ev)
	}
	<-done
}

func TestSpawnStepContextCancelTearsDownChild(t *testing.T) {
	sp := &stubSpawner{block: make(chan struct{})}
	rec := &eventRecorder{}
	stepCtx, cancelStep := context.WithCancel(context.Background())
	base, token, _ := startSpawnGateway(t, stepCtx, spawnPolicy(3, 2, 4), testBinding(), spawnAgent(workerChild), sp, rec)
	type answer struct {
		code int
		out  spawnResponse
	}
	got := make(chan answer, 1)
	go func() {
		code, out := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x"))
		got <- answer{code, out}
	}()
	waitFor(t, "the child to be in flight", func() bool { return sp.callCount() == 1 })
	cancelStep()
	select {
	case a := <-got:
		if a.code != http.StatusOK || a.out.Status != "failed" || a.out.ChildRunID != "r-child" {
			t.Fatalf("answer = %+v, want the child's failed outcome", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling the step context did not tear the child down")
	}
	if ev := spawnEvents(rec); len(ev) != 1 || ev[0].Status != "failed" || ev[0].Reason != "cancelled" {
		t.Fatalf("events = %+v", ev)
	}
}

func TestSpawnAgentHangUpTearsDownChild(t *testing.T) {
	sp := &stubSpawner{block: make(chan struct{})}
	rec := &eventRecorder{}
	base, token, _ := startSpawnGateway(t, context.Background(), spawnPolicy(3, 2, 4), testBinding(), spawnAgent(workerChild), sp, rec)
	reqCtx, hangUp := context.WithCancel(context.Background())
	go func() {
		b, _ := json.Marshal(spawnBody("worker", "child-wf", "x"))
		req, _ := http.NewRequestWithContext(reqCtx, http.MethodPost, base+"spawn", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	waitFor(t, "the child to be in flight", func() bool { return sp.callCount() == 1 })
	hangUp()
	waitFor(t, "the child to be torn down and recorded", func() bool {
		ev := spawnEvents(rec)
		return len(ev) == 1 && ev[0].Status == "failed" && ev[0].Reason == "cancelled"
	})
}

func TestSpawnRejectsBadRequests(t *testing.T) {
	sp := &stubSpawner{result: SpawnResult{ChildRunID: "r-child", Status: "succeeded"}}
	rec := &eventRecorder{}
	base, token, _ := startSpawnGateway(t, context.Background(), spawnPolicy(3, 2, 4), testBinding(), spawnAgent(workerChild), sp, rec)
	get, _ := http.NewRequest(http.MethodGet, base+"spawn", nil)
	get.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d, want 405", resp.StatusCode)
	}
	bad, _ := http.NewRequest(http.MethodPost, base+"spawn", strings.NewReader("{not json"))
	bad.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad JSON: %d, want 400", resp.StatusCode)
	}
	huge, _ := http.NewRequest(http.MethodPost, base+"spawn", strings.NewReader(`{"role":"worker","workflow":"child-wf","input":"`+strings.Repeat("x", 2<<20)+`"}`))
	huge.Header.Set("Authorization", "Bearer "+token)
	// The server answers 400 after reading only the first MiB; the client
	// may see that answer or a reset while still writing. Either is fine —
	// what matters is below: nothing recorded, nothing started.
	if resp, err = http.DefaultClient.Do(huge); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("oversized body: %d, want 400", resp.StatusCode)
		}
	}
	if ev := spawnEvents(rec); len(ev) != 0 {
		t.Fatalf("bad requests must not be recorded: %+v", ev)
	}
	if sp.callCount() != 0 {
		t.Fatal("bad requests must start nothing")
	}
}

func TestSpawnInternalFailureRecordedWithFixedReason(t *testing.T) {
	sp := &stubSpawner{result: SpawnResult{ChildRunID: "r-child"}, err: errors.New("ledger write failed: open /secret/path: boom")}
	rec := &eventRecorder{}
	base, token, _ := startSpawnGateway(t, context.Background(), spawnPolicy(3, 2, 4), testBinding(), spawnAgent(workerChild), sp, rec)
	code, _ := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x"))
	if code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", code)
	}
	ev := spawnEvents(rec)
	if len(ev) != 1 || ev[0].Status != "failed" || ev[0].Reason != reasonSpawnIncomplete || ev[0].ChildRunID != "r-child" {
		t.Fatalf("events = %+v", ev)
	}
	if strings.Contains(ev[0].Reason, "secret") {
		t.Fatal("the error text reached the ledger")
	}
}

func TestSpawnCapsAgentSuppliedNames(t *testing.T) {
	sp := &stubSpawner{}
	rec := &eventRecorder{}
	base, token, _ := startSpawnGateway(t, context.Background(), spawnPolicy(3, 2, 4), testBinding(), spawnAgent(workerChild), sp, rec)
	long := strings.Repeat("r", 500)
	code, out := postSpawn(t, context.Background(), base, token, spawnBody(long, long, "x"))
	if code != http.StatusForbidden || out.Reason != reasonSpawnNotAllowed {
		t.Fatalf("code=%d out=%+v", code, out)
	}
	ev := spawnEvents(rec)
	if len(ev) != 1 || len([]rune(ev[0].ChildRole)) != 200 || len([]rune(ev[0].ChildWorkflow)) != 200 {
		t.Fatalf("agent-supplied names must be capped at 200 runes: role %d, workflow %d", len(ev[0].ChildRole), len(ev[0].ChildWorkflow))
	}
	if strings.Contains(ev[0].Reason, "r") && ev[0].Reason != reasonSpawnNotAllowed {
		t.Fatalf("the reason must be the fixed string, never interpolate the request: %q", ev[0].Reason)
	}
}

func TestSpawnUnknownSpawnerStatusIsRecordedFailed(t *testing.T) {
	sp := &stubSpawner{result: SpawnResult{ChildRunID: "r-child", Status: "sideways"}}
	rec := &eventRecorder{}
	base, token, _ := startSpawnGateway(t, context.Background(), spawnPolicy(3, 2, 4), testBinding(), spawnAgent(workerChild), sp, rec)
	code, out := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x"))
	if code != http.StatusOK || out.Status != "failed" {
		t.Fatalf("code=%d out=%+v", code, out)
	}
	if ev := spawnEvents(rec); len(ev) != 1 || ev[0].Status != "failed" {
		t.Fatalf("events = %+v", ev)
	}
}

func TestSpawnUnprovisionedChildDoesNotCount(t *testing.T) {
	// Key on "a compartment set was consumed", not "a ledger was written":
	// a refusal before provisioning, a failed provision, and an internal
	// failure before provisioning all give the slot back.
	cases := []struct {
		name   string
		result SpawnResult
		err    error
		code   int
	}{
		{"provision refused", SpawnResult{Status: "refused", Reason: "spawn compartment unavailable"}, nil, http.StatusForbidden},
		{"pre-run refusal with a child ledger", SpawnResult{ChildRunID: "r-obo", Status: "refused", Reason: "obo requires a verified invoker token"}, nil, http.StatusForbidden},
		{"internal failure before provisioning", SpawnResult{}, errors.New("ledger: open /secret: boom"), http.StatusBadGateway},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sp := &stubSpawner{result: c.result, err: c.err}
			rec := &eventRecorder{}
			base, token, p := startSpawnGateway(t, context.Background(), spawnPolicy(3, 2, 1), testBinding(), spawnAgent(workerChild), sp, rec)
			if code, _ := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x")); code != c.code {
				t.Fatalf("code = %d, want %d", code, c.code)
			}
			p.mu.Lock()
			total, inflight := p.spawnTotal, p.spawnInflight
			p.mu.Unlock()
			if total != 0 || inflight != 0 {
				t.Fatalf("spawnTotal=%d spawnInflight=%d, want 0 and 0: an unprovisioned child must give its slot back", total, inflight)
			}
			// The slot really is free: with max_total_spawns 1, a provisioned
			// child now fits.
			sp.mu.Lock()
			sp.result, sp.err = SpawnResult{ChildRunID: "r-child", Status: "succeeded", Provisioned: true}, nil
			sp.mu.Unlock()
			if code, out := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x")); code != http.StatusOK || out.Status != "succeeded" {
				t.Fatalf("after an unprovisioned child, a provisioned one must fit under max_total_spawns 1: code=%d out=%+v", code, out)
			}
			ev := spawnEvents(rec)
			if len(ev) != 2 || ev[0].ChildRunID != c.result.ChildRunID {
				t.Fatalf("events = %+v: the unprovisioned attempt is still recorded (with its child id when a ledger exists)", ev)
			}
		})
	}
}

func TestSpawnProvisionedRefusedChildCounts(t *testing.T) {
	// RBAC refused the child AFTER its compartments were provisioned: a set
	// was consumed, so it counts, exactly like a child that ran.
	sp := &stubSpawner{result: SpawnResult{ChildRunID: "r-refused", Status: "refused", Reason: "role \"worker\" requires membership", Provisioned: true}}
	rec := &eventRecorder{}
	base, token, p := startSpawnGateway(t, context.Background(), spawnPolicy(3, 2, 1), testBinding(), spawnAgent(workerChild), sp, rec)
	if code, _ := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x")); code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", code)
	}
	code, out := postSpawn(t, context.Background(), base, token, spawnBody("worker", "child-wf", "x"))
	if code != http.StatusForbidden || out.Reason != reasonSpawnTotal {
		t.Fatalf("a provisioned child consumed the only slot: code=%d out=%+v", code, out)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.spawnTotal != 1 {
		t.Fatalf("spawnTotal = %d, want 1", p.spawnTotal)
	}
}
