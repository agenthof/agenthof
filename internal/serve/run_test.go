package serve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/engine"
)

func mustRead(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var runReq = apiclient.RunRequest{Role: "se", Workflow: "fix-bug", Input: "x"}

// waitStatus polls GET /v1/runs/{id} until it leaves running (or the test
// deadline).
func (ts *testServer) waitStatus(t *testing.T, id string) apiclient.RunStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, body := ts.do(t, http.MethodGet, "/v1/runs/"+id, goodToken, nil)
		st := decode[apiclient.RunStatus](t, body)
		if st.Status != apiclient.StatusRunning {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("run %s never left running", id)
	return apiclient.RunStatus{}
}

func TestStartRunIs202WithLocationAndFinishesSucceeded(t *testing.T) {
	host := &fakeHost{}
	ts := newTestServer(t, host, fakeAuth{}, 2)
	host.run = engineRun(t, ts.logDir, gateExec{release: closedChan()})
	resp, body := ts.do(t, http.MethodPost, "/v1/runs", goodToken, runReq)
	acc := decode[apiclient.RunAccepted](t, body)
	if resp.StatusCode != http.StatusAccepted || acc.Status != apiclient.StatusRunning || !runIDPattern.MatchString(acc.RunID) {
		t.Fatalf("%d %+v", resp.StatusCode, acc)
	}
	if loc := resp.Header.Get("Location"); loc != "/v1/runs/"+acc.RunID {
		t.Fatalf("Location = %q", loc)
	}
	st := ts.waitStatus(t, acc.RunID)
	if st.Status != "succeeded" || st.Finished == nil || st.OutputPreview != "plan-text" || st.OutputSHA == "" {
		t.Fatalf("%+v", st)
	}
	events, _, err := engine.ReadLog(ts.logDir, acc.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if o := events[0].Origin; o == nil || o.Via != "api" || o.RemoteAddr == "" || o.ServerHost != "127.0.0.1:0" {
		t.Fatalf("workflow_started origin = %+v", o)
	}
}

func closedChan() chan struct{} { c := make(chan struct{}); close(c); return c }

func TestStartRunUnauthenticatedNeverPrepares(t *testing.T) {
	host := &fakeHost{}
	ts := newTestServer(t, host, fakeAuth{}, 1)
	resp, body := ts.do(t, http.MethodPost, "/v1/runs", "bad", runReq)
	if resp.StatusCode != http.StatusUnauthorized || string(body) != "unauthorized\n" || host.prepared.Load() != 0 {
		t.Fatalf("%d %q prepared=%d", resp.StatusCode, body, host.prepared.Load())
	}
	if entries, _ := os.ReadDir(ts.logDir); len(entries) != 0 {
		t.Fatalf("401 must write nothing: %v", entries)
	}
}

func TestStartRunAdmitRefusalIs403AndLedgered(t *testing.T) {
	reason := `role "se" requires membership in one of its allowed groups (finance); the invoker's groups don't qualify`
	ts := newTestServer(t, &fakeHost{admitReason: reason}, fakeAuth{}, 1)
	req, _ := http.NewRequest(http.MethodPost, ts.http.URL+"/v1/runs", strings.NewReader(`{"role":"se","workflow":"fix-bug","input":"x"}`))
	req.Header.Set("Authorization", "Bearer "+goodToken)
	// A tab is the one control byte Go's transport lets through in a header
	// value (ESC and friends are rejected client-side); unicode.IsPrint
	// rejects it, so it proves strip + cap through the real HTTP path. The
	// ESC case is pinned by Task 1's unit tests.
	req.Header.Set("User-Agent", "probe\t"+strings.Repeat("A", 500))
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	acc := decode[apiclient.RunAccepted](t, mustRead(t, resp))
	if resp.StatusCode != http.StatusForbidden || acc.Status != apiclient.StatusRefused || acc.Reason != reason {
		t.Fatalf("%d %+v", resp.StatusCode, acc)
	}
	events, _, err := engine.ReadLog(ts.logDir, acc.RunID)
	if err != nil || len(events) != 1 || events[0].Type != "run_refused" || events[0].Reason != reason {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	o := events[0].Origin
	if o == nil || o.Via != "api" || o.ForwardedFor != "203.0.113.9" || strings.Contains(o.UserAgent, "\t") || len([]rune(o.UserAgent)) != 200 {
		t.Fatalf("origin = %+v: must be stamped, forwarded_for verbatim, user_agent stripped and capped", o)
	}
	if inv := events[0].Binding.Invoker; inv.Subject != testInvoker.Subject || inv.Method != "oidc" {
		t.Fatalf("binding invoker = %+v, want the verified token's", inv)
	}
	// The refusal is a run: GET finds it on disk.
	st := ts.waitStatus(t, acc.RunID)
	if st.Status != apiclient.StatusRefused || st.Reason != reason {
		t.Fatalf("%+v", st)
	}
}

func TestStartRunConfigInvalidIs422WithFixedBodyAndFullLedgerReason(t *testing.T) {
	ts := newTestServer(t, &fakeHost{prepErr: fmt.Errorf("%w: agents/x.yaml: fronted agent needs an endpoint", ErrConfigInvalid)}, fakeAuth{}, 1)
	resp, body := ts.do(t, http.MethodPost, "/v1/runs", goodToken, runReq)
	acc := decode[apiclient.RunAccepted](t, body)
	if resp.StatusCode != http.StatusUnprocessableEntity || acc.Status != apiclient.StatusRefused || acc.Reason != "configuration invalid" {
		t.Fatalf("%d %+v", resp.StatusCode, acc)
	}
	events, _, _ := engine.ReadLog(ts.logDir, acc.RunID)
	if events[0].Reason != "configuration invalid: agents/x.yaml: fronted agent needs an endpoint" {
		t.Fatalf("ledger reason = %q", events[0].Reason)
	}
}

func TestStartRunBadBodies(t *testing.T) {
	host := &fakeHost{}
	ts := newTestServer(t, host, fakeAuth{}, 1)
	for name, body := range map[string]string{"not json": "{", "missing fields": `{"role":"se"}`} {
		req, _ := http.NewRequest(http.MethodPost, ts.http.URL+"/v1/runs", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+goodToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, resp.StatusCode)
		}
	}
	big := `{"role":"se","workflow":"fix-bug","input":"` + strings.Repeat("x", maxRunBody+1) + `"}`
	req, _ := http.NewRequest(http.MethodPost, ts.http.URL+"/v1/runs", strings.NewReader(big))
	req.Header.Set("Authorization", "Bearer "+goodToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("over-cap body: %d, want 413", resp.StatusCode)
	}
	if host.prepared.Load() != 0 {
		t.Fatal("a bad body must never reach Prepare")
	}
	// Every failed POST gave its slot back.
	if _, code := ts.srv.reserve(); code != 0 {
		t.Fatalf("slot leaked: reserve code %d", code)
	}
}

func TestStartRunCapIs429AndSlotReturns(t *testing.T) {
	host := &fakeHost{}
	ts := newTestServer(t, host, fakeAuth{}, 1)
	release := make(chan struct{})
	host.run = engineRun(t, ts.logDir, gateExec{release: release})
	resp, body := ts.do(t, http.MethodPost, "/v1/runs", goodToken, runReq)
	first := decode[apiclient.RunAccepted](t, body)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("%d", resp.StatusCode)
	}
	resp, _ = ts.do(t, http.MethodPost, "/v1/runs", goodToken, runReq)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("second POST = %d (Retry-After %q), want 429 with Retry-After", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if host.prepared.Load() != 1 {
		t.Fatalf("the slot must be reserved BEFORE the config load; Prepare ran %d times", host.prepared.Load())
	}
	close(release)
	ts.waitStatus(t, first.RunID)
	// The table flips to terminal a hair before the goroutine's deferred
	// release gives the slot back, so the next 202 is polled, not assumed.
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, body = ts.do(t, http.MethodPost, "/v1/runs", goodToken, runReq)
		if resp.StatusCode == http.StatusAccepted {
			// Let the run this POST started finish: a detached run still
			// writing its ledger would race the temp dir's removal.
			ts.waitStatus(t, decode[apiclient.RunAccepted](t, body).RunID)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the first run finished: %d, want 202", resp.StatusCode)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRunSurvivesClientDisconnect(t *testing.T) {
	host := &fakeHost{}
	ts := newTestServer(t, host, fakeAuth{}, 1)
	seen := make(chan context.Context, 1)
	release := make(chan struct{})
	host.run = func(ctx context.Context, runID string, _ *engine.Origin) (engine.Result, error) {
		seen <- ctx
		<-release
		return engine.Result{RunID: runID, Status: "succeeded"}, nil
	}
	reqCtx, cancelReq := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(reqCtx, http.MethodPost, ts.http.URL+"/v1/runs", strings.NewReader(`{"role":"se","workflow":"fix-bug","input":"x"}`))
	req.Header.Set("Authorization", "Bearer "+goodToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	cancelReq() // the client is gone
	runCtx := <-seen
	time.Sleep(50 * time.Millisecond)
	if runCtx.Err() != nil {
		t.Fatal("the run's context died with the request; it must derive from the server, not r.Context()")
	}
	close(release)
}

func TestCancelEndpointRecordsCancelled(t *testing.T) {
	host := &fakeHost{}
	ts := newTestServer(t, host, fakeAuth{}, 1)
	host.run = engineRun(t, ts.logDir, gateExec{release: make(chan struct{})}) // never released: only cancel ends it
	_, body := ts.do(t, http.MethodPost, "/v1/runs", goodToken, runReq)
	acc := decode[apiclient.RunAccepted](t, body)
	resp, _ := ts.do(t, http.MethodPost, "/v1/runs/"+acc.RunID+"/cancel", goodToken, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("cancel = %d", resp.StatusCode)
	}
	st := ts.waitStatus(t, acc.RunID)
	if st.Status != "cancelled" || st.Reason != "run cancelled" {
		t.Fatalf("%+v, want cancelled / run cancelled", st)
	}
}

func TestShutdownIs503ForPostAndCancelsRuns(t *testing.T) {
	host := &fakeHost{}
	ts := newTestServer(t, host, fakeAuth{}, 2)
	host.run = engineRun(t, ts.logDir, gateExec{release: make(chan struct{})})
	_, body := ts.do(t, http.MethodPost, "/v1/runs", goodToken, runReq)
	acc := decode[apiclient.RunAccepted](t, body)
	done := make(chan error, 1)
	go func() { done <- ts.srv.Shutdown(context.Background()) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, _ := ts.do(t, http.MethodPost, "/v1/runs", goodToken, runReq)
		if resp.StatusCode == http.StatusServiceUnavailable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("POST during shutdown = %d, want 503", resp.StatusCode)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Reads keep working after the drain; the run was cancelled, honestly.
	_, body = ts.do(t, http.MethodGet, "/v1/runs/"+acc.RunID, goodToken, nil)
	if st := decode[apiclient.RunStatus](t, body); st.Status != "cancelled" {
		t.Fatalf("%+v, want cancelled after shutdown", st)
	}
}

func TestRunErrorIsFixedReason(t *testing.T) {
	host := &fakeHost{}
	ts := newTestServer(t, host, fakeAuth{}, 1)
	host.run = func(_ context.Context, runID string, _ *engine.Origin) (engine.Result, error) {
		return engine.Result{RunID: runID, Status: "failed"}, errors.New("open /srv/secret/path: permission denied")
	}
	_, body := ts.do(t, http.MethodPost, "/v1/runs", goodToken, runReq)
	acc := decode[apiclient.RunAccepted](t, body)
	st := ts.waitStatus(t, acc.RunID)
	if st.Status != "failed" || st.Reason != "run error" {
		t.Fatalf("%+v: an engine error names a path and must not reach the API", st)
	}
}

// TestStartRunRejectsCraftedRoleWorkflow: role/workflow are attacker-controlled
// and land in Binding, which audit.Render prints verbatim; a crafted name
// (terminal escapes, megabyte padding) must be rejected 400 at the handler,
// before Prepare, writing nothing — not recorded and later re-emitted at a
// reader's terminal.
func TestStartRunRejectsCraftedRoleWorkflow(t *testing.T) {
	host := &fakeHost{}
	ts := newTestServer(t, host, fakeAuth{}, 1)
	cases := map[string]apiclient.RunRequest{
		"esc in role":    {Role: "se\x1b[2J", Workflow: "fix-bug", Input: "x"},
		"cr/lf workflow": {Role: "se", Workflow: "fix-bug\r\n", Input: "x"},
		"over-long role": {Role: strings.Repeat("A", maxNameLen+1), Workflow: "fix-bug", Input: "x"},
		"empty workflow": {Role: "se", Workflow: "", Input: "x"},
	}
	for name, req := range cases {
		resp, _ := ts.do(t, http.MethodPost, "/v1/runs", goodToken, req)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, resp.StatusCode)
		}
	}
	if host.prepared.Load() != 0 {
		t.Fatal("a crafted role/workflow must never reach Prepare")
	}
	if entries, _ := os.ReadDir(ts.logDir); len(entries) != 0 {
		t.Fatalf("a rejected name must write nothing: %v", entries)
	}
	if _, code := ts.srv.reserve(); code != 0 {
		t.Fatalf("slot leaked: reserve code %d", code)
	}
}

func TestValidName(t *testing.T) {
	for _, bad := range []string{"", "x\x1b[2J", "line\nbreak", "tab\there", strings.Repeat("A", maxNameLen+1)} {
		if validName(bad) {
			t.Errorf("validName(%q) = true, want false", bad)
		}
	}
	for _, ok := range []string{"se", "fix-bug", "software_engineer", strings.Repeat("A", maxNameLen)} {
		if !validName(ok) {
			t.Errorf("validName(%q) = false, want true", ok)
		}
	}
}
