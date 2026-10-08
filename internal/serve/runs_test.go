package serve

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
)

func TestRunIDPatternRejectsTraversalAndJunk(t *testing.T) {
	for _, bad := range []string{"..", "r-..", "r-0123/..", "r-ZZ", "run1", "", "r-", "R-abcd"} {
		if runIDPattern.MatchString(bad) {
			t.Errorf("%q must not be a run id", bad)
		}
	}
	if !runIDPattern.MatchString("r-0123456789abcdef") || !runIDPattern.MatchString("r-ab") {
		t.Error("well-formed ids must match")
	}
}

func TestBadRunIDRejectedBeforeFilesystem(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	// The log dir does not exist yet: a handler that reached the
	// filesystem would answer 404 (not found), never 400.
	for _, path := range []string{"/v1/runs/r-ZZ", "/v1/runs/notarun", "/v1/runs/r-ZZ/events", "/v1/runs/r-ZZ/audit", "/v1/runs/r-ZZ/cancel"} {
		method := http.MethodGet
		if path == "/v1/runs/r-ZZ/cancel" {
			method = http.MethodPost
		}
		resp, _ := ts.do(t, method, path, goodToken, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s %s = %d, want 400 before any filesystem join", method, path, resp.StatusCode)
		}
	}
}

func TestGetRunNotFoundIs404(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	resp, _ := ts.do(t, http.MethodGet, "/v1/runs/r-0123456789abcdef", goodToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
}

func TestGetRunOnDiskDerivesStatusFromTheLedger(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	// A refusal recorded by another process: refused + its reason.
	id, err := engine.Refuse(ts.logDir, "se", "fix-bug", testInvoker, "why not", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := ts.do(t, http.MethodGet, "/v1/runs/"+id, goodToken, nil)
	st := decode[apiclient.RunStatus](t, body)
	if resp.StatusCode != 200 || st.Status != apiclient.StatusRefused || st.Reason != "why not" || st.Finished == nil {
		t.Fatalf("%d %+v", resp.StatusCode, st)
	}
	// A ledger with no terminal event: incomplete.
	log, err := engine.OpenLog(ts.logDir, "r-feedfacefeedface")
	if err != nil {
		t.Fatal(err)
	}
	bind := engine.Binding{Invoker: testInvoker, Role: "se", Workflow: "fix-bug", RunID: "r-feedfacefeedface"}
	if err := log.Append(engine.Event{Time: time.Now().UTC(), Type: "workflow_started", Binding: bind}); err != nil {
		t.Fatal(err)
	}
	_ = log.Close()
	_, body = ts.do(t, http.MethodGet, "/v1/runs/r-feedfacefeedface", goodToken, nil)
	if st := decode[apiclient.RunStatus](t, body); st.Status != apiclient.StatusIncomplete || st.Finished != nil {
		t.Fatalf("%+v, want incomplete", st)
	}
}

func TestListRunsUnionsTableAndDisk(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	if _, err := engine.Refuse(ts.logDir, "se", "fix-bug", testInvoker, "why not", nil); err != nil {
		t.Fatal(err)
	}
	// control.jsonl and torn fragments are never runs.
	for _, name := range []string{"control.jsonl", "control.jsonl.torn-1", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(ts.logDir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	hosted, err := ts.srv.runs.mint(ts.logDir, cancel, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, body := ts.do(t, http.MethodGet, "/v1/runs", goodToken, nil)
	list := decode[apiclient.RunList](t, body)
	if len(list.Runs) != 2 {
		t.Fatalf("runs = %+v, want the hosted run and the on-disk refusal only", list.Runs)
	}
	seen := map[string]string{}
	for _, r := range list.Runs {
		seen[r.RunID] = r.Status
	}
	if seen[hosted] != apiclient.StatusRunning {
		t.Fatalf("hosted run status = %q", seen[hosted])
	}
}

func TestCancelUnknownOrFinishedRun(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	resp, _ := ts.do(t, http.MethodPost, "/v1/runs/r-0123456789abcdef/cancel", goodToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cancel of an unhosted run = %d, want 404", resp.StatusCode)
	}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	id, _ := ts.srv.runs.mint(ts.logDir, cancel, time.Now())
	ts.srv.runs.finish(id, engine.Result{RunID: id, Status: "succeeded"}, "", time.Now())
	resp, _ = ts.do(t, http.MethodPost, "/v1/runs/"+id+"/cancel", goodToken, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("cancel of a finished run = %d, want 409", resp.StatusCode)
	}
}

// A hosted run cancelled through the API: the engine records cancelled and
// the table reads that ledger's last word back as the status reason.
func TestCancelAHostedRunReadsItsTerminalReasonBack(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	ctx, cancel := context.WithCancel(ts.srv.base)
	defer cancel()
	id, err := ts.srv.runs.mint(ts.logDir, cancel, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp, body := ts.do(t, http.MethodPost, "/v1/runs/"+id+"/cancel", goodToken, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("cancel of a running run = %d (%s), want 202", resp.StatusCode, body)
	}
	if st := decode[apiclient.RunStatus](t, body); st.Status != apiclient.StatusRunning {
		t.Fatalf("the accepted body reports the run as it still is: %+v", st)
	}
	// Who cancelled is operator-visible: the accepted cancel names the
	// verified subject, and never the bearer it arrived with.
	logs := ts.logs.String()
	if !strings.Contains(logs, "run cancel requested") || !strings.Contains(logs, "invoker="+testInvoker.Subject) {
		t.Fatalf("the cancel log must name the invoker, got:\n%s", logs)
	}
	if strings.Contains(logs, goodToken) {
		t.Fatal("no log line may carry the bearer token")
	}
	// The run's context is already over, so the held step returns at once
	// and the engine writes a cancelled workflow_finished.
	run := engineRun(t, ts.logDir, gateExec{release: make(chan struct{})})
	res, err := run(ctx, id, &engine.Origin{Via: "api", ServerHost: "127.0.0.1:0"})
	if err != nil || res.Status != "cancelled" {
		t.Fatalf("res=%+v err=%v, want a cancelled run", res, err)
	}
	ts.srv.runs.finish(id, res, terminalReason(ts.logDir, id), time.Now())
	_, body = ts.do(t, http.MethodGet, "/v1/runs/"+id, goodToken, nil)
	st := decode[apiclient.RunStatus](t, body)
	if st.Status != "cancelled" || st.Reason != "run cancelled" || st.Finished == nil {
		t.Fatalf("%+v, want cancelled with the ledger's reason", st)
	}
	if terminalReason(ts.logDir, "r-0123456789abcdef") != "" {
		t.Error("a run with no ledger has no terminal reason")
	}
}

func TestMintNeverReusesAnInFlightOrOnDiskID(t *testing.T) {
	tbl := newRunTable()
	dir := t.TempDir()
	seen := map[string]bool{}
	for range 200 {
		id, err := tbl.mint(dir, func() {}, time.Now())
		if err != nil || seen[id] {
			t.Fatalf("id=%q err=%v dup=%v", id, err, seen[id])
		}
		seen[id] = true
	}
	// fresh is mint's decision: an in-flight id and an on-disk id are both
	// taken, even one the table has never seen.
	var inFlight string
	for id := range seen {
		inFlight = id
		break
	}
	onDisk := engine.NewRunID()
	if err := os.WriteFile(filepath.Join(dir, onDisk+".jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if tbl.fresh(dir, inFlight) {
		t.Fatal("an in-flight id is not fresh")
	}
	if tbl.fresh(dir, onDisk) {
		t.Fatal("an id with a log on disk is not fresh, even if the table never saw it")
	}
	if !tbl.fresh(dir, engine.NewRunID()) {
		t.Fatal("a new id is fresh")
	}
}

func TestShutdownRefusesNewRunsCancelsInFlightAndWaits(t *testing.T) {
	// Exercised end-to-end in run_test.go (Task 9) once POST exists; here
	// the lifecycle primitive alone: reserve, drain, release.
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	release, code := ts.srv.reserve()
	if code != 0 {
		t.Fatalf("first reserve code = %d, want 0", code)
	}
	if _, code := ts.srv.reserve(); code != http.StatusTooManyRequests {
		t.Fatalf("second reserve code = %d, want 429", code)
	}
	done := make(chan error, 1)
	go func() { done <- ts.srv.Shutdown(context.Background()) }()
	time.Sleep(20 * time.Millisecond)
	if _, code := ts.srv.reserve(); code != http.StatusServiceUnavailable {
		t.Fatalf("reserve during drain code = %d, want 503", code)
	}
	if ts.srv.base.Err() == nil {
		t.Fatal("Shutdown must cancel the base context every run derives from")
	}
	select {
	case <-done:
		t.Fatal("Shutdown returned while a slot was still held")
	default:
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestListRunsSkipsTheControlLedgerByIdentity: a hard link to the control
// ledger inside LogDir, named like a run id, is skipped by identity — never
// summarized, never warned about, never listed.
func TestListRunsSkipsTheControlLedgerByIdentity(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	if _, err := control.Append(ts.srv.cfg.ControlLog, control.Event{Action: "apply", Outcome: "success",
		Invoker: testInvoker, Witness: control.CaptureWitness(), ConfigHash: "sha256:aaa"}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ts.logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const alias = "r-0000000000000c71"
	if err := os.Link(ts.srv.cfg.ControlLog, filepath.Join(ts.logDir, alias+".jsonl")); err != nil {
		t.Fatal(err)
	}
	id, err := engine.Refuse(ts.logDir, "se", "fix-bug", testInvoker, "why not", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := ts.do(t, http.MethodGet, "/v1/runs", goodToken, nil)
	list := decode[apiclient.RunList](t, body)
	if resp.StatusCode != 200 || len(list.Runs) != 1 || list.Runs[0].RunID != id {
		t.Fatalf("%d %+v, want only %s", resp.StatusCode, list.Runs, id)
	}
	if strings.Contains(ts.logs.String(), alias) {
		t.Fatalf("the ledger must not be read as a run:\n%s", ts.logs.String())
	}
}
