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
	"github.com/agenthof/agenthof/internal/audit"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/investigate"
	"github.com/agenthof/agenthof/internal/ledger"
)

func TestEventsVerifiedAndInFlightAndBroken(t *testing.T) {
	host := &fakeHost{}
	ts := newTestServer(t, host, fakeAuth{}, 1)
	release := make(chan struct{})
	host.run = engineRun(t, ts.logDir, gateExec{release: release})
	_, body := ts.do(t, http.MethodPost, "/v1/runs", goodToken, runReq)
	acc := decode[apiclient.RunAccepted](t, body)
	path := filepath.Join(ts.logDir, acc.RunID+".jsonl")
	waitFor(t, func() bool { b, _ := os.ReadFile(path); return strings.Count(string(b), "\n") >= 2 }) // workflow_started + step_started

	_, body = ts.do(t, http.MethodGet, "/v1/runs/"+acc.RunID+"/events", goodToken, nil)
	ev := decode[apiclient.RunEvents](t, body)
	if ev.Integrity != apiclient.IntegrityVerified || ev.Head.Count != 2 || len(ev.Events) != 2 {
		t.Fatalf("%+v", ev)
	}

	// A record caught mid-write on a RUNNING run is in_flight, not damage;
	// the verified prefix still comes back.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"time":"2026-`); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	_, body = ts.do(t, http.MethodGet, "/v1/runs/"+acc.RunID+"/events", goodToken, nil)
	ev = decode[apiclient.RunEvents](t, body)
	if ev.Integrity != apiclient.IntegrityInFlight || ev.Head.Count != 2 || len(ev.Events) != 2 {
		t.Fatalf("%+v, want in_flight with the 2-event prefix", ev)
	}

	// Once the run ends the engine's next append lands after the partial
	// line, which the chain reads as a broken record — now terminal: broken
	// with its line.
	close(release)
	ts.waitStatus(t, acc.RunID)
	_, body = ts.do(t, http.MethodGet, "/v1/runs/"+acc.RunID+"/events", goodToken, nil)
	ev = decode[apiclient.RunEvents](t, body)
	if ev.Integrity != apiclient.IntegrityBroken || ev.BrokenLine != 3 {
		t.Fatalf("%+v, want broken at line 3", ev)
	}
}

func TestEventsTornWhenTerminal(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	id, err := engine.Refuse(ts.logDir, "se", "fix-bug", testInvoker, "why", nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(ts.logDir, id+".jsonl")
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, raw[:len(raw)-1], 0o600); err != nil { // drop the trailing newline
		t.Fatal(err)
	}
	_, body := ts.do(t, http.MethodGet, "/v1/runs/"+id+"/events", goodToken, nil)
	if ev := decode[apiclient.RunEvents](t, body); ev.Integrity != apiclient.IntegrityTorn || len(ev.Events) != 0 {
		t.Fatalf("%+v, want torn (a run nobody hosts is never in_flight)", ev)
	}
	resp, _ := ts.do(t, http.MethodGet, "/v1/runs/r-0123456789abcdef/events", goodToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown run events = %d, want 404", resp.StatusCode)
	}
}

func TestAuditEndpointRendersConfigJoin(t *testing.T) {
	host := &fakeHost{}
	ts := newTestServer(t, host, fakeAuth{}, 1)
	// A control apply the run's config_hash joins to.
	ctl := ts.srv.cfg.ControlLog
	// control.Append stamps the time itself (now), which is before the run
	// below starts — exactly the join ConfigJoin looks for.
	if _, err := control.Append(ctl, control.Event{Action: "apply", Outcome: "success", ConfigHash: "cafe0001", Invoker: testInvoker}); err != nil {
		t.Fatal(err)
	}
	reg := testRegistry(t)
	host.run = func(ctx context.Context, runID string, origin *engine.Origin) (engine.Result, error) {
		return engine.Run(ctx, reg, "se", "fix-bug", "x", testInvoker, gateExec{release: closedChan()},
			engine.Options{LogDir: ts.logDir, ArtifactDir: filepath.Join(ts.logDir, "arts"), RunID: runID, Origin: origin, ConfigHash: "cafe0001"})
	}
	_, body := ts.do(t, http.MethodPost, "/v1/runs", goodToken, runReq)
	acc := decode[apiclient.RunAccepted](t, body)
	ts.waitStatus(t, acc.RunID)

	resp, text := ts.do(t, http.MethodGet, "/v1/runs/"+acc.RunID+"/audit", goodToken, nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") || resp.Header.Get(apiclient.IntegrityHeader) != apiclient.IntegrityVerified {
		t.Fatalf("%d %q %q", resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get(apiclient.IntegrityHeader))
	}
	events, head, verr := engine.ReadLog(ts.logDir, acc.RunID)
	cev, verdict, _ := investigate.LoadControl(ctl)
	want := audit.Render(events, head, verr) + investigate.ConfigJoin(cev, verdict, "cafe0001", events[0].Time) + "\n"
	if string(text) != want {
		t.Fatalf("audit text differs from the local render:\n%s\n--- want ---\n%s", text, want)
	}
}

func TestInvestigateEndpointIsInvestigate1(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	if _, err := engine.Refuse(ts.logDir, "se", "fix-bug", testInvoker, "why", nil); err != nil {
		t.Fatal(err)
	}
	resp, body := ts.do(t, http.MethodGet, "/v1/investigate?outcome=refused&since=2020-01-01T00:00:00Z", goodToken, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	res, err := investigate.DecodeJSON(body)
	if err != nil || len(res.Events) != 1 || res.Events[0].Outcome != "refused" {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if !strings.Contains(string(body), `"since": "2020-01-01T00:00:00Z"`) {
		t.Fatalf("the query must echo the parsed filter: %s", body)
	}
	resp, _ = ts.do(t, http.MethodGet, "/v1/investigate?since=yesterday", goodToken, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a non-RFC3339 since = %d, want 400", resp.StatusCode)
	}
}

func TestIntegrityOfRunningRunOnlyPromotesTorn(t *testing.T) {
	s := &Server{runs: newRunTable()}
	id, _ := s.runs.mint(t.TempDir(), func() {}, time.Now())
	if got, _ := s.integrityOf(id, &ledger.TornError{}); got != apiclient.IntegrityInFlight {
		t.Fatalf("torn on a running run = %q, want in_flight", got)
	}
	if got, line := s.integrityOf(id, &ledger.ChainBrokenError{Line: 4}); got != apiclient.IntegrityBroken || line != 4 {
		t.Fatalf("broken on a running run = %q/%d, want broken/4 — a broken chain is never in flight", got, line)
	}
	if got, _ := s.integrityOf("r-notrunning", &ledger.TornError{}); got != apiclient.IntegrityTorn {
		t.Fatalf("torn on an unhosted run = %q, want torn", got)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition never held")
}
