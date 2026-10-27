package serve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/anchor/anchortest"
	"github.com/agenthof/agenthof/internal/apiclient"
	"github.com/agenthof/agenthof/internal/audit"
	"github.com/agenthof/agenthof/internal/completeness"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/investigate"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/sidecar"
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
	want := audit.Render(events, head, verr, completeness.Check(events), "ledger anchor: not anchored\n") + completeness.VerifyTree(ts.logDir, acc.RunID, events, verr).SubtreeLines() + investigate.ConfigJoin(cev, verdict, "cafe0001", events[0].Time) + "\n"
	if string(text) != want {
		t.Fatalf("audit text differs from the local render:\n%s\n--- want ---\n%s", text, want)
	}
}

func TestEventsAndAuditCarryCompleteness(t *testing.T) {
	host := &fakeHost{}
	ts := newTestServer(t, host, fakeAuth{}, 1)
	release := make(chan struct{})
	host.run = engineRun(t, ts.logDir, gateExec{release: release})
	_, body := ts.do(t, http.MethodPost, "/v1/runs", goodToken, runReq)
	acc := decode[apiclient.RunAccepted](t, body)
	path := filepath.Join(ts.logDir, acc.RunID+".jsonl")
	waitFor(t, func() bool { b, _ := os.ReadFile(path); return strings.Count(string(b), "\n") >= 2 })

	// Still running here: the file alone says unterminated; the server knows better.
	_, body = ts.do(t, http.MethodGet, "/v1/runs/"+acc.RunID+"/events", goodToken, nil)
	if ev := decode[apiclient.RunEvents](t, body); ev.Completeness != apiclient.CompletenessInFlight {
		t.Fatalf("%+v, want in_flight while the run is hosted and running", ev)
	}
	resp, text := ts.do(t, http.MethodGet, "/v1/runs/"+acc.RunID+"/audit", goodToken, nil)
	if resp.Header.Get(apiclient.CompletenessHeader) != apiclient.CompletenessInFlight || !strings.Contains(string(text), "ledger completeness: UNTERMINATED") {
		t.Fatalf("header %q text:\n%s", resp.Header.Get(apiclient.CompletenessHeader), text)
	}

	close(release)
	ts.waitStatus(t, acc.RunID)
	_, body = ts.do(t, http.MethodGet, "/v1/runs/"+acc.RunID+"/events", goodToken, nil)
	if ev := decode[apiclient.RunEvents](t, body); ev.Completeness != apiclient.CompletenessComplete || ev.CompletenessDetail != "" {
		t.Fatalf("%+v", ev)
	}
	resp, text = ts.do(t, http.MethodGet, "/v1/runs/"+acc.RunID+"/audit", goodToken, nil)
	if resp.Header.Get(apiclient.CompletenessHeader) != apiclient.CompletenessComplete || !strings.Contains(string(text), "ledger completeness: complete (") {
		t.Fatalf("header %q text:\n%s", resp.Header.Get(apiclient.CompletenessHeader), text)
	}
}

func TestAuditHeadersCarryTheTreeWorst(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	n1, n4 := 1, 4
	// Run ids are "r-" plus hex (see runIDPattern); the suffixes stand in for
	// root and child without lifting the hex-only constraint.
	const root, child = "r-aa", "r-cc"
	ce := []engine.Event{{Type: "workflow_started", DoorAccounting: engine.DoorAccountingAdmission}, {Type: "step_started", Step: "c"}, {Type: "step_succeeded", Step: "c", DoorCalls: &n4}, {Type: "workflow_finished", Status: "succeeded"}}
	writeLinked(t, ts.logDir, child, root, ce...)
	re := []engine.Event{{Type: "workflow_started", DoorAccounting: engine.DoorAccountingAdmission}, {Type: "step_started", Step: "a"}, {Type: "spawn", Status: "succeeded", ChildRunID: child, Depth: 1}, {Type: "step_succeeded", Step: "a", DoorCalls: &n1}, {Type: "workflow_finished", Status: "succeeded"}}
	writeLinked(t, ts.logDir, root, "", re...)
	resp, text := ts.do(t, http.MethodGet, "/v1/runs/"+root+"/audit", goodToken, nil)
	if resp.Header.Get(apiclient.CompletenessHeader) != apiclient.CompletenessGap || !strings.Contains(string(text), "subtree: run "+child+" — integrity verified, completeness gap") {
		t.Fatalf("header %q text:\n%s", resp.Header.Get(apiclient.CompletenessHeader), text)
	}
	// The text is byte-identical to the local render + subtree lines.
	events, head, verr := engine.ReadLog(ts.logDir, root)
	tree := completeness.VerifyTree(ts.logDir, root, events, verr)
	// No sidecar anywhere: the root reads not anchored, and a verified child's
	// subtree line says so too.
	notAnchored := func(completeness.Node) string { return ", anchor not-anchored" }
	if want := audit.Render(events, head, verr, tree.Root.Report, "ledger anchor: not anchored\n") + tree.SubtreeLinesWith(notAnchored); string(text) != want {
		t.Fatalf("server text differs from the local render:\n%s\n--- want ---\n%s", text, want)
	}
}

// TestAuditHeaderMapsUnreadableChildToBroken: a child ledger that cannot be
// read at all (here: a directory where the file should be — an open/IO
// failure, neither torn nor broken) is reported as `error` in the subtree
// text, but the Agenthof-Integrity header keeps its closed enum and reads
// `broken`, the way integrityOf already maps the run's own unreadable
// chain; the client exits 1 on it as the local command does.
func TestAuditHeaderMapsUnreadableChildToBroken(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	n1 := 1
	const root, child = "r-aa", "r-cc"
	if err := os.MkdirAll(filepath.Join(ts.logDir, child+".jsonl"), 0o755); err != nil {
		t.Fatal(err)
	}
	re := []engine.Event{{Type: "workflow_started", DoorAccounting: engine.DoorAccountingAdmission}, {Type: "step_started", Step: "a"}, {Type: "spawn", Status: "succeeded", ChildRunID: child, Depth: 1}, {Type: "step_succeeded", Step: "a", DoorCalls: &n1}, {Type: "workflow_finished", Status: "succeeded"}}
	writeLinked(t, ts.logDir, root, "", re...)
	resp, text := ts.do(t, http.MethodGet, "/v1/runs/"+root+"/audit", goodToken, nil)
	if got := resp.Header.Get(apiclient.IntegrityHeader); got != apiclient.IntegrityBroken {
		t.Fatalf("%s = %q, want %q (the header's enum is closed)\n%s", apiclient.IntegrityHeader, got, apiclient.IntegrityBroken, text)
	}
	if !strings.Contains(string(text), "subtree: run "+child+" — integrity error, completeness not judged") {
		t.Fatalf("text:\n%s", text)
	}
}

// writeLinked writes events as a run ledger, linked under parent when given.
func writeLinked(t *testing.T, dir, id, parent string, events ...engine.Event) {
	t.Helper()
	log, err := engine.OpenLog(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	b := engine.Binding{Invoker: testInvoker, Role: "se", Workflow: "fix-bug", RunID: id}
	if parent != "" {
		b.ParentRunID, b.Depth = parent, 1
	}
	for i, e := range events {
		e.Time, e.Binding = time.Unix(int64(i), 0).UTC(), b
		if err := log.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	_ = log.Close()
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

// TestInvestigateEndpointCarriesAnchorVerdicts: the server decides every
// anchor with the options it was configured with, per request — the
// document is the local document byte for byte, and a backend that stops
// answering is seen on the next request without a restart.
func TestInvestigateEndpointCarriesAnchorVerdicts(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	opts := investigate.Options{AnchorBackend: func(string, string, *ecdsa.PublicKey, bool) (anchor.Backend, error) { return stub, nil }}
	ts := newTestServerWith(t, &fakeHost{}, fakeAuth{}, 1, opts)
	ctl := ts.srv.cfg.ControlLog
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	head, err := control.Append(ctl, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc"})
	if err != nil {
		t.Fatal(err)
	}
	rcpt, err := stub.Submit(context.Background(), anchor.Head{Seq: head.Count, Hash: head.Hash})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.Append(ctl, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w,
		Anchor: &control.Anchor{Seq: head.Count, Hash: head.Hash, Kind: "tlog", BackendKind: stub.Kind(), Backend: rcpt.Backend, Ref: rcpt.Ref, Proof: rcpt.Proof}}); err != nil {
		t.Fatal(err)
	}

	resp, body := ts.do(t, http.MethodGet, "/v1/investigate", goodToken, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	local, err := investigate.Timeline(ts.logDir, ctl, investigate.Filter{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	want, err := investigate.RenderJSON(local, investigate.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != want {
		t.Fatalf("server document differs from the local one:\n%s\n--- want ---\n%s", body, want)
	}
	res, err := investigate.DecodeJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	var got *investigate.Anchor
	for _, e := range res.Events {
		if e.Kind == "anchor" {
			got = e.Anchor
		}
	}
	wantAnchor := &investigate.Anchor{Seq: 1, Hash: head.Hash, Kind: "tlog", BackendKind: "rfc3161", Backend: anchortest.StubBackend, Ref: rcpt.Ref, Verdict: "verified"}
	if !reflect.DeepEqual(got, wantAnchor) {
		t.Fatalf("anchor: %+v\nwant %+v", got, wantAnchor)
	}
	if !strings.Contains(investigate.RenderText(res), "\nanchors: 1 (1 verified, 0 mismatch, 0 unverifiable)\n") {
		t.Fatalf("text:\n%s", investigate.RenderText(res))
	}

	stub.Fail()
	_, body = ts.do(t, http.MethodGet, "/v1/investigate", goodToken, nil)
	if !strings.Contains(string(body), `"verdict": "unverifiable"`) || !strings.Contains(string(body), `"cause": "stub: unavailable"`) {
		t.Fatalf("per request: %s", body)
	}
}

// TestInvestigateEndpointOverASealedRoot: sealing the server's control ledger
// between two requests changes neither the chain nor the verdict — the second
// answer reads across the sealed segment, verified, with the logical count.
func TestInvestigateEndpointOverASealedRoot(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	ctl := ts.srv.cfg.ControlLog
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	for i := 0; i < 2; i++ {
		if _, err := control.Append(ctl, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc"}); err != nil {
			t.Fatal(err)
		}
	}
	type doc struct {
		Sources []struct {
			Kind  string `json:"kind"`
			Count int    `json:"count"`
		} `json:"sources"`
		Integrity struct {
			OK bool `json:"ok"`
		} `json:"integrity"`
	}
	get := func() doc {
		t.Helper()
		resp, body := ts.do(t, http.MethodGet, "/v1/investigate", goodToken, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		var d doc
		if err := json.Unmarshal(body, &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := get(); !d.Integrity.OK || len(d.Sources) != 1 || d.Sources[0].Count != 2 {
		t.Fatalf("before the seal: %+v", d)
	}
	if _, err := control.SealActive(ctl, control.Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: w}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Append(ctl, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc"}); err != nil {
		t.Fatal(err)
	}
	if d := get(); !d.Integrity.OK || len(d.Sources) != 1 || d.Sources[0].Count != 4 {
		t.Fatalf("after the seal: %+v", d)
	}
}

// TestInvestigateEndpointOverAFaultedSealedRoot: a set fault is an answer,
// not a server error — 200, the control source's verdict "broken" (a foreign
// genesis in the continuation) or "torn" (a torn continuation tail), and
// integrity.ok false.
func TestInvestigateEndpointOverAFaultedSealedRoot(t *testing.T) {
	for name, tc := range map[string]struct{ plant, verdict string }{
		"boundary": {`{"v":"control/1","seq":1,"time":"2026-10-15T10:00:00Z","action":"apply","outcome":"success","invoker":{"subject":"old","issuer":"local","method":"static"},"witness":{"os_user":"o","hostname":"h"},"prev":"","log_id":"` + strings.Repeat("cd", 16) + `"}` + "\n", "broken"},
		"torn":     {`{"torn`, "torn"},
	} {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
			ctl := ts.srv.cfg.ControlLog
			inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
			if _, err := control.Append(ctl, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc"}); err != nil {
				t.Fatal(err)
			}
			if _, err := control.SealActive(ctl, control.Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: w}, nil); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(ctl, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.WriteString(tc.plant)
			_ = f.Close()
			resp, body := ts.do(t, http.MethodGet, "/v1/investigate", goodToken, nil)
			if resp.StatusCode != 200 {
				t.Fatalf("%d %s", resp.StatusCode, body)
			}
			var d struct {
				Sources []struct {
					Kind      string `json:"kind"`
					Integrity string `json:"integrity"`
				} `json:"sources"`
				Integrity struct {
					OK bool `json:"ok"`
				} `json:"integrity"`
			}
			if err := json.Unmarshal(body, &d); err != nil {
				t.Fatal(err)
			}
			if d.Integrity.OK || len(d.Sources) != 1 || d.Sources[0].Kind != "control" || d.Sources[0].Integrity != tc.verdict {
				t.Fatalf("%+v", d)
			}
		})
	}
}

// anchorRun writes a sidecar beside run id's ledger, minted by stub over the
// run's final head.
func anchorRun(t *testing.T, logDir, id string, stub *anchortest.Stub) {
	t.Helper()
	chain, head, err := ledger.ReadVerify(filepath.Join(logDir, id+".jsonl"), ledger.Unlocked)
	if err != nil {
		t.Fatal(err)
	}
	rcpt, err := stub.Submit(context.Background(), anchor.Head{Seq: head.Count, Hash: head.Hash})
	if err != nil {
		t.Fatal(err)
	}
	if !sidecar.FinalEvent(chain) {
		t.Fatalf("run %s has no final event", id)
	}
	rec := sidecar.Record{Time: time.Now().UTC(), RunID: id, Seq: head.Count, Hash: head.Hash, Kind: "tlog", BackendKind: stub.Kind(), Backend: rcpt.Backend, Ref: rcpt.Ref, Proof: rcpt.Proof}
	if err := sidecar.Append(sidecar.Path(logDir, id), id, rec); err != nil {
		t.Fatal(err)
	}
}

// TestAuditTextCarriesTheAnchorLine: the audit text prints the run's anchor
// line after the completeness line and ", anchor <state>" on each verified
// child's subtree line — the same text the local command renders, read offline
// under the server's own pin (here: none) and never asking the log.
func TestAuditTextCarriesTheAnchorLine(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	opts := investigate.Options{AnchorBackend: func(string, string, *ecdsa.PublicKey, bool) (anchor.Backend, error) { return stub, nil }}
	ts := newTestServerWith(t, &fakeHost{}, fakeAuth{}, 1, opts)
	n1, n0 := 1, 0
	const root, child = "r-00000000000000aa", "r-00000000000000cc"
	ce := []engine.Event{{Type: "workflow_started", DoorAccounting: engine.DoorAccountingAdmission}, {Type: "step_started", Step: "c"}, {Type: "step_succeeded", Step: "c", DoorCalls: &n0}, {Type: "workflow_finished", Status: "succeeded"}}
	writeLinked(t, ts.logDir, child, root, ce...)
	re := []engine.Event{{Type: "workflow_started", DoorAccounting: engine.DoorAccountingAdmission}, {Type: "step_started", Step: "a"}, {Type: "spawn", Status: "succeeded", ChildRunID: child, Depth: 1}, {Type: "step_succeeded", Step: "a", DoorCalls: &n1}, {Type: "workflow_finished", Status: "succeeded"}}
	writeLinked(t, ts.logDir, root, "", re...)

	getAudit := func() string {
		t.Helper()
		resp, text := ts.do(t, http.MethodGet, "/v1/runs/"+root+"/audit", goodToken, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, text)
		}
		return string(text)
	}

	// Nothing anchored: the root says so, and so does the child's line.
	text := getAudit()
	if !strings.Contains(text, "ledger completeness: complete (1 door call(s) accounted)\nledger anchor: not anchored\n") ||
		!strings.Contains(text, "subtree: run "+child+" — integrity verified, completeness complete, anchor not-anchored\n") {
		t.Fatalf("unanchored:\n%s", text)
	}

	// Both anchored: offline, no pin, a backend that needs none → verified under
	// the key as served; never "independent".
	anchorRun(t, ts.logDir, child, stub)
	anchorRun(t, ts.logDir, root, stub)
	text = getAudit()
	if !strings.Contains(text, "ledger anchor: anchored — verified under the log key as served (not independent; ") || strings.Contains(text, "independently verified") ||
		!strings.Contains(text, ", anchor verified\n") {
		t.Fatalf("anchored:\n%s", text)
	}

	// A backend that cannot decide is unverifiable on both lines — never
	// tampering — and the root line names the way to a networked check.
	stub.Fail()
	text = getAudit()
	if !strings.Contains(text, "ledger anchor: unverifiable — stub: unavailable; pin the log key in anchor.pub beside the control ledger or pass --anchor-key, or run audit verify "+root+" to check under the key the log serves\n") ||
		!strings.Contains(text, ", anchor unverifiable\n") || strings.Contains(text, "MISMATCH") {
		t.Fatalf("unverifiable:\n%s", text)
	}
}

// submitCounter wraps a stub and counts Submit: a read route must never submit
// (serve does not anchor), so the count stays zero across every read below.
type submitCounter struct {
	*anchortest.Stub
	submits *int
}

func (c submitCounter) Submit(ctx context.Context, h anchor.Head) (anchor.Receipt, error) {
	*c.submits++
	return c.Stub.Submit(ctx, h)
}

func simpleRunEvents(status string) []engine.Event {
	n0 := 0
	return []engine.Event{{Type: "workflow_started", DoorAccounting: engine.DoorAccountingAdmission}, {Type: "step_started", Step: "c"}, {Type: "step_succeeded", Step: "c", DoorCalls: &n0}, {Type: "workflow_finished", Status: status}}
}

// TestEventsAndAuditCarryAnchorState: both read routes report the run's anchor
// state in the closed four-word enum, offline under the server's own pin, and
// agree. A read never submits — the backend is only ever asked to verify, from
// the stored proof — and as-served (a networked state) is never a value.
func TestEventsAndAuditCarryAnchorState(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	var submits int
	backend := submitCounter{Stub: stub, submits: &submits}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var pinned atomic.Bool
	opts := investigate.Options{
		AnchorBackend: func(string, string, *ecdsa.PublicKey, bool) (anchor.Backend, error) { return backend, nil },
		AnchorKey: func() (*ecdsa.PublicKey, error) {
			if pinned.Load() {
				return &key.PublicKey, nil
			}
			return nil, nil
		},
	}
	ts := newTestServerWith(t, &fakeHost{}, fakeAuth{}, 1, opts)
	const id = "r-00000000000000aa"
	writeLinked(t, ts.logDir, id, "", simpleRunEvents("succeeded")...)

	read := func(want, wantDetail string) {
		t.Helper()
		resp, body := ts.do(t, http.MethodGet, "/v1/runs/"+id+"/events", goodToken, nil)
		ev := decode[apiclient.RunEvents](t, body)
		if resp.StatusCode != 200 || ev.Anchor != want {
			t.Fatalf("events anchor = %q (%d), want %q\n%s", ev.Anchor, resp.StatusCode, want, body)
		}
		if wantDetail == "" && ev.AnchorDetail != "" || wantDetail != "" && !strings.Contains(ev.AnchorDetail, wantDetail) {
			t.Fatalf("anchor_detail = %q, want it to contain %q", ev.AnchorDetail, wantDetail)
		}
		resp, text := ts.do(t, http.MethodGet, "/v1/runs/"+id+"/audit", goodToken, nil)
		if got := resp.Header.Get(apiclient.AnchorHeader); got != want {
			t.Fatalf("%s = %q, want %q\n%s", apiclient.AnchorHeader, got, want, text)
		}
		switch want {
		case apiclient.AnchorNotAnchored, apiclient.AnchorVerified, apiclient.AnchorMismatch, apiclient.AnchorUnverifiable:
		default:
			t.Fatalf("%q is not one of the four words", want)
		}
	}

	// No sidecar: not anchored, no detail — and the pin is never resolved for it.
	read(apiclient.AnchorNotAnchored, "")
	// The raw JSON key is `anchor`, omitted when empty.
	_, body := ts.do(t, http.MethodGet, "/v1/runs/"+id+"/events", goodToken, nil)
	if !strings.Contains(string(body), `"anchor":"not-anchored"`) || strings.Contains(string(body), "anchor_detail") {
		t.Fatalf("wire: %s", body)
	}

	anchorRun(t, ts.logDir, id, stub)
	read(apiclient.AnchorVerified, "")
	pinned.Store(true)
	read(apiclient.AnchorVerified, "")
	pinned.Store(false)

	// A backend that cannot decide: unverifiable, with the cause — never
	// mismatch, never as-served.
	stub.Fail()
	read(apiclient.AnchorUnverifiable, "stub: unavailable")

	// A reforged ledger: valid chain, but it no longer reproduces the anchored
	// head — mismatch.
	if err := os.Remove(filepath.Join(ts.logDir, id+".jsonl")); err != nil {
		t.Fatal(err)
	}
	writeLinked(t, ts.logDir, id, "", simpleRunEvents("failed")...)
	read(apiclient.AnchorMismatch, "does not reproduce the anchored head")

	if submits != 0 {
		t.Fatalf("serve submitted %d time(s); a read route never anchors", submits)
	}
}

// TestEventsOmitsAnchorWhenTheChainFailed: a torn or broken ledger has nothing
// a sidecar can be checked against, so neither route reports an anchor.
func TestEventsOmitsAnchorWhenTheChainFailed(t *testing.T) {
	ts := newTestServer(t, &fakeHost{}, fakeAuth{}, 1)
	const id = "r-00000000000000aa"
	writeLinked(t, ts.logDir, id, "", simpleRunEvents("succeeded")...)
	f, err := os.OpenFile(filepath.Join(ts.logDir, id+".jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"torn":`); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	_, body := ts.do(t, http.MethodGet, "/v1/runs/"+id+"/events", goodToken, nil)
	if ev := decode[apiclient.RunEvents](t, body); ev.Integrity == apiclient.IntegrityVerified || ev.Anchor != "" || ev.AnchorDetail != "" {
		t.Fatalf("%+v", ev)
	}
	resp, _ := ts.do(t, http.MethodGet, "/v1/runs/"+id+"/audit", goodToken, nil)
	if got := resp.Header.Get(apiclient.AnchorHeader); got != "" {
		t.Fatalf("%s = %q on a failed chain", apiclient.AnchorHeader, got)
	}
}

// TestAuditHeaderCarriesTheChildAnchorWorst: the header is the tree's worst —
// a verified child's mismatch outranks the root's verified, an unverifiable
// child lifts a verified root to unverifiable, and a root mismatch is not
// lowered by a child's unverifiable.
func TestAuditHeaderCarriesTheChildAnchorWorst(t *testing.T) {
	good := anchortest.NewStub([]byte("s"))
	opts := investigate.Options{AnchorBackend: func(string, string, *ecdsa.PublicKey, bool) (anchor.Backend, error) { return good, nil }}
	ts := newTestServerWith(t, &fakeHost{}, fakeAuth{}, 1, opts)
	n1, n0 := 1, 0
	const root, child = "r-00000000000000aa", "r-00000000000000cc"
	childEvents := func(status string) []engine.Event {
		return []engine.Event{{Type: "workflow_started", DoorAccounting: engine.DoorAccountingAdmission}, {Type: "step_started", Step: "c"}, {Type: "step_succeeded", Step: "c", DoorCalls: &n0}, {Type: "workflow_finished", Status: status}}
	}
	rootEvents := []engine.Event{{Type: "workflow_started", DoorAccounting: engine.DoorAccountingAdmission}, {Type: "step_started", Step: "a"}, {Type: "spawn", Status: "succeeded", ChildRunID: child, Depth: 1}, {Type: "step_succeeded", Step: "a", DoorCalls: &n1}, {Type: "workflow_finished", Status: "succeeded"}}
	writeLinked(t, ts.logDir, child, root, childEvents("succeeded")...)
	writeLinked(t, ts.logDir, root, "", rootEvents...)
	header := func() string {
		t.Helper()
		resp, text := ts.do(t, http.MethodGet, "/v1/runs/"+root+"/audit", goodToken, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, text)
		}
		return resp.Header.Get(apiclient.AnchorHeader)
	}
	if got := header(); got != apiclient.AnchorNotAnchored {
		t.Fatalf("nothing anchored: %q", got)
	}
	// Only the child anchored and verified: the root's own word stands.
	anchorRun(t, ts.logDir, child, good)
	if got := header(); got != apiclient.AnchorNotAnchored {
		t.Fatalf("child verified, root not anchored: %q", got)
	}
	anchorRun(t, ts.logDir, root, good)
	if got := header(); got != apiclient.AnchorVerified {
		t.Fatalf("both verified: %q", got)
	}
	// The child's ledger reforged: its mismatch outranks the root's verified.
	if err := os.Remove(filepath.Join(ts.logDir, child+".jsonl")); err != nil {
		t.Fatal(err)
	}
	writeLinked(t, ts.logDir, child, root, childEvents("failed")...)
	if got := header(); got != apiclient.AnchorMismatch {
		t.Fatalf("child mismatch: %q", got)
	}
	// Restore the child; a backend that cannot decide lifts both to unverifiable.
	if err := os.Remove(filepath.Join(ts.logDir, child+".jsonl")); err != nil {
		t.Fatal(err)
	}
	writeLinked(t, ts.logDir, child, root, childEvents("succeeded")...)
	good.Fail()
	if got := header(); got != apiclient.AnchorUnverifiable {
		t.Fatalf("unverifiable: %q", got)
	}
	// A root mismatch is not lowered by a child's unverifiable.
	if err := os.Remove(filepath.Join(ts.logDir, root+".jsonl")); err != nil {
		t.Fatal(err)
	}
	reforged := append([]engine.Event(nil), rootEvents...)
	reforged[len(reforged)-1].Status = "failed"
	writeLinked(t, ts.logDir, root, "", reforged...)
	if got := header(); got != apiclient.AnchorMismatch {
		t.Fatalf("root mismatch + child unverifiable: %q", got)
	}
}
