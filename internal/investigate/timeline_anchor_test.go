package investigate

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/anchor/anchortest"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// anchoredLedger writes <dir>/control.jsonl with one apply and one success
// anchor produced by be (the stub or a Rekor client over the fake), and
// returns the ledger path, the covered head and the receipt.
func anchoredLedger(t *testing.T, be anchor.Backend) (string, ledger.Head, anchor.Receipt) {
	t.Helper()
	ctl := filepath.Join(t.TempDir(), "control.jsonl")
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	head, err := control.Append(ctl, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc"})
	if err != nil {
		t.Fatal(err)
	}
	rcpt, err := be.Submit(context.Background(), anchor.Head{Seq: head.Count, Hash: head.Hash})
	if err != nil {
		t.Fatal(err)
	}
	payload := &control.Anchor{Seq: head.Count, Hash: head.Hash, Kind: "tlog", BackendKind: be.Kind(), Backend: rcpt.Backend, Ref: rcpt.Ref, Proof: rcpt.Proof, BackendKeyID: rcpt.BackendKeyID}
	if _, err := control.Append(ctl, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: payload}); err != nil {
		t.Fatal(err)
	}
	return ctl, head, rcpt
}

func stubOptions(stub *anchortest.Stub) Options {
	return Options{AnchorBackend: func(string, string, *ecdsa.PublicKey, bool) (anchor.Backend, error) { return stub, nil }}
}

// anchorEvents returns the success anchor records of res, in order, and
// fails if any of them lacks a verdict: a success record always carries one.
func anchorEvents(t *testing.T, res Result) []Record {
	t.Helper()
	var out []Record
	for _, e := range res.Events {
		if e.Source != "control" || e.Kind != "anchor" || e.Outcome != "success" {
			continue
		}
		if e.Anchor == nil || e.Anchor.Verdict == "" {
			t.Fatalf("a success anchor record without a verdict: %+v", e)
		}
		out = append(out, e)
	}
	return out
}

// TestTimelineAnchorVerdictsViaStub: the three verdicts, hermetically —
// verified through the stub, a structural mismatch with CheckAnchors's exact
// cause (carried whole, though over the 200-character field cap), unverifiable when the backend
// cannot answer, mismatch when it denies — with the facts on every one.
func TestTimelineAnchorVerdictsViaStub(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	ctl, head, rcpt := anchoredLedger(t, stub)
	logs := t.TempDir()

	res, err := Timeline(logs, ctl, Filter{}, stubOptions(stub))
	if err != nil {
		t.Fatal(err)
	}
	ev := anchorEvents(t, res)
	want := &Anchor{Seq: 1, Hash: head.Hash, Kind: "tlog", BackendKind: "rfc3161", Backend: anchortest.StubBackend, Ref: rcpt.Ref, Verdict: "verified"}
	if len(ev) != 1 || *ev[0].Anchor != *want {
		t.Fatalf("verified: %+v\nwant %+v", ev[0].Anchor, want)
	}
	if ExitCode(res) != 0 {
		t.Fatalf("exit %d", ExitCode(res))
	}

	// a second anchor whose recorded hash the chain does not reproduce
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	wrong := strings.Repeat("ff", 32)
	if _, err := control.Append(ctl, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w,
		Anchor: &control.Anchor{Seq: 1, Hash: wrong, Kind: "tlog", BackendKind: "rfc3161", Backend: anchortest.StubBackend, Ref: rcpt.Ref, Proof: rcpt.Proof}}); err != nil {
		t.Fatal(err)
	}
	res, err = Timeline(logs, ctl, Filter{}, stubOptions(stub))
	if err != nil {
		t.Fatal(err)
	}
	ev = anchorEvents(t, res)
	cause := fmt.Sprintf("the chain does not reproduce the recorded head at seq 1 (chain %s, recorded %s)", head.Hash, wrong)
	if len(ev) != 2 || ev[1].Anchor.Verdict != "mismatch" || ev[1].Anchor.Cause != cause || len(cause) <= 200 {
		t.Fatalf("structural: %+v (cause %d chars)", ev[1].Anchor, len(cause))
	}
	if ExitCode(res) != 0 || ev[0].Anchor.Verdict != "verified" {
		t.Fatalf("a mismatch anchor never changes the exit: %d, %+v", ExitCode(res), ev[0].Anchor)
	}

	stub.Deny()
	res, _ = Timeline(logs, ctl, Filter{}, stubOptions(stub))
	if ev = anchorEvents(t, res); ev[0].Anchor.Verdict != "mismatch" || ev[0].Anchor.Cause != "stub: denied" {
		t.Fatalf("Deny: %+v", ev[0].Anchor)
	}
	stub.Fail()
	res, _ = Timeline(logs, ctl, Filter{}, stubOptions(stub))
	if ev = anchorEvents(t, res); ev[0].Anchor.Verdict != "unverifiable" || ev[0].Anchor.Cause != "stub: unavailable" {
		t.Fatalf("Fail: %+v", ev[0].Anchor)
	}
}

// TestTimelineAnchorKeyAndOfflineViaRekorFake: under the zero Options a
// transparency-log anchor is unverifiable (no key to verify under); a
// structurally wrong one is a mismatch before any key is needed; pinned
// through AnchorKey it verifies from the stored proof with no request made.
func TestTimelineAnchorKeyAndOfflineViaRekorFake(t *testing.T) {
	fake := anchortest.NewRekorV1()
	t.Cleanup(fake.Close)
	rk, err := anchor.NewRekor(fake.URL, anchor.RekorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctl, head, rcpt := anchoredLedger(t, rk)
	logs := t.TempDir()

	res, err := Timeline(logs, ctl, Filter{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ev := anchorEvents(t, res)
	if len(ev) != 1 || ev[0].Anchor.Verdict != "unverifiable" || ev[0].Anchor.Cause != "no key to verify under (unpinned, offline)" || ev[0].Anchor.BackendKeyID != rcpt.BackendKeyID {
		t.Fatalf("unpinned: %+v", ev[0].Anchor)
	}

	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	if _, err := control.Append(ctl, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w,
		Anchor: &control.Anchor{Seq: 1, Hash: strings.Repeat("ff", 32), Kind: "tlog", BackendKind: "transparency-log", Backend: rcpt.Backend, Ref: rcpt.Ref, Proof: rcpt.Proof, BackendKeyID: rcpt.BackendKeyID}}); err != nil {
		t.Fatal(err)
	}
	res, _ = Timeline(logs, ctl, Filter{}, Options{})
	if ev = anchorEvents(t, res); len(ev) != 2 || ev[1].Anchor.Verdict != "mismatch" || !strings.HasPrefix(ev[1].Anchor.Cause, "the chain does not reproduce the recorded head at seq 1 (chain "+head.Hash) {
		t.Fatalf("structural mismatch needs no key: %+v", ev[1].Anchor)
	}

	calls := 0
	before := len(fake.Requests())
	pinned := Options{AnchorKey: func() (*ecdsa.PublicKey, error) { calls++; return fake.PublicKey(), nil }}
	res, _ = Timeline(logs, ctl, Filter{}, pinned)
	if ev = anchorEvents(t, res); ev[0].Anchor.Verdict != "verified" || ev[0].Anchor.Cause != "" || ev[1].Anchor.Verdict != "mismatch" {
		t.Fatalf("pinned: %+v %+v", ev[0].Anchor, ev[1].Anchor)
	}
	if calls != 1 || len(fake.Requests()) != before {
		t.Fatalf("key resolved %d time(s), %d request(s) made", calls, len(fake.Requests())-before)
	}
}

// TestTimelineTornControlAnchorsAreUnverifiable: a torn tail after a good
// anchor — source torn, exit 1, the anchor's facts present, verdict
// unverifiable with the torn cause, and the key never resolved.
func TestTimelineTornControlAnchorsAreUnverifiable(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	ctl, head, rcpt := anchoredLedger(t, stub)
	f, err := os.OpenFile(ctl, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"v":"control/1","seq":3,"partial`); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	calls := 0
	o := stubOptions(stub)
	o.AnchorKey = func() (*ecdsa.PublicKey, error) { calls++; return nil, nil }
	res, err := Timeline(t.TempDir(), ctl, Filter{}, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sources) != 1 || res.Sources[0].Integrity != "torn" || ExitCode(res) != 1 {
		t.Fatalf("%+v exit %d", res.Sources, ExitCode(res))
	}
	ev := anchorEvents(t, res)
	want := &Anchor{Seq: 1, Hash: head.Hash, Kind: "tlog", BackendKind: "rfc3161", Backend: anchortest.StubBackend, Ref: rcpt.Ref, Verdict: "unverifiable", Cause: causeTorn}
	if len(ev) != 1 || *ev[0].Anchor != *want {
		t.Fatalf("torn: %+v\nwant %+v", ev[0].Anchor, want)
	}
	if calls != 0 {
		t.Fatalf("the key was resolved %d time(s) on a torn chain", calls)
	}
}

// TestTimelineBrokenControlAnchorsAreUnverifiable: a well-formed record
// mid-file whose prev does not chain — source broken, the anchor in the
// valid prefix unverifiable with the broken cause (not the torn one).
func TestTimelineBrokenControlAnchorsAreUnverifiable(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	ctl, _, _ := anchoredLedger(t, stub)
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	if _, err := control.Append(ctl, control.Event{Action: "disable", Agent: "coder", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(ctl)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	var last map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &last); err != nil {
		t.Fatal(err)
	}
	last["prev"] = strings.Repeat("0", 64)
	raw, err := json.Marshal(last)
	if err != nil {
		t.Fatal(err)
	}
	lines[2] = string(raw)
	if err := os.WriteFile(ctl, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Timeline(t.TempDir(), ctl, Filter{}, stubOptions(stub))
	if err != nil {
		t.Fatal(err)
	}
	if res.Sources[0].Integrity != "broken" || ExitCode(res) != 1 {
		t.Fatalf("%+v exit %d", res.Sources, ExitCode(res))
	}
	if ev := anchorEvents(t, res); len(ev) != 1 || ev[0].Anchor.Verdict != "unverifiable" || ev[0].Anchor.Cause != causeBroken {
		t.Fatalf("broken: %+v", ev)
	}
}

// TestUnverifiableCauseSplitsThreeWays: torn, broken and unreadable never
// share a remedy (audit repair control fixes only a torn tail).
func TestUnverifiableCauseSplitsThreeWays(t *testing.T) {
	if unverifiableCause("torn") != causeTorn || unverifiableCause("broken") != causeBroken || unverifiableCause("error") != causeUnreadable {
		t.Fatal("the cause must follow the verdict word")
	}
	for _, c := range []string{causeTorn, causeBroken, causeUnreadable} {
		if !strings.HasPrefix(c, "control ledger ") || !strings.Contains(c, "no verdict") || !strings.Contains(c, "audit verify control") {
			t.Fatalf("cause %q", c)
		}
	}
	if !strings.Contains(causeTorn, "agenthof audit repair control") || strings.Contains(causeBroken, "run: agenthof audit repair control") || strings.Contains(causeUnreadable, "repair") {
		t.Fatal("only the torn cause may name the repair as the remedy")
	}
}

// TestTimelineCleansAnchorFactsNeverTheCause: control characters planted in
// backend and ref (Append does not clean them) are gone from the Record;
// the verdict's cause is carried as the backend produced it.
func TestTimelineCleansAnchorFactsNeverTheCause(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	ctl, head, rcpt := anchoredLedger(t, stub)
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	if _, err := control.Append(ctl, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w,
		Anchor: &control.Anchor{Seq: 1, Hash: head.Hash, Kind: "tlog", BackendKind: "rfc3161", Backend: anchortest.StubBackend + "\x07", Ref: rcpt.Ref + "\x1b[31m", Proof: rcpt.Proof}}); err != nil {
		t.Fatal(err)
	}
	res, err := Timeline(t.TempDir(), ctl, Filter{}, stubOptions(stub))
	if err != nil {
		t.Fatal(err)
	}
	ev := anchorEvents(t, res)
	if len(ev) != 2 || ev[1].Anchor.Backend != anchortest.StubBackend || ev[1].Anchor.Ref != rcpt.Ref+"[31m" {
		t.Fatalf("hostile facts: %+v", ev[1].Anchor)
	}
	if ev[1].Anchor.Verdict != "mismatch" || ev[1].Anchor.Cause != "proof does not hash to the recorded ref" {
		t.Fatalf("the stub judges the ref as recorded: %+v", ev[1].Anchor)
	}
	if b, _ := json.Marshal(ev); strings.ContainsAny(string(b), "\x07\x1b") || strings.Contains(string(b), `\u0007`) || strings.Contains(string(b), `\u001b`) {
		t.Fatalf("a control character reached the document: %s", b)
	}
}

// TestLoadControlUnchanged: the wrapper keeps its contract for its other
// callers — events, verdict, ok — and loadControl returns the same events
// plus the records.
func TestLoadControlUnchanged(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	ctl, _, _ := anchoredLedger(t, stub)
	events, verdict, ok := LoadControl(ctl)
	recs, events2, verdict2, ok2 := loadControl(ctl)
	if !ok || !ok2 || verdict != "verified" || verdict2 != verdict || len(events) != 2 || len(events2) != 2 || len(recs) != 2 {
		t.Fatalf("%v %v %q %q %d %d %d", ok, ok2, verdict, verdict2, len(events), len(events2), len(recs))
	}
	if _, verdict, ok := LoadControl(filepath.Join(t.TempDir(), "none.jsonl")); ok || verdict != "missing" {
		t.Fatalf("missing: %v %q", ok, verdict)
	}
}

// TestTimelineAnchorVerdictsAcrossASeal: an anchor whose covered head sits in
// a sealed segment still verifies once the ledger is sealed and has grown a
// continuation, and so does an anchor recorded in the continuation that
// covers the seal's own head — both with their global seqs.
func TestTimelineAnchorVerdictsAcrossASeal(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	ctl, head, _ := anchoredLedger(t, stub) // seq 1 apply, seq 2 anchor (covers seq 1)
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	res, err := control.SealActive(ctl, control.Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: w}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealHead := anchor.Head{Seq: res.HeadSeq, Hash: res.HeadHash}
	rcpt, err := stub.Submit(context.Background(), sealHead)
	if err != nil {
		t.Fatal(err)
	}
	payload := &control.Anchor{Seq: sealHead.Seq, Hash: sealHead.Hash, Kind: "tlog", BackendKind: stub.Kind(), Backend: rcpt.Backend, Ref: rcpt.Ref, Proof: rcpt.Proof, BackendKeyID: rcpt.BackendKeyID}
	if _, err := control.Append(ctl, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: payload}); err != nil {
		t.Fatal(err)
	}

	got, err := Timeline(t.TempDir(), ctl, Filter{}, stubOptions(stub))
	if err != nil {
		t.Fatal(err)
	}
	ev := anchorEvents(t, got)
	if len(ev) != 2 {
		t.Fatalf("anchor events: %+v", ev)
	}
	if a := ev[0].Anchor; ev[0].Seq != 2 || a.Seq != 1 || a.Hash != head.Hash || a.Verdict != "verified" {
		t.Fatalf("anchor over a sealed head: seq %d %+v", ev[0].Seq, a)
	}
	if a := ev[1].Anchor; ev[1].Seq != 4 || a.Seq != 3 || a.Hash != sealHead.Hash || a.Verdict != "verified" {
		t.Fatalf("anchor over the seal head, in the continuation: seq %d %+v", ev[1].Seq, a)
	}
	if got.Sources[len(got.Sources)-1].Integrity != "verified" {
		t.Fatalf("%+v", got.Sources)
	}
}

// appendRunScopedAnchor appends a run-scoped success anchor (no proof; its seq
// is a run position, well past the control count) and returns its payload.
func appendRunScopedAnchor(t *testing.T, ctl string) *control.Anchor {
	t.Helper()
	a := &control.Anchor{RunID: "r-0123456789abcdef", Seq: 7, Hash: strings.Repeat("ab", 32), Kind: "tlog", BackendKind: "rfc3161", Backend: anchortest.StubBackend, Ref: "run-ref"}
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	if _, err := control.Append(ctl, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: a}); err != nil {
		t.Fatal(err)
	}
	return a
}

// TestInvestigateViewCarriesRunIDAndNoVerdictForARunScopedAnchor: a run-scoped
// anchor record shows the run, the run position, hash and ref, but is never
// judged against the control chain — no verdict, no cause — and the anchors:
// trailer counts only the control-scoped verdicts.
func TestInvestigateViewCarriesRunIDAndNoVerdictForARunScopedAnchor(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	ctl, _, _ := anchoredLedger(t, stub)
	a := appendRunScopedAnchor(t, ctl)

	res, err := Timeline(t.TempDir(), ctl, Filter{}, stubOptions(stub))
	if err != nil {
		t.Fatal(err)
	}
	var run *Record
	for i := range res.Events {
		if e := res.Events[i]; e.Anchor != nil && e.Anchor.RunID != "" {
			run = &res.Events[i]
		}
	}
	if run == nil || run.Anchor.RunID != a.RunID || run.Anchor.Seq != 7 || run.Anchor.Hash != a.Hash || run.Anchor.Ref != "run-ref" || run.Anchor.Verdict != "" || run.Anchor.Cause != "" {
		t.Fatalf("run-scoped view: %+v", run)
	}
	if ExitCode(res) != 0 {
		t.Fatalf("exit %d", ExitCode(res))
	}

	js, err := RenderJSON(res, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Events []struct {
			Anchor map[string]any `json:"anchor"`
		} `json:"events"`
	}
	if err := json.Unmarshal([]byte(js), &doc); err != nil {
		t.Fatal(err)
	}
	var found map[string]any
	for _, e := range doc.Events {
		if e.Anchor != nil && e.Anchor["run_id"] == a.RunID {
			found = e.Anchor
		}
	}
	if found == nil {
		t.Fatalf("no run_id in the JSON: %s", js)
	}
	for _, k := range []string{"run_id", "seq", "hash", "ref"} {
		if _, ok := found[k]; !ok {
			t.Fatalf("anchor object lacks %q: %v", k, found)
		}
	}
	for _, k := range []string{"verdict", "cause"} {
		if _, ok := found[k]; ok {
			t.Fatalf("a run-scoped anchor must carry no %q: %v", k, found)
		}
	}

	txt := RenderText(res)
	var line string
	for _, l := range strings.Split(txt, "\n") {
		if strings.Contains(l, "run="+a.RunID) {
			line = l
		}
	}
	if line == "" || !strings.Contains(line, "run="+a.RunID+" anchor=7:"+a.Hash) || strings.Contains(line, "verdict=") {
		t.Fatalf("text line %q in:\n%s", line, txt)
	}
	if !strings.Contains(txt, "anchors: 1 (1 verified, 0 mismatch, 0 unverifiable)\n") {
		t.Fatalf("the trailer counts only control-scoped verdicts:\n%s", txt)
	}
}

// TestTimelineSkipsRunScopedAnchorsOnATornChain: on a torn chain the
// non-valid-chain enumerator would hand every success anchor record a
// control-chain cause; a run-scoped one is not about the control chain and
// gets no verdict, while the control anchor still gets the torn cause.
func TestTimelineSkipsRunScopedAnchorsOnATornChain(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	ctl, _, _ := anchoredLedger(t, stub)
	a := appendRunScopedAnchor(t, ctl)
	f, err := os.OpenFile(ctl, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"v":"control/1","seq":4,"partial`); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	res, err := Timeline(t.TempDir(), ctl, Filter{}, stubOptions(stub))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sources) != 1 || res.Sources[0].Integrity != "torn" {
		t.Fatalf("%+v", res.Sources)
	}
	var ctlN, runN int
	for _, e := range res.Events {
		switch {
		case e.Anchor == nil:
		case e.Anchor.RunID == a.RunID:
			runN++
			if e.Anchor.Verdict != "" || e.Anchor.Cause != "" {
				t.Fatalf("a run-scoped anchor got a control-chain verdict: %+v", e.Anchor)
			}
		default:
			ctlN++
			if e.Anchor.Verdict != "unverifiable" || e.Anchor.Cause != causeTorn {
				t.Fatalf("control anchor: %+v", e.Anchor)
			}
		}
	}
	if runN != 1 || ctlN != 1 {
		t.Fatalf("run=%d control=%d", runN, ctlN)
	}
}
