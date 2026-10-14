package anchorverify_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/anchor/anchortest"
	"github.com/agenthof/agenthof/internal/anchorverify"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// newLedger returns a fresh control ledger with one apply record, its head,
// and the invoker/witness every append below uses.
func newLedger(t *testing.T) (string, ledger.Head, identity.Invoker, control.Witness) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "control.jsonl")
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	head, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc"})
	if err != nil {
		t.Fatal(err)
	}
	return p, head, inv, w
}

// appendAnchor appends a success anchor record for be's receipt over head.
func appendAnchor(t *testing.T, p string, inv identity.Invoker, w control.Witness, be anchor.Backend, head ledger.Head) anchor.Receipt {
	t.Helper()
	rcpt, err := be.Submit(context.Background(), anchor.Head{Seq: head.Count, Hash: head.Hash})
	if err != nil {
		t.Fatal(err)
	}
	payload := &control.Anchor{Seq: head.Count, Hash: head.Hash, Kind: "tlog", BackendKind: be.Kind(), Backend: rcpt.Backend, Ref: rcpt.Ref, Proof: rcpt.Proof, BackendKeyID: rcpt.BackendKeyID}
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: payload}); err != nil {
		t.Fatal(err)
	}
	return rcpt
}

// appendWrongAnchor appends a success anchor whose recorded hash the chain
// does not reproduce — a valid hex value Append admits and CheckAnchors
// refuses — and returns the cause CheckAnchors will give.
func appendWrongAnchor(t *testing.T, p string, inv identity.Invoker, w control.Witness, head ledger.Head) string {
	t.Helper()
	wrong := strings.Repeat("ff", 32)
	a := &control.Anchor{Seq: head.Count, Hash: wrong, Kind: "tlog", BackendKind: "rfc3161", Backend: anchortest.StubBackend, Ref: strings.Repeat("0", 64), Proof: "AQID"}
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: a}); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("the chain does not reproduce the recorded head at seq %d (chain %s, recorded %s)", head.Count, head.Hash, wrong)
}

func records(t *testing.T, p string) []ledger.Record {
	t.Helper()
	recs, _, err := ledger.ReadVerify(p, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// planted is a hand-built success anchor record with no payload — the shape
// Append refuses and a hostile writer can plant — appended to a records
// slice (never to disk; CheckAnchors reads records only).
func planted(seq int) ledger.Record {
	raw := fmt.Sprintf(`{"v":"control/1","seq":%d,"time":"2026-10-14T06:00:00Z","action":"anchor","outcome":"success","invoker":{"subject":"forger","issuer":"local","method":"asserted"},"witness":{"os_user":"forger","hostname":"elsewhere"},"prev":""}`, seq)
	return ledger.Record{Raw: []byte(raw)}
}

func stubFactory(stub *anchortest.Stub) anchorverify.Factory {
	return func(string, string, *ecdsa.PublicKey, bool) (anchor.Backend, error) { return stub, nil }
}

// brokenBackend breaks the Backend contract: a plain error from Verify.
type brokenBackend struct{ err error }

func (brokenBackend) Kind() string { return "rfc3161" }
func (brokenBackend) Submit(context.Context, anchor.Head) (anchor.Receipt, error) {
	return anchor.Receipt{}, nil
}
func (b brokenBackend) Verify(context.Context, anchor.Head, anchor.Receipt) error { return b.err }

func one(t *testing.T, results []anchorverify.Result) anchorverify.Result {
	t.Helper()
	if len(results) != 1 {
		t.Fatalf("want one result, got %d: %+v", len(results), results)
	}
	return results[0]
}

// TestVerifyLadderNeverFolds: each rung of the ladder gives its state and its
// exact cause; mismatch and unverifiable never fold into each other; one
// Result per success record, in chain order; failed and refused records are
// skipped; a wrapped typed verdict keeps its classification.
func TestVerifyLadderNeverFolds(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	p, head, inv, w := newLedger(t)
	appendAnchor(t, p, inv, w, stub, head)
	if r := one(t, anchorverify.Verify(records(t, p), anchorverify.Options{Factory: stubFactory(stub), Offline: true})); r.State != anchorverify.StateVerified || r.Cause != "" || r.Check.RecordSeq != 2 || r.Check.Anchor == nil {
		t.Fatalf("good: %+v", r)
	}

	// structural: the chain does not reproduce the recorded head
	wantCause := appendWrongAnchor(t, p, inv, w, head)
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "error", Reason: &control.Reason{Code: control.CodeAnchorFailed, Message: "status 503 from log.example"}, Invoker: inv, Witness: w, Anchor: &control.Anchor{Seq: 1, Hash: head.Hash, Kind: "tlog"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "refused", Reason: control.NotAuthorized("anchor"), Invoker: inv, Witness: w}); err != nil {
		t.Fatal(err)
	}
	recs := append(records(t, p), planted(6))
	results := anchorverify.Verify(recs, anchorverify.Options{Factory: stubFactory(stub), Offline: true})
	if len(results) != 3 {
		t.Fatalf("want 3 results (two real successes, one planted; error and refused skipped), got %d: %+v", len(results), results)
	}
	if results[0].State != anchorverify.StateVerified {
		t.Fatalf("[0]: %+v", results[0])
	}
	if results[1].State != anchorverify.StateMismatch || results[1].Cause != wantCause || results[1].Check.Mismatch != wantCause {
		t.Fatalf("[1]: %+v", results[1])
	}
	if results[2].State != anchorverify.StateMismatch || results[2].Cause != "anchor record without coverage" || results[2].Check.Anchor != nil || results[2].Check.RecordSeq != 6 {
		t.Fatalf("[2]: %+v", results[2])
	}

	// the backend's verdicts, on a ledger with one good anchor
	p2, head2, inv2, w2 := newLedger(t)
	stub2 := anchortest.NewStub([]byte("s2"))
	appendAnchor(t, p2, inv2, w2, stub2, head2)
	recs2 := records(t, p2)
	refuse := func(kind, url string, _ *ecdsa.PublicKey, _ bool) (anchor.Backend, error) {
		return nil, fmt.Errorf("anchor backend kind %q is not implemented", kind)
	}
	if r := one(t, anchorverify.Verify(recs2, anchorverify.Options{Factory: refuse, Offline: true})); r.State != anchorverify.StateUnverifiable || r.Cause != `anchor backend kind "rfc3161" is not implemented` {
		t.Fatalf("factory refuses: %+v", r)
	}
	stub2.Deny()
	if r := one(t, anchorverify.Verify(recs2, anchorverify.Options{Factory: stubFactory(stub2), Offline: true})); r.State != anchorverify.StateMismatch || r.Cause != "stub: denied" {
		t.Fatalf("Deny: %+v", r)
	}
	stub2.Fail()
	if r := one(t, anchorverify.Verify(recs2, anchorverify.Options{Factory: stubFactory(stub2), Offline: true})); r.State != anchorverify.StateUnverifiable || r.Cause != "stub: unavailable" {
		t.Fatalf("Fail: %+v", r)
	}
	plain := func(string, string, *ecdsa.PublicKey, bool) (anchor.Backend, error) {
		return brokenBackend{err: errors.New("boom")}, nil
	}
	if r := one(t, anchorverify.Verify(recs2, anchorverify.Options{Factory: plain, Offline: true})); r.State != anchorverify.StateUnverifiable || r.Cause != "boom" {
		t.Fatalf("plain error: %+v", r)
	}
	wrapped := func(string, string, *ecdsa.PublicKey, bool) (anchor.Backend, error) {
		return brokenBackend{err: fmt.Errorf("rekor: %w", &anchor.Mismatch{Cause: "token covers another head"})}, nil
	}
	if r := one(t, anchorverify.Verify(recs2, anchorverify.Options{Factory: wrapped, Offline: true})); r.State != anchorverify.StateMismatch || r.Cause != "token covers another head" {
		t.Fatalf("wrapped Mismatch must still classify as mismatch: %+v", r)
	}
}

// TestVerifyResolvesTheKeyOnceIffNeeded: 0 calls on a chain without anchors
// (and nil results), 1 call on a chain with three — even when all three are
// structural mismatches; a resolve error makes every structurally sound
// anchor unverifiable with that error as its cause.
func TestVerifyResolvesTheKeyOnceIffNeeded(t *testing.T) {
	p, head, inv, w := newLedger(t)
	calls := 0
	count := func() (*ecdsa.PublicKey, error) { calls++; return nil, nil }
	if res := anchorverify.Verify(records(t, p), anchorverify.Options{ResolveKey: count}); res != nil || calls != 0 {
		t.Fatalf("no anchors: %v calls=%d", res, calls)
	}
	for i := 0; i < 3; i++ {
		appendWrongAnchor(t, p, inv, w, head)
	}
	res := anchorverify.Verify(records(t, p), anchorverify.Options{ResolveKey: count})
	if len(res) != 3 || calls != 1 {
		t.Fatalf("three structural mismatches: %d results, %d calls", len(res), calls)
	}
	for _, r := range res {
		if r.State != anchorverify.StateMismatch {
			t.Fatalf("%+v", r)
		}
	}

	stub := anchortest.NewStub([]byte("s"))
	p2, head2, inv2, w2 := newLedger(t)
	appendAnchor(t, p2, inv2, w2, stub, head2)
	failing := func() (*ecdsa.PublicKey, error) {
		return nil, errors.New("pinned log key /x/anchor.pub: not a PEM PUBLIC KEY block")
	}
	if r := one(t, anchorverify.Verify(records(t, p2), anchorverify.Options{ResolveKey: failing, Factory: stubFactory(stub), Offline: true})); r.State != anchorverify.StateUnverifiable || r.Cause != "pinned log key /x/anchor.pub: not a PEM PUBLIC KEY block" {
		t.Fatalf("resolve error: %+v", r)
	}
}

// TestVerifyNoKeyIsTheBackendsRuling: the helper never rules on key == nil.
// The stub verifies keyless; Default's Rekor, unpinned and offline, says "no
// key to verify under" — pinned and offline it verifies from the stored proof
// and sends nothing.
func TestVerifyNoKeyIsTheBackendsRuling(t *testing.T) {
	stub := anchortest.NewStub([]byte("s"))
	p, head, inv, w := newLedger(t)
	appendAnchor(t, p, inv, w, stub, head)
	if r := one(t, anchorverify.Verify(records(t, p), anchorverify.Options{Factory: stubFactory(stub), Offline: true})); r.State != anchorverify.StateVerified {
		t.Fatalf("keyless stub: %+v", r)
	}

	fake := anchortest.NewRekorV1()
	t.Cleanup(fake.Close)
	rk, err := anchor.NewRekor(fake.URL, anchor.RekorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p2, head2, inv2, w2 := newLedger(t)
	appendAnchor(t, p2, inv2, w2, rk, head2)
	recs := records(t, p2)
	if r := one(t, anchorverify.Verify(recs, anchorverify.Options{Offline: true})); r.State != anchorverify.StateUnverifiable || r.Cause != "no key to verify under (unpinned, offline)" {
		t.Fatalf("unpinned offline under Default: %+v", r)
	}
	before := len(fake.Requests())
	pin := func() (*ecdsa.PublicKey, error) { return fake.PublicKey(), nil }
	if r := one(t, anchorverify.Verify(recs, anchorverify.Options{ResolveKey: pin, Offline: true})); r.State != anchorverify.StateVerified || r.Cause != "" {
		t.Fatalf("pinned offline under Default: %+v", r)
	}
	if after := len(fake.Requests()); after != before {
		t.Fatalf("offline verify made %d request(s)", after-before)
	}
}

// TestDefaultDispatch: transparency-log builds a *anchor.Rekor; any other
// kind is "not implemented" (the exact text the CLI's own dispatch returns).
func TestDefaultDispatch(t *testing.T) {
	be, err := anchorverify.Default("transparency-log", "https://rekor.sigstore.dev/", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := be.(*anchor.Rekor); !ok || be.Kind() != "transparency-log" {
		t.Fatalf("%T %q", be, be.Kind())
	}
	for _, kind := range []string{"rfc3161", "kms", ""} {
		if _, err := anchorverify.Default(kind, "https://x.example", nil, true); err == nil || err.Error() != fmt.Sprintf("anchor backend kind %q is not implemented", kind) {
			t.Fatalf("%q: %v", kind, err)
		}
	}
	if _, err := anchorverify.Default("transparency-log", "rekor.sigstore.dev", nil, true); err == nil {
		t.Fatal("a non-absolute URL must be refused at construction")
	}
}
