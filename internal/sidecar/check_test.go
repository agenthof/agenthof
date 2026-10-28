package sidecar_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/anchor/anchortest"
	"github.com/agenthof/agenthof/internal/anchorverify"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/sidecar"
)

func hashOf(r ledger.Record) string {
	sum := sha256.Sum256(r.Raw)
	return hex.EncodeToString(sum[:])
}

func finishedRun(t *testing.T, dir, id string) []ledger.Record {
	t.Helper()
	return writeRun(t, dir, id, engine.Event{Type: "workflow_started"}, engine.Event{Type: "step_started"}, engine.Event{Type: "workflow_finished", Status: "succeeded"})
}

// headRecord is a sidecar record over chain's final event, with a stub proof.
func headRecord(t *testing.T, stub *anchortest.Stub, id string, chain []ledger.Record) sidecar.Record {
	t.Helper()
	h := hashOf(chain[len(chain)-1])
	rcpt, err := stub.Submit(t.Context(), anchor.Head{Seq: len(chain), Hash: h})
	if err != nil {
		t.Fatal(err)
	}
	return sidecar.Record{RunID: id, Seq: len(chain), Hash: h, Kind: "tlog", BackendKind: stub.Kind(), Backend: rcpt.Backend, Ref: rcpt.Ref, Proof: rcpt.Proof, BackendKeyID: rcpt.BackendKeyID}
}

func stubOpts(stub *anchortest.Stub) anchorverify.Options {
	return anchorverify.Options{Offline: true, Factory: func(string, string, *ecdsa.PublicKey, bool) (anchor.Backend, error) { return stub, nil }}
}

func oneCheck(t *testing.T, id string, chain []ledger.Record, r sidecar.Record) control.AnchorCheck {
	t.Helper()
	cs := sidecar.Check(id, chain, []sidecar.Record{r})
	if len(cs) != 1 || cs[0].RecordSeq != 1 || cs[0].Anchor == nil {
		t.Fatalf("checks = %+v", cs)
	}
	return cs[0]
}

func TestCheckVerifiedRecordThroughTheLadder(t *testing.T) {
	dir := t.TempDir()
	stub := anchortest.NewStub([]byte("s"))
	chain := finishedRun(t, dir, testRun)
	r := headRecord(t, stub, testRun, chain)
	if err := sidecar.Append(sidecar.Path(dir, testRun), testRun, r); err != nil {
		t.Fatal(err)
	}
	v := sidecar.Verify(dir, testRun, chain, stubOpts(stub))
	if !v.Found || v.Err != nil || len(v.Results) != 1 || v.Results[0].State != anchorverify.StateVerified || v.State() != sidecar.StateVerified {
		t.Fatalf("%+v state=%s", v, v.State())
	}
	c := v.Results[0].Check
	if c.Anchor.RunID != testRun || c.Anchor.Seq != len(chain) || c.Anchor.Proof != r.Proof {
		t.Fatalf("check anchor = %+v", c.Anchor)
	}
}

func TestVerifyNotFoundAndReadError(t *testing.T) {
	dir := t.TempDir()
	chain := finishedRun(t, dir, testRun)
	if v := sidecar.Verify(dir, testRun, chain, anchorverify.Options{}); v.Found || v.State() != sidecar.StateNotAnchored {
		t.Fatalf("%+v", v)
	}
	writeAt := sidecar.Path(dir, testRun)
	if err := sidecarWrite(writeAt, "not json\n"); err != nil {
		t.Fatal(err)
	}
	if v := sidecar.Verify(dir, testRun, chain, anchorverify.Options{}); !v.Found || v.Err == nil || len(v.Results) != 0 || v.State() != sidecar.StateUnverifiable {
		t.Fatalf("%+v", v)
	}
}

func mismatchCause(t *testing.T, c control.AnchorCheck, wantSub string) {
	t.Helper()
	if c.Mismatch == "" || !strings.Contains(c.Mismatch, wantSub) {
		t.Fatalf("Mismatch = %q, want it to contain %q", c.Mismatch, wantSub)
	}
}

func TestCheckWrongRunIDIsMismatch(t *testing.T) {
	chain := finishedRun(t, t.TempDir(), testRun)
	r := headRecord(t, anchortest.NewStub([]byte("s")), testRun, chain)
	r.RunID = "r-ffffffffffffffff"
	c := oneCheck(t, testRun, chain, r)
	if c.Mismatch != "sidecar record names another run" {
		t.Fatalf("Mismatch = %q", c.Mismatch)
	}
}

func TestCheckBadHashIsMismatch(t *testing.T) {
	chain := finishedRun(t, t.TempDir(), testRun)
	r := headRecord(t, anchortest.NewStub([]byte("s")), testRun, chain)
	r.Hash = strings.ToUpper(r.Hash)
	if c := oneCheck(t, testRun, chain, r); c.Mismatch != "anchor hash is not a lowercase hex sha256" {
		t.Fatalf("Mismatch = %q", c.Mismatch)
	}
}

func TestCheckWrongSeqIsMismatch(t *testing.T) {
	chain := finishedRun(t, t.TempDir(), testRun)
	r := headRecord(t, anchortest.NewStub([]byte("s")), testRun, chain)
	r.Seq = len(chain) - 1
	mismatchCause(t, oneCheck(t, testRun, chain, r), "anchor covers event 2 but the ledger has 3 events")
}

func TestCheckRefusesSeqBeyondChain(t *testing.T) {
	chain := finishedRun(t, t.TempDir(), testRun)
	r := headRecord(t, anchortest.NewStub([]byte("s")), testRun, chain)
	r.Seq = len(chain) + 1
	if c := oneCheck(t, testRun, chain, r); c.Mismatch != "anchor covers event 4 but the ledger has 3 events" {
		t.Fatalf("Mismatch = %q", c.Mismatch)
	}
	r.Seq = 0
	mismatchCause(t, oneCheck(t, testRun, chain, r), "anchor covers event 0 but the ledger has 3 events")
	r.Seq = -1
	mismatchCause(t, oneCheck(t, testRun, chain, r), "anchor covers event -1")
}

func TestCheckOnEmptyChainIsMismatch(t *testing.T) {
	r := rec(1)
	r.Hash = strings.Repeat("ab", 32)
	for _, chain := range [][]ledger.Record{nil, {}} {
		if c := oneCheck(t, testRun, chain, r); c.Mismatch != "anchor covers event 1 but the ledger has 0 events" {
			t.Fatalf("Mismatch = %q", c.Mismatch)
		}
	}
	// and through the ladder: never verified.
	stub := anchortest.NewStub([]byte("s"))
	res := anchorverify.Decide(sidecar.Check(testRun, nil, []sidecar.Record{r}), stubOpts(stub))
	if len(res) != 1 || res[0].State != anchorverify.StateMismatch {
		t.Fatalf("%+v", res)
	}
}

func TestCheckWrongHashIsMismatch(t *testing.T) {
	dir := t.TempDir()
	stub := anchortest.NewStub([]byte("s"))
	chain := finishedRun(t, dir, testRun)
	r := headRecord(t, stub, testRun, chain)
	// the ledger was reforged after anchoring: same length, different tail
	forged := append([]ledger.Record{}, chain...)
	forged[len(forged)-1] = ledger.Record{Raw: []byte(`{"type":"workflow_finished","status":"failed"}`)}
	c := oneCheck(t, testRun, forged, r)
	want := "the ledger does not reproduce the anchored head at event 3 (ledger " + hashOf(forged[2]) + ", recorded " + r.Hash + ")"
	if c.Mismatch != want {
		t.Fatalf("Mismatch = %q\nwant       %q", c.Mismatch, want)
	}
	res := anchorverify.Decide([]control.AnchorCheck{c}, stubOpts(stub))
	if res[0].State != anchorverify.StateMismatch {
		t.Fatalf("%+v", res[0])
	}
}

func TestCheckNonTerminalAtSeqIsMismatch(t *testing.T) {
	chain := finishedRun(t, t.TempDir(), testRun)
	cut := chain[:2] // before the terminal event
	r := headRecord(t, anchortest.NewStub([]byte("s")), testRun, cut)
	if c := oneCheck(t, testRun, cut, r); c.Mismatch != "the anchored event is not the run's final event" {
		t.Fatalf("Mismatch = %q", c.Mismatch)
	}
}

func TestCheckRunRefusedAloneIsFinal(t *testing.T) {
	chain := writeRun(t, t.TempDir(), testRun, engine.Event{Type: "run_refused", Reason: "no"})
	r := headRecord(t, anchortest.NewStub([]byte("s")), testRun, chain)
	if c := oneCheck(t, testRun, chain, r); c.Mismatch != "" {
		t.Fatalf("Mismatch = %q", c.Mismatch)
	}
}

func TestCheckOneCheckPerRecordInOrder(t *testing.T) {
	chain := finishedRun(t, t.TempDir(), testRun)
	good := headRecord(t, anchortest.NewStub([]byte("s")), testRun, chain)
	bad := good
	bad.RunID = "r-ffffffffffffffff"
	cs := sidecar.Check(testRun, chain, []sidecar.Record{bad, good})
	if len(cs) != 2 || cs[0].RecordSeq != 1 || cs[1].RecordSeq != 2 || cs[0].Mismatch == "" || cs[1].Mismatch != "" {
		t.Fatalf("%+v", cs)
	}
	if sidecar.Check(testRun, chain, nil) != nil {
		t.Fatal("no records must yield no checks")
	}
}

func TestVerdictState(t *testing.T) {
	res := func(states ...anchorverify.State) []anchorverify.Result {
		var out []anchorverify.Result
		for _, s := range states {
			out = append(out, anchorverify.Result{State: s})
		}
		return out
	}
	V, M, U := anchorverify.StateVerified, anchorverify.StateMismatch, anchorverify.StateUnverifiable
	cases := []struct {
		name string
		v    sidecar.Verdict
		want string
	}{
		{"not found", sidecar.Verdict{}, sidecar.StateNotAnchored},
		{"read error", sidecar.Verdict{Found: true, Err: errors.New("x")}, sidecar.StateUnverifiable},
		{"found but no evidence", sidecar.Verdict{Found: true}, sidecar.StateUnverifiable},
		{"all verified", sidecar.Verdict{Found: true, Results: res(V, V)}, sidecar.StateVerified},
		{"one unverifiable", sidecar.Verdict{Found: true, Results: res(V, U)}, sidecar.StateUnverifiable},
		{"mismatch beats unverifiable", sidecar.Verdict{Found: true, Results: res(U, M, V)}, sidecar.StateMismatch},
	}
	for _, c := range cases {
		if got := c.v.State(); got != c.want {
			t.Errorf("%s: State() = %q, want %q", c.name, got, c.want)
		}
	}
}

func sidecarWrite(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }

func TestCheckZeroSeqOnEmptyChainDoesNotPanic(t *testing.T) {
	r := rec(0)
	if c := oneCheck(t, testRun, nil, r); c.Mismatch != "anchor covers event 0 but the ledger has 0 events" {
		t.Fatalf("Mismatch = %q", c.Mismatch)
	}
}
