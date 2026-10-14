package control_test

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// TestCheckAnchors: a correct anchor passes; a recorded hash the chain does
// not reproduce, a seq at or after the record, and a success without a
// payload are mismatches with their fixed causes; a failed anchor and a
// refused anchor are skipped, not checked; the function takes only records.
func TestCheckAnchors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	inv, w := identity.Static("dana@example.com"), control.CaptureWitness()
	head, err := control.Append(p, control.Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:abc"})
	if err != nil {
		t.Fatal(err)
	}
	good := &control.Anchor{Seq: 1, Hash: head.Hash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://rekor.sigstore.dev", Ref: strings.Repeat("0", 80), Proof: "AQID"}
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: good}); err != nil {
		t.Fatal(err)
	}
	wrong := *good
	wrong.Hash = strings.Repeat("ff", 32)
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: &wrong}); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "error", Reason: &control.Reason{Code: control.CodeAnchorFailed, Message: "status 501 from rekor.test"}, Invoker: inv, Witness: w, Anchor: &control.Anchor{Seq: 3, Hash: strings.Repeat("ee", 32), Kind: "tlog"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "refused", Reason: control.NotAuthorized("anchor"), Invoker: inv, Witness: w}); err != nil {
		t.Fatal(err)
	}
	recs, _, err := ledger.ReadVerify(p, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	// Hand-built shapes Append refuses but a hostile writer could plant: a
	// success without coverage and a seq that is not before its record.
	recs = append(recs, recAnchor(6, "success", "", ""), recAnchor(7, "success", "", `{"seq":7,"hash":"`+head.Hash+`","kind":"tlog"}`))

	got := control.CheckAnchors(recs)
	if len(got) != 4 {
		t.Fatalf("want 4 checks (two real successes, two planted), got %d: %+v", len(got), got)
	}
	sum := sha256.Sum256(recs[0].Raw)
	if got[0].RecordSeq != 2 || got[0].Mismatch != "" || got[0].Anchor.Seq != 1 || hex.EncodeToString(sum[:]) != head.Hash {
		t.Fatalf("good: %+v", got[0])
	}
	if want := "the chain does not reproduce the recorded head at seq 1 (chain " + head.Hash + ", recorded " + strings.Repeat("ff", 32) + ")"; got[1].RecordSeq != 3 || got[1].Mismatch != want {
		t.Fatalf("wrong hash: %+v", got[1])
	}
	if got[2].RecordSeq != 6 || got[2].Anchor != nil || got[2].Mismatch != "anchor record without coverage" {
		t.Fatalf("no payload: %+v", got[2])
	}
	if got[3].RecordSeq != 7 || got[3].Mismatch != "anchor covers seq 7, which is not before the record (seq 7)" {
		t.Fatalf("seq not before: %+v", got[3])
	}
	if len(control.CheckAnchors(nil)) != 0 || len(control.CheckAnchors(recs[:1])) != 0 {
		t.Fatal("no anchors → no checks")
	}
}
