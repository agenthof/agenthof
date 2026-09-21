package control_test

import (
	"path/filepath"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

func TestDecodeRoundTripsSeqAndTime(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.jsonl")
	inv := identity.Static("dana@example.com")
	if _, err := control.Append(p, control.Event{Action: "apply", Outcome: "success",
		Invoker: inv, Witness: control.CaptureWitness(), ConfigHash: "sha256:abc"}); err != nil {
		t.Fatal(err)
	}
	recs, _, _ := ledger.ReadVerify(p, ledger.Locked)
	d, err := control.Decode(recs[0].Raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.Seq != 1 {
		t.Fatalf("seq=%d", d.Seq)
	}
	if d.Action != "apply" || d.Outcome != "success" {
		t.Fatalf("%+v", d)
	}
	if d.ConfigHash != "sha256:abc" {
		t.Fatalf("hash=%q", d.ConfigHash)
	}
	if d.Invoker.Subject != "dana@example.com" {
		t.Fatalf("inv=%+v", d.Invoker)
	}
	if d.Time.IsZero() {
		t.Fatal("time not decoded")
	}
}
