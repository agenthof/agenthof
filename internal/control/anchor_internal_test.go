package control

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRecordWireOrderPutsAnchorBetweenDetailAndPrev: the additive field sits
// after detail and before prev when present (the first anchoring writer will
// marshal exactly this record), and detail…prev stay adjacent when absent —
// so no record written today changes by a byte.
func TestRecordWireOrderPutsAnchorBetweenDetailAndPrev(t *testing.T) {
	with, err := json.Marshal(record{V: "control/1", Seq: 2, Action: "anchor", Outcome: "success", Detail: "d",
		Anchor: &Anchor{Seq: 1, Hash: "h", Kind: "tlog", Ref: "12345"}, Prev: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `"detail":"d","anchor":{"seq":1,"hash":"h","kind":"tlog","ref":"12345"},"prev":"p"`; !strings.Contains(string(with), want) {
		t.Fatalf("wire order:\n%s\nwant substring %s", with, want)
	}
	without, err := json.Marshal(record{V: "control/1", Seq: 1, Action: "prune", Outcome: "success", Detail: "d", Prev: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `"detail":"d","prev":"p"`; !strings.Contains(string(without), want) || strings.Contains(string(without), "anchor") {
		t.Fatalf("absent anchor must be byte-absent:\n%s", without)
	}
}
