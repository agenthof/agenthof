package control_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// rec builds a hand-crafted control/1 wire record (Task 8's Render reads
// records straight off ledger.ReadVerify's raw bytes, so tests build that
// exact wire shape rather than going through Append/a real chain).
func rec(seq int, action, agent, outcome, subject, method string) ledger.Record {
	agentField := ""
	if agent != "" {
		agentField = fmt.Sprintf(`"agent":%q,`, agent)
	}
	raw := fmt.Sprintf(
		`{"v":"control/1","seq":%d,"time":"2026-09-21T10:%02d:00Z",`+
			`"action":%q,%s"outcome":%q,`+
			`"invoker":{"subject":%q,"issuer":"local","method":%q},`+
			`"witness":{"os_user":"dana","hostname":"host"},"prev":""}`,
		seq, seq, action, agentField, outcome, subject, method,
	)
	return ledger.Record{Raw: []byte(raw)}
}

// TestControlRenderTaint covers the brief's Step 1 (task-8-brief.md): two
// clean records plus a repair record must render TAINTED at the first
// repair record's seq, and the apply record's derived label must appear.
func TestControlRenderTaint(t *testing.T) {
	recs := []ledger.Record{
		rec(1, "apply", "", "success", "dana@example.com", "static"),
		rec(2, "disable", "coder", "success", "dana@example.com", "static"),
		rec(3, "repair", "", "success", "dana@example.com", "static"),
	}
	head := ledger.Head{Hash: "deadbeef", Count: 3}
	out := control.Render(recs, head, nil)
	if !strings.Contains(out, "TAINTED (repaired at seq 3)") {
		t.Fatalf("missing taint line:\n%s", out)
	}
	if !strings.Contains(out, "config applied") {
		t.Fatalf("missing label:\n%s", out)
	}
}

// TestControlRenderLabelsAndInvoker covers the per-action derived labels
// and the "<subject> (<method>)" invoker rendering for every action/outcome
// combination named in the brief.
func TestControlRenderLabelsAndInvoker(t *testing.T) {
	recs := []ledger.Record{
		rec(1, "apply", "", "success", "dana@example.com", "static"),
		rec(2, "apply", "", "rejected", "dana@example.com", "static"),
		rec(3, "apply", "", "error", "dana@example.com", "static"),
		rec(4, "apply", "", "refused", "dana@example.com", "static"),
		rec(5, "enable", "coder", "success", "dana@example.com", "asserted"),
		rec(6, "disable", "coder", "success", "dana@example.com", "asserted"),
	}
	head := ledger.Head{Hash: "abc123", Count: 6}
	out := control.Render(recs, head, nil)
	for _, want := range []string{
		"config applied", "config rejected", "config apply error", "config apply refused",
		"enabled agent coder", "disabled agent coder",
		"dana@example.com (static)", "dana@example.com (asserted)",
		"control ledger integrity: verified (6 events)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
}

// TestControlRenderTorn covers the TORN integrity line, and that a torn
// chain still renders the recovered valid prefix (not just the failure).
func TestControlRenderTorn(t *testing.T) {
	recs := []ledger.Record{
		rec(1, "apply", "", "success", "dana@example.com", "static"),
	}
	head := ledger.Head{Hash: "abc", Count: 1}
	verr := &ledger.TornError{Offset: 42}
	out := control.Render(recs, head, verr)
	if !strings.Contains(out, "TORN — last record incomplete") {
		t.Fatalf("missing TORN line:\n%s", out)
	}
	if !strings.Contains(out, "config applied") {
		t.Fatalf("torn render must still show the valid prefix:\n%s", out)
	}
}

// TestControlRenderBroken covers the BROKEN integrity line.
func TestControlRenderBroken(t *testing.T) {
	recs := []ledger.Record{
		rec(1, "apply", "", "success", "dana@example.com", "static"),
	}
	head := ledger.Head{Hash: "abc", Count: 1}
	verr := &ledger.ChainBrokenError{Line: 2}
	out := control.Render(recs, head, verr)
	if !strings.Contains(out, "BROKEN at seq 2") {
		t.Fatalf("missing BROKEN line:\n%s", out)
	}
}

// TestControlRenderBrokenAndTainted covers the brief's "both facts" rule:
// a torn/broken AND tainted log must show both the taint line and the
// torn/broken line.
func TestControlRenderBrokenAndTainted(t *testing.T) {
	recs := []ledger.Record{
		rec(1, "apply", "", "success", "dana@example.com", "static"),
		rec(2, "repair", "", "success", "dana@example.com", "static"),
	}
	head := ledger.Head{Hash: "abc", Count: 2}
	verr := &ledger.ChainBrokenError{Line: 3}
	out := control.Render(recs, head, verr)
	if !strings.Contains(out, "TAINTED (repaired at seq 2)") {
		t.Fatalf("missing taint line:\n%s", out)
	}
	if !strings.Contains(out, "BROKEN at seq 3") {
		t.Fatalf("missing broken line:\n%s", out)
	}
}

// TestIsTainted covers IsTainted directly: no repair record -> false;
// a repair record -> true and the first repair's seq.
func TestIsTainted(t *testing.T) {
	clean := []ledger.Record{
		rec(1, "apply", "", "success", "dana@example.com", "static"),
		rec(2, "disable", "coder", "success", "dana@example.com", "static"),
	}
	if tainted, _ := control.IsTainted(clean); tainted {
		t.Fatal("a clean chain must not be tainted")
	}

	tainted := []ledger.Record{
		rec(1, "apply", "", "success", "dana@example.com", "static"),
		rec(2, "repair", "", "success", "dana@example.com", "static"),
		rec(3, "enable", "coder", "success", "dana@example.com", "static"),
	}
	ok, seq := control.IsTainted(tainted)
	if !ok || seq != 2 {
		t.Fatalf("IsTainted = %v, %d; want true, 2", ok, seq)
	}
}
