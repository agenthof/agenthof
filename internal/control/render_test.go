package control_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// rec builds a hand-crafted control/1 wire record (Render reads
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

// TestControlRenderBootstrapLabel: a bootstrap apply renders distinctly, so a
// second bootstrap (someone removed the installed pointer) is visible in the
// audit trail; an ordinary apply keeps its plain label.
func TestControlRenderBootstrapLabel(t *testing.T) {
	boot := ledger.Record{Raw: []byte(`{"v":"control/1","seq":1,"time":"2026-10-07T10:01:00Z",` +
		`"action":"apply","outcome":"success",` +
		`"invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},` +
		`"witness":{"os_user":"dana","hostname":"host"},"config_hash":"sha256:abc","bootstrap":true,"prev":""}`)}
	recs := []ledger.Record{boot, rec(2, "apply", "", "success", "dana@example.com", "asserted")}
	out := control.Render(recs, ledger.Head{Hash: "deadbeef", Count: 2}, nil)
	if !strings.Contains(out, "seq 1  2026-10-07 10:01:00  config applied (bootstrap) — dana@example.com (asserted)") {
		t.Fatalf("missing bootstrap label:\n%s", out)
	}
	if !strings.Contains(out, "seq 2  2026-09-21 10:02:00  config applied — dana@example.com (asserted)") {
		t.Fatalf("ordinary apply label changed:\n%s", out)
	}
}

// TestControlRenderBootstrapFlipLabel: a kill-switch flip that ran while
// nothing was installed edited the configuration directory and installed
// nothing; its label says so, and is NOT "(bootstrap)", which for an apply
// means the opposite (it installed the first snapshot).
func TestControlRenderBootstrapFlipLabel(t *testing.T) {
	flip := ledger.Record{Raw: []byte(`{"v":"control/1","seq":1,"time":"2026-10-07T10:01:00Z",` +
		`"action":"enable","agent":"coder","outcome":"success",` +
		`"invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},` +
		`"witness":{"os_user":"dana","hostname":"host"},"config_hash":"sha256:abc","bootstrap":true,"prev":""}`)}
	recs := []ledger.Record{flip, rec(2, "disable", "coder", "success", "dana@example.com", "asserted")}
	out := control.Render(recs, ledger.Head{Hash: "deadbeef", Count: 2}, nil)
	if !strings.Contains(out, "seq 1  2026-10-07 10:01:00  enabled agent coder (nothing installed; directory edited) — dana@example.com (asserted)") {
		t.Fatalf("missing bootstrap-era flip label:\n%s", out)
	}
	if !strings.Contains(out, "seq 2  2026-09-21 10:02:00  disabled agent coder — dana@example.com (asserted)") {
		t.Fatalf("ordinary flip label changed:\n%s", out)
	}
	if strings.Contains(out, "agent coder (bootstrap)") {
		t.Fatalf("a flip must never render as (bootstrap):\n%s", out)
	}
}
