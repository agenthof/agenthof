package control_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

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

// TestControlRenderTaint covers taint rendering: two
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
// combination.
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

// TestControlRenderBrokenAndTainted covers the "both facts" rule:
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

// recVia is rec with an origin on the wire, as an API-recorded control
// event carries it.
func recVia(seq int, action, outcome, subject, method, via string) ledger.Record {
	raw := fmt.Sprintf(
		`{"v":"control/1","seq":%d,"time":"2026-10-08T10:%02d:00Z",`+
			`"action":%q,"outcome":%q,`+
			`"invoker":{"subject":%q,"issuer":"https://idp.test","method":%q},`+
			`"witness":{"os_user":"svc","hostname":"host"},"config_hash":"sha256:abc",`+
			`"origin":{"via":%q,"remote_addr":"10.0.0.9:4","user_agent":"ua/1"},"prev":""}`,
		seq, seq, action, outcome, subject, method, via,
	)
	return ledger.Record{Raw: []byte(raw)}
}

// TestControlRenderOrigin: a record with origin renders "(oidc, via api)";
// one without renders "(oidc)" exactly as before; the remote address and
// user agent are not rendered.
func TestControlRenderOrigin(t *testing.T) {
	recs := []ledger.Record{
		recVia(1, "apply", "success", "dana@example.com", "oidc", "api"),
		rec(2, "apply", "", "refused", "dana@example.com", "oidc"),
	}
	out := control.Render(recs, ledger.Head{Hash: "h", Count: 2}, nil)
	for _, want := range []string{
		"seq 1  2026-10-08 10:01:00  config applied — dana@example.com (oidc, via api)\n",
		"seq 2  2026-09-21 10:02:00  config apply refused — dana@example.com (oidc)\n", // rec() stamps 2026-09-21
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	for _, leak := range []string{"10.0.0.9", "ua/1"} {
		if strings.Contains(out, leak) {
			t.Fatalf("%q must not be rendered:\n%s", leak, out)
		}
	}
}

// recDetail is rec with a detail field, for the (<detail>) suffix.
func recDetail(seq int, action, outcome, detail string) ledger.Record {
	raw := fmt.Sprintf(
		`{"v":"control/1","seq":%d,"time":"2026-10-08T10:%02d:00Z",`+
			`"action":%q,"outcome":%q,`+
			`"invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},`+
			`"witness":{"os_user":"dana","hostname":"host"},"detail":%q,"prev":""}`,
		seq, seq, action, outcome, detail,
	)
	return ledger.Record{Raw: []byte(raw)}
}

// TestControlRenderProvisionAndPruneLabels: the six labels, worded around
// the action on every non-success outcome; provision's success label is
// "provision ok" (a success may have minted nothing); a record with detail
// renders it in parentheses after the label, and one without renders as
// before.
func TestControlRenderProvisionAndPruneLabels(t *testing.T) {
	recs := []ledger.Record{
		rec(1, "provision", "", "success", "dana@example.com", "asserted"),
		rec(2, "provision", "", "refused", "dana@example.com", "asserted"),
		rec(3, "provision", "", "error", "dana@example.com", "asserted"),
		rec(4, "prune", "", "refused", "dana@example.com", "asserted"),
		rec(5, "prune", "", "error", "dana@example.com", "asserted"),
		recDetail(6, "prune", "success", "pruned 3 run(s) and 1 artifact(s) older than 180d"),
		rec(7, "prune", "", "success", "dana@example.com", "asserted"),
	}
	out := control.Render(recs, ledger.Head{Hash: "h", Count: 7}, nil)
	for _, want := range []string{
		"seq 1  2026-09-21 10:01:00  provision ok — dana@example.com (asserted)\n",
		"seq 2  2026-09-21 10:02:00  provision refused — dana@example.com (asserted)\n",
		"seq 3  2026-09-21 10:03:00  provision error — dana@example.com (asserted)\n",
		"seq 4  2026-09-21 10:04:00  runs prune refused — dana@example.com (asserted)\n",
		"seq 5  2026-09-21 10:05:00  runs prune error — dana@example.com (asserted)\n",
		"seq 6  2026-10-08 10:06:00  runs pruned (pruned 3 run(s) and 1 artifact(s) older than 180d) — dana@example.com (asserted)\n",
		"seq 7  2026-09-21 10:07:00  runs pruned — dana@example.com (asserted)\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "keys provisioned") {
		t.Fatalf("a provision label must not claim keys were minted:\n%s", out)
	}
}

// TestControlRenderVouch: a vouch success renders "vouched for installed
// config <hash>" and, with the writer's Detail appended by Render, reads
// "(previously on record: <h2>, apply)" — one pair of parentheses, never
// nested; a refused vouch renders "vouch refused".
func TestControlRenderVouch(t *testing.T) {
	ok := ledger.Record{Raw: []byte(`{"v":"control/1","seq":2,"time":"2026-10-12T10:02:00Z","action":"vouch","outcome":"success",` +
		`"invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},"witness":{"os_user":"dana","hostname":"host"},` +
		`"config_hash":"sha256:bbb","detail":"previously on record: sha256:aaa, apply","prev":"x"}`)}
	refused := ledger.Record{Raw: []byte(`{"v":"control/1","seq":3,"time":"2026-10-12T10:03:00Z","action":"vouch","outcome":"refused",` +
		`"reason":{"code":"token_verification_failed","message":"token verification failed"},` +
		`"invoker":{"subject":"(unverified)","issuer":"https://idp","method":"oidc-rejected"},"witness":{"os_user":"dana","hostname":"host"},"prev":"y"}`)}
	out := control.Render([]ledger.Record{rec(1, "apply", "", "success", "dana@example.com", "asserted"), ok, refused}, ledger.Head{Hash: "z", Count: 3}, nil)
	if !strings.Contains(out, "seq 2  2026-10-12 10:02:00  vouched for installed config sha256:bbb (previously on record: sha256:aaa, apply) — dana@example.com (asserted)") {
		t.Fatalf("vouch success line:\n%s", out)
	}
	if strings.Contains(out, "((") || strings.Contains(out, "))") {
		t.Fatalf("nested parentheses:\n%s", out)
	}
	if !strings.Contains(out, "vouch refused — (unverified) (oidc-rejected)") {
		t.Fatalf("vouch refused line:\n%s", out)
	}
}

// TestControlRenderAnchorLabels: a success anchor names the head it pins by
// seq and hash and the knob that produced it; a success without its payload
// is malformed and must not read as a pin; a non-success is worded around
// the action; the locator, backend and proof stay in the record, not on the
// line; the integrity line is untouched (no taint from an anchor).
func TestControlRenderAnchorLabels(t *testing.T) {
	h := strings.Repeat("ab", 32)
	recs := []ledger.Record{
		rec(1, "apply", "", "success", "dana@example.com", "asserted"),
		recAnchor(2, "success", "", `{"seq":1,"hash":"`+h+`","kind":"tlog","backend_kind":"transparency-log","backend":"https://log.example","ref":"12345","proof":"AQID"}`),
		recAnchor(3, "success", "", ""),
		recAnchor(4, "error", "", `{"seq":1,"hash":"`+h+`"}`),
	}
	out := control.Render(recs, ledger.Head{Hash: "z", Count: 4}, nil)
	for _, want := range []string{
		"seq 2  2026-10-13 10:02:00  head anchored: seq 1 " + h + " (tlog) — dana@example.com (asserted)\n",
		"seq 3  2026-10-13 10:03:00  anchor record without coverage — dana@example.com (asserted)\n",
		"seq 4  2026-10-13 10:04:00  anchor error — dana@example.com (asserted)\n",
		"control ledger integrity: verified (4 events)\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	for _, leak := range []string{"12345", "https://log.example", "transparency-log", "AQID"} {
		if strings.Contains(out, leak) {
			t.Fatalf("%q must stay in the record, not on the line:\n%s", leak, out)
		}
	}
	if tainted, _ := control.IsTainted(recs); tainted {
		t.Fatal("an anchor must not taint the ledger")
	}
}

// TestRenderShowsARealAnchorAndHidesItsLocator: a success anchor written by
// Append renders as "head anchored: seq K <hash> (tlog)"; the ref, the proof
// and the key id stay in the record for raw readers.
func TestRenderShowsARealAnchorAndHidesItsLocator(t *testing.T) {
	p, inv, w := appliedLedger(t)
	a := goodAnchor()
	if _, err := control.Append(p, control.Event{Action: "anchor", Outcome: "success", Invoker: inv, Witness: w, Anchor: a}); err != nil {
		t.Fatal(err)
	}
	recs, head, err := ledger.ReadVerify(p, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	out := control.Render(recs, head, nil)
	if !strings.Contains(out, "seq 2  ") || !strings.Contains(out, "head anchored: seq 1 "+coveredHash+" (tlog) — dana@example.com (asserted)") {
		t.Fatalf("render:\n%s", out)
	}
	for _, hidden := range []string{a.Ref, a.Proof, a.BackendKeyID, a.Backend} {
		if strings.Contains(out, hidden) {
			t.Fatalf("render must not show %q:\n%s", hidden, out)
		}
	}
}

// TestControlRenderSealLabelAndSegments: a success seal renders
// "segment N sealed (seq A–B)", a refused seal "seal refused"; RenderView
// prints one segment line per sealed segment before the events and
// "verified (N events, k sealed segments)" when k > 0; Render on a plain
// View is byte-identical to today.
func TestControlRenderSealLabelAndSegments(t *testing.T) {
	raw := `{"v":"control/1","seq":6,"time":"2026-10-15T09:00:00Z","action":"seal","outcome":"success","invoker":{"subject":"dana","issuer":"local","method":"static"},"witness":{"os_user":"dana","hostname":"host"},"seal":{"segment":1,"first_seq":1,"head_seq":5,"head_hash":"h","content_sha256":"c"},"prev":"p"}`
	v := control.View{Records: []ledger.Record{rec(1, "apply", "", "success", "dana", "static"), {Raw: []byte(raw)}, rec(7, "prune", "", "success", "dana", "static")}, Head: ledger.Head{Hash: "x", Count: 7}, FirstSeq: 1,
		Sealed: []control.Segment{{N: 1, Path: "/r/control.jsonl.seg-000001", FirstSeq: 1, HeadSeq: 6, HeadHash: "hh", SHA256: "ff", SealedAt: time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)}},
		Active: control.Segment{FirstSeq: 7, HeadSeq: 7, Records: 1}}
	out := control.RenderView(v, nil)
	for _, want := range []string{
		"control ledger — 7 events\n",
		"segment 1: seq 1–6 sealed 2026-10-15T09:00:00Z control.jsonl.seg-000001\n",
		"seq 6  2026-10-15 09:00:00  segment 1 sealed (seq 1–5) — dana (static)\n",
		"control ledger integrity: verified (7 events, 1 sealed segments)\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "segment 1: seq") > strings.Index(out, "seq 1  ") {
		t.Fatal("segment lines print before the events")
	}
	plain := []ledger.Record{rec(1, "apply", "", "success", "dana", "static")}
	if control.Render(plain, ledger.Head{Hash: "x", Count: 1}, nil) != control.RenderView(control.View{Records: plain, Head: ledger.Head{Hash: "x", Count: 1}}, nil) || strings.Contains(control.Render(plain, ledger.Head{Count: 1}, nil), "sealed segments") {
		t.Fatal("a plain View renders exactly as Render did")
	}
	refusedRaw := `{"v":"control/1","seq":2,"time":"2026-10-15T09:00:00Z","action":"seal","outcome":"refused","invoker":{"subject":"m","issuer":"local","method":"static"},"witness":{},"prev":"p"}`
	if out := control.Render([]ledger.Record{{Raw: []byte(refusedRaw)}}, ledger.Head{Count: 1}, nil); !strings.Contains(out, "  seal refused — m (static)") {
		t.Fatalf("%s", out)
	}
}

// TestLabelWormSeal: a seal record with a sink block labels where the
// protected copy went and until when; without a block the shipped label is
// unchanged.
func TestLabelWormSeal(t *testing.T) {
	const head = `{"v":"control/1","seq":6,"time":"2026-10-15T09:00:00Z","action":"seal","outcome":"success","invoker":{"subject":"dana","issuer":"local","method":"static"},"witness":{"os_user":"dana","hostname":"host"},"seal":{"segment":1,"first_seq":1,"head_seq":5,"head_hash":"h","content_sha256":"c"`
	worm := head + `,"sink":{"kind":"s3-object-lock","url":"https://s3.eu-central-1.amazonaws.com/acme/agenthof","key":"agenthof/x/seg-000001","mode":"compliance","retain_until":"2033-10-20T09:12:00Z"}},"prev":"p"}`
	floor := head + `},"prev":"p"}`
	for raw, want := range map[string]string{
		worm:  "  seq 6  2026-10-15 09:00:00  segment 1 sealed (seq 1–5) → protected copy s3-object-lock https://s3.eu-central-1.amazonaws.com/acme/agenthof until 2033-10-20T09:12:00Z — dana (static)\n",
		floor: "  seq 6  2026-10-15 09:00:00  segment 1 sealed (seq 1–5) — dana (static)\n",
	} {
		out := control.Render([]ledger.Record{{Raw: []byte(raw)}}, ledger.Head{Count: 1}, nil)
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

// TestRenderViewRotationState: a seal that was not rotated says so between
// the segment lines and the events, naming the segment by its ordinal — the
// active is that segment in state B, the manifest already lists it in state C.
func TestRenderViewRotationState(t *testing.T) {
	sealed := []control.Segment{{N: 1, Path: "/r/control.jsonl.seg-000001", FirstSeq: 1, HeadSeq: 4}}
	b := control.RenderView(control.View{State: control.StateSealedNotRotated, Sealed: sealed, Head: ledger.Head{Count: 0}}, nil)
	if !strings.Contains(b, "control ledger: segment 2 sealed, rotation not completed; run: agenthof audit seal\n") {
		t.Fatalf("state B:\n%s", b)
	}
	c := control.RenderView(control.View{State: control.StateRotatedNotSwapped, Sealed: sealed}, nil)
	if !strings.Contains(c, "control ledger: segment 1 sealed, rotation not completed; run: agenthof audit seal\n") {
		t.Fatalf("state C:\n%s", c)
	}
	if strings.Contains(control.RenderView(control.View{Sealed: sealed}, nil), "rotation not completed") {
		t.Fatal("an open set has no rotation state")
	}
}

// TestIntegrityLineSetFaults: each set fault has its verdict; the active's
// torn/broken lines are today's; the global seq is printed.
func TestIntegrityLineSetFaults(t *testing.T) {
	v := control.View{Head: ledger.Head{Count: 3}}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&control.SetError{Fault: control.FaultBroken, Segment: 0, Seq: 3, Err: &ledger.ChainBrokenError{Line: 3}}, "control ledger integrity: BROKEN at seq 3\n"},
		{&control.SetError{Fault: control.FaultBroken, Segment: 0, Seq: 12, Err: &ledger.ChainBrokenError{Line: 2}}, "control ledger integrity: BROKEN at seq 12\n"},
		{&control.SetError{Fault: control.FaultTorn, Segment: 0, Seq: 4, Err: &ledger.TornError{Offset: 10}}, "control ledger integrity: TORN — last record incomplete\n"},
		{&control.SetError{Fault: control.FaultBroken, Segment: 2, Seq: 9}, "control ledger integrity: BROKEN at seq 9 (segment 2)\n"},
		{&control.SetError{Fault: control.FaultTorn, Segment: 2, Seq: 9}, "control ledger integrity: TORN (segment 2)\n"},
		{&control.SetError{Fault: control.FaultBoundary, Segment: 3, Seq: 11}, "control ledger integrity: BOUNDARY BROKEN between segments 2 and 3\n"},
		{&control.SetError{Fault: control.FaultBoundary, Segment: 0, Seq: 11}, "control ledger integrity: BOUNDARY BROKEN between the last sealed segment and the active\n"},
		{&control.SetError{Fault: control.FaultMissingSegment, Segment: 2}, "control ledger integrity: SEGMENT 2 MISSING\n"},
		{&control.SetError{Fault: control.FaultUnexpectedSegment, Path: "/r/control.jsonl.seg-000004"}, "control ledger integrity: UNEXPECTED SEGMENT control.jsonl.seg-000004\n"},
		{&control.SetError{Fault: control.FaultManifest, Segment: 2, Err: errors.New("head_hash a recorded, b verified")}, "control ledger integrity: MANIFEST disagrees with segment 2: head_hash a recorded, b verified\n"},
		{&control.SetError{Fault: control.FaultManifest, Segment: 0, Err: errors.New("log_id a recorded, b verified")}, "control ledger integrity: MANIFEST invalid: log_id a recorded, b verified\n"},
		{&control.SetError{Fault: control.FaultSealNotLast, Segment: 0, Seq: 8}, "control ledger integrity: SEAL NOT LAST in the active segment (seal at seq 7)\n"},
		{&control.SetError{Fault: control.FaultSealNotLast, Segment: 2, Seq: 8}, "control ledger integrity: SEAL NOT LAST in segment 2 (seal at seq 7)\n"},
		{&ledger.ChainBrokenError{Line: 2}, "control ledger integrity: BROKEN at seq 2\n"},
		{&ledger.TornError{Offset: 1}, "control ledger integrity: TORN — last record incomplete\n"},
	} {
		if got := control.RenderView(v, tc.err); !strings.HasSuffix(got, tc.want) {
			t.Fatalf("%v:\n%s\nwant suffix %q", tc.err, got, tc.want)
		}
	}
}

// TestRenderHeaderShowsTheLogID: the header names the ledger's identity on its
// own line directly under the first line, so an operator can read the id the
// rebuild asks for (audit restore control --rebuild --log-id) off audit
// control; the id is the genesis record's, and the existing lines keep their
// order.
func TestRenderHeaderShowsTheLogID(t *testing.T) {
	p, _, _ := appliedLedger(t)
	recs, head, err := ledger.ReadVerify(p, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	id, err := control.GenesisLogID(recs)
	if err != nil {
		t.Fatal(err)
	}
	out := control.Render(recs, head, nil)
	if want := "control ledger — 1 events\nlog_id: " + id + "\n\n"; !strings.HasPrefix(out, want) {
		t.Fatalf("header must carry the log_id under its first line, want prefix %q in:\n%s", want, out)
	}
}

// TestRenderHeaderOmitsAMissingLogID: a root written before ledgers carried a
// log_id has none to show, and the header prints no log_id line at all, never
// an empty one.
func TestRenderHeaderOmitsAMissingLogID(t *testing.T) {
	recs := []ledger.Record{rec(1, "apply", "", "success", "dana@example.com", "static")}
	out := control.Render(recs, ledger.Head{Hash: "h", Count: 1}, nil)
	if strings.Contains(out, "log_id") {
		t.Fatalf("a root with no log_id must print no log_id line:\n%s", out)
	}
	if !strings.HasPrefix(out, "control ledger — 1 events\n\n") {
		t.Fatalf("header unchanged for a pre-log_id root:\n%s", out)
	}
}
