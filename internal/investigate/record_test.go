package investigate

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/anchorverify"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/identity"
)

func TestNormalizeMapping(t *testing.T) {
	e := engine.Event{Type: "workflow_started", Time: time.Unix(10, 0).UTC(),
		ConfigHash: "sha256:x", Binding: engine.Binding{RunID: "r-1", Role: "se",
			Workflow: "fix-bug", Invoker: identity.Invoker{Subject: "dana", Method: "asserted", Issuer: "local"}}}
	r := normalizeRun(e, 0)
	if r.Source != "run" || r.RunID != "r-1" || r.Kind != "workflow_started" {
		t.Fatalf("%+v", r)
	}
	if r.ConfigHash != "sha256:x" || r.Invoker.Subject != "dana" || r.Role != "se" {
		t.Fatalf("%+v", r)
	}

	d := control.DecodedEvent{Seq: 3, Time: time.Unix(20, 0).UTC(), Action: "disable",
		Agent: "coder", Outcome: "success", Invoker: identity.Invoker{Subject: "ops", Method: "asserted"}}
	c := normalizeControl(d, nil)
	if c.Source != "control" || c.Kind != "disable" || c.Agent != "coder" || c.Seq != 3 {
		t.Fatalf("%+v", c)
	}
	if c.Outcome != "success" || c.Invoker.Subject != "ops" {
		t.Fatalf("%+v", c)
	}
}

// TestNormalizeRunOutcome checks that Record.Outcome is derived only from
// the event types that carry a genuine run-level outcome, and never leaks
// e.Status's other meanings (e.g. bounced_back's target step name) into it.
func TestNormalizeRunOutcome(t *testing.T) {
	cases := []struct {
		name string
		e    engine.Event
		want string
	}{
		{"run_refused has no Status but must map to refused",
			engine.Event{Type: "run_refused", Reason: "role not in registry"}, "refused"},
		{"bounced_back's Status is a step name, not an outcome",
			engine.Event{Type: "bounced_back", Step: "code", Status: "plan"}, ""},
		{"workflow_finished succeeded",
			engine.Event{Type: "workflow_finished", Status: "succeeded"}, "succeeded"},
		{"workflow_finished failed",
			engine.Event{Type: "workflow_finished", Status: "failed"}, "failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := normalizeRun(c.e, 0).Outcome; got != c.want {
				t.Fatalf("Outcome = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRecordJSONShape(t *testing.T) {
	r := normalizeControl(control.DecodedEvent{Seq: 1, Time: time.Unix(0, 0).UTC(), Action: "apply", Outcome: "success"}, nil)
	b, _ := json.Marshal(r)
	s := string(b)
	for _, want := range []string{`"source":"control"`, `"kind":"apply"`, `"seq":1`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s in %s", want, s)
		}
	}
	if strings.Contains(s, `"run_id"`) || strings.Contains(s, `"pos"`) {
		t.Fatalf("unexpected field: %s", s)
	}
}

// TestNormalizeControlDoesNotCarryDetail: the investigate/1 record has no
// detail field — a control event's prose summary is not part of the
// published contract; provision and prune surface as kinds, nothing more.
func TestNormalizeControlDoesNotCarryDetail(t *testing.T) {
	r := normalizeControl(control.DecodedEvent{Seq: 3, Time: time.Unix(0, 0).UTC(), Action: "prune", Outcome: "success", Detail: "pruned 1 run(s) and 0 artifact(s) older than 180d"}, nil)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "prune" || !strings.Contains(string(b), `"kind":"prune"`) {
		t.Fatalf("kind must be the action: %s", b)
	}
	if strings.Contains(string(b), "detail") || strings.Contains(string(b), "pruned 1") {
		t.Fatalf("detail must not reach investigate/1: %s", b)
	}
}

// TestNormalizeControlAnchorFactsAndVerdict: facts on every attempt that
// recorded a payload, a verdict on every success record — payload or not —
// nothing on a refused record; the fact fields are cleaned, the cause is
// carried exactly as produced, and the proof never enters the record.
func TestNormalizeControlAnchorFactsAndVerdict(t *testing.T) {
	hash, keyID := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	ref := strings.Repeat("0", 16) + strings.Repeat("ef", 32)
	payload := &control.Anchor{Seq: 1, Hash: hash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://log.example", Ref: ref, Proof: "AQID", BackendKeyID: keyID}
	at := time.Unix(0, 0).UTC()

	verified := &anchorverify.Result{Check: control.AnchorCheck{RecordSeq: 2, Anchor: payload}, State: anchorverify.StateVerified}
	r := normalizeControl(control.DecodedEvent{Seq: 2, Time: at, Action: "anchor", Outcome: "success", Anchor: payload}, verified)
	want := &Anchor{Seq: 1, Hash: hash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://log.example", Ref: ref, BackendKeyID: keyID, Verdict: "verified"}
	if !reflect.DeepEqual(r.Anchor, want) {
		t.Fatalf("success: %+v\nwant %+v", r.Anchor, want)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"anchor":{"seq":1,"hash":"`+hash+`","kind":"tlog","backend_kind":"transparency-log","backend":"https://log.example","ref":"`+ref+`","backend_key_id":"`+keyID+`","verdict":"verified"}`) {
		t.Fatalf("success JSON: %s", b)
	}
	if strings.Contains(string(b), "proof") || strings.Contains(string(b), "AQID") || strings.Contains(string(b), "cause") {
		t.Fatalf("no proof, no empty cause: %s", b)
	}

	// a failed attempt: what it tried, no ref, no verdict
	tried := &control.Anchor{Seq: 1, Hash: hash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://log.example"}
	r = normalizeControl(control.DecodedEvent{Seq: 3, Time: at, Action: "anchor", Outcome: "error", Reason: &control.Reason{Code: control.CodeAnchorFailed, Message: "status 503 from log.example"}, Anchor: tried}, nil)
	if b, _ = json.Marshal(r.Anchor); string(b) != `{"seq":1,"hash":"`+hash+`","kind":"tlog","backend_kind":"transparency-log","backend":"https://log.example"}` {
		t.Fatalf("error record: %s", b)
	}

	// a refused anchor: no payload, no object
	r = normalizeControl(control.DecodedEvent{Seq: 4, Time: at, Action: "anchor", Outcome: "refused", Reason: control.NotAuthorized("anchor")}, nil)
	if r.Anchor != nil {
		t.Fatalf("refused: %+v", r.Anchor)
	}
	if b, _ = json.Marshal(r); strings.Contains(string(b), `"anchor":`) {
		t.Fatalf("refused JSON: %s", b)
	}

	// a planted success record without a payload: verdict and cause only
	noPayload := &anchorverify.Result{Check: control.AnchorCheck{RecordSeq: 5, Mismatch: "anchor record without coverage"}, State: anchorverify.StateMismatch, Cause: "anchor record without coverage"}
	r = normalizeControl(control.DecodedEvent{Seq: 5, Time: at, Action: "anchor", Outcome: "success"}, noPayload)
	if b, _ = json.Marshal(r.Anchor); string(b) != `{"verdict":"mismatch","cause":"anchor record without coverage"}` {
		t.Fatalf("planted: %s", b)
	}

	// a non-anchor record never carries the object
	if r = normalizeControl(control.DecodedEvent{Seq: 6, Time: at, Action: "apply", Outcome: "success"}, nil); r.Anchor != nil {
		t.Fatalf("apply: %+v", r.Anchor)
	}

	// cleaning: the fact fields lose control characters and are capped; an
	// honest record is byte-identical; the cause is carried whole — the
	// structural cause is longer than origin.Clean's 200-rune cap and must
	// not be truncated.
	hostile := &control.Anchor{Seq: 1, Hash: hash, Kind: "tlog\x07", BackendKind: "transparency-log\x1b[31m", Backend: "https://log.example\x00", Ref: "123\x0045", BackendKeyID: keyID + "\x1b"}
	cause := fmt.Sprintf("the chain does not reproduce the recorded head at seq %d (chain %s, recorded %s)", 1, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if len(cause) <= 200 {
		t.Fatalf("the structural cause is %d characters; the test assumes it is over origin.Clean's 200-rune cap", len(cause))
	}
	mismatch := &anchorverify.Result{Check: control.AnchorCheck{RecordSeq: 7, Anchor: hostile, Mismatch: cause}, State: anchorverify.StateMismatch, Cause: cause}
	r = normalizeControl(control.DecodedEvent{Seq: 7, Time: at, Action: "anchor", Outcome: "success", Anchor: hostile}, mismatch)
	want = &Anchor{Seq: 1, Hash: hash, Kind: "tlog", BackendKind: "transparency-log[31m", Backend: "https://log.example", Ref: "12345", BackendKeyID: keyID, Verdict: "mismatch", Cause: cause}
	if !reflect.DeepEqual(r.Anchor, want) {
		t.Fatalf("hostile: %+v\nwant %+v", r.Anchor, want)
	}
	long := &control.Anchor{Seq: 1, Hash: hash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://" + strings.Repeat("x", 300), Ref: ref}
	r = normalizeControl(control.DecodedEvent{Seq: 8, Time: at, Action: "anchor", Outcome: "error", Reason: &control.Reason{Code: control.CodeAnchorFailed, Message: "x"}, Anchor: long}, nil)
	if len(r.Anchor.Backend) != 200 {
		t.Fatalf("a 308-byte backend must be capped at 200 runes, got %d", len(r.Anchor.Backend))
	}
}
