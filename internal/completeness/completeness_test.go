package completeness

import (
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/engine"
)

// Builders for the shapes the engine produces (engine.Run's emission sites).
func ev(typ string) engine.Event { return engine.Event{Time: time.Unix(0, 0).UTC(), Type: typ} }
func started() engine.Event {
	e := ev("workflow_started")
	e.DoorAccounting = engine.DoorAccountingAdmission
	return e
}
func oldStarted() engine.Event           { return ev("workflow_started") }
func stepStart(name string) engine.Event { e := ev("step_started"); e.Step = name; return e }
func door(kind string) engine.Event      { return ev(kind) }
func terminal(typ, name string, n int) engine.Event {
	e := ev(typ)
	e.Step = name
	e.DoorCalls = &n
	return e
}
func stepOK(name string, n int) engine.Event   { return terminal("step_succeeded", name, n) }
func stepFail(name string, n int) engine.Event { return terminal("step_failed", name, n) }
func unstamped(typ, name string) engine.Event  { e := ev(typ); e.Step = name; return e }
func bounce(name, target string) engine.Event {
	e := ev("bounced_back")
	e.Step = name
	e.Status = target
	return e
}
func finished(status string) engine.Event { e := ev("workflow_finished"); e.Status = status; return e }
func refused() engine.Event               { return ev("run_refused") }

func TestCheckAcceptsEveryEngineShape(t *testing.T) {
	cases := map[string]struct {
		events []engine.Event
		doors  int
	}{
		"refused-only":                {[]engine.Event{refused()}, 0},
		"one step, no doors":          {[]engine.Event{started(), stepStart("a"), stepOK("a", 0), finished("succeeded")}, 0},
		"doors inside the window":     {[]engine.Event{started(), stepStart("a"), door("model_call"), door("tool_call"), door("exec"), door("spawn"), stepOK("a", 4), finished("succeeded")}, 4},
		"tool proxy start failed":     {[]engine.Event{started(), stepStart("a"), stepFail("a", 0), finished("failed")}, 0},
		"ErrStepConfig after a step":  {[]engine.Event{started(), stepStart("a"), door("model_call"), stepOK("a", 1), stepStart("b"), door("model_call"), stepFail("b", 1), finished("failed")}, 2},
		"artifact store write failed": {[]engine.Event{started(), stepStart("a"), door("tool_call"), stepFail("a", 1), finished("failed")}, 1},
		"fail-back then succeed":      {[]engine.Event{started(), stepStart("a"), stepOK("a", 0), stepStart("b"), door("tool_call"), door("tool_call"), stepFail("b", 2), bounce("b", "a"), stepStart("a"), stepOK("a", 0), stepStart("b"), door("exec"), stepOK("b", 1), finished("succeeded")}, 3},
		"bounces exhausted":           {[]engine.Event{started(), stepStart("a"), stepFail("a", 0), bounce("a", "a"), stepStart("a"), stepFail("a", 0), finished("failed")}, 0},
		"cancelled before any step":   {[]engine.Event{started(), finished("cancelled")}, 0},
		"cancelled after a step":      {[]engine.Event{started(), stepStart("a"), stepOK("a", 0), finished("cancelled")}, 0},
		"cancelled during a step":     {[]engine.Event{started(), stepStart("a"), door("exec"), stepFail("a", 1), finished("cancelled")}, 1},
		"cancelled after a bounce":    {[]engine.Event{started(), stepStart("a"), stepFail("a", 0), bounce("a", "a"), finished("cancelled")}, 0},
	}
	for name, c := range cases {
		r := Check(c.events)
		if r.Verdict != Complete || r.DoorCalls != c.doors {
			t.Errorf("%s: %+v, want complete with %d door calls", name, r, c.doors)
		}
	}
}

func TestCheckUnterminated(t *testing.T) {
	for name, events := range map[string][]engine.Event{
		"zero events":        nil,
		"cut after a step":   {started(), stepStart("a"), stepOK("a", 0)},
		"cut mid-step":       {started(), stepStart("a"), door("tool_call")},
		"old ledger, no end": {oldStarted(), stepStart("a")},
	} {
		if r := Check(events); r.Verdict != Unterminated {
			t.Errorf("%s: %+v, want unterminated", name, r)
		}
	}
}

func TestCheckGaps(t *testing.T) {
	cases := map[string]struct {
		events []engine.Event
		detail string
	}{
		"count mismatch (a dropped event)":  {[]engine.Event{started(), stepStart("research"), door("tool_call"), door("tool_call"), door("tool_call"), door("tool_call"), stepOK("research", 5), finished("succeeded")}, "step research: 5 door call(s) admitted, 4 recorded"},
		"count mismatch on a failed step":   {[]engine.Event{started(), stepStart("a"), stepFail("a", 1), finished("failed")}, "step a: 1 door call(s) admitted, 0 recorded"},
		"missing terminal before next step": {[]engine.Event{started(), stepStart("a"), stepStart("b"), stepOK("b", 0), finished("succeeded")}, "step a has no terminal before step_started"},
		"missing terminal before finish":    {[]engine.Event{started(), stepStart("a"), finished("failed")}, "step a has no terminal before workflow_finished"},
		"terminal names another step":       {[]engine.Event{started(), stepStart("a"), stepOK("b", 0), finished("succeeded")}, "step_succeeded for step b without a matching step_started"},
		"door outside a window":             {[]engine.Event{started(), door("model_call"), stepStart("a"), stepOK("a", 0), finished("succeeded")}, "model_call event outside a step window"},
		"finish not last":                   {[]engine.Event{started(), stepStart("a"), stepOK("a", 0), finished("succeeded"), finished("succeeded")}, "workflow_finished is not the last event"},
		"succeeded after a failed step":     {[]engine.Event{started(), stepStart("a"), stepFail("a", 0), finished("succeeded")}, "workflow_finished succeeded after step_failed"},
		"failed after a succeeded step":     {[]engine.Event{started(), stepStart("a"), stepOK("a", 0), finished("failed")}, "workflow_finished failed after step_succeeded"},
		"bounce after success":              {[]engine.Event{started(), stepStart("a"), stepOK("a", 0), bounce("a", "a"), stepStart("a"), stepOK("a", 0), finished("succeeded")}, "bounced_back not after step_failed"},
		"refused not alone":                 {[]engine.Event{refused(), started()}, "run_refused is not alone"},
		"refused mid-run":                   {[]engine.Event{started(), refused(), finished("failed")}, "run_refused outside a step window"},
		"starts with a step":                {[]engine.Event{stepStart("a"), stepOK("a", 0), finished("succeeded")}, "first event is step_started, want workflow_started or run_refused"},
		"one terminal unstamped":            {[]engine.Event{started(), stepStart("a"), stepOK("a", 0), stepStart("b"), unstamped("step_succeeded", "b"), finished("succeeded")}, "step b terminal lacks door_calls"},
		"field without marker":              {[]engine.Event{oldStarted(), stepStart("a"), stepOK("a", 0), finished("succeeded")}, "door_calls present without the accounting marker on workflow_started"},
	}
	for name, c := range cases {
		r := Check(c.events)
		if r.Verdict != Gap || r.Detail != c.detail {
			t.Errorf("%s: got %+v, want gap %q", name, r, c.detail)
		}
	}
}

// TestStripFieldWithMarkerIsGap: a new-engine ledger whose EVERY terminal
// lacks door_calls still reads gap, because the marker promised them — a
// regression that stops stamping cannot hide behind no-claim.
func TestStripFieldWithMarkerIsGap(t *testing.T) {
	r := Check([]engine.Event{started(), stepStart("a"), unstamped("step_succeeded", "a"), finished("succeeded")})
	if r.Verdict != Gap || r.Detail != "step a terminal lacks door_calls" {
		t.Fatalf("%+v", r)
	}
}

// TestNoClaimSkipsAllJudgment: an old ledger (no marker, no field) is judged
// on integrity only — its structure is not second-guessed.
func TestNoClaimSkipsAllJudgment(t *testing.T) {
	r := Check([]engine.Event{oldStarted(), unstamped("step_started", "a"), unstamped("step_succeeded", "a"), finished("")})
	if r.Verdict != NoClaim {
		t.Fatalf("%+v, want no-claim even with an empty final status", r)
	}
}

func TestPreMigrationFixtureReadsNoClaim(t *testing.T) {
	events, _, err := engine.ReadLog("../engine/testdata", "pre-migration")
	if err != nil {
		t.Fatal(err)
	}
	if r := Check(events); r.Verdict != NoClaim {
		t.Fatalf("the pre-R10.13 fixture must read no-claim, got %+v", r)
	}
}

func TestLine(t *testing.T) {
	for want, r := range map[string]Report{
		"ledger completeness: complete (7 door call(s) accounted)\n":                                                       {Verdict: Complete, DoorCalls: 7},
		"ledger completeness: GAP — step research: 5 door call(s) admitted, 4 recorded\n":                                  {Verdict: Gap, Detail: "step research: 5 door call(s) admitted, 4 recorded"},
		"ledger completeness: UNTERMINATED — no final event; still running or tail lost (this reader cannot tell which)\n": {Verdict: Unterminated},
		"ledger completeness: no claim (recorded before door accounting)\n":                                                {Verdict: NoClaim},
		"": {},
	} {
		if got := r.Line(); got != want {
			t.Errorf("%+v: %q, want %q", r, got, want)
		}
		if strings.Contains(strings.ToLower(r.Line()), "incomplete") {
			t.Errorf("the completeness line must never use the run-status word: %q", r.Line())
		}
	}
}
