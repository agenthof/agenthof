package investigate

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

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
	c := normalizeControl(d)
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
	r := normalizeControl(control.DecodedEvent{Seq: 1, Time: time.Unix(0, 0).UTC(), Action: "apply", Outcome: "success"})
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
