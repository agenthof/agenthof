// Package investigate defines the unified Record type that run events and
// control events are normalized into for investigation tooling, along with
// the normalizers that produce it.
package investigate

import (
	"time"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
)

// Invoker is the normalized identity of whoever caused a Record's event.
type Invoker struct {
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	Method     string `json:"method"`
	AssertedAs string `json:"asserted_as,omitempty"`
}

// Record is the unified, source-agnostic shape that both run events and
// control events are normalized into. It is the public JSON contract for
// investigation output.
type Record struct {
	Time        time.Time `json:"time"`
	Source      string    `json:"source"`
	RunID       string    `json:"run_id,omitempty"`
	Kind        string    `json:"kind"`
	Invoker     Invoker   `json:"invoker"`
	Role        string    `json:"role,omitempty"`
	Workflow    string    `json:"workflow,omitempty"`
	Agent       string    `json:"agent,omitempty"`
	Outcome     string    `json:"outcome,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	ConfigHash  string    `json:"config_hash,omitempty"`
	ArtifactSHA string    `json:"artifact_sha,omitempty"`
	Seq         int       `json:"seq,omitempty"`

	// pos is the intra-source position (line index for run events, Seq
	// for control events) used only for merge ordering; it is never
	// serialized.
	pos int
}

// normalizeRun maps a run engine.Event into the unified Record shape.
// lineIdx is the event's position within its run log, used for merge
// ordering.
//
// Outcome is derived only for the event types that actually carry a run-level
// outcome — workflow_finished ("succeeded"|"failed") and run_refused (which
// itself carries no Status, so "refused" is supplied here). e.Status is
// reused by other event types for unrelated things (e.g. bounced_back sets
// Status to the target step name), so copying it blindly would leak a step
// name into Outcome; every other event type leaves Outcome empty.
func normalizeRun(e engine.Event, lineIdx int) Record {
	outcome := ""
	switch e.Type {
	case "workflow_finished":
		outcome = e.Status // "succeeded" | "failed"
	case "run_refused":
		outcome = "refused"
	}
	return Record{
		Time:   e.Time,
		Source: "run",
		RunID:  e.Binding.RunID,
		Kind:   e.Type,
		Invoker: Invoker{
			Subject: e.Binding.Invoker.Subject,
			Issuer:  e.Binding.Invoker.Issuer,
			Method:  e.Binding.Invoker.Method,
		},
		Role:        e.Binding.Role,
		Workflow:    e.Binding.Workflow,
		Agent:       e.Agent,
		Outcome:     outcome,
		Reason:      e.Reason,
		ConfigHash:  e.ConfigHash,
		ArtifactSHA: e.ArtifactSHA,
		pos:         lineIdx,
	}
}

// normalizeControl maps a control.DecodedEvent into the unified Record
// shape.
func normalizeControl(d control.DecodedEvent) Record {
	var reason string
	if d.Reason != nil {
		reason = d.Reason.Message
	}
	return Record{
		Time:   d.Time,
		Source: "control",
		Kind:   d.Action,
		Invoker: Invoker{
			Subject:    d.Invoker.Subject,
			Issuer:     d.Invoker.Issuer,
			Method:     d.Invoker.Method,
			AssertedAs: d.AssertedAs,
		},
		Agent:      d.Agent,
		Outcome:    d.Outcome,
		Reason:     reason,
		ConfigHash: d.ConfigHash,
		Seq:        d.Seq,
		pos:        d.Seq,
	}
}
