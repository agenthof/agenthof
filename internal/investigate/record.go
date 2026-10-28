// Package investigate defines the unified Record type that run events and
// control events are normalized into for investigation tooling, along with
// the normalizers that produce it.
package investigate

import (
	"time"

	"github.com/agenthof/agenthof/internal/anchorverify"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/origin"
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

	// ParentRunID and Depth place a spawned child run in its delegation
	// tree: the run that asked for it and how deep it sits (a root is 0).
	// Absent on a root run's records.
	ParentRunID string `json:"parent_run_id,omitempty"`
	Depth       int    `json:"depth,omitempty"`

	// Anchor is what a control "anchor" record says it pinned, and — on a
	// success record — whether this reader could stand behind it, decided
	// offline. Absent on every record that is not an anchor. Present on
	// every success anchor record, payload or not: a success record without
	// a payload carries only its verdict (a mismatch, "anchor record without
	// coverage"). Additive and omitempty.
	Anchor *Anchor `json:"anchor,omitempty"`

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
		ParentRunID: e.Binding.ParentRunID,
		Depth:       e.Binding.Depth,
		pos:         lineIdx,
	}
}

// Anchor is the investigate/1 view of a control anchor payload: the facts as
// recorded (never the proof), plus the offline verdict. Every fact string is
// origin.Clean'd at normalization — the ledger's writer may be hostile — and
// every field is omitempty, so a payload-less success record renders no 0
// or "". Cause is carried exactly as the verifier produced it: the
// structural cause is longer than origin.Clean's cap, and truncating it
// would make this view and audit verify control disagree on the one verdict
// they must share.
type Anchor struct {
	RunID        string `json:"run_id,omitempty"`         // the run a run-scoped anchor covers; "" for a control-ledger anchor, which is the only kind that carries a verdict
	Seq          int    `json:"seq,omitempty"`            // the covered head's seq (1 ≤ Seq < the record's own Seq); for a run-scoped anchor, the run-ledger position
	Hash         string `json:"hash,omitempty"`           // the covered head's hash, as recorded
	Kind         string `json:"kind,omitempty"`           // "tlog" | "signed"
	BackendKind  string `json:"backend_kind,omitempty"`   // the proof format: "transparency-log" | "rfc3161" | …
	Backend      string `json:"backend,omitempty"`        // the log's public identity (URL), as recorded
	Ref          string `json:"ref,omitempty"`            // the entry locator; absent on a failed attempt
	BackendKeyID string `json:"backend_key_id,omitempty"` // which log key signed at anchor time; "" for a kind without one
	Verdict      string `json:"verdict,omitempty"`        // "verified" | "mismatch" | "unverifiable"; present iff the record's outcome is "success"
	Cause        string `json:"cause,omitempty"`          // operator prose for a non-verified verdict; "" when verified
}

// normalizeControl maps a control.DecodedEvent into the unified Record
// shape. verdict is the offline anchor verdict for a success anchor record
// (Timeline supplies one for every such record); nil for every other record.
func normalizeControl(d control.DecodedEvent, verdict *anchorverify.Result) Record {
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
		Anchor:     anchorView(d, verdict),
		pos:        d.Seq,
	}
}

// anchorView builds the investigate/1 anchor object: the facts on every
// anchor attempt that recorded a payload (a failed attempt recorded what it
// tried), and the verdict on every success record, payload or not. nil for
// any record that is not an anchor, and for a refused anchor (no payload,
// no claim). The proof is deliberately not copied.
func anchorView(d control.DecodedEvent, verdict *anchorverify.Result) *Anchor {
	if d.Action != "anchor" {
		return nil
	}
	var v *Anchor
	if a := d.Anchor; a != nil {
		v = &Anchor{
			RunID: origin.Clean(a.RunID), Seq: a.Seq, Hash: origin.Clean(a.Hash), Kind: origin.Clean(a.Kind), BackendKind: origin.Clean(a.BackendKind),
			Backend: origin.Clean(a.Backend), Ref: origin.Clean(a.Ref), BackendKeyID: origin.Clean(a.BackendKeyID),
		}
	}
	if d.Outcome != "success" || verdict == nil {
		return v
	}
	if v == nil {
		v = &Anchor{}
	}
	v.Verdict, v.Cause = string(verdict.State), verdict.Cause
	return v
}
