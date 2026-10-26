// Package completeness judges whether a run ledger accounts for itself —
// a second axis beside integrity. Integrity (the hash chain, the sequence
// numbers, the torn-tail check) says the recorded events are unedited and
// unbroken; completeness says the recorded set is the set the run
// produced: every step has its terminal, every door event sits inside a
// step's window, and the door events recorded inside each window are as
// many as the gateway admitted for that step (door_calls on the terminal).
// It is judged against the gateway's own count, so it detects an honest
// source's accidental loss (a write that failed, a path that never
// recorded); it does not make the source trustworthy, and it is never a
// value of the integrity enum.
package completeness

import (
	"fmt"

	"github.com/agenthof/agenthof/internal/engine"
)

// The completeness verdicts. They are never values of the integrity enum,
// and the word "incomplete" (a run status) is never one of them.
const (
	Complete     = "complete"     // every invariant holds and every step's recorded door events == door_calls
	Gap          = "gap"          // the chain is intact but the ledger does not account for itself (Detail says where)
	Unterminated = "unterminated" // no final event: still running, or the tail was lost — the file cannot tell which
	NoClaim      = "no-claim"     // a ledger written before door accounting: integrity only
)

// Report is one run ledger's completeness verdict. Verdict is "" when
// integrity failed: a torn or broken chain is missing records by
// definition, and completeness is not judged on it.
type Report struct {
	Verdict   string
	Detail    string // Gap: the first violation in ledger order
	DoorCalls int    // Complete: door events accounted across every step
}

func gap(detail string) Report { return Report{Verdict: Gap, Detail: detail} }

// doorTypes are the gateway-recorded events a step's door_calls counts.
var doorTypes = map[string]bool{"tool_call": true, "model_call": true, "exec": true, "spawn": true}

// Check judges one verified ledger. Order: zero events and the refused-only
// shape; then unterminated (the last event is not workflow_finished — no
// further judgment, the structure of an unfinished run is noise); then the
// marker rules (no marker and no door_calls anywhere is a pre-accounting
// ledger: no-claim, nothing else judged; door_calls without the marker is
// an inconsistency: gap); then structure and counts together, in ledger
// order, the first violation being the detail. Spawn linkage is VerifyTree's.
func Check(events []engine.Event) Report {
	if len(events) == 0 {
		return Report{Verdict: Unterminated}
	}
	first := events[0]
	switch first.Type {
	case "run_refused":
		if len(events) == 1 {
			return Report{Verdict: Complete}
		}
		return gap("run_refused is not alone")
	case "workflow_started":
	default:
		return gap(fmt.Sprintf("first event is %s, want workflow_started or run_refused", first.Type))
	}
	if events[len(events)-1].Type != "workflow_finished" {
		return Report{Verdict: Unterminated}
	}
	if first.DoorAccounting == "" {
		for _, e := range events {
			if (e.Type == "step_succeeded" || e.Type == "step_failed") && e.DoorCalls != nil {
				return gap("door_calls present without the accounting marker on workflow_started")
			}
		}
		return Report{Verdict: NoClaim}
	}
	var open *struct {
		step  string
		doors int
	}
	prev := first.Type // the last lifecycle event, for the terminal's consistency
	total := 0
	for i, e := range events[1:] {
		last := i == len(events)-2
		switch {
		case doorTypes[e.Type]:
			if open == nil {
				return gap(fmt.Sprintf("%s event outside a step window", e.Type))
			}
			open.doors++
			total++
			continue
		case e.Type == "step_started":
			if open != nil {
				return gap(fmt.Sprintf("step %s has no terminal before step_started", open.step))
			}
			open = &struct {
				step  string
				doors int
			}{step: e.Step}
		case e.Type == "step_succeeded" || e.Type == "step_failed":
			if open == nil || open.step != e.Step {
				return gap(fmt.Sprintf("%s for step %s without a matching step_started", e.Type, e.Step))
			}
			if e.DoorCalls == nil {
				return gap(fmt.Sprintf("step %s terminal lacks door_calls", e.Step))
			}
			if *e.DoorCalls != open.doors {
				return gap(fmt.Sprintf("step %s: %d door call(s) admitted, %d recorded", e.Step, *e.DoorCalls, open.doors))
			}
			open = nil
		case e.Type == "bounced_back":
			if open != nil {
				return gap(fmt.Sprintf("bounced_back inside step %s's window", open.step))
			}
			if prev != "step_failed" {
				return gap("bounced_back not after step_failed")
			}
		case e.Type == "workflow_finished":
			if !last {
				return gap("workflow_finished is not the last event")
			}
			if open != nil {
				return gap(fmt.Sprintf("step %s has no terminal before workflow_finished", open.step))
			}
			if !terminalConsistent(e.Status, prev) {
				return gap(fmt.Sprintf("workflow_finished %s after %s", e.Status, prev))
			}
		default:
			if open != nil {
				return gap(fmt.Sprintf("%s inside step %s's window", e.Type, open.step))
			}
			return gap(fmt.Sprintf("%s outside a step window", e.Type))
		}
		prev = e.Type
	}
	return Report{Verdict: Complete, DoorCalls: total}
}

// terminalConsistent is the engine's workflow_finished emission sites as a
// table: succeeded follows a succeeded step; failed follows a failed step;
// cancelled follows the between-steps check (after workflow_started, a
// succeeded step, or a bounce) or a step that failed because the run was
// cancelled. A zero-step workflow is rejected at registry validation, so
// succeeded never follows workflow_started.
func terminalConsistent(status, prev string) bool {
	switch status {
	case "succeeded":
		return prev == "step_succeeded"
	case "failed":
		return prev == "step_failed"
	case "cancelled":
		return prev == "workflow_started" || prev == "step_succeeded" || prev == "step_failed" || prev == "bounced_back"
	}
	return false
}

// Line renders the "ledger completeness: …" line, or "" when not judged. It
// is the one rendering, shared by audit, audit verify and serve. The word
// "incomplete" is a run status and never appears here; a gap names the step
// and both numbers, or the structural violation; unterminated says plainly
// that the file cannot tell in-progress from lost.
func (r Report) Line() string {
	switch r.Verdict {
	case Complete:
		return fmt.Sprintf("ledger completeness: complete (%d door call(s) accounted)\n", r.DoorCalls)
	case Gap:
		return "ledger completeness: GAP — " + r.Detail + "\n"
	case Unterminated:
		return "ledger completeness: UNTERMINATED — no final event; still running or tail lost (this reader cannot tell which)\n"
	case NoClaim:
		return "ledger completeness: no claim (recorded before door accounting)\n"
	}
	return ""
}
