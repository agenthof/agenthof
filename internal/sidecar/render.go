package sidecar

import (
	"fmt"
	"strings"

	"github.com/agenthof/agenthof/internal/anchorverify"
	"github.com/agenthof/agenthof/internal/origin"
)

// RenderOptions says how the reader that produced a Verdict was placed, which
// is what decides how a verdict may be worded.
type RenderOptions struct {
	Pinned      bool   // the resolved log key was non-nil
	Offline     bool   // the presence check was not made
	OfflineOnly bool   // the reader is offline by construction (audit <run-id>, serve): name audit verify as the way to a networked check
	RunID       string // the run the hint names
}

// Process exit codes for an anchor verdict on a run, the control verifier's
// numbers: a definitive content disagreement and an absent verdict. The one
// definition: cmd/agenthof's exit constants are these.
const (
	ExitMismatch     = 6
	ExitUnverifiable = 7
)

// Exit is the exit code a Verdict contributes: 6 for a mismatch, 7 for an
// unverifiable one (no verdict; never tamper detected), else 0 — a run that is
// not anchored is not a fault.
func Exit(v Verdict) int {
	switch v.State() {
	case StateMismatch:
		return ExitMismatch
	case StateUnverifiable:
		return ExitUnverifiable
	}
	return 0
}

// TreeExit is the worst anchor verdict across a run and its verified
// descendants, ranked 6 > 7 > 0: a mismatch anywhere is 6 whatever else the
// tree holds, and no later node can lower what an earlier one raised.
func TreeExit(root Verdict, children []Verdict) int {
	worst := Exit(root)
	for _, c := range children {
		switch Exit(c) {
		case ExitMismatch:
			return ExitMismatch
		case ExitUnverifiable:
			if worst != ExitMismatch {
				worst = ExitUnverifiable
			}
		}
	}
	return worst
}

// Lines renders a Verdict as the run's anchor line(s), each "\n"-terminated:
// exactly one of five states per record, worded so that a verdict is never
// stronger than the evidence behind it.
//
//   - not anchored — all a posture-blind reader can say;
//   - verified, key not pinned: anchored, under the key the log served, and
//     said to be NOT independent — the log vouched for itself;
//   - verified, key pinned: independently verified;
//   - MISMATCH: only a decoded record that disagrees with the ledger;
//   - unverifiable: no verdict could be reached (no key, an unreachable log, a
//     rotated key, an unreadable sidecar) — never tampering.
//
// A sidecar that could not be read at all carries no pin hint: no key was
// resolved, so Pinned means nothing, and the cause names the file fault, which
// is the fix. More than one record prints one line each and a summary.
// Everything that came from the sidecar, the ledger or a backend passes
// origin.Clean before it can reach a terminal.
func Lines(v Verdict, o RenderOptions) string {
	switch {
	case !v.Found:
		return "ledger anchor: not anchored\n"
	case v.Err != nil:
		return "ledger anchor: unverifiable — " + origin.Clean(v.Err.Error()) + "\n"
	case len(v.Results) == 0:
		return "ledger anchor: unverifiable — the sidecar holds no records\n"
	}
	var sb strings.Builder
	var verified, mismatch, unverifiable int
	for _, r := range v.Results {
		switch r.State {
		case anchorverify.StateVerified:
			verified++
			sb.WriteString(verifiedLine(r, o))
		case anchorverify.StateMismatch:
			mismatch++
			sb.WriteString("ledger anchor: MISMATCH — " + origin.Clean(r.Cause) + "\n")
		default:
			unverifiable++
			sb.WriteString(unverifiableLine(r, o))
		}
	}
	if len(v.Results) > 1 {
		fmt.Fprintf(&sb, "ledger anchors: %d (%d verified, %d mismatch, %d unverifiable)\n", len(v.Results), verified, mismatch, unverifiable)
	}
	return sb.String()
}

func verifiedLine(r anchorverify.Result, o RenderOptions) string {
	if !o.Pinned {
		return "ledger anchor: anchored — verified under the log key as served (not independent; pin the log key in anchor.pub or --anchor-key to verify independently)\n"
	}
	presence := ""
	if o.Offline {
		presence = "; offline: presence not checked"
	}
	a := r.Check.Anchor
	if a == nil { // Check always sets it; a verdict with nothing to name still says what it is
		return "ledger anchor: independently verified (log key pinned" + presence + ")\n"
	}
	return fmt.Sprintf("ledger anchor: independently verified (log key pinned%s; events %d %s → %s entry %s)\n",
		presence, a.Seq, origin.Clean(a.Hash), origin.Clean(a.Backend), origin.Clean(a.Ref))
}

func unverifiableLine(r anchorverify.Result, o RenderOptions) string {
	line := "ledger anchor: unverifiable — " + origin.Clean(r.Cause)
	if !o.Pinned {
		line += "; pin the log key in anchor.pub beside the control ledger or pass --anchor-key"
		if o.OfflineOnly {
			// Only an unpinned reader gains by asking the log for its key; a
			// pinned one would run audit verify under the same pin.
			line += ", or run audit verify " + origin.Clean(o.RunID) + " to check under the key the log serves"
		}
	}
	return line + "\n"
}
