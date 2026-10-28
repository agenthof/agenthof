package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/origin"
)

// IsTainted reports whether any of records carries action "repair", and,
// if so, the seq of the FIRST such record. A repair record means the
// ledger was regenerated after damage — that fact is decidable purely
// from file contents and, once true, is reported forever:
// nothing in this package clears it, and a later clean stretch of records
// does not un-taint an earlier repair.
func IsTainted(records []ledger.Record) (bool, int) {
	for _, r := range records {
		var rec record
		if err := json.Unmarshal(r.Raw, &rec); err != nil {
			continue
		}
		if rec.Action == "repair" {
			return true, rec.Seq
		}
	}
	return false, 0
}

// label derives the human-readable line label for a control record's
// action/outcome pair. It never claims a state change that
// didn't happen: enable/disable/repair/prune only get their past-tense label on
// outcome "success" — every other outcome is worded around the action,
// not past it.
func label(rec record) string {
	switch rec.Action {
	case "apply":
		switch rec.Outcome {
		case "success":
			if rec.Bootstrap {
				// Permitted because nothing was installed — the first apply,
				// or a re-bootstrap after the installed pointer was removed;
				// a reader must be able to tell the two kinds apart.
				return "config applied (bootstrap)"
			}
			return "config applied"
		case "rejected":
			return "config rejected"
		case "refused":
			return "config apply refused"
		default:
			return "config apply error"
		}
	case "enable":
		return flipLabel("enable", "enabled", rec)
	case "disable":
		return flipLabel("disable", "disabled", rec)
	case "repair":
		if rec.Outcome == "success" {
			return "ledger repaired"
		}
		return "ledger repair " + rec.Outcome
	case "provision":
		// "ok", not "keys provisioned": a successful provision may have minted
		// nothing (every role control-only, or every key already valid), and
		// the record carries no per-role outcome — stdout does.
		if rec.Outcome == "success" {
			return "provision ok"
		}
		return "provision " + rec.Outcome
	case "prune":
		if rec.Outcome == "success" {
			return "runs pruned"
		}
		return "runs prune " + rec.Outcome
	case "vouch":
		// The hash is the label's subject: a vouch installs no bytes, it
		// makes the ledger stand behind the pointer that names them. Detail
		// (what was on record before) is appended by Render in ONE pair of
		// parentheses, so the writer's Detail uses a comma, never parentheses.
		if rec.Outcome == "success" {
			return "vouched for installed config " + rec.ConfigHash
		}
		return "vouch " + rec.Outcome
	case "seal":
		// A successful seal is the last record of the segment it closes; the
		// label names the unit so a reader can find the segment by ordinal,
		// and, on a worm seal, where the protected copy went and until when
		// (the key stays in the record for raw readers). Rendering is not
		// verifying: whether the copy is there is verify's verdict.
		if rec.Outcome == "success" {
			if rec.Seal == nil {
				return "seal record without payload"
			}
			lbl := fmt.Sprintf("segment %d sealed (seq %d–%d)", rec.Seal.Segment, rec.Seal.FirstSeq, rec.Seal.HeadSeq)
			if s := rec.Seal.Sink; s != nil {
				lbl += fmt.Sprintf(" → protected copy %s %s until %s", origin.Clean(s.Kind), origin.Clean(s.URL), s.RetainUntil.UTC().Format(time.RFC3339))
			}
			return lbl
		}
		return "seal " + rec.Outcome
	case "anchor":
		// The record pins a PRIOR head; the label names which one, so a
		// reader can find the covered record by seq. A success record
		// without its payload is malformed and must not read as a pin. The
		// locator, backend and proof stay in the record for raw readers, as
		// Origin's address and user agent do.
		if rec.Outcome == "success" {
			if rec.Anchor == nil {
				return "anchor record without coverage"
			}
			if rec.Anchor.RunID != "" {
				// Run-scoped: Seq is a count of the run's events, not a
				// control-chain position. Every recorded string is cleaned.
				return fmt.Sprintf("run %s anchored: events %d %s (%s)", origin.Clean(rec.Anchor.RunID), rec.Anchor.Seq, origin.Clean(rec.Anchor.Hash), origin.Clean(rec.Anchor.Kind))
			}
			return fmt.Sprintf("head anchored: seq %d %s (%s)", rec.Anchor.Seq, rec.Anchor.Hash, rec.Anchor.Kind)
		}
		return "anchor " + rec.Outcome
	case "restore":
		// A restore puts a sealed segment's own bytes back from its protected
		// copy; it is not a repair and taints nothing. The detail (which
		// segment, from which version, what was moved aside) is appended by
		// Render as for prune.
		if rec.Outcome == "success" {
			return "restored a sealed segment from its protected copy"
		}
		return "restore " + rec.Outcome
	default:
		return rec.Action
	}
}

// flipLabel renders an enable/disable record: "<pastTense> agent <x>" on
// success, or "<verb> agent <x> <outcome>" otherwise (e.g. "disable agent
// coder refused") — the action never appears to have completed when it
// was refused or errored. A successful flip marked Bootstrap ran while
// nothing was installed: it edited the configuration directory and installed
// nothing, and says so — not "(bootstrap)", which on an apply means the
// opposite (that apply installed the first snapshot).
func flipLabel(verb, pastTense string, rec record) string {
	if rec.Outcome == "success" {
		if rec.Bootstrap {
			return fmt.Sprintf("%s agent %s (nothing installed; directory edited)", pastTense, rec.Agent)
		}
		return fmt.Sprintf("%s agent %s", pastTense, rec.Agent)
	}
	return fmt.Sprintf("%s agent %s %s", verb, rec.Agent, rec.Outcome)
}

// integrityLine renders the control ledger's final integrity line(s).
// Taint (IsTainted) is decidable independently of chain verification, so
// it is checked regardless of verr: on an otherwise-clean chain it
// replaces "verified" outright, and on a failed one it is reported
// alongside the fault, never instead of it (a torn+tainted log
// shows both facts). Every seq printed is the GLOBAL seq of the logical
// chain, which is the line number on a never-sealed ledger.
func integrityLine(v View, verr error) string {
	tainted, seq := IsTainted(v.Records)
	if verr == nil {
		if tainted {
			return fmt.Sprintf("control ledger integrity: TAINTED (repaired at seq %d)\n", seq)
		}
		if len(v.Sealed) > 0 {
			return fmt.Sprintf("control ledger integrity: verified (%d events, %d sealed segments)\n", v.Head.Count, len(v.Sealed))
		}
		return fmt.Sprintf("control ledger integrity: verified (%d events)\n", v.Head.Count)
	}
	var sb strings.Builder
	if tainted {
		fmt.Fprintf(&sb, "control ledger integrity: TAINTED (repaired at seq %d)\n", seq)
	}
	sb.WriteString(faultLine(verr))
	return sb.String()
}

// faultLine is the integrity line for a ledger that did not verify. A bare
// ledger error (a caller that reads one file) keeps today's two verdicts.
func faultLine(verr error) string {
	if se, ok := errors.AsType[*SetError](verr); ok {
		return setFaultLine(se)
	}
	if broken, ok := errors.AsType[*ledger.ChainBrokenError](verr); ok {
		// Unlike the run-log renderer (internal/audit), this renderer
		// displays a 1-indexed seq per event, and for a control log
		// seq == line, so the first bad record IS broken.Line itself —
		// printing Line-1 would point an auditor at the last good record
		// instead of the actual break.
		return fmt.Sprintf("control ledger integrity: BROKEN at seq %d\n", broken.Line)
	}
	if _, ok := errors.AsType[*ledger.TornError](verr); ok {
		return "control ledger integrity: TORN — last record incomplete\n"
	}
	return "control ledger integrity: BROKEN at event 0\n"
}

// setFaultLine is the one-line verdict on each segment-set fault. The full
// remedy is the SetError's own text; this line names the fault and where.
func setFaultLine(se *SetError) string {
	const p = "control ledger integrity: "
	switch se.Fault {
	case FaultBroken:
		if se.Segment == 0 {
			return fmt.Sprintf(p+"BROKEN at seq %d\n", se.Seq)
		}
		return fmt.Sprintf(p+"BROKEN at seq %d (segment %d)\n", se.Seq, se.Segment)
	case FaultTorn:
		if se.Segment == 0 {
			return p + "TORN — last record incomplete\n"
		}
		return fmt.Sprintf(p+"TORN (segment %d)\n", se.Segment)
	case FaultBoundary:
		if se.Segment == 0 {
			return p + "BOUNDARY BROKEN between the last sealed segment and the active\n"
		}
		return fmt.Sprintf(p+"BOUNDARY BROKEN between segments %d and %d\n", se.Segment-1, se.Segment)
	case FaultMissingSegment:
		return fmt.Sprintf(p+"SEGMENT %d MISSING\n", se.Segment)
	case FaultUnexpectedSegment:
		return fmt.Sprintf(p+"UNEXPECTED SEGMENT %s\n", filepath.Base(se.Path))
	case FaultManifest:
		if se.Segment == 0 {
			return fmt.Sprintf(p+"MANIFEST invalid: %v\n", se.Err)
		}
		return fmt.Sprintf(p+"MANIFEST disagrees with segment %d: %v\n", se.Segment, se.Err)
	case FaultSealNotLast:
		if se.Segment == 0 {
			return fmt.Sprintf(p+"SEAL NOT LAST in the active segment (seal at seq %d)\n", se.Seq-1)
		}
		return fmt.Sprintf(p+"SEAL NOT LAST in segment %d (seal at seq %d)\n", se.Segment, se.Seq-1)
	}
	// FaultActiveMissing never reaches the renderer: callers print its text
	// instead, there being no ledger to render.
	return "control ledger integrity: BROKEN at event 0\n"
}

// Render renders the control ledger's valid prefix (records) of a
// never-sealed ledger; it is RenderView over a View that holds only them.
func Render(records []ledger.Record, head ledger.Head, verr error) string {
	return RenderView(View{Records: records, Head: head, FirstSeq: 1}, verr)
}

// headerLogID is the identity the header shows: the manifest's when the View
// carries one, else the genesis record's; "" for a root that has neither.
func headerLogID(v View) string {
	if v.LogID != "" {
		return v.LogID
	}
	id, err := GenesisLogID(v.Records)
	if err != nil {
		return ""
	}
	return id
}

// RenderView renders the ledger as one logical chain, as a human-readable
// audit trail: a header (the event count and the ledger's log_id
// when it has one), one `segment k: seq A–B sealed <time>
// <file>` line per sealed segment (only when there is one), the rotation
// state when a seal did not complete, one line per event carrying its
// derived label, invoker, and time, and a final integrity line. verr is
// Read's second return value — nil for a clean ledger, or the typed error
// (*SetError, or a bare *ledger.TornError / *ledger.ChainBrokenError) where
// verification stopped; either way, v holds whatever valid prefix was
// recovered and it is rendered in full.
func RenderView(v View, verr error) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "control ledger — %d events\n", v.Head.Count)
	// The ledger's identity, which a rebuild from the sink asks for. A root
	// written before ledgers carried one has none: no line, never an empty one.
	if id := headerLogID(v); id != "" {
		fmt.Fprintf(&sb, "log_id: %s\n", id)
	}
	sb.WriteString("\n")
	for _, s := range v.Sealed {
		fmt.Fprintf(&sb, "segment %d: seq %d–%d sealed %s %s\n", s.N, s.FirstSeq, s.HeadSeq, s.SealedAt.UTC().Format(time.RFC3339), filepath.Base(s.Path))
	}
	if v.State != StateOpen {
		fmt.Fprintf(&sb, "control ledger: segment %d sealed, rotation not completed; run: agenthof audit seal\n", v.RotatingSegment())
	}
	for _, r := range v.Records {
		var rec record
		if err := json.Unmarshal(r.Raw, &rec); err != nil {
			// ReadVerify only admits a record into the valid prefix once
			// its JSON has parsed for chain purposes; this is defensive,
			// not a path exercised by a real ledger.
			continue
		}
		// A control ledger spans days or months, unlike a single run's
		// ledger (internal/audit), so each line needs a full date, not
		// just a time of day; the seq is shown too so a reader can find
		// the record the integrity line's "repaired at seq K" names.
		t := rec.Time.UTC().Format("2006-01-02 15:04:05")
		// An API-recorded action names its way in beside the method; a CLI
		// record (no origin) renders exactly as before. The remote address
		// and user agent stay in the record for raw readers, not here.
		who := fmt.Sprintf("%s (%s)", rec.Invoker.Subject, rec.Invoker.Method)
		if rec.Origin != nil {
			who = fmt.Sprintf("%s (%s, via %s)", rec.Invoker.Subject, rec.Invoker.Method, rec.Origin.Via)
		}
		// A record with a detail renders it after the label, for any action:
		// the renderer does not know which actions set it.
		lbl := label(rec)
		if rec.Detail != "" {
			lbl += " (" + rec.Detail + ")"
		}
		fmt.Fprintf(&sb, "  seq %d  %s  %s — %s\n", rec.Seq, t, lbl, who)
	}
	sb.WriteString(integrityLine(v, verr))
	return sb.String()
}
