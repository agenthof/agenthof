package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/agenthof/agenthof/internal/ledger"
)

// IsTainted reports whether any of records carries action "repair", and,
// if so, the seq of the FIRST such record. A repair record means the
// ledger was regenerated after damage — that fact is decidable purely
// from file contents (spec §3.6) and, once true, is reported forever:
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
// action/outcome pair (spec §3.6). It never claims a state change that
// didn't happen: enable/disable/repair only get their past-tense label on
// outcome "success" — every other outcome is worded around the action,
// not past it.
func label(rec record) string {
	switch rec.Action {
	case "apply":
		switch rec.Outcome {
		case "success":
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
	default:
		return rec.Action
	}
}

// flipLabel renders an enable/disable record: "<pastTense> agent <x>" on
// success, or "<verb> agent <x> <outcome>" otherwise (e.g. "disable agent
// coder refused") — the action never appears to have completed when it
// was refused or errored.
func flipLabel(verb, pastTense string, rec record) string {
	if rec.Outcome == "success" {
		return fmt.Sprintf("%s agent %s", pastTense, rec.Agent)
	}
	return fmt.Sprintf("%s agent %s %s", verb, rec.Agent, rec.Outcome)
}

// integrityLine renders the control ledger's final integrity line(s).
// Taint (IsTainted) is decidable independently of chain verification, so
// it is checked regardless of verr: on an otherwise-clean chain it
// replaces "verified" outright, and on a torn/broken chain it is reported
// alongside the torn/broken fact, never instead of it (spec §3.6: "a
// torn+tainted log shows both facts").
func integrityLine(records []ledger.Record, head ledger.Head, verr error) string {
	tainted, seq := IsTainted(records)
	if verr == nil {
		if tainted {
			return fmt.Sprintf("control ledger integrity: TAINTED (repaired at seq %d)\n", seq)
		}
		return fmt.Sprintf("control ledger integrity: verified (%d events)\n", head.Count)
	}
	var sb strings.Builder
	if tainted {
		fmt.Fprintf(&sb, "control ledger integrity: TAINTED (repaired at seq %d)\n", seq)
	}
	if broken, ok := errors.AsType[*ledger.ChainBrokenError](verr); ok {
		// Unlike the run-log renderer (internal/audit), this renderer
		// displays a 1-indexed seq per event, and for a control log
		// seq == line, so the first bad record IS broken.Line itself —
		// printing Line-1 would point an auditor at the last good record
		// instead of the actual break.
		fmt.Fprintf(&sb, "control ledger integrity: BROKEN at seq %d\n", broken.Line)
		return sb.String()
	}
	if _, ok := errors.AsType[*ledger.TornError](verr); ok {
		sb.WriteString("control ledger integrity: TORN — last record incomplete\n")
		return sb.String()
	}
	sb.WriteString("control ledger integrity: BROKEN at event 0\n")
	return sb.String()
}

// Render renders the control ledger's valid prefix (records) as a
// human-readable audit trail: a header, one line per event carrying its
// derived label, invoker, and time, and a final integrity line (spec
// §3.6). head and verr are ReadVerify's second and third return values —
// verr is nil for a clean ledger, or the typed ledger error
// (*ledger.TornError / *ledger.ChainBrokenError) describing where
// verification stopped; either way, records is whatever valid prefix was
// recovered and is rendered in full.
func Render(records []ledger.Record, head ledger.Head, verr error) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "control ledger — %d events\n\n", head.Count)
	for _, r := range records {
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
		fmt.Fprintf(&sb, "  seq %d  %s  %s — %s (%s)\n", rec.Seq, t, label(rec), rec.Invoker.Subject, rec.Invoker.Method)
	}
	sb.WriteString(integrityLine(records, head, verr))
	return sb.String()
}
