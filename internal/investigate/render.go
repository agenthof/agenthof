package investigate

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// ExitCode derives a process exit code from r's per-source integrity
// verdicts: 1 if any source is torn, broken, or unreadable (error) — this
// takes precedence over 3; else 3 if any source is tainted; else 0, meaning
// every source verified, or there were no sources at all (nothing recorded
// is not a problem). Completeness never changes the exit code (reserved for
// a later contract change).
func ExitCode(r Result) int {
	_, fatal, tainted := integritySummary(r.Sources)
	switch {
	case fatal:
		return 1
	case tainted:
		return 3
	default:
		return 0
	}
}

// integritySummary classifies sources into a human-readable issue line per
// non-verified source, plus whether any source is fatal (torn/broken/error,
// or an integrity verdict this package doesn't recognize) and whether any is
// tainted. An unrecognized verdict is treated as fatal rather than silently
// read as clean, since a future verdict string must never render green by
// accident.
func integritySummary(sources []Source) (issues []string, fatal, tainted bool) {
	issues = []string{}
	for _, s := range sources {
		switch s.Integrity {
		case "verified":
			continue
		case "tainted":
			tainted = true
		case "torn", "broken", "error":
			fatal = true
		default:
			fatal = true
		}
		issues = append(issues, issueLine(s))
	}
	return issues, fatal, tainted
}

// sourceLabel names a source for operator-facing text: "control ledger" for
// the control log, or "run <id>" for a run log, with the id recovered from
// its file name.
func sourceLabel(s Source) string {
	if s.Kind == "control" {
		return "control ledger"
	}
	id := strings.TrimSuffix(filepath.Base(s.Path), ".jsonl")
	return fmt.Sprintf("run %s", id)
}

// issueLine renders one non-verified source as a human-readable line, used
// both in RenderJSON's integrity.issues and RenderText's trailing summary.
func issueLine(s Source) string {
	label := sourceLabel(s)
	switch s.Integrity {
	case "torn":
		return fmt.Sprintf("%s TORN at %s", label, s.Path)
	case "broken":
		return fmt.Sprintf("%s BROKEN", label)
	case "error":
		return fmt.Sprintf("%s read error", label)
	case "tainted":
		return fmt.Sprintf("%s TAINTED", label)
	default:
		return fmt.Sprintf("%s has unrecognized integrity %q", label, s.Integrity)
	}
}

// RenderText renders r as an operator-facing plain-text timeline: a header,
// one integrity summary line per source, one line per event, and a trailing
// overall integrity line, and — whenever an event in the view carries an
// anchor verdict — a trailing count of those verdicts. It never claims more
// than the evidence supports — a torn or broken source is named as a gap in
// the record, not papered over.
func RenderText(r Result) string {
	var b strings.Builder

	fmt.Fprintf(&b, "investigation timeline: %d event(s) across %d source(s)\n", len(r.Events), len(r.Sources))

	for _, s := range r.Sources {
		comp := ""
		if s.Completeness != "" {
			comp = " completeness=" + s.Completeness
		}
		fmt.Fprintf(&b, "source: %s %s integrity=%s%s count=%d\n", s.Kind, s.Path, s.Integrity, comp, s.Count)
	}

	for _, e := range r.Events {
		// A spawned child is indented under its parent: two spaces per level
		// of depth, so the tree reads off the left margin.
		fmt.Fprintf(&b, "%s%s %s %s — %s (%s)", strings.Repeat("  ", e.Depth),
			e.Time.UTC().Format(time.RFC3339), e.Source, e.Kind, e.Invoker.Subject, e.Invoker.Method)

		var tags []string
		if e.Agent != "" {
			tags = append(tags, "agent="+e.Agent)
		}
		if e.Outcome != "" {
			tags = append(tags, "outcome="+e.Outcome)
		}
		if e.Reason != "" {
			tags = append(tags, "reason="+e.Reason)
		}
		if e.ParentRunID != "" {
			tags = append(tags, "parent="+e.ParentRunID)
		}
		// An anchor record's facts and verdict, each present iff recorded:
		// a failed attempt shows what it tried; a planted success record
		// without a payload shows its verdict and cause only. cause= is last:
		// it carries spaces, as reason= already does. The hash is printed
		// whole — it is the value an operator compares with the anchored:
		// line shipped off the box.
		if a := e.Anchor; a != nil {
			if a.Seq != 0 || a.Hash != "" {
				tags = append(tags, fmt.Sprintf("anchor=%d:%s", a.Seq, a.Hash))
			}
			if a.Backend != "" {
				tags = append(tags, "backend="+a.Backend)
			}
			if a.Ref != "" {
				tags = append(tags, "ref="+a.Ref)
			}
			if a.Verdict != "" {
				tags = append(tags, "verdict="+a.Verdict)
			}
			if a.Cause != "" {
				tags = append(tags, "cause="+a.Cause)
			}
		}
		if len(tags) > 0 {
			fmt.Fprintf(&b, " [%s]", strings.Join(tags, " "))
		}
		b.WriteString("\n")
	}

	issues, fatal, tainted := integritySummary(r.Sources)
	if !fatal && !tainted {
		b.WriteString("integrity: OK\n")
	} else {
		fmt.Fprintf(&b, "integrity: %s\n", strings.Join(issues, "; "))
	}

	// The honesty trailer: an unqualified "integrity: OK" after a whole-root
	// re-forge would imply more trust than this view earns — the re-forged
	// chain verifies; only the anchor line says mismatch. So whenever the
	// view carries an anchor verdict, one more line states the count, in the
	// gate's own summary phrase. Counted over the events in the view and
	// nothing else, so a document decoded from JSON prints the same trailer
	// from the same events; a verdict word this build does not know counts
	// as unverifiable, never as verified.
	var anchors, verified, mismatch, unverifiable int
	for _, e := range r.Events {
		if e.Anchor == nil || e.Anchor.Verdict == "" {
			continue
		}
		anchors++
		switch e.Anchor.Verdict {
		case "verified":
			verified++
		case "mismatch":
			mismatch++
		default:
			unverifiable++
		}
	}
	if anchors > 0 {
		fmt.Fprintf(&b, "anchors: %d (%d verified, %d mismatch, %d unverifiable)\n", anchors, verified, mismatch, unverifiable)
	}

	return b.String()
}

// envelope is the top-level investigate/1 JSON object.
type envelope struct {
	V         string        `json:"v"`
	Query     queryJSON     `json:"query"`
	Sources   []sourceJSON  `json:"sources"`
	Events    []Record      `json:"events"`
	Integrity integrityJSON `json:"integrity"`
}

// queryJSON reflects only the Filter fields that were actually set; a zero
// value (empty string, nil time) is omitted rather than rendered as its
// zero-ish JSON form, so the object names exactly what was asked for.
type queryJSON struct {
	Since      string `json:"since,omitempty"`
	Until      string `json:"until,omitempty"`
	Invoker    string `json:"invoker,omitempty"`
	Agent      string `json:"agent,omitempty"`
	Outcome    string `json:"outcome,omitempty"`
	Run        string `json:"run,omitempty"`
	ConfigHash string `json:"config_hash,omitempty"`
}

// sourceJSON is Source's JSON shape (Source itself carries no json tags).
type sourceJSON struct {
	Path         string `json:"path"`
	Kind         string `json:"kind"`
	Integrity    string `json:"integrity"`
	Completeness string `json:"completeness,omitempty"`
	Count        int    `json:"count"`
}

// integrityJSON is the envelope's overall integrity verdict: ok mirrors
// ExitCode(r)==0 exactly, and issues names every non-verified source.
type integrityJSON struct {
	OK     bool     `json:"ok"`
	Issues []string `json:"issues"`
}

// RenderJSON renders r as the investigate/1 JSON contract: the query that
// produced it (set filters only), a per-source integrity summary, the
// merged events, and an overall integrity verdict whose ok field always
// equals ExitCode(r)==0. All timestamps are RFC3339 UTC.
func RenderJSON(r Result, f Filter) (string, error) {
	q := queryJSON{
		Invoker:    f.Invoker,
		Agent:      f.Agent,
		Outcome:    f.Outcome,
		Run:        f.Run,
		ConfigHash: f.ConfigHash,
	}
	if f.Since != nil {
		q.Since = f.Since.UTC().Format(time.RFC3339)
	}
	if f.Until != nil {
		q.Until = f.Until.UTC().Format(time.RFC3339)
	}

	sources := make([]sourceJSON, 0, len(r.Sources))
	for _, s := range r.Sources {
		sources = append(sources, sourceJSON(s))
	}

	// Copy events rather than mutating r.Events in place: normalizing Time
	// to UTC for the JSON contract must not surprise the caller holding r.
	events := make([]Record, 0, len(r.Events))
	for _, e := range r.Events {
		e.Time = e.Time.UTC()
		events = append(events, e)
	}

	issues, _, _ := integritySummary(r.Sources)
	env := envelope{
		V:       "investigate/1",
		Query:   q,
		Sources: sources,
		Events:  events,
		Integrity: integrityJSON{
			OK:     ExitCode(r) == 0,
			Issues: issues,
		},
	}

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
