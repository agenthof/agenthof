package investigate

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/ledger"
)

// Filter narrows Timeline's output. Since/Until bound the event time window
// (Since inclusive, Until exclusive); nil means unbounded on that side. Each
// string field, when non-empty, is matched exactly against the
// corresponding Record field — no normalization, no substring matching.
type Filter struct {
	Since, Until                             *time.Time
	Invoker, Agent, Outcome, Run, ConfigHash string
}

// Source summarizes one input that Timeline drew evidence from: a run log
// or the control log.
type Source struct {
	Path      string
	Kind      string // "run" | "control"
	Integrity string // "verified" | "torn" | "broken" | "tainted" | "error"
	Count     int    // valid-prefix records parsed from this source, before Filter is applied
}

// Result is Timeline's output: the merged, filtered records plus a
// per-source integrity summary.
type Result struct {
	Events  []Record
	Sources []Source
}

// Timeline enumerates every run log under logDir plus the control log at
// controlLog, normalizes and merges their events into one deterministically
// ordered stream, and applies f.
//
// Evidence is never silently dropped: a torn or broken source still
// contributes its valid prefix and is listed in Result.Sources with its
// verdict, rather than aborting the whole timeline. The control log is
// loaded independently of run-log enumeration, so a runs directory that
// doesn't exist yet (nothing has run) means zero run sources, not an empty
// timeline — a control log that already has recorded applies must still
// surface.
func Timeline(logDir, controlLog string, f Filter) (Result, error) {
	var records []Record
	var sources []Source

	entries, err := os.ReadDir(logDir)
	switch {
	case err == nil:
		// fall through to enumeration below
	case os.IsNotExist(err):
		// No runs directory yet: zero run sources, not an error — the
		// control log below is still consulted.
		entries = nil
	default:
		return Result{}, err
	}

	for _, entry := range entries {
		name := entry.Name()
		// Mirror pruneRuns' skip rules: never touch the control ledger or
		// its torn-repair fragments, directories, or non-log files.
		if name == "control.jsonl" || strings.Contains(name, ".torn-") {
			continue
		}
		if entry.IsDir() || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		runID := strings.TrimSuffix(name, ".jsonl")
		if f.Run != "" && runID != f.Run {
			continue
		}

		// mtime prefilter (spec §4): Since-only, with slack for coarse-mtime
		// filesystems. NEVER prefilter on Until — a run that started
		// before Until but finished at/after it still holds pre-Until
		// events that must appear; only the per-event predicate below may
		// drop those on Until's account.
		if f.Since != nil {
			info, ierr := entry.Info()
			if ierr == nil && info.ModTime().Add(2*time.Second).Before(*f.Since) {
				continue
			}
			// A stat failure here doesn't earn a skip: treat the file as
			// non-prefilterable and let the real parse below decide.
		}

		path := filepath.Join(logDir, name)
		events, _, rerr := engine.ReadLog(logDir, runID)
		switch {
		case rerr == nil:
			sources = append(sources, Source{Path: path, Kind: "run", Integrity: "verified", Count: len(events)})
		case errors.Is(rerr, os.ErrNotExist):
			// Pruned between ReadDir and read: no source to report, not
			// an error.
			continue
		default:
			if _, ok := errors.AsType[*ledger.TornError](rerr); ok {
				sources = append(sources, Source{Path: path, Kind: "run", Integrity: "torn", Count: len(events)})
			} else if _, ok := errors.AsType[*ledger.ChainBrokenError](rerr); ok {
				sources = append(sources, Source{Path: path, Kind: "run", Integrity: "broken", Count: len(events)})
			} else {
				// An IO error on a source that exists must surface (spec
				// §5), not be swallowed.
				sources = append(sources, Source{Path: path, Kind: "run", Integrity: "error", Count: 0})
			}
		}

		for i, e := range events {
			records = append(records, normalizeRun(e, i))
		}
	}

	controlEvents, verdict, ok := LoadControl(controlLog)
	if ok {
		// A missing control log (ok==false) means "nothing recorded" and
		// is omitted from Sources entirely (spec §5) — never listed with
		// a synthetic "missing" integrity value.
		sources = append(sources, Source{Path: controlLog, Kind: "control", Integrity: verdict, Count: len(controlEvents)})
		for _, d := range controlEvents {
			records = append(records, normalizeControl(d))
		}
	}

	// spec §4: sort key is (Time, Source, RunID, pos) via a stable sort,
	// compared with Before/Equal (never ==). Source is compared as a plain
	// string, which happens to place "control" before "run" alphabetically —
	// matching the intent that a control apply at time T precedes a run
	// event at T. RunID discriminates different runs that would otherwise
	// tie on (Time, Source, pos); pos is unique within a single source.
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if !a.Time.Equal(b.Time) {
			return a.Time.Before(b.Time)
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.RunID != b.RunID {
			return a.RunID < b.RunID
		}
		return a.pos < b.pos
	})

	var out []Record
	for _, r := range records {
		if matches(r, f) {
			out = append(out, r)
		}
	}

	return Result{Events: out, Sources: sources}, nil
}

// matches applies f's exact-match predicates to r. Time.Before is used
// throughout rather than ==, since time.Time values that represent the same
// instant need not be identical in representation.
func matches(r Record, f Filter) bool {
	if f.Since != nil && r.Time.Before(*f.Since) {
		return false
	}
	if f.Until != nil && !r.Time.Before(*f.Until) {
		return false
	}
	if f.Invoker != "" && r.Invoker.Subject != f.Invoker {
		return false
	}
	if f.Agent != "" && r.Agent != f.Agent {
		return false
	}
	if f.Outcome != "" && r.Outcome != f.Outcome {
		return false
	}
	if f.Run != "" && r.RunID != f.Run {
		return false
	}
	if f.ConfigHash != "" && r.ConfigHash != f.ConfigHash {
		return false
	}
	return true
}
