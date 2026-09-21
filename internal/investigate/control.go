package investigate

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// LoadControl reads+verifies the control log. Returns the decoded valid-prefix
// events, an integrity verdict ("verified"|"torn"|"broken"|"tainted"|
// "missing"|"error"), and ok=false only when the file is MISSING
// (os.IsNotExist). A torn/broken log returns its valid prefix + verdict,
// ok=true.
//
// verdict "error" covers a present-but-unreadable file (e.g. a permissions
// error, or any other open/IO failure ReadVerify surfaces that is neither
// "not exist" nor a torn/broken chain). The file exists, so ok is true per
// the "ok=false only when MISSING" rule above; ConfigJoin treats "error"
// the same as "missing"/"torn"/"broken" (spec §5: an IO error on an
// existing source is treated like torn/broken).
func LoadControl(path string) (events []control.DecodedEvent, verdict string, ok bool) {
	recs, _, err := ledger.ReadVerify(path, ledger.Locked)
	if err != nil {
		var torn *ledger.TornError
		var broken *ledger.ChainBrokenError
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil, "missing", false
		case errors.As(err, &torn):
			verdict = "torn"
		case errors.As(err, &broken):
			verdict = "broken"
		default:
			verdict = "error"
		}
	} else if tainted, _ := control.IsTainted(recs); tainted {
		verdict = "tainted"
	} else {
		verdict = "verified"
	}

	for _, r := range recs {
		d, derr := control.Decode(r.Raw)
		if derr != nil {
			// The valid prefix from ReadVerify should always decode; if it
			// somehow doesn't, stop here and return what decoded so far
			// rather than panicking or silently dropping the mismatch.
			break
		}
		events = append(events, d)
	}
	return events, verdict, true
}

// ConfigJoin implements spec §2: the join line for a run whose
// workflow_started carries runHash at runStart. verdict is LoadControl's
// verdict.
func ConfigJoin(events []control.DecodedEvent, verdict string, runHash string, runStart time.Time) string {
	switch verdict {
	case "missing", "torn", "broken", "error":
		return fmt.Sprintf("config %s — control ledger unavailable", runHash)
	}

	var latest *control.DecodedEvent
	nonApplyFlip := false
	for i := range events {
		e := &events[i]
		if e.ConfigHash != runHash {
			continue
		}
		if e.Action == "apply" && e.Outcome == "success" && !e.Time.After(runStart) {
			// events is in ledger seq order (monotonically increasing
			// append time), so the last qualifying event in iteration
			// order is the latest one — no need to compare Time here,
			// which would add a clock dependency the chain itself
			// doesn't have.
			latest = e
			continue
		}
		if e.Action != "apply" {
			// A non-apply event (enable/disable, ...) with a matching
			// hash: regardless of its own outcome/time, it earns the
			// "matches a later enable/disable, not an apply" wording
			// below. A later or failed *apply* with a matching hash is
			// deliberately NOT routed here — spec §2's middle case is
			// specifically the non-apply flip; a later/failed apply
			// correctly falls through to the plain "no successful apply
			// on record" branch instead (there genuinely is no
			// successful apply on record at/before the run).
			nonApplyFlip = true
		}
	}

	if latest != nil {
		return fmt.Sprintf("config %s — applied by %s (%s) at %s",
			runHash, latest.Invoker.Subject, latest.Invoker.Method, latest.Time.Format(time.RFC3339))
	}
	if nonApplyFlip {
		return fmt.Sprintf("config %s — no successful apply on record (matches a later enable/disable, not an apply)", runHash)
	}
	return fmt.Sprintf("config %s — no successful apply on record", runHash)
}
