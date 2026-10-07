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

// ConfigJoin renders the join line for a run whose workflow_started carries
// runHash at runStart; verdict is LoadControl's. The run's install is the
// LAST installing event (control.Installing: a successful apply, or a
// successful kill-switch flip against an installed snapshot) in ledger
// order whose hash equals the run's and whose time is not after the run's
// start — events is in seq order, so the last qualifying event is the latest
// install with no clock comparison. Five forms, verbatim in
// docs/reference/config.md: applied by (an apply); installed by … (kill
// switch: …) (a flip); no install on record at the run's start (the hash
// matches only later installs — the install→record gap re-installed later,
// or clock skew — known but not vouched for at run time); no install on
// record; control ledger unavailable.
func ConfigJoin(events []control.DecodedEvent, verdict string, runHash string, runStart time.Time) string {
	switch verdict {
	case "missing", "torn", "broken", "error":
		return fmt.Sprintf("config %s — control ledger unavailable", runHash)
	}

	var install *control.DecodedEvent
	later := false
	for i := range events {
		e := &events[i]
		if e.ConfigHash != runHash || !control.Installing(*e) {
			continue
		}
		if e.Time.After(runStart) {
			later = true
			continue
		}
		install = e
	}

	switch {
	case install == nil && later:
		return fmt.Sprintf("config %s — no install on record at the run's start (matches a later apply or kill-switch flip)", runHash)
	case install == nil:
		return fmt.Sprintf("config %s — no install on record", runHash)
	case install.Action == "apply":
		return fmt.Sprintf("config %s — applied by %s (%s) at %s",
			runHash, install.Invoker.Subject, install.Invoker.Method, install.Time.Format(time.RFC3339))
	}
	state := "disabled"
	if install.Action == "enable" {
		state = "enabled"
	}
	return fmt.Sprintf("config %s — installed by %s (%s) at %s (kill switch: %s agent %s)",
		runHash, install.Invoker.Subject, install.Invoker.Method, install.Time.Format(time.RFC3339), state, install.Agent)
}
