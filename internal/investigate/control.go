package investigate

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// LoadControl reads+verifies the control ledger as one logical chain across
// its sealed segments and the active (control.Read, the same segment-set
// view audit verify control uses). Returns the decoded valid-prefix events,
// an integrity verdict ("verified"|"torn"|"broken"|"tainted"|"missing"|
// "error"), and ok=false only when there is no control ledger at all — no
// active, no manifest, no segment. A torn or broken ledger returns its valid
// prefix + verdict, ok=true.
//
// Verdicts over a segment set: a torn active is "torn"; every other set
// fault — a broken or missing sealed segment, a boundary that does not chain,
// an unexpected segment file, a manifest that disagrees with the files, a
// seal that is not last, a root with history whose active is gone — is a
// chain the reader cannot walk whole, so "broken". A rotation interrupted
// after the chain was fully written (a seal not yet rotated) still reads as
// one verified chain.
//
// verdict "error" covers a present-but-unreadable ledger (e.g. a permissions
// error, or any other open/IO failure control.Read surfaces that is neither
// "not exist" nor a set fault). The ledger exists, so ok is true per the
// "ok=false only when MISSING" rule above; ConfigJoin treats "error" the same
// as "missing"/"torn"/"broken" (spec §5: an IO error on an existing source is
// treated like torn/broken).
func LoadControl(path string) (events []control.DecodedEvent, verdict string, ok bool) {
	_, events, verdict, ok = loadControl(path)
	return events, verdict, ok
}

// loadControl is LoadControl with the valid-prefix records kept beside the
// decoded events: the anchor verdict hashes record bytes
// (control.CheckAnchors), so Timeline needs them, while LoadControl's other
// callers do not.
func loadControl(path string) (records []ledger.Record, events []control.DecodedEvent, verdict string, ok bool) {
	v, err := control.Read(path, ledger.Locked)
	recs := v.Records
	if err != nil {
		var se *control.SetError
		switch {
		case !errors.As(err, &se) && errors.Is(err, os.ErrNotExist):
			return nil, nil, "missing", false
		case errors.As(err, &se) && se.Fault == control.FaultTorn && se.Segment == 0:
			verdict = "torn"
		case errors.As(err, &se):
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
			// The valid prefix from control.Read should always decode; if it
			// somehow doesn't, stop here and return what decoded so far
			// rather than panicking or silently dropping the mismatch.
			break
		}
		events = append(events, d)
	}
	return recs, events, verdict, true
}

// ConfigJoin renders the join line for a run whose workflow_started carries
// runHash at runStart; verdict is LoadControl's. The run's install is the
// LAST installing event (control.Installing: a successful apply, a
// successful kill-switch flip against an installed snapshot, or a successful
// vouch) in ledger order whose hash equals the run's and whose time is not
// after the run's start — events is in seq order, so the last qualifying
// event is the latest install with no clock comparison. The forms rendered
// here: applied by (an apply); installed by … (kill switch: …) (a flip);
// vouched for by … (a vouch); no install on record at
// the run's start (the hash matches only later installs — the install→record
// gap re-installed later, or clock skew — known but not vouched for at run
// time); no install on record; control ledger unavailable.
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
		return fmt.Sprintf("config %s — no install on record at the run's start (matches a later apply, kill-switch flip or vouch)", runHash)
	case install == nil:
		return fmt.Sprintf("config %s — no install on record", runHash)
	case install.Action == "apply":
		return fmt.Sprintf("config %s — applied by %s (%s) at %s",
			runHash, install.Invoker.Subject, install.Invoker.Method, install.Time.Format(time.RFC3339))
	case install.Action == "vouch":
		return fmt.Sprintf("config %s — vouched for by %s (%s) at %s",
			runHash, install.Invoker.Subject, install.Invoker.Method, install.Time.Format(time.RFC3339))
	}
	state := "disabled"
	if install.Action == "enable" {
		state = "enabled"
	}
	return fmt.Sprintf("config %s — installed by %s (%s) at %s (kill switch: %s agent %s)",
		runHash, install.Invoker.Subject, install.Invoker.Method, install.Time.Format(time.RFC3339), state, install.Agent)
}
