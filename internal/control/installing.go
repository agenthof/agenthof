package control

import "github.com/agenthof/agenthof/internal/ledger"

// Installing reports whether e put a snapshot in place: a successful apply,
// or a successful kill-switch flip that ran against an installed snapshot.
// A flip marked Bootstrap ran while nothing was installed — it edited the
// configuration directory and recorded that directory's hash, installing
// nothing — so it is not an install, whatever its hash. This is the ONE
// definition the three readers use: cmd/agenthof's installed-pointer
// verdict (audit control / audit verify control exit 5), the configuration
// pull's version and vouching (through LastInstalling), and
// internal/investigate's run config-join; they must never drift from each
// other.
func Installing(e DecodedEvent) bool {
	return e.Outcome == "success" && e.ConfigHash != "" &&
		(e.Action == "apply" || ((e.Action == "enable" || e.Action == "disable") && !e.Bootstrap))
}

// LastInstalling returns the last record in records that Installing
// accepts — the event that put the current snapshot in place, if the ledger
// recorded it — with its Seq and Time. A record Decode rejects is skipped,
// not fatal: the verdict is taken over the decodable history, exactly as the
// audit readers take it. ok is false when no record installs anything.
func LastInstalling(records []ledger.Record) (last DecodedEvent, ok bool) {
	for _, r := range records {
		d, err := Decode(r.Raw)
		if err != nil {
			continue
		}
		if Installing(d) {
			last, ok = d, true
		}
	}
	return last, ok
}
