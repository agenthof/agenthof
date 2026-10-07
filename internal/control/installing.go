package control

// Installing reports whether e put a snapshot in place: a successful apply,
// or a successful kill-switch flip that ran against an installed snapshot.
// A flip marked Bootstrap ran while nothing was installed — it edited the
// configuration directory and recorded that directory's hash, installing
// nothing — so it is not an install, whatever its hash. This is the ONE
// definition both readers use: cmd/agenthof's installed-pointer verdict
// (audit control / audit verify control exit 5) and internal/investigate's
// run config-join; they must never drift from each other.
func Installing(e DecodedEvent) bool {
	return e.Outcome == "success" && e.ConfigHash != "" &&
		(e.Action == "apply" || ((e.Action == "enable" || e.Action == "disable") && !e.Bootstrap))
}
