package main

import (
	"fmt"
	"path/filepath"
	"slices"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/registry"
)

// installedStore is the installed-config store for a control ledger: the
// "installed" directory beside it (default .agenthof/installed/). One store
// per control root, derived here and nowhere else, so apply, the kill
// switch, repair and the audit readers can never disagree about where the
// installed configuration lives.
func installedStore(controlLog string) string {
	return filepath.Join(filepath.Dir(controlLog), "installed")
}

// msgInstalledNotRecorded is apply's analogue of the kill switch's "state
// changed; event NOT recorded": the snapshot is installed and the pointer
// flipped, but the success event could not be appended. audit control and
// audit verify control surface the resulting pointer-vs-ledger mismatch.
const msgInstalledNotRecorded = "installed; event NOT recorded"

// msgNoConfigInstalled is run's fixed refusal reason — printed, ledgered,
// and (as serve.ErrNoConfigInstalled) answered 422 — when the control root
// has nothing installed. No paths: the hint line beside it names them.
const msgNoConfigInstalled = "no configuration installed"

// exitInstalledMismatch is audit verify control's exit code when the
// installed pointer does not name the last recorded successful apply —
// checked after the chain (1), taint (3) and --expect-head (4) verdicts.
const exitInstalledMismatch = 5

// applyFloorErrors is the no-apply-floor check: a configuration that grants
// apply to no role could be installed and then never be changed again
// through the control plane, so it is rejected at the apply boundary. It
// lives here and NOT in registry.Validate on purpose — Validate also serves
// run, serve and registry list, which must keep accepting a run-only
// configuration that grants nothing. It is a property of what may be
// installed, so it sits on the install path.
func applyFloorErrors(cfg config.Config) []registry.ValidationError {
	for _, r := range cfg.Roles {
		if slices.Contains(r.Control, "apply") {
			return nil
		}
	}
	return []registry.ValidationError{{
		File:   "roles",
		Entity: "(config)",
		Code:   "no-apply-floor",
		Msg:    "no role grants apply: a configuration nobody may apply could never be changed again; grant control: [apply] to at least one role",
	}}
}

// installedPointerLine renders the audit readers' one-line verdict on the
// installed pointer: nothing when no store exists (nothing has ever been
// installed under this control root), otherwise whether the pointer names
// the LAST successful apply the ledger recorded. Only apply records are
// compared — a kill-switch flip rewrites the config directory and records
// the directory's new hash, which legitimately differs from the installed
// snapshot. mismatch is true for a pointer the ledger cannot vouch for: the
// install→record gap, a lost tail, or a damaged pointer.
func installedPointerLine(controlLog string, records []ledger.Record) (line string, mismatch bool) {
	hash, installed, err := config.InstalledHash(installedStore(controlLog))
	if err != nil {
		return fmt.Sprintf("installed config: %v\n", err), true
	}
	if !installed {
		return "", false
	}
	last := ""
	for _, r := range records {
		d, derr := control.Decode(r.Raw)
		if derr != nil {
			continue
		}
		if d.Action == "apply" && d.Outcome == "success" {
			last = d.ConfigHash
		}
	}
	switch {
	case last == "":
		return fmt.Sprintf("installed config: %s — no successful apply on record: the install was not recorded, or its record was lost\n", hash), true
	case last != hash:
		return fmt.Sprintf("installed config: %s — does NOT match the last recorded apply (%s): the install was not recorded, or its record was lost\n", hash, last), true
	}
	return fmt.Sprintf("installed config: %s — matches the last recorded apply\n", hash), false
}
