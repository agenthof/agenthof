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

// installedLock is the installed-configuration writer lock for a control
// ledger: "installed.lock" BESIDE the store (never inside it, so a store
// listing holds only snapshots and the pointer). Every pointer writer —
// apply (CLI or API) and the kill switch — takes it through
// ledger.LockFile from its authorize-read through its success append. The
// file is empty and never removed; a prune of this directory must not take
// it for an orphan. Derived here, next to installedStore, and nowhere else.
func installedLock(controlLog string) string {
	return filepath.Join(filepath.Dir(controlLog), "installed.lock")
}

// msgNoConfigInstalled is run's fixed refusal reason — printed, ledgered,
// and (as serve.ErrNoConfigInstalled) answered 422 — when the control root
// has nothing installed. No paths: the hint line beside it names them.
const msgNoConfigInstalled = "no configuration installed"

// exitInstalledMismatch is audit verify control's exit code when the
// installed pointer does not name the last recorded install — the last
// event control.Installing accepts: an apply, or a kill-switch flip against
// an installed snapshot — checked after the chain (1), taint (3) and
// --expect-head (4) verdicts.
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
// the LAST install the ledger recorded — the last event control.Installing
// accepts, so a kill-switch flip (which installs a re-snapshot) counts and a
// bootstrap-era flip (which edited the directory and installed nothing) does
// not. mismatch is true for a pointer the ledger cannot vouch for: the
// install→record gap, a lost tail, or a damaged pointer. The verdict is
// pointer-vouched at check time, not history-complete: a later recorded
// install clears an earlier gap from it.
func installedPointerLine(controlLog string, records []ledger.Record) (line string, mismatch bool) {
	hash, installed, err := config.InstalledHash(installedStore(controlLog))
	if err != nil {
		return fmt.Sprintf("installed config: %v\n", err), true
	}
	if !installed {
		return "", false
	}
	var last *control.DecodedEvent
	for _, r := range records {
		d, derr := control.Decode(r.Raw)
		if derr != nil {
			continue
		}
		if control.Installing(d) {
			last = &d
		}
	}
	switch {
	case last == nil:
		return fmt.Sprintf("installed config: %s — no install on record: the install was not recorded, or its record was lost\n", hash), true
	case last.ConfigHash != hash:
		return fmt.Sprintf("installed config: %s — does NOT match the last recorded install (%s, %s): the install was not recorded, or its record was lost\n", hash, last.ConfigHash, installLabel(*last)), true
	}
	return fmt.Sprintf("installed config: %s — matches the last recorded install (%s)\n", hash, installLabel(*last)), false
}

// installLabel names an installing event for the audit readers: "apply", or
// "<disable|enable> agent <name>" for a kill-switch flip.
func installLabel(d control.DecodedEvent) string {
	if d.Action == "apply" {
		return "apply"
	}
	return d.Action + " agent " + d.Agent
}
