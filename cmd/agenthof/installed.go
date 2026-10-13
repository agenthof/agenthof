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

// installedLock is the installed-configuration lock for a control ledger:
// "installed.lock" BESIDE the store (never inside it, so a store listing
// holds only snapshots and the pointer). Every pointer writer — apply (CLI
// or API) and the kill switch — and every writer of the ledger's account of
// the pointer — config sign, config vouch — takes it EXCLUSIVE through
// ledger.LockFile
// from its authorize-read through its success append; every execution read
// (run, serve's Prepare and startup look) and the authorization reads of
// gateway provision and runs prune take it SHARED through
// ledger.LockFileShared across pointer, ledger (and .sig, floor) so it sees
// the consistent pair a writer publishes, and creates the file on a root
// nothing has applied to yet. The file is empty and never removed; a prune
// of this directory must not take it for an orphan. Derived here, next to
// installedStore, and nowhere else.
func installedLock(controlLog string) string {
	return filepath.Join(filepath.Dir(controlLog), "installed.lock")
}

// msgNoConfigInstalled is run's fixed refusal reason — printed, ledgered,
// and (as serve.ErrNoConfigInstalled) answered 422 — when the control root
// has nothing installed. No paths: the hint line beside it names them.
const msgNoConfigInstalled = "no configuration installed"

// exitInstalledMismatch is audit verify control's exit code when the
// installed pointer does not name the last recorded install — the last
// event control.Installing accepts: an apply, a vouch, or a kill-switch flip
// against an installed snapshot — checked after the chain (1), taint (3) and
// --expect-head (4) verdicts.
const exitInstalledMismatch = 5

// installedHatch is the one escape-hatch line a control command prints after
// config.InstalledRoles reports a store fault — a malformed pointer, a
// snapshot that is gone, or bytes that do not hash as the pointer — so every
// command names the same way out: remove the pointer and re-bootstrap. It
// names the FULL pointer path. Never printed for a not-on-record verdict,
// which has its own remedy (config vouch): a byte fault is never healed by
// vouching, and naming vouch here would misdirect.
func installedHatch(prefix, verb, store string) string {
	return fmt.Sprintf("%s: cannot read the installed configuration under %s; refusing to %s (remove %s to re-bootstrap)\n",
		prefix, store, verb, filepath.Join(store, config.InstalledPointer))
}

// applyFloorErrors is the no-apply-floor check: some role must grant apply
// to a NAMED group — a configuration nobody may apply could be installed and
// then never be changed again through the control plane, so it is rejected
// at the install boundary. "Named" means a literal group, never the "*"
// marker, which authz.ControlAllows does not honour: it restates exactly the
// two rules registry.Validate already enforces for apply (no-access-floor,
// public-control-role), so for apply the check is redundant — Build runs
// first — and for config vouch, which never runs Build, it is the ONE
// validation the roles alone can answer: without it a correctly hashed
// snapshot could be vouched into a lockout no apply could install. There is
// deliberately no empty-string rule: Validate has none, and the floor must
// not be a new apply rejection. It lives here and NOT in registry.Validate on
// purpose — Validate also serves run, serve and registry list, which must
// keep accepting a run-only configuration that grants nothing.
func applyFloorErrors(cfg config.Config) []registry.ValidationError {
	for _, r := range cfg.Roles {
		if !slices.Contains(r.Control, "apply") {
			continue
		}
		for _, g := range r.AllowedGroups {
			if g != "*" {
				return nil
			}
		}
	}
	return []registry.ValidationError{{
		File:   "roles",
		Entity: "(config)",
		Code:   "no-apply-floor",
		Msg:    "no role grants apply to a named group: a configuration nobody may apply could never be changed again; grant control: [apply] to at least one role whose allowed_groups names a real group",
	}}
}

// installedPointerLine renders the audit readers' one-line verdict on the
// installed pointer: nothing when no store exists (nothing has ever been
// installed under this control root), otherwise whether the pointer names
// the LAST install the ledger recorded — the last event control.Installing
// accepts, so a vouch (which makes the ledger stand behind the pointer) and a
// kill-switch flip (which installs a re-snapshot) count and a bootstrap-era flip (which edited the directory and installed nothing) does
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
	last, found := control.LastInstalling(records)
	switch {
	case !found:
		return fmt.Sprintf("installed config: %s — no install on record: the install was not recorded, or its record was lost\n", hash), true
	case last.ConfigHash != hash:
		return fmt.Sprintf("installed config: %s — does NOT match the last recorded install (%s, %s): the install was not recorded, or its record was lost\n", hash, last.ConfigHash, installLabel(last)), true
	}
	return fmt.Sprintf("installed config: %s — matches the last recorded install (%s)\n", hash, installLabel(last)), false
}

// installLabel names an installing event for the audit readers: "apply",
// "vouch", or "<disable|enable> agent <name>" for a kill-switch flip. It is
// only ever called on LastInstalling's result, so the default branch is
// unreachable for any action Installing does not accept — an anchor record
// never arrives here, because the predicate upstream excludes it.
func installLabel(d control.DecodedEvent) string {
	switch d.Action {
	case "apply", "vouch":
		return d.Action
	}
	return d.Action + " agent " + d.Agent
}
