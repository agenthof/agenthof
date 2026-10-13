package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// cmdConfigVouch is `config vouch`: make the control ledger vouch for the
// snapshot the pointer ALREADY names — the recovery for an unrecorded
// install (the install→record crash gap of an apply or a kill-switch flip, a
// record lost to a torn tail, a hand re-aim the operator judges legitimate).
// It byte-verifies the pointer, confirms the apply floor on the roles (some
// role grants apply to a named group — the one validation the roles alone can
// answer; Build is NOT run, so a flipped snapshot that references a disabled
// agent heals exactly as flipInstalled installed it), and, if and only if the
// ledger does not vouch for the pointer, appends a `vouch` install event for
// that exact hash. It moves no pointer, stages no bytes, touches no
// configuration directory. It is a bootstrap-class act (constitution,
// Article VI): permitted without a role grant, for any identity the host
// resolves — you cannot authorize against the very roles whose provenance is
// in doubt — a presented token that fails verification is still refused and
// recorded; always recorded under the invoker with the three identities, and
// the record's detail names what the ledger vouched for before. Local only,
// like config sign. Order, pinned: (1) the invoker; (1b) the root's
// integrity posture (reserved or unreadable: exit 2, unrecorded); (2) ledger writable
// (busy or damaged: unrecorded); (3) a refused token (recorded); (4) the
// installed-configuration writer lock, EXCLUSIVE, held through the append
// and the sign step — a reader must never see the pair mid-vouch; (5) the
// roles read, byte-verified (fault: recorded error with the hatch; nothing
// installed: unrecorded); (6) the apply floor (recorded rejected); (7) the
// vouch itself (busy/damaged unrecorded; already on record → exit 0,
// unrecorded, idempotent for scripts; not on record → continue); (8) the
// append; (9) sign when a key is configured. Exit 0 vouched or already
// vouched; 1 every refusal or fault; 2 usage.
func cmdConfigVouch(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("config vouch", flag.ContinueOnError)
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; the installed configuration is read from installed/ beside it")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC token (ID token, or an access token minted for AGENTHOF_OIDC_AUDIENCE) to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// 1. The invoker.
	inv, assertedAs, refused, usageErr, verifyErr := resolveInvoker(*as, *groups, *token)
	if usageErr {
		_, _ = fmt.Fprintln(out, "config vouch: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}
	// 1b. The root's integrity posture, before the ledger-writable check:
	// its fault is exit 2 and the command's own; the helper's contract
	// (false ⇒ exit 1) is untouched.
	if _, err := loadIntegrity(*controlLog); err != nil {
		_, _ = fmt.Fprintf(out, "config vouch: %v\n", err)
		return 2
	}
	// 2. The ledger must be writable before anything is recorded.
	if !controlLedgerWritable("config vouch", *controlLog, out) {
		return 1
	}

	// record appends this invocation's terminal event. The chain is known
	// writable, so recorded outcome and exit disagree only on an append that
	// itself fails.
	record := func(outcome string, reason *control.Reason, hash, detail string, code int) int {
		head, appendErr := control.Append(*controlLog, control.Event{
			Action:     "vouch",
			Outcome:    outcome,
			Reason:     reason,
			Invoker:    inv,
			AssertedAs: assertedAs,
			Witness:    control.CaptureWitness(),
			ConfigHash: hash,
			Detail:     detail,
		})
		if appendErr != nil {
			_, _ = fmt.Fprintln(out, appendErr)
			if outcome == "success" {
				_, _ = fmt.Fprintln(out, "vouch NOT recorded")
			}
			return 1
		}
		_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
		return code
	}

	// 3. A refused token: the recorded reason is fixed (the OIDC error can
	// echo claim values from the unverified token); only the printed line
	// shows it.
	if refused {
		_, _ = fmt.Fprintf(out, "config vouch: token authentication failed: %v\n", verifyErr)
		return record("refused", &control.Reason{Code: control.CodeTokenVerificationFailed, Message: "token verification failed"}, "", "", 1)
	}

	// 4. The writer lock, held to the end: an apply or flip racing this
	// command waits (bounded) and then sees the vouched pair whole.
	unlock, lockErr := ledger.LockFile(installedLock(*controlLog))
	if lockErr != nil {
		if errors.Is(lockErr, ledger.ErrLockHeld) {
			_, _ = fmt.Fprintf(out, "config vouch: %s\n", msgLockBusy)
			return 1
		}
		_, _ = fmt.Fprintln(out, lockErr)
		return record("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(lockErr)}, "", "", 1)
	}
	defer unlock()

	// 5. The pointer and its roles, byte-verified. A fault is the rm-current
	// hatch — never vouching: bytes that do not hash as the pointer are never
	// blessed.
	store := installedStore(*controlLog)
	roles, hash, installed, instErr := config.InstalledRoles(store)
	if instErr != nil {
		_, _ = fmt.Fprintln(out, instErr)
		_, _ = fmt.Fprint(out, installedHatch("config vouch", "vouch", store))
		return record("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(instErr)}, "", "", 1)
	}
	if !installed {
		_, _ = fmt.Fprintf(out, "config vouch: nothing is installed under %s; nothing to vouch for\n", store)
		return 1
	}

	// 6. The apply floor — what Build carried for apply, restated over the
	// roles alone, so a vouched snapshot can never be a control-plane lockout.
	if errs := applyFloorErrors(config.Config{Roles: roles}); len(errs) > 0 {
		for _, e := range errs {
			_, _ = fmt.Fprintln(out, e.Error())
		}
		return record("rejected", &control.Reason{Code: control.CodeValidationFailed, Message: truncateErr(errs[0])}, hash, "", 1)
	}

	// 7. Does the ledger vouch already? The same definition every reader uses.
	_, last, refusal := vouchInstalled(*controlLog, hash)
	switch {
	case refusal == nil:
		_, _ = fmt.Fprintf(out, "config vouch: %s is already on record (%s, version %d); nothing to do\n", hash, installLabel(last), last.Seq)
		return 0
	case refusal.Transient():
		_, _ = fmt.Fprintf(out, "config vouch: %s\n", msgLockBusy)
		return 1
	case refusal.Kind != verifyNotOnRecord:
		// Damaged or unreadable past step 2 — a race; the hint is inside.
		_, _ = fmt.Fprintf(out, "config vouch: %s\n", refusal.Error())
		return 1
	}
	detail := "no install on record"
	if last.ConfigHash != "" {
		// A comma, not parentheses: the renderer appends "(<detail>)".
		detail = fmt.Sprintf("previously on record: %s, %s", last.ConfigHash, installLabel(last))
	}

	// 8. The record — the ONE thing a vouch writes.
	_, _ = fmt.Fprintf(out, "vouched: %s\n", hash)
	if code := record("success", nil, hash, detail, 0); code != 0 {
		return code
	}

	// 9. Sign, as every installer does after its record; the vouch stands if
	// the signature cannot be written.
	info, signed, err := signIfConfigured(*controlLog)
	if err != nil {
		_, _ = fmt.Fprintf(out, "signature NOT written: %v; %s\n", err, signRemedy(*controlLog, err))
		return 1
	}
	if signed {
		_, _ = fmt.Fprintf(out, "signed: key_id %s\n", info.KeyID)
	}
	return 0
}
