package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/agenthof/agenthof/internal/authz"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

// sizeRE is --if-larger-than's grammar: a non-negative integer with an
// optional single k/m/g suffix (case-insensitive, 1024-based).
var sizeRE = regexp.MustCompile(`^([0-9]+)([kKmMgG])?$`)

// parseSize parses --if-larger-than; ok is false outside the grammar or on
// overflow.
func parseSize(s string) (int64, bool) {
	m := sizeRE.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	shift := map[string]uint{"": 0, "k": 10, "m": 20, "g": 30}[strings.ToLower(m[2])]
	if shift > 0 && n > (1<<63-1)>>shift {
		return 0, false
	}
	return n << shift, true
}

// cmdAuditSeal is `audit seal`: close the control ledger's active segment
// into a sealed file and open the next, the chain continuing unbroken. Order,
// pinned (audit anchor's order with the seal steps added):
//
//  1. the invoker (--token without AGENTHOF_OIDC_ISSUER → exit 2) and the
//     --if-larger-than grammar (exit 2), unrecorded;
//  2. the posture (a fault → exit 2);
//  3. the set, writable: busy → exit 1 unrecorded; a torn active → the
//     repair hint; ErrSealed (state B or C) → a COMPLETION run: steps 4–5,
//     then CompleteSeal, every refusal printed and not recorded (the closed
//     segment takes no record and the next does not exist); the threshold
//     does not apply to a completion;
//  4. a refused token → recorded refused;
//  5. the authorization read under installed.lock EXCLUSIVE, held to the
//     end: nothing installed → recorded refused; a store fault → recorded
//     error + the hatch; not on record → recorded refused; no seal grant →
//     recorded refused;
//  6. --if-larger-than by a stat of the name: not larger → printed, exit 0,
//     nothing recorded (after authorization, so every refusal is recorded
//     and an authorized cron's no-op leaves no record);
//  7. steps 7 to 11 are control.SealActive on one held chain (or
//     CompleteSeal): the empty check, the link, the record, the manifest,
//     the swap;
//  12. print `sealed: segment N seq=A..B sha256=<file> (<name>)` and the
//     head line — the head is the seal record; a completion prints
//     `completed rotation of segment N` first.
func cmdAuditSeal(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("audit seal", flag.ContinueOnError)
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; integrity.yaml, installed/ and installed.lock are read from beside it; the sealed segments and the manifest are created beside it")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC token to authenticate the invoker (env AGENTHOF_TOKEN fallback); a production cron presents this, not --as/--groups")
	ifLarger := fs.String("if-larger-than", "", "seal only if the active segment is strictly larger than this size (bytes; k, m or g suffix, 1024-based); otherwise print and exit 0, nothing recorded")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	inv, assertedAs, refused, usageErr, verifyErr := resolveInvoker(*as, *groups, *token)
	if usageErr {
		_, _ = fmt.Fprintln(out, "audit seal: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}
	threshold := int64(-1)
	if flagGiven(fs, "if-larger-than") {
		n, ok := parseSize(*ifLarger)
		if !ok {
			_, _ = fmt.Fprintln(out, "audit seal: --if-larger-than must be a non-negative integer with an optional k, m or g suffix")
			return 2
		}
		threshold = n
	}
	if _, err := loadIntegrity(*controlLog); err != nil {
		_, _ = fmt.Fprintf(out, "audit seal: %v\n", err)
		return 2
	}

	completing := false
	switch werr := control.Writable(*controlLog); {
	case werr == nil:
	case errors.Is(werr, control.ErrSealed):
		completing = true
	default:
		printWritableFault("audit seal", *controlLog, "", werr, out) // busy, the repair hint, or the fault's text — the set was read once
		return 1
	}

	record := func(outcome string, reason *control.Reason, code int) int {
		if completing {
			return code // a refused completion is printed, not recorded
		}
		head, appendErr := control.Append(*controlLog, control.Event{
			Action: "seal", Outcome: outcome, Reason: reason,
			Invoker: inv, AssertedAs: assertedAs, Witness: control.CaptureWitness(),
		})
		if appendErr != nil {
			_, _ = fmt.Fprintln(out, appendErr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", head.Count, head.Hash)
		return code
	}

	if refused {
		_, _ = fmt.Fprintf(out, "audit seal: token authentication failed: %v\n", verifyErr)
		return record("refused", &control.Reason{Code: control.CodeTokenVerificationFailed, Message: "token verification failed"}, 1)
	}

	// The authorization read under installed.lock EXCLUSIVE, held to the end:
	// no pointer writer is ever caught between its state change and its
	// success append by this seal. Lock order store → ledger.
	store := installedStore(*controlLog)
	unlock, lockErr := ledger.LockFile(installedLock(*controlLog))
	if lockErr != nil {
		if errors.Is(lockErr, ledger.ErrLockHeld) {
			_, _ = fmt.Fprintf(out, "audit seal: %s\n", msgLockBusy)
			return 1
		}
		_, _ = fmt.Fprintln(out, lockErr)
		return record("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(lockErr)}, 1)
	}
	defer unlock()
	installedRoles, hash, installed, instErr := config.InstalledRoles(store)
	if instErr != nil {
		_, _ = fmt.Fprintln(out, instErr)
		_, _ = fmt.Fprint(out, installedHatch("audit seal", "seal", store))
		return record("error", &control.Reason{Code: control.CodeIOError, Message: truncateErr(instErr)}, 1)
	}
	if !installed {
		_, _ = fmt.Fprintf(out, "audit seal: %s\n", msgNothingInstalled)
		_, _ = fmt.Fprintf(out, "%s under %s; run: agenthof apply --config <dir> --control-log %s\n", msgNoConfigInstalled, store, *controlLog)
		return record("refused", &control.Reason{Code: control.CodeNotAuthorized, Message: msgNothingInstalled}, 1)
	}
	if _, _, refusal := vouchInstalled(*controlLog, hash); refusal != nil {
		switch {
		case refusal.Transient():
			_, _ = fmt.Fprintf(out, "audit seal: %s\n", msgLockBusy)
			return 1
		case refusal.Kind != verifyNotOnRecord:
			_, _ = fmt.Fprintf(out, "audit seal: %s\n", refusal.Error())
			return 1
		}
		_, _ = fmt.Fprintf(out, "audit seal: %s\n", refusal.Error())
		return record("refused", vouchRefused(refusal), 1)
	}
	if !authz.ControlAllows(installedRoles, inv, "seal") {
		reason := control.NotAuthorized("seal")
		_, _ = fmt.Fprintf(out, "audit seal: %s\n", reason.Message)
		return record("refused", reason, 1)
	}

	if !completing && threshold >= 0 {
		info, err := os.Stat(*controlLog)
		if err != nil {
			_, _ = fmt.Fprintf(out, "audit seal: %v\n", err)
			return 1
		}
		if info.Size() <= threshold {
			_, _ = fmt.Fprintf(out, "audit seal: active segment is %d bytes, not larger than %s; nothing sealed\n", info.Size(), *ifLarger)
			return 0
		}
	}

	var res control.SealResult
	var err error
	if completing {
		res, err = control.CompleteSeal(*controlLog)
	} else {
		res, err = control.SealActive(*controlLog, control.Event{Action: "seal", Outcome: "success", Invoker: inv, AssertedAs: assertedAs, Witness: control.CaptureWitness()})
	}
	if err != nil {
		return printSealFailure(err, out)
	}
	if res.Completed {
		_, _ = fmt.Fprintf(out, "completed rotation of segment %d\n", res.Segment)
	}
	_, _ = fmt.Fprintf(out, "sealed: segment %d seq=%d..%d sha256=%s (%s)\n", res.Segment, res.FirstSeq, res.HeadSeq, res.SHA256, filepath.Base(res.Path))
	_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", res.HeadSeq, res.HeadHash)
	return 0
}

// flagGiven reports whether name was set on the command line (so an empty
// --if-larger-than= is usage rather than "no threshold").
func flagGiven(fs *flag.FlagSet, name string) bool {
	given := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			given = true
		}
	})
	return given
}

// printSealFailure prints the fixed line for a seal that did not complete and
// returns 1. A link failure recorded nothing; a record failure left the
// segment open; a manifest or swap failure left state B or C, which a re-run
// completes; a set fault names its own remedy.
func printSealFailure(err error, out io.Writer) int {
	var se *control.SealError
	switch {
	case errors.Is(err, control.ErrNothingToSeal):
		_, _ = fmt.Fprintln(out, "audit seal: the active segment is empty; nothing to seal")
	case errors.Is(err, ledger.ErrLockHeld):
		_, _ = fmt.Fprintf(out, "audit seal: %s\n", msgLockBusy)
	case errors.Is(err, control.ErrUnsealable):
		_, _ = fmt.Fprintf(out, "audit seal: %v\n", err)
	case errors.As(err, &se) && (se.Step == control.SealStepManifest || se.Step == control.SealStepSwap):
		_, _ = fmt.Fprintf(out, "audit seal: %v\n", err)
		_, _ = fmt.Fprintln(out, "audit seal: sealed; rotation NOT completed — re-run: agenthof audit seal")
	default:
		_, _ = fmt.Fprintf(out, "audit seal: %v\n", err)
	}
	return 1
}
