package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/authz"
	"github.com/agenthof/agenthof/internal/config"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/origin"
	"github.com/agenthof/agenthof/internal/sink"
)

// cmdAuditRestoreControl implements `audit restore control [--control-log
// <path>] [--config <dir>] [--as <user>] [--groups <a,b>] [--token <jwt>]
// [--segment N]... [--integrity <path>] [--sink-timeout <dur>] [--rebuild
// --log-id <id>]`: put a sealed segment of the control ledger back from the
// protected copy the sink holds, selected by the chain — or, with --rebuild,
// reconstruct the whole sealed set and its manifest from the sink alone. It
// is not a repair — nothing is truncated, the bytes written hash to what the
// manifest and the next segment already commit to — so it taints nothing;
// it is recorded, because a recovery is a visible, attributable act.
//
// Order, pinned (audit repair control's, with the sink):
//
//  1. the flags (exit 2): --rebuild requires --log-id and refuses --segment;
//  2. the invoker (--token without AGENTHOF_OIDC_ISSUER → exit 2); a refused
//     token is printed and NOT recorded — the root may be exactly the
//     damaged one;
//  3. authorization against the installed snapshot's byte-verified roles —
//     or --config's while nothing is installed — for the `repair` grant,
//     without consulting the ledger (repair's exemption, extended to the
//     recovery that restores what the ledger lost); a refusal is printed,
//     not recorded, and the caller learns nothing of the root;
//  4. the posture, read only now (a fault → exit 2; sink: local or absent →
//     `no sink configured`, exit 1): --integrity names a copy held off the
//     box, else integrity.yaml beside the ledger; the sink it names is built
//     (no network yet);
//  5. installed.lock EXCLUSIVE around the whole restore (busy → exit 1), as
//     the repair holds it, so no pointer writer and no seal runs alongside;
//  6. control.Restore: the verdict, the selection (every sink call), the
//     write under the active's lock, the re-read, the record — or
//     control.Rebuild: the verdict kept, the whole chain fetched and
//     verified before any write, the writes, the re-read, the record;
//  7. print per segment `restored: segment N from <kind> <url> version=<id>
//     sha256=<…> (<replaced name> | nothing was there)` with its information
//     lines beneath (not the oldest; unlocked; the manifest entry
//     disagrees), then the head line. A fault after a write prints the
//     segments written, then the fault, `NOT recorded`, exit 1. A rebuild
//     prints each UNDER-LOCKED ordinal, then `rebuilt: segments 1–N from
//     <kind> <url> (W written, R replaced)` with the evidence names kept,
//     then the head line; rebuilt but not recorded prints the fault with
//     its remedy, exit 1.
func cmdAuditRestoreControl(args []string, out io.Writer) int {
	if len(args) < 1 || args[0] != "control" {
		_, _ = fmt.Fprintln(out, "audit restore needs a subcommand: control")
		return 2
	}
	fs := flag.NewFlagSet("audit restore control", flag.ContinueOnError)
	controlLog := fs.String("control-log", ".agenthof/control.jsonl", "control-plane ledger path; integrity.yaml, installed/ and installed.lock are read from beside it")
	cfgDir := fs.String("config", "./config", "config directory; its roles decide who may restore only until a configuration is installed")
	as := fs.String("as", "", "invoker identity (defaults to the OS user); ignored when --token is given")
	groups := fs.String("groups", "", "comma-separated groups asserted for the --as identity; DEV ONLY — self-asserted, not verified, ignored when --token is given")
	token := fs.String("token", "", "raw OIDC token to authenticate the invoker (env AGENTHOF_TOKEN fallback); when set, identity comes from the token, not --as/--groups")
	var segments []int
	fs.Func("segment", "restore only this sealed segment (repeatable); refused when it is not the one at fault", func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return errors.New("--segment must be a positive integer")
		}
		segments = append(segments, n)
		return nil
	})
	integrity := fs.String("integrity", "", "read the sink posture from this copy of integrity.yaml instead of the one beside the ledger")
	sinkTimeout := fs.Duration("sink-timeout", 2*time.Minute, "bound on each call to the sink")
	rebuild := fs.Bool("rebuild", false, "reconstruct the whole sealed set and its manifest from the sink (with --log-id)")
	logID := fs.String("log-id", "", "with --rebuild: the ledger's identity, from the sealed:/control head: lines shipped off the box or the bucket listing")
	fs.SetOutput(out)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *rebuild {
		if *logID == "" {
			_, _ = fmt.Fprintln(out, "audit restore control: --rebuild requires --log-id <id> (the ledger's identity — from the sealed:/control head: lines shipped off the box, audit control's header, or the bucket listing)")
			return 2
		}
		if len(segments) > 0 {
			_, _ = fmt.Fprintln(out, "audit restore control: --segment cannot be combined with --rebuild")
			return 2
		}
	}

	inv, assertedAs, refused, usageErr, verifyErr := resolveInvoker(*as, *groups, *token)
	if usageErr {
		_, _ = fmt.Fprintln(out, "audit restore control: AGENTHOF_OIDC_ISSUER must be set in the environment to authenticate --token")
		return 2
	}
	if refused {
		_, _ = fmt.Fprintf(out, "audit restore control: token authentication failed: %v\n", verifyErr)
		return 1
	}

	// Authorization exactly as the repair's: the installed snapshot's roles,
	// byte-verified, without the ledger's vouch — or --config's while nothing
	// is installed. Nothing in this stretch appends, and the posture is read
	// only after it, so a refused caller learns nothing of the root.
	store := installedStore(*controlLog)
	roles, _, installed, instErr := config.InstalledRoles(store)
	if instErr != nil {
		_, _ = fmt.Fprintln(out, instErr)
		_, _ = fmt.Fprint(out, installedHatch("audit restore control", "restore", store))
		return 1
	}
	if !installed {
		cfg, loadErrs := config.LoadDir(*cfgDir)
		if len(loadErrs) > 0 {
			for _, e := range loadErrs {
				_, _ = fmt.Fprintln(out, e)
			}
			_, _ = fmt.Fprintf(out, "audit restore control: cannot read the configuration at %s; refusing to restore\n", *cfgDir)
			return 1
		}
		roles = cfg.Roles
	}
	if !authz.ControlAllows(roles, inv, "repair") {
		_, _ = fmt.Fprintf(out, "audit restore control: %s\n", control.NotAuthorized("repair").Message)
		return 1
	}

	path := integrityPath(*controlLog)
	var in config.Integrity
	var err error
	if *integrity != "" {
		path = *integrity
		in, err = loadIntegrityAt(path)
	} else {
		in, err = loadIntegrity(*controlLog)
	}
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit restore control: %v\n", err)
		return 2
	}
	if in.Sink != "worm" {
		_, _ = fmt.Fprintf(out, "audit restore control: no sink configured in %s; a protected copy exists only under sink: worm\n", path)
		return 1
	}
	be, err := sinkFor(in, *sinkTimeout)
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit restore control: %v\n", err)
		return 2
	}

	unlock, lockErr := ledger.LockFile(installedLock(*controlLog))
	if lockErr != nil {
		if errors.Is(lockErr, ledger.ErrLockHeld) {
			_, _ = fmt.Fprintf(out, "audit restore control: %s\n", msgLockBusy)
			return 1
		}
		_, _ = fmt.Fprintln(out, lockErr)
		return 1
	}
	event := control.Event{Action: "restore", Outcome: "success", Invoker: inv, AssertedAs: assertedAs, Witness: control.CaptureWitness()}
	if *rebuild {
		res, err := control.Rebuild(*controlLog, *logID, be, event)
		unlock()
		return printRebuilt(res, err, *controlLog, *logID, be, out)
	}
	res, err := control.Restore(*controlLog, segments, be, event)
	unlock()
	for _, s := range res.Restored {
		printRestored(s, out)
	}
	if err != nil {
		switch {
		case len(res.Restored) > 0:
			// Judged first: a busy re-read or append after a write must still
			// say the write happened and carry its cause.
			_, _ = fmt.Fprintf(out, "audit restore control: the segments above were written but NOT recorded — %v\n", err)
		case os.IsNotExist(err):
			_, _ = fmt.Fprintf(out, "no control ledger at %s — nothing recorded yet\n", *controlLog)
		case errors.Is(err, ledger.ErrLockHeld):
			_, _ = fmt.Fprintf(out, "audit restore control: %s\n", msgLockBusy)
		default:
			_, _ = fmt.Fprintf(out, "audit restore control: %v\n", err)
		}
		return 1
	}
	_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", res.Head.Count, res.Head.Hash)
	return 0
}

// printRebuilt prints a rebuild's outcome and returns the exit code. A
// rebuild that ran to its writes — recorded, or not (a *control.RebuildError)
// — prints each UNDER-LOCKED ordinal, then the `rebuilt:` line with the
// evidence names kept (printed, never recorded); the head line closes a
// recorded one. Rebuilt but not recorded names the fault: an active that no
// longer chains from the rebuilt head gets its remedy. Anything else is the
// refusal's own text, nothing written.
func printRebuilt(res control.RebuildResult, err error, controlLog, logID string, be sink.Backend, out io.Writer) int {
	var re *control.RebuildError
	if err == nil || errors.As(err, &re) {
		for _, k := range res.UnderLocked {
			_, _ = fmt.Fprintf(out, "segment %d: UNDER-LOCKED in the sink — the bytes are the chain's, but the lock is not what the posture claims\n", k)
		}
		line := fmt.Sprintf("rebuilt: segments 1–%d from %s %s (%d written, %d replaced)", res.Segments, origin.Clean(be.Kind()), origin.Clean(be.URL()), res.Written, res.Replaced)
		if len(res.ReplacedNames) > 0 {
			names := make([]string, len(res.ReplacedNames))
			for i, n := range res.ReplacedNames {
				names[i] = filepath.Base(n)
			}
			line += " kept at " + strings.Join(names, ", ")
		}
		_, _ = fmt.Fprintln(out, line)
	}
	switch {
	case err == nil:
		_, _ = fmt.Fprintf(out, "control head: seq=%d sha256=%s\n", res.Head.Count, res.Head.Hash)
		return 0
	case re != nil:
		var se *control.SetError
		if errors.As(re.Fault, &se) && se.Fault == control.FaultBoundary && se.Segment == 0 {
			_, _ = fmt.Fprintf(out, "audit restore control: rebuilt %d sealed segments; NOT recorded — the active does not chain from segment %d's head: move %s aside (its records are evidence, not chain), create an empty %s, then re-run audit restore control --rebuild --log-id %s to record the rebuild\n", res.Segments, res.Segments, controlLog, controlLog, logID)
			return 1
		}
		_, _ = fmt.Fprintf(out, "audit restore control: %v\n", err)
	case errors.Is(err, ledger.ErrLockHeld):
		_, _ = fmt.Fprintf(out, "audit restore control: %s\n", msgLockBusy)
	default:
		_, _ = fmt.Fprintf(out, "audit restore control: %v\n", err)
	}
	return 1
}

// printRestored prints one restored segment's line and the information
// lines beneath it. Kind, URL and the version id come from the sink and the
// record it holds; origin.Clean strips control characters before any of
// them reaches a terminal.
func printRestored(s control.RestoredSegment, out io.Writer) {
	kept := "nothing was there"
	if s.Replaced != "" {
		kept = filepath.Base(s.Replaced)
	}
	id := origin.Clean(s.VersionID)
	_, _ = fmt.Fprintf(out, "restored: segment %d from %s %s version=%s sha256=%s (%s)\n", s.N, origin.Clean(s.Sink.Kind), origin.Clean(s.Sink.URL), id, s.SHA256, kept)
	if s.NotOldest {
		_, _ = fmt.Fprintf(out, "selected version %s is not the oldest at the key — the oldest does not chain; verify will report LOCAL MISMATCH until the sink is examined\n", id)
	}
	if s.Unlocked {
		_, _ = fmt.Fprintf(out, "segment %d restored from an UNLOCKED version; the sink's lock is not what the posture claims\n", s.N)
	}
	if s.ManifestDisagrees {
		_, _ = fmt.Fprintf(out, "segment %d: the manifest's sha256 disagrees with the restored bytes (%s restored); the chain is the record — rewrite the manifest entry from audit verify control's output, or restore the manifest from a copy\n", s.N, s.SHA256)
	}
}
