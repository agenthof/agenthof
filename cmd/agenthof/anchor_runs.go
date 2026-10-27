package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/anchor"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/sidecar"
)

// runAnchorOpts is the run-anchoring forms' flags: --log-dir for both, then
// either --run (runID) or --pending (with its --limit).
type runAnchorOpts struct {
	logDir  string
	runID   string // --run
	pending bool   // --pending
	limit   int    // --limit, default 50
}

// runAnchorOutcome is what anchoring one run came to. The first and the last
// four say what reached disk; the middle two say whether a sweep may go on.
type runAnchorOutcome int

const (
	runAnchored        runAnchorOutcome = iota // sidecar written, control record landed
	runNotAnchorable                           // unterminated / torn / broken / pruned mid-pass: nothing written, nothing recorded
	runSubmitFailed                            // per-entry rejection: the log ANSWERED and refused THIS head; anchor error recorded; the sweep goes on
	runTransportFailed                         // PASS-FATAL: the log did not answer; anchor error recorded; the sweep stops here
	runBackendFailed                           // PASS-FATAL: the backend could not be built or its credential not resolved — it recurs identically for every run; anchor error recorded; the sweep stops here
	runProofNotWritten                         // anchored at the log, sidecar write failed: error recorded
	runNotRecorded                             // anchored, sidecar written, control Append failed
)

// classifySubmitFault says whether a Submit failure is the log refusing this
// head (runSubmitFailed — the next run may well succeed) or a fault that every
// later run would meet identically (a log that does not answer, a credential
// the broker could not resolve), which a sweep must stop on rather than record
// once per run.
func classifySubmitFault(err error) runAnchorOutcome {
	var tr *anchor.Transport
	var ce *anchorCredentialError
	switch {
	case errors.As(err, &tr):
		return runTransportFailed
	case errors.As(err, &ce):
		return runBackendFailed
	}
	return runSubmitFailed
}

// recordFault appends one anchor error record naming what was tried and
// returns the head it produced; an append failure is printed and yields the
// zero head (no record landed, so no head line may claim one).
func (s *anchorSession) recordFault(code string, err error, tried *control.Anchor) ledger.Head {
	head, appendErr := s.record("error", &control.Reason{Code: code, Message: truncateErr(err)}, tried)
	if appendErr != nil {
		_, _ = fmt.Fprintln(s.out, appendErr)
		return ledger.Head{}
	}
	return head
}

// anchorRun is the per-run body, steps 7–10: read the finished run's ledger,
// submit its final head, write the proof beside it, record the run-scoped
// success. It prints the per-run failure lines itself and returns the lines to
// ship on success; head is the control head of the record it appended (the
// success or the error), zero when none landed. The caller holds the
// run-anchoring lock.
func (s *anchorSession) anchorRun(logDir, id string) (outcome runAnchorOutcome, shipped []string, head ledger.Head) {
	out, in := s.out, s.in

	// 7. The run's head. A run ledger has one writer and no repair: only a
	// whole chain that ends at its final event is anchorable.
	chain, runHead, err := ledger.ReadVerify(filepath.Join(logDir, id+".jsonl"), ledger.Unlocked)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		_, _ = fmt.Fprintf(out, "audit anchor: no run %s under %s\n", id, logDir)
		return runNotAnchorable, nil, ledger.Head{}
	case err != nil:
		_, _ = fmt.Fprintf(out, "audit anchor: run %s: %v; a run ledger has no repair — not anchorable\n", id, err)
		return runNotAnchorable, nil, ledger.Head{}
	case !sidecar.FinalEvent(chain):
		_, _ = fmt.Fprintf(out, "audit anchor: run %s has no final event; still running or tail lost — not anchorable\n", id)
		return runNotAnchorable, nil, ledger.Head{}
	}
	covered := anchor.Head{Seq: runHead.Count, Hash: runHead.Hash}
	tried := &control.Anchor{RunID: id, Seq: covered.Seq, Hash: covered.Hash, Kind: "tlog", BackendKind: in.AnchorBackend.Kind, Backend: strings.TrimSuffix(in.AnchorBackend.URL, "/")}

	// 8. Network happens only from here.
	be, err := newAnchorBackend(backendSpec{Kind: in.AnchorBackend.Kind, URL: in.AnchorBackend.URL, Key: s.pub, Credential: in.AnchorBackend.Credential})
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: run %s: %v\n", id, err)
		return runBackendFailed, nil, s.recordFault(control.CodeAnchorFailed, err, tried)
	}
	tried.BackendKind = be.Kind()
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	rcpt, err := be.Submit(ctx, covered)
	cancel()
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: run %s: %v\n", id, err)
		return classifySubmitFault(err), nil, s.recordFault(control.CodeAnchorFailed, err, tried)
	}

	// 9. The proof beside the run, written atomically.
	rec := sidecar.Record{
		Time: time.Now().UTC(), RunID: id, Seq: covered.Seq, Hash: covered.Hash, Kind: "tlog",
		BackendKind: be.Kind(), Backend: rcpt.Backend, Ref: rcpt.Ref, Proof: rcpt.Proof, BackendKeyID: rcpt.BackendKeyID,
		AnchoredBy: sidecar.Actor{Subject: s.inv.Subject, Issuer: s.inv.Issuer, Method: s.inv.Method},
	}
	if err := sidecar.Append(sidecar.Path(logDir, id), id, rec); err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: run %s: anchored at %s but the run's proof could NOT be written beside it: %v\n", id, rcpt.Ref, err)
		return runProofNotWritten, nil, s.recordFault(control.CodeIOError, err, tried)
	}

	// 10. The governance record: run-scoped, and without the proof — that
	// lives beside the run.
	payload := &control.Anchor{RunID: id, Seq: covered.Seq, Hash: covered.Hash, Kind: "tlog", BackendKind: be.Kind(), Backend: rcpt.Backend, Ref: rcpt.Ref, BackendKeyID: rcpt.BackendKeyID}
	recorded, err := s.record("success", nil, payload)
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: anchored run %s and its proof is beside the receipt, but the control ledger did NOT record it: %v\n", id, err)
		return runNotRecorded, nil, ledger.Head{}
	}
	logLine, indexLine := receiptLines(rcpt, s.keyMode)
	return runAnchored, []string{
		fmt.Sprintf("anchored run %s: events=%d sha256=%s", id, covered.Seq, covered.Hash),
		logLine,
		indexLine,
	}, recorded
}

// anchorRuns is the run-anchoring forms after the shared preamble: the
// run-anchoring lock (step 6), then the body, then the shipped lines.
func (s *anchorSession) anchorRuns(o runAnchorOpts) int {
	// Both forms serialize on one host-level lock, taken after the
	// authorization read (installed.lock is released by now) and held through
	// the last control Append, so overlapping passes cannot file one head twice.
	unlock, err := ledger.LockFile(sidecar.LockPath(o.logDir))
	if err != nil {
		if errors.Is(err, ledger.ErrLockHeld) {
			_, _ = fmt.Fprintf(s.out, "audit anchor: another agenthof process is anchoring runs under %s; retry\n", o.logDir)
			return 1
		}
		_, _ = fmt.Fprintf(s.out, "audit anchor: %v\n", err)
		return 1
	}
	defer unlock()

	if o.pending {
		return s.anchorPending(o.logDir, o.limit)
	}
	outcome, shipped, head := s.anchorRun(o.logDir, o.runID)
	if outcome == runAnchored {
		return s.finish(shipped, head, 0)
	}
	if head.Count > 0 { // an error record landed: the head line is still true
		return s.finish(nil, head, 1)
	}
	return 1
}

// anchorPending is the sweep, run under the run-anchoring lock: every run
// under logDir that has no sidecar yet is a candidate, taken in name order
// and filed through anchorRun, so each run is filed once — a run with a
// sidecar is never a candidate again, whatever the cron's interval.
//
//   - runAnchored is counted and its lines are printed as they land;
//   - runNotAnchorable (unterminated, torn, gone) is reported by the body,
//     counted as skipped and does NOT count against limit: a run that is still
//     running must not eat the pass's budget;
//   - runSubmitFailed, runProofNotWritten and runNotRecorded are failures that
//     count against limit; the pass goes on to the next run;
//   - runTransportFailed and runBackendFailed are failures every later run
//     would meet identically, so the pass stops there and leaves the rest for
//     the next one: an outage costs one error record, not one per run.
//
// remaining is the candidates not attempted. Exit 0 iff nothing failed, which
// includes an empty pass and a pass cut short by limit (the next tick
// continues); a pass stopped by a pass-fatal fault exits 1.
func (s *anchorSession) anchorPending(logDir string, limit int) int {
	out := s.out
	ctlInfo, err := statControlLog(s.controlLog)
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: control log %s: %v\n", s.controlLog, err)
		return 1
	}
	candidates, err := sidecar.Candidates(logDir, ctlInfo)
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: %v\n", err)
		return 1
	}

	anchored, skipped, failed, attempts, handled := 0, 0, 0, 0, 0
	for _, id := range candidates {
		if attempts >= limit {
			break
		}
		handled++
		outcome, shipped, _ := s.anchorRun(logDir, id)
		switch outcome {
		case runAnchored:
			anchored++
			attempts++
			for _, l := range shipped {
				_, _ = fmt.Fprintln(out, l)
			}
		case runNotAnchorable:
			skipped++
		default:
			failed++
			attempts++
		}
		if outcome == runTransportFailed || outcome == runBackendFailed {
			break
		}
	}
	remaining := len(candidates) - handled
	_, _ = fmt.Fprintf(out, "pending: %d anchored, %d skipped (not anchorable), %d remaining\n", anchored, skipped, remaining)

	// The head is read once, after the last append, even when this pass
	// appended nothing: the line every control writer ends on.
	v, err := control.Read(s.controlLog, ledger.Locked)
	if err != nil {
		_, _ = fmt.Fprintf(out, "audit anchor: %v\n", err)
		return 1
	}
	code := 0
	if failed > 0 {
		code = 1
	}
	return s.finish(nil, v.Head, code)
}
