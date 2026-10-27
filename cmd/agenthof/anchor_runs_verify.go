package main

import (
	"crypto/ecdsa"
	"time"

	"github.com/agenthof/agenthof/internal/sidecar"
)

// verifyRunAnchor decides one run's anchor: only when sidecar.Path(logDir,
// runID) exists does it read the run's records (once, hash-verified,
// unlocked) and resolve the pin through key; a run with no sidecar touches
// neither, so an unanchored run never reads anchor.pub. The backend is built
// from each record's own backend_kind and backend through verifyBackendFactory
// — never integrity.yaml. The bool is Pinned: the resolved key was non-nil.
// key should be a sync.OnceValues over pinnedLogKey, shared across a tree.
func verifyRunAnchor(logDir, runID string, key func() (*ecdsa.PublicKey, error), offline bool, timeout time.Duration) (sidecar.Verdict, bool) {
	return sidecar.VerifyRun(logDir, runID, key, verifyBackendFactory, offline, timeout)
}

// runAnchorExit is the worst anchor verdict in a tree: 6 if any is a
// mismatch, else 7 if any is unverifiable, else 0 (verified, and not
// anchored, are 0).
func runAnchorExit(root sidecar.Verdict, children []sidecar.Verdict) int {
	worst := sidecar.Exit(root)
	for _, c := range children {
		switch sidecar.Exit(c) {
		case exitAnchorMismatch:
			return exitAnchorMismatch
		case exitAnchorUnverifiable:
			worst = exitAnchorUnverifiable
		}
	}
	return worst
}

// runExitCode folds a run's verdicts into one exit by the audit commands'
// precedence 1 > 6 > 11 > 12 > 4 > 7 > 0: the run's own torn or broken chain
// (or a descendant's) outranks everything; a definitive anchor verdict
// outranks completeness (the anchor is a verdict on the whole chain, a gap one
// inside it); every definitive verdict outranks the one transient; 12 keeps
// its place before 4 (a live run's head legitimately differs from any recorded
// expectation) and 7 comes after 4. comp is completeness.ExitCode(tree);
// anchor is runAnchorExit.
func runExitCode(comp, anchor int, expectFailed bool) int {
	switch {
	case comp == 1:
		return 1
	case anchor == exitAnchorMismatch:
		return exitAnchorMismatch
	case comp != 0:
		return comp // 11, then 12
	case expectFailed:
		return 4
	case anchor == exitAnchorUnverifiable:
		return exitAnchorUnverifiable
	}
	return 0
}
