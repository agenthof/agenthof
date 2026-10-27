package sidecar

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/agenthof/agenthof/internal/anchorverify"
	"github.com/agenthof/agenthof/internal/control"
	"github.com/agenthof/agenthof/internal/ledger"
)

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Check is the run-shaped structural check: one control.AnchorCheck per
// record, RecordSeq = the record's 1-based line, so anchorverify.Decide
// judges a sidecar exactly as it judges a control ledger's anchors. A record
// is believed only if the ledger reproduces it; per record, first fault only:
//
//   - the record must name this run;
//   - its hash must be a lowercase hex sha256;
//   - its seq must equal the ledger's event count. This is also the range
//     check, and it runs before any indexing: a seq beyond the chain, or any
//     record against a zero-event chain, is a mismatch, never a panic;
//   - sha256 of the ledger's event at seq must equal the hash;
//   - that event must be the run's final event.
//
// chain must be the hash-verified output of ledger.ReadVerify: Check trusts
// its records' bytes as the ledger and verifies nothing about the chain itself.
//
// The Anchor each check carries is copied from the record, so Decide verifies
// the stored proof the way it verifies a control record's.
func Check(runID string, chain []ledger.Record, recs []Record) []control.AnchorCheck {
	var out []control.AnchorCheck
	for i, r := range recs {
		c := control.AnchorCheck{
			RecordSeq: i + 1,
			Anchor: &control.Anchor{
				RunID: r.RunID, Seq: r.Seq, Hash: r.Hash, Kind: r.Kind,
				BackendKind: r.BackendKind, Backend: r.Backend, Ref: r.Ref,
				Proof: r.Proof, BackendKeyID: r.BackendKeyID,
			},
		}
		switch {
		case r.RunID != runID:
			c.Mismatch = "sidecar record names another run"
		case !hashRE.MatchString(r.Hash):
			c.Mismatch = "anchor hash is not a lowercase hex sha256"
		case r.Seq < 1 || r.Seq != len(chain):
			c.Mismatch = fmt.Sprintf("anchor covers event %d but the ledger has %d events", r.Seq, len(chain))
		default:
			sum := sha256.Sum256(chain[r.Seq-1].Raw)
			if got := hex.EncodeToString(sum[:]); got != r.Hash {
				c.Mismatch = fmt.Sprintf("the ledger does not reproduce the anchored head at event %d (ledger %s, recorded %s)", r.Seq, got, r.Hash)
			} else if !FinalEvent(chain) {
				c.Mismatch = "the anchored event is not the run's final event"
			}
		}
		out = append(out, c)
	}
	return out
}

// Verdict is what a run's sidecar says about its ledger.
type Verdict struct {
	Found   bool
	Err     error // Read's error; Results empty when set
	Results []anchorverify.Result
}

// Verify reads runID's sidecar under logDir and, when it is there and
// readable, decides every record through the one ladder. chain must be
// ledger.ReadVerify's hash-verified output.
func Verify(logDir, runID string, chain []ledger.Record, o anchorverify.Options) Verdict {
	recs, found, err := Read(Path(logDir, runID))
	if err != nil || !found {
		return Verdict{Found: found, Err: err}
	}
	return Verdict{Found: true, Results: anchorverify.Decide(Check(runID, chain, recs), o)}
}

// VerifyRun is Verify for a caller that has not read the run's ledger: the one
// path every reader of a run's anchor takes (the audit commands and serve). It
// touches nothing when the run has no sidecar — no ledger read and no pin
// resolved, so an unanchored run never reads anchor.pub — and otherwise reads
// the ledger once (hash-verified, unlocked) and decides every record through
// Verify. A run id that is not a run id's shape has no sidecar by
// construction (every writer refuses one), so it is not anchored and is never
// joined into a path. An unreadable ledger or a sidecar path that cannot be
// statted is a found-but-unreadable verdict (unverifiable), never "not anchored".
//
// key resolves the pinned log key (nil func or nil key = unpinned) and factory
// builds the verify-side backend (nil = anchorverify.Default). pinned reports
// whether the resolved key was non-nil; it is false when no record was
// decided, because then no key was resolved. key is called at most once here;
// a caller verifying several runs shares one memoized func across them.
func VerifyRun(logDir, runID string, key func() (*ecdsa.PublicKey, error), factory anchorverify.Factory, offline bool, timeout time.Duration) (v Verdict, pinned bool) {
	if !RunIDRE.MatchString(runID) {
		return Verdict{}, false
	}
	if _, err := os.Lstat(Path(logDir, runID)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Verdict{}, false
		}
		return Verdict{Found: true, Err: err}, false
	}
	chain, _, err := ledger.ReadVerify(filepath.Join(logDir, runID+".jsonl"), ledger.Unlocked)
	if err != nil {
		return Verdict{Found: true, Err: fmt.Errorf("the run ledger cannot be read to check its anchor: %w", err)}, false
	}
	resolve := func() (*ecdsa.PublicKey, error) { return nil, nil }
	if key != nil {
		resolve = sync.OnceValues(key)
	}
	v = Verify(logDir, runID, chain, anchorverify.Options{ResolveKey: resolve, Factory: factory, Offline: offline, Timeout: timeout})
	if len(v.Results) > 0 {
		k, _ := resolve() // memoized: resolved inside Decide, never a second read
		pinned = k != nil
	}
	return v, pinned
}

// The folded states of a Verdict.
const (
	StateNotAnchored  = "not-anchored"
	StateVerified     = "verified"
	StateMismatch     = "mismatch"
	StateUnverifiable = "unverifiable"
)

// State folds the verdict to one word: no sidecar is not-anchored; an
// unreadable one, or one with no results, is unverifiable; any mismatch wins over any unverifiable,
// which wins over verified.
func (v Verdict) State() string {
	switch {
	case !v.Found:
		return StateNotAnchored
	case v.Err != nil, len(v.Results) == 0:
		// No evidence is never "verified": a gate defaults to unverifiable.
		return StateUnverifiable
	}
	worst := StateVerified
	for _, r := range v.Results {
		switch r.State {
		case anchorverify.StateMismatch:
			return StateMismatch
		case anchorverify.StateUnverifiable:
			worst = StateUnverifiable
		}
	}
	return worst
}
