package control

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// record is the control/1 on-disk shape. Field order here is the wire
// order (spec §3.2): v, seq, time, action, agent, outcome, reason,
// invoker, asserted_as, witness, config_hash, fragment_len,
// fragment_sha256, prev, log_id. It intentionally does not embed Event,
// since the wire order interleaves the writer-assigned fields (seq, time
// up front; prev, log_id at the end) around the caller-assigned ones.
//
// v, seq, time, action, outcome, invoker, witness, and prev are never
// omitempty: the ledger's parseLineFields requires "prev" present (empty
// string at genesis) to identify a record's place in the chain, and the
// others are always meaningful once Append has run.
type record struct {
	V           string           `json:"v"`
	Seq         int              `json:"seq"`
	Time        time.Time        `json:"time"`
	Action      string           `json:"action"`
	Agent       string           `json:"agent,omitempty"`
	Outcome     string           `json:"outcome"`
	Reason      *Reason          `json:"reason,omitempty"`
	Invoker     identity.Invoker `json:"invoker"`
	AssertedAs  string           `json:"asserted_as,omitempty"`
	Witness     Witness          `json:"witness"`
	ConfigHash  string           `json:"config_hash,omitempty"`
	FragmentLen int              `json:"fragment_len,omitempty"`
	FragmentSHA string           `json:"fragment_sha256,omitempty"`
	Prev        string           `json:"prev"`
	LogID       string           `json:"log_id,omitempty"`
}

// Append rejects any non-"success" Event with a nil Reason: every
// control-plane denial must explain itself, and this is the one place
// that rule is enforced, rather than scattered across call sites. It
// then opens the control log at path Locked (ledger.Open verifies the
// chain and fails on a torn or broken log), assigns seq=Count()+1,
// time=now UTC, and prev=the current head, sets a fresh log_id on the
// genesis record only, marshals the record, and appends it. It returns
// the chain's new Head.
func Append(path string, e Event) (ledger.Head, error) {
	if e.Outcome != "success" && e.Reason == nil {
		return ledger.Head{}, fmt.Errorf("control: outcome %q requires a reason", e.Outcome)
	}
	c, err := ledger.Open(path, ledger.Locked)
	if err != nil {
		return ledger.Head{}, err
	}
	defer func() { _ = c.Close() }()

	rec := record{
		V:           "control/1",
		Seq:         c.Count() + 1,
		Time:        time.Now().UTC(),
		Action:      e.Action,
		Agent:       e.Agent,
		Outcome:     e.Outcome,
		Reason:      e.Reason,
		Invoker:     e.Invoker,
		AssertedAs:  e.AssertedAs,
		Witness:     e.Witness,
		ConfigHash:  e.ConfigHash,
		FragmentLen: e.FragmentLen,
		FragmentSHA: e.FragmentSHA,
		Prev:        c.Prev(),
	}
	if c.Count() == 0 {
		id, err := newLogID()
		if err != nil {
			return ledger.Head{}, err
		}
		rec.LogID = id
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return ledger.Head{}, err
	}
	if err := c.Append(line); err != nil {
		return ledger.Head{}, err
	}
	return ledger.Head{Hash: c.Prev(), Count: c.Count()}, nil
}

// Repair recovers a torn-tail control ledger (spec §3.6). It reads the
// live file with ledger.ReadVerify(path, ledger.Locked):
//
//   - nil error means the chain is already clean — there is nothing to
//     repair, and Repair refuses rather than silently doing nothing.
//   - a *ledger.ChainBrokenError means a well-formed record disagrees
//     with the chain (wrong prev/seq, or a non-final syntax error) —
//     that is not a simple "cut off the damaged tail" fix, so Repair
//     refuses and names the offending line for a human to investigate.
//   - only a *ledger.TornError (the final record looks like the tail of
//     an interrupted write) is auto-repairable, and is the only case
//     that falls through to the steps below.
//
// The fragment — every byte from the TornError's Offset (the end of the
// last fully verified record) to end-of-file — is copied to a sibling
// file "<path>.torn-<unix-seconds>" (mode 0600), created with O_EXCL so
// a second repair landing in the same second never clobbers an earlier
// fragment (it gets a "-2", "-3", ... suffix instead; see
// writeTornFragment). That fragment file is NEVER pruned by anything in
// this package or the CLI: it is the only remaining copy of whatever was
// in the damaged tail, kept indefinitely as a forensic artifact for an
// operator to inspect by hand.
//
// The live file is then truncated to Offset — removing the damaged tail
// entirely, including a terminated-but-unparseable last line, which
// counts as part of the fragment, not a kept record — and a chained
// "repair" event is appended via Append, carrying the fragment's length
// and sha256 so every future read of the ledger shows it was recovered
// (see IsTainted; a repair record's presence taints the ledger forever).
//
// Locking note: ReadVerify above takes only a shared lock and releases
// it before returning, so there is a small window before the truncate
// and Append below where another process could act on the file. This is
// accepted for V1 (single-admin operation) rather than adding
// cross-process coordination beyond what ledger.Open/ReadVerify already
// provide; the truncate and Append are run back-to-back to keep that
// window as small as possible.
//
// Residual risk: if Truncate below succeeds but the following Append
// then fails (e.g. disk full, or another process holds the ledger lock
// past Append's own timeout), the live file is left as a valid, clean,
// shorter chain with NO repair record — the taint is lost, even though
// the fragment file (written before either of those steps) still exists
// as evidence that a repair was attempted. Making truncate+append atomic
// would need a write-new-file-then-rename, which is beyond V1's scope;
// an operator hitting this should treat any "<path>.torn-*" file's
// existence as itself meaning the ledger was once torn, regardless of
// what the live file's own taint bit says.
func Repair(path string, op identity.Invoker, assertedAs string, witness Witness) (fragmentLen int, fragmentSHA string, err error) {
	_, _, verr := ledger.ReadVerify(path, ledger.Locked)
	if verr == nil {
		return 0, "", fmt.Errorf("control: ledger %s is not torn; nothing to repair", path)
	}
	var broken *ledger.ChainBrokenError
	var torn *ledger.TornError
	switch {
	case errors.As(verr, &broken):
		return 0, "", fmt.Errorf("control: chain break at line %d is not auto-repairable (only a torn tail can be repaired)", broken.Line)
	case errors.As(verr, &torn):
		// Only a torn tail is auto-repairable; fall through below.
	default:
		return 0, "", verr
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	if torn.Offset < 0 || torn.Offset > int64(len(raw)) {
		return 0, "", fmt.Errorf("control: torn offset %d out of range for %d-byte file %s", torn.Offset, len(raw), path)
	}
	fragment := raw[torn.Offset:]
	fragmentLen = len(fragment)
	sum := sha256.Sum256(fragment)
	fragmentSHA = hex.EncodeToString(sum[:])

	if err := writeTornFragment(path, fragment); err != nil {
		return 0, "", err
	}
	if err := os.Truncate(path, torn.Offset); err != nil {
		return 0, "", err
	}
	if _, err := Append(path, Event{
		Action:      "repair",
		Outcome:     "success",
		FragmentLen: fragmentLen,
		FragmentSHA: fragmentSHA,
		Invoker:     op,
		AssertedAs:  assertedAs,
		Witness:     witness,
	}); err != nil {
		return 0, "", err
	}
	return fragmentLen, fragmentSHA, nil
}

// maxTornFragmentAttempts bounds writeTornFragment's retry loop against
// same-second filename collisions. A collision can only recur this many
// times if something keeps calling Repair in a tight loop within one
// wall-clock second; past that it's treated as a real failure, not
// transient contention.
const maxTornFragmentAttempts = 1000

// writeTornFragment writes fragment to a fresh sibling file named
// "<path>.torn-<unix-seconds>" (mode 0600), refusing to ever overwrite
// an existing one: a fragment file is the sole surviving copy of
// whatever was in a torn ledger's damaged tail (see Repair's doc
// comment), so a second repair landing in the same second gets a
// "-2", "-3", ... suffix instead of silently clobbering the first.
//
// It syncs before closing (matching ledger.Chain.Append's own
// sync-after-write convention): Write+Close alone only fixes PROGRAM
// order (the fragment file "happens before" the caller's later
// Truncate/Append), not DURABILITY order. Without the sync, a crash
// between this function returning and Append's own fsync could persist
// the truncate to disk while the fragment bytes — the only surviving
// evidence of what was in the damaged tail — are still sitting in the
// page cache and vanish. The sync makes that "evidence before
// destruction" ordering hold across a crash, not just in program order.
func writeTornFragment(path string, fragment []byte) error {
	base := fmt.Sprintf("%s.torn-%d", path, time.Now().Unix())
	for attempt := 0; attempt < maxTornFragmentAttempts; attempt++ {
		candidate := base
		if attempt > 0 {
			candidate = fmt.Sprintf("%s-%d", base, attempt+1)
		}
		f, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		_, writeErr := f.Write(fragment)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}
	return fmt.Errorf("control: could not create a fresh torn-fragment file for %s after %d attempts", path, maxTornFragmentAttempts)
}

// newLogID generates a fresh genesis log identifier: 16 bytes from
// crypto/rand, hex-encoded.
func newLogID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
