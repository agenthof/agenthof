package control

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/origin"
)

// record is the control/1 on-disk shape. Field order here is the wire
// order (spec §3.2): v, seq, time, action, agent, outcome, reason,
// invoker, asserted_as, witness, config_hash, bootstrap, fragment_len,
// fragment_sha256, origin, detail, anchor, seal, prev, log_id. It intentionally does not embed Event,
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
	Bootstrap   bool             `json:"bootstrap,omitempty"`
	FragmentLen int              `json:"fragment_len,omitempty"`
	FragmentSHA string           `json:"fragment_sha256,omitempty"`
	Origin      *origin.Origin   `json:"origin,omitempty"`
	Detail      string           `json:"detail,omitempty"`
	// Anchor is the payload of an action "anchor" record, copied from the
	// Event once the permit below admits it.
	Anchor *Anchor `json:"anchor,omitempty"`
	// Seal is the payload of an action "seal" record (control.Seal).
	Seal  *Seal  `json:"seal,omitempty"`
	Prev  string `json:"prev"`
	LogID string `json:"log_id,omitempty"`
}

// MaxAnchorProofLen bounds Anchor.Proof on a record: 8192 bytes of standard
// base64 — a transparency log's inclusion proof with its signed checkpoint
// (≈6 KB base64 at a few billion entries, measured; fits past 2^47), an
// RFC-3161 token (≤5.5 KB) and a tile-backed log entry (≈1.5 KB) all fit.
// Fixed here by the first anchoring
// writer; internal/anchor.MaxProofLen is documented as equal and a test in
// cmd/agenthof pins the equality — this package imports nothing of anchor.
const MaxAnchorProofLen = 8192

// Length caps on the locator and identity strings of an anchor record,
// judged at Append beside the proof cap: a Rekor entry id is 80 bytes, a
// backend URL conventionally fits in 2048, a kind is a word, a key id is 64
// hex. Nothing an honest writer produces comes near them; they make the
// honest ledger's bounds explicit, so every cause a verifier derives from a
// record Append wrote is bounded too.
const (
	MaxAnchorRefLen          = 256
	MaxAnchorBackendLen      = 2048
	MaxAnchorBackendKindLen  = 64
	MaxAnchorBackendKeyIDLen = 128
)

var anchorHashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// checkAnchorShape is Append's permit for an anchor record — the structural
// rules decidable before the ledger is opened, so a malformed anchor appends
// nothing and, on a fresh root, creates no file. There is no caller-identity
// check: Go cannot tell audit anchor from another caller honestly, and a
// structural rule every writer must meet is the narrowest permit that is also
// enforceable. Append does not check Anchor.Hash against the chain — that is
// the verifier's job (CheckAnchors).
func checkAnchorShape(e Event) error {
	if e.Anchor != nil && e.Action != "anchor" {
		return fmt.Errorf("control: anchor payload on a %q record", e.Action)
	}
	if e.Action != "anchor" {
		return nil
	}
	if e.Outcome == "success" && e.Anchor == nil {
		return errors.New("control: a successful anchor must say what it covers")
	}
	if e.Outcome == "refused" && e.Anchor != nil {
		// A refusal happens before the head is read; a payload there would be invented.
		return errors.New("control: a refused anchor tried nothing and covers nothing")
	}
	if e.ConfigHash != "" {
		return errors.New("control: an anchor installs nothing and carries no config_hash")
	}
	a := e.Anchor
	if a == nil {
		return nil
	}
	if !anchorHashRE.MatchString(a.Hash) {
		return fmt.Errorf("control: anchor hash %q is not a lowercase hex sha256", a.Hash)
	}
	if len(a.Proof) > MaxAnchorProofLen {
		return fmt.Errorf("control: anchor proof is %d bytes; the cap is %d", len(a.Proof), MaxAnchorProofLen)
	}
	for _, f := range []struct {
		name, value string
		cap         int
	}{
		{"ref", a.Ref, MaxAnchorRefLen},
		{"backend", a.Backend, MaxAnchorBackendLen},
		{"backend_kind", a.BackendKind, MaxAnchorBackendKindLen},
		{"backend_key_id", a.BackendKeyID, MaxAnchorBackendKeyIDLen},
	} {
		if len(f.value) > f.cap {
			return fmt.Errorf("control: anchor %s is %d bytes; the cap is %d", f.name, len(f.value), f.cap)
		}
	}
	if e.Outcome != "success" {
		return nil
	}
	switch {
	case a.Kind == "":
		return errors.New("control: successful anchor record is incomplete (kind)")
	case a.Kind != "tlog" && a.Kind != "signed":
		return fmt.Errorf("control: anchor kind %q is not tlog or signed", a.Kind)
	case a.BackendKind == "":
		return errors.New("control: successful anchor record is incomplete (backend_kind)")
	case a.Backend == "":
		return errors.New("control: successful anchor record is incomplete (backend)")
	case a.Ref == "":
		return errors.New("control: successful anchor record is incomplete (ref)")
	case a.Proof == "":
		return errors.New("control: successful anchor record is incomplete (proof)")
	}
	return nil
}

// checkAnchorCoverage is the one permit rule that needs the chain: the
// covered seq must exist, 1 ≤ Seq ≤ Count, read under the exclusive flock so
// it holds across any head advance since the caller read the head. A refusal
// here appends nothing — on a fresh root the file now exists and is empty,
// which is "no record appended", the honest statement of unchanged.
func checkAnchorCoverage(a *Anchor, count int) error {
	if a != nil && (a.Seq < 1 || a.Seq > count) {
		return fmt.Errorf("control: anchor covers seq %d but the chain has %d records", a.Seq, count)
	}
	return nil
}

// Append admits an anchor record only through checkAnchorShape and
// checkAnchorCoverage, a seal record only through checkSealShape and
// checkSealPlacement (seal.go), and rejects any non-"success" Event with a
// nil Reason: every control-plane denial must explain itself, and this is the
// one place that rule is enforced, rather than scattered across call sites.
// It then opens the active segment through the seam (openActive: a torn or
// broken active, a sealed-not-rotated active — ErrSealed — or a damaged set
// refuses), appends on the chain's logical position (appendOn), and closes.
// It returns the chain's new Head, whose Count is the global seq.
func Append(path string, e Event) (ledger.Head, error) {
	if err := checkAnchorShape(e); err != nil {
		return ledger.Head{}, err
	}
	if err := checkSealShape(e); err != nil {
		return ledger.Head{}, err
	}
	if e.Outcome != "success" && e.Reason == nil {
		return ledger.Head{}, fmt.Errorf("control: outcome %q requires a reason", e.Outcome)
	}
	c, view, err := openActive(path)
	if err != nil {
		return ledger.Head{}, err
	}
	defer func() { _ = c.Close() }()
	head, _, err := appendOn(c, view, e)
	return head, err
}

// appendOn is Append's body over a chain the caller already holds (openActive
// gave it, with the View read under its lock), so the seal can write its
// record on the chain it holds without a second handle contending with the
// first. The two permit rules that need the chain run here: anchor coverage
// and seal placement (the payload must describe exactly the active this
// chain holds — the View's sealed count and records are what it is judged
// against). Every position is LOGICAL: coverage is judged against
// Base+Count, seq is Base+Count+1, and log_id is minted on the genesis —
// Base 0, Count 0 — and nowhere else: the first record of a later segment
// continues the chain's identity, it does not start one. The returned Head is
// logical too: Count is the chain's last seq, which is what every writer
// prints as seq=. The marshalled line is returned beside it for a caller that
// needs the bytes it wrote.
func appendOn(c *ledger.Chain, view View, e Event) (ledger.Head, []byte, error) {
	logical := int(c.Base()) + c.Count()
	if err := checkAnchorCoverage(e.Anchor, logical); err != nil {
		return ledger.Head{}, nil, err
	}
	if err := checkSealPlacement(c, view, e); err != nil {
		return ledger.Head{}, nil, err
	}
	rec := record{
		V:           "control/1",
		Seq:         logical + 1,
		Time:        time.Now().UTC(),
		Action:      e.Action,
		Agent:       e.Agent,
		Outcome:     e.Outcome,
		Reason:      e.Reason,
		Invoker:     e.Invoker,
		AssertedAs:  e.AssertedAs,
		Witness:     e.Witness,
		ConfigHash:  e.ConfigHash,
		Bootstrap:   e.Bootstrap,
		FragmentLen: e.FragmentLen,
		FragmentSHA: e.FragmentSHA,
		Origin:      e.Origin.Sanitized(),
		Detail:      origin.Clean(e.Detail),
		Anchor:      e.Anchor,
		Seal:        e.Seal,
		Prev:        c.Prev(),
	}
	if c.Base() == 0 && c.Count() == 0 {
		id, err := newLogID()
		if err != nil {
			return ledger.Head{}, nil, err
		}
		rec.LogID = id
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return ledger.Head{}, nil, err
	}
	if err := c.Append(line); err != nil {
		return ledger.Head{}, nil, err
	}
	return ledger.Head{Hash: c.Prev(), Count: int(c.Base()) + c.Count()}, line, nil
}

// RepairResult is what a repair did: the fragment it moved aside and, when
// it completed a rotation, the segment it sealed (0 for a plain torn tail).
type RepairResult struct {
	FragmentLen      int
	FragmentSHA      string
	CompletedSegment int
}

// Repair recovers the control ledger's ACTIVE segment and nothing else. It
// reads the whole set (Read, under the reader's shared lock) and decides
// from the verdict; only two shapes are repaired, and in both the damaged
// bytes are moved aside before anything is truncated:
//
//   - the active ends in a torn tail and its verified records hold no
//     successful seal (state A, or a seal line cut mid-write — a torn seal is
//     no seal): the tail from the TornError's Offset is moved to a fragment,
//     the active truncated there, and a "repair" record appended on the
//     active's logical position — the taint lands in the active segment and
//     IsTainted finds it in the logical chain;
//   - the active's verified records hold a successful seal that recomputes
//     and bytes follow its line — records a writer older than this root's
//     seals appended (FaultSealNotLast), a torn write, or both: every byte
//     after the seal line is moved to a fragment, the active truncated at the
//     end of the seal line (state B exactly), the rotation completed
//     (CompleteSeal: link, manifest, swap — the same commit points), and the
//     "repair" record appended as the new active's first record, prev the
//     seal line's hash, seq the seal's + 1. A seal whose payload does not
//     recompute is a planted seal: refused with that fault before anything
//     is touched, because completing it would fail after the truncate.
//
// Everything else refuses with the fault's own remedy and changes nothing:
// a clean set ("not torn; nothing to repair"); state B or C ("run audit
// seal" — completing a rotation is not a repair); a chain break in the
// active (the global seq; a well-formed record that disagrees with the chain
// is not a tail to cut off); a boundary fault in the active (its cause's
// remedy, never "run repair"); any fault in a sealed segment (a sealed
// segment is the unit a copy exists of and the boundary every later segment
// chains from, so it is never repaired in place); a missing, unexpected or
// disagreeing segment or manifest.
//
// The fragment file "<active>.torn-<unix-seconds>" (mode 0600, O_EXCL — a
// second repair in the same second gets a "-2", "-3", ... suffix; see
// writeTornFragment) is the only remaining copy of the bytes moved aside.
// Nothing in this package or the CLI ever prunes it: it is kept indefinitely
// as a forensic artifact for an operator to inspect by hand, and its
// existence alone means the ledger was once damaged, whatever the live
// chain's taint says.
//
// Locking: Read's shared lock is released before anything is done; the
// fragment and the truncate then run under the active's exclusive lock
// (moveTailAside), which excludes every writer that respects it, and the
// bytes are re-read under that lock and must still end at the verified
// prefix, else the repair refuses. CompleteSeal and Append take their own
// locks afterwards; a write that lands in between stays on disk and
// surfaces as a set fault on the next read — nothing is cut off unseen. The
// command holds installed.lock exclusively around the whole call, which
// keeps every pointer writer out of the rotation.
//
// Residual risks: a crash between the truncate and the repair append leaves
// a clean, shorter chain with no taint, the fragment its only evidence; in
// the post-seal case a crash between the truncate and the rotation leaves
// state B (audit seal completes it; the repair record is then owed, and a
// re-run of repair refuses with "run audit seal") and a crash between the
// rotation and the append leaves a clean rotated root with a fragment and no
// taint. Making the steps atomic would need a write-new-set-then-rename,
// beyond V1's scope.
func Repair(path string, op identity.Invoker, assertedAs string, witness Witness) (RepairResult, error) {
	resolved, err := resolveControlLog(path)
	if err != nil {
		return RepairResult{}, err
	}
	v, verr := Read(path, ledger.Locked)
	if verr == nil {
		if v.State != StateOpen {
			return RepairResult{}, fmt.Errorf("control: ledger %s: the active segment is sealed and not yet rotated; run audit seal to complete it — not a repair matter", path)
		}
		return RepairResult{}, fmt.Errorf("control: ledger %s is not torn; nothing to repair", path)
	}
	var se *SetError
	if !errors.As(verr, &se) || se.Segment != 0 {
		return RepairResult{}, verr // not a set fault, or a fault in a sealed segment: its own text
	}
	switch se.Fault {
	case FaultTorn, FaultSealNotLast:
	case FaultBroken:
		return RepairResult{}, fmt.Errorf("control: chain break at seq %d is not auto-repairable (only a torn tail can be repaired)", se.Seq)
	default:
		return RepairResult{}, verr
	}
	active := activeRecords(v)
	sealAt, err := sealToComplete(v, active)
	if err != nil {
		return RepairResult{}, err
	}
	if sealAt < 0 {
		var torn *ledger.TornError
		if !errors.As(se.Err, &torn) {
			return RepairResult{}, fmt.Errorf("control: ledger %s: records after a seal were reported and no seal was found; run audit verify control", path)
		}
		res, err := moveTailAside(resolved, torn.Offset, active)
		if err != nil {
			return RepairResult{}, err
		}
		return res, appendRepair(resolved, res, op, assertedAs, witness)
	}
	var offset int64
	for _, r := range active[:sealAt+1] {
		offset += int64(len(r.Raw)) + 1
	}
	res, err := moveTailAside(resolved, offset, active[:sealAt+1])
	if err != nil {
		return RepairResult{}, err
	}
	if crashAt("repair_after_truncate_before_rotate") {
		return RepairResult{}, errStoppedByTestHook
	}
	seal, err := CompleteSeal(resolved)
	if err != nil {
		return RepairResult{}, fmt.Errorf("control: moved %d bytes after the seal line aside and truncated the active at the seal, but completing the rotation failed: %w; run audit seal to complete it — the fragment file is the evidence of the repair", res.FragmentLen, err)
	}
	res.CompletedSegment = seal.Segment
	if crashAt("repair_after_rotate_before_append") {
		return RepairResult{}, errStoppedByTestHook
	}
	return res, appendRepair(resolved, res, op, assertedAs, witness)
}

// sealToComplete finds the first successful seal among the active's verified
// records: -1 when there is none (a torn tail is repaired as a torn tail).
// A seal that is there must recompute — judged exactly as finishActive judges
// a sealed-not-rotated active, over the records through the seal line — and
// the root must carry the identity the manifest records (manifestLogID), so
// that the rotation repair is attempted only where it is known to complete;
// a planted seal is its FaultManifest and a genesis without a log_id is
// ErrUnsealable, both refused before anything is touched.
func sealToComplete(v View, active []ledger.Record) (int, error) {
	for i, r := range active {
		rec, ok := decodeRecord(r)
		if !ok || rec.Action != "seal" || rec.Outcome != "success" {
			continue
		}
		through := v
		through.Records = v.Records[:len(v.Records)-len(active)+i+1]
		through.Active.Records = i + 1
		through.Head = ledger.Head{Hash: hashOf(r.Raw), Count: rec.Seq}
		if _, err := finishActive(through, len(v.Sealed)); err != nil {
			return -1, err
		}
		if _, err := manifestLogID(through); err != nil {
			return -1, err
		}
		return i, nil
	}
	return -1, nil
}

// moveTailAside is the one destructive step of a repair, and it runs under
// the active's exclusive lock, as every writer does: the active is opened by
// name, LOCK_EX taken (bounded; busy refuses), the handle re-stat'ed to be
// the file the name still refers to (a rotation swapped under the name
// refuses — a truncate by name would otherwise extend a fresh, empty
// active), and the bytes read through that handle. The verified prefix Read
// saw must still end exactly at offset — its last line, newline and all,
// immediately before it — else the active changed under the repair and
// nothing is touched. Only then is every byte from offset to end-of-file
// copied to a fresh fragment file (the evidence, synced before anything is
// removed) and the handle truncated at offset and synced. The lock is
// released on return; CompleteSeal and Append take their own afterwards.
func moveTailAside(resolved string, offset int64, prefix []ledger.Record) (RepairResult, error) {
	f, err := os.OpenFile(resolved, os.O_RDWR, 0)
	if err != nil {
		return RepairResult{}, err
	}
	defer func() { _ = f.Close() }()
	if err := ledger.LockExclusive(f); err != nil {
		return RepairResult{}, fmt.Errorf("control: repair %s: %w", resolved, err)
	}
	defer ledger.Unlock(f)
	fi, err := f.Stat()
	if err != nil {
		return RepairResult{}, err
	}
	if !sameFile(resolved, fi) {
		return RepairResult{}, fmt.Errorf("control: %s was rotated while it was being repaired; run audit verify control and retry", resolved)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return RepairResult{}, err
	}
	if offset < 0 || offset > int64(len(raw)) {
		return RepairResult{}, fmt.Errorf("control: torn offset %d out of range for %d-byte file %s", offset, len(raw), resolved)
	}
	if len(prefix) > 0 {
		last := append(append([]byte{}, prefix[len(prefix)-1].Raw...), '\n')
		if !bytes.HasSuffix(raw[:offset], last) {
			return RepairResult{}, fmt.Errorf("control: %s changed while it was being repaired; run audit verify control and retry", resolved)
		}
	}
	fragment := raw[offset:]
	sum := sha256.Sum256(fragment)
	res := RepairResult{FragmentLen: len(fragment), FragmentSHA: hex.EncodeToString(sum[:])}
	if err := writeTornFragment(resolved, fragment); err != nil {
		return RepairResult{}, err
	}
	if err := f.Truncate(offset); err != nil {
		return RepairResult{}, err
	}
	if err := f.Sync(); err != nil {
		return RepairResult{}, err
	}
	return res, nil
}

// appendRepair appends the chained "repair" record carrying the fragment's
// length and sha256, so every future read shows the ledger was recovered
// (IsTainted; the taint is forever). It goes through Append, on the active's
// logical position — after a completed rotation that is the new segment's
// first record.
func appendRepair(resolved string, res RepairResult, op identity.Invoker, assertedAs string, witness Witness) error {
	if _, err := Append(resolved, Event{
		Action:      "repair",
		Outcome:     "success",
		FragmentLen: res.FragmentLen,
		FragmentSHA: res.FragmentSHA,
		Invoker:     op,
		AssertedAs:  assertedAs,
		Witness:     witness,
	}); err != nil {
		return fmt.Errorf("control: moved %d bytes aside and truncated the active, but the repair record could not be appended: %w", res.FragmentLen, err)
	}
	return nil
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

// genesisLogIDRE is what newLogID produces: 16 bytes, lowercase hex.
var genesisLogIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// GenesisLogID reads the control ledger's identity: the log_id Append set
// on the genesis record and nothing since — audit repair control truncates
// a torn tail and never rewrites genesis, so it is stable for the ledger's
// life. It is a one-field decode of records[0]: DecodedEvent omits log_id
// on purpose. An empty ledger, a genesis that does not decode, and a
// genesis without a log_id or with one that is not 32 lowercase hex are
// refused — no ledger this package wrote looks like that, and a reader
// binding a signature to the ledger's identity must not guess one.
func GenesisLogID(records []ledger.Record) (string, error) {
	if len(records) == 0 {
		return "", errors.New("control ledger: no genesis record")
	}
	var genesis struct {
		LogID string `json:"log_id"`
	}
	if err := json.Unmarshal(records[0].Raw, &genesis); err != nil {
		return "", fmt.Errorf("control ledger genesis: %w", err)
	}
	if !genesisLogIDRE.MatchString(genesis.LogID) {
		return "", errors.New("control ledger genesis has no log_id")
	}
	return genesis.LogID, nil
}
