package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/agenthof/agenthof/internal/atomicfile"
	"github.com/agenthof/agenthof/internal/ledger"
	"github.com/agenthof/agenthof/internal/origin"
)

// ErrNothingToSeal is the seal's verdict on an active that holds no record: a
// segment of only a seal record has no content.
var ErrNothingToSeal = errors.New("control: the active segment is empty; nothing to seal")

// ErrNoHardLinks is the seal's verdict when link(2) refused for a reason that
// means the filesystem does not make hard links. Judged before anything is
// recorded.
var ErrNoHardLinks = errors.New("control: this filesystem does not support hard links, which the rotation needs; nothing sealed")

var errNothingToComplete = errors.New("control: the active segment is open; nothing to complete")

// ErrUnsealable is the seal's verdict on a root whose genesis carries no
// log_id — one written before ledgers carried an identity. The manifest
// every rotation writes requires the log_id, so a seal recorded on such a
// root could never complete; it is refused before anything is linked or
// recorded, and the root remains today's single, writable file. No remedy is
// named because none exists short of editing the ledger.
var ErrUnsealable = errors.New("control: the control ledger genesis carries no log_id; it cannot be sealed and remains a single file")

// manifestLogID is the log_id the manifest for this View carries: the
// manifest's own once one exists (identityCheck already bound it to the
// genesis), else the genesis's. Every path that commits toward a rotation —
// the placement permit, the seal, the repair that completes a seal — asks it
// BEFORE touching the disk, so a root without one is refused whole.
func manifestLogID(v View) (string, error) {
	if v.LogID != "" {
		return v.LogID, nil
	}
	id, err := GenesisLogID(v.Records)
	if err != nil {
		return "", fmt.Errorf("%w (%v)", ErrUnsealable, err)
	}
	return id, nil
}

// errStoppedByTestHook is what crashAt returns in place of the step it stops
// before; it never appears outside a test.
var errStoppedByTestHook = errors.New("stopped by AGENTHOF_TEST_CRASH_AT")

// linkFile is os.Link behind a var so a test can hand in a filesystem that
// cannot link.
var linkFile = os.Link

// crashAt is the rotation's in-process crash hook (apply's pattern): the
// step named by AGENTHOF_TEST_CRASH_AT is never taken, so a test observes the
// exact on-disk state a crash there would leave.
func crashAt(point string) bool { return os.Getenv("AGENTHOF_TEST_CRASH_AT") == point }

// SealStep names the step of a seal that failed, so the command prints the
// fixed line beside it: a preflight or link failure recorded nothing; a
// record failure left the segment open; a sink, manifest or swap failure
// left state B or C, which a re-run completes. Never serialized.
type SealStep int

const (
	SealStepPreflight SealStep = iota + 1
	SealStepLink
	SealStepRecord
	SealStepSink
	SealStepManifest
	SealStepSwap
)

// SealError is a seal step's typed failure.
type SealError struct {
	Step SealStep
	Err  error
}

func (e *SealError) Error() string { return e.Err.Error() }
func (e *SealError) Unwrap() error { return e.Err }

// SealResult is what a seal, or a completion, did.
type SealResult struct {
	Segment   int    // the ordinal sealed
	FirstSeq  int    // the segment's first seq
	HeadSeq   int    // the seal record's seq — the head
	HeadHash  string // sha256 of the seal line — the head, and the next segment's Start.Prev
	SHA256    string // the whole sealed file
	Path      string // the segment's path
	Completed bool   // an interrupted rotation was completed rather than a new seal made
	// The protected copy this run had confirmed — the seal record's sink
	// block and the sink's receipt for it. Zero on a floor seal and on a
	// state C completion, which makes no sink call.
	Sink        *SealSink
	VersionID   string
	RetainUntil time.Time
	Existed     bool
}

// checkSealShape is Append's structural permit for a seal record, decidable
// before the ledger is opened (checkAnchorShape's twin, with its rationale:
// Go cannot tell audit seal from another caller honestly, so the permit is a
// structural rule every writer must meet). A seal payload only on action
// seal; a successful seal carries one; a refused or error seal carries none;
// a seal carries no config_hash, no anchor, no detail; hashes are 64
// lowercase hex; segment ≥ 1, first_seq ≥ 1, head_seq ≥ first_seq; a sink
// block, when present, meets checkSealSink. Whether the payload describes
// the active is checkSealPlacement's question.
func checkSealShape(e Event) error {
	if e.Seal != nil && e.Action != "seal" {
		return fmt.Errorf("control: seal payload on a %q record", e.Action)
	}
	if e.Action != "seal" {
		return nil
	}
	if e.Outcome == "success" && e.Seal == nil {
		return errors.New("control: a successful seal must say what it closes")
	}
	if e.Outcome != "success" && e.Seal != nil {
		return errors.New("control: a refused seal closed nothing and carries no payload")
	}
	if e.ConfigHash != "" || e.Anchor != nil || e.Detail != "" {
		return errors.New("control: a seal installs nothing and carries no config_hash, anchor or detail")
	}
	s := e.Seal
	if s == nil {
		return nil
	}
	switch {
	case !anchorHashRE.MatchString(s.HeadHash) || !anchorHashRE.MatchString(s.ContentSHA256):
		return errors.New("control: seal head_hash and content_sha256 must be lowercase hex sha256")
	case s.Segment < 1 || s.FirstSeq < 1 || s.HeadSeq < s.FirstSeq:
		return fmt.Errorf("control: seal payload segment %d first_seq %d head_seq %d is malformed", s.Segment, s.FirstSeq, s.HeadSeq)
	}
	return checkSealSink(s.Sink)
}

// checkSealPlacement needs the open chain: the root must have the identity a
// rotation records (manifestLogID — a genesis without a log_id is
// ErrUnsealable), and the payload must describe exactly the active this
// chain holds — segment N+1, first_seq Base+1, head_seq Base+Count,
// head_hash the chain's head, at least one record, and content_sha256
// recomputed from the records read under the lock. A seal that passes it is
// the one audit seal would write and one whose rotation can complete;
// nothing else can be written as a seal.
func checkSealPlacement(c *ledger.Chain, view View, e Event) error {
	if e.Action != "seal" || e.Seal == nil {
		return nil
	}
	if c.Count() < 1 {
		return ErrNothingToSeal
	}
	if _, err := manifestLogID(view); err != nil {
		return err
	}
	s := e.Seal
	want := len(view.Sealed) + 1
	first, head := int(c.Base())+1, int(c.Base())+c.Count()
	switch {
	case s.Segment != want:
		return fmt.Errorf("control: seal names segment %d; the active is segment %d", s.Segment, want)
	case s.FirstSeq != first:
		return fmt.Errorf("control: seal first_seq %d; the active begins at %d", s.FirstSeq, first)
	case s.HeadSeq != head:
		return fmt.Errorf("control: seal head_seq %d; the active's head is %d", s.HeadSeq, head)
	case s.HeadHash != c.Prev():
		return fmt.Errorf("control: seal head_hash %s; the active's head is %s", s.HeadHash, c.Prev())
	}
	if content := sealContentDigest(activeRecords(view)); s.ContentSHA256 != content {
		return fmt.Errorf("control: seal content_sha256 %s; the active's bytes hash to %s", s.ContentSHA256, content)
	}
	return nil
}

// SealActive is steps 7–11 of audit seal on ONE held chain, in this order
// under the active's exclusive lock: openActive (busy, damaged and ErrSealed
// refuse here); sweep the temps an earlier crash left (before any step, so
// even an empty active's refusal leaves none behind); an empty active is
// ErrNothingToSeal; on a sink: worm root, the sink's preflight (the
// credential resolves, the bucket answers with Object Lock enabled, the
// seal's own key is empty) — a refusal records nothing; link the active
// under its segment name (a filesystem that cannot link fails with nothing
// recorded; EEXIST to the same inode is a re-run after a crash and
// continues; EEXIST to another file is FaultUnexpectedSegment); compute
// content_sha256 from the records read under the lock and append the seal
// record, its sink block naming where the protected copy goes — commit 1,
// the segment is closed; then rotate: the protected copy, confirmed; the
// manifest — commit 2, the set is rotated; swap a fresh, empty active under
// the name. The chain's lock is on the old inode throughout, and every name
// below derives from the View's resolved active path — the one the lock was
// taken on. e is a success seal event without a payload; the payload is
// computed here. A nil sink is the floor: no preflight, no block, no copy.
func SealActive(controlLog string, e Event, sink SinkWriter) (SealResult, error) {
	if e.Action != "seal" || e.Outcome != "success" || e.Seal != nil {
		return SealResult{}, errors.New("control: SealActive takes a success seal event without a payload")
	}
	c, v, err := openActive(controlLog)
	if err != nil {
		return SealResult{}, err
	}
	defer func() { _ = c.Close() }()
	resolved := v.Active.Path
	sweepTemps(resolved)
	if c.Count() == 0 {
		return SealResult{}, ErrNothingToSeal
	}
	// The identity the manifest will record, judged before the link: a root
	// without one is refused with nothing linked and nothing recorded (the
	// permit in appendOn would refuse too, but only after the link).
	logID, err := manifestLogID(v)
	if err != nil {
		return SealResult{}, err
	}
	n := len(v.Sealed) + 1
	// The preflight is a fresh seal's only: the key must be empty, which is
	// true before this seal's record exists and never after it (a re-run
	// completes through rotate, whose Put recognizes the seal's own copy).
	var loc *SealSink
	if sink != nil {
		l := sink.Locator(logID, n, time.Now().UTC())
		if err := sink.Prepare(context.Background(), l); err != nil {
			return SealResult{}, &SealError{Step: SealStepPreflight, Err: err}
		}
		loc = &l
	}
	if err := linkSegment(resolved, n); err != nil {
		return SealResult{}, &SealError{Step: SealStepLink, Err: err}
	}
	if crashAt("after_link_before_seal") {
		return SealResult{}, &SealError{Step: SealStepRecord, Err: errStoppedByTestHook}
	}
	e.Seal = &Seal{Segment: n, FirstSeq: int(c.Base()) + 1, HeadSeq: int(c.Base()) + c.Count(), HeadHash: c.Prev(), ContentSHA256: sealContentDigest(activeRecords(v)), Sink: loc}
	if err := checkSealShape(e); err != nil {
		return SealResult{}, &SealError{Step: SealStepRecord, Err: err}
	}
	head, line, err := appendOn(c, v, e)
	if err != nil {
		return SealResult{}, &SealError{Step: SealStepRecord, Err: err}
	}
	v.Records = append(v.Records, ledger.Record{Raw: line})
	v.Active.Records++
	v.Active.HeadSeq, v.Active.HeadHash, v.Head = head.Count, head.Hash, head
	if crashAt("after_seal_before_manifest") {
		return SealResult{}, &SealError{Step: SealStepManifest, Err: errStoppedByTestHook}
	}
	return rotate(resolved, v, sink, nil)
}

// confirmedCopy is a protected copy a post-seal repair confirmed BEFORE the
// destructive truncate, so the rotation can take it without a second sink
// call.
type confirmedCopy struct {
	block   SealSink // the seal record's sink block (the Put's authority/key)
	whole   string   // the sealed segment's whole-digest the Put confirmed
	receipt PutReceipt
}

// CompleteSeal finishes a rotation found in state B (the protected copy
// when the record names one, manifest, swap) or C (swap). It locks the
// active by name exactly as a writer does and holds LOCK_EX for the
// duration — a sealed-not-rotated active takes no appends, but the lock
// still serializes two completions — reading the set as Read does
// (VerifyReader: nothing is appended, so no chain is resumed). An open
// active has nothing to complete. sink is the root's posture now; what the
// record was sealed for is rotate's to compare.
func CompleteSeal(controlLog string, sink SinkWriter) (SealResult, error) {
	return completeSealWith(controlLog, sink, nil)
}

// completeSealWith is CompleteSeal with a copy the caller already confirmed
// (Repair's post-seal case; nil for audit seal), handed down to rotate.
func completeSealWith(controlLog string, sink SinkWriter, pre *confirmedCopy) (SealResult, error) {
	f, v, err := lockActive(controlLog, false, func(f *os.File, s ledger.Start) ([]ledger.Record, ledger.Head, error) {
		return ledger.VerifyReader(f, s)
	})
	if err != nil {
		return SealResult{}, err
	}
	defer func() {
		ledger.Unlock(f)
		_ = f.Close()
	}()
	if v.State == StateOpen {
		return SealResult{}, errNothingToComplete
	}
	resolved := v.Active.Path
	sweepTemps(resolved)
	res, err := rotate(resolved, v, sink, pre)
	res.Completed = true
	return res, err
}

// rotate is the protected copy, commit 2 and the swap over a View whose
// active ends in a successful seal (state B — the seal just written, or
// found) or whose manifest already lists it (state C): link if the link is
// missing; when the seal record carries a sink block, Put the sealed bytes
// to the sink it names and have the copy confirmed; write the manifest with
// the new entry; swap. Each step is idempotent against a crash that already
// took it — Put's oldest-version rule makes the copy so. The manifest is
// written only after a confirmed Put, so a segment the manifest lists has a
// confirmed protected copy, or carries no block. State C makes no sink
// call: the manifest's listing is the confirmation.
//
// pre is a copy the caller confirmed before it changed anything local (a
// post-seal repair, which must make no sink call between its truncate and
// its repair record): when it names this record's block and the digest of
// the bytes read here, the Put is skipped and its receipt taken — no sink
// call. Anything else falls through to the Put; a confirmation is never
// trusted for bytes it did not cover. nil is every other caller.
//
// The record is the authority for what a segment was sealed FOR: a block
// completes only through a sink of the same kind and URL (nil or another
// refuses, state B stands — flipping integrity.yaml is not an escape), and
// only at the key that sink derives for this ledger's segment — the chain
// fixes the seal's five chain fields, never its block, so a chained seal
// line written by hand could otherwise aim the Put at any key in the bucket
// (another ledger's, in a shared one); no block completes without an
// upload whatever the posture now says, since the chained seal line cannot
// be retrofitted.
func rotate(resolved string, v View, sink SinkWriter, pre *confirmedCopy) (SealResult, error) {
	var n int
	var seg Segment
	var sunk *SealSink // the block a Put confirmed on this run; nil in state C and on the floor
	var rcpt PutReceipt
	switch v.State {
	case StateRotatedNotSwapped:
		n = len(v.Sealed)
		seg = v.Sealed[n-1]
	default:
		n = len(v.Sealed) + 1
		active := activeRecords(v)
		if err := linkSegment(resolved, n); err != nil {
			return SealResult{}, &SealError{Step: SealStepLink, Err: err}
		}
		// The View's state says the last record is a successful seal that
		// decoded; the guard makes a disagreement impossible to dereference.
		last, ok := decodeRecord(active[len(active)-1])
		if !ok || last.Seal == nil {
			return SealResult{}, &SealError{Step: SealStepManifest, Err: errors.New("control: the active's last record does not decode as a seal; run audit verify control")}
		}
		whole, size := segmentDigests(active)
		seg = Segment{N: n, Path: SegmentPath(resolved, n), FirstSeq: v.Active.FirstSeq, HeadSeq: v.Head.Count, HeadHash: v.Head.Hash, SHA256: whole, Bytes: size, Records: len(active), SealedAt: last.Time, Sink: last.Seal.Sink}
		logID, err := manifestLogID(v)
		if err != nil {
			return SealResult{}, &SealError{Step: SealStepManifest, Err: err}
		}
		if block := last.Seal.Sink; block != nil {
			// Kind, URL and Key are the record's, which a hand can write:
			// origin.Clean before any of them reaches a terminal.
			if sink == nil || sink.Kind() != block.Kind || sink.URL() != block.URL {
				return SealResult{}, &SealError{Step: SealStepSink, Err: fmt.Errorf("segment %d was sealed for a protected copy at %s %s; integrity.yaml no longer names it — restore that posture to complete the rotation", n, origin.Clean(block.Kind), origin.Clean(block.URL))}
			}
			// Locator's key depends on the log_id and the ordinal alone (its
			// time is retain_until's), so the record's key is compared, not
			// the block.
			if want := sink.Locator(logID, n, last.Time).Key; block.Key != want {
				return SealResult{}, &SealError{Step: SealStepSink, Err: fmt.Errorf("segment %d was sealed for a protected copy at key %s; the sink derives %s for this ledger's segment %d — the record does not name this ledger's own copy; run audit verify control", n, origin.Clean(block.Key), want, n)}
			}
			if pre != nil && pre.block.Kind == block.Kind && pre.block.URL == block.URL && pre.whole == whole {
				rcpt = pre.receipt
			} else {
				if crashAt("after_seal_before_sink") {
					return SealResult{}, &SealError{Step: SealStepSink, Err: errStoppedByTestHook}
				}
				if rcpt, err = sink.Put(context.Background(), *block, segmentBytes(active), whole); err != nil {
					return SealResult{}, &SealError{Step: SealStepSink, Err: err}
				}
				if crashAt("after_sink_before_manifest") {
					return SealResult{}, &SealError{Step: SealStepManifest, Err: errStoppedByTestHook}
				}
			}
			sunk = block
		}
		m := Manifest{V: ManifestVersion, LogID: logID}
		for _, s := range append(v.Sealed, seg) {
			m.Segments = append(m.Segments, manifestEntry(resolved, s))
		}
		if err := writeManifest(resolved, m); err != nil {
			return SealResult{}, &SealError{Step: SealStepManifest, Err: err}
		}
	}
	if crashAt("after_manifest_before_swap") {
		return SealResult{}, &SealError{Step: SealStepSwap, Err: errStoppedByTestHook}
	}
	if err := swapActive(resolved); err != nil {
		return SealResult{}, &SealError{Step: SealStepSwap, Err: err}
	}
	return SealResult{Segment: n, FirstSeq: seg.FirstSeq, HeadSeq: seg.HeadSeq, HeadHash: seg.HeadHash, SHA256: seg.SHA256, Path: seg.Path,
		Sink: sunk, VersionID: rcpt.VersionID, RetainUntil: rcpt.RetainUntil, Existed: rcpt.Existed}, nil
}

// linkSegment hard-links the resolved active under segment n's name and
// fsyncs the directory. EEXIST to the same inode (a re-run) is fine; EEXIST
// to another file is an unexpected segment; EPERM, EOPNOTSUPP, ENOTSUP and
// EXDEV are what link(2) says on a filesystem without hard links; any other
// failure is reported as itself.
func linkSegment(resolved string, n int) error {
	seg := SegmentPath(resolved, n)
	err := linkFile(resolved, seg)
	if err == nil {
		atomicfile.SyncDir(filepath.Dir(resolved))
		return nil
	}
	if errors.Is(err, os.ErrExist) {
		a, aerr := os.Stat(resolved)
		b, berr := os.Stat(seg)
		if aerr == nil && berr == nil && os.SameFile(a, b) {
			return nil
		}
		return &SetError{Fault: FaultUnexpectedSegment, Path: seg}
	}
	for _, no := range []error{syscall.EPERM, syscall.EOPNOTSUPP, syscall.ENOTSUP, syscall.EXDEV} {
		if errors.Is(err, no) {
			return fmt.Errorf("%w (%v)", ErrNoHardLinks, err)
		}
	}
	return err
}
