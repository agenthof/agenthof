package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/agenthof/agenthof/internal/ledger"
)

// ErrNothingToSeal is the seal's verdict on an active that holds no record: a
// segment of only a seal record has no content.
var ErrNothingToSeal = errors.New("control: the active segment is empty; nothing to seal")

// ErrNoHardLinks is the seal's verdict when link(2) refused for a reason that
// means the filesystem does not make hard links. Judged before anything is
// recorded.
var ErrNoHardLinks = errors.New("control: this filesystem does not support hard links, which the rotation needs; nothing sealed")

var errNothingToComplete = errors.New("control: the active segment is open; nothing to complete")

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
// fixed line beside it: a link failure recorded nothing; a record failure
// left the segment open; a manifest or swap failure left state B or C,
// which a re-run completes.
type SealStep int

const (
	SealStepLink SealStep = iota + 1
	SealStepRecord
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
}

// checkSealShape is Append's structural permit for a seal record, decidable
// before the ledger is opened (checkAnchorShape's twin, with its rationale:
// Go cannot tell audit seal from another caller honestly, so the permit is a
// structural rule every writer must meet). A seal payload only on action
// seal; a successful seal carries one; a refused or error seal carries none;
// a seal carries no config_hash, no anchor, no detail; hashes are 64
// lowercase hex; segment ≥ 1, first_seq ≥ 1, head_seq ≥ first_seq. Whether
// the payload describes the active is checkSealPlacement's question.
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
	return nil
}

// checkSealPlacement needs the open chain: the payload must describe exactly
// the active this chain holds — segment N+1, first_seq Base+1, head_seq
// Base+Count, head_hash the chain's head, at least one record, and
// content_sha256 recomputed from the records read under the lock. A seal
// that passes it is the one audit seal would write; nothing else can be
// written as a seal.
func checkSealPlacement(c *ledger.Chain, view View, e Event) error {
	if e.Action != "seal" || e.Seal == nil {
		return nil
	}
	s := e.Seal
	want := len(view.Sealed) + 1
	first, head := int(c.Base())+1, int(c.Base())+c.Count()
	switch {
	case s.Segment != want:
		return fmt.Errorf("control: seal names segment %d; the active is segment %d", s.Segment, want)
	case c.Count() < 1:
		return ErrNothingToSeal
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
// ErrNothingToSeal; link the active under its segment name FIRST (a
// filesystem that cannot link fails with nothing recorded; EEXIST to the same
// inode is a re-run after a crash and continues; EEXIST to another file is
// FaultUnexpectedSegment); compute content_sha256 from the records read
// under the lock and append the seal record — commit 1, the segment is
// closed; write the manifest — commit 2, the set is rotated; swap a fresh,
// empty active under the name. The chain's lock is on the old inode
// throughout, and every name below derives from the View's resolved active
// path — the one the lock was taken on. e is a success seal event without a
// payload; the payload is computed here.
func SealActive(controlLog string, e Event) (SealResult, error) {
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
	n := len(v.Sealed) + 1
	if err := linkSegment(resolved, n); err != nil {
		return SealResult{}, &SealError{Step: SealStepLink, Err: err}
	}
	if crashAt("after_link_before_seal") {
		return SealResult{}, &SealError{Step: SealStepRecord, Err: errStoppedByTestHook}
	}
	e.Seal = &Seal{Segment: n, FirstSeq: int(c.Base()) + 1, HeadSeq: int(c.Base()) + c.Count(), HeadHash: c.Prev(), ContentSHA256: sealContentDigest(activeRecords(v))}
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
	return rotate(resolved, v)
}

// CompleteSeal finishes a rotation found in state B (manifest, swap) or C
// (swap). It locks the active by name exactly as a writer does and holds
// LOCK_EX for the duration — a sealed-not-rotated active takes no appends,
// but the lock still serializes two completions — reading the set as Read
// does (VerifyReader: nothing is appended, so no chain is resumed). An open
// active has nothing to complete.
func CompleteSeal(controlLog string) (SealResult, error) {
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
	res, err := rotate(resolved, v)
	res.Completed = true
	return res, err
}

// rotate is commit 2 and the swap over a View whose active ends in a
// successful seal (state B — the seal just written, or found) or whose
// manifest already lists it (state C): link if the link is missing, write
// the manifest with the new entry, swap. Each step is idempotent against a
// crash that already took it.
func rotate(resolved string, v View) (SealResult, error) {
	var n int
	var seg Segment
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
		last, _ := decodeRecord(active[len(active)-1])
		whole, size := segmentDigests(active)
		seg = Segment{N: n, Path: SegmentPath(resolved, n), FirstSeq: v.Active.FirstSeq, HeadSeq: v.Head.Count, HeadHash: v.Head.Hash, SHA256: whole, Bytes: size, Records: len(active), SealedAt: last.Time}
		logID := v.LogID
		if logID == "" {
			id, err := GenesisLogID(v.Records)
			if err != nil {
				return SealResult{}, &SealError{Step: SealStepManifest, Err: err}
			}
			logID = id
		}
		m := Manifest{V: ManifestVersion, LogID: logID}
		for _, s := range append(v.Sealed, seg) {
			m.Segments = append(m.Segments, ManifestEntry{N: s.N, File: filepath.Base(s.Path), FirstSeq: s.FirstSeq, HeadSeq: s.HeadSeq, HeadHash: s.HeadHash, SHA256: s.SHA256, Bytes: s.Bytes, SealedAt: s.SealedAt})
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
	return SealResult{Segment: n, FirstSeq: seg.FirstSeq, HeadSeq: seg.HeadSeq, HeadHash: seg.HeadHash, SHA256: seg.SHA256, Path: seg.Path}, nil
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
		fsyncDir(filepath.Dir(resolved))
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
