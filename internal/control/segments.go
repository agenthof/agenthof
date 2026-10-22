package control

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/ledger"
)

// SegmentPath and ManifestPath derive the segment set's file names from the
// RESOLVED active path (filepath.EvalSymlinks, once, at the seam's entry) and
// nowhere else: a symlinked --control-log is a supported shape and link(2)
// does not dereference a symlink, so the segments and the manifest live
// beside the file, not beside the link. Neither name ends in .jsonl — runs
// prune deletes aged *.jsonl under --log-dir, and investigate/serve list
// *.jsonl as runs; the suffix rule is what keeps them out.
func SegmentPath(resolved string, n int) string { return fmt.Sprintf("%s.seg-%06d", resolved, n) }
func ManifestPath(resolved string) string       { return resolved + ".segments" }

// segmentNameRE is the one spelling of a segment: six digits, no more, no less.
var segmentNameRE = regexp.MustCompile(`^\.seg-([0-9]{6})$`)

// resolveControlLog resolves symlinks once. A name that does not exist
// resolves to itself, so the caller's open reports the name's own ENOENT. A
// DANGLING link resolves to its target (the link read, made absolute against
// the link's directory, that directory resolved): a sealed root's history
// lives beside the target, so that is where hasHistory must look before a
// writer is allowed to create — resolving to the link's own path would find
// no history beside the link and re-found a fresh genesis beside the sealed
// segments. The target is also what the writer's create-on-first-write makes
// and what every later resolution of the same name returns. Only ONE level of
// a dangling link is followed: a --control-log that is a link to another link
// to a missing target resolves to that middle link, not to the final target.
func resolveControlLog(controlLog string) (string, error) {
	r, err := filepath.EvalSymlinks(controlLog)
	if err == nil {
		return r, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	fi, lerr := os.Lstat(controlLog)
	if lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		return controlLog, nil
	}
	target, rerr := os.Readlink(controlLog)
	if rerr != nil {
		return "", rerr
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(controlLog), target)
	}
	dir, derr := filepath.EvalSymlinks(filepath.Dir(target))
	if derr != nil {
		if errors.Is(derr, fs.ErrNotExist) {
			return target, nil
		}
		return "", derr
	}
	return filepath.Join(dir, filepath.Base(target)), nil
}

// State is the rotation state the set is found in.
type State int

const (
	StateOpen              State = iota // the active segment takes appends (today's only state)
	StateSealedNotRotated               // the active's last record is a successful seal; the manifest does not list it yet
	StateRotatedNotSwapped              // the manifest lists it; the active name still refers to the sealed file
)

// Segment describes one segment as verified. N is 0 for the active.
type Segment struct {
	N        int
	Path     string
	FirstSeq int       // Base+1; for an empty active, the seq the next record will carry
	HeadSeq  int       // last seq; FirstSeq-1 when empty
	HeadHash string    // sha256 of the last line; the Start.Prev of the next segment
	SHA256   string    // whole-file sha256 (sealed segments; "" for the active)
	Bytes    int64     // the file's size
	Records  int       // records in this segment
	SealedAt time.Time // the seal record's time; zero for the active
	Sink     *SealSink // the seal record's sink block, carried as recorded; nil on a floor seal and for the active
}

// View is the ledger read as one logical chain. Head is LOGICAL: Count is
// the last seq of the chain (over a chain contiguous from 1 the record count
// IS the last seq, which keeps every `seq=` print and every records[seq-1]
// index correct), Hash the active's head or, when the active is empty, the
// last sealed head. FirstSeq is 1 (reserved for retention: the seq of
// Records[0]). Sealed is nil when the root has never sealed.
type View struct {
	Records  []ledger.Record
	Head     ledger.Head
	FirstSeq int
	Sealed   []Segment
	Active   Segment
	State    State
	LogID    string
}

// RotatingSegment is the ordinal of the segment whose rotation did not
// complete: in state B the active IS the sealed-but-unlisted segment (the
// manifest lists one fewer), in state C the manifest already lists it. It is
// meaningful only when State is not StateOpen.
func (v View) RotatingSegment() int {
	if v.State == StateSealedNotRotated {
		return len(v.Sealed) + 1
	}
	return len(v.Sealed)
}

// siblingNames lists the directory entries beside resolved whose name begins
// with the active's base name + ".seg-" — a plain prefix match on a directory
// listing, never a glob: filepath.Glob reads [, ], * and ? in the PATH as
// pattern syntax, so a root under a directory named like "a[1]" would list
// nothing with a nil error and every fault below would go silent. A missing
// directory is no siblings.
func siblingNames(resolved string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Dir(resolved))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	prefix := filepath.Base(resolved) + ".seg-"
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			out = append(out, filepath.Join(filepath.Dir(resolved), e.Name()))
		}
	}
	return out, nil
}

// listSiblings returns the .seg-* siblings as ordinal → path. Any sibling
// whose suffix is not exactly six digits is an unexpected segment: nothing
// in the set is inferred from the listing, it only catches what the manifest
// does not explain.
func listSiblings(resolved string) (map[int]string, error) {
	names, err := siblingNames(resolved)
	if err != nil {
		return nil, err
	}
	base := filepath.Base(resolved)
	out := map[int]string{}
	for _, p := range names {
		sub := segmentNameRE.FindStringSubmatch(filepath.Base(p)[len(base):])
		if sub == nil {
			return nil, &SetError{Fault: FaultUnexpectedSegment, Path: p}
		}
		n, _ := strconv.Atoi(sub[1])
		out[n] = p
	}
	return out, nil
}

// sortedOrdinals is the deterministic walk order over listSiblings' map, so
// a fault always names the lowest unexplained sibling.
func sortedOrdinals(siblings map[int]string) []int {
	ords := make([]int, 0, len(siblings))
	for n := range siblings {
		ords = append(ords, n)
	}
	slices.Sort(ords)
	return ords
}

// hasHistory reports whether a manifest or any .seg-* sibling exists beside
// resolved. A directory that cannot be listed is an error, never "no
// history": the answer decides whether a missing active is recreated.
func hasHistory(resolved string) (bool, error) {
	if _, err := os.Lstat(ManifestPath(resolved)); err == nil {
		return true, nil
	}
	names, err := siblingNames(resolved)
	if err != nil {
		return false, err
	}
	return len(names) > 0, nil
}

func sameFile(path string, info os.FileInfo) bool {
	fi, err := os.Stat(path)
	return err == nil && os.SameFile(fi, info)
}

// Read verifies the whole set and returns the logical chain. The error, when
// non-nil, is a *SetError, the raw *fs.PathError of a root with no history
// (nothing recorded yet), or a lock/IO error; Records/Head still carry the
// valid prefix that verified before the fault, as ledger.ReadVerify does.
//
// The sealed walk runs under the reader's shared lock: a seal needs the
// active's exclusive lock to commit, so while a reader holds LOCK_SH the
// manifest and the sealed files it names cannot change under it, and the two
// phases below see one consistent set with no re-check.
func Read(controlLog string, mode ledger.LockMode) (View, error) {
	resolved, err := resolveControlLog(controlLog)
	if err != nil {
		return View{}, err
	}
	f, err := openByName(resolved, mode)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			history, herr := hasHistory(resolved)
			if herr != nil {
				return View{}, herr
			}
			if history {
				return View{}, activeMissing(resolved)
			}
		}
		return View{}, err // ENOENT is the raw *fs.PathError: "nothing recorded yet"
	}
	defer func() {
		if mode == ledger.Locked {
			ledger.Unlock(f)
		}
		_ = f.Close()
	}()
	w, err := walkSealed(resolved)
	if err != nil {
		return w.v, err
	}
	return readActive(resolved, f, w, func(s ledger.Start) ([]ledger.Record, ledger.Head, error) {
		return ledger.VerifyReader(f, s)
	})
}

// activeMissing builds FaultActiveMissing with the sealed count the manifest
// lists (0 when only stray siblings exist).
func activeMissing(resolved string) *SetError {
	n := 0
	if m, err := loadManifest(resolved); err == nil && m != nil {
		n = len(m.Segments)
	}
	return &SetError{Fault: FaultActiveMissing, Path: resolved, want: strconv.Itoa(n)}
}

// openByName opens the active read-only, takes the shared flock when mode is
// Locked (bounded, ErrLockHeld on contention), then re-stats: a name rotated
// between open and lock refers to a different file than the handle, so the
// open is retried once; a second miss is an error naming contention. After
// it returns, the handle IS the file the name refers to. The writer's
// counterpart is openActive, which inspects between lock and verify.
func openByName(resolved string, mode ledger.LockMode) (*os.File, error) {
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(resolved, os.O_RDONLY, 0)
		if err != nil {
			return nil, err
		}
		if mode == ledger.Locked {
			if lerr := ledger.LockShared(f); lerr != nil {
				_ = f.Close()
				return nil, fmt.Errorf("ledger: read %s: %w", resolved, lerr)
			}
		}
		fi, err := f.Stat()
		if err != nil {
			if mode == ledger.Locked {
				ledger.Unlock(f)
			}
			_ = f.Close()
			return nil, err
		}
		if sameFile(resolved, fi) {
			return f, nil
		}
		if mode == ledger.Locked {
			ledger.Unlock(f)
		}
		_ = f.Close()
	}
	return nil, fmt.Errorf("control: %s was rotated twice while opening it; retry", resolved)
}

// sealedWalk is the first phase of the read algorithm: the manifest and the
// sealed segments it lists, verified in order. It needs no handle on the
// active — sealed files are fixed and the manifest is replaced whole — so
// the writer runs it BEFORE taking the active's exclusive lock (and holds
// the lock for the active alone) while the reader runs it under its shared
// lock. v carries the prefix so far (Records, Sealed, LogID; Head only when
// the walk failed); start is the Start the active must continue from; m is
// nil when the root has never sealed.
type sealedWalk struct {
	m     *Manifest
	v     View
	start ledger.Start
}

// walkSealed reads the manifest and verifies every sealed segment in its
// order. On a fault the returned view holds the valid prefix and its head,
// as ledger.ReadVerify does.
func walkSealed(resolved string) (sealedWalk, error) {
	w := sealedWalk{v: View{FirstSeq: 1, State: StateOpen}}
	m, err := loadManifest(resolved)
	if err != nil {
		return w, err
	}
	if m == nil {
		return w, nil
	}
	w.m, w.v.LogID = m, m.LogID
	for i, e := range m.Segments {
		k := i + 1
		seg, recs, err := verifySealed(resolved, k, w.start, e)
		w.v.Records = append(w.v.Records, recs...)
		if err != nil {
			w.v.Head = ledger.Head{Hash: w.start.Prev, Count: int(w.start.Base)}
			if len(recs) > 0 {
				w.v.Head = ledger.Head{Hash: hashOf(recs[len(recs)-1].Raw), Count: int(w.start.Base) + len(recs)}
			}
			return w, err
		}
		w.v.Sealed = append(w.v.Sealed, seg)
		w.start = ledger.Start{Prev: seg.HeadHash, Base: uint64(seg.HeadSeq)}
	}
	return w, nil
}

// readActive is the second phase, over an open handle that IS the active
// (locked, or Unlocked-mode): the siblings the manifest does not explain,
// judged against the handle; state C; the active's one read — verifyActive
// is ledger.VerifyReader for a reader and ledger.Resume for the writer; the
// seal-terminal check; the identity check.
func readActive(resolved string, handle *os.File, w sealedWalk, verifyActive func(ledger.Start) ([]ledger.Record, ledger.Head, error)) (View, error) {
	v := w.v
	hinfo, err := handle.Stat()
	if err != nil {
		return v, err
	}
	siblings, err := listSiblings(resolved)
	if err != nil {
		return v, err
	}
	if w.m == nil {
		// Single-segment mode: any sibling is a fault, except the first
		// seal's own link to this very inode (its state A′ or B).
		for _, n := range sortedOrdinals(siblings) {
			if n == 1 && sameFile(siblings[n], hinfo) {
				continue
			}
			return v, &SetError{Fault: FaultUnexpectedSegment, Path: siblings[n], noManifest: true, want: filepath.Base(ManifestPath(resolved))}
		}
		recs, head, verr := verifyActive(ledger.Start{})
		v.Records, v.Head = recs, head
		v.Active = Segment{N: 0, Path: resolved, FirstSeq: 1, HeadSeq: head.Count, HeadHash: head.Hash, Bytes: hinfo.Size(), Records: head.Count}
		if verr != nil {
			return v, mapActiveFault(resolved, handle, 0, ledger.Start{}, recs, verr)
		}
		return finishActive(v, 0)
	}
	n := len(w.m.Segments)
	start := w.start
	// Siblings the manifest does not explain, judged against the handle: the
	// one tolerated is the in-progress link of seal N+1 (states A′ and B).
	for _, ord := range sortedOrdinals(siblings) {
		if ord >= 1 && ord <= n {
			continue // listed by the manifest and verified above
		}
		if ord == n+1 && sameFile(siblings[ord], hinfo) {
			continue
		}
		// Ordinal 0 (no manifest ever lists it) and anything past N+1.
		return v, &SetError{Fault: FaultUnexpectedSegment, Path: siblings[ord]}
	}
	v.Head = ledger.Head{Hash: start.Prev, Count: int(start.Base)}
	// State C: the active name still refers to the sealed file. The logical
	// active is empty; nothing more is read from the handle. n >= 1: a
	// manifest naming no segment is refused by ParseManifest.
	if sameFile(SegmentPath(resolved, n), hinfo) {
		v.State = StateRotatedNotSwapped
		v.Active = Segment{N: 0, Path: resolved, FirstSeq: int(start.Base) + 1, HeadSeq: int(start.Base), HeadHash: start.Prev}
		return identityCheck(v, w.m)
	}
	recs, head, verr := verifyActive(start)
	v.Records = append(v.Records, recs...)
	v.Active = Segment{N: 0, Path: resolved, FirstSeq: int(start.Base) + 1, HeadSeq: int(start.Base) + head.Count, HeadHash: head.Hash, Bytes: hinfo.Size(), Records: head.Count}
	if head.Count > 0 {
		v.Head = ledger.Head{Hash: head.Hash, Count: int(start.Base) + head.Count}
	}
	if verr != nil {
		return v, mapActiveFault(resolved, handle, n, start, recs, verr)
	}
	v, err = finishActive(v, n)
	if err != nil {
		return v, err
	}
	return identityCheck(v, w.m)
}

// identityCheck: the manifest's log_id must be the genesis's — a manifest
// from another root is refused.
func identityCheck(v View, m *Manifest) (View, error) {
	logID, err := GenesisLogID(v.Records)
	if err != nil || logID != m.LogID {
		return v, &SetError{Fault: FaultManifest, Segment: 0, Path: ManifestPath(v.Active.Path), Err: fmt.Errorf("log_id %s recorded, %s verified", m.LogID, logID)}
	}
	return v, nil
}

// verifySealed reads one sealed segment: open it Unlocked (nothing writes a
// sealed segment), verify it from start, hash its lines, require its last
// record to be its seal and nothing to follow it, then cross-check the
// manifest entry and the seal payload. A disagreement names the field with
// the recorded and the verified value. The seal-terminal check runs before
// the manifest cross-checks on purpose: a record appended after the seal
// also changes head_seq, head_hash, sha256 and bytes, and the fault to name
// is the appended record, not the figures it disturbed.
func verifySealed(resolved string, k int, start ledger.Start, e ManifestEntry) (Segment, []ledger.Record, error) {
	path := SegmentPath(resolved, k)
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Segment{}, nil, &SetError{Fault: FaultMissingSegment, Segment: k, Path: path, want: e.SHA256}
	}
	if err != nil {
		return Segment{}, nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return Segment{}, nil, err
	}
	recs, head, verr := ledger.VerifyReader(f, start)
	var torn *ledger.TornError
	var broken *ledger.ChainBrokenError
	switch {
	case errors.As(verr, &torn):
		return Segment{}, recs, &SetError{Fault: FaultTorn, Segment: k, Path: path, Seq: int(start.Base) + len(recs) + 1, Err: verr, want: e.SHA256}
	case errors.As(verr, &broken):
		if broken.Line == 1 && k > 1 {
			return Segment{}, recs, &SetError{Fault: FaultBoundary, Segment: k, Path: path, Seq: int(start.Base) + 1, Err: verr}
		}
		return Segment{}, recs, &SetError{Fault: FaultBroken, Segment: k, Path: path, Seq: int(start.Base) + broken.Line, Err: verr, want: e.SHA256}
	case verr != nil:
		return Segment{}, recs, verr
	}
	headSeq := int(start.Base) + head.Count
	whole, size := segmentDigests(recs)
	disagree := func(field string, recorded, verified any) error {
		return &SetError{Fault: FaultManifest, Segment: k, Path: path, Err: fmt.Errorf("%s %v recorded, %v verified", field, recorded, verified)}
	}
	var sealedAt time.Time
	var sink *SealSink
	for i, r := range recs {
		rec, ok := decodeRecord(r)
		if !ok || rec.Action != "seal" || rec.Outcome != "success" {
			continue
		}
		if i != len(recs)-1 {
			return Segment{}, recs, &SetError{Fault: FaultSealNotLast, Segment: k, Path: path, Seq: rec.Seq + 1, want: strconv.Itoa(headSeq)}
		}
		want := Seal{Segment: k, FirstSeq: int(start.Base) + 1, HeadSeq: rec.Seq - 1, HeadHash: rec.Prev, ContentSHA256: sealContentDigest(recs[:i])}
		if !sealChainFieldsAgree(rec.Seal, want) {
			return Segment{}, recs, disagree("seal", rec.Seal, want)
		}
		// The sink block is carried, not recomputed; the one thing the chain
		// can say about it is that its retain_until is after the seal's time.
		if rec.Seal.Sink != nil && !rec.Seal.Sink.RetainUntil.After(rec.Time) {
			return Segment{}, recs, &SetError{Fault: FaultManifest, Segment: k, Path: path, Err: sinkRetainErr(rec.Seal.Sink, rec.Time)}
		}
		sealedAt, sink = rec.Time, rec.Seal.Sink
	}
	if sealedAt.IsZero() {
		return Segment{}, recs, disagree("seal", "none", "a successful seal as the last record")
	}
	switch {
	case e.FirstSeq != int(start.Base)+1:
		return Segment{}, recs, disagree("first_seq", e.FirstSeq, start.Base+1)
	case e.HeadSeq != headSeq:
		return Segment{}, recs, disagree("head_seq", e.HeadSeq, headSeq)
	case e.HeadHash != head.Hash:
		return Segment{}, recs, disagree("head_hash", e.HeadHash, head.Hash)
	case e.SHA256 != whole:
		return Segment{}, recs, disagree("sha256", e.SHA256, whole)
	case e.Bytes != info.Size() || size != info.Size():
		return Segment{}, recs, disagree("bytes", e.Bytes, info.Size())
	}
	return Segment{N: k, Path: path, FirstSeq: int(start.Base) + 1, HeadSeq: headSeq, HeadHash: head.Hash, SHA256: whole, Bytes: info.Size(), Records: head.Count, SealedAt: sealedAt, Sink: sink}, recs, nil
}

// mapActiveFault translates the ledger's per-file error on the active into
// the set's fault with the global seq. A ChainBrokenError on line 1 of a
// continuation (Base > 0) is a boundary fault, never "broken"; when that
// first record is a fresh genesis the fault names the older-binary cause
// (an older writer, opening the empty active with a zero Start, minted its
// own seq-1 genesis). The verifier returns no records on a line-1 fault, so
// the first line is read from handle — on this fault path only, never on the
// success path, which keeps the active's one read.
func mapActiveFault(resolved string, handle io.ReaderAt, sealedCount int, start ledger.Start, prefix []ledger.Record, verr error) error {
	var torn *ledger.TornError
	var broken *ledger.ChainBrokenError
	switch {
	case errors.As(verr, &torn):
		return &SetError{Fault: FaultTorn, Segment: 0, Path: resolved, Seq: int(start.Base) + len(prefix) + 1, Err: verr}
	case errors.As(verr, &broken):
		if broken.Line == 1 && start.Base > 0 {
			return &SetError{Fault: FaultBoundary, Segment: 0, Path: resolved, Seq: int(start.Base) + 1, Err: verr, want: strconv.Itoa(sealedCount), olderBinary: firstLineIsFreshGenesis(handle)}
		}
		return &SetError{Fault: FaultBroken, Segment: 0, Path: resolved, Seq: int(start.Base) + broken.Line, Err: verr}
	}
	return verr
}

// maxGenesisLine bounds the first-line read of firstLineIsFreshGenesis.
const maxGenesisLine = 8 << 10

// firstLineIsFreshGenesis reports whether the first line of r is what Append
// mints on an empty ledger: an empty prev and a log_id of 32 lowercase hex. A
// read or decode failure is "no" — the generic boundary text stands.
func firstLineIsFreshGenesis(r io.ReaderAt) bool {
	// A genesis line is a few hundred bytes. The cap keeps a corrupt active
	// with no newline from being buffered whole; a line that long is not a
	// fresh genesis, and the unterminated, truncated read fails to decode.
	line, err := bufio.NewReader(io.LimitReader(io.NewSectionReader(r, 0, math.MaxInt64), maxGenesisLine)).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	var first struct {
		Prev  string `json:"prev"`
		LogID string `json:"log_id"`
	}
	if json.Unmarshal(line, &first) != nil {
		return false
	}
	return first.Prev == "" && genesisLogIDRE.MatchString(first.LogID)
}

// finishActive is the seal-terminal check over the active's records: a
// successful seal that is not the last record is FaultSealNotLast{0}; a
// successful seal that IS the last record and recomputes marks the set
// StateSealedNotRotated; one that does not recompute is a planted seal
// (FaultManifest{N+1}). sealedCount is N.
func finishActive(v View, sealedCount int) (View, error) {
	active := activeRecords(v)
	for i, r := range active {
		rec, ok := decodeRecord(r)
		if !ok || rec.Action != "seal" || rec.Outcome != "success" {
			continue
		}
		if i != len(active)-1 {
			return v, &SetError{Fault: FaultSealNotLast, Segment: 0, Path: v.Active.Path, Seq: rec.Seq + 1, want: strconv.Itoa(v.Head.Count)}
		}
		want := Seal{Segment: sealedCount + 1, FirstSeq: v.Active.FirstSeq, HeadSeq: rec.Seq - 1, HeadHash: rec.Prev, ContentSHA256: sealContentDigest(active[:i])}
		if !sealChainFieldsAgree(rec.Seal, want) {
			return v, &SetError{Fault: FaultManifest, Segment: sealedCount + 1, Path: v.Active.Path, Seq: rec.Seq, Err: fmt.Errorf("seal payload %+v recorded, %+v verified", rec.Seal, want)}
		}
		if rec.Seal.Sink != nil && !rec.Seal.Sink.RetainUntil.After(rec.Time) {
			return v, &SetError{Fault: FaultManifest, Segment: sealedCount + 1, Path: v.Active.Path, Seq: rec.Seq, Err: sinkRetainErr(rec.Seal.Sink, rec.Time)}
		}
		v.State = StateSealedNotRotated
	}
	return v, nil
}

// activeRecords is the active's slice of the logical records.
func activeRecords(v View) []ledger.Record {
	return v.Records[len(v.Records)-v.Active.Records:]
}

// hashOf is the ledger's line hash: sha256 of the line without its newline.
func hashOf(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }

// decodeRecord is the one-record decode every walker uses; a record the
// chain admitted always decodes, so false is defensive.
func decodeRecord(r ledger.Record) (record, bool) {
	var rec record
	if err := json.Unmarshal(r.Raw, &rec); err != nil {
		return record{}, false
	}
	return rec, true
}

// Writable is the writer's precheck: the set opens, locks and verifies, and
// the active is open for appends. It holds nothing past its return. The
// error is nil, a wrapped ledger.ErrLockHeld (busy), ErrSealed (state B or
// C), a *SetError, or an IO error.
func Writable(controlLog string) error {
	c, _, err := openActive(controlLog)
	if err != nil {
		return err
	}
	return c.Close()
}

// Test hooks: no-ops in production; a test installs a function that rotates
// the ledger at the one schedule each rule exists for.
var (
	betweenOpenAndLock = func() {}
	betweenWalkAndOpen = func() {}
)

// openActive is the writer's entry: lockActive with ledger.Resume as the
// active's one read, so the caller gets the active chain over the locked
// handle, plus the writer's verdict — a set in state B or C is ErrSealed and
// nothing is held. It never uses the fused ledger.Open/OpenFrom: the Start is
// known only after the sealed walk, and a locked handle that turns out to be
// the sealed file under the active's name (state C) must read as ErrSealed,
// not as a damaged chain — in state C readActive never calls the verifier, so
// Resume never runs on the sealed inode and chain stays nil.
func openActive(controlLog string) (*ledger.Chain, View, error) {
	var chain *ledger.Chain
	f, v, err := lockActive(controlLog, true, func(f *os.File, s ledger.Start) ([]ledger.Record, ledger.Head, error) {
		c, recs, err := ledger.Resume(f, ledger.Locked, s)
		chain = c
		head := ledger.Head{Hash: s.Prev}
		if len(recs) > 0 {
			head = ledger.Head{Hash: hashOf(recs[len(recs)-1].Raw), Count: len(recs)}
		}
		return recs, head, err
	})
	if err != nil {
		return nil, v, err
	}
	if v.State != StateOpen {
		ledger.Unlock(f)
		_ = f.Close()
		return nil, v, ErrSealed
	}
	return chain, v, nil
}

// lockActive walks the sealed segments, then opens and locks the active BY
// NAME, decides what the locked handle is, and returns the handle (locked
// LOCK_EX; the caller releases it) with the View in whatever rotation state
// the set is — openActive adds the writer's verdict, CompleteSeal requires
// state B or C. Order: (a) resolve; Stat (following a symlink, as
// ledger.Open's create-or-resume did) — a missing active beside a manifest
// or a sibling is FaultActiveMissing and nothing is created; with no history,
// today's create-on-first-write stands when create is set, else the name's
// own ENOENT; (b) walkSealed — the manifest M and every sealed segment, read
// without the active's lock (they are fixed files), so the exclusive lock
// below is held for the active alone, not for O(total bytes); (c) open by
// name, LOCK_EX; (d) re-stat; (e) re-read the manifest and require it to
// equal M — a seal that ran to completion between (b) and (c) left the name
// on a new, empty active that the stale Start would accept vacuously, and
// this writer would then duplicate the sealed range; (f) readActive over the
// locked handle: the sibling check, state C (decided before the handle is
// read), verifyActive as the active's one read, the seal-terminal check. (d)
// and (e) retry from (a) once. On an error nothing is held.
func lockActive(controlLog string, create bool, verifyActive func(*os.File, ledger.Start) ([]ledger.Record, ledger.Head, error)) (*os.File, View, error) {
	resolved, err := resolveControlLog(controlLog)
	if err != nil {
		return nil, View{}, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		missing := false
		if _, serr := os.Stat(resolved); serr != nil {
			if !errors.Is(serr, fs.ErrNotExist) {
				return nil, View{}, serr
			}
			history, herr := hasHistory(resolved)
			if herr != nil {
				return nil, View{}, herr
			}
			if history {
				return nil, View{}, activeMissing(resolved)
			}
			missing = true
		}
		w, werr := walkSealed(resolved)
		if werr != nil {
			return nil, w.v, werr
		}
		betweenWalkAndOpen()
		f, err := openForAppend(resolved, missing && create)
		if err != nil {
			return nil, View{}, err
		}
		betweenOpenAndLock()
		if lerr := ledger.LockExclusive(f); lerr != nil {
			_ = f.Close()
			return nil, View{}, fmt.Errorf("ledger: open %s: %w", resolved, lerr)
		}
		fi, serr := f.Stat()
		if serr != nil || !sameFile(resolved, fi) {
			ledger.Unlock(f)
			_ = f.Close()
			continue
		}
		m2, merr := loadManifest(resolved)
		if merr != nil {
			ledger.Unlock(f)
			_ = f.Close()
			return nil, View{}, merr
		}
		if !manifestEqual(w.m, m2) {
			ledger.Unlock(f)
			_ = f.Close()
			continue
		}
		v, rerr := readActive(resolved, f, w, func(s ledger.Start) ([]ledger.Record, ledger.Head, error) {
			return verifyActive(f, s)
		})
		if rerr != nil {
			ledger.Unlock(f)
			_ = f.Close()
			return nil, v, rerr
		}
		return f, v, nil
	}
	return nil, View{}, fmt.Errorf("control: %s was rotated twice while opening it; retry", resolved)
}

// manifestEqual: same N and same last head (nil == nil).
func manifestEqual(a, b *Manifest) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil || len(a.Segments) != len(b.Segments):
		return false
	}
	return a.Segments[len(a.Segments)-1].HeadHash == b.Segments[len(b.Segments)-1].HeadHash
}

// openForAppend is today's create-on-first-write (ledger.Open's flags and
// its directory fsync on create) when create is set, else a plain open.
func openForAppend(resolved string, create bool) (*os.File, error) {
	flag := os.O_RDWR | os.O_APPEND
	if create {
		if err := os.MkdirAll(filepath.Dir(resolved), 0o700); err != nil {
			return nil, err
		}
		flag |= os.O_CREATE
	}
	f, err := os.OpenFile(resolved, flag, 0o600)
	if err != nil {
		return nil, err
	}
	if create {
		if d, derr := os.Open(filepath.Dir(resolved)); derr == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return f, nil
}
