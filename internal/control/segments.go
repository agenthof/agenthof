package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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

// resolveControlLog resolves symlinks once. A name that does not exist (or a
// dangling link) resolves to itself, so the caller's open reports the
// name's own ENOENT.
func resolveControlLog(controlLog string) (string, error) {
	r, err := filepath.EvalSymlinks(controlLog)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return controlLog, nil
		}
		return "", err
	}
	return r, nil
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

// listSiblings globs resolved + ".seg-*" and returns ordinal → path. Any
// match that is not exactly six digits is an unexpected segment: nothing in
// the set is inferred from a glob, the glob only catches what the manifest
// does not explain.
func listSiblings(resolved string) (map[int]string, error) {
	matches, err := filepath.Glob(resolved + ".seg-*")
	if err != nil {
		return nil, err
	}
	base := filepath.Base(resolved)
	out := map[int]string{}
	for _, m := range matches {
		suffix := filepath.Base(m)[len(base):]
		sub := segmentNameRE.FindStringSubmatch(suffix)
		if sub == nil {
			return nil, &SetError{Fault: FaultUnexpectedSegment, Path: m}
		}
		n, _ := strconv.Atoi(sub[1])
		out[n] = m
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

// hasHistory reports whether a manifest or any .seg-* sibling exists.
func hasHistory(resolved string) bool {
	if _, err := os.Lstat(ManifestPath(resolved)); err == nil {
		return true
	}
	matches, _ := filepath.Glob(resolved + ".seg-*")
	return len(matches) > 0
}

func sameFile(path string, info os.FileInfo) bool {
	fi, err := os.Stat(path)
	return err == nil && os.SameFile(fi, info)
}

// Read verifies the whole set and returns the logical chain. The error, when
// non-nil, is a *SetError, the raw *fs.PathError of a root with no history
// (nothing recorded yet), or a lock/IO error; Records/Head still carry the
// valid prefix that verified before the fault, as ledger.ReadVerify does.
func Read(controlLog string, mode ledger.LockMode) (View, error) {
	resolved, err := resolveControlLog(controlLog)
	if err != nil {
		return View{}, err
	}
	f, err := openByName(resolved, mode)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && hasHistory(resolved) {
			return View{}, activeMissing(resolved)
		}
		return View{}, err // ENOENT is the raw *fs.PathError: "nothing recorded yet"
	}
	defer func() {
		if mode == ledger.Locked {
			ledger.Unlock(f)
		}
		_ = f.Close()
	}()
	return readSet(resolved, f, func(s ledger.Start) ([]ledger.Record, ledger.Head, error) {
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

// readSet is the read algorithm over an open, locked (or Unlocked-mode)
// handle that IS the active. verifyActive is how the caller reads the handle
// — ledger.VerifyReader for a reader, ledger.Resume for the writer — so the
// handle is read exactly once either way.
func readSet(resolved string, handle *os.File, verifyActive func(ledger.Start) ([]ledger.Record, ledger.Head, error)) (View, error) {
	hinfo, err := handle.Stat()
	if err != nil {
		return View{}, err
	}
	v := View{FirstSeq: 1, State: StateOpen}
	siblings, err := listSiblings(resolved)
	if err != nil {
		return v, err
	}
	m, err := loadManifest(resolved)
	if err != nil {
		return v, err
	}
	if m == nil {
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
			return v, mapActiveFault(resolved, 0, ledger.Start{}, recs, verr)
		}
		return finishActive(v, 0)
	}
	return readSealedSet(resolved, hinfo, siblings, m, verifyActive)
}

// readSealedSet is the read algorithm with a manifest present: each sealed
// segment in manifest order, the siblings the manifest does not explain, the
// active (or state C), the seal-terminal check and the identity check.
func readSealedSet(resolved string, hinfo os.FileInfo, siblings map[int]string, m *Manifest, verifyActive func(ledger.Start) ([]ledger.Record, ledger.Head, error)) (View, error) {
	v := View{FirstSeq: 1, State: StateOpen, LogID: m.LogID}
	start := ledger.Start{}
	for i, e := range m.Segments {
		k := i + 1
		seg, recs, err := verifySealed(resolved, k, start, e)
		v.Records = append(v.Records, recs...)
		if err != nil {
			v.Head = ledger.Head{Hash: start.Prev, Count: int(start.Base)}
			if len(recs) > 0 {
				v.Head = ledger.Head{Hash: hashOf(recs[len(recs)-1].Raw), Count: int(start.Base) + len(recs)}
			}
			return v, err
		}
		v.Sealed = append(v.Sealed, seg)
		start = ledger.Start{Prev: seg.HeadHash, Base: uint64(seg.HeadSeq)}
		delete(siblings, k)
	}
	n := len(m.Segments)
	// Siblings the manifest does not explain, judged against the handle: the
	// one tolerated is the in-progress link of seal N+1 (states A′ and B).
	for _, ord := range sortedOrdinals(siblings) {
		if ord == n+1 && sameFile(siblings[ord], hinfo) {
			continue
		}
		return v, &SetError{Fault: FaultUnexpectedSegment, Path: siblings[ord]}
	}
	v.Head = ledger.Head{Hash: start.Prev, Count: int(start.Base)}
	// State C: the active name still refers to the sealed file. The logical
	// active is empty; nothing more is read from the handle.
	if n > 0 && sameFile(SegmentPath(resolved, n), hinfo) {
		v.State = StateRotatedNotSwapped
		v.Active = Segment{N: 0, Path: resolved, FirstSeq: int(start.Base) + 1, HeadSeq: int(start.Base), HeadHash: start.Prev}
		return identityCheck(v, m)
	}
	recs, head, verr := verifyActive(start)
	v.Records = append(v.Records, recs...)
	v.Active = Segment{N: 0, Path: resolved, FirstSeq: int(start.Base) + 1, HeadSeq: int(start.Base) + head.Count, HeadHash: head.Hash, Bytes: hinfo.Size(), Records: head.Count}
	if head.Count > 0 {
		v.Head = ledger.Head{Hash: head.Hash, Count: int(start.Base) + head.Count}
	}
	if verr != nil {
		return v, mapActiveFault(resolved, n, start, recs, verr)
	}
	v, err := finishActive(v, n)
	if err != nil {
		return v, err
	}
	return identityCheck(v, m)
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
	content, whole, size := segmentDigests(recs)
	disagree := func(field string, recorded, verified any) error {
		return &SetError{Fault: FaultManifest, Segment: k, Path: path, Err: fmt.Errorf("%s %v recorded, %v verified", field, recorded, verified)}
	}
	var sealedAt time.Time
	for i, r := range recs {
		rec, ok := decodeRecord(r)
		if !ok || rec.Action != "seal" || rec.Outcome != "success" {
			continue
		}
		if i != len(recs)-1 {
			return Segment{}, recs, &SetError{Fault: FaultSealNotLast, Segment: k, Path: path, Seq: rec.Seq + 1, want: strconv.Itoa(headSeq)}
		}
		want := Seal{Segment: k, FirstSeq: int(start.Base) + 1, HeadSeq: rec.Seq - 1, HeadHash: rec.Prev, ContentSHA256: content}
		if rec.Seal == nil || *rec.Seal != want {
			return Segment{}, recs, disagree("seal", rec.Seal, want)
		}
		sealedAt = rec.Time
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
	return Segment{N: k, Path: path, FirstSeq: int(start.Base) + 1, HeadSeq: headSeq, HeadHash: head.Hash, SHA256: whole, Bytes: info.Size(), Records: head.Count, SealedAt: sealedAt}, recs, nil
}

// mapActiveFault translates the ledger's per-file error on the active into
// the set's fault with the global seq. A ChainBrokenError on line 1 of a
// continuation (Base > 0) is a boundary fault, never "broken".
func mapActiveFault(resolved string, sealedCount int, start ledger.Start, prefix []ledger.Record, verr error) error {
	var torn *ledger.TornError
	var broken *ledger.ChainBrokenError
	switch {
	case errors.As(verr, &torn):
		return &SetError{Fault: FaultTorn, Segment: 0, Path: resolved, Seq: int(start.Base) + len(prefix) + 1, Err: verr}
	case errors.As(verr, &broken):
		if broken.Line == 1 && start.Base > 0 {
			return &SetError{Fault: FaultBoundary, Segment: 0, Path: resolved, Seq: int(start.Base) + 1, Err: verr, want: strconv.Itoa(sealedCount)}
		}
		return &SetError{Fault: FaultBroken, Segment: 0, Path: resolved, Seq: int(start.Base) + broken.Line, Err: verr}
	}
	return verr
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
		content, _, _ := segmentDigests(active)
		want := Seal{Segment: sealedCount + 1, FirstSeq: v.Active.FirstSeq, HeadSeq: rec.Seq - 1, HeadHash: rec.Prev, ContentSHA256: content}
		if rec.Seal == nil || *rec.Seal != want {
			return v, &SetError{Fault: FaultManifest, Segment: sealedCount + 1, Path: v.Active.Path, Seq: rec.Seq, Err: fmt.Errorf("seal payload %+v recorded, %+v verified", rec.Seal, want)}
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

// openActive is the writer's entry. It opens and locks the active BY NAME,
// decides what the locked handle is, verifies the set exactly as Read does
// and returns the active chain (ledger.Resume over the locked handle) with
// the View. It never uses the fused ledger.Open/OpenFrom: the Start is known
// only after the sealed walk, and a locked handle that turns out to be the
// sealed file under the active's name (state C) must read as ErrSealed, not
// as a damaged chain. Order: (a) resolve, Lstat — a missing active beside a
// manifest or a sibling is FaultActiveMissing and nothing is created; with
// no history, today's create-on-first-write stands; (b) read the manifest M;
// (c) open by name, LOCK_EX; (d) re-stat; (e) re-read the manifest and
// require it to equal M — a seal that ran to completion between (b) and (c)
// left the name on a new, empty active that a stale Start would accept
// vacuously, and this writer would then duplicate the sealed range;
// (f) readSet over the locked handle: the sealed walk, the sibling check,
// state C (reached before the handle is read, so Resume never runs on the
// sealed inode), ledger.Resume as the active's one read, and the
// seal-terminal check; a set in state B or C is ErrSealed. (d) and (e) retry
// from (a) once.
func openActive(controlLog string) (*ledger.Chain, View, error) {
	resolved, err := resolveControlLog(controlLog)
	if err != nil {
		return nil, View{}, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		create := false
		if _, lerr := os.Lstat(resolved); lerr != nil {
			if !errors.Is(lerr, fs.ErrNotExist) {
				return nil, View{}, lerr
			}
			if hasHistory(resolved) {
				return nil, View{}, activeMissing(resolved)
			}
			create = true
		}
		m, merr := loadManifest(resolved)
		if merr != nil {
			return nil, View{}, merr
		}
		betweenWalkAndOpen()
		f, err := openForAppend(resolved, create)
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
		if !manifestEqual(m, m2) {
			ledger.Unlock(f)
			_ = f.Close()
			continue
		}
		var chain *ledger.Chain
		v, rerr := readSet(resolved, f, func(s ledger.Start) ([]ledger.Record, ledger.Head, error) {
			c, recs, err := ledger.Resume(f, ledger.Locked, s)
			chain = c
			head := ledger.Head{Hash: s.Prev}
			if len(recs) > 0 {
				head = ledger.Head{Hash: hashOf(recs[len(recs)-1].Raw), Count: len(recs)}
			}
			return recs, head, err
		})
		switch {
		case rerr != nil:
			ledger.Unlock(f)
			_ = f.Close()
			return nil, v, rerr
		case v.State != StateOpen:
			ledger.Unlock(f)
			_ = f.Close()
			return nil, v, ErrSealed
		}
		return chain, v, nil
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
	case len(a.Segments) == 0:
		return true
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
