package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/agenthof/agenthof/internal/ledger"
)

// ErrNothingToRestore is the restore's verdict on a set that reads clean: a
// restore answers a fault the local manifest names; a sink holding more than
// the root is the rebuild's question.
var ErrNothingToRestore = errors.New("control: nothing to restore; if the sink holds more than this root — audit verify control exit 9 — run: audit restore control --rebuild")

// maxRestoreBody bounds a copy's read when no manifest figure bounds it.
// The sink package documents the same figure as its own; this package
// imports no storage client, so the literal lives here too.
const maxRestoreBody = 256 << 20

// RestoredSegment is one sealed segment put back from its protected copy.
type RestoredSegment struct {
	N         int
	Sink      SealSink // the restored seal's own block: where the copy came from
	VersionID string   // the version the chain selected
	SHA256    string   // the restored file's whole-file digest
	// Replaced is the "<base>.replaced-NNNNNN-<ts>" file the bytes found under
	// the segment's name were moved to; "" when nothing was there.
	Replaced string
	// NotOldest: the selected version is not the oldest at the key (the
	// oldest does not chain). Unlocked: the selected version is not under a
	// COMPLIANCE lock. ManifestDisagrees: the manifest's sha256 for the
	// segment is not the restored bytes' — the entry is the wrong one. Each
	// is information the command prints; none stops the restore.
	NotOldest, Unlocked, ManifestDisagrees bool
}

// RestoreResult is what a restore did. Head is the chain's head after the
// last restore record.
type RestoreResult struct {
	Restored []RestoredSegment
	Head     ledger.Head
}

// Restore puts sealed segments back from their protected copies in the
// sink: every segment the read's verdict names, in ascending order,
// re-reading between segments, until the set reads clean; then one
// "restore" record per segment restored. only narrows to the named
// ordinals (nil: whatever is at fault); a named ordinal that is not at fault
// is refused before anything is written, naming the fault that is.
//
// The verdicts it answers are the faults in a sealed segment the manifest
// lists — FaultMissingSegment{k}, FaultTorn{k}, FaultBroken{k},
// FaultManifest{k} (a disagreeing figure), FaultBoundary{k ≥ 2} (segment k
// is the one that does not chain; k−1 verified). Everything else refuses
// with its own text and changes nothing: a clean set (ErrNothingToRestore),
// an incomplete rotation ("run audit seal"), a fault in the active (the
// repair's, or its own remedy), a missing or unusable manifest and a missing
// active beside history (both: the rebuild, with the ledger's identity when
// one reads).
//
// An incomplete rotation (state B or C) refuses before any write, decided
// from the active itself (incompleteRotation): with an earlier segment at
// fault Read's verdict cannot say so, and a restore that wrote first would
// leave its record owed forever, or move the active's own inode aside.
//
// Selection is by the chain, never by the manifest (verifyFetchedSegment):
// the versions at the segment's key, oldest first, until one is sealed
// segment k continuing the verified prefix — and the one whose seal line
// what follows chains from: segment k+1's first record, or the active's
// for the last listed segment. The manifest's sha256 is a
// cross-check only (ManifestDisagrees); the version's position and lock are
// reported (NotOldest, Unlocked). A sink error is that error with nothing
// written — "the protected copy is missing" is said only of an exhausted
// listing. Every sink call runs before the active is locked.
//
// Writing is temp → rename beside the ledger under the active's exclusive
// lock (holdActive, which also excludes a seal's walk-then-lock), the bytes
// found under the name moved aside first (moveAsideReplaced — never
// deleted: they are the evidence of what was there). The lock is released
// before the set is re-read and before the record is appended: Read takes
// LOCK_SH and Append LOCK_EX on fresh descriptors of the same file, and
// flock contends across descriptors within one process. The window between
// the rename and the record is Repair's residual, stated the same way: a
// failure or crash there leaves a verifying set with no record — the next
// verify is clean, and the .replaced-* file is the evidence. A set that
// does not read clean after a write (a manifest entry that is the wrong
// one, a later fault restore does not answer, a named ordinal exhausted)
// returns that fault beside the Restored so far: the bytes are left in
// place — they are the chain's — and nothing is recorded.
func Restore(controlLog string, only []int, r SinkReader, e Event) (RestoreResult, error) {
	if e.Action != "restore" || e.Outcome != "success" || e.Detail != "" {
		return RestoreResult{}, errors.New("control: Restore takes a success restore event without a detail")
	}
	resolved, err := resolveControlLog(controlLog)
	if err != nil {
		return RestoreResult{}, err
	}
	var res RestoreResult
	last := 0 // the highest ordinal restored so far
	for {
		v, verr := Read(controlLog, ledger.Locked)
		if verr == nil {
			if v.State != StateOpen {
				return res, errNotRestoreMatter(controlLog)
			}
			if last == 0 {
				return res, ErrNothingToRestore
			}
			break
		}
		k, m, rerr := restorable(resolved, v, verr)
		if rerr != nil {
			return res, rerr
		}
		if k <= last {
			return res, verr // the write did not clear the verdict: the fault stands
		}
		// An incomplete rotation refuses BEFORE any write (§11.2 step 4).
		// Read cannot say so here — its sealed walk stopped at k before the
		// active's state was decided — so the active is peeked at directly.
		incomplete, err := incompleteRotation(resolved, len(m.Segments))
		if err != nil {
			return res, err
		}
		if incomplete {
			return res, errNotRestoreMatter(controlLog)
		}
		if only != nil && !slices.Contains(only, k) {
			for _, n := range slices.Sorted(slices.Values(only)) {
				if n > last {
					return res, fmt.Errorf("control: segment %d is not at fault; the fault is in segment %d", n, k)
				}
			}
			return res, verr // every named ordinal is done; the rest is not this run's
		}
		seg, err := restoreSegment(resolved, v, m, k, verr, r)
		if err != nil {
			return res, err
		}
		res.Restored = append(res.Restored, seg)
		last = k
	}
	for _, s := range res.Restored {
		kept := "nothing was there"
		if s.Replaced != "" {
			kept = "replaced bytes kept at " + filepath.Base(s.Replaced)
		}
		rec := e
		rec.Detail = fmt.Sprintf("segment %d restored from %s version %s; %s", s.N, s.Sink.Kind, s.VersionID, kept)
		head, err := Append(resolved, rec)
		if err != nil {
			return res, fmt.Errorf("control: segment %d restored, but the restore record could not be appended: %w", s.N, err)
		}
		res.Head = head
	}
	return res, nil
}

// errNotRestoreMatter is the refusal on a sealed, not-yet-rotated active:
// completing a rotation is audit seal's, and a restore writes nothing on
// such a root.
func errNotRestoreMatter(controlLog string) error {
	return fmt.Errorf("control: ledger %s: the active segment is sealed and not yet rotated; run audit seal to complete it — not a restore matter", controlLog)
}

// incompleteRotation reports whether the active is a sealed segment whose
// rotation did not complete, decided from the active alone and before any
// write: state C — the active name refers to the inode of the last segment
// the manifest lists (listed; a restore of that segment would move the
// active's own inode aside and the re-read would misdiagnose a replaced
// active); state B — the active's last complete line is a successful seal
// (the manifest does not list it yet). A torn or missing last line is no
// seal: the active's own faults are the next read's to name. An absent
// active is no rotation at all (the rebuild tolerates one; a restore
// refused it from the read's verdict already).
func incompleteRotation(resolved string, listed int) (bool, error) {
	fi, err := os.Stat(resolved)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if listed > 0 && sameFile(SegmentPath(resolved, listed), fi) {
		return true, nil
	}
	line, err := lastLine(resolved, fi.Size())
	if err != nil || line == nil {
		return false, err
	}
	rec, ok := decodeRecord(ledger.Record{Raw: line})
	return ok && rec.Action == "seal" && rec.Outcome == "success", nil
}

// lastLine is the last newline-terminated line of the file at path, read
// from a bounded tail (maxRecordLine); nil when the file is empty, its last
// line is unterminated, or the line runs past the bound (not a control
// record).
func lastLine(path string, size int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	off := max(int64(0), size-maxRecordLine)
	buf := make([]byte, size-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if !bytes.HasSuffix(buf, []byte("\n")) {
		return nil, nil
	}
	buf = buf[:len(buf)-1]
	i := bytes.LastIndexByte(buf, '\n')
	if i < 0 && off > 0 {
		return nil, nil
	}
	return buf[i+1:], nil
}

// restorable decides whether verr is a fault a restore answers: a fault in
// a sealed segment k that the manifest lists. It returns k and the manifest;
// otherwise the error to return — verr unchanged for a fault with its own
// remedy (the active's, a seal appended to), or verr with the rebuild named
// for a missing or unusable manifest and a missing active.
func restorable(resolved string, v View, verr error) (int, *Manifest, error) {
	var se *SetError
	if !errors.As(verr, &se) {
		return 0, nil, verr // nothing recorded, a lock or IO error: as found
	}
	switch {
	case se.Fault == FaultActiveMissing,
		se.Fault == FaultManifest && se.Segment == 0,
		se.Fault == FaultUnexpectedSegment && se.noManifest:
		return 0, nil, fmt.Errorf("%w; run: audit restore control --rebuild --log-id %s", verr, rootLogID(resolved, v))
	case se.Segment == 0:
		return 0, nil, verr
	}
	switch se.Fault {
	case FaultMissingSegment, FaultTorn, FaultBroken, FaultManifest, FaultBoundary:
	default:
		return 0, nil, verr
	}
	m, err := loadManifest(resolved)
	if err != nil {
		return 0, nil, err
	}
	// A FaultManifest{N+1} is a planted seal in the ACTIVE (finishActive):
	// the manifest lists no such segment and no copy of it was ever
	// confirmed.
	if m == nil || se.Segment > len(m.Segments) || len(v.Sealed) != se.Segment-1 {
		return 0, nil, verr
	}
	return se.Segment, m, nil
}

// rootLogID is the ledger's identity for a rebuild hint, from whatever
// reads: the manifest's (the View carries it once the manifest loaded), the
// genesis's among the View's records, the manifest's read afresh, the first
// line of segment 1; else the literal placeholder.
func rootLogID(resolved string, v View) string {
	if v.LogID != "" {
		return v.LogID
	}
	if id, err := GenesisLogID(v.Records); err == nil {
		return id
	}
	if m, err := loadManifest(resolved); err == nil && m != nil {
		return m.LogID
	}
	if f, err := os.Open(SegmentPath(resolved, 1)); err == nil {
		defer func() { _ = f.Close() }()
		line, err := bufio.NewReader(io.LimitReader(f, maxGenesisLine)).ReadBytes('\n')
		if err == nil || errors.Is(err, io.EOF) {
			if id, gerr := GenesisLogID([]ledger.Record{{Raw: bytes.TrimSuffix(line, []byte("\n"))}}); gerr == nil {
				return id
			}
		}
	}
	return "<id>"
}

// restoreSegment is one segment's selection (every sink call) and write.
func restoreSegment(resolved string, v View, m *Manifest, k int, verr error, r SinkReader) (RestoredSegment, error) {
	start := ledger.Start{}
	if k >= 2 {
		prev := v.Sealed[k-2]
		start = ledger.Start{Prev: prev.HeadHash, Base: uint64(prev.HeadSeq)}
	}
	entry := m.Segments[k-1]
	// The read bound is the larger of a trusted manifest figure (bytes, when
	// the fault is not the entry's own) and the listing's size, under the
	// cap — so in effect the listing's size, which is the sink's own figure;
	// the manifest's only ever widens it, never narrows a copy out of reach.
	bound := int64(maxRestoreBody)
	var se *SetError
	if errors.As(verr, &se) && se.Fault != FaultManifest {
		bound = entry.Bytes
	}
	key := r.Prefix(v.LogID) + fmt.Sprintf("seg-%06d", k)
	ctx := context.Background()
	kv, err := r.ListVersions(ctx, key)
	if err != nil {
		return RestoredSegment{}, fmt.Errorf("control: segment %d: %w", k, err)
	}
	// The continuity constraint: what follows segment k must chain from the
	// selected seal line — segment k+1's first record, or the active's for
	// the last listed segment (an empty active constrains nothing).
	next, nextPath := fmt.Sprintf("segment %d", k+1), SegmentPath(resolved, k+1)
	if k == len(m.Segments) {
		next, nextPath = "the active segment", resolved
	}
	local := strings.TrimPrefix(next, "the ") // "the local segment 3" / "the local active segment"
	nextPrev := firstPrev(nextPath)
	var data []byte
	var seg Segment
	selected, chained := -1, 0
	for i, ver := range kv.Versions {
		b, err := r.Get(ctx, key, ver.ID, min(max(bound, ver.Size), maxRestoreBody))
		if err != nil {
			return RestoredSegment{}, fmt.Errorf("control: segment %d: %w", k, err)
		}
		s, _, verr := verifyFetchedSegment(b, k, start, v.LogID, key)
		if verr != nil {
			continue
		}
		if nextPrev != "" && s.HeadHash != nextPrev {
			chained++
			continue
		}
		data, seg, selected = b, s, i
		break
	}
	if selected < 0 {
		from := "the genesis"
		if k >= 2 {
			from = fmt.Sprintf("segment %d's head %s", k-1, start.Prev)
		}
		if chained > 0 {
			// A copy chains, and what should follow it does not continue it.
			// Which side is wrong cannot be known here: the chaining copy may
			// not be the seal's own, or the local file after it may have been
			// replaced. The rebuild's own continuity check decides from the
			// sink's whole chain.
			return RestoredSegment{}, fmt.Errorf("control: segment %d: %d version(s) at %s chain from %s, but %s's first record continues none of them — either the chaining copy at the key is not the seal's own (audit verify control's sink pass judges the oldest version) or the local %s was replaced; run: audit restore control --rebuild --log-id %s", k, chained, key, from, next, local, v.LogID)
		}
		return RestoredSegment{}, fmt.Errorf("control: segment %d: no version at %s chains from %s; the protected copy is missing", k, key, from)
	}
	id := kv.Versions[selected].ID
	lock, err := r.GetRetention(ctx, key, id)
	if err != nil {
		// Fail closed: the bytes are the chain's, but a lock that cannot be
		// read is not reported as one; nothing is written. A denied read is
		// the credential's, as audit verify control's is.
		return RestoredSegment{}, fmt.Errorf("control: segment %d: the lock on version %s could not be read; nothing was written — if the credential is denied, grant s3:GetObjectRetention (with s3:GetObject and s3:ListBucketVersions) and re-run: %w", k, id, err)
	}
	out := RestoredSegment{N: k, Sink: *seg.Sink, VersionID: id, SHA256: seg.SHA256,
		NotOldest: selected > 0, Unlocked: lock.Mode != "COMPLIANCE", ManifestDisagrees: entry.SHA256 != seg.SHA256}

	f, err := holdActive(resolved)
	if err != nil {
		return RestoredSegment{}, err
	}
	defer func() {
		ledger.Unlock(f)
		_ = f.Close()
	}()
	sweepTemps(resolved)
	path := SegmentPath(resolved, k)
	if _, err := os.Lstat(path); err == nil {
		name, err := moveAsideReplaced(path, fmt.Sprintf("%06d", k))
		if err != nil {
			return RestoredSegment{}, err
		}
		out.Replaced = name
	} else if !errors.Is(err, fs.ErrNotExist) {
		return RestoredSegment{}, err
	}
	if err := writeRestored(resolved, path, data); err != nil {
		return RestoredSegment{}, fmt.Errorf("control: segment %d: the restored bytes could not be written: %w", k, err)
	}
	return out, nil
}

// maxRecordLine bounds the read of one record line — a segment's first for
// the continuity check, the active's last for the rotation peek: a control
// record is at most a few KB (an anchor's proof is capped at 8 KB).
const maxRecordLine = 64 << 10

// firstPrev is the prev of the first record of the file at path, or "" when
// the file is absent, unreadable or its first line does not decode: then
// nothing constrains the selection beyond the chain.
func firstPrev(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	line, err := bufio.NewReader(io.LimitReader(f, maxRecordLine)).ReadBytes('\n')
	if err != nil {
		return ""
	}
	var first struct {
		Prev string `json:"prev"`
	}
	if json.Unmarshal(line, &first) != nil {
		return ""
	}
	return first.Prev
}

// verifyFetchedSegment judges bytes fetched from the sink as sealed segment
// k: (a) every line decodes and the records chain from start (k = 1: a
// genesis with prev "" and log_id == logID); (b) the first record's prev and
// seq continue start; (c) the last line is a successful seal that recomputes
// over the records before it, as segment k, and nothing follows it; (d) the
// seal's sink block names key, and its retain_until is after the seal's
// time (the reader's rule, so the written file verifies). What it accepts
// is exactly what verifySealed accepts at position k from start, the
// manifest cross-checks aside. Errors name the ordinal and the rule.
func verifyFetchedSegment(data []byte, k int, start ledger.Start, logID, key string) (Segment, []ledger.Record, error) {
	recs, head, err := ledger.VerifyReader(bytes.NewReader(data), start)
	var broken *ledger.ChainBrokenError
	switch {
	case errors.As(err, &broken) && broken.Line == 1 && k >= 2:
		// A record that does not continue start is judged before "no record
		// verified": the chain stops before its first line.
		return Segment{}, nil, fmt.Errorf("segment %d's first record does not chain from segment %d's head %s", k, k-1, start.Prev)
	case len(recs) == 0:
		return Segment{}, nil, fmt.Errorf("segment %d: the oldest version at the key is not a sealed segment of this ledger — the sink's copy was replaced before the seal could write it, or the key was pre-occupied", k)
	case errors.As(err, &broken):
		return Segment{}, nil, fmt.Errorf("segment %d: the copy's chain is broken at its line %d", k, broken.Line)
	case err != nil:
		return Segment{}, nil, fmt.Errorf("segment %d: the copy is torn after %d records", k, len(recs))
	}
	if k == 1 {
		id, err := GenesisLogID(recs)
		if err != nil {
			return Segment{}, nil, fmt.Errorf("segment 1: the copy's first record is not a genesis (%v)", err)
		}
		if id != logID {
			return Segment{}, nil, fmt.Errorf("segment 1: the genesis carries log_id %s, not this ledger's %s", id, logID)
		}
	}
	for i, r := range recs[:len(recs)-1] {
		if rec, ok := decodeRecord(r); ok && rec.Action == "seal" && rec.Outcome == "success" {
			return Segment{}, nil, fmt.Errorf("segment %d: a record follows the seal line (seal at line %d of %d)", k, i+1, len(recs))
		}
	}
	last, ok := decodeRecord(recs[len(recs)-1])
	if !ok || last.Action != "seal" || last.Outcome != "success" || last.Seal == nil {
		return Segment{}, nil, fmt.Errorf("segment %d: the last line is not a successful seal", k)
	}
	want := Seal{Segment: k, FirstSeq: int(start.Base) + 1, HeadSeq: last.Seq - 1, HeadHash: last.Prev, ContentSHA256: sealContentDigest(recs[:len(recs)-1])}
	if !sealChainFieldsAgree(last.Seal, want) {
		return Segment{}, nil, fmt.Errorf("segment %d: the seal does not recompute as segment %d (%s recorded, %s verified)", k, k, sealChainText(last.Seal), sealChainText(&want))
	}
	block := last.Seal.Sink
	switch {
	case block == nil:
		return Segment{}, nil, fmt.Errorf("segment %d: the seal names no sink block; no protected copy of it was ever written", k)
	case block.Key != key:
		return Segment{}, nil, fmt.Errorf("segment %d: the seal's sink block names %s, not %s", k, block.Key, key)
	case !block.RetainUntil.After(last.Time):
		return Segment{}, nil, fmt.Errorf("segment %d: %v", k, sinkRetainErr(block, last.Time))
	}
	whole, size := segmentDigests(recs)
	if size != int64(len(data)) {
		return Segment{}, nil, fmt.Errorf("segment %d: the copy's %d bytes are not its %d records", k, len(data), len(recs))
	}
	return Segment{N: k, FirstSeq: int(start.Base) + 1, HeadSeq: int(start.Base) + head.Count, HeadHash: head.Hash, SHA256: whole, Bytes: size, Records: head.Count, SealedAt: last.Time, Sink: block}, recs, nil
}

// holdActive opens the active by name read-write, takes its exclusive
// flock (bounded; busy refuses) and re-stats the handle to be the file the
// name still refers to, as every writer does: a restore's rename beside it
// then cannot interleave with a seal's walk-then-lock. The caller releases
// the lock (ledger.Unlock + Close). ENOENT is returned raw: the rebuild
// tolerates a missing active.
func holdActive(resolved string) (*os.File, error) {
	f, err := os.OpenFile(resolved, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if err := ledger.LockExclusive(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("control: restore %s: %w", resolved, err)
	}
	fi, err := f.Stat()
	if err == nil && !sameFile(resolved, fi) {
		err = fmt.Errorf("control: %s was rotated while it was being restored; run audit verify control and retry", resolved)
	}
	if err != nil {
		ledger.Unlock(f)
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// moveAsideReplaced moves the file at path — a segment file
// (<base>.seg-NNNNNN, what = "NNNNNN") or the manifest (<base>.segments,
// what = "segments") — to "<base>.replaced-<what>-<unix-seconds>" beside it,
// claimed by O_EXCL first (a same-second collision gets the "-2", "-3", …
// suffix, writeTornFragment's rule), then renamed over the claim and the
// directory fsynced. The name is built on the ACTIVE's base: a name under
// "<base>.seg-" would read as an unexpected segment on every read. It is
// never deleted by this package or the CLI: it is the evidence of what was
// under the name.
func moveAsideReplaced(path, what string) (string, error) {
	dir, name := filepath.Dir(path), filepath.Base(path)
	base := strings.TrimSuffix(strings.TrimSuffix(name, ".seg-"+what), "."+what)
	stem := fmt.Sprintf("%s.replaced-%s-%d", filepath.Join(dir, base), what, time.Now().Unix())
	for attempt := 0; attempt < maxTornFragmentAttempts; attempt++ {
		candidate := stem
		if attempt > 0 {
			candidate = fmt.Sprintf("%s-%d", stem, attempt+1)
		}
		f, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		_ = f.Close()
		if err := os.Rename(path, candidate); err != nil {
			_ = os.Remove(candidate)
			return "", err
		}
		fsyncDir(dir)
		return candidate, nil
	}
	return "", fmt.Errorf("control: could not claim a fresh replaced-file name for %s after %d attempts", path, maxTornFragmentAttempts)
}

// writeRestored writes data to dest by replaceFile's recipe — a 0600 temp
// ".<base>.restore-*" beside it (the active's base, dot-prefixed like the
// swap's temp; sweepTemps knows the prefix), fsync, rename, directory
// fsync. Never ".<base>.seg-NNNNNN.restore-*": that would be a sibling.
func writeRestored(resolved, dest string, data []byte) error {
	return replaceFile(dest, "."+filepath.Base(resolved)+".restore-*", data)
}

// checkRestoreShape is Append's structural permit for a restore record
// (checkSealShape's twin): only a success is recorded — a restore that did
// not restore changes nothing and has nothing to say on the chain; it
// installs nothing and carries no config_hash, anchor, seal or fragment; it
// must say what it restored (Detail, cleaned by Append).
func checkRestoreShape(e Event) error {
	if e.Action != "restore" {
		return nil
	}
	switch {
	case e.Outcome != "success":
		return errors.New("control: a restore that did not restore records nothing")
	case e.ConfigHash != "" || e.Anchor != nil || e.Seal != nil || e.FragmentLen != 0 || e.FragmentSHA != "":
		return errors.New("control: a restore installs nothing and carries no config_hash, anchor, seal or fragment")
	case e.Detail == "":
		return errors.New("control: a restore must say what it restored")
	}
	return nil
}

// RebuildResult is what a rebuild did. Segments is N, the sealed segments
// the sink holds and the chain verified; Written counts the segment files
// written (absent or differing), Replaced those among them that differed
// and were moved aside first; ReplacedNames is every "<base>.replaced-*"
// file written, the manifest's included; ManifestReplaced is the manifest's
// own, "" when the old manifest matched or was absent; ActiveCreated says an
// empty active was created; UnderLocked lists the ordinals whose version is
// not under a COMPLIANCE lock to at least the block's date — printed, never
// refused: the bytes are still the chain's. Head is the chain's head after
// the record.
type RebuildResult struct {
	Segments, Written, Replaced int
	ReplacedNames               []string
	ManifestReplaced            string
	ActiveCreated               bool
	Head                        ledger.Head
	UnderLocked                 []int

	manifestWritten bool // the manifest was written (absent or differing): "manifest rewritten"
}

// RebuildError is a rebuild that ran to its writes but was not recorded:
// the post-rebuild read is not clean, or the record could not be appended.
// The bytes written are left in place — they are the chain's.
type RebuildError struct {
	Result RebuildResult
	Fault  error
}

func (e *RebuildError) Error() string {
	return fmt.Sprintf("rebuilt %d sealed segments; NOT recorded — %v", e.Result.Segments, e.Fault)
}

func (e *RebuildError) Unwrap() error { return e.Fault }

// sinkSegmentKeyRE is the one spelling of a segment's key under the
// ledger's prefix (segmentNameRE's twin for the sink).
var sinkSegmentKeyRE = regexp.MustCompile(`^seg-([0-9]{6})$`)

// fetchedSegment is one sealed segment as fetched from the sink and judged
// by verifyFetchedSegment.
type fetchedSegment struct {
	data []byte
	seg  Segment
}

// Rebuild reconstructs the entire sealed set — every segment file and the
// manifest — of ledger logID from the sink alone, for a root whose local
// set is gone, damaged beyond the manifest, or tidied short. It is the
// restore's whole-set twin: untainted for the same reason (every byte
// written is one the chain and the seal records commit to, read back from
// the sink's oldest version at each key) and recorded as one "restore".
//
// Order: the local set is read and its verdict kept, not acted on — a clean
// set, any fault, nothing recorded yet and a missing active are all inputs;
// the one refusal is an incomplete rotation (state B or C, from the verdict
// or from the active itself when the walk never reached it): a rebuild
// never completes a rotation. A readable local identity (the manifest's or
// the genesis's) must be logID's: a rebuild reconstructs one ledger. The
// active is then held exclusively when it exists (holdActive; ENOENT is
// tolerated) and stale temps swept. Then the whole chain is fetched and
// verified before anything is written: every key under the prefix must be
// a sealed segment's; the ordinals must be exactly 1..N — a hole refuses
// naming it; for each ordinal the oldest non-marker version is the seal's
// copy, judged by verifyFetchedSegment from the prior head, and any failure
// refuses the WHOLE rebuild with the ordinal and cause — nothing local
// changes. A version whose lock is not COMPLIANCE to at least the block's
// date is reported (UnderLocked), never refused; a lock that cannot be read
// refuses (nothing written). Only then are the writes made, ascending: a
// local file byte-identical to the copy is left in place, a differing one
// moved aside as evidence (moveAsideReplaced) then rewritten, an absent one
// written; the manifest is recomputed from the fetched bytes (trailing local
// entries beyond N kept only while their files verify from N's head) and
// compared to the old one — moved aside and rewritten when it differs; an
// absent active is created empty (a present one is left as-is: its bytes
// are not the sink's business). Segments before the manifest, the manifest
// before the active: a crash mid-way leaves a state the next read names as
// a diagnosis, never a partial set as if complete, and the re-run finds the
// written files identical and completes.
//
// The lock is released before the set is re-read and before the record is
// appended, for the reason Restore states (flock contends across
// descriptors within one process). A set that does not read clean after the
// writes — above all a present active that no longer chains from segment
// N's head (the tidied truncation replaced it; FaultBoundary{0}) — is a
// *RebuildError carrying the result and the fault: nothing is recorded, the
// bytes stay. Otherwise one restore record is appended, even when nothing
// was written: a rebuild that verified the local set against the sink is a
// visible act, and it is what lets the remedy's re-run record what the first
// run did. The window between the last rename and the record is Repair's
// residual, stated the same way.
func Rebuild(controlLog, logID string, r SinkReader, e Event) (RebuildResult, error) {
	var res RebuildResult
	if e.Action != "restore" || e.Outcome != "success" || e.Detail != "" {
		return res, errors.New("control: Restore takes a success restore event without a detail")
	}
	resolved, err := resolveControlLog(controlLog)
	if err != nil {
		return res, err
	}
	v, verr := Read(controlLog, ledger.Locked)
	var se *SetError
	switch {
	case verr == nil:
		if v.State != StateOpen {
			return res, errNotRestoreMatter(controlLog)
		}
	case errors.As(verr, &se), errors.Is(verr, fs.ErrNotExist):
		// A fault, or nothing recorded: inputs. The rotation state the walk
		// never decided is read from the active itself.
		listed := 0
		if m, merr := loadManifest(resolved); merr == nil && m != nil {
			listed = len(m.Segments)
		}
		incomplete, err := incompleteRotation(resolved, listed)
		if err != nil {
			return res, err
		}
		if incomplete {
			return res, errNotRestoreMatter(controlLog)
		}
	default:
		return res, verr // a lock or IO error: as found
	}
	if have := rootLogID(resolved, v); have != "<id>" && have != logID {
		return res, fmt.Errorf("control: --log-id %s but this root is ledger %s; a rebuild reconstructs one ledger", logID, have)
	}

	active, err := holdActive(resolved)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return res, err
	}
	release := func() {
		if active != nil {
			ledger.Unlock(active)
			_ = active.Close()
			active = nil
		}
	}
	defer release()
	created := active == nil
	sweepTemps(resolved)

	fetched, under, err := fetchChain(logID, r)
	if err != nil {
		return res, err
	}
	res, err = rebuildWrite(resolved, logID, fetched, created)
	res.Segments, res.UnderLocked = len(fetched), under
	if err != nil {
		return res, err
	}
	release()

	v, verr = Read(controlLog, ledger.Locked)
	if verr != nil {
		return res, &RebuildError{Result: res, Fault: verr}
	}
	if v.State != StateOpen {
		return res, &RebuildError{Result: res, Fault: errNotRestoreMatter(controlLog)}
	}
	manifest, activeWas := "kept", "kept"
	if res.ManifestReplaced != "" || res.manifestWritten {
		manifest = "rewritten"
	}
	if res.ActiveCreated {
		activeWas = "created"
	}
	rec := e
	rec.Detail = fmt.Sprintf("rebuild from %s: %d segments verified against the sink, %d written, %d replaced, manifest %s, active %s", fetched[len(fetched)-1].seg.Sink.Kind, res.Segments, res.Written, res.Replaced, manifest, activeWas)
	head, err := Append(resolved, rec)
	if err != nil {
		return res, &RebuildError{Result: res, Fault: fmt.Errorf("the restore record could not be appended: %w", err)}
	}
	res.Head = head
	return res, nil
}

// fetchChain is every sink call of a rebuild: the listing under the
// ledger's prefix, judged as exactly the ordinals 1..N, then each ordinal's
// oldest non-marker version fetched and verified as the next link of the
// chain, its lock read. Nothing local is touched; the first fault returns.
func fetchChain(logID string, r SinkReader) ([]fetchedSegment, []int, error) {
	ctx := context.Background()
	prefix := r.Prefix(logID)
	listed, err := r.ListPrefix(ctx, prefix)
	if err != nil {
		return nil, nil, fmt.Errorf("control: listing %s: %w", prefix, err)
	}
	byOrdinal := map[int]KeyVersions{}
	for _, kv := range listed {
		sub := sinkSegmentKeyRE.FindStringSubmatch(strings.TrimPrefix(kv.Key, prefix))
		n := 0
		if sub != nil {
			n, _ = strconv.Atoi(sub[1])
		}
		if n == 0 {
			return nil, nil, fmt.Errorf("control: key %s under this ledger's prefix is not a sealed segment", kv.Key)
		}
		if len(kv.Versions) == 0 {
			continue // a delete marker alone: the key holds nothing
		}
		byOrdinal[n] = kv
	}
	held := make([]int, 0, len(byOrdinal))
	for n := range byOrdinal {
		held = append(held, n)
	}
	slices.Sort(held)
	if len(held) == 0 {
		return nil, nil, fmt.Errorf("control: cannot rebuild: the sink holds no segment of ledger %s under %s", logID, prefix)
	}
	n := held[len(held)-1]
	for k := 1; k <= n; k++ {
		if _, ok := byOrdinal[k]; !ok {
			return nil, nil, fmt.Errorf("control: cannot rebuild: the sink holds segments %s; segment %d is missing from the bucket — a chain with a hole cannot be reconstructed", ordinalRanges(held), k)
		}
	}
	var fetched []fetchedSegment
	var under []int
	start := ledger.Start{}
	for k := 1; k <= n; k++ {
		kv := byOrdinal[k]
		id := kv.Versions[0].ID // the oldest: the seal's copy by construction
		data, err := r.Get(ctx, kv.Key, id, maxRestoreBody)
		if err != nil {
			return nil, nil, fmt.Errorf("control: segment %d: %w", k, err)
		}
		seg, _, verr := verifyFetchedSegment(data, k, start, logID, kv.Key)
		if verr != nil {
			return nil, nil, fmt.Errorf("control: cannot rebuild: %w", verr)
		}
		lock, err := r.GetRetention(ctx, kv.Key, id)
		if err != nil {
			return nil, nil, fmt.Errorf("control: segment %d: the lock on version %s could not be read; nothing was written — if the credential is denied, grant s3:GetObjectRetention (with s3:GetObject and s3:ListBucketVersions) and re-run: %w", k, id, err)
		}
		if lock.Mode != "COMPLIANCE" || lock.RetainUntil.Before(seg.Sink.RetainUntil) {
			under = append(under, k)
		}
		fetched = append(fetched, fetchedSegment{data: data, seg: seg})
		start = ledger.Start{Prev: seg.HeadHash, Base: uint64(seg.HeadSeq)}
	}
	return fetched, under, nil
}

// ordinalRanges renders sorted ordinals as their runs: "1–3", "1–1 and
// 3–3", "1–3, 5–7 and 9–9".
func ordinalRanges(held []int) string {
	var parts []string
	for i := 0; i < len(held); {
		j := i
		for j+1 < len(held) && held[j+1] == held[j]+1 {
			j++
		}
		parts = append(parts, fmt.Sprintf("%d–%d", held[i], held[j]))
		i = j + 1
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// rebuildWrite is the rebuild's writes, under the active's lock when one
// exists: segments ascending, the manifest, then the active when createActive.
func rebuildWrite(resolved, logID string, fetched []fetchedSegment, createActive bool) (RebuildResult, error) {
	var res RebuildResult
	if createActive {
		if err := os.MkdirAll(filepath.Dir(resolved), 0o700); err != nil {
			return res, err
		}
	}
	for i, f := range fetched {
		k := i + 1
		path := SegmentPath(resolved, k)
		have, err := os.ReadFile(path)
		switch {
		case err == nil && bytes.Equal(have, f.data):
			continue
		case err == nil:
			name, err := moveAsideReplaced(path, fmt.Sprintf("%06d", k))
			if err != nil {
				return res, err
			}
			res.Replaced++
			res.ReplacedNames = append(res.ReplacedNames, name)
		case !errors.Is(err, fs.ErrNotExist):
			return res, err
		}
		if err := writeRestored(resolved, path, f.data); err != nil {
			return res, fmt.Errorf("control: segment %d: the rebuilt bytes could not be written: %w", k, err)
		}
		res.Written++
	}
	if crashAt("rebuild_after_segment_before_manifest") {
		return res, errStoppedByTestHook
	}

	m := Manifest{V: ManifestVersion, LogID: logID}
	for _, f := range fetched {
		m.Segments = append(m.Segments, manifestEntry(resolved, f.seg))
	}
	// Local segments beyond N are not the sink's to judge: their entries
	// stay while the files verify from N's head; from the first that does
	// not, the read names them.
	last := fetched[len(fetched)-1].seg
	if old, err := loadManifest(resolved); err == nil && old != nil {
		start := ledger.Start{Prev: last.HeadHash, Base: uint64(last.HeadSeq)}
		for j := len(fetched) + 1; j <= len(old.Segments); j++ {
			seg, _, err := verifySealed(resolved, j, start, old.Segments[j-1])
			if err != nil {
				break
			}
			m.Segments = append(m.Segments, manifestEntry(resolved, seg))
			start = ledger.Start{Prev: seg.HeadHash, Base: uint64(seg.HeadSeq)}
		}
	}
	data, err := json.Marshal(m)
	if err != nil {
		return res, err
	}
	have, err := os.ReadFile(ManifestPath(resolved))
	switch {
	case err == nil && bytes.Equal(have, data):
	case err == nil:
		name, err := moveAsideReplaced(ManifestPath(resolved), "segments")
		if err != nil {
			return res, err
		}
		res.ManifestReplaced = name
		res.ReplacedNames = append(res.ReplacedNames, name)
		fallthrough
	case errors.Is(err, fs.ErrNotExist):
		if err := writeManifest(resolved, m); err != nil {
			return res, fmt.Errorf("control: the rebuilt manifest could not be written: %w", err)
		}
		res.manifestWritten = true
	default:
		return res, err
	}
	if crashAt("rebuild_after_manifest_before_active") {
		return res, errStoppedByTestHook
	}
	if createActive {
		if err := swapActive(resolved); err != nil {
			return res, fmt.Errorf("control: the empty active could not be created: %w", err)
		}
		res.ActiveCreated = true
	}
	return res, nil
}
