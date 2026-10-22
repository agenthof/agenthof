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
	"slices"
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
// Selection is by the chain, never by the manifest (verifyFetchedSegment):
// the versions at the segment's key, oldest first, until one is sealed
// segment k continuing the verified prefix — and, when segment k+1's first
// line reads, the one its prev names. The manifest's sha256 is a
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
				return res, fmt.Errorf("control: ledger %s: the active segment is sealed and not yet rotated; run audit seal to complete it — not a restore matter", controlLog)
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
	// The manifest's bytes bound the read only when the entry is trusted; a
	// disagreeing entry (FaultManifest{k}) bounds nothing but the cap.
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
	nextPrev := firstPrev(SegmentPath(resolved, k+1))
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
			// The copy is there and chains; what does not continue it is the
			// local segment after it — not this restore's fault to answer.
			return RestoredSegment{}, fmt.Errorf("control: segment %d: %d version(s) at %s chain from %s, but segment %d's first record continues none of them; the local segment %d is not this ledger's — run: audit restore control --rebuild --log-id %s", k, chained, key, from, k+1, k+1, v.LogID)
		}
		return RestoredSegment{}, fmt.Errorf("control: segment %d: no version at %s chains from %s; the protected copy is missing", k, key, from)
	}
	id := kv.Versions[selected].ID
	lock, err := r.GetRetention(ctx, key, id)
	if err != nil {
		return RestoredSegment{}, fmt.Errorf("control: segment %d: %w", k, err)
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

// maxFirstLine bounds the read of a segment's first line for the
// continuity check: a control record is at most a few KB (an anchor's proof
// is capped at 8 KB).
const maxFirstLine = 64 << 10

// firstPrev is the prev of the first record of the file at path, or "" when
// the file is absent, unreadable or its first line does not decode: then
// nothing constrains the selection beyond the chain.
func firstPrev(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	line, err := bufio.NewReader(io.LimitReader(f, maxFirstLine)).ReadBytes('\n')
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
