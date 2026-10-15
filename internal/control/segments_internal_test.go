package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// appendN appends n apply records through Append.
func appendN(t *testing.T, p string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := Append(p, Event{Action: "apply", Outcome: "success", Invoker: identity.Static("dana@example.com"), Witness: Witness{OSUser: "dana", Hostname: "host"}, ConfigHash: "sha256:abc"}); err != nil {
			t.Fatal(err)
		}
	}
}

// sealByHand turns the active at p into sealed segment N+1 and a fresh,
// empty active: it writes the seal record by hand and composes the manifest
// writer and the swap primitive (writeManifest, swapActive), so the reader
// tests read the on-disk shape the seal command produces. stopAt leaves the root in a
// crash state: "A'" after the link, "B" after the seal record, "C" after the
// manifest; "" completes. It returns the seal line.
func sealByHand(t *testing.T, p, stopAt string) []byte {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Read(p, ledger.Unlocked)
	if err != nil {
		t.Fatalf("pre-state must read: %v", err)
	}
	n := len(v.Sealed) + 1
	seg := SegmentPath(resolved, n)
	if err := os.Link(resolved, seg); err != nil {
		t.Fatal(err)
	}
	if stopAt == "A'" {
		return nil
	}
	start := ledger.Start{}
	if n > 1 {
		prev := v.Sealed[n-2]
		start = ledger.Start{Prev: prev.HeadHash, Base: uint64(prev.HeadSeq)}
	}
	active := activeRecords(v)
	content := sealContentDigest(active)
	rec := record{V: "control/1", Seq: v.Head.Count + 1, Time: time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC), Action: "seal", Outcome: "success",
		Invoker: identity.Static("dana@example.com"), Witness: Witness{OSUser: "dana", Hostname: "host"},
		Seal: &Seal{Segment: n, FirstSeq: v.Active.FirstSeq, HeadSeq: v.Head.Count, HeadHash: v.Head.Hash, ContentSHA256: content}, Prev: v.Head.Hash}
	line, _ := json.Marshal(rec)
	c, err := ledger.OpenFrom(resolved, ledger.Locked, start)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append(line); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if stopAt == "B" {
		return line
	}
	whole, size := segmentDigests(append(append([]ledger.Record{}, active...), ledger.Record{Raw: line}))
	logID, err := GenesisLogID(v.Records)
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{V: ManifestVersion, LogID: logID}
	for _, s := range v.Sealed {
		m.Segments = append(m.Segments, ManifestEntry{N: s.N, File: filepath.Base(s.Path), FirstSeq: s.FirstSeq, HeadSeq: s.HeadSeq, HeadHash: s.HeadHash, SHA256: s.SHA256, Bytes: s.Bytes, SealedAt: s.SealedAt})
	}
	m.Segments = append(m.Segments, ManifestEntry{N: n, File: filepath.Base(seg), FirstSeq: v.Active.FirstSeq, HeadSeq: rec.Seq, HeadHash: hashLine(line), SHA256: whole, Bytes: size, SealedAt: rec.Time})
	if err := writeManifest(resolved, m); err != nil {
		t.Fatal(err)
	}
	if stopAt == "C" {
		return line
	}
	if err := swapActive(resolved); err != nil {
		t.Fatal(err)
	}
	return line
}

func hashLine(line []byte) string { s := sha256.Sum256(line); return hex.EncodeToString(s[:]) }

// twoSegments: 5 records sealed, 3 more sealed, 2 in the active (seq 1..12).
func twoSegments(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 5)
	sealByHand(t, p, "")
	appendN(t, p, 3)
	sealByHand(t, p, "")
	appendN(t, p, 2)
	return p
}

// TestReadAcrossSegments: the view is the concatenation; Head.Count is the
// last seq; each sealed head is sha256(its seal line); the active's FirstSeq
// is the last sealed head + 1; GenesisLogID works over the logical records.
func TestReadAcrossSegments(t *testing.T) {
	p := twoSegments(t)
	v, err := Read(p, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Records) != 12 || v.Head.Count != 12 || len(v.Sealed) != 2 || v.State != StateOpen || v.FirstSeq != 1 {
		t.Fatalf("%+v", v)
	}
	s1, s2 := v.Sealed[0], v.Sealed[1]
	if s1.FirstSeq != 1 || s1.HeadSeq != 6 || s2.FirstSeq != 7 || s2.HeadSeq != 10 || v.Active.FirstSeq != 11 || v.Active.HeadSeq != 12 {
		t.Fatalf("seq ranges: %+v %+v %+v", s1, s2, v.Active)
	}
	if s1.HeadHash != hashLine(v.Records[5].Raw) || s2.HeadHash != hashLine(v.Records[9].Raw) || v.Head.Hash != hashLine(v.Records[11].Raw) {
		t.Fatal("sealed heads must be the seal lines' hashes")
	}
	if s1.SealedAt.IsZero() || s1.SHA256 == "" || s1.Bytes == 0 {
		t.Fatalf("segment facts: %+v", s1)
	}
	logID, err := GenesisLogID(v.Records)
	if err != nil || v.LogID != logID {
		t.Fatalf("identity: %v %q %q", err, v.LogID, logID)
	}
	for i, r := range v.Records {
		rec, _ := decodeRecord(r)
		if rec.Seq != i+1 {
			t.Fatalf("record %d has seq %d", i, rec.Seq)
		}
		if i > 0 && rec.LogID != "" {
			t.Fatalf("log_id on seq %d", rec.Seq)
		}
	}
}

// TestSetFaultsAcrossSegments: the tamper matrix — each edit names its
// fault, its segment and its global seq; none of them unwraps to a ledger
// error.
func TestSetFaultsAcrossSegments(t *testing.T) {
	assertFault := func(t *testing.T, p string, want Fault, seg int) *SetError {
		t.Helper()
		_, err := Read(p, ledger.Locked)
		var se *SetError
		if !errors.As(err, &se) || se.Fault != want || se.Segment != seg {
			t.Fatalf("want fault %d in segment %d, got %v", want, seg, err)
		}
		var broken *ledger.ChainBrokenError
		var torn *ledger.TornError
		if errors.As(err, &broken) || errors.As(err, &torn) {
			t.Fatalf("a sealed-segment or structural fault must not unwrap: %v", err)
		}
		return se
	}
	t.Run("boundary tamper", func(t *testing.T) {
		p := twoSegments(t)
		seg2 := SegmentPath(p, 2)
		data, _ := os.ReadFile(seg2)
		// flip one hex digit inside the first record's prev
		i := bytes.Index(data, []byte(`"prev":"`)) + len(`"prev":"`)
		if data[i] == '0' {
			data[i] = '1'
		} else {
			data[i] = '0'
		}
		_ = os.WriteFile(seg2, data, 0o600)
		if se := assertFault(t, p, FaultBoundary, 2); se.Seq != 7 {
			t.Fatalf("seq %d", se.Seq)
		}
	})
	t.Run("dropped segment", func(t *testing.T) {
		p := twoSegments(t)
		_ = os.Remove(SegmentPath(p, 2))
		if se := assertFault(t, p, FaultMissingSegment, 2); !strings.Contains(se.Error(), "expected sha256") {
			t.Fatal(se.Error())
		}
		// Edit the manifest to drop entry 2 as well → the active no longer
		// chains from what the manifest now calls the last head.
		m, _ := loadManifest(p)
		m.Segments = m.Segments[:1]
		data, _ := json.Marshal(m)
		_ = os.WriteFile(ManifestPath(p), data, 0o600)
		if se := assertFault(t, p, FaultBoundary, 0); se.Seq != 7 || strings.Contains(se.Error(), "older than") {
			t.Fatalf("%d %s", se.Seq, se.Error())
		}
	})
	t.Run("reordered", func(t *testing.T) {
		p := twoSegments(t)
		a, _ := os.ReadFile(SegmentPath(p, 1))
		b, _ := os.ReadFile(SegmentPath(p, 2))
		_ = os.WriteFile(SegmentPath(p, 1), b, 0o600)
		_ = os.WriteFile(SegmentPath(p, 2), a, 0o600)
		_, err := Read(p, ledger.Locked)
		var se *SetError
		if !errors.As(err, &se) || se.Segment != 1 || (se.Fault != FaultBroken && se.Fault != FaultBoundary) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("duplicated", func(t *testing.T) {
		p := twoSegments(t)
		b, _ := os.ReadFile(SegmentPath(p, 2))
		_ = os.WriteFile(SegmentPath(p, 3), b, 0o600)
		_ = assertFault(t, p, FaultUnexpectedSegment, 0)
		m, _ := loadManifest(p)
		e := m.Segments[1]
		e.N, e.File, e.FirstSeq, e.HeadSeq = 3, filepath.Base(SegmentPath(p, 3)), 11, 14
		m.Segments = append(m.Segments, e)
		data, _ := json.Marshal(m)
		_ = os.WriteFile(ManifestPath(p), data, 0o600)
		_ = assertFault(t, p, FaultBoundary, 3)
	})
	t.Run("manifest disagreements", func(t *testing.T) {
		for field, edit := range map[string]func(e *ManifestEntry, m *Manifest){
			"head_hash": func(e *ManifestEntry, _ *Manifest) { e.HeadHash = strings.Repeat("0", 64) },
			"sha256":    func(e *ManifestEntry, _ *Manifest) { e.SHA256 = strings.Repeat("0", 64) },
			"bytes":     func(e *ManifestEntry, _ *Manifest) { e.Bytes++ },
			"log_id":    func(_ *ManifestEntry, m *Manifest) { m.LogID = strings.Repeat("0", 32) },
		} {
			p := twoSegments(t)
			m, _ := loadManifest(p)
			edit(&m.Segments[1], m)
			data, _ := json.Marshal(m)
			_ = os.WriteFile(ManifestPath(p), data, 0o600)
			_, err := Read(p, ledger.Locked)
			var se *SetError
			if !errors.As(err, &se) || se.Fault != FaultManifest || !strings.Contains(err.Error(), field) {
				t.Fatalf("%s: %v", field, err)
			}
		}
		p := twoSegments(t)
		_ = os.Remove(ManifestPath(p))
		_ = assertFault(t, p, FaultUnexpectedSegment, 0)
		_ = os.Remove(SegmentPath(p, 1))
		_ = os.Remove(SegmentPath(p, 2))
		_, err := Read(p, ledger.Locked)
		var se *SetError
		var broken *ledger.ChainBrokenError
		if !errors.As(err, &se) || se.Fault != FaultBroken || se.Segment != 0 || se.Seq != 1 || !errors.As(err, &broken) {
			t.Fatalf("no manifest, no segments, non-empty active: %v", err)
		}
	})
	t.Run("seal not last in a sealed segment", func(t *testing.T) {
		p := twoSegments(t)
		seg1 := SegmentPath(p, 1)
		v, _ := Read(p, ledger.Locked)
		extra := record{V: "control/1", Seq: 7, Time: time.Now().UTC(), Action: "prune", Outcome: "success", Invoker: identity.Static("x"), Witness: Witness{}, Prev: v.Sealed[0].HeadHash}
		line, _ := json.Marshal(extra)
		f, _ := os.OpenFile(seg1, os.O_APPEND|os.O_WRONLY, 0)
		_, _ = f.Write(append(line, '\n'))
		_ = f.Close()
		if se := assertFault(t, p, FaultSealNotLast, 1); se.Seq != 7 {
			t.Fatalf("seq %d", se.Seq)
		}
	})
	t.Run("active missing with history", func(t *testing.T) {
		p := twoSegments(t)
		_ = os.Remove(p)
		se := assertFault(t, p, FaultActiveMissing, 0)
		if errors.Is(se, fs.ErrNotExist) || os.IsNotExist(se) || !strings.Contains(se.Error(), "lists 2 sealed segments") {
			t.Fatalf("%v", se)
		}
		_, _, err := openActive(p)
		if !errors.As(err, &se) || se.Fault != FaultActiveMissing {
			t.Fatalf("openActive: %v", err)
		}
		if _, lerr := os.Lstat(p); !errors.Is(lerr, fs.ErrNotExist) {
			t.Fatal("openActive must not recreate a missing active beside history")
		}
	})
	t.Run("global seq in a sealed broken segment", func(t *testing.T) {
		p := twoSegments(t)
		seg2 := SegmentPath(p, 2)
		data, _ := os.ReadFile(seg2)
		lines := bytes.Split(data, []byte("\n"))
		i := bytes.Index(lines[2], []byte(`"prev":"`)) + len(`"prev":"`)
		lines[2][i] ^= 1
		_ = os.WriteFile(seg2, bytes.Join(lines, []byte("\n")), 0o600)
		if se := assertFault(t, p, FaultBroken, 2); se.Seq != 9 {
			t.Fatalf("file line 3 of segment 2 is global seq 9, got %d", se.Seq)
		}
	})
}

// TestOrdinalZeroSiblingIsUnexpected: no manifest ever lists segment 0, so a
// `.seg-000000` beside a populated manifest is an unexpected segment. Beside
// an empty manifest — itself refused by ParseManifest, so the fault is
// FaultManifest, not the ordinal-0 one — even a hard link to the active must
// never read as state C and lock every writer out with ErrSealed.
func TestOrdinalZeroSiblingIsUnexpected(t *testing.T) {
	p := twoSegments(t)
	if err := os.WriteFile(SegmentPath(p, 0), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Read(p, ledger.Locked)
	var se *SetError
	if !errors.As(err, &se) || se.Fault != FaultUnexpectedSegment || !strings.Contains(err.Error(), "control.jsonl.seg-000000") {
		t.Fatalf("segment 0 beside a populated manifest: %v", err)
	}

	q := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, q, 1)
	v, err := Read(q, ledger.Unlocked)
	if err != nil {
		t.Fatal(err)
	}
	logID, _ := GenesisLogID(v.Records)
	m, _ := json.Marshal(Manifest{V: ManifestVersion, LogID: logID})
	if err := os.WriteFile(ManifestPath(q), m, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(q, SegmentPath(q, 0)); err != nil {
		t.Fatal(err)
	}
	v, err = Read(q, ledger.Locked)
	if v.State == StateRotatedNotSwapped || !errors.As(err, &se) || se.Fault != FaultManifest {
		t.Fatalf("segment 0 linked to the active beside an empty manifest: state %d err %v", v.State, err)
	}
	if werr := Writable(q); errors.Is(werr, ErrSealed) || !errors.As(werr, &se) || se.Fault != FaultManifest {
		t.Fatalf("the writer must not be locked out as sealed: %v", werr)
	}
}

// TestStateMachineReads: A′, B and C each read with complete, correct records
// and the right State; openActive appends normally in A′ and returns
// ErrSealed — never a damaged verdict — in B and C.
func TestStateMachineReads(t *testing.T) {
	for _, tc := range []struct {
		stop  string
		state State
	}{{"A'", StateOpen}, {"B", StateSealedNotRotated}, {"C", StateRotatedNotSwapped}} {
		t.Run(tc.stop, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "control.jsonl")
			appendN(t, p, 5)
			sealByHand(t, p, "")
			appendN(t, p, 3)
			sealLine := sealByHand(t, p, tc.stop)
			v, err := Read(p, ledger.Locked)
			if err != nil || v.State != tc.state {
				t.Fatalf("%v state %d", err, v.State)
			}
			switch tc.stop {
			case "A'":
				// 6 (segment 1) + 3 in the open active; no seal record yet.
				if len(v.Records) != 9 || v.Head.Count != 9 || len(v.Sealed) != 1 {
					t.Fatalf("A′: %d records head %d", len(v.Records), v.Head.Count)
				}
			case "B":
				// The seal record is the active's last line and the head; the
				// manifest still lists one segment.
				if len(v.Records) != 10 || v.Head.Count != 10 || v.Head.Hash != hashLine(sealLine) || len(v.Sealed) != 1 {
					t.Fatalf("B: %d records head %+v", len(v.Records), v.Head)
				}
			case "C":
				// The manifest lists both; the logical active is empty and the
				// head is segment 2's.
				if len(v.Records) != 10 || v.Head.Count != 10 || len(v.Sealed) != 2 || v.Head.Hash != v.Sealed[1].HeadHash || v.Active.Records != 0 {
					t.Fatalf("C: %d records head %+v", len(v.Records), v.Head)
				}
			}
			c, _, err := openActive(p)
			switch tc.stop {
			case "A'":
				if err != nil {
					t.Fatalf("A′ must append: %v", err)
				}
				_ = c.Close()
			default:
				var broken *ledger.ChainBrokenError
				if !errors.Is(err, ErrSealed) || errors.As(err, &broken) {
					t.Fatalf("%s: want ErrSealed, got %v", tc.stop, err)
				}
			}
		})
	}
}

// TestOpenActiveStateCIsErrSealed is the regression pin for the
// open-by-name → lock → inspect → Resume order: a fused OpenFrom with
// start_{N+1} would verify the sealed file under the active's name against
// the wrong Start and report ChainBrokenError.
func TestOpenActiveStateCIsErrSealed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 5)
	sealByHand(t, p, "C")
	_, _, err := openActive(p)
	var se *SetError
	if !errors.Is(err, ErrSealed) || errors.As(err, &se) {
		t.Fatalf("want ErrSealed, got %v", err)
	}
}

// TestOpenActiveRestatRetries: the name is rotated between open and lock;
// openActive notices the handle is not the file the name refers to and
// reopens, so the chain it returns is over the new active.
func TestOpenActiveRestatRetries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 5)
	prev := betweenOpenAndLock
	once := false
	betweenOpenAndLock = func() {
		if !once {
			once = true
			sealByHand(t, p, "")
		}
	}
	t.Cleanup(func() { betweenOpenAndLock = prev })
	c, v, err := openActive(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.Base() != 6 || c.Count() != 0 || len(v.Sealed) != 1 {
		t.Fatalf("the chain must be over the new active: base %d count %d sealed %d", c.Base(), c.Count(), len(v.Sealed))
	}
}

// TestOpenActiveManifestRecheckClosesTheForkWindow: a seal completes between
// the writer's sealed walk and its lock; the manifest re-check under the lock
// restarts the writer, so the record it appends carries prev == head_{N+1}
// and seq == head_{N+1}.Seq + 1 — never head_N's. Without the re-check the
// writer, holding a stale walk under its lock, refuses on the completed
// seal's link as an unexpected sibling (the sibling check is the fail-closed
// second line); the re-check turns that refusal into the correct retry.
func TestOpenActiveManifestRecheckClosesTheForkWindow(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 5)
	sealByHand(t, p, "")
	appendN(t, p, 3)
	prev := betweenWalkAndOpen
	once := false
	betweenWalkAndOpen = func() {
		if !once {
			once = true
			sealByHand(t, p, "")
		}
	}
	t.Cleanup(func() { betweenWalkAndOpen = prev })
	c, v, err := openActive(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Sealed) != 2 || c.Base() != 10 || c.Prev() != v.Sealed[1].HeadHash {
		_ = c.Close()
		t.Fatalf("the writer must restart with start_{N+1}: sealed %d base %d", len(v.Sealed), c.Base())
	}
	_ = c.Close()
	if _, err := Read(p, ledger.Locked); err != nil {
		t.Fatalf("the set must still verify: %v", err)
	}
}

// TestAppendOnLogicalPosition: the first record after a seal carries
// seq == sealed head + 1, prev == the sealed head, and NO log_id; a later
// record continues; an anchor covering the sealed head is admitted (coverage
// is judged on the logical count); the returned Head is logical.
func TestAppendOnLogicalPosition(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 5)
	sealByHand(t, p, "")
	head, err := Append(p, Event{Action: "prune", Outcome: "success", Invoker: identity.Static("dana@example.com"), Witness: Witness{}})
	if err != nil || head.Count != 7 {
		t.Fatalf("append after a seal: %v %+v", err, head)
	}
	v, err := Read(p, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := decodeRecord(v.Records[6])
	if rec.Seq != 7 || rec.Prev != v.Sealed[0].HeadHash || rec.LogID != "" {
		t.Fatalf("first record of segment 2: %+v", rec)
	}
	if head.Hash != hashOf(v.Records[6].Raw) {
		t.Fatal("the returned head must be the new record's hash")
	}
	anchorOK := &Anchor{Seq: 6, Hash: v.Sealed[0].HeadHash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://log.test", Ref: strings.Repeat("0", 80), Proof: "AQID"}
	if _, err := Append(p, Event{Action: "anchor", Outcome: "success", Invoker: identity.Static("x"), Witness: Witness{}, Anchor: anchorOK}); err != nil {
		t.Fatalf("an anchor covering the sealed head must be admitted: %v", err)
	}
	if _, err := Append(p, Event{Action: "anchor", Outcome: "success", Invoker: identity.Static("x"), Witness: Witness{}, Anchor: &Anchor{Seq: 9, Hash: anchorOK.Hash, Kind: "tlog", BackendKind: "transparency-log", Backend: "https://log.test", Ref: strings.Repeat("0", 80), Proof: "AQID"}}); err == nil || !strings.Contains(err.Error(), "the chain has 8 records") {
		t.Fatalf("coverage beyond the logical count must be refused with the logical count: %v", err)
	}
	v, err = Read(p, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range CheckAnchors(v.Records) {
		if c.Mismatch != "" {
			t.Fatalf("CheckAnchors across the boundary: %s", c.Mismatch)
		}
	}
}

// TestAppendFreshRootIsToday: on a root with no file, Append still creates the
// active, writes the genesis with a log_id at seq 1, and leaves exactly one
// file.
func TestAppendFreshRootIsToday(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nested", "control.jsonl")
	appendN(t, p, 1)
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 || entries[0].Name() != "control.jsonl" {
		t.Fatalf("fresh root: %v", entries)
	}
	v, err := Read(p, ledger.Locked)
	rec, _ := decodeRecord(v.Records[0])
	if err != nil || rec.Seq != 1 || rec.LogID == "" {
		t.Fatalf("%v %+v", err, rec)
	}
}

// TestOlderBinaryGenesisIsBoundaryWithCause: a fresh genesis (prev "", seq
// 1, log_id) in the empty active of a rotated root → FaultBoundary{0} whose
// message names the older-binary cause; errors.As(&broken) is false;
// openActive refuses with the same error; the printed remedy works — move
// the active aside, create an empty one → Read verifies with zero active
// records and head = segment N's, and the next Append carries seq N+1,
// prev = head_N.
func TestOlderBinaryGenesisIsBoundaryWithCause(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 3)
	sealByHand(t, p, "")
	c, err := ledger.Open(p, ledger.Locked) // what an older binary does: zero Start on the empty active
	if err != nil {
		t.Fatal(err)
	}
	line, _ := json.Marshal(record{V: "control/1", Seq: 1, Action: "apply", Outcome: "success", Invoker: identity.Static("old"), Witness: Witness{}, Prev: "", LogID: strings.Repeat("cd", 16)})
	if err := c.Append(line); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	_, err = Read(p, ledger.Locked)
	var se *SetError
	var broken *ledger.ChainBrokenError
	if !errors.As(err, &se) || se.Fault != FaultBoundary || se.Segment != 0 || !strings.Contains(err.Error(), "a writer older than this root's seals") || !strings.Contains(err.Error(), "the chain continues from seq 4") || errors.As(err, &broken) {
		t.Fatalf("%v", err)
	}
	if _, _, oerr := openActive(p); oerr == nil || oerr.Error() != err.Error() {
		t.Fatalf("openActive: %v", oerr)
	}
	if err := os.Rename(p, p+".foreign"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := Read(p, ledger.Locked)
	if err != nil || v.Active.Records != 0 || v.Head != (ledger.Head{Hash: v.Sealed[0].HeadHash, Count: 4}) {
		t.Fatalf("remedy: %v %+v", err, v.Head)
	}
	appendN(t, p, 1)
	v, _ = Read(p, ledger.Locked)
	rec, _ := decodeRecord(v.Records[4])
	if rec.Seq != 5 || rec.Prev != v.Sealed[0].HeadHash || rec.LogID != "" {
		t.Fatalf("%+v", rec)
	}
}

// TestBoundaryWithoutFreshGenesisIsNotOlderBinary: a first record that is a
// genesis in shape only (prev set, or no 32-hex log_id), or an empty-chain
// mismatch, keeps the generic boundary text.
func TestBoundaryWithoutFreshGenesisIsNotOlderBinary(t *testing.T) {
	for name, line := range map[string]string{
		"prev set":   `{"v":"control/1","seq":1,"action":"apply","outcome":"success","prev":"` + strings.Repeat("ee", 32) + `","log_id":"` + strings.Repeat("cd", 16) + `"}`,
		"no log_id":  `{"v":"control/1","seq":1,"action":"apply","outcome":"success","prev":""}`,
		"bad log_id": `{"v":"control/1","seq":1,"action":"apply","outcome":"success","prev":"","log_id":"zz"}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "control.jsonl")
			appendN(t, p, 3)
			sealByHand(t, p, "")
			if err := os.WriteFile(p, []byte(line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Read(p, ledger.Locked)
			var se *SetError
			if !errors.As(err, &se) || se.Fault != FaultBoundary || se.olderBinary || strings.Contains(err.Error(), "a writer older than this root's seals") {
				t.Fatalf("%v", err)
			}
		})
	}
}
