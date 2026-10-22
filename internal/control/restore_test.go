package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// fakeVersion is one object version as the fakeReader holds it.
type fakeVersion struct {
	id    string
	data  []byte
	mode  string // "COMPLIANCE", "GOVERNANCE" or "" (no lock)
	until time.Time
}

// fakeReader is an in-memory SinkReader: key → versions oldest first, ids
// minted "v-1", "v-2", … in insertion order across every key (the sinktest
// fake's rule). errs fails one operation by name.
type fakeReader struct {
	next    int
	objects map[string][]fakeVersion
	errs    map[string]error
	calls   []string
}

func newFakeReader() *fakeReader {
	return &fakeReader{objects: map[string][]fakeVersion{}, errs: map[string]error{}}
}

// add appends a version at key (the newest) and returns its id.
func (r *fakeReader) add(key string, data []byte, mode string, until time.Time) string {
	r.next++
	id := fmt.Sprintf("v-%d", r.next)
	r.objects[key] = append(r.objects[key], fakeVersion{id: id, data: bytes.Clone(data), mode: mode, until: until})
	return id
}

func (r *fakeReader) Prefix(logID string) string { return "p/" + logID + "/" }

func (r *fakeReader) ListVersions(_ context.Context, key string) (KeyVersions, error) {
	r.calls = append(r.calls, "ListVersions")
	if err := r.errs["ListVersions"]; err != nil {
		return KeyVersions{}, err
	}
	kv := KeyVersions{Key: key}
	vs := r.objects[key]
	for i, v := range vs {
		kv.Versions = append(kv.Versions, SinkVersion{ID: v.id, IsLatest: i == len(vs)-1, Size: int64(len(v.data))})
	}
	return kv, nil
}

func (r *fakeReader) ListPrefix(ctx context.Context, prefix string) ([]KeyVersions, error) {
	if err := r.errs["ListPrefix"]; err != nil {
		return nil, err
	}
	var out []KeyVersions
	for key := range r.objects {
		if strings.HasPrefix(key, prefix) {
			kv, _ := r.ListVersions(ctx, key)
			out = append(out, kv)
		}
	}
	return out, nil
}

func (r *fakeReader) find(key, id string) (fakeVersion, bool) {
	for _, v := range r.objects[key] {
		if v.id == id {
			return v, true
		}
	}
	return fakeVersion{}, false
}

func (r *fakeReader) GetRetention(_ context.Context, key, id string) (SinkRetention, error) {
	r.calls = append(r.calls, "GetRetention")
	if err := r.errs["GetRetention"]; err != nil {
		return SinkRetention{}, err
	}
	v, ok := r.find(key, id)
	if !ok {
		return SinkRetention{}, fmt.Errorf("no version %s at %s", id, key)
	}
	if v.mode == "" {
		return SinkRetention{}, nil
	}
	return SinkRetention{Mode: v.mode, RetainUntil: v.until}, nil
}

func (r *fakeReader) Get(_ context.Context, key, id string, max int64) ([]byte, error) {
	r.calls = append(r.calls, "Get")
	if err := r.errs["Get"]; err != nil {
		return nil, err
	}
	v, ok := r.find(key, id)
	if !ok {
		return nil, fmt.Errorf("no version %s at %s", id, key)
	}
	if int64(len(v.data)) > max {
		return nil, fmt.Errorf("object %s version %s exceeds the %d-byte bound", key, id, max)
	}
	return bytes.Clone(v.data), nil
}

// restoreFixture: two worm seals through SealActive, each copy stored in the
// reader by the sink's Put (so the "bucket" holds exactly what the seal
// wrote): segment 1 = seq 1–4 (v-1), segment 2 = seq 5–8 (v-2), the active
// empty.
func restoreFixture(t *testing.T) (string, *fakeReader) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "control.jsonl")
	r := newFakeReader()
	s := &fakeSink{}
	s.onPut = func() { r.add(s.putLoc.Key, s.putData, "COMPLIANCE", s.putLoc.RetainUntil) }
	for i := 0; i < 2; i++ {
		appendN(t, p, 3)
		if _, err := SealActive(p, sealEvent(), s); err != nil {
			t.Fatal(err)
		}
	}
	if v, err := Read(p, ledger.Locked); err != nil || len(v.Sealed) != 2 || v.Head.Count != 8 {
		t.Fatalf("fixture: %v %+v", err, v.Head)
	}
	return p, r
}

func restoreEvent() Event {
	return Event{Action: "restore", Outcome: "success", Invoker: identity.Static("ops@example.com"), Witness: Witness{OSUser: "ops", Hostname: "host"}}
}

func segKey(t *testing.T, p string, r *fakeReader, n int) string {
	t.Helper()
	return r.Prefix(logIDOf(t, p)) + fmt.Sprintf("seg-%06d", n)
}

func assertSetFault(t *testing.T, p string, want Fault, seg int) *SetError {
	t.Helper()
	_, err := Read(p, ledger.Locked)
	var se *SetError
	if !errors.As(err, &se) || se.Fault != want || se.Segment != seg {
		t.Fatalf("want fault %d in segment %d, got %v", want, seg, err)
	}
	return se
}

func lastRecord(t *testing.T, p string) (record, View) {
	t.Helper()
	v, err := Read(p, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := decodeRecord(v.Records[len(v.Records)-1])
	if !ok {
		t.Fatal("the last record does not decode")
	}
	return rec, v
}

// TestRestoreMissingSegment: segment 1 removed → restored byte-identical
// from v-1, nothing moved aside, the set clean, one restore record, no
// taint, the last install unchanged.
func TestRestoreMissingSegment(t *testing.T) {
	p, r := restoreFixture(t)
	seg1 := SegmentPath(p, 1)
	want, err := os.ReadFile(seg1)
	if err != nil {
		t.Fatal(err)
	}
	m, err := loadManifest(p)
	if err != nil || m == nil {
		t.Fatal(err)
	}
	before, _ := Read(p, ledger.Locked)
	installBefore, ok := LastInstalling(before.Records)
	if !ok {
		t.Fatal("the fixture installs")
	}
	if err := os.Remove(seg1); err != nil {
		t.Fatal(err)
	}
	_ = assertSetFault(t, p, FaultMissingSegment, 1)
	res, err := Restore(p, nil, r, restoreEvent())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Restored) != 1 {
		t.Fatalf("%+v", res)
	}
	got := res.Restored[0]
	if got.N != 1 || got.VersionID != "v-1" || got.SHA256 != m.Segments[0].SHA256 || got.Replaced != "" || got.NotOldest || got.Unlocked || got.ManifestDisagrees || got.Sink.Kind != "s3-object-lock" {
		t.Fatalf("%+v", got)
	}
	back, err := os.ReadFile(seg1)
	if err != nil || !bytes.Equal(back, want) {
		t.Fatalf("the restored file is not what was removed: %v", err)
	}
	rec, v := lastRecord(t, p)
	if rec.Action != "restore" || rec.Outcome != "success" || rec.Seq != 9 || rec.Detail != "segment 1 restored from s3-object-lock version v-1; nothing was there" || rec.Invoker.Subject != "ops@example.com" {
		t.Fatalf("%+v", rec)
	}
	if v.Head != res.Head {
		t.Fatalf("head %+v vs %+v", v.Head, res.Head)
	}
	if tainted, _ := IsTainted(v.Records); tainted {
		t.Fatal("a restore taints nothing")
	}
	if installAfter, ok := LastInstalling(v.Records); !ok || installAfter.Seq != installBefore.Seq {
		t.Fatal("a restore installs nothing")
	}
	if calls := strings.Join(r.calls, ","); calls != "ListVersions,Get,GetRetention" {
		t.Fatalf("calls %s", calls)
	}
}

// TestRestoreDamagedSegmentKeepsEvidence: a truncated segment 2 (FaultTorn)
// is restored, the damaged bytes kept at <base>.replaced-000002-<ts>, the
// record saying so; "junk\n" appended is a torn tail too and restorable; a
// chained record appended after the seal (FaultSealNotLast) is deliberately
// NOT restorable and refuses with the shipped text, nothing touched.
func TestRestoreDamagedSegmentKeepsEvidence(t *testing.T) {
	p, r := restoreFixture(t)
	seg2 := SegmentPath(p, 2)
	data, _ := os.ReadFile(seg2)
	damaged := data[:len(data)-10]
	if err := os.WriteFile(seg2, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = assertSetFault(t, p, FaultTorn, 2)
	res, err := Restore(p, nil, r, restoreEvent())
	if err != nil || len(res.Restored) != 1 || res.Restored[0].N != 2 || res.Restored[0].VersionID != "v-2" {
		t.Fatalf("%v %+v", err, res)
	}
	replaced := res.Restored[0].Replaced
	resolvedDir, _ := filepath.EvalSymlinks(filepath.Dir(p))
	if !regexp.MustCompile(`control\.jsonl\.replaced-000002-\d+$`).MatchString(replaced) || filepath.Dir(replaced) != resolvedDir {
		t.Fatalf("replaced name %q", replaced)
	}
	if kept, err := os.ReadFile(replaced); err != nil || !bytes.Equal(kept, damaged) {
		t.Fatalf("the replaced file must hold the damaged bytes: %v", err)
	}
	if back, _ := os.ReadFile(seg2); !bytes.Equal(back, data) {
		t.Fatal("segment 2 is not the sealed bytes")
	}
	rec, _ := lastRecord(t, p)
	if want := "segment 2 restored from s3-object-lock version v-2; replaced bytes kept at " + filepath.Base(replaced); rec.Detail != want {
		t.Fatalf("detail %q, want %q", rec.Detail, want)
	}

	t.Run("junk appended is torn and restorable", func(t *testing.T) {
		p, r := restoreFixture(t)
		seg1 := SegmentPath(p, 1)
		appendBytes(t, seg1, []byte("junk\n"))
		_ = assertSetFault(t, p, FaultTorn, 1)
		res, err := Restore(p, nil, r, restoreEvent())
		if err != nil || len(res.Restored) != 1 || res.Restored[0].N != 1 || !strings.Contains(res.Restored[0].Replaced, "control.jsonl.replaced-000001-") {
			t.Fatalf("%v %+v", err, res)
		}
		if kept, _ := os.ReadFile(res.Restored[0].Replaced); !bytes.HasSuffix(kept, []byte("junk\n")) {
			t.Fatal("the evidence holds the appended junk")
		}
	})
	t.Run("seal not last is not restorable", func(t *testing.T) {
		p, r := restoreFixture(t)
		v, _ := Read(p, ledger.Locked)
		extra := record{V: "control/1", Seq: v.Sealed[1].HeadSeq + 1, Time: time.Now().UTC(), Action: "prune", Outcome: "success", Invoker: identity.Static("old"), Witness: Witness{}, Prev: v.Sealed[1].HeadHash}
		line, _ := json.Marshal(extra)
		appendBytes(t, SegmentPath(p, 2), append(line, '\n'))
		se := assertSetFault(t, p, FaultSealNotLast, 2)
		snap := snapshotDir(t, filepath.Dir(p))
		_, err := Restore(p, nil, r, restoreEvent())
		if err == nil || err.Error() != se.Error() || !strings.Contains(err.Error(), "a sealed segment was appended to") {
			t.Fatalf("%v", err)
		}
		if snapshotDir(t, filepath.Dir(p)) != snap || len(r.calls) != 0 {
			t.Fatal("a refusal changes nothing and reads nothing")
		}
	})
}

// TestRestoreNamesAreNotSiblings (§14.3): the restore temp and the replaced
// name fall outside the <base>.seg- prefix — a root with both beside it
// reads clean — and sweepTemps removes the temp but never the evidence.
func TestRestoreNamesAreNotSiblings(t *testing.T) {
	p, r := restoreFixture(t)
	dir := filepath.Dir(p)
	temp := filepath.Join(dir, ".control.jsonl.restore-abc")
	kept := filepath.Join(dir, "control.jsonl.replaced-000001-1")
	for _, f := range []string{temp, kept} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Read(p, ledger.Locked); err != nil {
		t.Fatalf("neither name is a segment: %v", err)
	}
	if _, err := Restore(p, nil, r, restoreEvent()); !errors.Is(err, ErrNothingToRestore) {
		t.Fatalf("%v", err)
	}
	sweepTemps(p)
	if _, err := os.Lstat(temp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the restore temp is swept")
	}
	if _, err := os.Lstat(kept); err != nil {
		t.Fatal("the replaced file is evidence and is never swept")
	}
}

// TestRestoreSelectsByTheChain: the version is chosen by the chain, never by
// position or by the manifest — an oldest that does not chain is skipped
// (NotOldest); a GOVERNANCE-locked copy is still the right bytes (Unlocked);
// a manifest sha256 that disagrees is printed, not refused; no chaining
// version → the "protected copy is missing" refusal with nothing written;
// a transport error is that error, never "missing".
func TestRestoreSelectsByTheChain(t *testing.T) {
	far := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	t.Run("not oldest", func(t *testing.T) {
		p, r := restoreFixture(t)
		key := segKey(t, p, r, 1)
		real := r.objects[key][0].data
		r.objects[key] = []fakeVersion{{id: "v-1", data: []byte("other\n"), mode: "COMPLIANCE", until: far}, {id: "v-2", data: real, mode: "COMPLIANCE", until: far}}
		_ = os.Remove(SegmentPath(p, 1))
		res, err := Restore(p, nil, r, restoreEvent())
		if err != nil || len(res.Restored) != 1 || res.Restored[0].VersionID != "v-2" || !res.Restored[0].NotOldest || res.Restored[0].Unlocked {
			t.Fatalf("%v %+v", err, res)
		}
		if _, err := Read(p, ledger.Locked); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unlocked", func(t *testing.T) {
		p, r := restoreFixture(t)
		key := segKey(t, p, r, 1)
		r.objects[key][0].mode = "GOVERNANCE"
		_ = os.Remove(SegmentPath(p, 1))
		res, err := Restore(p, nil, r, restoreEvent())
		if err != nil || len(res.Restored) != 1 || !res.Restored[0].Unlocked || res.Restored[0].NotOldest {
			t.Fatalf("%v %+v", err, res)
		}
		p, r = restoreFixture(t)
		r.objects[segKey(t, p, r, 1)][0].mode = ""
		_ = os.Remove(SegmentPath(p, 1))
		if res, err := Restore(p, nil, r, restoreEvent()); err != nil || !res.Restored[0].Unlocked {
			t.Fatalf("no lock at all: %v %+v", err, res)
		}
	})
	t.Run("manifest disagrees", func(t *testing.T) {
		p, r := restoreFixture(t)
		m, _ := loadManifest(p)
		m.Segments[0].SHA256 = strings.Repeat("0", 64)
		data, _ := json.Marshal(m)
		_ = os.WriteFile(ManifestPath(p), data, 0o600)
		se := assertSetFault(t, p, FaultManifest, 1)
		if !strings.Contains(se.Error(), "sha256") {
			t.Fatal(se)
		}
		// The restore proceeds — the chain's bytes are written, the old file
		// kept — but the manifest is untouched and still disagrees, so the set
		// does not read clean and nothing is recorded: the fault is returned
		// beside what was written, for the command to print both.
		res, err := Restore(p, nil, r, restoreEvent())
		var after *SetError
		if err == nil || !errors.As(err, &after) || after.Fault != FaultManifest || after.Segment != 1 || !strings.Contains(err.Error(), "sha256") {
			t.Fatalf("%v", err)
		}
		if len(res.Restored) != 1 || !res.Restored[0].ManifestDisagrees || res.Restored[0].Replaced == "" || res.Restored[0].SHA256 == m.Segments[0].SHA256 {
			t.Fatalf("%+v", res)
		}
		if fi, err := os.Stat(p); err != nil || fi.Size() != 0 {
			t.Fatal("nothing recorded: the active stays empty")
		}
	})
	t.Run("none chains", func(t *testing.T) {
		p, r := restoreFixture(t)
		key := segKey(t, p, r, 1)
		r.objects[key] = []fakeVersion{{id: "v-1", data: []byte("other\n"), mode: "COMPLIANCE", until: far}}
		_ = os.Remove(SegmentPath(p, 1))
		snap := snapshotDir(t, filepath.Dir(p))
		_, err := Restore(p, nil, r, restoreEvent())
		want := "control: segment 1: no version at " + key + " chains from the genesis; the protected copy is missing"
		if err == nil || err.Error() != want {
			t.Fatalf("%v", err)
		}
		if snapshotDir(t, filepath.Dir(p)) != snap {
			t.Fatal("nothing written")
		}
		_ = assertSetFault(t, p, FaultMissingSegment, 1)
		r.objects[key] = nil
		if _, err := Restore(p, nil, r, restoreEvent()); err == nil || err.Error() != want {
			t.Fatalf("an empty key: %v", err)
		}
		// Segment 2's text names the preceding head.
		p, r = restoreFixture(t)
		v, _ := Read(p, ledger.Locked)
		key2 := segKey(t, p, r, 2)
		r.objects[key2] = nil
		_ = os.Remove(SegmentPath(p, 2))
		if _, err := Restore(p, nil, r, restoreEvent()); err == nil || err.Error() != "control: segment 2: no version at "+key2+" chains from segment 1's head "+v.Sealed[0].HeadHash+"; the protected copy is missing" {
			t.Fatalf("%v", err)
		}
	})
	t.Run("transport error is not missing", func(t *testing.T) {
		for _, op := range []string{"ListVersions", "Get", "GetRetention"} {
			p, r := restoreFixture(t)
			r.errs[op] = errors.New("status 503 from host (" + op + ")")
			_ = os.Remove(SegmentPath(p, 1))
			snap := snapshotDir(t, filepath.Dir(p))
			_, err := Restore(p, nil, r, restoreEvent())
			if err == nil || !strings.Contains(err.Error(), "status 503 from host ("+op+")") || strings.Contains(err.Error(), "missing") {
				t.Fatalf("%s: %v", op, err)
			}
			if snapshotDir(t, filepath.Dir(p)) != snap {
				t.Fatalf("%s: nothing written", op)
			}
		}
	})
}

// TestRestoreRefusals: every verdict restore does not answer refuses with
// its own text and touches nothing.
func TestRestoreRefusals(t *testing.T) {
	t.Run("clean", func(t *testing.T) {
		p, r := restoreFixture(t)
		if _, err := Restore(p, nil, r, restoreEvent()); !errors.Is(err, ErrNothingToRestore) || !strings.Contains(err.Error(), "run: audit restore control --rebuild") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("state B", func(t *testing.T) {
		p, r := restoreFixture(t)
		appendN(t, p, 1)
		sealByHand(t, p, "B")
		_, err := Restore(p, nil, r, restoreEvent())
		if want := fmt.Sprintf("control: ledger %s: the active segment is sealed and not yet rotated; run audit seal to complete it — not a restore matter", p); err == nil || err.Error() != want {
			t.Fatalf("%v", err)
		}
	})
	t.Run("torn active", func(t *testing.T) {
		p, r := restoreFixture(t)
		appendN(t, p, 1)
		tear(t, p, 10)
		se := assertSetFault(t, p, FaultTorn, 0)
		if _, err := Restore(p, nil, r, restoreEvent()); err == nil || err.Error() != se.Error() {
			t.Fatalf("%v", err)
		}
	})
	t.Run("planted seal in the active", func(t *testing.T) {
		p, r := restoreFixture(t)
		appendN(t, p, 1)
		v, _ := Read(p, ledger.Locked)
		planted := record{V: "control/1", Seq: v.Head.Count + 1, Time: time.Now().UTC(), Action: "seal", Outcome: "success", Invoker: identity.Static("x"), Witness: Witness{},
			Seal: &Seal{Segment: 3, FirstSeq: 9, HeadSeq: 9, HeadHash: v.Head.Hash, ContentSHA256: strings.Repeat("0", 64)}, Prev: v.Head.Hash}
		line, _ := json.Marshal(planted)
		appendBytes(t, p, append(line, '\n'))
		se := assertSetFault(t, p, FaultManifest, 3)
		if _, err := Restore(p, nil, r, restoreEvent()); err == nil || err.Error() != se.Error() {
			t.Fatalf("a FaultManifest the manifest does not list is the active's: %v", err)
		}
	})
	t.Run("manifest removed", func(t *testing.T) {
		p, r := restoreFixture(t)
		id := logIDOf(t, p)
		_ = os.Remove(ManifestPath(p))
		se := assertSetFault(t, p, FaultUnexpectedSegment, 0)
		_, err := Restore(p, nil, r, restoreEvent())
		if err == nil || err.Error() != se.Error()+"; run: audit restore control --rebuild --log-id "+id {
			t.Fatalf("%v", err)
		}
	})
	t.Run("manifest unusable", func(t *testing.T) {
		p, r := restoreFixture(t)
		id := logIDOf(t, p)
		_ = os.WriteFile(ManifestPath(p), []byte("{"), 0o600)
		se := assertSetFault(t, p, FaultManifest, 0)
		if _, err := Restore(p, nil, r, restoreEvent()); err == nil || err.Error() != se.Error()+"; run: audit restore control --rebuild --log-id "+id {
			t.Fatalf("%v", err)
		}
	})
	t.Run("active missing", func(t *testing.T) {
		p, r := restoreFixture(t)
		id := logIDOf(t, p)
		_ = os.Remove(p)
		se := assertSetFault(t, p, FaultActiveMissing, 0)
		if _, err := Restore(p, nil, r, restoreEvent()); err == nil || err.Error() != se.Error()+"; run: audit restore control --rebuild --log-id "+id {
			t.Fatalf("%v", err)
		}
	})
	t.Run("nothing readable names the literal", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "control.jsonl")
		_ = os.WriteFile(SegmentPath(p, 1), []byte("junk\n"), 0o600)
		_ = os.WriteFile(p, nil, 0o600)
		se := assertSetFault(t, p, FaultUnexpectedSegment, 0)
		if _, err := Restore(p, nil, newFakeReader(), restoreEvent()); err == nil || err.Error() != se.Error()+"; run: audit restore control --rebuild --log-id <id>" {
			t.Fatalf("%v", err)
		}
	})
	t.Run("nothing recorded", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "control.jsonl")
		if _, err := Restore(p, nil, newFakeReader(), restoreEvent()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("only names another segment", func(t *testing.T) {
		p, r := restoreFixture(t)
		_ = os.Remove(SegmentPath(p, 1))
		snap := snapshotDir(t, filepath.Dir(p))
		if _, err := Restore(p, []int{2}, r, restoreEvent()); err == nil || err.Error() != "control: segment 2 is not at fault; the fault is in segment 1" {
			t.Fatalf("%v", err)
		}
		if snapshotDir(t, filepath.Dir(p)) != snap || len(r.calls) != 0 {
			t.Fatal("nothing written, nothing read")
		}
		// The named ordinals narrow: one of them at fault is restored, one
		// that turns out not to be is simply not touched.
		if res, err := Restore(p, []int{1, 2}, r, restoreEvent()); err != nil || len(res.Restored) != 1 || res.Restored[0].N != 1 {
			t.Fatalf("%v %+v", err, res)
		}
	})
	t.Run("event shape", func(t *testing.T) {
		p, r := restoreFixture(t)
		for _, e := range []Event{{Action: "repair", Outcome: "success"}, {Action: "restore", Outcome: "refused"}, {Action: "restore", Outcome: "success", Detail: "x"}} {
			if _, err := Restore(p, nil, r, e); err == nil || !strings.Contains(err.Error(), "Restore takes a success restore event without a detail") {
				t.Fatalf("%+v: %v", e, err)
			}
		}
	})
}

// TestRestoreTwoSegmentsInOrder: both sealed segments removed → restored in
// ascending order, re-reading between them, then one record per segment.
func TestRestoreTwoSegmentsInOrder(t *testing.T) {
	p, r := restoreFixture(t)
	_ = os.Remove(SegmentPath(p, 1))
	_ = os.Remove(SegmentPath(p, 2))
	res, err := Restore(p, nil, r, restoreEvent())
	if err != nil || len(res.Restored) != 2 || res.Restored[0].N != 1 || res.Restored[1].N != 2 || res.Restored[0].VersionID != "v-1" || res.Restored[1].VersionID != "v-2" {
		t.Fatalf("%v %+v", err, res)
	}
	v, err := Read(p, ledger.Locked)
	if err != nil || v.Head.Count != 10 || v.Head != res.Head {
		t.Fatalf("%v %+v", err, v.Head)
	}
	for i, want := range []string{"segment 1 restored from s3-object-lock version v-1; nothing was there", "segment 2 restored from s3-object-lock version v-2; nothing was there"} {
		rec, _ := decodeRecord(v.Records[8+i])
		if rec.Action != "restore" || rec.Detail != want || rec.Seq != 9+i {
			t.Fatalf("%+v", rec)
		}
	}
	// Narrowed to segment 1 while 2 is also gone: 1 is restored, then the
	// fault in 2 is returned as found and nothing is recorded.
	p, r = restoreFixture(t)
	_ = os.Remove(SegmentPath(p, 1))
	_ = os.Remove(SegmentPath(p, 2))
	if _, err := Restore(p, []int{1}, r, restoreEvent()); err == nil || !strings.Contains(err.Error(), "control ledger segment 2 missing") {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(SegmentPath(p, 1)); err != nil {
		t.Fatal("segment 1 was restored and left in place")
	}
	_ = assertSetFault(t, p, FaultMissingSegment, 2)
}

// TestRestoreContinuityWithNextSegment: a candidate for segment 1 that
// recomputes (the same records under a seal line that differs only in its
// time) but whose seal hash is not what segment 2's first record names as
// prev is skipped; the real copy is selected.
func TestRestoreContinuityWithNextSegment(t *testing.T) {
	far := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	// forge rewrites a sealed segment's seal line with another time: the
	// chain fields still recompute, the line's hash differs.
	forge := func(real []byte) []byte {
		lines := bytes.Split(bytes.TrimSuffix(real, []byte("\n")), []byte("\n"))
		var seal map[string]any
		if err := json.Unmarshal(lines[len(lines)-1], &seal); err != nil {
			t.Fatal(err)
		}
		seal["time"] = "2026-01-01T00:00:00Z"
		altered, _ := json.Marshal(seal)
		lines[len(lines)-1] = altered
		return append(bytes.Join(lines, []byte("\n")), '\n')
	}
	p, r := restoreFixture(t)
	key := segKey(t, p, r, 1)
	real := r.objects[key][0].data
	forged := forge(real)
	if _, _, err := verifyFetchedSegment(forged, 1, ledger.Start{}, logIDOf(t, p), key); err != nil {
		t.Fatalf("the forged candidate must recompute on its own: %v", err)
	}
	r.objects[key] = []fakeVersion{{id: "v-1", data: forged, mode: "COMPLIANCE", until: far}, {id: "v-2", data: real, mode: "COMPLIANCE", until: far}}
	_ = os.Remove(SegmentPath(p, 1))
	res, err := Restore(p, nil, r, restoreEvent())
	if err != nil || len(res.Restored) != 1 || res.Restored[0].VersionID != "v-2" || !res.Restored[0].NotOldest {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := Read(p, ledger.Locked); err != nil {
		t.Fatal(err)
	}

	// Only the forged candidate at the key, and segment 2 continues the
	// real one: the copy chains but the local segment after it does not
	// continue it — named as such, never "missing"; nothing written.
	p, r = restoreFixture(t)
	key, id := segKey(t, p, r, 1), logIDOf(t, p)
	r.objects[key] = []fakeVersion{{id: "v-1", data: forge(r.objects[key][0].data), mode: "COMPLIANCE", until: far}}
	_ = os.Remove(SegmentPath(p, 1))
	snap := snapshotDir(t, filepath.Dir(p))
	_, err = Restore(p, nil, r, restoreEvent())
	if want := "control: segment 1: 1 version(s) at " + key + " chain from the genesis, but segment 2's first record continues none of them — either the chaining copy at the key is not the seal's own (audit verify control's sink pass judges the oldest version) or the local segment 2 was replaced; run: audit restore control --rebuild --log-id " + id; err == nil || err.Error() != want {
		t.Fatalf("%v", err)
	}
	if snapshotDir(t, filepath.Dir(p)) != snap {
		t.Fatal("nothing written")
	}

	// The last listed segment: what follows it is the active, whose first
	// record's prev is the constraint. A forged oldest copy of segment 2
	// that recomputes is skipped for the real one the active continues
	// from; with only the forgery at the key the refusal names the active.
	p, r = restoreFixture(t)
	appendN(t, p, 1) // the active now holds a record chained from segment 2's seal
	key = segKey(t, p, r, 2)
	real2 := r.objects[key][0].data
	r.objects[key] = []fakeVersion{{id: "v-1", data: forge(real2), mode: "COMPLIANCE", until: far}, {id: "v-2", data: real2, mode: "COMPLIANCE", until: far}}
	_ = os.Remove(SegmentPath(p, 2))
	res, err = Restore(p, nil, r, restoreEvent())
	if err != nil || len(res.Restored) != 1 || res.Restored[0].N != 2 || res.Restored[0].VersionID != "v-2" || !res.Restored[0].NotOldest {
		t.Fatalf("%v %+v", err, res)
	}
	if v, err := Read(p, ledger.Locked); err != nil || v.Head.Count != 10 {
		t.Fatalf("%v %+v", err, v.Head)
	}
	p, r = restoreFixture(t)
	appendN(t, p, 1)
	key, id = segKey(t, p, r, 2), logIDOf(t, p)
	r.objects[key] = []fakeVersion{{id: "v-1", data: forge(r.objects[key][0].data), mode: "COMPLIANCE", until: far}}
	_ = os.Remove(SegmentPath(p, 2))
	snap = snapshotDir(t, filepath.Dir(p))
	_, err = Restore(p, nil, r, restoreEvent())
	if err == nil || !strings.Contains(err.Error(), "but the active segment's first record continues none of them — either the chaining copy at the key is not the seal's own") || !strings.HasSuffix(err.Error(), "or the local active segment was replaced; run: audit restore control --rebuild --log-id "+id) {
		t.Fatalf("%v", err)
	}
	if snapshotDir(t, filepath.Dir(p)) != snap {
		t.Fatal("nothing written")
	}
	// An EMPTY active constrains nothing: the forgery alone is accepted for
	// the last segment (§5.3's oldest-first rule is the defence there).
	p, r = restoreFixture(t)
	key = segKey(t, p, r, 2)
	r.objects[key] = []fakeVersion{{id: "v-1", data: forge(r.objects[key][0].data), mode: "COMPLIANCE", until: far}}
	_ = os.Remove(SegmentPath(p, 2))
	if res, err := Restore(p, nil, r, restoreEvent()); err == nil || len(res.Restored) != 1 || !strings.Contains(err.Error(), "manifest disagrees with segment 2") {
		t.Fatalf("an empty active cannot judge the last segment; the manifest's figure then does: %v %+v", err, res)
	}
}

// TestRestoreRefusesIncompleteRotationBeforeWriting (§11.2 step 4): a root
// in state B or C whose EARLIER segment is at fault — Read's verdict stops
// at that segment and never decides the rotation state — is refused from
// the active itself before any write, with no sink call; and in state C
// the last listed segment IS the active's inode, so a torn one is refused
// rather than moved aside from under the active's name.
func TestRestoreRefusesIncompleteRotationBeforeWriting(t *testing.T) {
	for _, state := range []string{"B", "C"} {
		t.Run("state "+state+" earlier segment missing", func(t *testing.T) {
			p, r := restoreFixture(t)
			appendN(t, p, 1)
			sealByHand(t, p, state)
			_ = os.Remove(SegmentPath(p, 1))
			_ = assertSetFault(t, p, FaultMissingSegment, 1)
			snap := snapshotDir(t, filepath.Dir(p))
			_, err := Restore(p, nil, r, restoreEvent())
			if err == nil || err.Error() != errNotRestoreMatter(p).Error() {
				t.Fatalf("%v", err)
			}
			if snapshotDir(t, filepath.Dir(p)) != snap || len(r.calls) != 0 {
				t.Fatal("refused before any write and before any sink call")
			}
			_ = assertSetFault(t, p, FaultMissingSegment, 1)
		})
	}
	t.Run("state C last segment torn is the active", func(t *testing.T) {
		p, r := restoreFixture(t)
		appendN(t, p, 1)
		sealByHand(t, p, "C") // the manifest lists 3; the active name is segment 3's inode
		seg3 := SegmentPath(p, 3)
		data, _ := os.ReadFile(seg3)
		_ = os.WriteFile(seg3, data[:len(data)-10], 0o600)
		_ = assertSetFault(t, p, FaultTorn, 3)
		snap := snapshotDir(t, filepath.Dir(p))
		_, err := Restore(p, nil, r, restoreEvent())
		if err == nil || err.Error() != errNotRestoreMatter(p).Error() {
			t.Fatalf("%v", err)
		}
		if snapshotDir(t, filepath.Dir(p)) != snap || len(r.calls) != 0 {
			t.Fatal("the active's own inode is never moved aside")
		}
	})
	t.Run("open active with a fault is still restored", func(t *testing.T) {
		p, r := restoreFixture(t)
		appendN(t, p, 2) // an open active with records: no refusal
		_ = os.Remove(SegmentPath(p, 1))
		if res, err := Restore(p, nil, r, restoreEvent()); err != nil || len(res.Restored) != 1 {
			t.Fatalf("%v %+v", err, res)
		}
	})
}

// TestVerifyFetchedSegmentTexts pins the rule each refusal names (reused by
// the rebuild).
func TestVerifyFetchedSegmentTexts(t *testing.T) {
	p, r := restoreFixture(t)
	id := logIDOf(t, p)
	v, _ := Read(p, ledger.Locked)
	key1, key2 := segKey(t, p, r, 1), segKey(t, p, r, 2)
	seg1, seg2 := r.objects[key1][0].data, r.objects[key2][0].data
	start2 := ledger.Start{Prev: v.Sealed[0].HeadHash, Base: uint64(v.Sealed[0].HeadSeq)}
	if seg, recs, err := verifyFetchedSegment(seg2, 2, start2, id, key2); err != nil || seg.N != 2 || seg.FirstSeq != 5 || seg.HeadSeq != 8 || seg.HeadHash != v.Sealed[1].HeadHash || seg.SHA256 != v.Sealed[1].SHA256 || seg.Bytes != int64(len(seg2)) || len(recs) != 4 || seg.Sink == nil || seg.SealedAt.IsZero() {
		t.Fatalf("%v %+v", err, seg)
	}
	other := strings.Repeat("a", 32)
	// A well-formed record chained after segment 1's seal line.
	sealLine := seg1[bytes.LastIndex(seg1[:len(seg1)-1], []byte("\n"))+1 : len(seg1)-1]
	afterSeal, _ := json.Marshal(record{V: "control/1", Seq: 5, Action: "prune", Outcome: "success", Invoker: identity.Static("old"), Witness: Witness{}, Prev: hashLine(sealLine)})
	for name, c := range map[string]struct {
		data       []byte
		k          int
		start      ledger.Start
		logID, key string
		want       string
	}{
		"foreign":        {[]byte("other\n"), 2, start2, id, key2, "segment 2: the oldest version at the key is not a sealed segment of this ledger — the sink's copy was replaced before the seal could write it, or the key was pre-occupied"},
		"empty":          {nil, 2, start2, id, key2, "segment 2: the oldest version at the key is not a sealed segment of this ledger — the sink's copy was replaced before the seal could write it, or the key was pre-occupied"},
		"wrong start":    {seg2, 4, ledger.Start{Prev: strings.Repeat("0", 64), Base: 8}, id, key2, "segment 4's first record does not chain from segment 3's head " + strings.Repeat("0", 64)},
		"other key":      {seg2, 2, start2, id, "p/x/seg-000002", "segment 2: the seal's sink block names " + key2 + ", not p/x/seg-000002"},
		"other ledger":   {seg1, 1, ledger.Start{}, other, key1, "segment 1: the genesis carries log_id " + id + ", not this ledger's " + other},
		"wrong ordinal":  {seg1, 2, ledger.Start{}, id, key1, "segment 2: the seal does not recompute as segment 2 (segment=1"},
		"torn copy":      {seg1[:len(seg1)-3], 1, ledger.Start{}, id, key1, "segment 1: the copy is torn after 3 records"},
		"seal not last":  {append(append(bytes.Clone(seg1), afterSeal...), '\n'), 1, ledger.Start{}, id, key1, "segment 1: a record follows the seal line"},
		"not a seal":     {seg1[:bytes.LastIndex(seg1[:len(seg1)-1], []byte("\n"))+1], 1, ledger.Start{}, id, key1, "segment 1: the last line is not a successful seal"},
		"genesis in two": {seg1, 2, start2, id, key2, "segment 2's first record does not chain from segment 1's head " + v.Sealed[0].HeadHash},
	} {
		_, _, err := verifyFetchedSegment(c.data, c.k, c.start, c.logID, c.key)
		if err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Fatalf("%s: %v\nwant prefix %q", name, err, c.want)
		}
	}
}

// TestCheckRestoreShape: the three permit texts, and Append refusing a
// restore that carries a config_hash with nothing appended.
func TestCheckRestoreShape(t *testing.T) {
	for _, c := range []struct {
		e    Event
		want string
	}{
		{Event{Action: "restore", Outcome: "refused", Detail: "x"}, "control: a restore that did not restore records nothing"},
		{Event{Action: "restore", Outcome: "error", Detail: "x"}, "control: a restore that did not restore records nothing"},
		{Event{Action: "restore", Outcome: "success", Detail: "x", ConfigHash: "sha256:a"}, "control: a restore installs nothing and carries no config_hash, anchor, seal or fragment"},
		{Event{Action: "restore", Outcome: "success", Detail: "x", Anchor: &Anchor{}}, "control: a restore installs nothing and carries no config_hash, anchor, seal or fragment"},
		{Event{Action: "restore", Outcome: "success", Detail: "x", Seal: &Seal{}}, "control: a restore installs nothing and carries no config_hash, anchor, seal or fragment"},
		{Event{Action: "restore", Outcome: "success", Detail: "x", FragmentLen: 1}, "control: a restore installs nothing and carries no config_hash, anchor, seal or fragment"},
		{Event{Action: "restore", Outcome: "success", Detail: "x", FragmentSHA: "a"}, "control: a restore installs nothing and carries no config_hash, anchor, seal or fragment"},
		{Event{Action: "restore", Outcome: "success"}, "control: a restore must say what it restored"},
		{Event{Action: "restore", Outcome: "success", Detail: "segment 1 restored"}, ""},
		{Event{Action: "apply", Outcome: "success", ConfigHash: "sha256:a"}, ""},
	} {
		err := checkRestoreShape(c.e)
		if (err == nil) != (c.want == "") || (err != nil && err.Error() != c.want) {
			t.Fatalf("%+v: %v", c.e, err)
		}
	}
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 1)
	before, _ := os.ReadFile(p)
	_, err := Append(p, Event{Action: "restore", Outcome: "success", Detail: "x", ConfigHash: "sha256:a", Invoker: identity.Static("x")})
	if err == nil || err.Error() != "control: a restore installs nothing and carries no config_hash, anchor, seal or fragment" {
		t.Fatalf("%v", err)
	}
	if after, _ := os.ReadFile(p); !bytes.Equal(before, after) {
		t.Fatal("nothing appended")
	}
	if _, err := Append(p, Event{Action: "restore", Outcome: "success", Detail: "segment 1 restored from s3-object-lock version v-1; nothing was there", Invoker: identity.Static("x")}); err != nil {
		t.Fatal(err)
	}
	v, _ := Read(p, ledger.Locked)
	if tainted, _ := IsTainted(v.Records); tainted {
		t.Fatal("a restore record is not a taint")
	}
	if last, ok := LastInstalling(v.Records); !ok || last.Seq != 1 {
		t.Fatal("a restore record installs nothing: the apply at seq 1 is still the last install")
	}
}

// TestRestoreLabel: the rendered line for a restore record.
func TestRestoreLabel(t *testing.T) {
	out := RenderView(View{Records: []ledger.Record{
		{Raw: []byte(`{"v":"control/1","seq":1,"time":"2026-10-22T10:00:00Z","action":"restore","outcome":"success","invoker":{"subject":"ops","issuer":"local","method":"static"},"witness":{},"detail":"segment 1 restored from s3-object-lock version v-1; nothing was there","prev":""}`)},
	}, Head: ledger.Head{Count: 1}, FirstSeq: 1}, nil)
	if !strings.Contains(out, "  seq 1  2026-10-22 10:00:00  restored a sealed segment from its protected copy (segment 1 restored from s3-object-lock version v-1; nothing was there) — ops (static)\n") {
		t.Fatalf("%s", out)
	}
	if got := label(record{Action: "restore", Outcome: "refused"}); got != "restore refused" {
		t.Fatalf("%q", got)
	}
}
