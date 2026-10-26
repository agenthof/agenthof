package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

// fakeSink records calls and fails on command. It keeps what a Put stored,
// by key, so the oldest-version rule a real Put applies holds here too: a
// key holding these bytes is Existed; a key holding other bytes refuses.
type fakeSink struct {
	url, kind          string // "" → the defaults
	calls              []string
	prepareErr, putErr error
	putData            []byte
	putSHA             string
	putLoc             SealSink
	receipts           []PutReceipt      // every receipt a Put returned, in order
	objects            map[string][]byte // what Put stored, by key
	// onPut runs after a Put succeeds, before it returns — a test's lever
	// for what happens between a repair's pre-confirmed copy and its
	// truncate (the sink goes away; another holder takes the active's lock).
	onPut func()
}

func (f *fakeSink) Kind() string {
	if f.kind != "" {
		return f.kind
	}
	return "s3-object-lock"
}

func (f *fakeSink) URL() string {
	if f.url != "" {
		return f.url
	}
	return "https://sink.example/bucket/p"
}

func (f *fakeSink) Locator(logID string, n int, at time.Time) SealSink {
	return SealSink{Kind: f.Kind(), URL: f.URL(), Key: fmt.Sprintf("p/%s/seg-%06d", logID, n), Mode: "compliance", RetainUntil: at.Add(24 * time.Hour).Truncate(time.Second).UTC()}
}

func (f *fakeSink) Prepare(context.Context, SealSink) error {
	f.calls = append(f.calls, "Prepare")
	return f.prepareErr
}

func (f *fakeSink) Put(_ context.Context, s SealSink, data []byte, sha string) (PutReceipt, error) {
	f.calls = append(f.calls, "Put")
	f.putLoc, f.putData, f.putSHA = s, bytes.Clone(data), sha
	if f.putErr != nil {
		return PutReceipt{}, f.putErr
	}
	if f.objects == nil {
		f.objects = map[string][]byte{}
	}
	rcpt := PutReceipt{VersionID: "v-1", RetainUntil: s.RetainUntil}
	if have, ok := f.objects[s.Key]; ok {
		if !bytes.Equal(have, data) {
			return PutReceipt{}, fmt.Errorf("key %s is occupied by a version that is not this segment", s.Key)
		}
		rcpt.Existed = true
	} else {
		f.objects[s.Key] = bytes.Clone(data)
	}
	f.receipts = append(f.receipts, rcpt)
	if f.onPut != nil {
		f.onPut()
	}
	return rcpt, nil
}

func logIDOf(t *testing.T, p string) string {
	t.Helper()
	v, err := Read(p, ledger.Unlocked)
	if err != nil {
		t.Fatal(err)
	}
	id, err := GenesisLogID(v.Records)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func dirEntries(t *testing.T, p string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// sealBlockOf decodes the seal record that ends the sealed segment n.
func sealBlockOf(t *testing.T, v View, n int) (record, *SealSink) {
	t.Helper()
	end := 0
	for _, s := range v.Sealed[:n] {
		end += s.Records
	}
	rec, ok := decodeRecord(v.Records[end-1])
	if !ok || rec.Action != "seal" || rec.Seal == nil {
		t.Fatalf("segment %d does not end in a seal: %+v", n, rec)
	}
	return rec, rec.Seal.Sink
}

// TestSealActiveSinkSequence: Prepare runs BEFORE the link (a preflight
// failure is SealStepPreflight with no sibling, no record and the active
// unchanged); on success the calls are Prepare then Put, the seal record
// carries the sink's Locator for segment 1 (retain_until after the record's
// time), Put received the sealed file's exact bytes and the manifest's
// digest, and the result carries the receipt.
func TestSealActiveSinkSequence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 3)
	before, _ := os.ReadFile(p)
	f := &fakeSink{prepareErr: errors.New("bucket worm does not have Object Lock enabled")}
	_, err := SealActive(p, sealEvent(), f)
	var se *SealError
	if !errors.As(err, &se) || se.Step != SealStepPreflight || !strings.Contains(err.Error(), "Object Lock") {
		t.Fatalf("preflight: %v", err)
	}
	if strings.Join(f.calls, ",") != "Prepare" {
		t.Fatalf("calls %v", f.calls)
	}
	if after, _ := os.ReadFile(p); !bytes.Equal(before, after) || dirEntries(t, p) != 1 {
		t.Fatal("a refused preflight links and records nothing")
	}
	if err := Writable(p); err != nil {
		t.Fatalf("the root stays writable: %v", err)
	}

	f.prepareErr, f.calls = nil, nil
	start := time.Now().UTC().Truncate(time.Second)
	res, err := SealActive(p, sealEvent(), f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.calls, ",") != "Prepare,Put" {
		t.Fatalf("calls %v", f.calls)
	}
	v, err := Read(p, ledger.Locked)
	if err != nil || len(v.Sealed) != 1 || v.State != StateOpen {
		t.Fatalf("%v %+v", err, v)
	}
	rec, block := sealBlockOf(t, v, 1)
	if block == nil {
		t.Fatal("the seal record carries no sink block")
	}
	want := f.Locator(logIDOf(t, p), 1, start)
	if block.Kind != want.Kind || block.URL != want.URL || block.Key != want.Key || block.Mode != want.Mode {
		t.Fatalf("block %+v, want %+v", *block, want)
	}
	if block.RetainUntil.Before(want.RetainUntil) || !block.RetainUntil.After(rec.Time) {
		t.Fatalf("retain_until %s (record %s, locator from %s)", block.RetainUntil, rec.Time, start)
	}
	resolved, _ := filepath.EvalSymlinks(p)
	seg, _ := os.ReadFile(SegmentPath(resolved, 1))
	if !bytes.Equal(f.putData, seg) {
		t.Fatal("Put must receive the sealed file byte for byte")
	}
	if f.putSHA != v.Sealed[0].SHA256 || f.putLoc != *block {
		t.Fatalf("Put received sha %s loc %+v; manifest %s block %+v", f.putSHA, f.putLoc, v.Sealed[0].SHA256, *block)
	}
	if res.Sink == nil || *res.Sink != *block || res.VersionID != "v-1" || res.Existed || !res.RetainUntil.Equal(block.RetainUntil) || res.Completed {
		t.Fatalf("result %+v", res)
	}
	if v.Sealed[0].Sink == nil || *v.Sealed[0].Sink != *block {
		t.Fatalf("Read carries the block: %+v", v.Sealed[0].Sink)
	}
}

// TestSealActiveFloorIsUntouched: a nil sink is the shipped seal — no sink
// key on the record, the same payload, the same files.
func TestSealActiveFloorIsUntouched(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 3)
	before, _ := Read(p, ledger.Locked)
	res, err := SealActive(p, sealEvent(), nil)
	if err != nil || res.Sink != nil || res.VersionID != "" || !res.RetainUntil.IsZero() || res.Existed {
		t.Fatalf("%v %+v", err, res)
	}
	v, _ := Read(p, ledger.Locked)
	rec, block := sealBlockOf(t, v, 1)
	if block != nil || bytes.Contains(v.Records[3].Raw, []byte(`"sink"`)) {
		t.Fatalf("a floor seal carries no sink: %s", v.Records[3].Raw)
	}
	if *rec.Seal != (Seal{Segment: 1, FirstSeq: 1, HeadSeq: 3, HeadHash: before.Head.Hash, ContentSHA256: sealContentDigest(before.Records)}) {
		t.Fatalf("payload %+v", *rec.Seal)
	}
	if dirEntries(t, p) != 3 || v.Sealed[0].Sink != nil {
		t.Fatalf("layout: %d entries, sink %+v", dirEntries(t, p), v.Sealed[0].Sink)
	}
}

// TestRotatePutFailureLeavesStateB: a failed Put is SealStepSink and leaves
// state B — the block on the last record, no manifest, writers refuse; a
// re-run calls Put again and completes; a third run has nothing to complete.
func TestRotatePutFailureLeavesStateB(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 3)
	f := &fakeSink{putErr: errors.New("status 503 from sink.example (PutObject)")}
	_, err := SealActive(p, sealEvent(), f)
	var se *SealError
	if !errors.As(err, &se) || se.Step != SealStepSink || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("put failure: %v", err)
	}
	v, err := Read(p, ledger.Locked)
	if err != nil || v.State != StateSealedNotRotated || len(v.Sealed) != 0 {
		t.Fatalf("%v %+v", err, v)
	}
	last, _ := decodeRecord(v.Records[len(v.Records)-1])
	if last.Seal == nil || last.Seal.Sink == nil {
		t.Fatalf("the seal record carries the block: %+v", last.Seal)
	}
	if _, err := os.Stat(ManifestPath(p)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no manifest in state B: %v", err)
	}
	if err := Writable(p); !errors.Is(err, ErrSealed) {
		t.Fatalf("writers refuse: %v", err)
	}
	f.putErr = nil
	res, err := CompleteSeal(p, f)
	if err != nil || !res.Completed || res.Existed || res.Sink == nil || res.VersionID != "v-1" {
		t.Fatalf("%v %+v", err, res)
	}
	if strings.Join(f.calls, ",") != "Prepare,Put,Put" {
		t.Fatalf("calls %v", f.calls)
	}
	v, err = Read(p, ledger.Locked)
	if err != nil || v.State != StateOpen || len(v.Sealed) != 1 || v.Sealed[0].Sink == nil {
		t.Fatalf("%v %+v", err, v)
	}
	if _, err := CompleteSeal(p, f); !errors.Is(err, errNothingToComplete) {
		t.Fatalf("third run: %v", err)
	}
}

// TestCompleteSealConfirmsWithoutPut: state B with the copy confirmed (the
// hook after Put, before the manifest) → the re-run's Put finds the key
// holding the segment, answers Existed, and the result says so.
func TestCompleteSealConfirmsWithoutPut(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 3)
	f := &fakeSink{}
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "after_sink_before_manifest")
	_, err := SealActive(p, sealEvent(), f)
	t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
	var se *SealError
	if !errors.As(err, &se) || se.Step != SealStepManifest || !errors.Is(err, errStoppedByTestHook) {
		t.Fatalf("hook: %v", err)
	}
	if strings.Join(f.calls, ",") != "Prepare,Put" {
		t.Fatalf("calls %v", f.calls)
	}
	res, err := CompleteSeal(p, f)
	if err != nil || !res.Completed || !res.Existed || res.Sink == nil {
		t.Fatalf("%v %+v", err, res)
	}
	if strings.Join(f.calls, ",") != "Prepare,Put,Put" {
		t.Fatalf("calls %v", f.calls)
	}
}

// TestCrashHooksWithASink: each hook's step and the number of Put calls it
// leaves behind; the shipped after_seal_before_manifest still stops before
// Put; CompleteSeal completes every one.
func TestCrashHooksWithASink(t *testing.T) {
	for _, tc := range []struct {
		hook string
		step SealStep
		puts int
	}{
		{"after_seal_before_sink", SealStepSink, 0},
		{"after_sink_before_manifest", SealStepManifest, 1},
		{"after_seal_before_manifest", SealStepManifest, 0},
	} {
		t.Run(tc.hook, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "control.jsonl")
			appendN(t, p, 3)
			f := &fakeSink{}
			t.Setenv("AGENTHOF_TEST_CRASH_AT", tc.hook)
			_, err := SealActive(p, sealEvent(), f)
			t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
			var se *SealError
			if !errors.As(err, &se) || se.Step != tc.step || !errors.Is(err, errStoppedByTestHook) {
				t.Fatalf("hook %s: %v", tc.hook, err)
			}
			if got := strings.Count(strings.Join(f.calls, ","), "Put"); got != tc.puts {
				t.Fatalf("%d Put calls, want %d (%v)", got, tc.puts, f.calls)
			}
			v, err := Read(p, ledger.Locked)
			if err != nil || v.State != StateSealedNotRotated {
				t.Fatalf("%v state %d", err, v.State)
			}
			res, err := CompleteSeal(p, f)
			if err != nil || !res.Completed || res.Sink == nil {
				t.Fatalf("completion: %v %+v", err, res)
			}
			if got := strings.Count(strings.Join(f.calls, ","), "Put"); got != tc.puts+1 {
				t.Fatalf("completion calls Put once: %v", f.calls)
			}
			v, err = Read(p, ledger.Locked)
			if err != nil || v.State != StateOpen || len(v.Sealed) != 1 || v.Sealed[0].Sink == nil {
				t.Fatalf("after completion: %v %+v", err, v)
			}
		})
	}
}

// TestRotateStateCNeverCallsTheSink: the manifest's listing is the
// confirmation; a swap-only completion makes no sink call.
func TestRotateStateCNeverCallsTheSink(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 3)
	sealByHand(t, p, "C")
	f := &fakeSink{}
	res, err := CompleteSeal(p, f)
	if err != nil || !res.Completed || res.Sink != nil || len(f.calls) != 0 {
		t.Fatalf("%v %+v calls %v", err, res, f.calls)
	}
}

const postureChangedText = "segment 1 was sealed for a protected copy at s3-object-lock https://sink.example/bucket/p; integrity.yaml no longer names it — restore that posture to complete the rotation"

// TestRotatePostureChanged: a record with a block completes only
// through the sink it names — a nil sink or another URL is refused and
// state B stands; a record without a block completes without an upload
// whatever the posture now says.
func TestRotatePostureChanged(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 3)
	f := &fakeSink{}
	block := f.Locator(logIDOf(t, p), 1, time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC))
	sealByHand(t, p, "B", &block)
	for name, sink := range map[string]SinkWriter{"nil": nil, "other url": &fakeSink{url: "https://other.example/bucket"}} {
		_, err := CompleteSeal(p, sink)
		var se *SealError
		if !errors.As(err, &se) || se.Step != SealStepSink || err.Error() != postureChangedText {
			t.Fatalf("%s: %v", name, err)
		}
		if v, err := Read(p, ledger.Locked); err != nil || v.State != StateSealedNotRotated {
			t.Fatalf("%s: state B stands: %v %d", name, err, v.State)
		}
	}
	if res, err := CompleteSeal(p, f); err != nil || !res.Completed || res.Sink == nil || strings.Join(f.calls, ",") != "Put" {
		t.Fatalf("the named sink completes: %v %+v %v", err, res, f.calls)
	}

	q := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, q, 3)
	sealByHand(t, q, "B")
	g := &fakeSink{}
	res, err := CompleteSeal(q, g)
	if err != nil || !res.Completed || res.Sink != nil || len(g.calls) != 0 {
		t.Fatalf("no block: %v %+v calls %v", err, res, g.calls)
	}
	if v, err := Read(q, ledger.Locked); err != nil || v.State != StateOpen || v.Sealed[0].Sink != nil {
		t.Fatalf("%v %+v", err, v)
	}

	// The record's kind and URL come from the ledger, which a hand can
	// write: a control character in them never reaches the refusal's text.
	r := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, r, 3)
	escaped := f.Locator(logIDOf(t, r), 1, time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC))
	escaped.Kind = "s3-object-lock\x1b[2J"
	sealByHand(t, r, "B", &escaped)
	_, err = CompleteSeal(r, f)
	if err == nil || strings.Contains(err.Error(), "\x1b") || !strings.Contains(err.Error(), "at s3-object-lock[2J https://sink.example/bucket/p;") {
		t.Fatalf("the refusal is cleaned for the terminal: %q", err)
	}
}

// TestRotateRefusesARecordNamingAnotherKey (the key): the chain fixes
// a seal's five chain fields and carries its sink block as recorded, so a
// correctly chained seal line written by hand can name any key — another
// ledger's seg-000001 in a shared bucket. A block completes only through
// the key the sink derives for THIS ledger's segment: a record naming
// another is refused with no Put and state B standing, and the repair
// refuses it before its truncate with nothing changed.
func TestRotateRefusesARecordNamingAnotherKey(t *testing.T) {
	const other = "ffffffffffffffffffffffffffffffff"
	at := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	t.Run("completion", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "control.jsonl")
		appendN(t, p, 3)
		f := &fakeSink{}
		id := logIDOf(t, p)
		block := f.Locator(id, 1, at)
		block.Key = "p/" + other + "/seg-000001"
		sealByHand(t, p, "B", &block)
		_, err := CompleteSeal(p, f)
		var se *SealError
		want := "segment 1 was sealed for a protected copy at key p/" + other + "/seg-000001; the sink derives p/" + id + "/seg-000001 for this ledger's segment 1 — the record does not name this ledger's own copy; run audit verify control"
		if !errors.As(err, &se) || se.Step != SealStepSink || err.Error() != want {
			t.Fatalf("%v", err)
		}
		if len(f.calls) != 0 {
			t.Fatalf("the sink was called: %v", f.calls)
		}
		if v, err := Read(p, ledger.Locked); err != nil || v.State != StateSealedNotRotated {
			t.Fatalf("state B stands: %v %d", err, v.State)
		}
	})
	t.Run("repair", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "control.jsonl")
		appendN(t, p, 3)
		f := &fakeSink{}
		id := logIDOf(t, p)
		block := f.Locator(id, 1, at)
		block.Key = "p/" + other + "/seg-000001"
		line := sealByHand(t, p, "B", &block)
		appendRaw(t, p, hashOf(line), 5, 6)
		before, _ := os.ReadFile(p)
		dir := snapshotDir(t, filepath.Dir(p))
		_, err := Repair(p, repairOp, "", repairWitness, f)
		want := "control: ledger " + p + ": segment was sealed for a protected copy at key p/" + other + "/seg-000001; the sink derives p/" + id + "/seg-000001 for this ledger's segment 1 — the record does not name this ledger's own copy; run audit verify control"
		if err == nil || err.Error() != want {
			t.Fatalf("%v", err)
		}
		if len(f.calls) != 0 {
			t.Fatalf("the sink was called: %v", f.calls)
		}
		stillTorn(t, p, before)
		if snapshotDir(t, filepath.Dir(p)) != dir {
			t.Fatal("a refusal changes nothing on disk")
		}
	})
}

// tornWormRoot is the one post-seal shape a repair completes, on a worm
// root: three records, a seal by hand carrying f's block for segment 1
// (state B), and two records an older writer appended after the seal line.
// It returns the path, the block, and the sealed segment's exact bytes —
// the file through the seal line — which is what the protected copy holds.
func tornWormRoot(t *testing.T, f *fakeSink) (p string, block SealSink, sealed []byte) {
	t.Helper()
	p = filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 3)
	block = f.Locator(logIDOf(t, p), 1, time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC))
	line := sealByHand(t, p, "B", &block)
	sealed, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	appendRaw(t, p, hashOf(line), 5, 6)
	return p, block, sealed
}

// stillTorn asserts p reads as the post-seal fault it started with — nothing
// repaired, no taint — and that its bytes are exactly before.
func stillTorn(t *testing.T, p string, before []byte) {
	t.Helper()
	v, err := Read(p, ledger.Locked)
	var se *SetError
	if !errors.As(err, &se) || se.Fault != FaultSealNotLast || se.Segment != 0 {
		t.Fatalf("the ledger stays torn: %v", err)
	}
	if tainted, _ := IsTainted(v.Records); tainted {
		t.Fatal("no repair record was appended")
	}
	if after, _ := os.ReadFile(p); !bytes.Equal(before, after) {
		t.Fatal("the active changed")
	}
	if frags, _ := filepath.Glob(p + ".torn-*"); len(frags) != 0 {
		t.Fatalf("a fragment was written: %v", frags)
	}
}

// repairedWorm asserts a completed post-seal repair on a worm root: segment 1
// sealed with its block, the repair record the new active's first (seq 5,
// prev the seal line's hash), the taint on the chain.
func repairedWorm(t *testing.T, p string, block SealSink) {
	t.Helper()
	v, err := Read(p, ledger.Locked)
	if err != nil || v.State != StateOpen || len(v.Sealed) != 1 || v.Sealed[0].Sink == nil || *v.Sealed[0].Sink != block || v.Active.Records != 1 {
		t.Fatalf("%v %+v", err, v)
	}
	rep, _ := decodeRecord(v.Records[4])
	if rep.Action != "repair" || rep.Seq != 5 || rep.Prev != v.Sealed[0].HeadHash {
		t.Fatalf("the repair record opens the next segment: %+v", rep)
	}
	if tainted, seq := IsTainted(v.Records); !tainted || seq != 5 {
		t.Fatalf("taint %v at %d", tainted, seq)
	}
}

var repairOp, repairWitness = identity.Static("ops@example.com"), Witness{OSUser: "ops", Hostname: "host"}

// TestRepairPassesTheSink: the post-seal repair hands the root's sink its
// one Put (no Prepare: the record exists) and completes through it.
func TestRepairPassesTheSink(t *testing.T) {
	f := &fakeSink{}
	p, block, _ := tornWormRoot(t, f)
	res, err := Repair(p, repairOp, "", repairWitness, f)
	if err != nil || res.CompletedSegment != 1 || strings.Join(f.calls, ",") != "Put" {
		t.Fatalf("%v %+v calls %v", err, res, f.calls)
	}
	repairedWorm(t, p, block)
}

// TestRepairPostSealConfirmsCopyBeforeTruncate: the protected copy is the
// repair's one fallible network step, and it runs BEFORE the destructive
// truncate — a sink that cannot confirm it fails the repair with nothing
// changed: no fragment, the active byte for byte as it was, the ledger still
// reporting its torn fault, no repair record. The operator retries whole.
func TestRepairPostSealConfirmsCopyBeforeTruncate(t *testing.T) {
	f := &fakeSink{putErr: errors.New("status 503 from sink.example (PutObject)")}
	p, _, _ := tornWormRoot(t, f)
	before, _ := os.ReadFile(p)
	dir := snapshotDir(t, filepath.Dir(p))
	_, err := Repair(p, repairOp, "", repairWitness, f)
	if err == nil || !strings.Contains(err.Error(), "the protected copy could not be confirmed; nothing was changed — retry when the sink is reachable: status 503 from sink.example (PutObject)") {
		t.Fatalf("%v", err)
	}
	if strings.Join(f.calls, ",") != "Put" {
		t.Fatalf("calls %v", f.calls)
	}
	stillTorn(t, p, before)
	if snapshotDir(t, filepath.Dir(p)) != dir {
		t.Fatal("a refused repair changes nothing on disk")
	}
}

// TestRepairPostSealTaintLandsWhenSinkHealthy: a healthy sink → the copy is
// confirmed with the sealed segment's exact bytes, digest and the record's
// own block; the rotation completes; the repair record is the new segment's
// first and the taint is on the chain. (The CLI's exit 3 and TAINTED line
// for this shape are pinned in cmd/agenthof.)
func TestRepairPostSealTaintLandsWhenSinkHealthy(t *testing.T) {
	f := &fakeSink{}
	p, block, sealed := tornWormRoot(t, f)
	res, err := Repair(p, repairOp, "", repairWitness, f)
	if err != nil || res.CompletedSegment != 1 || res.FragmentLen == 0 {
		t.Fatalf("%v %+v", err, res)
	}
	sum := sha256.Sum256(sealed)
	if f.putLoc != block || !bytes.Equal(f.putData, sealed) || f.putSHA != hex.EncodeToString(sum[:]) {
		t.Fatalf("Put received loc %+v sha %s (%d bytes); want the record's block and the sealed file", f.putLoc, f.putSHA, len(f.putData))
	}
	if len(f.receipts) != 1 || f.receipts[0].Existed {
		t.Fatalf("receipts %+v", f.receipts)
	}
	repairedWorm(t, p, block)
	if seg, _ := os.ReadFile(SegmentPath(p, 1)); !bytes.Equal(seg, sealed) {
		t.Fatal("the sealed segment is the bytes the copy holds")
	}
}

// TestRepairPostSealNoSinkCallAfterTruncate proves the receipt threading:
// the sink goes away the moment the pre-confirmed Put returns, and the
// repair still completes — the rotation consumed the confirmation and made
// no sink call of its own after the truncate. One Put, nothing after it.
func TestRepairPostSealNoSinkCallAfterTruncate(t *testing.T) {
	f := &fakeSink{}
	down := errors.New("sink unreachable after the copy was confirmed")
	f.onPut = func() { f.putErr, f.prepareErr = down, down }
	p, block, _ := tornWormRoot(t, f)
	res, err := Repair(p, repairOp, "", repairWitness, f)
	if err != nil || res.CompletedSegment != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	if strings.Join(f.calls, ",") != "Put" {
		t.Fatalf("the rotation called the sink after the truncate: %v", f.calls)
	}
	repairedWorm(t, p, block)
}

// TestRepairPostSealReputAfterMoveAsideRefusalTakesExisted is the hazard
// proof for a copy committed to a write-once key before the local commit:
// the pre-Put succeeds, the truncate refuses (another holder on the active's
// lock; the active changed under the repair), nothing local changes, and the
// operator's retry re-Puts the SAME bytes — the key's copy is Existed, never
// occupied — and completes with the taint on the chain.
func TestRepairPostSealReputAfterMoveAsideRefusalTakesExisted(t *testing.T) {
	for name, tc := range map[string]struct {
		refuse  func(t *testing.T, f *fakeSink, p string) (undo func())
		wantErr func(err error) bool
	}{
		"busy": {
			refuse: func(t *testing.T, f *fakeSink, p string) func() {
				var holder *os.File
				f.onPut = func() {
					h, err := os.OpenFile(p, os.O_RDWR, 0)
					if err != nil {
						t.Fatal(err)
					}
					if err := ledger.LockExclusive(h); err != nil {
						t.Fatal(err)
					}
					holder = h
				}
				return func() {
					ledger.Unlock(holder)
					_ = holder.Close()
				}
			},
			wantErr: func(err error) bool { return errors.Is(err, ledger.ErrLockHeld) },
		},
		"changed": {
			refuse: func(t *testing.T, f *fakeSink, p string) func() {
				raw, _ := os.ReadFile(p)
				f.onPut = func() {
					if err := os.WriteFile(p, append([]byte("\n"), raw...), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return func() { _ = os.WriteFile(p, raw, 0o600) }
			},
			wantErr: func(err error) bool {
				return err != nil && strings.Contains(err.Error(), "changed while it was being repaired")
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeSink{}
			p, block, sealed := tornWormRoot(t, f)
			undo := tc.refuse(t, f, p)
			_, err := Repair(p, repairOp, "", repairWitness, f)
			undo()
			if !tc.wantErr(err) {
				t.Fatalf("%v", err)
			}
			if strings.Join(f.calls, ",") != "Put" || !bytes.Equal(f.objects[block.Key], sealed) {
				t.Fatalf("the copy was confirmed before the refusal: calls %v", f.calls)
			}
			if frags, _ := filepath.Glob(p + ".torn-*"); len(frags) != 0 {
				t.Fatalf("a refused truncate writes no fragment: %v", frags)
			}
			f.onPut = nil
			res, err := Repair(p, repairOp, "", repairWitness, f)
			if err != nil || res.CompletedSegment != 1 {
				t.Fatalf("retry: %v %+v", err, res)
			}
			if strings.Join(f.calls, ",") != "Put,Put" || len(f.receipts) != 2 || f.receipts[0].Existed || !f.receipts[1].Existed {
				t.Fatalf("the retry takes the Existed path: calls %v receipts %+v", f.calls, f.receipts)
			}
			if len(f.objects) != 1 || !bytes.Equal(f.objects[block.Key], sealed) {
				t.Fatal("the key holds the one copy, unchanged")
			}
			repairedWorm(t, p, block)
		})
	}
}

// TestRepairPostSealFloorUnchanged is the regression guard: a post-seal
// repair whose seal record carries no sink block makes no sink call whatever
// posture is handed in, and a torn-tail repair (no seal) makes none either;
// the taint lands as before.
func TestRepairPostSealFloorUnchanged(t *testing.T) {
	for name, sink := range map[string]*fakeSink{"worm posture": {}, "floor": nil} {
		t.Run("no block, "+name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "control.jsonl")
			appendN(t, p, 3)
			line := sealByHand(t, p, "B")
			appendRaw(t, p, hashOf(line), 5, 6)
			var w SinkWriter
			if sink != nil {
				w = sink
			}
			res, err := Repair(p, repairOp, "", repairWitness, w)
			if err != nil || res.CompletedSegment != 1 {
				t.Fatalf("%v %+v", err, res)
			}
			if sink != nil && len(sink.calls) != 0 {
				t.Fatalf("a record without a block makes no sink call: %v", sink.calls)
			}
			v, err := Read(p, ledger.Locked)
			if err != nil || v.State != StateOpen || len(v.Sealed) != 1 || v.Sealed[0].Sink != nil || v.Active.Records != 1 {
				t.Fatalf("%v %+v", err, v)
			}
			if tainted, seq := IsTainted(v.Records); !tainted || seq != 5 {
				t.Fatalf("taint %v at %d", tainted, seq)
			}
		})
	}
	t.Run("torn tail", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "control.jsonl")
		appendN(t, p, 3)
		tear(t, p, 4)
		f := &fakeSink{}
		res, err := Repair(p, repairOp, "", repairWitness, f)
		if err != nil || res.CompletedSegment != 0 || len(f.calls) != 0 {
			t.Fatalf("%v %+v calls %v", err, res, f.calls)
		}
		v, err := Read(p, ledger.Locked)
		if err != nil {
			t.Fatal(err)
		}
		if tainted, seq := IsTainted(v.Records); !tainted || seq != 4 {
			t.Fatalf("taint %v at %d", tainted, seq)
		}
	})
}

// TestRepairPostSealRefusesFlippedPostureBeforeTruncate (from the
// repair): the record names a protected copy; a posture that no longer does
// — nil, another kind, another URL — is refused BEFORE the truncate, with no
// sink call, no fragment, the active byte for byte as it was.
func TestRepairPostSealRefusesFlippedPostureBeforeTruncate(t *testing.T) {
	for name, sink := range map[string]*fakeSink{"nil": nil, "other kind": {kind: "other-kind"}, "other url": {url: "https://other.example/bucket"}} {
		t.Run(name, func(t *testing.T) {
			p, _, _ := tornWormRoot(t, &fakeSink{})
			before, _ := os.ReadFile(p)
			dir := snapshotDir(t, filepath.Dir(p))
			var w SinkWriter
			if sink != nil {
				w = sink
			}
			_, err := Repair(p, repairOp, "", repairWitness, w)
			if err == nil || !strings.Contains(err.Error(), "segment was sealed for a protected copy at s3-object-lock https://sink.example/bucket/p; integrity.yaml no longer names it — restore that posture to repair") {
				t.Fatalf("%v", err)
			}
			if sink != nil && len(sink.calls) != 0 {
				t.Fatalf("calls %v", sink.calls)
			}
			stillTorn(t, p, before)
			if snapshotDir(t, filepath.Dir(p)) != dir {
				t.Fatal("a refusal changes nothing on disk")
			}
		})
	}
}
