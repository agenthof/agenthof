package control

import (
	"bytes"
	"context"
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

// fakeSink records calls and fails on command. The oldest-version
// idempotency lives inside a real Put; the fake only answers Existed.
type fakeSink struct {
	url                string // "" → the default
	calls              []string
	prepareErr, putErr error
	putData            []byte
	putSHA             string
	putLoc             SealSink
	existed            bool
}

func (f *fakeSink) Kind() string { return "s3-object-lock" }

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
	return PutReceipt{VersionID: "v-1", RetainUntil: s.RetainUntil, Existed: f.existed}, nil
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
// hook after Put, before the manifest) → the re-run's Put answers Existed
// and the result says so.
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
	f.existed = true
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

// TestRotatePostureChanged (§8.5): a record with a block completes only
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
}

// TestRepairPassesTheSink: the post-seal repair uploads before it rotates
// (no Prepare: the record exists); handed nil against a record with a
// block, it refuses to rotate and state B stands.
func TestRepairPassesTheSink(t *testing.T) {
	fixture := func(t *testing.T) (string, *fakeSink) {
		p := filepath.Join(t.TempDir(), "control.jsonl")
		appendN(t, p, 3)
		f := &fakeSink{}
		block := f.Locator(logIDOf(t, p), 1, time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC))
		line := sealByHand(t, p, "B", &block)
		appendRaw(t, p, hashOf(line), 5, 6)
		return p, f
	}
	op, w := identity.Static("ops@example.com"), Witness{OSUser: "ops", Hostname: "host"}
	p, f := fixture(t)
	res, err := Repair(p, op, "", w, f)
	if err != nil || res.CompletedSegment != 1 || strings.Join(f.calls, ",") != "Put" {
		t.Fatalf("%v %+v calls %v", err, res, f.calls)
	}
	v, err := Read(p, ledger.Locked)
	if err != nil || v.State != StateOpen || len(v.Sealed) != 1 || v.Sealed[0].Sink == nil {
		t.Fatalf("%v %+v", err, v)
	}

	q, _ := fixture(t)
	_, err = Repair(q, op, "", w, nil)
	if err == nil || !strings.Contains(err.Error(), "completing the rotation failed: "+postureChangedText) {
		t.Fatalf("nil sink: %v", err)
	}
	if v, err := Read(q, ledger.Locked); err != nil || v.State != StateSealedNotRotated {
		t.Fatalf("state B stands: %v %d", err, v.State)
	}
}
