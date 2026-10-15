package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

func sealEvent() Event {
	return Event{Action: "seal", Outcome: "success", Invoker: identity.Static("dana@example.com"), Witness: Witness{OSUser: "dana", Hostname: "host"}}
}

// TestSealActiveRotates: five records → sealed segment 1 whose bytes are the
// old active plus the seal line; the seal record's payload names segment 1,
// seq 1..5, the fifth record's hash and the content hash of the old bytes;
// the manifest's one entry recomputes; the active is empty; Read verifies;
// the result's head is the seal record (seq 6).
func TestSealActiveRotates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 5)
	old, _ := os.ReadFile(p)
	oldSum := sha256.Sum256(old)
	before, _ := Read(p, ledger.Locked)
	res, err := SealActive(p, sealEvent())
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(p) // the segment lives beside the real file (t.TempDir is a symlink on Darwin)
	if res.Segment != 1 || res.FirstSeq != 1 || res.HeadSeq != 6 || res.Completed || res.Path != SegmentPath(resolved, 1) {
		t.Fatalf("%+v", res)
	}
	seg, _ := os.ReadFile(SegmentPath(p, 1))
	if !bytes.HasPrefix(seg, old) || bytes.Count(seg, []byte("\n")) != 6 {
		t.Fatal("the sealed file is the old active plus the seal line")
	}
	sealLine := bytes.TrimSuffix(seg[len(old):], []byte("\n"))
	rec, _ := decodeRecord(ledger.Record{Raw: sealLine})
	if rec.Action != "seal" || rec.Outcome != "success" || rec.Seq != 6 || rec.Seal == nil || *rec.Seal != (Seal{Segment: 1, FirstSeq: 1, HeadSeq: 5, HeadHash: before.Head.Hash, ContentSHA256: hex.EncodeToString(oldSum[:])}) || rec.Prev != before.Head.Hash || rec.LogID != "" {
		t.Fatalf("seal record: %+v", rec)
	}
	if res.HeadHash != hashOf(sealLine) {
		t.Fatal("the head is the seal record")
	}
	info, _ := os.Stat(p)
	if info.Size() != 0 {
		t.Fatal("the active must be empty")
	}
	v, err := Read(p, ledger.Locked)
	if err != nil || len(v.Sealed) != 1 || v.Head.Count != 6 || v.Head.Hash != res.HeadHash || v.Active.FirstSeq != 7 || v.State != StateOpen {
		t.Fatalf("%v %+v", err, v)
	}
	if v.Sealed[0].SHA256 != res.SHA256 {
		t.Fatal("the manifest's sha256 is the result's")
	}
	// A second seal chains from the first; log_id is not minted again.
	appendN(t, p, 2)
	res2, err := SealActive(p, sealEvent())
	if err != nil || res2.Segment != 2 || res2.FirstSeq != 7 || res2.HeadSeq != 9 {
		t.Fatalf("second seal: %v %+v", err, res2)
	}
	v, _ = Read(p, ledger.Locked)
	first, _ := decodeRecord(v.Records[6])
	if first.LogID != "" || first.Prev != v.Sealed[0].HeadHash {
		t.Fatalf("segment 2's first record: %+v", first)
	}
	if id, err := GenesisLogID(v.Records); err != nil || id != v.LogID {
		t.Fatalf("identity: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 4 { // control.jsonl, .seg-000001, .seg-000002, .segments
		t.Fatalf("%v", entries)
	}
}

// TestSealActiveRefusals: an empty active (fresh and rotated) is
// ErrNothingToSeal, unrecorded; a filesystem that cannot link fails before
// anything is recorded (no sibling, no manifest, active unchanged); state B
// and C are ErrSealed; a foreign file under the next segment's name is
// FaultUnexpectedSegment with nothing recorded.
func TestSealActiveRefusals(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 0)
	if _, err := os.Create(p); err != nil {
		t.Fatal(err)
	}
	if _, err := SealActive(p, sealEvent()); !errors.Is(err, ErrNothingToSeal) {
		t.Fatalf("empty: %v", err)
	}
	appendN(t, p, 2)
	orig := linkFile
	defer func() { linkFile = orig }()
	linkFile = func(string, string) error { return &os.LinkError{Op: "link", Err: syscall.EPERM} }
	before, _ := os.ReadFile(p)
	_, err := SealActive(p, sealEvent())
	linkFile = orig
	var se *SealError
	if !errors.Is(err, ErrNoHardLinks) || !errors.As(err, &se) || se.Step != SealStepLink {
		t.Fatalf("no hard links: %v", err)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("nothing may be recorded when the link fails")
	}
	if entries, _ := os.ReadDir(filepath.Dir(p)); len(entries) != 1 {
		t.Fatalf("no sibling, no manifest: %v", entries)
	}
	if err := os.WriteFile(SegmentPath(p, 1), []byte("foreign\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = SealActive(p, sealEvent())
	var set *SetError
	if !errors.As(err, &set) || set.Fault != FaultUnexpectedSegment {
		t.Fatalf("foreign file: %v", err)
	}
	_ = os.Remove(SegmentPath(p, 1))
	for _, stop := range []string{"B", "C"} {
		q := filepath.Join(t.TempDir(), "control.jsonl")
		appendN(t, q, 3)
		sealByHand(t, q, stop)
		if _, err := SealActive(q, sealEvent()); !errors.Is(err, ErrSealed) {
			t.Fatalf("%s: %v", stop, err)
		}
	}
	q := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, q, 3)
	sealByHand(t, q, "")
	if _, err := SealActive(q, sealEvent()); !errors.Is(err, ErrNothingToSeal) {
		t.Fatalf("empty rotated active: %v", err)
	}
}

// TestSealCrashHooksAndCompletion: each hook leaves its state; Read reads
// it; the next SealActive (A′) or CompleteSeal (B, C) ends in the layout an
// uninterrupted seal leaves; stale temps are swept by the completion.
func TestSealCrashHooksAndCompletion(t *testing.T) {
	for _, tc := range []struct {
		hook  string
		state State
		step  SealStep
	}{
		{"after_link_before_seal", StateOpen, SealStepRecord},
		{"after_seal_before_manifest", StateSealedNotRotated, SealStepManifest},
		{"after_manifest_before_swap", StateRotatedNotSwapped, SealStepSwap},
	} {
		t.Run(tc.hook, func(t *testing.T) {
			for _, first := range []bool{true, false} {
				p := filepath.Join(t.TempDir(), "control.jsonl")
				appendN(t, p, 3)
				if !first {
					sealByHand(t, p, "")
					appendN(t, p, 2)
				}
				t.Setenv("AGENTHOF_TEST_CRASH_AT", tc.hook)
				_, err := SealActive(p, sealEvent())
				t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
				var se *SealError
				if !errors.As(err, &se) || se.Step != tc.step || !errors.Is(err, errStoppedByTestHook) {
					t.Fatalf("hook %s: %v", tc.hook, err)
				}
				v, err := Read(p, ledger.Locked)
				if err != nil || v.State != tc.state {
					t.Fatalf("after %s: %v state %d", tc.hook, err, v.State)
				}
				_ = os.WriteFile(filepath.Join(filepath.Dir(p), "control.jsonl.segments-stale"), []byte("x"), 0o600)
				_ = os.WriteFile(filepath.Join(filepath.Dir(p), ".control.jsonl.next-stale"), []byte("x"), 0o600)
				var res SealResult
				if tc.state == StateOpen {
					res, err = SealActive(p, sealEvent()) // reuses the link: EEXIST ∧ SameFile
				} else {
					res, err = CompleteSeal(p)
					if err == nil && !res.Completed {
						t.Fatal("a completion says so")
					}
				}
				if err != nil {
					t.Fatalf("completion after %s: %v", tc.hook, err)
				}
				v, err = Read(p, ledger.Locked)
				if err != nil || v.State != StateOpen || v.Active.Records != 0 || len(v.Sealed) != res.Segment {
					t.Fatalf("after completion: %v %+v", err, v)
				}
				for _, stale := range []string{"control.jsonl.segments-stale", ".control.jsonl.next-stale"} {
					if _, err := os.Stat(filepath.Join(filepath.Dir(p), stale)); err == nil {
						t.Fatalf("%s must be swept", stale)
					}
				}
			}
		})
	}
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 1)
	if _, err := CompleteSeal(p); err == nil || !strings.Contains(err.Error(), "nothing to complete") {
		t.Fatalf("CompleteSeal on an open active: %v", err)
	}
}

// TestSealPermit: a planted seal payload on an apply; a success seal without
// a payload; a refused seal with one; head_hash ≠ prev; segment ≠ N+1;
// content_sha256 wrong — each refused before any write (file size
// unchanged). A correct payload through Append is admitted (it produces
// state B, which CompleteSeal finishes).
func TestSealPermit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 3)
	v, _ := Read(p, ledger.Locked)
	content := sealContentDigest(v.Records)
	good := Seal{Segment: 1, FirstSeq: 1, HeadSeq: 3, HeadHash: v.Head.Hash, ContentSHA256: content}
	inv, w := identity.Static("d"), Witness{}
	size := func() int64 { i, _ := os.Stat(p); return i.Size() }
	before := size()
	bad := []struct {
		name string
		e    Event
		want string
	}{
		{"on an apply", Event{Action: "apply", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:x", Seal: &good}, "seal payload on a \"apply\" record"},
		{"success without payload", Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: w}, "a successful seal must say what it closes"},
		{"refused with payload", Event{Action: "seal", Outcome: "refused", Reason: NotAuthorized("seal"), Invoker: inv, Witness: w, Seal: &good}, "a refused seal closed nothing"},
		{"config_hash", Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: w, ConfigHash: "sha256:x", Seal: &good}, "a seal installs nothing"},
		{"head_hash", Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: w, Seal: &Seal{Segment: 1, FirstSeq: 1, HeadSeq: 3, HeadHash: strings.Repeat("0", 64), ContentSHA256: content}}, "head_hash"},
		{"first_seq", Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: w, Seal: &Seal{Segment: 1, FirstSeq: 2, HeadSeq: 3, HeadHash: v.Head.Hash, ContentSHA256: content}}, "first_seq"},
		{"head_seq", Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: w, Seal: &Seal{Segment: 1, FirstSeq: 1, HeadSeq: 2, HeadHash: v.Head.Hash, ContentSHA256: content}}, "head_seq"},
		{"segment", Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: w, Seal: &Seal{Segment: 2, FirstSeq: 1, HeadSeq: 3, HeadHash: v.Head.Hash, ContentSHA256: content}}, "segment 2"},
		{"content", Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: w, Seal: &Seal{Segment: 1, FirstSeq: 1, HeadSeq: 3, HeadHash: v.Head.Hash, ContentSHA256: strings.Repeat("0", 64)}}, "content_sha256"},
		{"not hex", Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: w, Seal: &Seal{Segment: 1, FirstSeq: 1, HeadSeq: 3, HeadHash: "zz", ContentSHA256: content}}, "lowercase hex"},
	}
	for _, c := range bad {
		if _, err := Append(p, c.e); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v (want %q)", c.name, err, c.want)
		}
		if size() != before {
			t.Fatalf("%s: a refused seal must write nothing", c.name)
		}
	}
	if _, err := Append(p, Event{Action: "seal", Outcome: "refused", Reason: NotAuthorized("seal"), Invoker: inv, Witness: w}); err != nil {
		t.Fatalf("a refused seal without payload is an ordinary record: %v", err)
	}
	v, _ = Read(p, ledger.Locked)
	content = sealContentDigest(v.Records)
	if _, err := Append(p, Event{Action: "seal", Outcome: "success", Invoker: inv, Witness: w, Seal: &Seal{Segment: 1, FirstSeq: 1, HeadSeq: 4, HeadHash: v.Head.Hash, ContentSHA256: content}}); err != nil {
		t.Fatalf("a correct payload is admitted: %v", err)
	}
	if v, _ := Read(p, ledger.Locked); v.State != StateSealedNotRotated {
		t.Fatal("a seal record written through Append is state B")
	}
	if _, err := CompleteSeal(p); err != nil {
		t.Fatal(err)
	}
	// Installing never accepts a seal.
	v, _ = Read(p, ledger.Locked)
	last, _ := decodeRecord(v.Records[len(v.Records)-1])
	if Installing(DecodedEvent{Action: last.Action, Outcome: last.Outcome, ConfigHash: last.ConfigHash}) {
		t.Fatal("a seal is not an install")
	}
}

// TestSealActiveHoldsOneChain: a reader holding LOCK_SH on the active makes
// SealActive busy at its openActive with nothing recorded; a seal never calls
// Append (the record is written on the chain it holds — exactly one append).
func TestSealActiveHoldsOneChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 2)
	f, _ := os.Open(p)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err := SealActive(p, sealEvent())
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
	if !errors.Is(err, ledger.ErrLockHeld) || time.Since(start) < 4*time.Second {
		t.Fatalf("busy: %v after %v", err, time.Since(start))
	}
	v, _ := Read(p, ledger.Locked)
	if len(v.Records) != 2 || len(v.Sealed) != 0 {
		t.Fatal("nothing recorded while busy")
	}
}

// genesisWithoutLogID writes a root older than the genesis log_id: a hand
// genesis without one, then n records through Append (which mints a log_id
// on the genesis only, so the root stays without one).
func genesisWithoutLogID(t *testing.T, p string, n int) {
	t.Helper()
	c, err := ledger.Open(p, ledger.Locked)
	if err != nil {
		t.Fatal(err)
	}
	line := `{"v":"control/1","seq":1,"time":"2026-10-09T02:12:01Z","action":"apply","outcome":"success","invoker":{"subject":"dana@example.com","issuer":"local","method":"asserted"},"witness":{"os_user":"dana","hostname":"h"},"config_hash":"sha256:abc","prev":""}`
	if err := c.Append([]byte(line)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	appendN(t, p, n)
}

// TestSealRefusesGenesisWithoutLogID: a root whose genesis carries no log_id
// cannot be rotated (the manifest requires one), so every path that commits
// toward a rotation refuses BEFORE touching the disk: SealActive links and
// records nothing and the root stays writable; Append refuses a correct seal
// payload the same way; Repair on a seal with records after it (the
// older-binary shape) truncates nothing and writes no fragment. The message
// names no re-run.
func TestSealRefusesGenesisWithoutLogID(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	genesisWithoutLogID(t, p, 2)
	before, _ := os.ReadFile(p)
	_, err := SealActive(p, sealEvent())
	if !errors.Is(err, ErrUnsealable) || strings.Contains(err.Error(), "re-run") {
		t.Fatalf("SealActive: %v", err)
	}
	if after, _ := os.ReadFile(p); !bytes.Equal(before, after) {
		t.Fatal("nothing may be recorded")
	}
	if entries, _ := os.ReadDir(filepath.Dir(p)); len(entries) != 1 {
		t.Fatalf("nothing linked, no manifest: %v", entries)
	}
	if err := Writable(p); err != nil {
		t.Fatalf("the root stays writable: %v", err)
	}
	appendN(t, p, 1)
	v, _ := Read(p, ledger.Locked)
	size := func() int64 { i, _ := os.Stat(p); return i.Size() }
	was := size()
	_, err = Append(p, Event{Action: "seal", Outcome: "success", Invoker: identity.Static("d"), Seal: &Seal{Segment: 1, FirstSeq: 1, HeadSeq: 4, HeadHash: v.Head.Hash, ContentSHA256: sealContentDigest(v.Records)}})
	if !errors.Is(err, ErrUnsealable) || size() != was {
		t.Fatalf("Append with a correct payload: %v (size %d → %d)", err, was, size())
	}
	q := filepath.Join(t.TempDir(), "control.jsonl")
	genesisWithoutLogID(t, q, 2)
	line := sealByHand(t, q, "B")
	appendRaw(t, q, hashOf(line), 5)
	raw, _ := os.ReadFile(q)
	if _, err := repairIt(t, q); !errors.Is(err, ErrUnsealable) {
		t.Fatalf("Repair: %v", err)
	}
	if now, _ := os.ReadFile(q); !bytes.Equal(raw, now) {
		t.Fatal("the repair must truncate nothing")
	}
	if frags, _ := filepath.Glob(q + ".torn-*"); len(frags) != 0 {
		t.Fatalf("no fragment: %v", frags)
	}
}
