package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/identity"
	"github.com/agenthof/agenthof/internal/ledger"
)

func repairIt(t *testing.T, p string) (RepairResult, error) {
	t.Helper()
	return Repair(p, identity.Static("ops@example.com"), "", Witness{OSUser: "ops", Hostname: "host"})
}

// appendRaw appends chained records through the bare ledger — no control
// permit runs — the way a binary older than this root's seals would write
// after a seal line. It returns the lines written, newline-terminated.
func appendRaw(t *testing.T, p string, prev string, seqs ...int) [][]byte {
	t.Helper()
	c, err := ledger.OpenFrom(p, ledger.Locked, ledger.Start{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	var lines [][]byte
	for _, seq := range seqs {
		r := record{V: "control/1", Seq: seq, Action: "prune", Outcome: "success", Invoker: identity.Static("old"), Witness: Witness{}, Prev: prev}
		b, _ := json.Marshal(r)
		if err := c.Append(b); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, append(b, '\n'))
		prev = hashOf(b)
	}
	return lines
}

// appendBytes appends b as is — no chain, no permit.
func appendBytes(t *testing.T, p string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

// tear appends an unterminated partial line.
func tear(t *testing.T, p string, seq int) []byte {
	t.Helper()
	frag := []byte(`{"v":"control/1","seq":` + strconv.Itoa(seq) + `,"prev":""`)
	appendBytes(t, p, frag)
	return frag
}

// snapshotDir is every entry's name and size: a refusal changes nothing.
func snapshotDir(t *testing.T, dir string) string {
	t.Helper()
	var sb strings.Builder
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		i, _ := e.Info()
		sb.WriteString(e.Name() + ":" + strconv.FormatInt(i.Size(), 10) + ";")
	}
	return sb.String()
}

// TestRepairTornActiveOnARotatedRoot: a torn tail in the active of a rotated
// root is repaired as today, the repair record carrying the active's Start
// (prev = the sealed head); IsTainted finds it in the logical chain.
func TestRepairTornActiveOnARotatedRoot(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 3)
	sealByHand(t, p, "")
	appendN(t, p, 1)
	tear(t, p, 6)
	res, err := repairIt(t, p)
	if err != nil || res.CompletedSegment != 0 || res.FragmentLen == 0 {
		t.Fatalf("%v %+v", err, res)
	}
	v, err := Read(p, ledger.Locked)
	if err != nil || v.Head.Count != 6 {
		t.Fatalf("%v %+v", err, v.Head)
	}
	last, _ := decodeRecord(v.Records[5])
	if last.Action != "repair" || last.Seq != 6 || last.FragmentLen != res.FragmentLen {
		t.Fatalf("%+v", last)
	}
	if tainted, seq := IsTainted(v.Records); !tainted || seq != 6 {
		t.Fatal("tainted across segments")
	}
}

// TestRepairTornSealRecordReopensTheSegment: a seal line cut mid-write is a
// torn tail — "a torn seal is no seal": repaired, the segment is open again,
// a later seal works and the taint is in segment 1.
func TestRepairTornSealRecordReopensTheSegment(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 3)
	line := sealByHand(t, p, "B")
	data, _ := os.ReadFile(p)
	_ = os.WriteFile(p, data[:len(data)-len(line)/2], 0o600)
	if _, err := repairIt(t, p); err != nil {
		t.Fatal(err)
	}
	v, err := Read(p, ledger.Locked)
	if err != nil || v.State != StateOpen || len(v.Sealed) != 0 || v.Head.Count != 4 {
		t.Fatalf("%v %+v", err, v)
	}
	if _, err := SealActive(p, sealEvent()); err != nil {
		t.Fatal(err)
	}
	v, _ = Read(p, ledger.Locked)
	if tainted, seq := IsTainted(v.Records); !tainted || seq != 4 || v.Sealed[0].HeadSeq != 5 {
		t.Fatalf("taint in segment 1: %v %d", tainted, seq)
	}
}

// TestRepairPostSealRecords: the older-binary shape — two ordinary records
// after the seal line in the active. Read → FaultSealNotLast{0} at the first
// post-seal seq; Repair moves exactly those bytes to a torn fragment, the
// sealed segment equals the bytes up to and including the seal line, the
// manifest lists it, and the new active holds exactly one record — repair,
// prev = sha256(seal line), seq = seal.seq + 1.
func TestRepairPostSealRecords(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.jsonl")
	appendN(t, p, 3)
	line := sealByHand(t, p, "B")
	sealed, _ := os.ReadFile(p)
	extra := appendRaw(t, p, hashOf(line), 5, 6)
	_, err := Read(p, ledger.Locked)
	var se *SetError
	if !errors.As(err, &se) || se.Fault != FaultSealNotLast || se.Segment != 0 || se.Seq != 5 || !strings.Contains(err.Error(), "run: agenthof audit repair control") {
		t.Fatalf("%v", err)
	}
	if _, _, err := openActive(p); err == nil || !errors.As(err, &se) {
		t.Fatal("writers refuse with the repair hint")
	}
	res, err := repairIt(t, p)
	if err != nil || res.CompletedSegment != 1 || res.FragmentLen != len(bytes.Join(extra, nil)) {
		t.Fatalf("%v %+v", err, res)
	}
	frags, _ := filepath.Glob(p + ".torn-*")
	if len(frags) != 1 {
		t.Fatalf("one fragment: %v", frags)
	}
	frag, _ := os.ReadFile(frags[0])
	if !bytes.Equal(frag, bytes.Join(extra, nil)) {
		t.Fatal("the fragment is exactly the post-seal records")
	}
	seg, _ := os.ReadFile(SegmentPath(p, 1))
	if !bytes.Equal(seg, sealed) {
		t.Fatal("the sealed segment is the bytes up to and including the seal line")
	}
	v, err := Read(p, ledger.Locked)
	if err != nil || len(v.Sealed) != 1 || v.Active.Records != 1 || v.Head.Count != 5 {
		t.Fatalf("%v %+v", err, v)
	}
	rep, _ := decodeRecord(v.Records[4])
	if rep.Action != "repair" || rep.Seq != 5 || rep.Prev != hashOf(line) || rep.FragmentLen != res.FragmentLen {
		t.Fatalf("%+v", rep)
	}
}

// TestRepairTornTailAfterAnIntactSeal: a torn write after a successful seal
// — alone, or after post-seal records — is post-seal bytes like any other:
// everything after the seal line is one fragment, the rotation is completed
// and the repair record opens the next segment. Never "repaired as a torn
// tail" into state B with no taint.
func TestRepairTornTailAfterAnIntactSeal(t *testing.T) {
	for name, between := range map[string][]int{"seal then torn": nil, "seal, records, then torn": {5, 6}} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "control.jsonl")
			appendN(t, p, 3)
			line := sealByHand(t, p, "B")
			sealed, _ := os.ReadFile(p)
			var want []byte
			if between != nil {
				want = bytes.Join(appendRaw(t, p, hashOf(line), between...), nil)
			}
			want = append(want, tear(t, p, 5+len(between))...)
			res, err := repairIt(t, p)
			if err != nil || res.CompletedSegment != 1 || res.FragmentLen != len(want) {
				t.Fatalf("%v %+v", err, res)
			}
			frags, _ := filepath.Glob(p + ".torn-*")
			if len(frags) != 1 {
				t.Fatalf("exactly one fragment: %v", frags)
			}
			if frag, _ := os.ReadFile(frags[0]); !bytes.Equal(frag, want) {
				t.Fatal("the fragment is every byte after the seal line")
			}
			if seg, _ := os.ReadFile(SegmentPath(p, 1)); !bytes.Equal(seg, sealed) {
				t.Fatal("the sealed segment is the bytes up to and including the seal line")
			}
			v, err := Read(p, ledger.Locked)
			if err != nil || v.State != StateOpen || len(v.Sealed) != 1 || v.Active.Records != 1 || v.Head.Count != 5 {
				t.Fatalf("%v %+v", err, v)
			}
			if tainted, seq := IsTainted(v.Records); !tainted || seq != 5 {
				t.Fatalf("taint opens the next segment: %v %d", tainted, seq)
			}
		})
	}
}

// TestRepairRefusesAPlantedSealBeforeTouchingAnything: a seal line whose
// payload does not recompute, followed by a record or a torn tail, is not a
// rotation to complete — completing it would fail after the truncate and
// leave the active ending in a bad seal. Repair judges the seal first and
// refuses with the fault; nothing on disk changes.
func TestRepairRefusesAPlantedSealBeforeTouchingAnything(t *testing.T) {
	for name, after := range map[string]func(t *testing.T, p, prev string){
		"record": func(t *testing.T, p, prev string) { appendRaw(t, p, prev, 5) },
		"torn":   func(t *testing.T, p, _ string) { tear(t, p, 5) },
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "control.jsonl")
			appendN(t, p, 3)
			v, err := Read(p, ledger.Locked)
			if err != nil {
				t.Fatal(err)
			}
			planted := record{V: "control/1", Seq: 4, Action: "seal", Outcome: "success", Invoker: identity.Static("old"), Witness: Witness{},
				Seal: &Seal{Segment: 1, FirstSeq: 1, HeadSeq: 3, HeadHash: v.Head.Hash, ContentSHA256: strings.Repeat("0", 64)}, Prev: v.Head.Hash}
			b, _ := json.Marshal(planted)
			c, err := ledger.OpenFrom(p, ledger.Locked, ledger.Start{})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Append(b); err != nil {
				t.Fatal(err)
			}
			_ = c.Close()
			after(t, p, hashOf(b))
			before := snapshotDir(t, filepath.Dir(p))
			_, err = repairIt(t, p)
			if err == nil || !strings.Contains(err.Error(), "seal payload") || strings.Contains(err.Error(), "audit repair control") {
				t.Fatalf("%v", err)
			}
			if snapshotDir(t, filepath.Dir(p)) != before {
				t.Fatal("a refusal changes nothing")
			}
		})
	}
}

// TestRepairPostSealCrashHooks: a crash after the truncate leaves state B
// (audit seal completes it; the fragment exists; no taint — the documented
// residual); a crash after the rotation leaves a clean rotated root with a
// fragment and no taint.
func TestRepairPostSealCrashHooks(t *testing.T) {
	for _, tc := range []struct {
		hook  string
		state State
	}{{"repair_after_truncate_before_rotate", StateSealedNotRotated}, {"repair_after_rotate_before_append", StateOpen}} {
		p := filepath.Join(t.TempDir(), "control.jsonl")
		appendN(t, p, 3)
		line := sealByHand(t, p, "B")
		appendRaw(t, p, hashOf(line), 5)
		t.Setenv("AGENTHOF_TEST_CRASH_AT", tc.hook)
		_, err := repairIt(t, p)
		t.Setenv("AGENTHOF_TEST_CRASH_AT", "")
		if !errors.Is(err, errStoppedByTestHook) {
			t.Fatalf("%s: %v", tc.hook, err)
		}
		v, rerr := Read(p, ledger.Locked)
		if rerr != nil || v.State != tc.state {
			t.Fatalf("%s: %v state %d", tc.hook, rerr, v.State)
		}
		if frags, _ := filepath.Glob(p + ".torn-*"); len(frags) != 1 {
			t.Fatalf("%s: the fragment exists", tc.hook)
		}
		if tainted, _ := IsTainted(v.Records); tainted {
			t.Fatalf("%s: the residual is a lost taint", tc.hook)
		}
		if tc.state == StateSealedNotRotated {
			if _, err := repairIt(t, p); err == nil || !strings.Contains(err.Error(), "run audit seal") {
				t.Fatalf("a re-run of repair in state B refuses: %v", err)
			}
			if _, err := CompleteSeal(p); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TestRepairRefusesSetFaults: clean rotated root → "not torn"; state B/C →
// "run audit seal"; a torn or broken sealed segment → "never repaired in
// place"; a boundary fault in the active → "restore from a copy", never
// "run repair"; a missing segment → its remedy. Nothing on disk changes.
func TestRepairRefusesSetFaults(t *testing.T) {
	for name, prep := range map[string]func(t *testing.T, p string) string{
		"clean":   func(t *testing.T, p string) string { return "not torn; nothing to repair" },
		"state B": func(t *testing.T, p string) string { sealByHand(t, p, "B"); return "run audit seal" },
		"state C": func(t *testing.T, p string) string { sealByHand(t, p, "C"); return "run audit seal" },
		"torn sealed": func(t *testing.T, p string) string {
			seg := SegmentPath(p, 1)
			d, _ := os.ReadFile(seg)
			_ = os.WriteFile(seg, d[:len(d)-2], 0o600)
			return "never repaired in place"
		},
		"missing": func(t *testing.T, p string) string { _ = os.Remove(SegmentPath(p, 1)); return "restore it from a copy" },
		"boundary": func(t *testing.T, p string) string {
			d, _ := os.ReadFile(p)
			d[bytes.Index(d, []byte(`"prev":"`))+8] ^= 1
			_ = os.WriteFile(p, d, 0o600)
			return "does not chain from segment 1's head"
		},
		"broken": func(t *testing.T, p string) string {
			// A well-formed record whose prev disagrees with the chain: the
			// bare ledger refuses to append it, so it is written as bytes.
			b, _ := json.Marshal(record{V: "control/1", Seq: 7, Action: "prune", Outcome: "success", Invoker: identity.Static("old"), Witness: Witness{}, Prev: strings.Repeat("0", 64)})
			appendBytes(t, p, append(b, '\n'))
			return "chain break at seq 7 is not auto-repairable"
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "control.jsonl")
			appendN(t, p, 3)
			sealByHand(t, p, "")
			appendN(t, p, 2)
			want := prep(t, p)
			before := snapshotDir(t, filepath.Dir(p))
			_, err := repairIt(t, p)
			if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "audit repair control") {
				t.Fatalf("%s: %v", name, err)
			}
			if snapshotDir(t, filepath.Dir(p)) != before {
				t.Fatalf("%s: a refusal changes nothing", name)
			}
		})
	}
}
