package ledger

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// seqLine builds a chained, seq-carrying record (a control-log shape).
func seqLine(prev string, seq int, note string) []byte {
	b, _ := json.Marshal(map[string]any{"prev": prev, "seq": seq, "note": note})
	return b
}

// threeRecords writes seq 1..3 to a fresh file and returns its path and head.
func threeRecords(t *testing.T) (string, Head) {
	t.Helper()
	s1 := seqLine("", 1, "a")
	s2 := seqLine(hashOf(s1), 2, "b")
	s3 := seqLine(hashOf(s2), 3, "c")
	return writeFile(t, s1, s2, s3), Head{Hash: hashOf(s3), Count: 3}
}

// TestOpenIsOpenFromZero / TestReadVerifyIsReadVerifyFromZero: the zero Start
// is today — identical outputs, including the typed errors, over the
// torn/broken matrix ledger_test.go already exercises.
func TestReadVerifyIsReadVerifyFromZero(t *testing.T) {
	clean, _ := threeRecords(t)
	tornPath := writeFile(t, seqLine("", 1, "a"))
	torn, _ := os.ReadFile(tornPath)
	if err := os.WriteFile(tornPath, append(torn, []byte(`{"prev":`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	s1 := seqLine("", 1, "a")
	brokenPath := writeFile(t, s1, seqLine("deadbeef", 2, "b"))
	for _, p := range []string{clean, tornPath, brokenPath, filepath.Join(t.TempDir(), "missing.jsonl")} {
		r1, h1, e1 := ReadVerify(p, Unlocked)
		r2, h2, e2 := ReadVerifyFrom(p, Unlocked, Start{})
		if len(r1) != len(r2) || h1 != h2 || (e1 == nil) != (e2 == nil) || (e1 != nil && e1.Error() != e2.Error()) {
			t.Fatalf("%s: ReadVerify %v/%+v/%v vs ReadVerifyFrom %v/%+v/%v", p, len(r1), h1, e1, len(r2), h2, e2)
		}
		for i := range r1 {
			if string(r1[i].Raw) != string(r2[i].Raw) {
				t.Fatalf("%s: record %d differs", p, i)
			}
		}
	}
}

func TestOpenIsOpenFromZero(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	c, err := OpenFrom(p, Unlocked, Start{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Base() != 0 || c.Count() != 0 || c.Prev() != "" {
		t.Fatalf("zero Start chain: base %d count %d prev %q", c.Base(), c.Count(), c.Prev())
	}
	if err := c.Append(seqLine("", 1, "a")); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	c2, err := Open(p, Unlocked)
	if err != nil || c2.Count() != 1 || c2.Base() != 0 {
		t.Fatalf("Open after OpenFrom: %v count %d", err, c2.Count())
	}
	_ = c2.Close()
}

// TestStartContinuesChain: a second file that starts from the first file's
// head verifies with that Start; a wrong prev, a wrong seq, or a seq-less
// first record with Base > 0 is ChainBrokenError{Line: 1}; the zero Start
// over the continuation is BROKEN at line 1 by design.
func TestStartContinuesChain(t *testing.T) {
	_, head := threeRecords(t)
	start := Start{Prev: head.Hash, Base: 3}
	s4 := seqLine(head.Hash, 4, "d")
	s5 := seqLine(hashOf(s4), 5, "e")
	recs, h, err := ReadVerifyFrom(writeFile(t, s4, s5), Unlocked, start)
	if err != nil || len(recs) != 2 || h.Count != 2 || h.Hash != hashOf(s5) {
		t.Fatalf("continuation: %v %d %+v", err, len(recs), h)
	}
	if _, _, err := ReadVerify(writeFile(t, s4, s5), Unlocked); !isBrokenAt(err, 1) {
		t.Fatalf("zero Start over a continuation must be BROKEN at line 1, got %v", err)
	}
	cases := map[string][]byte{
		"wrong prev":  seqLine("ab"+head.Hash[2:], 4, "d"),
		"wrong seq":   seqLine(head.Hash, 5, "d"),
		"missing seq": mkLine(t, head.Hash, "d"),
	}
	for name, first := range cases {
		if _, _, err := ReadVerifyFrom(writeFile(t, first), Unlocked, start); !isBrokenAt(err, 1) {
			t.Fatalf("%s: want ChainBrokenError{1}, got %v", name, err)
		}
	}
}

func isBrokenAt(err error, line int) bool {
	var b *ChainBrokenError
	return errors.As(err, &b) && b.Line == line
}

// TestAppendFromStart: OpenFrom and Resume with Base > 0 require the first
// append to carry prev == Start.Prev and seq == Base+1; a zero-Start probe
// and a seq-less first record are refused (the chain is in seq mode before
// any record); a mixed Start is ErrBadStart on every constructor.
func TestAppendFromStart(t *testing.T) {
	_, head := threeRecords(t)
	start := Start{Prev: head.Hash, Base: 3}
	p := filepath.Join(t.TempDir(), "seg2.jsonl")
	c, err := OpenFrom(p, Unlocked, start)
	if err != nil || c.Base() != 3 || c.Prev() != head.Hash || c.Count() != 0 {
		t.Fatalf("OpenFrom: %v base %d prev %q", err, c.Base(), c.Prev())
	}
	if err := c.Append(seqLine("", 1, "probe")); err == nil {
		t.Fatal("a zero-Start probe must be refused")
	}
	if err := c.Append(mkLine(t, head.Hash, "noseq")); err == nil {
		t.Fatal("a seq-less first record must be refused on a Base > 0 chain")
	}
	if err := c.Append(seqLine(head.Hash, 5, "skip")); err == nil {
		t.Fatal("seq must be Base+1")
	}
	if err := c.Append(seqLine(head.Hash, 4, "d")); err != nil {
		t.Fatalf("first append: %v", err)
	}
	_ = c.Close()
	recs, h, err := ReadVerifyFrom(p, Unlocked, start)
	if err != nil || len(recs) != 1 || h.Count != 1 {
		t.Fatalf("reread: %v %d", err, len(recs))
	}
	// Resume over a caller-opened, caller-locked empty handle behaves the same.
	p2 := filepath.Join(t.TempDir(), "seg3.jsonl")
	f, err := os.OpenFile(p2, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := LockExclusive(f); err != nil {
		t.Fatal(err)
	}
	rc, recs2, err := Resume(f, Locked, start)
	if err != nil || len(recs2) != 0 || rc.Base() != 3 {
		t.Fatalf("Resume empty: %v %d", err, len(recs2))
	}
	if err := rc.Append(mkLine(t, head.Hash, "noseq")); err == nil {
		t.Fatal("Resume with Base > 0 must preset seq mode")
	}
	if err := rc.Append(seqLine(head.Hash, 4, "d")); err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()
	for _, bad := range []Start{{Prev: head.Hash, Base: 0}, {Prev: "", Base: 3}} {
		if _, err := OpenFrom(filepath.Join(t.TempDir(), "x.jsonl"), Unlocked, bad); !errors.Is(err, ErrBadStart) {
			t.Fatalf("OpenFrom(%+v) = %v, want ErrBadStart", bad, err)
		}
		if _, _, err := ReadVerifyFrom(p, Unlocked, bad); !errors.Is(err, ErrBadStart) {
			t.Fatalf("ReadVerifyFrom(%+v) = %v, want ErrBadStart", bad, err)
		}
		if _, _, err := VerifyReader(nil, bad); !errors.Is(err, ErrBadStart) {
			t.Fatalf("VerifyReader(%+v) = %v, want ErrBadStart", bad, err)
		}
		g, _ := os.Open(p)
		if _, _, err := Resume(g, Unlocked, bad); !errors.Is(err, ErrBadStart) {
			t.Fatalf("Resume(%+v) = %v, want ErrBadStart", bad, err)
		}
		_ = g.Close()
	}
	if _, err := os.Stat(filepath.Join(t.TempDir(), "never.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ErrBadStart must create nothing")
	}
}

// TestResumeNeverCreatesNorLocks: Resume takes no flock (a concurrent
// LOCK_EX holder does not block it), Close releases the caller's lock when
// mode == Locked, its records equal ReadVerifyFrom's, and the handle is read
// once (its offset sits at EOF and nothing seeks back).
func TestResumeNeverCreatesNorLocks(t *testing.T) {
	p, _ := threeRecords(t)
	holder, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, recs, err := Resume(f, Unlocked, Start{})
	if err != nil || len(recs) != 3 || c.Count() != 3 {
		t.Fatalf("Resume under a foreign LOCK_EX must not block: %v %d", err, len(recs))
	}
	off, _ := f.Seek(0, io.SeekCurrent)
	info, _ := f.Stat()
	if off != info.Size() {
		t.Fatalf("Resume must read the handle exactly once to EOF: offset %d size %d", off, info.Size())
	}
	want, _, _ := ReadVerifyFrom(p, Unlocked, Start{})
	for i := range want {
		if string(want[i].Raw) != string(recs[i].Raw) {
			t.Fatalf("record %d differs", i)
		}
	}
	_ = c.Close()
	_ = syscall.Flock(int(holder.Fd()), syscall.LOCK_UN)
	_ = holder.Close()

	// Locked: Close releases the lock the caller took.
	g, _ := os.OpenFile(p, os.O_RDWR|os.O_APPEND, 0)
	if err := LockExclusive(g); err != nil {
		t.Fatal(err)
	}
	c2, _, err := Resume(g, Locked, Start{})
	if err != nil {
		t.Fatal(err)
	}
	_ = c2.Close()
	h, _ := os.OpenFile(p, os.O_RDWR, 0)
	defer func() { _ = h.Close() }()
	if err := syscall.Flock(int(h.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("Close(Locked) must release the caller's flock: %v", err)
	}
}
