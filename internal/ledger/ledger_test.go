package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hashOf(line []byte) string { s := sha256.Sum256(line); return hex.EncodeToString(s[:]) }

// mkLine builds a minimal chained record with the given prev.
func mkLine(t *testing.T, prev, note string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"prev": prev, "note": note})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, lines ...[]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAppendAcrossReopens(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	c, err := Open(p, Unlocked)
	if err != nil {
		t.Fatal(err)
	}
	l1 := mkLine(t, c.Prev(), "a")
	if err := c.Append(l1); err != nil {
		t.Fatal(err)
	}
	l2 := mkLine(t, c.Prev(), "b")
	if err := c.Append(l2); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	c2, err := Open(p, Unlocked) // fresh open must RESUME, not restart at genesis
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	if got, want := c2.Prev(), hashOf(l2); got != want {
		t.Fatalf("resumed head %q, want %q", got, want)
	}
	if c2.Count() != 2 {
		t.Fatalf("count %d, want 2", c2.Count())
	}
	l3 := mkLine(t, c2.Prev(), "c")
	if err := c2.Append(l3); err != nil {
		t.Fatal(err)
	}
	recs, head, err := ReadVerify(p, Unlocked)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(recs) != 3 || head.Count != 3 || head.Hash != hashOf(l3) {
		t.Fatalf("bad head %+v len %d", head, len(recs))
	}
}

func TestAppendRefusesForkedPrev(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	c, _ := Open(p, Unlocked)
	defer func() { _ = c.Close() }()
	if err := c.Append(mkLine(t, c.Prev(), "a")); err != nil {
		t.Fatal(err)
	}
	err := c.Append(mkLine(t, "0000dead", "forked"))
	if err == nil || !strings.Contains(err.Error(), "refusing append") {
		t.Fatalf("want fork refusal, got %v", err)
	}
}

// TestAppendRejectedProbeDoesNotPoisonSeqMode guards against a rejected
// Append (forged prev, with a seq field present) permanently pinning
// the chain's seq mode from a line that never got written. "First
// record decides seq mode" must mean the first COMMITTED record.
func TestAppendRejectedProbeDoesNotPoisonSeqMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	c, err := Open(p, Unlocked)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	forged, err := json.Marshal(map[string]any{"prev": "0000dead", "seq": 1, "note": "forged"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append(forged); err == nil || !strings.Contains(err.Error(), "refusing append") {
		t.Fatalf("want fork refusal, got %v", err)
	}

	genesis := mkLine(t, c.Prev(), "a")
	if err := c.Append(genesis); err != nil {
		t.Fatalf("legitimate genesis append rejected after a bad probe: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	recs, head, err := ReadVerify(p, Unlocked)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(recs) != 1 || head.Count != 1 || head.Hash != hashOf(genesis) {
		t.Fatalf("bad head %+v len %d", head, len(recs))
	}
}

func TestTornMatrix(t *testing.T) {
	l1 := mkLine(t, "", "a")
	l2 := mkLine(t, hashOf(l1), "b")
	cases := []struct {
		name string
		raw  []byte
		torn bool // else: broken (when line>0) or clean (line==0)
		line int  // for broken
	}{
		{"empty file is clean", nil, false, 0},
		{"lone newline is torn", []byte("\n"), true, 0},
		{"missing trailing newline is torn", append(append(append([]byte{}, l1...), '\n'), l2...), true, 0},
		{"unparseable terminated last line is torn", []byte(string(l1) + "\n{oops\n"), true, 0},
		{"nul in tail is torn", append(append(append([]byte{}, l1...), '\n'), 0x00, '\n'), true, 0},
		{"unparseable middle line is broken", []byte("{oops\n" + string(l1) + "\n"), false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "chain.jsonl")
			if tc.raw != nil {
				if err := os.WriteFile(p, tc.raw, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(p, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, _, err := ReadVerify(p, Unlocked)
			switch {
			case tc.torn:
				var te *TornError
				if !errors.As(err, &te) {
					t.Fatalf("want TornError, got %v", err)
				}
			case tc.line > 0:
				var be *ChainBrokenError
				if !errors.As(err, &be) || be.Line != tc.line {
					t.Fatalf("want broken at %d, got %v", tc.line, err)
				}
			default:
				if err != nil {
					t.Fatalf("want clean, got %v", err)
				}
			}
		})
	}
}

func TestBrokenMiddleReturnsValidPrefix(t *testing.T) {
	l1 := mkLine(t, "", "a")
	l2 := mkLine(t, hashOf(l1), "b")
	l3 := mkLine(t, "badbadbad", "tampered-prev")
	p := writeFile(t, l1, l2, l3)
	recs, head, err := ReadVerify(p, Unlocked)
	var be *ChainBrokenError
	if !errors.As(err, &be) || be.Line != 3 {
		t.Fatalf("want broken at 3, got %v", err)
	}
	if len(recs) != 2 || head.Count != 2 || head.Hash != hashOf(l2) {
		t.Fatalf("prefix wrong: %d %+v", len(recs), head)
	}
}

func TestTornReturnsValidPrefix(t *testing.T) {
	l1 := mkLine(t, "", "a")
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	if err := os.WriteFile(p, append(append(append([]byte{}, l1...), '\n'), []byte(`{"prev":"`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, head, err := ReadVerify(p, Unlocked)
	var te *TornError
	if !errors.As(err, &te) {
		t.Fatalf("want torn, got %v", err)
	}
	if len(recs) != 1 || head.Hash != hashOf(l1) {
		t.Fatalf("prefix wrong")
	}
	if _, oerr := Open(p, Unlocked); oerr == nil {
		t.Fatal("Open must refuse a torn log")
	}
}

func TestHonestyTailDeletionInvisible(t *testing.T) {
	l1 := mkLine(t, "", "a")
	l2 := mkLine(t, hashOf(l1), "b")
	p := writeFile(t, l1, l2)
	if err := os.WriteFile(p, append(append([]byte{}, l1...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	} // delete last line + newline
	_, head, err := ReadVerify(p, Unlocked)
	if err != nil {
		t.Fatalf("tail deletion must verify clean (documented limitation): %v", err)
	}
	if head.Hash != hashOf(l1) {
		t.Fatal("head must be the surviving line")
	} // --expect-head catches this in Task 4
}

func TestGoldenBytes(t *testing.T) {
	line := []byte(`{"prev":"","note":"golden"}`)
	const want = "96f506b274e505fb26b491538aa5b91d8af8d8c5bd303864eff84c2d73112054" // sha256 of the exact bytes above
	if got := hashOf(line); got != want {
		t.Fatalf("golden hash drifted: %s", got)
	}
}

func TestLargeRecordRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "chain.jsonl")
	c, _ := Open(p, Unlocked)
	big := mkLine(t, c.Prev(), strings.Repeat("x", 100_000)) // > 64 KiB line
	if err := c.Append(big); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	recs, _, err := ReadVerify(p, Unlocked)
	if err != nil || len(recs) != 1 || !bytes.Equal(recs[0].Raw, big) {
		t.Fatalf("large record: %v", err)
	}
}

func TestCRLFChangesHash(t *testing.T) {
	l1 := mkLine(t, "", "a")
	if hashOf(append(l1, '\r')) == hashOf(l1) {
		t.Fatal("impossible")
	}
	// A CRLF-terminated line stores \r as part of the record bytes; the chain
	// must hash it. Guard: a file whose line ends \r\n must verify against
	// hash-including-\r, i.e. a successor built on hashOf(l1) must FAIL.
	withCR := append(append([]byte{}, l1...), '\r')
	l2 := mkLine(t, hashOf(l1), "b") // wrong: built on hash WITHOUT \r
	p := writeFile(t, withCR, l2)
	_, _, err := ReadVerify(p, Unlocked)
	var be *ChainBrokenError
	if !errors.As(err, &be) || be.Line != 2 {
		t.Fatalf("CR must be hashed as content: %v", err)
	}
}

func TestSeqRules(t *testing.T) {
	mk := func(prev string, seq int, note string) []byte {
		b, _ := json.Marshal(map[string]any{"prev": prev, "seq": seq, "note": note})
		return b
	}
	s1 := mk("", 1, "a")
	s2 := mk(hashOf(s1), 2, "b")
	if _, _, err := ReadVerify(writeFile(t, s1, s2), Unlocked); err != nil {
		t.Fatalf("seq chain: %v", err)
	}
	gap := mk(hashOf(s1), 3, "gap")
	if _, _, err := ReadVerify(writeFile(t, s1, gap), Unlocked); err == nil {
		t.Fatal("seq gap must break")
	}
	noSeq := mkLine(t, hashOf(s1), "mixed")
	if _, _, err := ReadVerify(writeFile(t, s1, noSeq), Unlocked); err == nil {
		t.Fatal("mixed seq presence must break")
	}
}
