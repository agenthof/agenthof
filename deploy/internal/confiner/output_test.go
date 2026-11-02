package confiner

import "testing"

func TestCapWriterKeepsFirstMaxAndCounts(t *testing.T) {
	c := NewCapWriter(4)
	_, _ = c.Write([]byte("abcdef"))
	out, trunc := c.Output()
	if string(out) != "abcd"+TruncationMarker || !trunc || c.Total() != 6 {
		t.Fatalf("%q %v %d", out, trunc, c.Total())
	}
	c2 := NewCapWriter(4)
	_, _ = c2.Write([]byte("ab"))
	if out, trunc := c2.Output(); string(out) != "ab" || trunc {
		t.Fatal("under the cap: verbatim, not truncated")
	}
}
