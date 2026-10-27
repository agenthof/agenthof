package sidecar

import (
	"errors"
	"strings"
	"testing"

	"github.com/agenthof/agenthof/internal/anchorverify"
	"github.com/agenthof/agenthof/internal/control"
)

const (
	rHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rRef  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func result(state anchorverify.State, cause string) anchorverify.Result {
	return anchorverify.Result{
		Check: control.AnchorCheck{RecordSeq: 1, Anchor: &control.Anchor{RunID: "r-0123456789abcdef", Seq: 3, Hash: rHash, Backend: "http://127.0.0.1:1", Ref: rRef}},
		State: state, Cause: cause,
	}
}

func verdict(rs ...anchorverify.Result) Verdict { return Verdict{Found: true, Results: rs} }

func TestLinesFiveStates(t *testing.T) {
	const pinHint = "; pin the log key in anchor.pub beside the control ledger or pass --anchor-key"
	const auditHint = ", or run audit verify r-0123456789abcdef to check under the key the log serves"
	where := "events 3 " + rHash + " → http://127.0.0.1:1 entry " + rRef
	cases := []struct {
		name string
		v    Verdict
		o    RenderOptions
		want string
	}{
		{"not found", Verdict{}, RenderOptions{}, "ledger anchor: not anchored\n"},
		{"sidecar unreadable", Verdict{Found: true, Err: errors.New("sidecar x is empty")}, RenderOptions{OfflineOnly: true, RunID: "r-0123456789abcdef"},
			"ledger anchor: unverifiable — sidecar x is empty\n"},
		{"verified unpinned", verdict(result(anchorverify.StateVerified, "")), RenderOptions{},
			"ledger anchor: anchored — verified under the log key as served (not independent; pin the log key in anchor.pub or --anchor-key to verify independently)\n"},
		{"verified pinned", verdict(result(anchorverify.StateVerified, "")), RenderOptions{Pinned: true},
			"ledger anchor: independently verified (log key pinned; " + where + ")\n"},
		{"verified pinned offline", verdict(result(anchorverify.StateVerified, "")), RenderOptions{Pinned: true, Offline: true},
			"ledger anchor: independently verified (log key pinned; offline: presence not checked; " + where + ")\n"},
		{"mismatch", verdict(result(anchorverify.StateMismatch, "the anchored event is not the run's final event")), RenderOptions{Pinned: true},
			"ledger anchor: MISMATCH — the anchored event is not the run's final event\n"},
		{"unverifiable pinned", verdict(result(anchorverify.StateUnverifiable, "log key differs from the pinned key")), RenderOptions{Pinned: true},
			"ledger anchor: unverifiable — log key differs from the pinned key\n"},
		{"unverifiable unpinned", verdict(result(anchorverify.StateUnverifiable, "dial refused")), RenderOptions{},
			"ledger anchor: unverifiable — dial refused" + pinHint + "\n"},
		{"unverifiable unpinned offline-only", verdict(result(anchorverify.StateUnverifiable, "no key to verify under (unpinned, offline)")), RenderOptions{Offline: true, OfflineOnly: true, RunID: "r-0123456789abcdef"},
			"ledger anchor: unverifiable — no key to verify under (unpinned, offline)" + pinHint + auditHint + "\n"},
	}
	for _, c := range cases {
		if got := Lines(c.v, c.o); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}

	// The as-served case is never "independent", whatever else is set.
	for _, o := range []RenderOptions{{}, {Offline: true}, {OfflineOnly: true}, {Offline: true, OfflineOnly: true, RunID: "r-x"}} {
		if got := Lines(verdict(result(anchorverify.StateVerified, "")), o); strings.Contains(got, "independently verified") || !strings.Contains(got, "not independent") {
			t.Errorf("unpinned verified must read as served, not independent: %q", got)
		}
	}

	// Two records: one line each, then a summary.
	two := Lines(verdict(result(anchorverify.StateVerified, ""), result(anchorverify.StateMismatch, "x"), result(anchorverify.StateUnverifiable, "y")), RenderOptions{Pinned: true})
	if n := strings.Count(two, "ledger anchor: "); n != 3 || !strings.HasSuffix(two, "ledger anchors: 3 (1 verified, 1 mismatch, 1 unverifiable)\n") {
		t.Errorf("three records:\n%s", two)
	}
	if one := Lines(verdict(result(anchorverify.StateVerified, "")), RenderOptions{Pinned: true}); strings.Contains(one, "ledger anchors:") {
		t.Errorf("one record has no summary: %q", one)
	}
}

// TestLinesCleansEverythingTheSidecarCarries: a hash, backend, ref or cause
// planted with control characters reaches the terminal without them.
func TestLinesCleansEverythingTheSidecarCarries(t *testing.T) {
	r := result(anchorverify.StateVerified, "")
	r.Check.Anchor.Hash, r.Check.Anchor.Backend, r.Check.Anchor.Ref = "h\x1b[2J", "b\x1b[2J", "r\x1b[2J"
	u := result(anchorverify.StateUnverifiable, "c\x1b[2J")
	for _, got := range []string{
		Lines(verdict(r), RenderOptions{Pinned: true}),
		Lines(verdict(u), RenderOptions{}),
		Lines(Verdict{Found: true, Err: errors.New("e\x1b[2J")}, RenderOptions{}),
	} {
		if strings.ContainsRune(got, 0x1b) {
			t.Errorf("an escape byte reached the output: %q", got)
		}
	}
}

// TestLinesNeverReadsNoResultsAsVerified: a found sidecar that yielded no
// results is unverifiable, never verified.
func TestLinesNeverReadsNoResultsAsVerified(t *testing.T) {
	got := Lines(Verdict{Found: true}, RenderOptions{})
	if !strings.HasPrefix(got, "ledger anchor: unverifiable — ") || strings.Contains(got, "verified (") {
		t.Errorf("got %q", got)
	}
}

func TestExitMapsStates(t *testing.T) {
	for _, c := range []struct {
		name string
		v    Verdict
		want int
	}{
		{"not anchored", Verdict{}, 0},
		{"verified", verdict(result(anchorverify.StateVerified, "")), 0},
		{"unverifiable", verdict(result(anchorverify.StateUnverifiable, "x")), 7},
		{"unreadable", Verdict{Found: true, Err: errors.New("x")}, 7},
		{"mismatch", verdict(result(anchorverify.StateVerified, ""), result(anchorverify.StateMismatch, "x")), 6},
		{"mismatch beats unverifiable", verdict(result(anchorverify.StateUnverifiable, "x"), result(anchorverify.StateMismatch, "x")), 6},
	} {
		if got := Exit(c.v); got != c.want {
			t.Errorf("%s: Exit = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestTreeExitRanksMismatchOverUnverifiable: 6 > 7 > 0 across the root and its
// descendants, whatever the order — a later node never lowers an earlier one.
func TestTreeExitRanksMismatchOverUnverifiable(t *testing.T) {
	mm := verdict(result(anchorverify.StateMismatch, "x"))
	un := verdict(result(anchorverify.StateUnverifiable, "y"))
	ok := verdict(result(anchorverify.StateVerified, ""))
	for _, c := range []struct {
		name     string
		root     Verdict
		children []Verdict
		want     int
	}{
		{"root mismatch, child unverifiable", mm, []Verdict{un}, ExitMismatch},
		{"root unverifiable, child mismatch", un, []Verdict{mm}, ExitMismatch},
		{"mismatch then unverifiable siblings", ok, []Verdict{mm, un}, ExitMismatch},
		{"unverifiable then mismatch siblings", ok, []Verdict{un, mm}, ExitMismatch},
		{"unverifiable only", ok, []Verdict{un, ok}, ExitUnverifiable},
		{"nothing", Verdict{}, nil, 0},
	} {
		if got := TreeExit(c.root, c.children); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}
