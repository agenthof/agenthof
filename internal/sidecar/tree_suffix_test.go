package sidecar

import (
	"testing"

	"github.com/agenthof/agenthof/internal/anchorverify"
	"github.com/agenthof/agenthof/internal/completeness"
)

// TestSuffixWordsAnUnpinnedVerifiedAnchorAsServed: a descendant's subtree line
// is as honest as the root's — verified under a key the log served is not
// independent, and the line says so; pinned, or any other state, it does not.
func TestSuffixWordsAnUnpinnedVerifiedAnchorAsServed(t *testing.T) {
	verified := Verdict{Found: true, Results: []anchorverify.Result{{State: anchorverify.StateVerified}}}
	unverifiable := Verdict{Found: true, Results: []anchorverify.Result{{State: anchorverify.StateUnverifiable}}}
	tv := TreeVerdicts{byRun: map[string]treeChild{
		"r-served":  {v: verified},
		"r-pinned":  {v: verified, pinned: true},
		"r-unknown": {v: unverifiable},
		"r-none":    {v: Verdict{}},
	}}
	for id, want := range map[string]string{
		"r-served":  ", anchor verified (as served)",
		"r-pinned":  ", anchor verified",
		"r-unknown": ", anchor unverifiable",
		"r-none":    ", anchor not-anchored",
		"r-absent":  "",
	} {
		if got := tv.Suffix(completeness.Node{RunID: id}); got != want {
			t.Errorf("%s: %q, want %q", id, got, want)
		}
	}
}
