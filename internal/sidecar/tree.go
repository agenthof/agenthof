package sidecar

import (
	"crypto/ecdsa"
	"sync"
	"time"

	"github.com/agenthof/agenthof/internal/anchorverify"
	"github.com/agenthof/agenthof/internal/completeness"
)

// TreeVerdicts is a run's anchor verdicts across its delegation tree: the
// root's, and one per descendant whose chain verified (a descendant that is
// torn, broken or unreadable has no chain to check a sidecar against, and its
// subtree line already says so).
type TreeVerdicts struct {
	Root     Verdict
	Pinned   bool                 // the resolved key was non-nil
	Children []Verdict            // verified descendants, in tree order
	byRun    map[string]treeChild // the same, by run id
}

// treeChild is a descendant's verdict with whether it was judged under a
// pinned key, which decides how its subtree line words a verified anchor.
type treeChild struct {
	v      Verdict
	pinned bool
}

// VerifyTree decides the anchor of tree's root (runID) and of every verified
// descendant, through VerifyRun. key is resolved at most once for the whole
// tree, and only if some run in it is anchored. The root is skipped when
// rootChainOK is false (its own chain is torn or broken: nothing else is
// judged).
func VerifyTree(logDir, runID string, tree completeness.Tree, rootChainOK bool, key func() (*ecdsa.PublicKey, error), factory anchorverify.Factory, offline bool, timeout time.Duration) TreeVerdicts {
	if key != nil {
		key = sync.OnceValues(key)
	}
	var t TreeVerdicts
	if rootChainOK {
		t.Root, t.Pinned = VerifyRun(logDir, runID, key, factory, offline, timeout)
	}
	for _, c := range tree.Children {
		if c.Integrity != "verified" {
			continue
		}
		v, pinned := VerifyRun(logDir, c.RunID, key, factory, offline, timeout)
		t.Children = append(t.Children, v)
		if t.byRun == nil {
			t.byRun = map[string]treeChild{}
		}
		t.byRun[c.RunID] = treeChild{v: v, pinned: pinned}
	}
	return t
}

// Suffix is the word a descendant's subtree line gains: ", anchor <state>",
// or nothing for a descendant whose chain did not verify. A verified anchor
// judged without a pinned key is worded "(as served)", as the root's line
// words it: the log vouched for itself.
func (t TreeVerdicts) Suffix(n completeness.Node) string {
	c, ok := t.byRun[n.RunID]
	if !ok {
		return ""
	}
	state := c.v.State()
	if state == StateVerified && !c.pinned {
		return ", anchor " + state + " (as served)"
	}
	return ", anchor " + state
}
