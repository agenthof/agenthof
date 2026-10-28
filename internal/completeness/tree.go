package completeness

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/agenthof/agenthof/internal/engine"
	"github.com/agenthof/agenthof/internal/ledger"
)

// Node is one run in a delegation tree: its integrity word and, when the
// chain verified, its own completeness report.
type Node struct {
	RunID     string
	Integrity string // "verified" | "torn" | "broken" | "error"
	Report    Report
}

// Tree is a run and every descendant reachable through its spawn events,
// depth-first in spawn order. Each run keeps its own verdict; the exit code
// is the worst in the tree.
type Tree struct {
	Root     Node
	Children []Node
}

// IntegrityWord classifies engine.ReadLog's error the way the audit line
// does: nil verified, a torn tail torn, a broken link broken, anything else
// (open, IO) error.
func IntegrityWord(verr error) string {
	switch {
	case verr == nil:
		return "verified"
	case errors.As(verr, new(*ledger.TornError)):
		return "torn"
	case errors.As(verr, new(*ledger.ChainBrokenError)):
		return "broken"
	}
	return "error"
}

// VerifyTree judges runID (already read: events and verr) and its
// delegation tree under logDir. The forward check: every spawn event with a
// child id must name a ledger whose first event links back to this run at
// the spawn's depth, verified recursively — on a terminated and on an
// unterminated parent alike (a spawn event lands after its child returns,
// so a named child is over). The reverse check, only once the parent is
// terminated: every ledger under logDir whose first event names this run as
// its parent must be named by a spawn event. A no-claim run (written before
// door accounting) is judged on integrity alone: no linkage is checked and
// no children are walked. A corrupt parent_run_id that loops is walked once.
func VerifyTree(logDir, runID string, events []engine.Event, verr error) Tree {
	t := Tree{Root: Node{RunID: runID, Integrity: IntegrityWord(verr)}}
	if verr != nil {
		return t
	}
	t.Root.Report = Check(events)
	if t.Root.Report.Verdict == NoClaim {
		return t
	}
	parents, perr := Parents(logDir)
	seen := map[string]bool{runID: true}
	t.Root.Report = t.link(logDir, runID, events, t.Root.Report, parents, perr, seen)
	return t
}

func (t *Tree) link(logDir, runID string, events []engine.Event, rep Report, parents map[string]string, perr error, seen map[string]bool) Report {
	downgrade := func(detail string) {
		if rep.Verdict != Gap {
			rep = gap(detail)
		}
	}
	named := map[string]bool{}
	for _, e := range events {
		if e.Type != "spawn" || e.ChildRunID == "" {
			continue
		}
		child := e.ChildRunID
		named[child] = true
		if seen[child] {
			continue
		}
		seen[child] = true
		cev, _, cerr := engine.ReadLog(logDir, child)
		if errors.Is(cerr, fs.ErrNotExist) {
			downgrade(fmt.Sprintf("spawn names child %s: no ledger under the log directory", child))
			continue
		}
		node := Node{RunID: child, Integrity: IntegrityWord(cerr)}
		if len(cev) > 0 {
			b := cev[0].Binding
			if b.ParentRunID != runID {
				downgrade(fmt.Sprintf("child %s names parent %q, not this run", child, b.ParentRunID))
			} else if b.Depth != e.Depth {
				downgrade(fmt.Sprintf("child %s is at depth %d, spawn says %d", child, b.Depth, e.Depth))
			}
		}
		if cerr == nil {
			node.Report = Check(cev)
			if node.Report.Verdict != NoClaim {
				node.Report = t.link(logDir, child, cev, node.Report, parents, perr, seen)
			}
		}
		t.Children = append(t.Children, node)
	}
	if rep.Verdict == Unterminated {
		return rep // the reverse check waits for the parent to finish
	}
	if perr != nil {
		downgrade("log directory could not be scanned for children")
		return rep
	}
	ids := make([]string, 0, len(parents))
	for id := range parents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if parents[id] == runID && !named[id] {
			downgrade(fmt.Sprintf("child %s names this run as its parent; no spawn event names it", id))
		}
	}
	return rep
}

// Parents maps every run ledger under logDir to the parent run its first
// event names ("" for a root, or for a file whose first line is not a
// decodable event). It reads one line per file. control.jsonl, *.torn-*
// fragments and non-.jsonl entries are skipped, as investigate and runs
// prune skip them; runs prune uses this same map to keep a tree whole.
func Parents(logDir string) (map[string]string, error) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".jsonl") || name == "control.jsonl" || strings.Contains(name, ".torn-") {
			continue
		}
		out[strings.TrimSuffix(name, ".jsonl")] = firstParent(filepath.Join(logDir, name))
	}
	return out, nil
}

func firstParent(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	if !sc.Scan() {
		return ""
	}
	var e engine.Event
	if json.Unmarshal(sc.Bytes(), &e) != nil {
		return ""
	}
	return e.Binding.ParentRunID
}

// ChildIntegrityFailure is the first descendant's non-verified integrity
// word, or "".
func (t Tree) ChildIntegrityFailure() string {
	for _, c := range t.Children {
		if c.Integrity != "verified" {
			return c.Integrity
		}
	}
	return ""
}

// ChildCompletenessWorst is Gap if any descendant has a gap, else
// Unterminated if any is unterminated, else "".
func (t Tree) ChildCompletenessWorst() string {
	worst := ""
	for _, c := range t.Children {
		switch c.Report.Verdict {
		case Gap:
			return Gap
		case Unterminated:
			worst = Unterminated
		}
	}
	return worst
}

// ExitCode is the worst verdict in the tree, by the audit commands'
// precedence: 1 for a torn, broken or unreadable ledger anywhere; 11 for a
// gap anywhere; 12 for an unterminated run anywhere; else 0 (complete and
// no-claim alike).
func ExitCode(t Tree) int {
	if t.Root.Integrity != "verified" || t.ChildIntegrityFailure() != "" {
		return 1
	}
	all := append([]Node{t.Root}, t.Children...)
	for _, n := range all {
		if n.Report.Verdict == Gap {
			return 11
		}
	}
	for _, n := range all {
		if n.Report.Verdict == Unterminated {
			return 12
		}
	}
	return 0
}

// SubtreeLines renders one line per descendant — its integrity and its
// completeness — for the parent's audit; nothing for a run with no children.
func (t Tree) SubtreeLines() string { return t.SubtreeLinesWith(nil) }

// SubtreeLinesWith is SubtreeLines with suffix(node) appended to each
// descendant's line before the newline — the hook a caller uses to add a
// word of its own (a child's anchor state) without this package knowing it.
// A nil suffix appends nothing.
func (t Tree) SubtreeLinesWith(suffix func(Node) string) string {
	var sb strings.Builder
	for _, c := range t.Children {
		comp := c.Report.Verdict
		if comp == "" {
			comp = "not judged"
		}
		extra := ""
		if suffix != nil {
			extra = suffix(c)
		}
		fmt.Fprintf(&sb, "subtree: run %s — integrity %s, completeness %s%s\n", c.RunID, c.Integrity, comp, extra)
	}
	return sb.String()
}
