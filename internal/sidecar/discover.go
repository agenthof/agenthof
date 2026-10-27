package sidecar

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Candidates names, sorted, the run ids under logDir that have a finished-run
// ledger shape and no sidecar yet: the runs an --pending pass may try. A
// candidate is a regular <id>.jsonl whose id has the run-id shape and whose
// <id>.anchor does not exist; control.jsonl, the repair fragments
// (.torn- in the name), directories and anything else are not. controlLog is
// the stat of the control ledger: an entry that is the same file (a symlink or
// hard link under another name) is never a run. A nil controlLog compares
// nothing. An entry that cannot be stat'd (vanished, or a dangling link) is not
// a resolvable run log and is skipped.
//
// Whether a candidate is anchorable (a whole chain ending at its final event)
// is not decided here: reading each ledger is the anchoring body's job. A
// child run is a candidate like any other. An absent logDir is no candidates.
func Candidates(logDir string, controlLog os.FileInfo) ([]string, error) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || name == "control.jsonl" || strings.Contains(name, ".torn-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		id := strings.TrimSuffix(name, ".jsonl")
		if !RunIDRE.MatchString(id) {
			continue
		}
		info, err := os.Stat(filepath.Join(logDir, name))
		if err != nil || info.IsDir() || (controlLog != nil && os.SameFile(info, controlLog)) {
			continue
		}
		if _, err := os.Lstat(Path(logDir, id)); !errors.Is(err, fs.ErrNotExist) {
			continue // anchored already — or a sidecar slot we cannot judge: not ours to refile
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
