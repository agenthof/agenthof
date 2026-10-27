package sidecar

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func touch(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func statOf(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// TestCandidatesSkipSetAndShape: only a regular run-shaped <id>.jsonl with no
// sidecar is a candidate; the control ledger, its repair fragments, a
// directory, a non-ledger, the lock file, a mis-shaped id and an anchored run
// are not. A child run is a file like any other, and the answer is sorted.
func TestCandidatesSkipSetAndShape(t *testing.T) {
	dir := t.TempDir()
	touch(t, dir, "control.jsonl")
	touch(t, dir, "control.jsonl.torn-1700000000")
	touch(t, dir, "r-00000000000000c1.jsonl.torn-1700000000")
	if err := os.Mkdir(filepath.Join(dir, "r-00000000000000d1.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	touch(t, dir, "notes.txt")
	touch(t, dir, LockName)
	touch(t, dir, "r-xyz.jsonl")
	touch(t, dir, "R-00000000000000E1.jsonl")
	touch(t, dir, "r-00000000000000f1.jsonl") // anchored
	touch(t, dir, "r-00000000000000f1.anchor")
	touch(t, dir, "r-00000000000000b2.jsonl")
	touch(t, dir, "r-00000000000000a1.jsonl") // a child, say: no different on disk
	touch(t, dir, "r-00000000000000a1.anchor.tmp-123")

	got, err := Candidates(dir, statOf(t, filepath.Join(dir, "control.jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"r-00000000000000a1", "r-00000000000000b2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestCandidatesSameFileControlLog: the control ledger under another name
// inside the log directory — a symlink or a hard link — is the same file and
// never a run.
func TestCandidatesSameFileControlLog(t *testing.T) {
	dir := t.TempDir()
	ctl := filepath.Join(t.TempDir(), "ledger.jsonl")
	if err := os.WriteFile(ctl, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ctl, filepath.Join(dir, "r-00000000000000a1.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(ctl, filepath.Join(dir, "r-00000000000000a2.jsonl")); err != nil {
		t.Fatal(err)
	}
	touch(t, dir, "r-00000000000000a3.jsonl")
	got, err := Candidates(dir, statOf(t, ctl))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"r-00000000000000a3"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestCandidatesAbsentDirIsEmpty(t *testing.T) {
	got, err := Candidates(filepath.Join(t.TempDir(), "nope"), nil)
	if err != nil || got != nil {
		t.Fatalf("got %v, %v", got, err)
	}
}
