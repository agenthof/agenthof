//go:build unix

package ledger

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
)

func TestCreateIsExclusiveAndOpenStillResumes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "run.jsonl")
	c, err := Create(p, Unlocked)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := c.Append([]byte(`{"prev":"","n":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(p, Unlocked); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a second Create on the same path must fail with fs.ErrExist, got %v", err)
	}
	// Open is create-or-resume and stays that way: the control ledger
	// reopens its file on every write.
	c2, err := Open(p, Unlocked)
	if err != nil {
		t.Fatalf("Open must resume the file Create made: %v", err)
	}
	defer func() { _ = c2.Close() }()
	if c2.Count() != 1 {
		t.Fatalf("Count = %d, want 1", c2.Count())
	}
}

func TestCreateMakesTheDirectory(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nested", "deeper", "run.jsonl")
	c, err := Create(p, Unlocked)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
}
