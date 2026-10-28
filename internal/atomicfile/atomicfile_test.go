package atomicfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agenthof/agenthof/internal/atomicfile"
)

func TestReplaceWritesMode0600(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "f")
	if err := atomicfile.Replace(dest, "f.tmp-*", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
	}
	if b, _ := os.ReadFile(dest); string(b) != "hello" {
		t.Fatalf("content = %q", b)
	}
	// replacing again overwrites whole
	if err := atomicfile.Replace(dest, "f.tmp-*", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "x" {
		t.Fatalf("content = %q", b)
	}
	assertOnly(t, dir, "f")
}

func TestReplaceLeavesNoTempOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "d")
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "keep"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicfile.Replace(dest, "d.tmp-*", []byte("data")); err == nil {
		t.Fatal("Replace over a non-empty directory succeeded")
	}
	assertOnly(t, dir, "d")
	if b, err := os.ReadFile(filepath.Join(dest, "keep")); err != nil || string(b) != "k" {
		t.Fatalf("dest disturbed: %q %v", b, err)
	}
}

func assertOnly(t *testing.T, dir string, want string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != want {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("dir holds %v, want only %q", names, want)
	}
}
