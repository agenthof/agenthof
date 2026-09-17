package agentrt

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func newTestJail(t *testing.T) *Jail {
	t.Helper()
	dir := t.TempDir()
	j, err := NewJail(dir)
	if err != nil {
		t.Fatalf("NewJail(%q): %v", dir, err)
	}
	return j
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// ---------------------------------------------------------------------
// NewJail
// ---------------------------------------------------------------------

func TestNewJail_ResolvesSymlinkedRoot(t *testing.T) {
	dir := t.TempDir() // on macOS this itself lives under /var -> /private/var
	j, err := NewJail(dir)
	if err != nil {
		t.Fatalf("NewJail: %v", err)
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if j.root != want {
		t.Fatalf("root = %q, want %q", j.root, want)
	}
}

func TestNewJail_MissingRootErrors(t *testing.T) {
	if _, err := NewJail(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected error for missing root")
	}
}

// ---------------------------------------------------------------------
// Invariant 1: path resolution confines .. and absolute inputs inside root
// ---------------------------------------------------------------------

func TestInvariant1_DotDotConfinedNotError(t *testing.T) {
	j := newTestJail(t)
	if err := j.Write("../../../etc/x.txt", "hi"); err != nil {
		t.Fatalf("Write with .. should be confined, not error: %v", err)
	}
	want := filepath.Join(j.root, "etc", "x.txt")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected file confined at %q: %v", want, err)
	}
}

func TestInvariant1_AbsolutePathConfinedNotError(t *testing.T) {
	j := newTestJail(t)
	if err := j.Write("/etc/passwd", "not the real one"); err != nil {
		t.Fatalf("Write with absolute path should be confined, not error: %v", err)
	}
	confined := filepath.Join(j.root, "etc", "passwd")
	data, err := os.ReadFile(confined)
	if err != nil {
		t.Fatalf("expected file confined at %q: %v", confined, err)
	}
	if string(data) != "not the real one" {
		t.Fatalf("unexpected content: %q", data)
	}
	if real, err := os.ReadFile("/etc/passwd"); err == nil && strings.Contains(string(real), "not the real one") {
		t.Fatal("real /etc/passwd was modified — jail escaped")
	}
}

// ---------------------------------------------------------------------
// Invariant 2: symlinked ancestor directories cannot carry an operation
// outside the root
// ---------------------------------------------------------------------

func TestInvariant2_SymlinkedAncestorDirEscapeRefused(t *testing.T) {
	j := newTestJail(t)
	external := t.TempDir()
	writeFile(t, filepath.Join(external, "secret.txt"), "outside")

	if err := os.Symlink(external, filepath.Join(j.root, "evil")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if _, _, _, _, _, err := j.Read("evil/secret.txt", 0, 0); err == nil || !strings.Contains(err.Error(), "escapes the workspace") {
		t.Fatalf("Read through symlinked ancestor: got err=%v, want \"escapes the workspace\"", err)
	}
	if err := j.Write("evil/secret.txt", "pwned"); err == nil || !strings.Contains(err.Error(), "escapes the workspace") {
		t.Fatalf("Write through symlinked ancestor: got err=%v, want \"escapes the workspace\"", err)
	}
	if data, _ := os.ReadFile(filepath.Join(external, "secret.txt")); string(data) == "pwned" {
		t.Fatal("external file was modified — jail escaped")
	}

	// Also exercise the nonexistent-remainder path: a not-yet-created file
	// under the symlinked (but existing) ancestor.
	if err := j.Write("evil/newdir/new.txt", "pwned"); err == nil || !strings.Contains(err.Error(), "escapes the workspace") {
		t.Fatalf("Write with nonexistent remainder under symlinked ancestor: got err=%v, want \"escapes the workspace\"", err)
	}
}

// TestInvariant2_ListAndSearchDoNotDescendSymlinkedSubdir guards against a
// bulk-exfiltration path distinct from the single-path Read/Write refusal
// above: List and Search walk the tree themselves rather than resolving a
// caller-supplied path, so they need their own check that a symlinked
// subdirectory never gets listed into or read through.
func TestInvariant2_ListAndSearchDoNotDescendSymlinkedSubdir(t *testing.T) {
	j := newTestJail(t)
	external := t.TempDir()
	writeFile(t, filepath.Join(external, "secret.txt"), "MATCHME")

	if err := os.Symlink(external, filepath.Join(j.root, "evil")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	entries, _, err := j.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Path, "evil/") || e.Path == "evil" {
			t.Fatalf("List surfaced a path under the symlinked subdirectory: %q", e.Path)
		}
	}

	_, count, err := j.Search("MATCHME", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if count != 0 {
		t.Fatalf("Search matched external content through symlinked subdirectory: count=%d", count)
	}
}

// ---------------------------------------------------------------------
// Invariant 3: a symlink AS THE FINAL TARGET is refused outright, even if
// it resolves back inside the root
// ---------------------------------------------------------------------

func TestInvariant3_SymlinkFinalTargetRefused_PointingInside(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "real.txt"), "hello")
	if err := os.Symlink(filepath.Join(j.root, "real.txt"), filepath.Join(j.root, "link.txt")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if _, _, _, _, _, err := j.Read("link.txt", 0, 0); err == nil || !strings.Contains(err.Error(), "symlink") || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("Read of symlink file: got err=%v, want \"symlink; refused\"", err)
	}
	if err := j.Write("link.txt", "clobber"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Write over symlink file: got err=%v, want symlink refusal", err)
	}
	if _, err := j.Edit("link.txt", "hello", "bye", false); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Edit of symlink file: got err=%v, want symlink refusal", err)
	}
}

func TestInvariant3_SymlinkFinalTargetRefused_PointingOutside(t *testing.T) {
	j := newTestJail(t)
	external := t.TempDir()
	writeFile(t, filepath.Join(external, "secret.txt"), "outside")
	if err := os.Symlink(filepath.Join(external, "secret.txt"), filepath.Join(j.root, "link.txt")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, _, _, _, _, err := j.Read("link.txt", 0, 0); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Read of outward-pointing symlink file: got err=%v, want symlink refusal", err)
	}
}

// ---------------------------------------------------------------------
// Invariant 4: any path with a .git component is refused, on every op
// that takes a single path
// ---------------------------------------------------------------------

func TestInvariant4_GitComponentRefused_ReadWriteEdit(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, ".git", "config"), "[core]\n")

	if _, _, _, _, _, err := j.Read(".git/config", 0, 0); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("Read of .git/config: got err=%v, want refusal", err)
	}
	if err := j.Write(".git/config", "x"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("Write of .git/config: got err=%v, want refusal", err)
	}
	if _, err := j.Edit(".git/config", "core", "x", false); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("Edit of .git/config: got err=%v, want refusal", err)
	}
}

func TestInvariant4_GitComponentRefused_ViaSymlinkAlias(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, ".git", "config"), "[core]\n")
	if err := os.Symlink(filepath.Join(j.root, ".git"), filepath.Join(j.root, "alias")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, _, _, _, _, err := j.Read("alias/config", 0, 0); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("Read via alias into .git: got err=%v, want refusal", err)
	}
}

func TestInvariant4_ListAndSearchSkipGit(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, ".git", "config"), "MATCHME\n")
	writeFile(t, filepath.Join(j.root, "keep.txt"), "keep\n")

	entries, _, err := j.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Path, ".git") {
			t.Fatalf("List surfaced a .git path: %q", e.Path)
		}
	}

	_, count, err := j.Search("MATCHME", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if count != 0 {
		t.Fatalf("Search matched inside .git: count=%d", count)
	}
}

func TestInvariant4_ListAndSearchSkipGitWorktreeFile(t *testing.T) {
	// In a git worktree, ".git" is a regular FILE (not a directory)
	// containing a "gitdir: <path>" pointer. It must still be skipped.
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, ".git"), "gitdir: /somewhere/else/.git/worktrees/x\n")
	writeFile(t, filepath.Join(j.root, "keep.txt"), "keep\n")

	entries, _, err := j.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Path != "keep.txt" {
		t.Fatalf("entries = %+v, want only keep.txt (gitfile must be skipped)", entries)
	}

	_, count, err := j.Search("gitdir", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if count != 0 {
		t.Fatalf("Search matched the .git worktree file: count=%d", count)
	}
}

// ---------------------------------------------------------------------
// Invariant 4b: the dot-prefixed-component denial generalizes beyond
// ".git" to ANY leading-dot path component (Constitution Art. I), applied
// at both the pre-resolution and post-resolution checks in resolve().
// ---------------------------------------------------------------------

func TestInvariant4b_DotComponentRefused_ReadWriteEdit(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, ".env"), "SECRET=1\n")
	writeFile(t, filepath.Join(j.root, ".ssh", "id_rsa"), "-----BEGIN-----\n")
	writeFile(t, filepath.Join(j.root, "sub", ".hidden"), "shh\n")

	for _, rel := range []string{".env", ".ssh/id_rsa", "sub/.hidden"} {
		if _, _, _, _, _, err := j.Read(rel, 0, 0); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("Read of %q: got err=%v, want refusal", rel, err)
		}
		if err := j.Write(rel, "x"); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("Write of %q: got err=%v, want refusal", rel, err)
		}
		if _, err := j.Edit(rel, "x", "y", false); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("Edit of %q: got err=%v, want refusal", rel, err)
		}
	}

	// The refused Write must not have created (or modified) anything.
	if _, err := os.Stat(filepath.Join(j.root, ".env")); err != nil {
		t.Fatalf("stat .env: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(j.root, ".env"))
	if err != nil || string(data) != "SECRET=1\n" {
		t.Fatalf(".env content changed by a refused write: data=%q err=%v", data, err)
	}
}

func TestInvariant4b_ListAndSearchOmitDotfiles(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, ".env"), "MATCHME\n")
	writeFile(t, filepath.Join(j.root, "keep.txt"), "keep\n")

	entries, _, err := j.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Path != "keep.txt" {
		t.Fatalf("entries = %+v, want only keep.txt (.env must be skipped)", entries)
	}

	_, count, err := j.Search("MATCHME", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if count != 0 {
		t.Fatalf("Search matched inside .env: count=%d", count)
	}
}

// ---------------------------------------------------------------------
// Invariant 5: Write refuses to overwrite an existing file over the
// 16000-byte cap
// ---------------------------------------------------------------------

func TestInvariant5_WriteRefusesLargeOverwrite(t *testing.T) {
	j := newTestJail(t)
	big := strings.Repeat("x", 16001)
	writeFile(t, filepath.Join(j.root, "big.txt"), big)

	err := j.Write("big.txt", "new")
	if err == nil || !strings.Contains(err.Error(), "edit") {
		t.Fatalf("Write over large file: got err=%v, want refusal mentioning edit", err)
	}
	data, rerr := os.ReadFile(filepath.Join(j.root, "big.txt"))
	if rerr != nil || string(data) != big {
		t.Fatal("large file content should be unchanged after refused overwrite")
	}
}

func TestInvariant5_WriteAllowsSmallOverwrite(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "small.txt"), "old")
	if err := j.Write("small.txt", "new"); err != nil {
		t.Fatalf("Write over small file should succeed: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(j.root, "small.txt"))
	if string(data) != "new" {
		t.Fatalf("content = %q, want %q", data, "new")
	}
}

// ---------------------------------------------------------------------
// Invariant 6: no os/exec import anywhere in this package. There is no Go
// test that can enforce a "no import" property meaningfully (a grep-based
// test would just duplicate a code review step); this is verified by
// inspection instead of a test.
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// List: skip rules, cap, sort, rel slash paths
// ---------------------------------------------------------------------

func TestList_SkipsDirsAndOversizedFiles(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "node_modules", "pkg", "index.js"), "x")
	writeFile(t, filepath.Join(j.root, "vendor", "lib", "a.go"), "x")
	writeFile(t, filepath.Join(j.root, "keep.txt"), "keep")
	writeFile(t, filepath.Join(j.root, "big.bin"), strings.Repeat("a", maxFileSize+1))

	entries, truncated, err := j.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if truncated {
		t.Fatal("did not expect truncation")
	}
	if len(entries) != 1 || entries[0].Path != "keep.txt" {
		t.Fatalf("entries = %+v, want only keep.txt", entries)
	}
}

func TestList_SkipsSymlinkedFiles(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "real.txt"), "hi")
	if err := os.Symlink(filepath.Join(j.root, "real.txt"), filepath.Join(j.root, "link.txt")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	entries, _, err := j.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, e := range entries {
		if e.Path == "link.txt" {
			t.Fatal("List surfaced a symlinked file")
		}
	}
}

func TestList_SortedAndRelSlashPaths(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "b.txt"), "b")
	writeFile(t, filepath.Join(j.root, "a", "c.txt"), "c")
	writeFile(t, filepath.Join(j.root, "a.txt"), "a")

	entries, _, err := j.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var paths []string
	for _, e := range entries {
		paths = append(paths, e.Path)
		if strings.Contains(e.Path, `\`) {
			t.Fatalf("path %q not slash-separated", e.Path)
		}
	}
	if !sortedStrings(paths) {
		t.Fatalf("entries not sorted by path: %v", paths)
	}
}

func sortedStrings(ss []string) bool {
	for i := 1; i < len(ss); i++ {
		if ss[i-1] > ss[i] {
			return false
		}
	}
	return true
}

func TestList_CapAndTruncated(t *testing.T) {
	j := newTestJail(t)
	for i := 0; i < 305; i++ {
		writeFile(t, filepath.Join(j.root, "many", padNum(i)+".txt"), "x")
	}
	entries, truncated, err := j.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true")
	}
	if len(entries) != maxListEntries {
		t.Fatalf("len(entries) = %d, want %d", len(entries), maxListEntries)
	}
	if !sortedStrings(pathsOf(entries)) {
		t.Fatal("capped entries not sorted")
	}
}

func padNum(i int) string {
	return fmt.Sprintf("%05d", i)
}

func pathsOf(entries []FileInfo) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Path
	}
	return out
}

// ---------------------------------------------------------------------
// Read: windows, defaults, EOF error, byte cap cut at line boundary,
// single oversized line, pagination beyond the cap
// ---------------------------------------------------------------------

func makeNumberedLines(n int, width int) []string {
	lines := make([]string, n)
	for i := 0; i < n; i++ {
		body := strings.Repeat("x", width)
		lines[i] = body + itoa(i)
	}
	return lines
}

func itoa(i int) string {
	return strconv.Itoa(i)
}

func TestRead_WholeFileDefaults(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "f.txt"), "a\nb\nc")

	content, start, end, total, truncated, err := j.Read("f.txt", 0, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if content != "a\nb\nc" || start != 1 || end != 3 || total != 3 || truncated {
		t.Fatalf("got content=%q start=%d end=%d total=%d truncated=%v", content, start, end, total, truncated)
	}
}

func TestRead_MidWindow(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "f.txt"), "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n")

	content, start, end, total, truncated, err := j.Read("f.txt", 3, 5)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if content != "3\n4\n5" || start != 3 || end != 5 || total != 10 || truncated {
		t.Fatalf("got content=%q start=%d end=%d total=%d truncated=%v", content, start, end, total, truncated)
	}
}

func TestRead_EmptyFileReturnsCleanEmptyResult(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "empty.txt"), "")

	content, start, end, total, truncated, err := j.Read("empty.txt", 0, 0)
	if err != nil {
		t.Fatalf("Read of empty file: unexpected error: %v", err)
	}
	if content != "" || start != 1 || end != 0 || total != 0 || truncated {
		t.Fatalf("got content=%q start=%d end=%d total=%d truncated=%v, want (\"\", 1, 0, 0, false)", content, start, end, total, truncated)
	}
}

func TestRead_StartBeyondEOFErrors(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "f.txt"), "1\n2\n3\n")

	if _, _, _, total, _, err := j.Read("f.txt", 100, 0); err == nil {
		t.Fatal("expected error for start beyond EOF")
	} else if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	} else if !strings.Contains(err.Error(), "beyond") {
		t.Fatalf("error = %v, want mention of beyond EOF", err)
	}
}

func TestRead_CapCutAtLineBoundary(t *testing.T) {
	j := newTestJail(t)
	lines := makeNumberedLines(400, 90) // ~95 bytes/line * 400 ~= 38000 bytes, well over the 16000 cap
	writeFile(t, filepath.Join(j.root, "big.txt"), strings.Join(lines, "\n"))

	content, start, end, total, truncated, err := j.Read("big.txt", 1, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true")
	}
	if total != 400 || start != 1 {
		t.Fatalf("start=%d total=%d", start, total)
	}
	if len(content) > readByteCap {
		t.Fatalf("content len = %d, exceeds cap %d", len(content), readByteCap)
	}
	if end >= total {
		t.Fatalf("end=%d should be well short of total=%d", end, total)
	}
	got := strings.Split(content, "\n")
	if len(got) != end {
		t.Fatalf("returned %d lines, want %d (end)", len(got), end)
	}
	for i, line := range got {
		if line != lines[i] {
			t.Fatalf("line %d = %q, want %q (must be a whole, uncut line)", i+1, line, lines[i])
		}
	}

	// The line just past the cut is unreachable via the whole-file read but
	// must still be reachable through a smaller, explicit window.
	nextLine := end + 50
	if nextLine > total {
		nextLine = total
	}
	c2, s2, e2, t2, trunc2, err := j.Read("big.txt", nextLine, nextLine)
	if err != nil {
		t.Fatalf("windowed Read beyond cap: %v", err)
	}
	if trunc2 || s2 != nextLine || e2 != nextLine || t2 != total {
		t.Fatalf("got content=%q start=%d end=%d total=%d truncated=%v", c2, s2, e2, t2, trunc2)
	}
	if c2 != lines[nextLine-1] {
		t.Fatalf("windowed content = %q, want %q", c2, lines[nextLine-1])
	}
}

func TestRead_SingleLineOverCapIsClipped(t *testing.T) {
	j := newTestJail(t)
	huge := strings.Repeat("y", 20000)
	writeFile(t, filepath.Join(j.root, "huge.txt"), huge)

	content, start, end, total, truncated, err := j.Read("huge.txt", 0, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !truncated || start != 1 || end != 1 || total != 1 {
		t.Fatalf("got start=%d end=%d total=%d truncated=%v", start, end, total, truncated)
	}
	if len(content) != readByteCap {
		t.Fatalf("content len = %d, want %d", len(content), readByteCap)
	}
}

// ---------------------------------------------------------------------
// Write: create + parent dirs, permission bits
// ---------------------------------------------------------------------

func TestWrite_CreatesFileAndParentDirs(t *testing.T) {
	j := newTestJail(t)
	if err := j.Write("a/b/c.txt", "hello"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	full := filepath.Join(j.root, "a", "b", "c.txt")
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("content = %q, want %q", data, "hello")
	}
	fi, err := os.Stat(full)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("file perm = %v, want 0644", fi.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Join(j.root, "a", "b"))
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if !dirInfo.IsDir() {
		t.Fatal("expected a/b to be a directory")
	}
}

// ---------------------------------------------------------------------
// Edit: all four error cases + replace-one + replace-all count
// ---------------------------------------------------------------------

func TestEdit_EmptyOldErrors(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "f.txt"), "hello")
	if _, err := j.Edit("f.txt", "", "x", false); err == nil {
		t.Fatal("expected error for empty old")
	}
}

func TestEdit_OldEqualsNewErrors(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "f.txt"), "hello")
	if _, err := j.Edit("f.txt", "hello", "hello", false); err == nil {
		t.Fatal("expected error when old == new")
	}
}

func TestEdit_NoMatchErrors(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "f.txt"), "hello world")
	_, err := j.Edit("f.txt", "goodbye", "hi", false)
	if err == nil {
		t.Fatal("expected error for no match")
	}
	if !strings.Contains(err.Error(), "not found") || !strings.Contains(err.Error(), "copy the exact text") {
		t.Fatalf("error = %v, want mention of not found + copy the exact text", err)
	}
}

func TestEdit_AmbiguousWithoutAllErrors(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "f.txt"), "foo bar foo baz foo")
	_, err := j.Edit("f.txt", "foo", "qux", false)
	if err == nil {
		t.Fatal("expected error for ambiguous match")
	}
	if !strings.Contains(err.Error(), "3") || !strings.Contains(err.Error(), "all") {
		t.Fatalf("error = %v, want mention of count (3) and all", err)
	}
}

func TestEdit_UniqueMatchReplaces(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "f.txt"), "hello world")
	n, err := j.Edit("f.txt", "world", "there", false)
	if err != nil {
		t.Fatalf("Edit: %v", err)
	}
	if n != 1 {
		t.Fatalf("n = %d, want 1", n)
	}
	data, _ := os.ReadFile(filepath.Join(j.root, "f.txt"))
	if string(data) != "hello there" {
		t.Fatalf("content = %q", data)
	}
}

func TestEdit_ReplaceAllReturnsCount(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "f.txt"), "foo bar foo baz foo")
	n, err := j.Edit("f.txt", "foo", "qux", true)
	if err != nil {
		t.Fatalf("Edit: %v", err)
	}
	if n != 3 {
		t.Fatalf("n = %d, want 3", n)
	}
	data, _ := os.ReadFile(filepath.Join(j.root, "f.txt"))
	if string(data) != "qux bar qux baz qux" {
		t.Fatalf("content = %q", data)
	}
}

// ---------------------------------------------------------------------
// Search: basic match, binary skip, default/hard caps, byte cap, bad
// pattern
// ---------------------------------------------------------------------

func TestSearch_Basic(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "a.txt"), "hello\nMATCH here\nbye\n")
	writeFile(t, filepath.Join(j.root, "b.txt"), "nothing\n")

	out, count, err := j.Search("MATCH", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
	if !strings.Contains(out, "a.txt:2: MATCH here") {
		t.Fatalf("output = %q, want row for a.txt:2", out)
	}
}

func TestSearch_SkipsBinaryFiles(t *testing.T) {
	j := newTestJail(t)
	binContent := "\x00MATCH binary\n"
	writeFile(t, filepath.Join(j.root, "bin.dat"), binContent)
	writeFile(t, filepath.Join(j.root, "text.txt"), "MATCH text\n")

	out, count, err := j.Search("MATCH", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1 (binary file must be skipped)", count)
	}
	if strings.Contains(out, "bin.dat") {
		t.Fatalf("output should not include binary file: %q", out)
	}
}

func TestSearch_DefaultAndHardCap(t *testing.T) {
	j := newTestJail(t)
	var b strings.Builder
	for i := 0; i < 250; i++ {
		b.WriteString("MATCH line\n")
	}
	writeFile(t, filepath.Join(j.root, "many.txt"), b.String())

	_, count, err := j.Search("MATCH", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if count != defaultSearchResults {
		t.Fatalf("count = %d, want default %d", count, defaultSearchResults)
	}

	_, count, err = j.Search("MATCH", 10000)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if count != maxSearchResults {
		t.Fatalf("count = %d, want hard cap %d", count, maxSearchResults)
	}
}

func TestSearch_OutputByteCap(t *testing.T) {
	j := newTestJail(t)
	var b strings.Builder
	longLine := strings.Repeat("m", 300)
	for i := 0; i < 200; i++ {
		b.WriteString("MATCH " + longLine + "\n")
	}
	writeFile(t, filepath.Join(j.root, "many.txt"), b.String())

	out, count, err := j.Search("MATCH", maxSearchResults)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(out) > searchByteCap {
		t.Fatalf("output len = %d, exceeds cap %d", len(out), searchByteCap)
	}
	if count >= maxSearchResults {
		t.Fatalf("count = %d, expected the byte cap to bind before the result cap", count)
	}
}

func TestSearch_BadPatternErrors(t *testing.T) {
	j := newTestJail(t)
	writeFile(t, filepath.Join(j.root, "a.txt"), "x")
	if _, _, err := j.Search("(unclosed", 0); err == nil {
		t.Fatal("expected error for invalid regexp")
	}
}
